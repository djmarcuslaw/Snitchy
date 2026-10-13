"""Who is this app? Finds the program on disk and checks its code signature.

The capture only tells us a process ID and a short name like "Google Chrome
H". From the PID we ask macOS for the full path of the program, then use the
built-in `codesign` tool to see who signed it:

  apple        - part of macOS, or an Apple app
  appstore     - distributed through the Mac App Store
  developer    - signed with a Developer ID (a known, paying developer)
  adhoc        - "signed" with no identity at all (common for homemade or
                 sketchy software, and for things you build yourself)
  unsigned     - no signature
  invalid      - signed, but the files no longer match the signature
                 (the app was modified after signing - worth a look)
  unknown      - we couldn't tell (process exited, file unreadable, ...)

`codesign` is slow-ish (tens of milliseconds), so checks run in a background
thread and results are cached per program.
"""

import ctypes
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time

_libproc = None
if sys.platform == "darwin":
    # Note: don't check os.path.exists() here. Since macOS 11 system libraries
    # live in a shared cache and aren't visible as files, but loading them by
    # this path still works.
    try:
        _libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
        _libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        _libproc.proc_pidpath.restype = ctypes.c_int
    except OSError:
        _libproc = None

PROC_PIDPATHINFO_MAXSIZE = 4096


def pid_path(pid):
    """Full path of the running program with this PID, or "" if unknown."""
    if _libproc is None or pid is None or pid <= 0:
        return ""
    buf = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)
    n = _libproc.proc_pidpath(pid, buf, PROC_PIDPATHINFO_MAXSIZE)
    return buf.value[:n].decode("utf-8", "replace") if n > 0 else ""


def bundle_of(path):
    """Return the outermost .app bundle containing `path`, or `path` itself.

    e.g. /Applications/Slack.app/Contents/Frameworks/Slack Helper.app/... ->
    /Applications/Slack.app, so helpers get credited to the app you know.
    """
    m = re.match(r"^(.*?\.app)(/|$)", path)
    return m.group(1) if m else path


def display_name(path, fallback):
    """A friendly app name: 'Slack' for /Applications/Slack.app, else fallback."""
    if path.endswith(".app"):
        return os.path.basename(path)[:-4]
    return fallback or os.path.basename(path)


def classify_signature(codesign_output, returncode):
    """Turn `codesign -dv --verbose=2` output into (signing, signer)."""
    text = codesign_output
    if "not signed at all" in text:
        return "unsigned", ""
    if returncode != 0 and "Authority=" not in text and "Signature=adhoc" not in text:
        return "unknown", ""
    authorities = re.findall(r"^Authority=(.+)$", text, re.M)
    team = re.search(r"^TeamIdentifier=(.+)$", text, re.M)
    first = authorities[0] if authorities else ""
    if "Signature=adhoc" in text or (not authorities and "linker-signed" in text):
        return "adhoc", ""
    if first.startswith("Developer ID Application:"):
        return "developer", first.split(":", 1)[1].strip()
    if first == "Software Signing":                    # Apple's own code
        return "apple", "Apple"
    if first.startswith("Apple Mac OS Application Signing") or first.startswith("Apple iPhone OS Application Signing"):
        return "appstore", (team.group(1) if team else "App Store")
    if first.startswith("Apple Development:") or first.startswith("Apple Distribution:"):
        return "developer", first.split(":", 1)[1].strip()
    if first:
        return "developer", first
    return "unknown", ""


def check_signature(path):
    """Run codesign on `path` and classify it. Safe to call on any path."""
    if not path or not os.path.exists(path):
        return "unknown", ""
    try:
        result = subprocess.run(
            ["/usr/bin/codesign", "-dv", "--verbose=2", path],
            capture_output=True, text=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown", ""
    signing, signer = classify_signature(result.stderr + result.stdout, result.returncode)
    if signing in ("developer", "appstore", "apple"):
        # Signed is only half the story: make sure the signature still matches
        # the files on disk (a modified app fails this check).
        try:
            verify = subprocess.run(["/usr/bin/codesign", "--verify", "--strict", path],
                                    capture_output=True, text=True, timeout=60)
            if verify.returncode != 0:
                return "invalid", signer
        except (OSError, subprocess.TimeoutExpired):
            pass
    return signing, signer


class SignatureChecker:
    """Background worker that checks signatures and stores them via a callback.

    `on_result(path, signing, signer)` is called from the worker thread.
    """

    def __init__(self, on_result):
        self._on_result = on_result
        self._queue = queue.Queue()
        self._seen = set()
        self._lock = threading.Lock()
        threading.Thread(target=self._run, name="codesign", daemon=True).start()

    def request(self, path):
        if not path:
            return
        with self._lock:
            if path in self._seen:
                return
            self._seen.add(path)
        self._queue.put(path)

    def pending(self):
        """True while checks are queued or running."""
        return self._queue.unfinished_tasks > 0

    def forget(self, path):
        """Allow a path to be re-checked (e.g. after an app update)."""
        with self._lock:
            self._seen.discard(path)

    def _run(self):
        while True:
            path = self._queue.get()
            signing, signer = check_signature(path)
            try:
                self._on_result(path, signing, signer)
            except Exception as exc:  # never let one bad result kill the worker
                print("snitchy: failed to save signature for %s: %s" % (path, exc), flush=True)
            finally:
                self._queue.task_done()


class ReverseDNS:
    """Last-resort hostnames: ask "who owns this IP?" (a PTR lookup).

    Only used when neither DNS nor TLS told us the name. Results look like
    "server-13-32-1-5.fra56.r.cloudfront.net", which at least tells you the
    company running the server.
    """

    def __init__(self, on_result, workers=2):
        self._on_result = on_result
        self._queue = queue.Queue(maxsize=5000)
        self._cache = {}
        self._lock = threading.Lock()
        for i in range(workers):
            threading.Thread(target=self._run, name="rdns-%d" % i, daemon=True).start()

    def request(self, ip):
        with self._lock:
            if len(self._cache) > 50000:      # keep memory bounded
                self._cache.clear()
            if ip in self._cache:
                name = self._cache[ip]
                if name:
                    self._on_result(ip, name)
                return
            self._cache[ip] = None
        try:
            self._queue.put_nowait(ip)
        except queue.Full:
            pass

    def _run(self):
        while True:
            ip = self._queue.get()
            try:
                name = socket.gethostbyaddr(ip)[0].lower()
            except (OSError, UnicodeError):
                name = ""
            with self._lock:
                self._cache[ip] = name
            if name:
                self._on_result(ip, name)
            time.sleep(0.01)
