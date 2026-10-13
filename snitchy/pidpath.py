"""A tiny root helper that answers one question: "what program is PID N?"

Why this exists: Snitchy drops from root to the unprivileged `nobody` user
right after starting capture. But macOS only tells you the on-disk path of
*other users'* processes if you're root, and Snitchy needs those paths to
check code signatures.

So before dropping root, Snitchy starts this helper as a separate root
process. It reads a process ID per line and replies with that program's
path (or an empty line). It does nothing else, which keeps the part of
Snitchy that still has root as small as possible.
"""

import subprocess
import sys
import threading

from . import appinfo


class PathHelper:
    """Client side: start the helper (while still root) and query it."""

    def __init__(self):
        self._proc = subprocess.Popen(
            [sys.executable, "-m", "snitchy.pidpath"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self._lock = threading.Lock()

    def lookup(self, pid):
        if pid is None or pid <= 0:
            return ""
        with self._lock:
            if self._proc.poll() is not None:
                return appinfo.pid_path(pid)        # helper gone: best effort
            try:
                self._proc.stdin.write("%d\n" % pid)
                self._proc.stdin.flush()
                return self._proc.stdout.readline().rstrip("\n")
            except (BrokenPipeError, OSError, ValueError):
                return ""

    def close(self):
        try:
            self._proc.stdin.close()               # helper exits when input ends
        except OSError:
            pass


def serve():
    """Helper side: one PID in, one path out, until stdin closes."""
    for line in sys.stdin:
        try:
            path = appinfo.pid_path(int(line))
        except ValueError:
            path = ""
        sys.stdout.write(path.replace("\n", " ") + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    serve()
