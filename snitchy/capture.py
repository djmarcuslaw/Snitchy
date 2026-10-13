"""The capture engine: runs tcpdump and feeds everything downstream.

    tcpdump (root) --pcapng--> PcapngStream --> Tracker --> Store (SQLite)
                                                       \\-> Hub (live dashboard feed)

tcpdump is the only part that needs root. It is started first; Snitchy can
then drop its own privileges (see cli.py) while tcpdump keeps running.
"""

import os
import queue
import select
import subprocess
import sys
import threading
import time

from . import appinfo
from .pcapng import PcapngStream
from .tracker import Tracker

TCPDUMP = "/usr/sbin/tcpdump"
FLUSH_SECONDS = 1.0          # how often new connections hit the log
PRUNE_SECONDS = 3600         # how often old history is deleted


def tcpdump_command(snaplen=2048):
    """The exact tcpdump invocation. Every flag is explained:

      -i pktap,all  Apple's tagged capture of every interface
      -P            write pcapng (Apple flag) so process tags are included
      -U            flush after every packet, so the log is real time
      --immediate-mode  hand packets over as they arrive (otherwise the
                    kernel batches them for up to a second, and programs
                    that run briefly are gone before we can identify them)
      -s 2048       keep the first 2 KB of each packet (enough for DNS
                    answers and the HTTPS hello; the rest is just counted)
      -n            never look up names itself (we do that)
      -q            less chatter on stderr
      -w -          write to stdout, which Snitchy reads
    """
    return [TCPDUMP, "-i", "pktap,all", "-P", "-U", "--immediate-mode", "-s", str(snaplen), "-n", "-q", "-w", "-"]


def start_tcpdump(snaplen=2048):
    # stderr is left alone so tcpdump's messages land in Snitchy's own log.
    return subprocess.Popen(tcpdump_command(snaplen), stdout=subprocess.PIPE, bufsize=0)


class Hub:
    """Fan-out of live events to every open dashboard tab."""

    def __init__(self):
        self._subscribers = []
        self._lock = threading.Lock()

    def subscribe(self):
        q = queue.Queue(maxsize=2000)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event):
        with self._lock:
            subscribers = list(self._subscribers)
        for q in subscribers:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass                  # a stalled browser tab just misses events


class Engine:
    def __init__(self, store, hub, keep_days=30, include_loopback=False, resolve_ips=True,
                 echo=False, path_lookup=appinfo.pid_path, sign_check=appinfo.check_signature):
        self.store = store
        self.hub = hub
        self.keep_days = keep_days
        self.echo = echo                       # print each new connection (selftest/debug)
        self.tracker = Tracker(include_loopback=include_loopback, path_lookup=path_lookup)
        self.stream = PcapngStream()
        self._events = queue.Queue()           # results arriving from helper threads
        self.signatures = appinfo.SignatureChecker(
            lambda path, signing, signer: self._events.put(("sig", path, signing, signer)),
            check=sign_check)
        self.rdns = appinfo.ReverseDNS(lambda ip, name: self._events.put(("rdns", ip, name))) \
            if resolve_ips else None
        self._checked = set()                  # program paths already queued for codesign
        self._last_flush = 0.0
        self._last_prune = 0.0
        self.started_at = time.time()

    # --- Main loop ---------------------------------------------------------------

    def run(self, proc, stop=None, duration=None):
        """Read tcpdump output until it exits (or `stop` is set / `duration` passes)."""
        fd = proc.stdout.fileno()
        deadline = time.time() + duration if duration else None
        while True:
            if stop is not None and stop.is_set():
                break
            if deadline and time.time() >= deadline:
                break
            ready, _, _ = select.select([fd], [], [], 0.5)
            if ready:
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    break                       # tcpdump exited
                for pkt in self.stream.feed(chunk):
                    self.tracker.handle(pkt)
            self.tick()
        self.tick(force=True)

    def feed_bytes(self, chunk):
        """Feed raw pcapng bytes directly (used by tests and file replay)."""
        for pkt in self.stream.feed(chunk):
            self.tracker.handle(pkt)

    def tick(self, force=False, now=None):
        now = now if now is not None else time.time()
        self._apply_helper_results()
        if force or now - self._last_flush >= FLUSH_SECONDS:
            self._last_flush = now
            self.tracker.expire(now)
            self.flush(now)
        if now - self._last_prune >= PRUNE_SECONDS:
            self._last_prune = now
            self.store.prune(self.keep_days)

    def flush(self, now=None, force=False):
        new, changed = self.tracker.drain(now, force=force)
        self.store.insert_connections(new)
        self.store.update_connections(changed)
        for flow in new + changed:
            self._check_signature(flow.path)
            if self.rdns and not flow.domain and flow.sni_done and not flow.rdns_requested:
                flow.rdns_requested = True
                self.rdns.request(flow.remote_ip)
        if new or changed:
            rows = self.store.get_connections([f.row_id for f in new + changed])
            by_id = {r["id"]: r for r in rows}
            for flow in new:
                row = by_id.get(flow.row_id)
                if row:
                    self.hub.publish({"type": "new", "row": row})
                    if self.echo:
                        print("  %-22s -> %s:%s" % (row["app"], row["domain"] or row["remote_ip"],
                                                    row["remote_port"]), file=sys.stderr, flush=True)
            for flow in changed:
                row = by_id.get(flow.row_id)
                if row:
                    self.hub.publish({"type": "update", "row": row})

    def _check_signature(self, path):
        if path and path not in self._checked:
            self._checked.add(path)
            known = self.store.known_signature(path)
            # Re-check once a day, and whenever the file changed (app update).
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                mtime = 0
            if known is None or time.time() - known["checked_at"] > 86400 or mtime > known["checked_at"]:
                self.signatures.request(path)

    def _apply_helper_results(self):
        while True:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                return
            if event[0] == "sig":
                _, path, signing, signer = event
                self.store.save_signature(path, signing, signer)
                self.hub.publish({"type": "signature", "path": path, "signing": signing, "signer": signer})
            elif event[0] == "rdns":
                _, ip, name = event
                self.tracker.apply_rdns(ip, name)
                self.store.fill_domain(ip, name, "rdns")


def run_with(engine, proc):
    """Run the engine on an already-started tcpdump. Returns tcpdump's exit code."""
    try:
        engine.run(proc)
    finally:
        if proc.poll() is None:
            try:
                proc.terminate()
            except PermissionError:
                # We dropped root, so we can't signal tcpdump. Closing its
                # output pipe makes it exit on its own (cli.py does that).
                return 0
    return proc.wait()
