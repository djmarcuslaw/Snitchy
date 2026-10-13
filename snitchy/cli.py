"""Command-line entry point: `snitchy <command>`.

  snitchy run        capture + dashboard (needs root: use sudo, or brew services)
  snitchy selftest   capture for a few seconds and print what was seen
  snitchy demo       dashboard with made-up data (no root, nothing captured)
  snitchy open       open the dashboard in your browser
"""

import argparse
import json
import os
import pwd
import signal
import subprocess
import sys
import tempfile
import threading
import time

from . import __version__
from .capture import Engine, Hub, run_with, start_tcpdump
from .server import make_server
from .store import Store

DEFAULT_PORT = 8899


def default_data_dir():
    if os.geteuid() == 0:
        return "/Library/Application Support/Snitchy"
    return os.path.expanduser("~/Library/Application Support/Snitchy")


def drop_privileges(username, data_dir):
    """Stop being root, keeping access to the log folder.

    tcpdump has already started as root and keeps running; from here on,
    Snitchy's own code (web server, parsing) runs as an ordinary user, so a
    bug in it can't be used to take over your Mac.
    """
    if os.geteuid() != 0 or not username or username == "root":
        return
    user = pwd.getpwnam(username)
    for root, dirs, files in os.walk(data_dir):
        os.chown(root, user.pw_uid, user.pw_gid)
        for name in files:
            os.chown(os.path.join(root, name), user.pw_uid, user.pw_gid)
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)


def _serve_in_background(server):
    threading.Thread(target=server.serve_forever, name="http", daemon=True).start()


def cmd_run(args):
    if os.geteuid() != 0:
        sys.exit("snitchy run needs administrator rights to capture traffic.\n"
                 "Try:  sudo snitchy run      (or: sudo brew services start snitchy)")
    data_dir = args.data_dir or default_data_dir()
    store = Store(os.path.join(data_dir, "snitchy.db"))
    hub = Hub()
    engine = Engine(store, hub, keep_days=args.keep_days, include_loopback=args.include_loopback,
                    resolve_ips=not args.no_rdns)
    proc = start_tcpdump()

    def status():
        return {"version": __version__, "capturing": proc.poll() is None,
                "started_at": engine.started_at, "stats": engine.tracker.stats,
                "active_flows": len(engine.tracker.flows), "keep_days": args.keep_days}

    server = make_server(store, hub, status, port=args.port)
    drop_privileges(args.user, data_dir)
    _serve_in_background(server)
    print("Snitchy %s is watching. Dashboard: http://localhost:%d" % (__version__, args.port), flush=True)

    # launchd (brew services) stops us with SIGTERM; turn that into a clean exit.
    def on_sigterm(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, on_sigterm)
    try:
        code = run_with(engine, proc)
    except KeyboardInterrupt:
        code = 0
    finally:
        try:
            proc.stdout.close()          # tcpdump exits once nobody is reading
        except OSError:
            pass
    if code:
        sys.exit("tcpdump stopped unexpectedly (exit code %s); see messages above." % code)


def cmd_selftest(args):
    """Capture briefly; list connections live, then print each one as JSON."""
    if os.geteuid() != 0:
        sys.exit("selftest needs administrator rights:  sudo snitchy selftest")
    tmp = tempfile.mkdtemp(prefix="snitchy-selftest-")
    store = Store(os.path.join(tmp, "selftest.db"))
    engine = Engine(store, Hub(), include_loopback=args.include_loopback, resolve_ips=not args.no_rdns,
                    echo=True)
    proc = start_tcpdump()
    drop_privileges(args.user, tmp)
    print("Capturing for %d seconds... (open a website now)" % args.seconds, file=sys.stderr, flush=True)
    try:
        engine.run(proc, duration=args.seconds)
    finally:
        try:
            proc.stdout.close()
        except OSError:
            pass
    # Give background signature checks a moment, then save everything.
    deadline = time.time() + 15
    while time.time() < deadline and engine.signatures.pending():
        time.sleep(0.2)
    time.sleep(0.5)
    engine.tick(force=True)
    engine.flush(force=True)
    for row in reversed(store.query_connections(limit=1000)):
        print(json.dumps(row), flush=True)
    stats = engine.tracker.stats
    print("Done: %(packets)d packets, %(decoded)d decoded, %(flows)d connections." % stats,
          file=sys.stderr, flush=True)
    sys.exit(0 if stats["flows"] else 1)


def cmd_demo(args):
    """Serve the dashboard with realistic fake data, for previewing the UI."""
    from .demo import fill_demo_data, live_demo
    tmp = tempfile.mkdtemp(prefix="snitchy-demo-")
    store = Store(os.path.join(tmp, "demo.db"))
    fill_demo_data(store)
    hub = Hub()
    server = make_server(store, hub, lambda: {"version": __version__, "capturing": True, "demo": True,
                                               "started_at": time.time(), "stats": {}},
                         port=args.port)
    _serve_in_background(server)
    print("Demo dashboard (fake data): http://localhost:%d   (Ctrl+C to stop)" % args.port, flush=True)
    try:
        live_demo(store, hub)
    except KeyboardInterrupt:
        pass


def cmd_open(args):
    subprocess.run(["open", "http://localhost:%d" % args.port])


def main(argv=None):
    parser = argparse.ArgumentParser(prog="snitchy", description="Real-time per-app network log for macOS.")
    parser.add_argument("--version", action="version", version="snitchy " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    def capture_options(p):
        p.add_argument("--user", default="nobody",
                       help="user to switch to after starting capture (default: nobody)")
        p.add_argument("--include-loopback", action="store_true",
                       help="also log traffic between apps on this Mac (noisy)")
        p.add_argument("--no-rdns", action="store_true", help="don't look up owners of unnamed IPs")

    p = sub.add_parser("run", help="capture and serve the dashboard (needs sudo)")
    capture_options(p)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--data-dir", help="where the log is stored")
    p.add_argument("--keep-days", type=int, default=30, help="days of history to keep (0 = forever)")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("selftest", help="capture briefly and print connections (needs sudo)")
    capture_options(p)
    p.add_argument("--seconds", type=int, default=15)
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("demo", help="dashboard with fake data")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("open", help="open the dashboard in your browser")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.set_defaults(func=cmd_open)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
