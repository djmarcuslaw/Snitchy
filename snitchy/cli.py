"""Command-line entry point: `snitchy <command>`.

  snitchy install-service    install/update the background service (sudo)
  snitchy uninstall-service  remove it (sudo)
  snitchy open               open the dashboard in your browser (signs you in)
  snitchy selftest           capture for a few seconds and print what was seen (sudo)
  snitchy run                capture + dashboard in the foreground (sudo)
  snitchy demo               dashboard with made-up data (no root, nothing captured)
"""

import argparse
import json
import os
import pwd
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time

from . import __version__, service
from .capture import Engine, Hub, run_with, start_tcpdump
from .pidpath import PathHelper, SignHelper
from .server import make_server
from .store import Store

DEFAULT_PORT = 8899


def default_data_dir():
    if os.geteuid() == 0:
        return service.DATA_DIR
    return os.path.expanduser("~/Library/Application Support/Snitchy")


def prepare_data_dir(data_dir, username):
    """Make the log folder private to the account Snitchy will run as.

    Runs as root, so it is careful: it refuses a folder that is really a
    symlink, and never follows symlinks inside it (otherwise a planted link
    could trick root into handing over some other file).
    """
    if os.path.islink(data_dir):
        sys.exit("Refusing to use %s: it is a symlink." % data_dir)
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    if os.geteuid() != 0:
        os.chmod(data_dir, 0o700)
        return
    user = pwd.getpwnam(username or "root")
    os.chown(data_dir, user.pw_uid, user.pw_gid, follow_symlinks=False)
    os.chmod(data_dir, 0o700)                      # only Snitchy (and root) can look inside
    for name in os.listdir(data_dir):
        path = os.path.join(data_dir, name)
        st = os.lstat(path)
        if stat.S_ISREG(st.st_mode):               # skip symlinks and anything odd
            os.chown(path, user.pw_uid, user.pw_gid, follow_symlinks=False)
            os.chmod(path, 0o600)


def drop_privileges(username):
    """Stop being root.

    tcpdump and the two small helpers have already started as root and keep
    running; from here on, Snitchy's own code (parsing, database, web
    server) runs as an ordinary user, so a bug in it can't take over your Mac.
    """
    if os.geteuid() != 0 or not username or username == "root":
        return
    user = pwd.getpwnam(username)
    os.setgroups([])
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)


def root_helpers(username):
    """How to look up program paths and signatures once we're no longer root.

    If we're about to drop root, start the two small root helpers
    (pidpath.py) first; otherwise just do the work directly.
    Returns (path_lookup, sign_check).
    """
    from . import appinfo
    if os.geteuid() == 0 and username and username != "root":
        return PathHelper().lookup, SignHelper().check
    return appinfo.pid_path, appinfo.check_signature


def _serve_in_background(server):
    threading.Thread(target=server.serve_forever, name="http", daemon=True).start()


def load_dashboard_token(token_file):
    """The dashboard password: from the service's token file, or a fresh one."""
    token = service.read_token(token_file) if token_file else None
    return token or secrets.token_urlsafe(32)


def cmd_run(args):
    if os.geteuid() != 0:
        sys.exit("snitchy run needs administrator rights to capture traffic.\n"
                 "Try:  sudo snitchy install-service   (or, in the foreground: sudo snitchy run)")
    os.umask(0o077)                                  # new files: readable by Snitchy only
    data_dir = args.data_dir or default_data_dir()
    prepare_data_dir(data_dir, args.user)
    token = load_dashboard_token(args.token_file)
    # Everything that needs root starts now...
    path_lookup, sign_check = root_helpers(args.user)
    proc = start_tcpdump()
    # ...then root is dropped before touching the database or the network.
    drop_privileges(args.user)
    store = Store(os.path.join(data_dir, "snitchy.db"))
    hub = Hub()
    engine = Engine(store, hub, keep_days=args.keep_days, include_loopback=args.include_loopback,
                    resolve_ips=not args.no_rdns, path_lookup=path_lookup, sign_check=sign_check)

    def status():
        return {"version": __version__, "capturing": proc.poll() is None,
                "started_at": engine.started_at, "stats": engine.tracker.stats,
                "active_flows": len(engine.tracker.flows), "keep_days": args.keep_days}

    server = make_server(store, hub, status, port=args.port, token=token)
    _serve_in_background(server)
    print("Snitchy %s is watching." % __version__, flush=True)
    if not args.token_file:
        print("Dashboard: http://localhost:%d/login?token=%s" % (args.port, token), flush=True)

    # launchd stops us with SIGTERM; turn that into a clean exit.
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
    os.umask(0o077)
    # /private/tmp, not your personal temp folder: the unprivileged account
    # Snitchy switches to must be able to reach it.
    tmp = tempfile.mkdtemp(prefix="snitchy-selftest-",
                           dir="/private/tmp" if os.path.isdir("/private/tmp") else None)
    prepare_data_dir(tmp, args.user)
    path_lookup, sign_check = root_helpers(args.user)
    proc = start_tcpdump()
    drop_privileges(args.user)
    store = Store(os.path.join(tmp, "selftest.db"))
    engine = Engine(store, Hub(), include_loopback=args.include_loopback, resolve_ips=not args.no_rdns,
                    echo=True, path_lookup=path_lookup, sign_check=sign_check)
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
    """Open the dashboard, signing in with the service's token."""
    url = "http://localhost:%d" % args.port
    try:
        token = service.read_token(args.token_file)
    except PermissionError:
        sys.exit("Only administrator accounts can open the Snitchy dashboard.\n"
                 "(Or try:  sudo snitchy open)")
    if token:
        url += "/login?token=" + token
    subprocess.run(["/usr/bin/open", url])


def cmd_install_service(args):
    extra = []
    if args.include_loopback:
        extra.append("--include-loopback")
    if args.no_rdns:
        extra.append("--no-rdns")
    try:
        service.install(args.port, args.keep_days, extra, keep_in_backups=args.keep_in_backups)
    except service.ServiceError as exc:
        sys.exit(str(exc))


def cmd_uninstall_service(args):
    try:
        service.uninstall(delete_data=args.delete_data)
    except service.ServiceError as exc:
        sys.exit(str(exc))


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

    p = sub.add_parser("install-service", help="install or update the background service (needs sudo)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--keep-days", type=int, default=30, help="days of history to keep (0 = forever)")
    p.add_argument("--include-loopback", action="store_true", help="also log traffic between apps on this Mac")
    p.add_argument("--no-rdns", action="store_true", help="don't look up owners of unnamed IPs")
    p.add_argument("--keep-in-backups", action="store_true",
                   help="let Time Machine back up the log (excluded by default)")
    p.set_defaults(func=cmd_install_service)

    p = sub.add_parser("uninstall-service", help="remove the background service (needs sudo)")
    p.add_argument("--delete-data", action="store_true", help="also delete the log")
    p.set_defaults(func=cmd_uninstall_service)

    p = sub.add_parser("run", help="capture and serve the dashboard in the foreground (needs sudo)")
    capture_options(p)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--data-dir", help="where the log is stored")
    p.add_argument("--token-file", help="file holding the dashboard password (default: print a new one)")
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
    p.add_argument("--token-file", default=service.TOKEN_FILE, help=argparse.SUPPRESS)
    p.set_defaults(func=cmd_open)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
