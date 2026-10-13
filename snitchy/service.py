"""Install / remove Snitchy's background service, the safe way.

Why not `brew services`? Homebrew's files are owned by your normal user
account. A root service running code from there means anything that runs
as you (including malware) could edit that code and have it run as root
at the next restart. So instead, `sudo snitchy install-service`:

  1. copies Snitchy into /Library/Snitchy, owned by root (only an
     administrator, with your password, can change it),
  2. runs it with Apple's own Python (from the Command Line Tools, also
     root-owned), never Homebrew's,
  3. registers it with launchd so it starts at boot.

Run `sudo snitchy install-service` again after `brew upgrade snitchy` to
pick up the new version. Layout:

  /Library/Snitchy/app/snitchy/   the code (root:wheel, read-only to others)
  /Library/Snitchy/launch.py      tiny launcher that imports only from app/
  /Library/Snitchy/dashboard-token   the dashboard password (root + admins)
  /Library/Application Support/Snitchy/   the log (only the service can read it)
  /Library/LaunchDaemons/<LABEL>.plist     the launchd job
  /Library/Logs/Snitchy.log                service messages
"""

import grp
import os
import plistlib
import secrets
import shutil
import stat
import subprocess

APP_DIR = "/Library/Snitchy"
PKG_PARENT = os.path.join(APP_DIR, "app")
LAUNCHER = os.path.join(APP_DIR, "launch.py")
TOKEN_FILE = os.path.join(APP_DIR, "dashboard-token")
DATA_DIR = "/Library/Application Support/Snitchy"
LABEL = "io.github.djmarcuslaw.snitchy"
PLIST = "/Library/LaunchDaemons/%s.plist" % LABEL
LOG = "/Library/Logs/Snitchy.log"
# Labels `brew services` used for earlier versions of Snitchy.
OLD_BREW_LABELS = ("homebrew.mxcl.snitchy", "sh.brew.snitchy")

LAUNCHER_SOURCE = '''\
# Snitchy launcher (written by `snitchy install-service`).
# Run with `python3 -I`, which ignores environment variables and the
# current folder, so only the root-owned copy below can be imported.
sys.path.insert(0, %r)
from snitchy.cli import main
main()
'''


class ServiceError(Exception):
    pass


# --- Safety checks -------------------------------------------------------------

def _root_owned_chain(path):
    """True if `path` and every folder above it is owned by root and not
    writable by anyone else (so no other account could swap it out)."""
    path = os.path.realpath(path)            # judge the real file, not a symlink to it
    while True:
        st = os.lstat(path)
        if st.st_uid != 0:
            return False
        # Writable by others is only OK with the sticky bit (like /tmp),
        # which stops them replacing entries they don't own.
        if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) and not st.st_mode & stat.S_ISVTX:
            return False
        parent = os.path.dirname(path)
        if parent == path:
            return True
        path = parent


# Where Apple's Python 3 lives, most preferred first. The Command Line Tools
# copy (which Homebrew requires) is always installed by root; /usr/bin/python3
# points at whichever developer tools `xcode-select` chose, which can be an
# Xcode copy owned by a normal account.
PYTHON_CANDIDATES = (
    "/Library/Developer/CommandLineTools/usr/bin/python3",
    "/usr/bin/python3",
)


def _probe_python(candidate):
    """Return (real interpreter path, new enough?) or None if it doesn't run."""
    try:
        out = subprocess.run(
            [candidate, "-I", "-c",
             "import os, sys; print(os.path.realpath(sys.executable)); print(sys.version_info >= (3, 8))"],
            capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0 or len(out.stdout.split()) < 2:
        return None
    path, new_enough = out.stdout.split()[:2]
    return path, new_enough == "True"


def find_system_python():
    """Path of Apple's Python 3, verified to be root-owned all the way up."""
    rejected = []
    for candidate in PYTHON_CANDIDATES:
        if not os.path.exists(candidate):
            continue
        probe = _probe_python(candidate)
        if probe is None:
            continue
        path, new_enough = probe
        if not new_enough:
            rejected.append("%s (older than Python 3.8)" % path)
        elif not _root_owned_chain(path):
            rejected.append("%s (not owned by root)" % path)
        else:
            return path
    if rejected:
        raise ServiceError("Couldn't find a safe copy of Apple's Python. Skipped:\n  " + "\n  ".join(rejected)
                           + "\nInstall or update Apple's Command Line Tools:  xcode-select --install")
    raise ServiceError("Apple's Python isn't available. Install the Command Line Tools first:\n"
                       "    xcode-select --install")


def _ensure_root_dir(path, mode=0o755):
    """Create `path` as a real, root-owned folder (never following a symlink)."""
    if os.path.lexists(path):
        st = os.lstat(path)
        if not stat.S_ISDIR(st.st_mode):
            raise ServiceError("%s exists and isn't a folder; please remove it." % path)
    else:
        os.mkdir(path, mode)
    os.chown(path, 0, 0, follow_symlinks=False)
    os.chmod(path, mode)


def _lock_down_tree(top):
    """root:wheel ownership; folders 755, files 644; symlinks removed."""
    for root, dirs, files in os.walk(top):
        os.chown(root, 0, 0, follow_symlinks=False)
        os.chmod(root, 0o755)
        for name in files:
            p = os.path.join(root, name)
            if os.path.islink(p):
                os.unlink(p)
                continue
            os.chown(p, 0, 0, follow_symlinks=False)
            os.chmod(p, 0o644)


# --- Pieces ----------------------------------------------------------------------

def install_code():
    """Copy the running Snitchy package into the root-owned app folder."""
    source = os.path.dirname(os.path.abspath(__file__))           # .../snitchy
    _ensure_root_dir(APP_DIR)
    staging = os.path.join(APP_DIR, "app.new")
    if os.path.lexists(staging):
        shutil.rmtree(staging)
    os.mkdir(staging, 0o755)
    shutil.copytree(source, os.path.join(staging, "snitchy"), symlinks=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    _lock_down_tree(staging)
    if os.path.lexists(PKG_PARENT):
        shutil.rmtree(PKG_PARENT)
    os.rename(staging, PKG_PARENT)
    _write_root_file(LAUNCHER, (LAUNCHER_SOURCE % PKG_PARENT).encode(), 0o644)


def _write_root_file(path, data, mode, gid=0):
    """Atomically write a root-owned file (replacing, never following, any symlink)."""
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chown(tmp, 0, gid, follow_symlinks=False)
    os.chmod(tmp, mode)
    os.rename(tmp, path)


def ensure_token():
    """The dashboard password: readable by root and admin accounts only."""
    if os.path.lexists(TOKEN_FILE) and not os.path.islink(TOKEN_FILE):
        return
    _write_root_file(TOKEN_FILE, secrets.token_urlsafe(32).encode(), 0o640, gid=grp.getgrnam("admin").gr_gid)


def read_token(path):
    """Read a token file; returns None if it doesn't exist."""
    try:
        with open(path) as fh:
            return fh.read().strip() or None
    except FileNotFoundError:
        return None


def _launchctl(*args):
    return subprocess.run(["/bin/launchctl"] + list(args), capture_output=True, text=True)


def remove_old_brew_service():
    """Stop and remove a `brew services` job from an earlier Snitchy version."""
    removed = False
    for label in OLD_BREW_LABELS:
        plist = "/Library/LaunchDaemons/%s.plist" % label
        _launchctl("bootout", "system/" + label)
        if os.path.lexists(plist):
            os.unlink(plist)
            removed = True
    return removed


def write_plist(python, port, keep_days, extra_args):
    job = {
        "Label": LABEL,
        "ProgramArguments": [python, "-I", "-B", LAUNCHER, "run", "--data-dir", DATA_DIR,
                             "--token-file", TOKEN_FILE, "--port", str(port),
                             "--keep-days", str(keep_days)] + extra_args,
        "RunAtLoad": True,
        "KeepAlive": True,
        "WorkingDirectory": "/",
        "StandardOutPath": LOG,
        "StandardErrorPath": LOG,
    }
    _write_root_file(PLIST, plistlib.dumps(job), 0o644)


# --- Commands ----------------------------------------------------------------------

def install(port, keep_days, extra_args, keep_in_backups=False):
    if os.geteuid() != 0:
        raise ServiceError("Run this with sudo:  sudo snitchy install-service")
    python = find_system_python()
    if remove_old_brew_service():
        print("Removed the old `brew services` job (Snitchy no longer runs from Homebrew's folders).")
    install_code()
    ensure_token()
    if not os.path.lexists(DATA_DIR):
        os.mkdir(DATA_DIR, 0o700)
    if not keep_in_backups:
        # The log is a browsing history; keep it out of Time Machine backups.
        subprocess.run(["/usr/bin/tmutil", "addexclusion", DATA_DIR], capture_output=True)
    write_plist(python, port, keep_days, extra_args)
    _launchctl("bootout", "system/" + LABEL)
    result = _launchctl("bootstrap", "system", PLIST)
    if result.returncode != 0:
        raise ServiceError("launchd refused to start Snitchy: " + (result.stderr or result.stdout).strip())
    print("Snitchy is installed and running (it will also start at every boot).")
    print("Open the dashboard with:  snitchy open")


def uninstall(delete_data=False):
    if os.geteuid() != 0:
        raise ServiceError("Run this with sudo:  sudo snitchy uninstall-service")
    _launchctl("bootout", "system/" + LABEL)
    if os.path.lexists(PLIST):
        os.unlink(PLIST)
    if os.path.isdir(APP_DIR) and not os.path.islink(APP_DIR):
        shutil.rmtree(APP_DIR)
    if delete_data and os.path.isdir(DATA_DIR) and not os.path.islink(DATA_DIR):
        shutil.rmtree(DATA_DIR)
        print("Deleted the log.")
    print("Snitchy's background service is removed.")
