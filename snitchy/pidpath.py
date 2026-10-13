"""Tiny root helpers that answer two narrow questions for Snitchy.

Why this exists: Snitchy drops from root to the unprivileged `nobody` user
right after starting capture. But as `nobody` it can no longer
  * see the on-disk path of other users' processes, or
  * read programs inside your home folder (where sketchy software often
    lives) to check their signatures.

So before dropping root, Snitchy starts two helper processes that stay root
and do only this:

  path helper:  one process ID in  -> that program's path out
  sign helper:  one program path in -> its signature verdict out

Each is a separate process so a slow signature check never delays the
(time-critical) path lookups. Neither parses network data or talks to the
web dashboard, which keeps the part of Snitchy that still has root small.
"""

import subprocess
import sys
import threading

from . import appinfo


class _Helper:
    """Client side: start a helper (while still root) and ask it one-line questions."""

    def __init__(self, mode):
        self._proc = subprocess.Popen(
            [sys.executable, "-m", "snitchy.pidpath", mode],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self._lock = threading.Lock()

    def ask(self, question):
        with self._lock:
            if self._proc.poll() is not None:
                return None
            try:
                self._proc.stdin.write(question.replace("\n", " ") + "\n")
                self._proc.stdin.flush()
                return self._proc.stdout.readline().rstrip("\n")
            except (BrokenPipeError, OSError, ValueError):
                return None

    def close(self):
        try:
            self._proc.stdin.close()               # helper exits when input ends
        except OSError:
            pass


class PathHelper(_Helper):
    def __init__(self):
        super().__init__("path")

    def lookup(self, pid):
        if pid is None or pid <= 0:
            return ""
        answer = self.ask(str(pid))
        return appinfo.pid_path(pid) if answer is None else answer


class SignHelper(_Helper):
    def __init__(self):
        super().__init__("sign")

    def check(self, path):
        answer = self.ask(path)
        if not answer or "\t" not in answer:
            return appinfo.check_signature(path)   # helper gone: best effort
        signing, signer = answer.split("\t", 1)
        return signing, signer


def serve(mode):
    """Helper side: one question per line in, one answer per line out."""
    for line in sys.stdin:
        line = line.rstrip("\n")
        if mode == "path":
            try:
                answer = appinfo.pid_path(int(line))
            except ValueError:
                answer = ""
        else:
            signing, signer = appinfo.check_signature(line)
            answer = "%s\t%s" % (signing, signer)
        sys.stdout.write(answer.replace("\n", " ") + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    serve(sys.argv[1] if len(sys.argv) > 1 else "path")
