"""The connection log database (a single SQLite file).

Two tables:

  connections - one row per network connection (a "flow"): when, which app,
                where to, how much data.
  binaries    - one row per program on disk, with its code-signing verdict.
                Joined onto connections when the dashboard asks.

SQLite handles one writer plus many readers at once (WAL mode), so the
capture loop writes while the web dashboard reads.
"""

import os
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS connections (
    id           INTEGER PRIMARY KEY,
    ts_start     REAL NOT NULL,     -- when the connection began (unix time)
    ts_last      REAL NOT NULL,     -- last packet seen
    proto        TEXT NOT NULL,     -- tcp / udp
    direction    TEXT NOT NULL,     -- out = your Mac connected out; in = something connected in
    iface        TEXT,
    local_ip     TEXT, local_port  INTEGER,
    remote_ip    TEXT, remote_port INTEGER,
    domain       TEXT,              -- best-known hostname for remote_ip
    domain_source TEXT,             -- sni / dns / rdns
    app          TEXT,              -- friendly app name
    pid          INTEGER,
    path         TEXT,              -- program or .app bundle on disk
    via          TEXT,              -- helper process that actually sent it, if different
    bytes_out    INTEGER DEFAULT 0, bytes_in   INTEGER DEFAULT 0,
    packets_out  INTEGER DEFAULT 0, packets_in INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_conn_ts     ON connections(ts_start);
CREATE INDEX IF NOT EXISTS idx_conn_app    ON connections(app);
CREATE INDEX IF NOT EXISTS idx_conn_domain ON connections(domain);
CREATE INDEX IF NOT EXISTS idx_conn_path   ON connections(path);
CREATE INDEX IF NOT EXISTS idx_conn_ip     ON connections(remote_ip);

CREATE TABLE IF NOT EXISTS binaries (
    path       TEXT PRIMARY KEY,
    signing    TEXT,                -- apple / appstore / developer / adhoc / unsigned / invalid / unknown
    signer     TEXT,
    checked_at REAL
);
"""

# Signature verdicts the dashboard highlights as worth a second look.
FLAGGED = ("unsigned", "adhoc", "untrusted", "invalid")
# The same list as SQL text, for queries below. Built from fixed constants
# above (never from user input), so formatting it into SQL is safe.
_FLAGGED_SQL = ",".join("'%s'" % v for v in FLAGGED)

_COLUMNS = ("c.id, c.ts_start, c.ts_last, c.proto, c.direction, c.iface, c.local_ip, c.local_port, "
            "c.remote_ip, c.remote_port, c.domain, c.domain_source, c.app, c.pid, c.path, c.via, "
            "c.bytes_out, c.bytes_in, c.packets_out, c.packets_in, b.signing, b.signer")


def _row_dict(row):
    return dict(row)


class Store:
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        self._write_lock = threading.Lock()
        db = self._db()
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript(SCHEMA)
        db.commit()

    def _db(self):
        """One connection per thread (sqlite3 connections aren't thread-safe)."""
        db = getattr(self._local, "db", None)
        if db is None:
            db = sqlite3.connect(self.path, timeout=30)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA synchronous=NORMAL")
            self._local.db = db
        return db

    # --- Writes (capture side) ----------------------------------------------

    def insert_connections(self, flows):
        """Insert new flows; sets flow.row_id on each."""
        if not flows:
            return
        with self._write_lock:
            db = self._db()
            for f in flows:
                cur = db.execute(
                    "INSERT INTO connections (ts_start, ts_last, proto, direction, iface, local_ip, local_port,"
                    " remote_ip, remote_port, domain, domain_source, app, pid, path, via,"
                    " bytes_out, bytes_in, packets_out, packets_in)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f.ts_start, f.ts_last, f.proto, f.direction, f.iface, f.local_ip, f.local_port,
                     f.remote_ip, f.remote_port, f.domain, f.domain_source, f.app, f.pid, f.path, f.via,
                     f.bytes_out, f.bytes_in, f.packets_out, f.packets_in))
                f.row_id = cur.lastrowid
            db.commit()

    def update_connections(self, flows):
        if not flows:
            return
        with self._write_lock:
            db = self._db()
            db.executemany(
                "UPDATE connections SET ts_last=?, domain=?, domain_source=?, app=?, pid=?, path=?, via=?,"
                " bytes_out=?, bytes_in=?, packets_out=?, packets_in=? WHERE id=?",
                [(f.ts_last, f.domain, f.domain_source, f.app, f.pid, f.path, f.via,
                  f.bytes_out, f.bytes_in, f.packets_out, f.packets_in, f.row_id)
                 for f in flows if f.row_id is not None])
            db.commit()

    def save_signature(self, path, signing, signer):
        with self._write_lock:
            db = self._db()
            db.execute("INSERT OR REPLACE INTO binaries (path, signing, signer, checked_at) VALUES (?,?,?,?)",
                       (path, signing, signer, time.time()))
            db.commit()

    def fill_domain(self, ip, name, source):
        """Give a hostname to every logged connection to `ip` that has none."""
        with self._write_lock:
            db = self._db()
            db.execute("UPDATE connections SET domain=?, domain_source=? WHERE remote_ip=? AND domain IS NULL",
                       (name, source, ip))
            db.commit()

    def known_signature(self, path):
        row = self._db().execute("SELECT signing, signer, checked_at FROM binaries WHERE path=?",
                                 (path,)).fetchone()
        return dict(row) if row else None

    def prune(self, keep_days):
        """Delete connections older than `keep_days` (0 or less = keep forever)."""
        if keep_days <= 0:
            return 0
        cutoff = time.time() - keep_days * 86400
        with self._write_lock:
            db = self._db()
            n = db.execute("DELETE FROM connections WHERE ts_start < ?", (cutoff,)).rowcount
            db.commit()
        return n

    # --- Reads (dashboard side) ---------------------------------------------

    def get_connections(self, ids):
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        rows = self._db().execute(
            "SELECT %s FROM connections c LEFT JOIN binaries b ON b.path = c.path WHERE c.id IN (%s)"
            % (_COLUMNS, marks), list(ids)).fetchall()
        return [_row_dict(r) for r in rows]

    def query_connections(self, since=None, until=None, search="", app="", domain="",
                          flagged=False, direction="", before_id=None, limit=200):
        where, args = [], []
        if since is not None:
            where.append("c.ts_start >= ?"); args.append(since)
        if until is not None:
            where.append("c.ts_start < ?"); args.append(until)
        if app:
            where.append("c.app = ?"); args.append(app)
        if domain:
            where.append("c.domain = ?"); args.append(domain)
        if direction in ("in", "out"):
            where.append("c.direction = ?"); args.append(direction)
        if flagged:
            where.append("b.signing IN (%s)" % ",".join("?" * len(FLAGGED))); args.extend(FLAGGED)
        if before_id:
            where.append("c.id < ?"); args.append(before_id)
        if search:
            like = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            where.append("(c.app LIKE ? ESCAPE '\\' OR c.domain LIKE ? ESCAPE '\\' OR c.remote_ip LIKE ? ESCAPE '\\'"
                         " OR c.path LIKE ? ESCAPE '\\' OR c.via LIKE ? ESCAPE '\\')")
            args.extend([like] * 5)
        sql = "SELECT %s FROM connections c LEFT JOIN binaries b ON b.path = c.path" % _COLUMNS
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY c.id DESC LIMIT ?"
        args.append(max(1, min(int(limit), 1000)))
        return [_row_dict(r) for r in self._db().execute(sql, args).fetchall()]

    def summary(self, since, until, bucket_seconds):
        """Numbers for the dashboard's tiles, chart and top-10 lists."""
        db = self._db()
        span = (since, until)
        totals = db.execute(
            "SELECT COUNT(*) AS connections, COUNT(DISTINCT c.app) AS apps,"
            " COUNT(DISTINCT COALESCE(c.domain, c.remote_ip)) AS destinations,"
            " COALESCE(SUM(c.bytes_out),0) AS bytes_out, COALESCE(SUM(c.bytes_in),0) AS bytes_in,"
            " SUM(CASE WHEN b.signing IN (%s) THEN 1 ELSE 0 END) AS flagged,"
            " SUM(CASE WHEN c.domain IS NULL THEN 1 ELSE 0 END) AS unnamed"
            " FROM connections c LEFT JOIN binaries b ON b.path = c.path"
            " WHERE c.ts_start >= ? AND c.ts_start < ?" % _FLAGGED_SQL, span).fetchone()
        timeline = db.execute(
            "SELECT CAST((ts_start - ?) / ? AS INTEGER) AS bucket, COUNT(*) AS n FROM connections"
            " WHERE ts_start >= ? AND ts_start < ? GROUP BY bucket ORDER BY bucket",
            (since, bucket_seconds, since, until)).fetchall()
        top_apps = db.execute(
            "SELECT c.app AS name, COUNT(*) AS n, MAX(b.signing) AS signing, MAX(b.signer) AS signer,"
            " MAX(c.path) AS path, COUNT(DISTINCT COALESCE(c.domain, c.remote_ip)) AS destinations"
            " FROM connections c LEFT JOIN binaries b ON b.path = c.path"
            " WHERE c.ts_start >= ? AND c.ts_start < ? GROUP BY c.app ORDER BY n DESC LIMIT 10", span).fetchall()
        top_domains = db.execute(
            "SELECT COALESCE(domain, remote_ip) AS name, domain IS NULL AS is_ip, COUNT(*) AS n,"
            " COUNT(DISTINCT app) AS apps FROM connections"
            " WHERE ts_start >= ? AND ts_start < ? GROUP BY name ORDER BY n DESC LIMIT 10", span).fetchall()
        flagged_apps = db.execute(
            "SELECT c.app AS name, c.path AS path, b.signing AS signing, COUNT(*) AS n, MAX(c.ts_start) AS last_seen"
            " FROM connections c JOIN binaries b ON b.path = c.path"
            " WHERE c.ts_start >= ? AND c.ts_start < ? AND b.signing IN (%s)"
            " GROUP BY c.path ORDER BY n DESC LIMIT 10" % _FLAGGED_SQL, span).fetchall()
        n_buckets = max(1, int((until - since) // bucket_seconds))
        counts = [0] * n_buckets
        for row in timeline:
            if 0 <= row["bucket"] < n_buckets:
                counts[row["bucket"]] = row["n"]
        return {
            "since": since, "until": until, "bucket_seconds": bucket_seconds,
            "totals": {k: (totals[k] or 0) for k in totals.keys()},
            "timeline": counts,
            "top_apps": [dict(r) for r in top_apps],
            "top_domains": [dict(r) for r in top_domains],
            "flagged_apps": [dict(r) for r in flagged_apps],
        }
