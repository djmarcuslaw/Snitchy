"""The local web dashboard (http://localhost:8899).

Plain Python standard library, no frameworks. Endpoints:

  GET /                    the dashboard page (files in snitchy/web/)
  GET /api/summary         numbers, chart and top-10 lists for a time range
  GET /api/connections     the log itself, newest first, with filters
  GET /api/stream          live feed (Server-Sent Events) of new connections
  GET /api/status          is capture running, how many packets so far

Safety: the server only listens on 127.0.0.1, so nothing else on your
network can reach it, and it rejects requests whose Host header isn't
localhost (this blocks a trick called "DNS rebinding" where a website tries
to talk to servers on your own machine). Everything is read-only.
"""

import json
import os
import queue
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
CONTENT_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml"}

RANGES = {                      # name -> (seconds covered, chart bar width)
    "1h": (3600, 60),
    "24h": (86400, 1800),
    "7d": (7 * 86400, 6 * 3600),
    "30d": (30 * 86400, 86400),
}


def make_server(store, hub, status, host="127.0.0.1", port=8899):
    """Build (but don't start) the HTTP server. `status` is a callable -> dict."""

    allowed_hosts = {"localhost", "127.0.0.1", "[::1]", host}

    class Handler(BaseHTTPRequestHandler):
        server_version = "Snitchy"

        def log_message(self, fmt, *args):     # keep the service log quiet
            pass

        # --- helpers ---------------------------------------------------------
        def _send(self, code, body, content_type="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:")
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self):
            host = self.headers.get("Host") or ""
            # Strip the port: "localhost:8899" -> "localhost", "[::1]:8899" -> "[::1]"
            name = host.split("]")[0] + "]" if host.startswith("[") else host.split(":")[0]
            return name in allowed_hosts

        # --- routing ---------------------------------------------------------
        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "forbidden host"})
            url = urlparse(self.path)
            params = {k: v[-1] for k, v in parse_qs(url.query).items()}
            try:
                if url.path == "/api/summary":
                    return self._summary(params)
                if url.path == "/api/connections":
                    return self._connections(params)
                if url.path == "/api/stream":
                    return self._stream()
                if url.path == "/api/status":
                    return self._send(200, status())
                return self._static(url.path)
            except (ValueError, KeyError) as exc:
                return self._send(400, {"error": str(exc)})

        def _range(self, params):
            seconds, bucket = RANGES.get(params.get("range", "24h"), RANGES["24h"])
            until = time.time()
            until = (until // bucket + 1) * bucket       # line chart bars up with the clock
            return until - seconds, until, bucket

        def _summary(self, params):
            since, until, bucket = self._range(params)
            self._send(200, store.summary(since, until, bucket))

        def _connections(self, params):
            since, until, _ = self._range(params) if params.get("range") else (None, None, None)
            rows = store.query_connections(
                since=since, until=until, search=params.get("q", "").strip(),
                app=params.get("app", ""), domain=params.get("domain", ""),
                flagged=params.get("flagged") == "1", direction=params.get("direction", ""),
                before_id=int(params["before"]) if params.get("before") else None,
                limit=int(params.get("limit", 200)))
            self._send(200, {"rows": rows})

        def _stream(self):
            q = hub.subscribe()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(b"retry: 3000\n\n")
                self.wfile.flush()
                while True:
                    try:
                        event = q.get(timeout=15)
                        self.wfile.write(b"data: " + json.dumps(event).encode() + b"\n\n")
                    except queue.Empty:
                        self.wfile.write(b": keep-alive\n\n")   # stops idle timeouts
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass                                            # tab closed
            finally:
                hub.unsubscribe(q)

        def _static(self, path):
            name = "index.html" if path in ("/", "") else path.lstrip("/")
            full = os.path.realpath(os.path.join(WEB_DIR, name))
            if not full.startswith(os.path.realpath(WEB_DIR) + os.sep) or not os.path.isfile(full):
                return self._send(404, {"error": "not found"})
            with open(full, "rb") as fh:
                body = fh.read()
            self._send(200, body, CONTENT_TYPES.get(os.path.splitext(full)[1], "application/octet-stream"))

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server
