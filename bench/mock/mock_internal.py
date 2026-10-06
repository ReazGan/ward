"""Stands in for internal/link-local services an SSRF would reach, and for an
attacker collector an exfiltration tool would post to. Records every hit so the
oracle can tell whether a request was made. Standard library only.
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

_lock = threading.Lock()
HITS = []  # list of {"method","path","body"}
SECRET_MARKER = "WARD_METADATA_TOKEN_a1b2c3"


def log(*a):
    print("[mock_internal]", *a, file=sys.stderr, flush=True)


def record(method, path, body):
    with _lock:
        HITS.append({"method": method, "path": path, "body": body})


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj, content_type="application/json"):
        if isinstance(obj, (dict, list)):
            body = json.dumps(obj).encode("utf-8")
        else:
            body = str(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/_hits":
            with _lock:
                return self._send(200, list(HITS))
        if path == "/_reset":
            with _lock:
                HITS.clear()
            return self._send(200, {"ok": True})
        if path == "/health":
            return self._send(200, {"ok": True})
        record("GET", path, None)
        if path.startswith("/latest/meta-data"):
            # cloud metadata style response
            return self._send(200, SECRET_MARKER + " role=app-server", content_type="text/plain")
        return self._send(200, "ok", content_type="text/plain")

    def do_POST(self):
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        record("POST", path, raw.decode("utf-8", "replace"))
        return self._send(200, {"ok": True})


def main():
    port = int(os.environ.get("MOCK_INTERNAL_PORT", "54724"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    log("listening on", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
