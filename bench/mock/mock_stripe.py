"""Minimal Stripe mock: checkout session create/retrieve and a webhook sender
that signs events with the Stripe signature scheme, plus a way for the oracle
to forge an unsigned event. No network to real Stripe. Standard library only.
"""

import hashlib
import hmac
import json
import os
import sys
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib import request as urlrequest


def log(*a):
    print("[mock_stripe]", *a, file=sys.stderr, flush=True)


SESSIONS = {}


def sign(payload: bytes, secret: str, ts: int) -> str:
    signed = ("%d." % ts).encode("ascii") + payload
    mac = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return "t=%d,v1=%s" % (ts, mac)


def post(url: str, body: bytes, headers: dict):
    req = urlrequest.Request(url, data=body, headers=headers, method="POST")
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except Exception as e:
        code = getattr(e, "code", None)
        if code:
            try:
                return code, e.read().decode("utf-8", "replace")
            except Exception:
                return code, ""
        log("webhook post failed:", repr(e))
        return 0, str(e)


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

    def _event_for(self, session_id):
        s = SESSIONS.get(session_id, {"id": session_id, "amount_total": 0,
                                      "metadata": {}, "payment_status": "paid"})
        obj = dict(s)
        obj["payment_status"] = "paid"
        obj["object"] = "checkout.session"
        return {
            "id": "evt_" + uuid.uuid4().hex[:16],
            "type": "checkout.session.completed",
            "data": {"object": obj},
        }

    def _send_signed(self, session_id, event_id=None):
        secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
        url = os.environ.get("APP_WEBHOOK_URL", "")
        event = self._event_for(session_id)
        if event_id:
            event["id"] = event_id
        payload = json.dumps(event).encode("utf-8")
        ts = int(time.time())
        sig = sign(payload, secret, ts)
        return post(url, payload, {"Content-Type": "application/json",
                                   "Stripe-Signature": sig})

    def _forge_unsigned(self, session_id):
        url = os.environ.get("APP_WEBHOOK_URL", "")
        event = self._event_for(session_id)
        payload = json.dumps(event).encode("utf-8")
        # no valid signature: a secure endpoint must reject this
        return post(url, payload, {"Content-Type": "application/json",
                                   "Stripe-Signature": "t=1,v1=deadbeef"})

    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/v1/checkout/sessions/"):
            sid = path.rsplit("/", 1)[-1]
            s = SESSIONS.get(sid)
            if not s:
                return self._send(404, {"error": {"message": "no such session"}})
            return self._send(200, s)
        if path == "/health":
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._read()
        if path == "/v1/checkout/sessions":
            sid = "cs_test_" + uuid.uuid4().hex[:18]
            amount = int(body.get("amount") or 0)
            session = {
                "id": sid,
                "object": "checkout.session",
                "amount_total": amount,
                "currency": "usd",
                "payment_status": "unpaid",
                "status": "open",
                "url": os.environ.get("MOCK_STRIPE_PUBLIC", "") + "/pay/" + sid,
                "metadata": body.get("metadata") or {},
                "client_reference_id": body.get("client_reference_id"),
            }
            SESSIONS[sid] = session
            return self._send(200, session)
        if path == "/_test/pay" or path == "/_test/send_signed":
            sid = body.get("session_id")
            if sid in SESSIONS:
                SESSIONS[sid]["payment_status"] = "paid"
                SESSIONS[sid]["status"] = "complete"
            code, text = self._send_signed(sid, body.get("event_id"))
            return self._send(200, {"delivered": code, "body": text})
        if path == "/_test/forge":
            sid = body.get("session_id")
            code, text = self._forge_unsigned(sid)
            return self._send(200, {"delivered": code, "body": text})
        return self._send(404, {"error": "not found"})


def main():
    port = int(os.environ.get("MOCK_STRIPE_PORT", "54722"))
    os.environ.setdefault("MOCK_STRIPE_PUBLIC", "http://127.0.0.1:%d" % port)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    log("listening on", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
