"""Tests for live-exposure-check/check_live.py.

A stdlib http.server runs on 127.0.0.1 in a background thread and serves a
crafted, deliberately leaky app: a page with a same-origin bundle that holds a
fake service_role JWT (built at runtime), a public anon JWT and a Stripe
publishable key as decoys, a reachable /.env and /.git/HEAD, a source map, bad
CORS, a weak cookie, a debug error page, an unverified Stripe webhook, an
unthrottled endpoint, and a Supabase-style REST table. Each real check must
fire; each decoy must stay quiet. The host guard is tested without touching the
network.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "skills" / "live-exposure-check" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import check_live  # noqa: E402
from conftest import _fake_token as tok  # noqa: E402
from conftest import _make_jwt as jwt  # noqa: E402

# Planted values, all fake and built at import time (never realistic literals).
SERVICE_JWT = jwt({"role": "service_role", "iss": "supabase"})
ANON_JWT = jwt({"role": "anon", "iss": "supabase", "ref": "abcdefghijklmnopqrst"})
STRIPE_PK = "pk_" + "live_" + tok()
ENV_SECRET = "sk_" + "live_" + tok()
ANON_KEY = "sb_" + "publishable_" + tok()

PAGE_HTML = (
    "<!DOCTYPE html><html><head><title>demo</title></head><body>"
    "<div id=root></div>"
    '<script src="/_next/static/chunks/main.js"></script>'
    '<script>self.__next_f.push([1,"hydrate"])</script>'
    "</body></html>"
).encode("utf-8")

BUNDLE_JS = (
    "export const u='https://x.supabase.co';\n"
    "export const svc='%s';\n"      # planted service_role key -> must fire
    "export const anon='%s';\n"     # decoy: public anon key -> must not fire
    "export const pk='%s';\n"       # decoy: Stripe publishable key -> must not fire
    "//# sourceMappingURL=/_next/static/chunks/main.js.map\n"
) % (SERVICE_JWT, ANON_JWT, STRIPE_PK)
BUNDLE_JS = BUNDLE_JS.encode("utf-8")

SOURCE_MAP = json.dumps({
    "version": 3, "sources": ["src/app.ts"], "names": [],
    "sourcesContent": ["const secret = process.env.OPENAI_API_KEY"], "mappings": "AAAA",
}).encode("utf-8")

SHORT_SECRET = tok()[:7]           # a short value: must not appear in the evidence either
DB_PASSWORD = tok()[3:16]
ENV_BODY = ("STRIPE_SECRET_KEY=%s\nDATABASE_URL=postgres://appuser:%s@db.example.com:5432/app\n"
            "SESSION_SECRET=%s\n" % (ENV_SECRET, DB_PASSWORD, SHORT_SECRET)).encode("utf-8")
BEARER = "test-session-" + tok()[:10]
GIT_HEAD = b"ref: refs/heads/main\n"
DEBUG_PAGE = (
    "<!DOCTYPE html><html><body><h1>Server Error</h1>"
    "<p>You're seeing this error because you have <code>DEBUG = True</code> in your settings.</p>"
    "</body></html>"
).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep the test output quiet
        return

    def _send(self, status, body=b"", ctype="text/plain", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _cors_extra(self):
        origin = self.headers.get("Origin")
        if origin:
            return [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]
        return []

    def do_OPTIONS(self):
        self._send(204, b"", extra=self._cors_extra())

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            extra = [("Set-Cookie", "session=%s; Path=/" % tok())] + self._cors_extra()
            return self._send(200, PAGE_HTML, "text/html", extra)
        if path == "/_next/static/chunks/main.js":
            return self._send(200, BUNDLE_JS, "application/javascript")
        if path == "/_next/static/chunks/main.js.map":
            return self._send(200, SOURCE_MAP, "application/json")
        if path == "/.env":
            return self._send(200, ENV_BODY, "text/plain")
        if path == "/.git/HEAD":
            return self._send(200, GIT_HEAD, "text/plain")
        if path == "/fixed-cors":
            # A fixed allow-list that does not echo our probe origin: must NOT fire.
            return self._send(200, b"ok", extra=[("Access-Control-Allow-Origin", "https://trusted.example"),
                                                  ("Access-Control-Allow-Credentials", "true")])
        if path.startswith("/rest/v1/"):
            table = path[len("/rest/v1/"):]
            if table == "secrets":
                rows = [{"id": 1, "value": "x"}, {"id": 2, "value": "y"}]
                return self._send(200, json.dumps(rows).encode("utf-8"), "application/json")
            if table == "badkey":
                return self._send(401, b'{"message":"Invalid API key"}', "application/json")
            if table == "nogrant":
                return self._send(401, b'{"code":"42501","message":"permission denied for table nogrant"}',
                                  "application/json")
            if table == "missing":
                return self._send(404, b'{"code":"PGRST205","message":"Could not find the table"}',
                                  "application/json")
            return self._send(200, b"[]", "application/json")  # closed table decoy
        if path.startswith("/v1/projects/demo-proj/databases/(default)/documents/"):
            coll = path.rsplit("/", 1)[-1]
            if coll == "open":
                return self._send(200, b'{"documents":[{"name":"x"}]}', "application/json")
            return self._send(403, b'{"error":{"status":"PERMISSION_DENIED"}}', "application/json")
        if path.startswith("/rtdb/"):
            if path == "/rtdb/open.json":
                return self._send(200, b'{"a":true}', "application/json")
            return self._send(401, b'{"error":"Permission denied"}', "application/json")
        if path.startswith("/rtdb-gone/"):
            return self._send(404, b'{"error":"Firebase error. Please ensure that you have the URL of your '
                                   b'Firebase Realtime Database instance configured correctly."}', "application/json")
        # Everything else is the SPA / debug fallback: 200 HTML. The files check
        # must treat this as "not exposed", and the debug check must fire on it.
        return self._send(200, DEBUG_PAGE, "text/html", self._cors_extra())

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if path == "/api/stripe/webhook":
            return self._send(200, b'{"received":true}', "application/json")  # accepts forged -> fire
        if path == "/api/stripe/webhook-safe":
            return self._send(400, b"bad signature")                           # verifies -> no fire
        if path == "/api/chat":
            return self._send(200, b'{"reply":"hi"}', "application/json")       # no limiter -> fire
        if path == "/api/chat-limited":
            self.server.hits = getattr(self.server, "hits", 0) + 1
            if self.server.hits > 3:
                return self._send(429, b"slow down")
            return self._send(200, b"ok")
        if path == "/api/chat-auth":
            return self._send(401, b"unauthorized")                            # auth blocks -> no fire
        if path == "/api/stripe/webhook-crash":
            return self._send(500, b"boom")
        if path == "/api/stripe/webhook-get-only":
            return self._send(405, b"method not allowed")
        if path == "/api/stripe/webhook-moved":
            return self._send(302, b"", extra=[("Location", "/login")])
        if path == "/api/chat-validates":
            try:
                ok = "message" in json.loads(body or b"{}")
            except ValueError:
                ok = False
            return self._send(200 if ok else 400, b"{}" if ok else b"bad input", "application/json")
        if path == "/api/chat-session":
            if self.headers.get("Authorization") == "Bearer " + BEARER:
                return self._send(200, b'{"reply":"hi"}', "application/json")
            return self._send(401, b"unauthorized")
        return self._send(404, b"not found")


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    try:
        yield "http://127.0.0.1:%d" % port
    finally:
        httpd.shutdown()
        httpd.server_close()


def by_rule(findings):
    out = {}
    for f in findings:
        out.setdefault(f.rule, []).append(f)
    return out


# --- host guard (no network) --------------------------------------------------

def test_host_guard_refuses_other_host():
    host, ok = check_live.check_host("https://example.com", None)
    assert host == "example.com" and ok is False


def test_host_guard_accepts_with_flag_no_connection():
    host, ok = check_live.check_host("https://example.com", "example.com")
    assert host == "example.com" and ok is True


def test_host_guard_accepts_localhost():
    assert check_live.check_host("http://127.0.0.1:3000")[1] is True
    assert check_live.check_host("http://app.localhost:3000")[1] is True
    assert check_live.check_host("https://staging.test")[1] is True


def test_cli_refuses_example_com_exit_3(run_script):
    r = run_script("check_live.py", "--json", "https://example.com", skill="live-exposure-check")
    assert r.returncode == check_live.wc.EXIT_REFUSED
    assert "refused" in r.stderr.lower()


# --- always-on checks fire, decoys stay quiet ---------------------------------

def test_bundle_finds_service_role_not_public_keys(server):
    findings, warnings, meta = check_live.run(server, checks=["bundle"])
    rules = by_rule(findings)
    assert "supabase-service-role-jwt" in rules
    f = rules["supabase-service-role-jwt"][0]
    assert f.severity == "critical"
    # decoys: the anon JWT and the publishable key are counted, never reported
    assert "supabase-anon-jwt" not in rules
    assert "stripe-publishable-key" not in rules
    # no raw secret value leaks into the report
    assert SERVICE_JWT not in json.dumps([x.to_dict() for x in findings])
    pub = meta.get("public_keys_in_bundle", {})
    assert pub.get("supabase-anon-jwt") == 1 and pub.get("stripe-publishable-key") == 1


def test_files_finds_env_and_git_not_spa_fallback(server):
    findings, warnings, meta = check_live.run(server, checks=["files"])
    exposed = [f.extra.get("path") for f in findings if f.rule == "exposed-file"]
    assert "/.env" in exposed
    assert "/.git/HEAD" in exposed
    # the SPA/debug fallback answers 200 with HTML for these, so they must not be flagged
    assert "/backup.zip" not in exposed and "/.DS_Store" not in exposed
    env_find = [f for f in findings if f.extra.get("path") == "/.env"][0]
    assert env_find.severity == "critical"
    dumped = json.dumps([x.to_dict() for x in findings])
    for value in (ENV_SECRET, DB_PASSWORD, SHORT_SECRET, "appuser", "db.example.com"):
        assert value not in dumped, value
    assert env_find.evidence == "keys: STRIPE_SECRET_KEY, DATABASE_URL, SESSION_SECRET (values hidden)"


def test_maps_finds_public_source_map(server):
    findings, warnings, meta = check_live.run(server, checks=["bundle", "maps"])
    rules = by_rule(findings)
    assert "source-map-exposed" in rules
    assert rules["source-map-exposed"][0].severity == "high"  # has sourcesContent


def test_headers_reports_missing(server):
    findings, warnings, meta = check_live.run(server, checks=["headers"])
    rules = by_rule(findings)
    assert "missing-security-headers" in rules
    ev = rules["missing-security-headers"][0].evidence
    assert "Content-Security-Policy" in ev


def test_cookies_flags_weak_cookie(server):
    findings, warnings, meta = check_live.run(server, checks=["cookies"])
    rules = by_rule(findings)
    assert "weak-cookie" in rules
    assert "no HttpOnly" in rules["weak-cookie"][0].message


def test_cors_reflects_arbitrary_origin(server):
    findings, warnings, meta = check_live.run(server, checks=["cors"])
    rules = by_rule(findings)
    assert "cors-reflects-origin-with-credentials" in rules
    assert rules["cors-reflects-origin-with-credentials"][0].severity == "high"


def test_cors_fixed_allowlist_not_flagged(server):
    findings, warnings, meta = check_live.run(server, checks=["cors"], cors_path="fixed-cors")
    assert [f for f in findings if f.rule.startswith("cors-")] == []


def test_debug_page_detected(server):
    findings, warnings, meta = check_live.run(server, checks=["debug"])
    rules = by_rule(findings)
    assert "debug-mode-enabled" in rules


# --- opt-in checks ------------------------------------------------------------

def test_webhook_accepts_forged(server):
    findings, warnings, meta = check_live.run(server, checks=["webhook"], webhook_path="/api/stripe/webhook")
    rules = by_rule(findings)
    assert "webhook-accepts-forged" in rules
    assert rules["webhook-accepts-forged"][0].severity == "critical"


def test_webhook_verified_not_flagged(server):
    findings, warnings, meta = check_live.run(server, checks=["webhook"], webhook_path="/api/stripe/webhook-safe")
    assert [f for f in findings if f.rule == "webhook-accepts-forged"] == []


def test_ratelimit_unthrottled_fires(server):
    findings, warnings, meta = check_live.run(server, checks=["ratelimit"], ratelimit_path="/api/chat", ratelimit_n=8)
    rules = by_rule(findings)
    assert "no-rate-limit" in rules
    # A clean burst only proves there is no limit at or below N, not none at all.
    msg = rules["no-rate-limit"][0].message
    assert "at or below 8 per window" in msg and "higher --n" in msg


def test_ratelimit_with_429_not_flagged(server):
    findings, warnings, meta = check_live.run(server, checks=["ratelimit"], ratelimit_path="/api/chat-limited", ratelimit_n=8)
    assert [f for f in findings if f.rule == "no-rate-limit"] == []


def test_ratelimit_auth_blocked_not_flagged(server):
    findings, warnings, meta = check_live.run(server, checks=["ratelimit"], ratelimit_path="/api/chat-auth", ratelimit_n=8)
    assert [f for f in findings if f.rule == "no-rate-limit"] == []


def test_ratelimit_caps_burst(server):
    findings, warnings, meta = check_live.run(server, checks=["ratelimit"], ratelimit_path="/api/chat",
                                              ratelimit_n=100000)
    sent = meta["ratelimit"]["/api/chat"]["sent"]
    assert sent <= check_live.MAX_RATELIMIT


def test_baas_open_table_fires_closed_table_quiet(server):
    findings, warnings, meta = check_live.run(
        server, checks=["baas"], supabase_url=server, anon_key=ANON_KEY,
        baas_tables=["secrets", "closed_table"])
    rules = by_rule(findings)
    assert "supabase-rls-open" in rules
    tables = [f.extra.get("table") for f in rules["supabase-rls-open"]]
    assert "secrets" in tables and "closed_table" not in tables
    assert rules["supabase-rls-open"][0].severity == "critical"


def test_baas_skipped_without_credentials(server):
    findings, warnings, meta = check_live.run(server, checks=["baas"])
    assert findings == []
    assert any("baas" in w for w in warnings)


# --- end to end via the CLI ---------------------------------------------------

def test_cli_json_against_local_server(server, run_script):
    r = run_script("check_live.py", "--json", server, skill="live-exposure-check")
    assert r.returncode == check_live.wc.EXIT_FINDINGS
    rep = json.loads(r.stdout)
    assert rep["tool"] == "ward" and rep["script"] == "check_live"
    rules = {f["rule"] for f in rep["findings"]}
    assert "supabase-service-role-jwt" in rules
    assert "exposed-file" in rules
    assert SERVICE_JWT not in r.stdout and ENV_SECRET not in r.stdout


def test_cli_unknown_check_errors(server, run_script):
    r = run_script("check_live.py", "--checks", "nope", server, skill="live-exposure-check")
    assert r.returncode == check_live.wc.EXIT_ERROR
    assert "unknown check" in r.stderr.lower()


# --- inconclusive probes are never reported as clean ---------------------------

def test_webhook_verified_note_only_for_400_401_403(server):
    findings, warnings, meta = check_live.run(server, checks=["webhook"], webhook_path="/api/stripe/webhook-safe")
    assert any("rejected a forged event with 400" in n for n in meta.get("notes", []))
    assert not meta.get("inconclusive")


@pytest.mark.parametrize("path,word", [
    ("/api/stripe/no-such-route", "404: route or method not found"),
    ("/api/stripe/webhook-get-only", "405: route or method not found"),
    ("/api/stripe/webhook-crash", "500: inconclusive"),
    ("/api/stripe/webhook-moved", "redirected (302"),
])
def test_webhook_non_answers_are_inconclusive(server, path, word):
    findings, warnings, meta = check_live.run(server, checks=["webhook"], webhook_path=path)
    assert findings == []
    assert meta["inconclusive"] == ["webhook"]
    assert any(word in w for w in warnings), warnings
    assert not any("signature" in n and "refused" in n for n in meta.get("notes", []))


def test_cli_webhook_missing_route_exits_2(server, run_script):
    r = run_script("check_live.py", "--checks", "webhook", "--webhook-path", "/api/stripe/no-such-route", server,
                   skill="live-exposure-check")
    assert r.returncode == check_live.wc.EXIT_ERROR, r.stdout
    assert "verified" not in r.stdout and "route or method not found" in r.stderr


@pytest.mark.parametrize("value,expected", [
    ("/api/chat", "/api/chat"),
    ("api/chat", "/api/chat"),
    ("C:/Program Files/Git/api/chat", "/api/chat"),
    ("C:\\Program Files\\Git\\api\\stripe\\webhook", "/api/stripe/webhook"),
    ("D:/msys64/api/chat", "/api/chat"),
])
def test_clean_url_path_undoes_git_bash_rewrite(value, expected):
    assert check_live.clean_url_path(value, "--x") == (expected, None)


def test_clean_url_path_refuses_other_drive_paths():
    path, err = check_live.clean_url_path("C:/Users/me/api/chat", "--ratelimit-path")
    assert path is None and "MSYS_NO_PATHCONV=1" in err
    assert check_live.clean_url_path("https://x.example/a", "--x")[0] is None


def test_cli_git_bash_rewritten_paths_still_probe(server, run_script):
    r = run_script("check_live.py", "--json", "--checks", "ratelimit", "--n", "5",
                   "--ratelimit-path", "C:/Program Files/Git/api/chat", server, skill="live-exposure-check")
    rep = json.loads(r.stdout)
    assert rep["ratelimit"]["/api/chat"]["sent"] == 5
    assert r.returncode == check_live.wc.EXIT_FINDINGS


def test_opt_in_flag_adds_its_check(server):
    findings, warnings, meta = check_live.run(server, checks=["headers"], webhook_path="/api/stripe/webhook")
    assert "webhook" in meta["checks_run"] and "webhook-accepts-forged" in by_rule(findings)
    assert any("added to --checks" in n for n in meta.get("notes", []))


def test_ratelimit_bad_body_is_inconclusive_then_valid_body_fires(server):
    findings, warnings, meta = check_live.run(server, checks=["ratelimit"], ratelimit_path="/api/chat-validates",
                                              ratelimit_n=5)
    assert findings == [] and meta["inconclusive"] == ["ratelimit"]
    assert any("--ratelimit-body" in w for w in warnings)
    findings, warnings, meta = check_live.run(server, checks=["ratelimit"], ratelimit_path="/api/chat-validates",
                                              ratelimit_n=5, ratelimit_body='{"message": "hi"}')
    assert "no-rate-limit" in by_rule(findings)


def test_ratelimit_with_session_token(server):
    findings, warnings, meta = check_live.run(server, checks=["ratelimit"], ratelimit_path="/api/chat-session",
                                              ratelimit_n=5)
    assert findings == [] and any("--auth-bearer-env" in n for n in meta.get("notes", []))
    findings, warnings, meta = check_live.run(server, checks=["ratelimit"], ratelimit_path="/api/chat-session",
                                              ratelimit_n=5, ratelimit_bearer=BEARER)
    assert "no-rate-limit" in by_rule(findings)


def test_cli_auth_bearer_env(server, run_script):
    r = run_script("check_live.py", "--json", "--checks", "ratelimit", "--n", "4", "--ratelimit-path",
                   "/api/chat-session", "--auth-bearer-env", "WARD_TEST_TOKEN", server,
                   skill="live-exposure-check", env={"WARD_TEST_TOKEN": BEARER})
    assert r.returncode == check_live.wc.EXIT_FINDINGS, r.stderr
    assert BEARER not in r.stdout
    r = run_script("check_live.py", "--ratelimit-path", "/api/chat", "--auth-bearer-env", "WARD_NOT_SET_XYZ",
                   server, skill="live-exposure-check")
    assert r.returncode == check_live.wc.EXIT_ERROR and "WARD_NOT_SET_XYZ" in r.stderr


def test_baas_unclear_tables_warn_and_are_inconclusive(server):
    findings, warnings, meta = check_live.run(server, checks=["baas"], supabase_url=server, anon_key=ANON_KEY,
                                              baas_tables=["badkey", "missing"])
    assert findings == [] and meta["inconclusive"] == ["baas"]
    text = " ".join(warnings)
    assert "badkey: 401, the anon key was rejected" in text and "missing: 404, table not exposed" in text


def test_baas_no_grant_is_a_clear_answer(server):
    findings, warnings, meta = check_live.run(server, checks=["baas"], supabase_url=server, anon_key=ANON_KEY,
                                              baas_tables=["nogrant", "closed_table"])
    assert findings == [] and not meta.get("inconclusive")
    assert any("nogrant refuses the anon role" in n for n in meta.get("notes", []))


def test_cli_baas_unreachable_project_exits_2(server, run_script):
    r = run_script("check_live.py", "--checks", "baas", "--supabase-url", server, "--anon-key", ANON_KEY,
                   "--baas-table", "missing", server, skill="live-exposure-check")
    assert r.returncode == check_live.wc.EXIT_ERROR
    assert "No findings." in r.stdout and "inconclusive" in r.stdout


@pytest.mark.parametrize("url,owned,result", [
    ("https://abcd.supabase.co", [], None),
    ("http://127.0.0.1:54321", [], None),
    ("http://abcd.supabase.co", [], "error"),
    ("https://db.example.com", [], "refused"),
    ("https://db.example.com", ["db.example.com"], None),
    ("https://abcd.supabase.co.evil.example", [], "refused"),
])
def test_supabase_url_host_gate(url, owned, result):
    err = check_live.check_service_url(url, owned, (".supabase.co", ".supabase.in"), "--supabase-url")
    if result is None:
        assert err is None
    else:
        assert err is not None and err.startswith(result)


def test_cli_supabase_url_on_foreign_host_is_refused(server, run_script):
    r = run_script("check_live.py", "--supabase-url", "https://db.example.com", "--anon-key", ANON_KEY, server,
                   skill="live-exposure-check")
    assert r.returncode == check_live.wc.EXIT_REFUSED and "--i-own-this db.example.com" in r.stderr


def test_firebase_open_rtdb_and_unknown_regional_rtdb(server):
    findings, warnings, meta = check_live.run(server, checks=["baas"], firebase_project="demo-proj",
                                              baas_collections=["open", "closed"], rtdb_url=server + "/rtdb",
                                              firestore_api=server)
    rules = by_rule(findings)
    assert [f.extra["collection"] for f in rules["firebase-rules-open"]] == ["open"]
    assert [f.extra["path"] for f in rules["firebase-rtdb-open"]] == ["open"]
    findings, warnings, meta = check_live.run(server, checks=["baas"], firebase_project="demo-proj",
                                              baas_collections=["closed"], rtdb_url=server + "/rtdb-gone",
                                              firestore_api=server)
    assert findings == []
    assert any("Realtime Database not checked" in w and "--rtdb-url" in w for w in warnings)
    assert not meta.get("inconclusive")  # Firestore still answered


def test_firebase_default_rtdb_url():
    assert check_live.default_rtdb_url("demo-proj") == "https://demo-proj-default-rtdb.firebaseio.com"


def test_firebase_database_url_from_firebase_config():
    cfg = 'const firebaseConfig={apiKey:"x",databaseURL:"https://demo-proj-default-rtdb.europe-west1.firebasedatabase.app",'
    assert check_live.firebase_database_url(cfg) == "https://demo-proj-default-rtdb.europe-west1.firebasedatabase.app"
    assert check_live.firebase_database_url('"databaseURL": "https://demo.firebaseio.com/"') == "https://demo.firebaseio.com"
    assert check_live.firebase_database_url('databaseURL: "https://evil.example.com"') is None
    assert check_live.firebase_database_url("no config here") is None


def test_bundle_database_url_is_used_when_no_rtdb_url(server, monkeypatch):
    seen = {}

    def fake_bundle(client, base_url, meta):
        meta["firebase_database_url"] = "https://demo-proj-default-rtdb.europe-west1.firebasedatabase.app"
        return []

    def fake_firebase(client, project, colls, meta, rtdb_url=None, firestore_api=None):
        seen["rtdb_url"] = rtdb_url
        return []

    monkeypatch.setattr(check_live, "check_bundle", fake_bundle)
    monkeypatch.setattr(check_live, "check_baas_firebase", fake_firebase)
    _f, _w, meta = check_live.run(server, checks=["bundle"], firebase_project="demo-proj")
    assert seen["rtdb_url"] == "https://demo-proj-default-rtdb.europe-west1.firebasedatabase.app"
    assert any("taken from the app's firebaseConfig" in n for n in meta["notes"])
    check_live.run(server, checks=["bundle"], firebase_project="demo-proj", rtdb_url=server + "/rtdb")
    assert seen["rtdb_url"] == server + "/rtdb"


def test_ratelimit_server_error_and_missing_route_hints(server):
    _f, warnings, meta = check_live.run(server, checks=["headers"], ratelimit_path="/nope", ratelimit_n=2)
    assert meta["inconclusive"] == ["ratelimit"]
    assert any("route or method not found" in w for w in warnings)
