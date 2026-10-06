"""Shared helpers for the oracle: config, HTTP, login, and result recording."""

import json
import os
import urllib.error as E
import urllib.request as U
from urllib.parse import quote

# These tests only run through run_oracle.py, which sets BENCH_FIXTURES. When
# that is absent (for example a repo-wide pytest collection), fall back to empty
# defaults so importing this module never fails; conftest skips the tests.
_fx_path = os.environ.get("BENCH_FIXTURES")
if _fx_path:
    with open(_fx_path, "r", encoding="utf-8") as _fh:
        FIX = json.load(_fh)
else:
    FIX = {"ports": {"supabase": "54721", "stripe": "54722", "llm": "54723",
                     "internal": "54724", "app": "3100"},
           "ids": {}, "users": [], "anon_key": "", "service_key": "",
           "openai_key": "", "markers": {}}

APP = os.environ.get("APP_BASE", "http://127.0.0.1:3100")
PORTS = FIX["ports"]
SUPA = "http://127.0.0.1:%s" % PORTS["supabase"]
STRIPE = "http://127.0.0.1:%s" % PORTS["stripe"]
LLM = "http://127.0.0.1:%s" % PORTS["llm"]
INTERNAL = "http://127.0.0.1:%s" % PORTS["internal"]
APP_DIR = os.environ.get("BENCH_APP_DIR", "")
EXPECT = os.environ.get("BENCH_EXPECT", "exploitable")
IDS = FIX["ids"]
ANON = FIX["anon_key"]
SERVICE = FIX["service_key"]

RESULTS = {"items": {}, "functional": {}}


def _flush():
    out = os.environ.get("BENCH_RESULTS")
    if not out:
        return
    try:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(RESULTS, fh, indent=2)
    except Exception:
        pass


def record_item(item_id, state):
    RESULTS["items"][item_id] = state
    _flush()


def record_func(name, passed):
    RESULTS["functional"][name] = "pass" if passed else "fail"
    _flush()


class _NoRedirect(U.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def request(method, url, body=None, headers=None, cookie=None, allow_redirect=True):
    h = dict(headers or {})
    if cookie:
        h["Cookie"] = cookie
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode("utf-8")
            h.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            data = body.encode("utf-8")
        else:
            data = body
    req = U.Request(url, data=data, method=method, headers=h)
    opener = U.build_opener(*( [] if allow_redirect else [_NoRedirect()] ))
    try:
        resp = opener.open(req, timeout=20)
        return resp.status, resp.headers, resp.read().decode("utf-8", "replace")
    except E.HTTPError as ex:
        return ex.code, ex.headers, ex.read().decode("utf-8", "replace")


def as_json(text, default=None):
    try:
        return json.loads(text)
    except Exception:
        return default


def user(email):
    for u in FIX["users"]:
        if u["email"] == email:
            return u
    raise KeyError(email)


_SESSIONS = {}


def login(email):
    # One login per user per oracle run, like a real user. Logging in again
    # for every check would trip a login rate limit, which is a valid fix.
    if email in _SESSIONS:
        return _SESSIONS[email]
    res = _login(email)
    if res["status"] == 200 and res["cookie"]:
        _SESSIONS[email] = res
    return res


def _login(email):
    u = user(email)
    status, headers, text = request(
        "POST", APP + "/api/login",
        body={"email": email, "password": u["password"]})
    cookie = None
    try:
        for sc in headers.get_all("Set-Cookie") or []:
            if sc.startswith("session="):
                cookie = sc.split(";", 1)[0]
    except Exception:
        pass
    data = as_json(text, {})
    return {"status": status, "cookie": cookie, "token": data.get("access_token"),
            "user": data.get("user")}


# --- direct Supabase mock helpers ---

def supa(method, path, key=None, token=None, body=None, prefer=None):
    k = key or ANON
    headers = {"apikey": k, "Authorization": "Bearer " + (token or k)}
    if prefer:
        headers["Prefer"] = prefer
    return request(method, SUPA + path, body=body, headers=headers)


def supa_admin_get(table, query=""):
    status, _, text = supa("GET", "/rest/v1/%s%s" % (table, query),
                           key=SERVICE, token=SERVICE)
    return as_json(text, [])


def stripe_post(path, body):
    status, _, text = request("POST", STRIPE + path, body=body)
    return status, as_json(text, {})


def enc(s):
    return quote(s, safe="")


# --- static source helpers (read the app under test) ---

def read_app_file(rel):
    p = os.path.join(APP_DIR, rel)
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def migrations_text():
    import glob
    out = []
    for p in sorted(glob.glob(os.path.join(APP_DIR, "supabase", "migrations", "*.sql"))):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                out.append(fh.read())
        except Exception:
            pass
    return "\n".join(out)


def live_policies():
    """Policies left after applying every migration in order (drops included)."""
    import sys
    mock_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "mock")
    if mock_dir not in sys.path:
        sys.path.insert(0, mock_dir)
    import mock_supabase
    _, policies = mock_supabase.parse_migrations(
        os.path.join(APP_DIR, "supabase", "migrations"))
    return policies


def strip_js_comments(text):
    import re
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(^|[^:])//[^\n]*", r"\1", text)


def bundle_contains(needle):
    import glob
    base = os.path.join(APP_DIR, ".next", "static")
    for p in glob.glob(os.path.join(base, "**", "*.js"), recursive=True):
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                if needle in fh.read():
                    return True
        except Exception:
            pass
    return False


def alice_credits():
    rows = supa_admin_get("profiles", "?id=eq.%s&select=credits" % IDS["alice"])
    if rows and isinstance(rows, list):
        try:
            return int(rows[0].get("credits") or 0)
        except Exception:
            return 0
    return 0
