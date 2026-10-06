"""Minimal PostgREST-ish Supabase mock that actually enforces RLS.

It reads the app's supabase/migrations/*.sql at startup to learn which tables
have RLS enabled and what policies exist, then evaluates a small policy grammar
on every request. Tables with RLS disabled are fully open to the anon key
(this is what makes a missing-RLS bug exploitable at runtime). The service role
key bypasses RLS.

Standard library only. Python 3.9+.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def log(*a):
    print("[mock_supabase]", *a, file=sys.stderr, flush=True)


# ---------- JWT (HS256) ----------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def jwt_encode(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing = (h + "." + p).encode("ascii")
    sig = hmac.new(secret.encode("utf-8"), signing, hashlib.sha256).digest()
    return h + "." + p + "." + b64url(sig)


def jwt_decode(token: str, secret: str):
    try:
        h, p, s = token.split(".")
        signing = (h + "." + p).encode("ascii")
        expected = hmac.new(secret.encode("utf-8"), signing, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, b64url_decode(s)):
            return None
        return json.loads(b64url_decode(p).decode("utf-8"))
    except Exception:
        return None


# ---------- migration parsing ----------

class Policy:
    def __init__(self, table, cmd, roles, using, check, name=""):
        self.name = name
        self.table = table
        self.cmd = cmd  # select|insert|update|delete|all
        self.roles = roles  # set or None (public)
        self.using = using  # normalized expr string or None
        self.check = check


def _clean_sql(text: str) -> str:
    # drop line comments
    out = []
    for line in text.splitlines():
        i = line.find("--")
        if i >= 0:
            line = line[:i]
        out.append(line)
    return "\n".join(out)


def parse_migrations(mig_dir: str):
    rls_tables = set()
    policies = []
    if not os.path.isdir(mig_dir):
        log("migrations dir not found:", mig_dir)
        return rls_tables, policies
    files = sorted(f for f in os.listdir(mig_dir) if f.endswith(".sql"))
    # Statements are applied in order across files, so a later migration can
    # drop a policy or toggle RLS the way it would on a real database.
    for fn in files:
        with open(os.path.join(mig_dir, fn), "r", encoding="utf-8", errors="replace") as fh:
            sql = _clean_sql(fh.read())
        for stmt in re.split(r";", sql):
            s = stmt.strip()
            m = re.match(
                r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?([\"\w\.]+)\s+"
                r"(enable|disable)\s+row\s+level\s+security", s, re.I)
            if m:
                if m.group(2).lower() == "enable":
                    rls_tables.add(_tbl(m.group(1)))
                else:
                    rls_tables.discard(_tbl(m.group(1)))
                continue
            m = re.match(r'drop\s+policy\s+(?:if\s+exists\s+)?("[^"]+"|\S+)\s+on\s+([\"\w\.]+)',
                         s, re.I)
            if m:
                name, table = m.group(1).strip('"'), _tbl(m.group(2))
                policies = [p for p in policies if not (p.table == table and p.name == name)]
                continue
            if re.match(r"create\s+policy", s, re.I):
                p = _parse_policy(s)
                if p:
                    policies = [q for q in policies
                                if not (q.table == p.table and q.name == p.name)]
                    policies.append(p)
    return rls_tables, policies


def _tbl(name: str) -> str:
    name = name.strip().strip('"')
    if "." in name:
        name = name.split(".")[-1]
    return name.strip('"').lower()


def _parse_policy(stmt: str):
    m = re.search(r'create\s+policy\s+("[^"]+"|\S+)\s+on\s+([\"\w\.]+)(.*)', stmt,
                  re.I | re.S)
    if not m:
        return None
    name = m.group(1).strip('"')
    table = _tbl(m.group(2))
    rest = m.group(3)
    cmd = "all"
    mc = re.search(r"\bfor\s+(select|insert|update|delete|all)\b", rest, re.I)
    if mc:
        cmd = mc.group(1).lower()
    roles = None
    mr = re.search(r"\bto\s+([a-zA-Z_,\s]+?)(?:\busing\b|\bwith\b|$)", rest, re.I)
    if mr:
        roles = set(r.strip().lower() for r in mr.group(1).split(",") if r.strip())
    using = _extract_paren(rest, "using")
    check = _extract_paren(rest, "with check")
    return Policy(table, cmd, roles, using, check, name)


def _extract_paren(text: str, keyword: str):
    idx = text.lower().find(keyword)
    if idx < 0:
        return None
    i = text.find("(", idx)
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
            if depth == 0:
                return _norm_expr(text[i + 1:j])
    return None


def _norm_expr(expr: str) -> str:
    return re.sub(r"\s+", " ", expr.strip().lower())


# ---------- policy evaluation ----------

class Ctx:
    def __init__(self, role, uid, claims):
        self.role = role  # anon|authenticated|service_role
        self.uid = uid
        self.claims = claims or {}


def eval_expr(expr, ctx: Ctx, row: dict):
    """Returns True/False. Unknown expressions deny (and are logged)."""
    if expr is None:
        return False
    e = expr.strip()
    if e == "true":
        return True
    if e == "false":
        return False

    # auth.uid() = col  (either order, with or without (select ...))
    m = re.match(r"\(?\s*select\s+auth\.uid\(\)\s*\)?\s*=\s*([\w\.]+)$", e)
    if m:
        return ctx.uid is not None and str(row.get(_col(m.group(1)))) == str(ctx.uid)
    m = re.match(r"([\w\.]+)\s*=\s*\(?\s*select\s+auth\.uid\(\)\s*\)?$", e)
    if m:
        return ctx.uid is not None and str(row.get(_col(m.group(1)))) == str(ctx.uid)
    m = re.match(r"auth\.uid\(\)\s*=\s*([\w\.]+)$", e)
    if m:
        return ctx.uid is not None and str(row.get(_col(m.group(1)))) == str(ctx.uid)
    m = re.match(r"([\w\.]+)\s*=\s*auth\.uid\(\)$", e)
    if m:
        return ctx.uid is not None and str(row.get(_col(m.group(1)))) == str(ctx.uid)

    # auth.role() = 'authenticated'
    m = re.match(r"auth\.role\(\)\s*=\s*'([^']+)'$", e)
    if m:
        return ctx.role == m.group(1)
    m = re.match(r"'([^']+)'\s*=\s*auth\.role\(\)$", e)
    if m:
        return ctx.role == m.group(1)

    # auth.jwt() -> 'user_metadata' ->> 'role' = 'admin'  (either order)
    m = re.match(
        r"\(?\s*auth\.jwt\(\)\s*->\s*'user_metadata'\s*->>\s*'(\w+)'\s*\)?\s*=\s*'([^']+)'$",
        e)
    if m:
        meta = ctx.claims.get("user_metadata") or {}
        return str(meta.get(m.group(1))) == m.group(2)
    m = re.match(
        r"'([^']+)'\s*=\s*\(?\s*auth\.jwt\(\)\s*->\s*'user_metadata'\s*->>\s*'(\w+)'\s*\)?$",
        e)
    if m:
        meta = ctx.claims.get("user_metadata") or {}
        return str(meta.get(m.group(2))) == m.group(1)

    log("unknown policy expression, denying:", repr(expr))
    return False


def _col(token: str) -> str:
    token = token.strip()
    if "." in token:
        token = token.split(".")[-1]
    return token


def applicable(policies, table, cmd, ctx: Ctx):
    out = []
    for p in policies:
        if p.table != table:
            continue
        if p.cmd != "all" and p.cmd != cmd:
            continue
        if p.roles is not None and ctx.role not in p.roles:
            continue
        out.append(p)
    return out


# ---------- data store ----------

class Store:
    def __init__(self, seed: dict):
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.columns = {}
        # sqlite stores booleans as 0/1; remember which columns are boolean so
        # rows go back out as JSON true/false like PostgREST returns them
        self.bool_cols = {}
        for table, rows in seed.items():
            cols = []
            seen = set()
            self.bool_cols[table] = set(
                k for r in rows for k, v in r.items() if isinstance(v, bool))
            for r in rows:
                for k in r.keys():
                    if k not in seen:
                        seen.add(k)
                        cols.append(k)
            if not cols:
                cols = ["id"]
            self.columns[table] = cols
            coldef = ", ".join('"%s"' % c for c in cols)
            self.conn.execute('create table "%s" (%s)' % (table, coldef))
            for r in rows:
                self._insert_row(table, r)
        self.conn.commit()

    def _insert_row(self, table, row):
        cols = self.columns[table]
        vals = [self._norm_val(row.get(c)) for c in cols]
        ph = ", ".join("?" for _ in cols)
        colnames = ", ".join('"%s"' % c for c in cols)
        self.conn.execute(
            'insert into "%s" (%s) values (%s)' % (table, colnames, ph), vals)

    def _norm_val(self, v):
        if isinstance(v, bool):
            return 1 if v else 0
        if isinstance(v, (dict, list)):
            return json.dumps(v)
        return v

    def all_rows(self, table):
        cur = self.conn.execute('select * from "%s"' % table)
        bools = self.bool_cols.get(table, ())
        out = []
        for r in cur.fetchall():
            d = dict(r)
            for c in bools:
                if d.get(c) in (0, 1):
                    d[c] = bool(d[c])
            out.append(d)
        return out

    def insert(self, table, row):
        with self.lock:
            # add any unseen columns are ignored; only known columns stored
            self._insert_row(table, row)
            self.conn.commit()

    def update(self, table, new_values, row_id):
        cols = [c for c in new_values.keys() if c in self.columns[table]]
        if not cols:
            return
        sets = ", ".join('"%s" = ?' % c for c in cols)
        vals = [self._norm_val(new_values[c]) for c in cols]
        vals.append(row_id)
        with self.lock:
            self.conn.execute(
                'update "%s" set %s where "id" = ?' % (table, sets), vals)
            self.conn.commit()

    def delete(self, table, row_id):
        with self.lock:
            self.conn.execute('delete from "%s" where "id" = ?' % table, [row_id])
            self.conn.commit()

    def raw(self, sql, params):
        with self.lock:
            cur = self.conn.execute(sql, params or [])
            try:
                return [dict(r) for r in cur.fetchall()]
            finally:
                self.conn.commit()


# ---------- HTTP ----------

class App:
    def __init__(self):
        fixtures_path = os.environ["BENCH_FIXTURES"]
        with open(fixtures_path, "r", encoding="utf-8") as fh:
            fx = json.load(fh)
        self.jwt_secret = fx["jwt_secret"]
        self.anon_key = fx["anon_key"]
        self.service_key = fx["service_key"]
        self.users = {u["email"]: u for u in fx["users"]}
        self.store = Store(fx["seed"])
        mig = os.environ.get("MIGRATIONS_DIR", "")
        self.rls_tables, self.policies = parse_migrations(mig)
        log("RLS tables:", sorted(self.rls_tables))
        log("policies:", [(p.table, p.cmd, p.using) for p in self.policies])

    def ctx_from_headers(self, headers) -> Ctx:
        auth = headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not token:
            token = headers.get("apikey", "")
        if token and token == self.service_key:
            return Ctx("service_role", None, {})
        if token and token == self.anon_key:
            return Ctx("anon", None, {})
        claims = jwt_decode(token, self.jwt_secret) if token else None
        if claims:
            role = claims.get("role", "authenticated")
            if role not in ("authenticated", "anon", "service_role"):
                role = "authenticated"
            return Ctx(role, claims.get("sub"), claims)
        return Ctx("anon", None, {})

    def can_select_row(self, table, ctx, row):
        if ctx.role == "service_role":
            return True
        if table not in self.rls_tables:
            # RLS disabled: open to anon + authenticated via default grants
            return True
        pols = applicable(self.policies, table, "select", ctx)
        for p in pols:
            if eval_expr(p.using if p.using is not None else "false", ctx, row):
                return True
        return False

    def can_insert_row(self, table, ctx, row):
        if ctx.role == "service_role":
            return True
        if table not in self.rls_tables:
            return True
        pols = applicable(self.policies, table, "insert", ctx)
        for p in pols:
            expr = p.check if p.check is not None else p.using
            if eval_expr(expr if expr is not None else "false", ctx, row):
                return True
        return False

    def can_update_row(self, table, ctx, old_row, new_row):
        if ctx.role == "service_role":
            return True
        if table not in self.rls_tables:
            return True
        pols = applicable(self.policies, table, "update", ctx)
        for p in pols:
            if not eval_expr(p.using if p.using is not None else "false", ctx, old_row):
                continue
            if p.check is None or eval_expr(p.check, ctx, new_row):
                return True
        return False

    def can_delete_row(self, table, ctx, row):
        if ctx.role == "service_role":
            return True
        if table not in self.rls_tables:
            return True
        pols = applicable(self.policies, table, "delete", ctx)
        for p in pols:
            if eval_expr(p.using if p.using is not None else "false", ctx, row):
                return True
        return False


def eq_filters(query):
    out = {}
    reserved = {"select", "order", "limit", "offset", "on_conflict"}
    for k, vals in query.items():
        if k in reserved:
            continue
        v = vals[0]
        if v.startswith("eq."):
            out[k] = v[3:]
    return out


def match_filters(row, filters):
    for k, v in filters.items():
        have = row.get(k)
        if isinstance(have, bool):
            have = "true" if have else "false"
        if str(have) != str(v):
            return False
    return True


def project(row, select_param):
    if not select_param or select_param == "*":
        return row
    cols = [c.strip() for c in select_param.split(",")]
    if "*" in cols:
        return row
    return {c: row.get(c) for c in cols}


class Handler(BaseHTTPRequestHandler):
    app: App = None

    def log_message(self, *a):
        pass

    def _send(self, code, obj, extra=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def do_PATCH(self):
        self._route("PATCH")

    def do_DELETE(self):
        self._route("DELETE")

    def _route(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        app = Handler.app
        try:
            if path.startswith("/auth/v1/token"):
                return self._auth_token()
            if path == "/auth/v1/user" and method == "GET":
                return self._auth_user()
            if path == "/rest/v1/rpc/search":
                return self._rpc_search()
            if path.startswith("/rest/v1/"):
                table = path[len("/rest/v1/"):].strip("/")
                if not table or "/" in table:
                    return self._send(404, {"error": "not found"})
                return self._rest(method, table, query)
            if path == "/health":
                return self._send(200, {"ok": True})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            log("error:", repr(e))
            self._send(500, {"error": str(e)})

    def _auth_user(self):
        # GET /auth/v1/user: what supabase.auth.getUser(token) calls.
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        claims = jwt_decode(token, Handler.app.jwt_secret) if token else None
        if not claims or claims.get("role") != "authenticated" or \
                int(claims.get("exp", 0)) < int(time.time()):
            return self._send(401, {"code": 401, "msg": "invalid JWT"})
        return self._send(200, {
            "id": claims.get("sub"),
            "aud": "authenticated",
            "role": "authenticated",
            "email": claims.get("email"),
            "app_metadata": claims.get("app_metadata") or {},
            "user_metadata": claims.get("user_metadata") or {},
        })

    def _auth_token(self):
        body = self._read_body() or {}
        email = body.get("email")
        password = body.get("password")
        user = Handler.app.users.get(email)
        if not user or user.get("password") != password:
            return self._send(400, {"error": "invalid_grant",
                                    "error_description": "Invalid login credentials"})
        now = int(time.time())
        payload = {
            "sub": user["id"],
            "email": user["email"],
            "role": "authenticated",
            "app_metadata": {"role": user.get("role", "user")},
            "user_metadata": {},
            "iss": "ward-demo",
            "iat": now,
            "exp": now + 3600,
        }
        token = jwt_encode(payload, Handler.app.jwt_secret)
        return self._send(200, {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "refresh-" + user["id"],
            "user": {"id": user["id"], "email": user["email"]},
        })

    def _rpc_search(self):
        body = self._read_body() or {}
        sql = body.get("sql", "")
        params = body.get("params", [])
        if not isinstance(sql, str) or not sql.lower().lstrip().startswith("select"):
            return self._send(400, {"error": "only select allowed"})
        rows = Handler.app.store.raw(sql, params)
        return self._send(200, rows)

    def _rest(self, method, table, query):
        app = Handler.app
        ctx = app.ctx_from_headers(self.headers)
        if table not in app.store.columns:
            return self._send(404, {"error": "relation not found: " + table})
        filters = eq_filters(query)
        prefer = self.headers.get("Prefer", "")
        accept = self.headers.get("Accept", "")
        want_object = "pgrst.object" in accept
        select_param = query.get("select", ["*"])[0]

        if method == "GET":
            rows = [r for r in app.store.all_rows(table) if match_filters(r, filters)]
            visible = [project(r, select_param) for r in rows
                       if app.can_select_row(table, ctx, r)]
            if want_object:
                if len(visible) == 1:
                    return self._send(200, visible[0])
                return self._send(406, {"error": "not a single row",
                                        "count": len(visible)})
            return self._send(200, visible)

        if method == "POST":
            body = self._read_body()
            rows = body if isinstance(body, list) else [body]
            inserted = []
            for r in rows:
                if not app.can_insert_row(table, ctx, r):
                    return self._send(401, {"error": "new row violates row-level "
                                            "security policy for table " + table})
                # every table here has "id" as its primary key, like the migrations
                if r.get("id") is not None and any(
                        str(x.get("id")) == str(r["id"]) for x in app.store.all_rows(table)):
                    return self._send(409, {
                        "code": "23505",
                        "message": "duplicate key value violates unique constraint "
                                   "\"%s_pkey\"" % table,
                        "details": "Key (id)=(%s) already exists." % r["id"],
                        "hint": None})
                app.store.insert(table, r)
                inserted.append(r)
            if "return=representation" in prefer:
                return self._send(201, inserted)
            return self._send(201, {})

        if method == "PATCH":
            body = self._read_body() or {}
            rows = [r for r in app.store.all_rows(table) if match_filters(r, filters)]
            updated = []
            for r in rows:
                new_row = dict(r)
                new_row.update(body)
                if not app.can_update_row(table, ctx, r, new_row):
                    return self._send(401, {"error": "row-level security policy"})
                app.store.update(table, body, r.get("id"))
                updated.append(new_row)
            if "return=representation" in prefer:
                return self._send(200, [project(r, select_param) for r in updated])
            return self._send(200, {})

        if method == "DELETE":
            rows = [r for r in app.store.all_rows(table) if match_filters(r, filters)]
            deleted = []
            for r in rows:
                if not app.can_delete_row(table, ctx, r):
                    return self._send(401, {"error": "row-level security policy"})
                app.store.delete(table, r.get("id"))
                deleted.append(r)
            return self._send(200, deleted if "return=representation" in prefer else {})

        return self._send(405, {"error": "method not allowed"})


def main():
    port = int(os.environ.get("MOCK_SUPABASE_PORT", "54721"))
    Handler.app = App()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    log("listening on", port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
