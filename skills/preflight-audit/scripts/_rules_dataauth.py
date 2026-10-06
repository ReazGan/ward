"""Data access and auth rules (threats-data classes 1-8).

Supabase: tables without RLS, policies that let everyone in, user_metadata
used for access, security definer functions, views that skip RLS, the
service role key in client code, getSession() trusted on the server.
Firebase: open, test-mode and any-signed-in-user rules for Firestore,
Storage and the Realtime Database, roles kept in a user-editable document.
Apps: by-id lookups with no ownership check (IDOR), role flags and password
checks in the browser, middleware or proxy as the only gate, Next.js
versions hit by CVE-2025-29927, mass assignment, fast password hashes and
JWTs that are decoded but never verified.

Every rule reports a candidate. Its fp_trap names the safe variant; the
agent confirms against the code before reporting.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import _wardcore as wc
from _wardcore import Hit, Rule

SKILL = "data-auth"

_JS_GLOBS = ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.mts", "*.cts"]
_WEB_GLOBS = _JS_GLOBS + ["*.vue", "*.svelte"]
_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
_TEST_GLOBS = [
    "**/test/**", "**/tests/**", "**/__tests__/**", "**/__mocks__/**", "**/e2e/**", "**/cypress/**",
    "**/playwright/**", "**/fixtures/**", "*.test.*", "*.spec.*", "*.stories.*", "test_*.py",
    "*_test.py", "conftest.py",
]

# Tables or collections whose rows are private by nature.
_PRIVATE_NAME = re.compile(
    r"(?:^|_)(?:messages?|chats?|conversations?|orders?|payments?|invoices?|transactions?|notes?|"
    r"documents?|files?|uploads?|attachments?|api_?keys?|tokens?|secrets?|credentials?|sessions?|"
    r"subscriptions?|bookings?|appointments?|patients?|medical|health|addresses|contacts?|leads?|"
    r"customers?|billing|wallets?|balances?|payouts?|receipts?|journals?|diar(?:y|ies)|private|dms?|"
    r"inbox|emails?|phones?|passwords?|kyc|identit(?:y|ies)|verifications?)(?:_|$)", re.I)
# Firestore and RTDB have no schema, so user documents count as private too.
_PRIVATE_DOC = re.compile(r"^(?:users?|profiles?|accounts?|members?|user_?data|userdata)$", re.I)
_SENSITIVE_COL = re.compile(
    r"^(?:e_?mail|email_address|phone|phone_number|mobile|address|street_address|password|"
    r"password_hash|hashed_password|token|access_token|refresh_token|api_key|secret|ssn|tax_id|"
    r"national_id|passport|passport_number|birth_?date|date_of_birth|dob|iban|card_number|salary|"
    r"ip_address|stripe_customer_id)$", re.I)
# Resources that are usually public when read by id.
_PUBLIC_MODEL = re.compile(
    r"^(?:products?|posts?|articles?|categor(?:y|ies)|tags?|blogs?|blog_?posts?|pages?|courses?|"
    r"lessons?|listings?|recipes?|faqs?|plans?|prices?|pricing|menus?|menu_?items?|countr(?:y|ies)|"
    r"cit(?:y|ies)|languages?|locales?|announcements?|changelogs?|docs?|guides?|tutorials?|events?|"
    r"venues?|locations?|stores?|shops?|brands?|genres?|movies?|books?|songs?|albums?|artists?|"
    r"games?|news|comments?|reviews?|testimonials?|portfolios?|projects_public)$", re.I)

_USE_SERVER = re.compile(r"""\A(?:\s|//[^\n]*(?:\n|\Z)|/\*(?:[^*]|\*(?!/))*\*/)*["']use server["']""")
_USE_CLIENT = re.compile(r"""\A(?:\s|//[^\n]*(?:\n|\Z)|/\*(?:[^*]|\*(?!/))*\*/)*["']use client["']""")
_SERVER_ONLY = re.compile(r"""import\s+["']server-only["']""")
_PUBLIC_ENV = re.compile(r"\b(?:NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|REACT_APP_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)\w*")


# ---------------------------------------------------------------------------
# Small shared helpers
# ---------------------------------------------------------------------------

def _is_test(rel: str) -> bool:
    return wc.match_any(rel, _TEST_GLOBS)


def _code_lines(ctx: Any, rel: str) -> List[str]:
    """Lines of a file with comments blanked, /* */ blocks included (line numbers kept)."""
    return ctx.code_lines(rel)


def _line_at(ctx: Any, rel: str, offset: int) -> Tuple[int, str]:
    n = ctx.line_of(rel, offset)
    lines = ctx.lines(rel)
    return n, (lines[n - 1].strip() if 0 < n <= len(lines) else "")


def _balanced(text: str, start: int, open_ch: str = "(", close_ch: str = ")") -> Optional[str]:
    """Text between an opening bracket at text[start - 1] and its partner."""
    depth = 1
    i = start
    n = len(text)
    while i < n:
        c = text[i]
        if c == "'":
            j = text.find("'", i + 1)
            if j == -1:
                return None
            i = j + 1
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return None


def _split_top(text: str, sep: str = ",") -> List[str]:
    """Split on sep at bracket depth 0."""
    out, depth, cur = [], 0, []
    for c in text:
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == sep and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
    out.append("".join(cur))
    return out


# ---------------------------------------------------------------------------
# Supabase: SQL migrations
# ---------------------------------------------------------------------------

_SQL_TOKEN = re.compile(r"--|/\*|'|\"|\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$|;")
_NAME = r'(?:"[^"]+"|[A-Za-z_][\w$]*)(?:\s*\.\s*(?:"[^"]+"|[A-Za-z_][\w$]*))?'
_PNAME = r'(?:"(?:[^"]|"")*"|[A-Za-z_][\w$]*)'

_RX_CREATE_TABLE = re.compile(
    r"create\s+(?:(?:global|local)\s+)?(?:(temp|temporary)\s+|unlogged\s+)?table\s+(?:if\s+not\s+exists\s+)?(" + _NAME + r")",
    re.I)
_RX_ALTER_TABLE = re.compile(r"alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(" + _NAME + r")\s+(.*)$", re.I | re.S)
_RX_DROP_TABLE = re.compile(r"drop\s+table\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?\s*$", re.I | re.S)
_RX_GRANT = re.compile(r"grant\s+(.+?)\s+on\s+(.+?)\s+to\s+(.+)$", re.I | re.S)
_RX_REVOKE = re.compile(r"revoke\s+(?:grant\s+option\s+for\s+)?(.+?)\s+on\s+(.+?)\s+from\s+(.+)$", re.I | re.S)
_RX_CREATE_POLICY = re.compile(r"create\s+policy\s+(" + _PNAME + r")\s+on\s+(" + _NAME + r")(.*)$", re.I | re.S)
_RX_ALTER_POLICY = re.compile(r"alter\s+policy\s+(" + _PNAME + r")\s+on\s+(" + _NAME + r")(.*)$", re.I | re.S)
_RX_DROP_POLICY = re.compile(r"drop\s+policy\s+(?:if\s+exists\s+)?(" + _PNAME + r")\s+on\s+(" + _NAME + r")", re.I)
_RX_CREATE_FUNC = re.compile(r"create\s+(?:or\s+replace\s+)?function\s+(" + _NAME + r")\s*\(", re.I)
_RX_ALTER_FUNC = re.compile(r"alter\s+function\s+(" + _NAME + r")\s*(?:\([^)]*\))?\s+(.*)$", re.I | re.S)
_RX_DROP_FUNC = re.compile(r"drop\s+function\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?\s*$", re.I | re.S)
_RX_CREATE_TRIGGER = re.compile(
    r"create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+\S+\s+(before|after|instead\s+of)\s+(.+?)\s+on\s+("
    + _NAME + r")\b.*?\bexecute\s+(?:function|procedure)\s+(" + _NAME + r")\s*\(", re.I | re.S)
_RX_DEFAULT_PRIV = re.compile(r"alter\s+default\s+privileges\b.*?\bin\s+schema\s+(\w+).*?\brevoke\s+(?:execute|all)"
                              r"(?:\s+privileges)?\s+on\s+functions\s+from\s+(.+)$", re.I | re.S)
# pg_dump and supabase db diff quote keywords and types: SET "search_path" TO '', RETURNS "trigger".
_RX_SET_PATH = re.compile(r"\bset\s+\"?search_path\"?\s*(?:=|\bto\b)", re.I)
_RX_RET_TRIGGER = re.compile(r"\breturns\s+(?:setof\s+)?\"?(?:event_)?trigger\"?(?![\w\"])", re.I)
_RX_RETURNS = re.compile(r"\breturns\s+(setof\s+|table\s*\()?\s*((?:\"?[\w$]+\"?\s*\.\s*)?\"?[\w$]+\"?)", re.I)
# The tag group must always take part (empty for $$), or the \1 backreference never matches.
_RX_DOLLAR_BODY = re.compile(r"\$([A-Za-z_]\w*|)\$(.*?)\$\1\$", re.S)
_RX_DML = re.compile(r"\binsert\s+into\b|\bupdate\s+(?:only\s+)?[\w.\"]+\s+(?:as\s+\w+\s+|\w+\s+)?set\b|\bdelete\s+from\b|"
                     r"\bvault\s*\.\s*(?:create|update)_secret\b|\btruncate\b", re.I)
_RX_SECRET_READ = re.compile(r"\bvault\s*\.|\bpgsodium\s*\.|\bdecrypted_secrets?\b|\bencrypted_password\b|"
                             r"\b(?!p_|v_|in_|_)\w*(?:password|secret|api_?key|access_token|refresh_token)\b", re.I)
_RX_PERSONAL_READ = re.compile(r"\bauth\s*\.\s*users\b|\b(?:email|phone|phone_number|mobile)\b", re.I)
_RX_CALL = re.compile(r"(?:\b\"?(\w+)\"?\s*\.\s*)?\b\"?(\w+)\"?\s*\(")
_RX_GUARD_CALL = re.compile(r"\b(?:if\s+not\s+(?:\(\s*)?(?:select\s+)?|perform\s+)(?:\"?\w+\"?\s*\.\s*)?\"?(\w+)\"?\s*\(",
                            re.I)
# select public.require_admin(); as its own statement (SQL-language functions): only helpers
# that raise count, since a bare select is_admin(); guards nothing.
_RX_SELECT_GUARD = re.compile(r"(?:^|;|\bbegin\b)\s*select\s+(?:\"?\w+\"?\s*\.\s*)?\"?((?:assert|require|ensure)_\w+|"
                              r"check_\w*(?:role|access|permission|admin)\w*)\"?\s*\(", re.I)
_GUARD_HELPER = re.compile(r"(?i)^(?:is_\w*(?:admin|member|owner|staff)\w*|has_\w*(?:role|permission|access)\w*|"
                           r"assert_\w+|require_\w+|ensure_\w+|check_\w*(?:role|access|permission|admin)\w*|"
                           r"current_user_is_\w+|is_current_user_\w+)$")
# IF auth.uid() IS NOT NULL AND NOT <role test> THEN RAISE: a caller with no session skips the check.
_RX_FAIL_OPEN = re.compile(r"\bif\s+\(?\s*(?:\(\s*select\s+)?auth\s*\.\s*uid\s*\(\s*\)\s*\)?\s+is\s+not\s+null\s+and\b"
                           r"(?:(?!\bend\s+if\b).){0,400}?\bthen\s+raise\b", re.I | re.S)
_SCALAR_RET = {"boolean", "bool", "uuid", "void", "integer", "int", "int4", "int8", "bigint", "smallint", "numeric"}
_FLAG_TYPES = {"timestamptz", "timestamp", "date", "real", "double", "float8", "float4", "interval"}
_TEXTY_RET = {"text", "varchar", "character", "json", "jsonb", "record", "setof", "table", "bytea"}
_RX_CREATE_VIEW = re.compile(
    r"create\s+(?:or\s+replace\s+)?(?:(temp|temporary)\s+)?(?:recursive\s+)?(materialized\s+)?view\s+"
    r"(?:if\s+not\s+exists\s+)?(" + _NAME + r")(.*)$", re.I | re.S)
_RX_ALTER_VIEW = re.compile(r"alter\s+view\s+(?:if\s+exists\s+)?(" + _NAME + r")\s+set\s*\(([^)]*)\)", re.I)
_RX_DROP_VIEW = re.compile(r"drop\s+(?:materialized\s+)?view\s+(?:if\s+exists\s+)?(.+?)(?:\s+(?:cascade|restrict))?\s*$",
                           re.I | re.S)
_RX_RLS_ON = re.compile(r"\benable\s+row\s+level\s+security\b", re.I)
_RX_RLS_OFF = re.compile(r"\bdisable\s+row\s+level\s+security\b", re.I)
_RX_INVOKER = re.compile(r"\bsecurity_invoker\b\"?\s*(?:=\s*'?(true|on|1|yes|false|off|0|no)'?)?", re.I)
_RX_AUTH_REF = re.compile(r"\bauth\s*\.\s*(?:uid|jwt|role|email)\s*\(|\bcurrent_setting\s*\(\s*'request\.jwt|"
                          r"\bcurrent_user\b|\bsession_user\b", re.I)
_RX_META_ANY = re.compile(r"\b(?:raw_)?user_meta(?:data|_data)\b", re.I)
_ROLEISH = (r"(?:role|roles|is_?admin|isadmin|admin|is_?staff|is_?moderator|plan|tier|permissions?|subscription|"
            r"credits|is_?pro|is_?premium|is_?paid|access_?level|user_?role|account_?type)")
_RX_META_ROLE = re.compile(r"\b(?:raw_user_meta_data|user_metadata)'?\s*->>?\s*'" + _ROLEISH + r"'", re.I)
_CONSTRAINT_WORDS = {"constraint", "primary", "foreign", "unique", "check", "exclude", "like"}
# MySQL, SQLite and SQL Server dumps: no RLS there, so they are not Supabase migrations.
_NOT_POSTGRES = re.compile(r"(?i)\bENGINE\s*=\s*\w+|\bAUTO_INCREMENT\b|\bAUTOINCREMENT\b|^\s*GO\s*$|"
                           r"create\s+table\s+(?:if\s+not\s+exists\s+)?`", re.M)


def _blank(buf: List[str], s: int, e: int) -> None:
    for k in range(s, e):
        if buf[k] != "\n":
            buf[k] = " "


def _sql_split(text: str) -> Tuple[str, str, List[Tuple[int, int]]]:
    """Return (clean, flat, spans). clean: comments blanked. flat: comments and
    dollar-quoted bodies blanked. spans: (start, end) of each statement.
    Offsets match the original text."""
    n = len(text)
    clean = list(text)
    flat = list(text)
    spans: List[Tuple[int, int]] = []
    start = 0
    i = 0
    while True:
        m = _SQL_TOKEN.search(text, i)
        if not m:
            break
        tok, s = m.group(0), m.start()
        if tok == "--":
            e = text.find("\n", s)
            e = n if e == -1 else e
            _blank(clean, s, e)
            _blank(flat, s, e)
            i = e
        elif tok == "/*":
            e = text.find("*/", s + 2)
            e = n if e == -1 else e + 2
            _blank(clean, s, e)
            _blank(flat, s, e)
            i = e
        elif tok == "'":
            j = s + 1
            while True:
                k = text.find("'", j)
                if k == -1:
                    k = n
                    break
                if text.startswith("''", k):
                    j = k + 2
                    continue
                break
            i = k + 1
        elif tok == '"':
            k = text.find('"', s + 1)
            i = n if k == -1 else k + 1
        elif tok == ";":
            spans.append((start, s))
            start = s + 1
            i = s + 1
        else:
            k = text.find(tok, m.end())
            k = n if k == -1 else k
            _blank(flat, m.end(), k)
            i = k + len(tok)
    if text[start:].strip():
        spans.append((start, n))
    return "".join(clean), "".join(flat), spans


def _qname(raw: str) -> Tuple[str, str]:
    """(schema, name) for an SQL identifier; unqualified names live in public."""
    parts = [p.strip().strip('"').lower() for p in raw.split(".")]
    if len(parts) == 1:
        return "public", parts[0]
    return parts[0], parts[1]


def _names(raw: str) -> List[Tuple[str, str]]:
    out = []
    for part in _split_top(raw):
        part = part.strip()
        if re.fullmatch(_NAME, part):
            out.append(_qname(part))
    return out


def _roles(raw: str) -> Set[str]:
    return {r.strip().strip('"').lower() for r in re.split(r"[,\s]+", raw) if r.strip()}


def _expr_after(text: str, rx: str) -> Optional[str]:
    m = re.search(rx, text, re.I)
    if not m:
        return None
    return _balanced(text, m.end())


def _norm_expr(expr: Optional[str]) -> str:
    return re.sub(r"[\s()]+", "", (expr or "").lower())


_ANY_AUTH_SQL = {
    "auth.role='authenticated'", "selectauth.role='authenticated'", "'authenticated'=auth.role",
    "auth.uidisnotnull", "selectauth.uidisnotnull", "auth.jwtisnotnull", "selectauth.jwtisnotnull",
    "auth.role::text='authenticated'",
}


def _strip_parens(text: str) -> str:
    t = text.strip()
    while t.startswith("(") and t.endswith(")") and _balanced(t, 1) == t[1:-1]:
        t = t[1:-1].strip()
    return t


def _split_bool(expr: str, word: str) -> List[str]:
    """Split an SQL expression on a top-level boolean keyword (or / and)."""
    out, depth, start, i, n = [], 0, 0, 0, len(expr)
    rx = re.compile(r"\b" + word + r"\b", re.I)
    while i < n:
        c = expr[i]
        if c == "'":
            j = expr.find("'", i + 1)
            i = n if j == -1 else j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif depth == 0 and c.isalpha() and (i == 0 or not (expr[i - 1].isalnum() or expr[i - 1] == "_")):
            m = rx.match(expr, i)
            if m:
                out.append(expr[start:i])
                start = i = m.end()
                continue
        i += 1
    out.append(expr[start:])
    return [p for p in (x.strip() for x in out) if p]


_RX_IS_NULL = re.compile(r"^(?:\w+\.)?\"?(\w+)\"?\s+is\s+null$", re.I)
_RX_OWNER_EQ = re.compile(
    r"^(?:\(?select)?auth\.uid\(?\)?(?:::text|::uuid)?=(?:\w+\.)?\"?[a-z_]\w*\"?(?:::text|::uuid)?$|"
    r"^(?:\w+\.)?\"?[a-z_]\w*\"?(?:::text|::uuid)?=(?:\(?select)?auth\.uid\(?\)?(?:::text|::uuid)?$")


def _expr_kind(expr: Optional[str]) -> str:
    """'true', 'any-auth', 'null-owner', 'owner', 'none' (no expression) or 'other'.

    An OR is as open as its most open branch: (true or ...) is 'true', and
    (user_id is null or auth.uid() = user_id) is 'null-owner'."""
    if expr is None:
        return "none"
    n = _norm_expr(expr)
    if n == "true":
        return "true"
    if n in _ANY_AUTH_SQL:
        return "any-auth"
    if _RX_OWNER_EQ.match(n):
        return "owner"
    parts = _split_bool(_strip_parens(expr), "or")
    if len(parts) > 1:
        kinds = [_expr_kind(p) for p in parts]
        if "true" in kinds:
            return "true"
        if "any-auth" in kinds:
            return "any-auth"
        if any(_RX_IS_NULL.match(_strip_parens(p)) for p in parts):
            return "null-owner"
    return "other"


def _null_owner_col(expr: Optional[str]) -> str:
    for p in _split_bool(_strip_parens(expr or ""), "or"):
        m = _RX_IS_NULL.match(_strip_parens(p))
        if m:
            return m.group(1).lower()
    return "owner"


class _SqlIndex:
    def __init__(self) -> None:
        self.exposed: Set[str] = {"public", "graphql_public"}
        self.tables: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.rls: Dict[Tuple[str, str], bool] = {}
        self.dynamic_rls = False
        self.granted: Set[Tuple[str, str]] = set()
        self.grant_all = False
        self.revoked: Dict[Tuple[str, str], Set[str]] = {}
        self.policies: Dict[Tuple[Tuple[str, str], str], Dict[str, Any]] = {}
        self.functions: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.func_path_fixed: Set[Tuple[str, str]] = set()
        self.func_invoker: Set[Tuple[str, str]] = set()
        # roles that can still EXECUTE each function: PUBLIC holds it by default in
        # Postgres, and Supabase's default privileges grant anon and authenticated too
        self.func_exec: Dict[Tuple[str, str], Set[str]] = {}
        self.func_svc_grant: Set[Tuple[str, str]] = set()
        self.func_anon_grant: Set[Tuple[str, str]] = set()
        self.default_func_revoked: Dict[str, Set[str]] = {}
        self.views: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.meta_hits: List[Tuple[str, int, str, str]] = []
        self.col_update_grant: Dict[Tuple[str, str], Set[str]] = {}
        self.update_revoked: Set[Tuple[str, str]] = set()
        self.triggers: Dict[Tuple[str, str], Set[Tuple[str, str]]] = {}
        self.auth_inserts: List[Tuple[str, int, str, bool]] = []
        self.email_admin: List[Tuple[str, int, str]] = []
        # DO blocks that drop policies through a loop the index could not expand
        self.dynamic_policy_drops: List[Tuple[str, int, str]] = []

    def rename(self, old: Tuple[str, str], new: Tuple[str, str]) -> None:
        if old in self.tables:
            self.tables[new] = self.tables.pop(old)
        if old in self.rls:
            self.rls[new] = self.rls.pop(old)
        if old in self.granted:
            self.granted.discard(old)
            self.granted.add(new)
        if old in self.revoked:
            self.revoked[new] = self.revoked.pop(old)
        for key in [k for k in self.policies if k[0] == old]:
            self.policies[(new, key[1])] = self.policies.pop(key)

    def drop(self, key: Tuple[str, str]) -> None:
        self.tables.pop(key, None)
        self.rls.pop(key, None)
        for k in [k for k in self.policies if k[0] == key]:
            del self.policies[k]

    def hidden(self, key: Tuple[str, str]) -> bool:
        """True when grants to both anon and authenticated were revoked."""
        roles = self.revoked.get(key, set())
        return "anon" in roles and "authenticated" in roles

    def exec_roles(self, key: Tuple[str, str]) -> Set[str]:
        if key not in self.func_exec:
            self.func_exec[key] = {"public", "anon", "authenticated"} - self.default_func_revoked.get(key[0], set())
        return self.func_exec[key]


def _exposed_schemas(ctx: Any) -> Set[str]:
    text = ctx.read("supabase/config.toml")
    if not text:
        return {"public", "graphql_public"}
    m = re.search(r"(?ms)^\s*\[api\]\s*$(.*?)(?=^\s*\[|\Z)", text)
    if m:
        s = re.search(r"^\s*schemas\s*=\s*\[([^\]]*)\]", m.group(1), re.M)
        if s:
            found = set(re.findall(r"[\"']([^\"']+)[\"']", s.group(1)))
            if found:
                return {x.lower() for x in found}
    return {"public", "graphql_public"}


def _parse_policy_rest(rest: str) -> Dict[str, Any]:
    cut = len(rest)
    for rx in (r"\busing\s*\(", r"\bwith\s+check\s*\("):
        m = re.search(rx, rest, re.I)
        if m:
            cut = min(cut, m.start())
    head = rest[:cut]
    d: Dict[str, Any] = {}
    m = re.search(r"\bas\s+(permissive|restrictive)\b", head, re.I)
    if m:
        d["permissive"] = m.group(1).lower() == "permissive"
    m = re.search(r"\bfor\s+(all|select|insert|update|delete)\b", head, re.I)
    if m:
        d["cmd"] = m.group(1).lower()
    m = re.search(r"\bto\s+(.+)$", head, re.I | re.S)
    if m:
        d["roles"] = _roles(m.group(1))
    u = _expr_after(rest, r"\busing\s*\(")
    if u is not None:
        d["using"] = u
    c = _expr_after(rest, r"\bwith\s+check\s*\(")
    if c is not None:
        d["check"] = c
    return d


def _table_columns(stmt: str, after: int) -> Set[str]:
    i = stmt.find("(", after)
    if i == -1:
        return set()
    body = _balanced(stmt, i + 1)
    if not body:
        return set()
    cols = set()
    for item in _split_top(body):
        words = item.strip().split()
        if not words:
            continue
        w = words[0].strip('"').lower()
        if w not in _CONSTRAINT_WORDS:
            cols.add(w)
    return cols


def _build_sql_index(ctx: Any) -> _SqlIndex:
    idx = _SqlIndex()
    idx.exposed = _exposed_schemas(ctx)
    for rel in ctx.glob("*.sql"):
        text = ctx.read(rel)
        if not text or _NOT_POSTGRES.search(text):
            continue
        clean, flat, spans = _sql_split(text)
        for s, e in spans:
            st = flat[s:e]
            body = st.lstrip()
            if not body:
                continue
            off = s + (len(st) - len(body))
            raw = clean[off:e]
            line = ctx.line_of(rel, off)
            _index_statement(idx, ctx, rel, off, line, body, raw)
    return idx


_RX_FOREACH = re.compile(r"\bforeach\s+(\w+)\s+in\s+array\s+(?:array\s*)?\[(.*?)\]\s*(?:::\s*[\w\[\]]+\s*)?loop\b(.*?)"
                         r"\bend\s+loop\b", re.I | re.S)
_RX_FOR_UNNEST = re.compile(r"\bfor\s+(\w+)\s+in\s+(?:select\s+)?unnest\s*\(\s*(?:array\s*)?\[(.*?)\]\s*"
                            r"(?:::\s*[\w\[\]]+\s*)?\)\s*(?:as\s+\w+\s*)?loop\b(.*?)\bend\s+loop\b", re.I | re.S)
_RX_EXEC_FMT = re.compile(r"\bexecute\s+format\s*\(\s*'((?:[^']|'')*)'\s*,\s*(\w+)\s*\)", re.I | re.S)
_RX_EMAIL_LIT = r"'[^'\s@]+@[^'\s]+'"
_RX_JWT_EMAIL = r"(?:auth\s*\.\s*jwt\s*\(\s*\)\s*->>?\s*'email'|auth\s*\.\s*email\s*\(\s*\))"
_RX_EMAIL_ADMIN = re.compile(
    _RX_JWT_EMAIL + r"[\s)',]{0,30}(?:=|\bin\s*\()\s*" + _RX_EMAIL_LIT + r"|"
    + _RX_EMAIL_LIT + r"\s*=\s*(?:\w+\s*\(\s*)*" + _RX_JWT_EMAIL, re.I)


def _func_names(raw: str) -> List[Tuple[str, str]]:
    """Function names in a GRANT, REVOKE or DROP FUNCTION list (argument lists dropped)."""
    out = []
    for part in _split_top(raw):
        m = re.match(r"\s*(" + _NAME + r")\s*(?:\(|$)", part.strip())
        if m:
            out.append(_qname(m.group(1)))
    return out


def _func_targets(idx: "_SqlIndex", target: str) -> Optional[List[Tuple[str, str]]]:
    """Functions named by a GRANT or REVOKE target, or None when it is not about functions."""
    m = re.match(r"(?:function|procedure|routine)s?\s+(.+)$", target, re.I | re.S)
    if m:
        return _func_names(m.group(1))
    m = re.match(r"all\s+(?:functions|routines|procedures)\s+in\s+schema\s+(.+)$", target, re.I | re.S)
    if m:
        schemas = {s.strip().strip('"').lower() for s in m.group(1).split(",")}
        return [k for k in idx.functions if k[0] in schemas]
    return None


def _func_info(rel: str, line: int, st: str, raw: str) -> Dict[str, Any]:
    m = _RX_DOLLAR_BODY.search(raw)
    body = m.group(2) if m else raw
    code = re.sub(r"'(?:[^']|'')*'", "''", body)
    ret = _RX_RETURNS.search(st)
    rtype = ""
    if ret:
        if ret.group(1) and ret.group(1).lower().startswith("setof"):
            rtype = "setof"
        elif ret.group(1):
            rtype = "table"
            tcols = _balanced(st, ret.end(1))
            types = [c.split()[1].strip('"').lower() for c in _split_top(tcols or "") if len(c.split()) > 1]
            if types and all(t in _SCALAR_RET or t in _FLAG_TYPES for t in types):
                rtype = "boolean"
        else:
            rtype = ret.group(2).split(".")[-1].strip().strip('"').lower()
    return {
        "rel": rel, "line": line,
        "definer": bool(re.search(r"\bsecurity\s+definer\b", st, re.I)),
        "search_path": bool(_RX_SET_PATH.search(st)),
        "trigger": bool(_RX_RET_TRIGGER.search(st)),
        "auth": bool(_RX_AUTH_REF.search(raw)),
        "failopen": bool(_RX_FAIL_OPEN.search(body)),
        "stable": bool(re.search(r"\b(?:stable|immutable)\b", st, re.I)),
        "returns": rtype,
        "dml": bool(_RX_DML.search(code)),
        "secret": bool(_RX_SECRET_READ.search(code)),
        "personal": bool(_RX_PERSONAL_READ.search(code)),
        "calls": {((s or "public").lower(), n.lower()) for s, n in _RX_CALL.findall(code)},
        "guards": {g.lower() for g in _RX_GUARD_CALL.findall(code) + _RX_SELECT_GUARD.findall(code)},
        "body": code.lower()[:20000],
        "email_admin": bool(_RX_EMAIL_ADMIN.search(body)),
        "meta": None,
    }


def _top_select_list(text: str) -> Optional[str]:
    """The select list of the top-level SELECT in text (up to its FROM)."""
    m = re.match(r"\s*\(?\s*select\s+(?:distinct\s+)?", text, re.I)
    if not m:
        return None
    depth, i, n = 0, m.end(), len(text)
    while i < n:
        c = text[i]
        if c == "'":
            j = text.find("'", i + 1)
            i = n if j == -1 else j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif (depth == 0 and text[i:i + 4].lower() == "from" and not (text[i - 1].isalnum() or text[i - 1] == "_")
              and not (text[i + 4:i + 5].isalnum() or text[i + 4:i + 5] == "_")):
            return text[m.end():i]
        i += 1
    return text[m.end():]


def _aggregate_only(view_body: str) -> bool:
    """True when the view selects only aggregates (count, exists, bool_or), no row data."""
    sel = _top_select_list(view_body)
    if not sel or not sel.strip():
        return False
    for item in _split_top(sel):
        item = re.sub(r"(?is)\s+as\s+\"?\w+\"?\s*$", "", item.strip())
        item = re.sub(r"(?:::\s*\w+)+$", "", item).strip()
        item = _strip_parens(item)
        if not re.match(r"(?i)(?:not\s+)?(?:count|exists|bool_or|bool_and|every)\s*\(", item):
            return False
    return True


def _expand_do(idx: "_SqlIndex", ctx: Any, rel: str, off: int, raw: str) -> str:
    """Index what a DO block runs through EXECUTE format('... %I ...', v) inside a loop
    over a literal array, one statement per table name. Returns raw with the
    expanded EXECUTE calls blanked, so the caller can tell what is left."""
    rest = list(raw)
    for rx in (_RX_FOREACH, _RX_FOR_UNNEST):
        for lm in rx.finditer(raw):
            var = lm.group(1).lower()
            names = [s.replace("''", "'").strip() for s in re.findall(r"'((?:[^']|'')*)'", lm.group(2))]
            names = [n for n in names if re.fullmatch(r"[\w$]+(?:\.[\w$]+)?", n)]
            if not names:
                continue
            base = lm.start(3)
            for em in _RX_EXEC_FMT.finditer(lm.group(3)):
                if em.group(2).lower() != var:
                    continue
                tmpl = em.group(1).replace("''", "'")
                if tmpl.count("%I") + tmpl.count("%s") != 1 or "%L" in tmpl:
                    continue
                eoff = off + base + em.start()
                line = ctx.line_of(rel, eoff)
                for name in names:
                    stmt = tmpl.replace("%I", name).replace("%s", name).strip().rstrip(";")
                    _index_statement(idx, ctx, rel, eoff, line, stmt, stmt, True)
                _blank(rest, base + em.start(), base + em.end())
    return "".join(rest)


def _index_statement(idx: "_SqlIndex", ctx: Any, rel: str, off: int, line: int, st: str, raw: str,
                     generated: bool = False) -> None:
    low = st[:40].lower()
    is_policy = low.startswith(("create policy", "alter policy"))
    is_func = bool(_RX_CREATE_FUNC.match(st))
    meta = None
    # user_metadata used in a policy or read for a role anywhere
    if not generated and _RX_META_ANY.search(raw):
        rx = _RX_META_ANY if is_policy else _RX_META_ROLE
        m = rx.search(raw)
        if m:
            meta = _line_at(ctx, rel, off + m.start())
            if not is_policy and not is_func:
                kind = "backfill" if re.match(r"(?:update|insert|delete|with|do)\b", low) else "role"
                idx.meta_hits.append((rel, meta[0], meta[1], kind))

    if re.match(r"do\b", low):
        left = _expand_do(idx, ctx, rel, off, raw)
        if _RX_RLS_ON.search(left):
            idx.dynamic_rls = True
        if re.search(r"\bexecute\b", left, re.I) and re.search(r"\bdrop\s+policy\b", left, re.I):
            idx.dynamic_policy_drops.append((rel, line, raw.lower()))
        return
    # RLS switched on inside an event trigger function
    if _RX_RLS_ON.search(raw) and not _RX_RLS_ON.search(st):
        idx.dynamic_rls = True
    if not generated and re.match(r"insert\s+into\s+\"?auth\"?\s*\.\s*\"?(?:users|identities)\b", st, re.I):
        idx.auth_inserts.append((rel, line, _line_at(ctx, rel, off)[1], "encrypted_password" in raw.lower()))
        return

    m = _RX_CREATE_TABLE.match(st)
    if m:
        if m.group(1):
            return
        key = _qname(m.group(2))
        if re.search(r"\bpartition\s+of\b", st, re.I):
            return
        idx.tables[key] = {"rel": rel, "line": line, "cols": _table_columns(st, m.end())}
        idx.rls.setdefault(key, False)
        return
    m = _RX_ALTER_TABLE.match(st)
    if m:
        key = _qname(m.group(1))
        rest = m.group(2)
        if _RX_RLS_ON.search(rest):
            idx.rls[key] = True
        elif _RX_RLS_OFF.search(rest):
            idx.rls[key] = False
        if key in idx.tables:
            for c in re.findall(r"\badd\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?\"?([A-Za-z_]\w*)\"?", rest, re.I):
                if c.lower() not in _CONSTRAINT_WORDS and c.lower() not in ("column", "if"):
                    idx.tables[key]["cols"].add(c.lower())
        r = re.search(r"\brename\s+to\s+(" + _NAME + r")", rest, re.I)
        if r:
            new = _qname(r.group(1))
            if "." not in r.group(1):
                new = (key[0], new[1])
            idx.rename(key, new)
        return
    m = _RX_DROP_TABLE.match(st)
    if m:
        for key in _names(m.group(1)):
            idx.drop(key)
        return
    m = _RX_DEFAULT_PRIV.match(st)
    if m:
        idx.default_func_revoked.setdefault(m.group(1).lower(), set()).update(_roles(m.group(2)))
        return
    m = _RX_GRANT.match(st)
    if m:
        privs, target, roles = m.group(1), m.group(2).strip(), _roles(m.group(3))
        keys = _func_targets(idx, target)
        if keys is not None:
            for key in keys:
                idx.exec_roles(key).update(roles & {"anon", "authenticated", "public"})
                if roles & {"anon", "public"}:
                    idx.func_anon_grant.add(key)
                if "service_role" in roles:
                    idx.func_svc_grant.add(key)
            return
        if not roles & {"anon", "authenticated", "public"}:
            return
        if re.match(r"all\s+tables\s+in\s+schema\s+public\b", target, re.I):
            idx.grant_all = True
        elif not re.match(r"(?:schema|sequence|all\s)", target, re.I):
            target = re.sub(r"^table\s+", "", target, flags=re.I)
            cols = re.search(r"\bupdate\s*\(([^)]*)\)", privs, re.I)
            for key in _names(target):
                idx.granted.add(key)
                if cols:
                    idx.col_update_grant.setdefault(key, set()).update(
                        c.strip().strip('"').lower() for c in cols.group(1).split(","))
        return
    m = _RX_REVOKE.match(st)
    if m:
        privs, target, roles = m.group(1), m.group(2).strip(), _roles(m.group(3))
        keys = _func_targets(idx, target)
        if keys is not None:
            if re.search(r"\b(?:execute|all)\b", privs, re.I):
                for key in keys:
                    idx.exec_roles(key).difference_update(roles)
        elif not re.match(r"(?:schema|sequence|all\s)", target, re.I):
            target = re.sub(r"^table\s+", "", target, flags=re.I)
            for key in _names(target):
                idx.revoked.setdefault(key, set()).update(roles)
                if roles & {"authenticated", "public"} and re.search(r"\b(?:update|all)\b(?!\s*\()", privs, re.I):
                    idx.update_revoked.add(key)
        return
    m = _RX_CREATE_POLICY.match(st)
    if m:
        tkey = _qname(m.group(2))
        pname = m.group(1).strip('"').lower()
        d = _parse_policy_rest(m.group(3))
        pol = {"rel": rel, "line": line, "cmd": d.get("cmd", "all"), "roles": d.get("roles", {"public"}),
               "permissive": d.get("permissive", True), "using": d.get("using"), "check": d.get("check"),
               "evidence": ctx.lines(rel)[line - 1].strip() if line <= len(ctx.lines(rel)) else "",
               "meta": meta, "email_admin": bool(_RX_EMAIL_ADMIN.search(raw))}
        idx.policies[(tkey, pname)] = pol
        return
    m = _RX_ALTER_POLICY.match(st)
    if m:
        tkey = _qname(m.group(2))
        pname = m.group(1).strip('"').lower()
        pol = idx.policies.get((tkey, pname))
        if pol is None:
            return
        rest = m.group(3)
        r = re.match(r"\s*rename\s+to\s+(" + _PNAME + r")", rest, re.I)
        if r:
            idx.policies[(tkey, r.group(1).strip('"').lower())] = idx.policies.pop((tkey, pname))
            return
        d = _parse_policy_rest(rest)
        changed = False
        for k in ("roles", "using", "check"):
            if k in d:
                pol[k] = d[k]
                changed = True
        if changed:
            pol["rel"], pol["line"] = rel, line
            pol["evidence"] = ctx.lines(rel)[line - 1].strip() if line <= len(ctx.lines(rel)) else ""
            pol["meta"] = meta
            pol["email_admin"] = bool(_RX_EMAIL_ADMIN.search(raw))
        return
    m = _RX_DROP_POLICY.match(st)
    if m:
        idx.policies.pop((_qname(m.group(2)), m.group(1).strip('"').lower()), None)
        return
    m = _RX_CREATE_FUNC.match(st)
    if m:
        key = _qname(m.group(1))
        info = _func_info(rel, line, st, raw)
        info["meta"] = meta
        idx.functions[key] = info
        idx.exec_roles(key)
        idx.func_path_fixed.discard(key)
        idx.func_invoker.discard(key)
        return
    m = _RX_DROP_FUNC.match(st)
    if m:
        for key in _func_names(m.group(1)):
            idx.functions.pop(key, None)
            idx.func_exec.pop(key, None)
            idx.func_svc_grant.discard(key)
            idx.func_anon_grant.discard(key)
        return
    m = _RX_ALTER_FUNC.match(st)
    if m:
        key = _qname(m.group(1))
        rest = m.group(2)
        if _RX_SET_PATH.search(rest):
            idx.func_path_fixed.add(key)
        if re.search(r"\bsecurity\s+invoker\b", rest, re.I):
            idx.func_invoker.add(key)
        return
    m = _RX_CREATE_TRIGGER.match(st)
    if m:
        if m.group(1).lower() == "before" and re.search(r"\b(?:update|insert)\b", m.group(2), re.I):
            idx.triggers.setdefault(_qname(m.group(3)), set()).add(_qname(m.group(4)))
        return
    m = _RX_CREATE_VIEW.match(st)
    if m:
        if m.group(1):
            return
        key = _qname(m.group(3))
        rest = m.group(4)
        as_m = re.search(r"\bas\b", rest, re.I)
        head = rest[:as_m.start()] if as_m else rest
        inv = _RX_INVOKER.search(head)
        invoker = bool(inv) and (inv.group(1) or "true").lower() in ("true", "on", "1", "yes")
        idx.views[key] = {"rel": rel, "line": line, "materialized": bool(m.group(2)), "invoker": invoker,
                          "auth_users": bool(re.search(r"\bauth\s*\.\s*users\b", rest, re.I)),
                          "aggregate": bool(as_m) and _aggregate_only(rest[as_m.end():])}
        return
    m = _RX_ALTER_VIEW.match(st)
    if m:
        key = _qname(m.group(1))
        inv = _RX_INVOKER.search(m.group(2))
        if inv and key in idx.views:
            idx.views[key]["invoker"] = (inv.group(1) or "true").lower() in ("true", "on", "1", "yes")
        return
    m = _RX_DROP_VIEW.match(st)
    if m:
        for key in _names(m.group(1)):
            idx.views.pop(key, None)


def _sql_index(ctx: Any) -> _SqlIndex:
    return ctx.memo("dataauth-sql-index", lambda: _build_sql_index(ctx))


_FROM_TABLE = re.compile(r"""\.(?:from|table)\(\s*['"`]([A-Za-z_][\w]*)['"`]\s*\)""")


def _app_tables(ctx: Any) -> Set[str]:
    """Table names the app code queries through the Data API (.from('x'))."""
    def build() -> Set[str]:
        out: Set[str] = set()
        for rel in ctx.glob(*(_WEB_GLOBS + ["*.py", "*.dart"])):
            if _is_test(rel):
                continue
            text = ctx.read(rel)
            if ".from(" not in text and ".table(" not in text:
                continue
            out.update(t.lower() for t in _FROM_TABLE.findall(text))
        return out
    return ctx.memo("dataauth-app-tables", build)


def check_rls_disabled(path: str, text: str, ctx: Any) -> List[Hit]:
    idx = _sql_index(ctx)
    if idx.dynamic_rls:
        return []
    used = None
    hits = []
    for key, t in idx.tables.items():
        if t["rel"] != path or key[0] not in idx.exposed or idx.rls.get(key):
            continue
        if idx.hidden(key):
            continue
        if used is None:
            used = _app_tables(ctx)
        has_policy = any(k[0] == key for k in idx.policies)
        name = "%s.%s" % key
        reached = key[1] in used or key in idx.granted or idx.grant_all
        sev = "critical" if reached else "high"
        if has_policy:
            msg = ("table %s has policies but RLS is never enabled, so the policies do nothing and the "
                   "public anon key can read and write every row" % name)
        elif key[1] in used:
            msg = ("table %s is queried by the app but RLS is never enabled; the public anon key can read "
                   "and write every row" % name)
        else:
            msg = ("table %s never gets RLS enabled; on projects that expose public tables to the Data "
                   "API, the anon key can read and write every row" % name)
        ev = ctx.lines(path)[t["line"] - 1].strip() if t["line"] <= len(ctx.lines(path)) else ""
        hits.append(Hit(t["line"], ev, msg, sev))
    return hits


_SERVICE_ROLES = {"service_role", "postgres", "supabase_admin", "supabase_auth_admin"}
_ADDRESS_COL = {"address", "street_address"}
_OWNER_COLS = {"user_id", "owner_id", "profile_id", "customer_id", "created_by", "author_id", "member_id",
               "account_id", "patient_id", "email", "userid", "ownerid"}
_SEV_DOWN = {"critical": "high", "high": "medium", "medium": "low", "low": "low", "info": "info"}


def _signup_open(ctx: Any) -> Optional[bool]:
    """enable_signup from supabase/config.toml [auth], or None when it is not set."""
    text = ctx.read("supabase/config.toml")
    if not text:
        return None
    m = re.search(r"(?ms)^\s*\[auth\]\s*$(.*?)(?=^\s*\[|\Z)", text)
    if m:
        s = re.search(r"^\s*enable_signup\s*=\s*(true|false)\b", m.group(1), re.M)
        if s:
            return s.group(1) == "true"
    return None


def _person_owned(tkey: Tuple[str, str], cols: Set[str]) -> bool:
    return bool(cols & _OWNER_COLS or _PRIVATE_NAME.search(tkey[1]) or _PRIVATE_DOC.match(tkey[1]))


def check_permissive_policy(path: str, text: str, ctx: Any) -> List[Hit]:
    idx = _sql_index(ctx)
    hits: List[Hit] = []
    shared: List[Tuple[Dict[str, Any], Tuple[str, str], str]] = []
    null_owner: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for (tkey, pname), p in idx.policies.items():
        if p["rel"] != path or not p["permissive"]:
            continue
        roles = p["roles"] or {"public"}
        if roles <= _SERVICE_ROLES:
            continue
        anon = bool(roles & {"public", "anon"})
        cmd = p["cmd"]
        expr = p["check"] if cmd == "insert" else p["using"]
        kind = _expr_kind(expr)
        table = "%s.%s" % tkey
        info = idx.tables.get(tkey) or {}
        cols = info.get("cols", set())
        sensitive = sorted(c for c in cols if _SENSITIVE_COL.match(c)
                           and (c not in _ADDRESS_COL or _person_owned(tkey, cols)))
        if kind == "null-owner":
            if cmd == "select" and not (sensitive or _PRIVATE_NAME.search(tkey[1])):
                continue
            g = null_owner.setdefault(tkey, {"line": p["line"], "evidence": p["evidence"], "cmds": set(),
                                             "anon": False, "col": _null_owner_col(expr)})
            if p["line"] < g["line"]:
                g["line"], g["evidence"] = p["line"], p["evidence"]
            g["cmds"].add(cmd)
            g["anon"] = g["anon"] or anon
            continue
        if kind not in ("true", "any-auth"):
            continue
        if kind == "any-auth":
            anon = False
        who = "anyone, even logged out," if anon else "any signed-in user"
        if cmd in ("update", "delete", "all"):
            verb = {"update": "change", "delete": "delete", "all": "read, change and delete"}[cmd]
            sev = "critical" if anon else "high"
            msg = "policy on %s lets %s %s every row" % (table, who, verb)
        elif cmd == "insert":
            sev = "high" if anon else "medium"
            msg = ("policy on %s lets %s insert rows with any owner or values; fine only for a public "
                   "form table with no owner column" % (table, who))
        else:
            storage = tkey == ("storage", "objects")
            if not (sensitive or _PRIVATE_NAME.search(tkey[1]) or storage):
                continue
            sev = "high" if anon else "medium"
            if storage:
                what = "every file in every Storage bucket"
            elif sensitive:
                what = "every row, including %s" % ", ".join(sensitive[:3])
            else:
                what = "every row"
            msg = "policy on %s lets %s read %s; fine only if the table is public by design" % (table, who, what)
        drop = [d for d in idx.dynamic_policy_drops if d[0] > path and (
            re.search(r"\b" + re.escape(tkey[1]) + r"\b", d[2]) or pname in d[2])]
        if drop:
            msg += " (a DO block in %s may drop this policy; check it)" % drop[0][0]
            sev = _SEV_DOWN[sev]
        if anon:
            hits.append(Hit(p["line"], p["evidence"], msg, sev))
        else:
            shared.append(({"line": p["line"], "evidence": p["evidence"], "msg": msg, "sev": sev}, tkey, cmd))
    for tkey, g in null_owner.items():
        cmds = g["cmds"]
        verbs = [v for c, v in (("select", "read"), ("insert", "insert"), ("update", "change"), ("delete", "delete"))
                 if c in cmds or "all" in cmds]
        who = "anyone, even logged out," if g["anon"] else "any signed-in user"
        col = g["col"]
        msg = ("policies on %s.%s let %s %s rows whose %s is NULL" % (tkey[0], tkey[1], who,
                                                                      ", ".join(verbs), col))
        if "insert" in cmds or "all" in cmds:
            msg += ", and the insert rule lets them create such rows"
        msg += "; make %s NOT NULL DEFAULT auth.uid() and drop the IS NULL branch" % col
        sev = "medium" if cmds == {"select"} else "high"
        hits.append(Hit(g["line"], g["evidence"], msg, sev))
    tables = sorted({"%s.%s" % t if t[0] != "public" else t[1] for _, t, _ in shared})
    if len(tables) >= 3:
        # one design decision (every signed-in user shares every row), reported once per file
        first = min((h for h, _, _ in shared), key=lambda h: h["line"])
        signup = _signup_open(ctx)
        writes = any(c != "select" for _, _, c in shared)
        shown = ", ".join(tables[:6]) + (", ..." if len(tables) > 6 else "")
        msg = ("%d tables (%s) let any signed-in user %s every row; fine for a single-team app only if "
               "public sign-ups are disabled" % (len(tables), shown, "read and change" if writes else "read"))
        if signup is False:
            msg += "; supabase/config.toml turns sign-ups off, confirm the same in the dashboard"
            sev = "low"
        else:
            msg += ("; supabase/config.toml leaves sign-ups on, so anyone can create an account and reach it all"
                    if signup else "; check whether anyone can sign up")
            sev = "high" if writes else "medium"
        hits.append(Hit(first["line"], first["evidence"], msg, sev))
    else:
        hits.extend(Hit(h["line"], h["evidence"], h["msg"], h["sev"]) for h, _, _ in shared)
    return _merge_same_line(hits)


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_RX_HIT_TABLE = re.compile(r"^polic(?:y|ies) on (\S+?) let")


def _merge_same_line(hits: List[Hit]) -> List[Hit]:
    """One finding per line: a DO-block loop creates a policy per table from a single
    EXECUTE line, and the engine keeps one finding per (rule, file, line)."""
    by_line: Dict[int, List[Hit]] = {}
    for h in hits:
        by_line.setdefault(h.line, []).append(h)
    out = []
    for line in sorted(by_line):
        group = sorted(by_line[line], key=lambda h: _SEV_ORDER.get(h.severity or "high", 1))
        first = group[0]
        others = []
        for h in group[1:]:
            m = _RX_HIT_TABLE.match(h.message or "")
            if m and m.group(1) not in others:
                others.append(m.group(1))
        if others:
            first = first._replace(message="%s (the same statement also covers %s)" % (first.message,
                                                                                    ", ".join(others[:5])))
        out.append(first)
    return out


_PRIV_COL = re.compile(r"^(?:role|roles|user_?role|is_?admin|admin|is_?staff|is_?moderator|is_?verified|verified|"
                       r"credits?|points|balance|coins|tokens|quota|plan|tier|is_?premium|is_?pro|is_?paid|"
                       r"subscription\w*|access_?level|account_?type|permissions?|is_?approved|approved)$")
# Tables that describe a user, where those columns grant something. A chat message's
# role or a budget account's balance belongs to the user and is not a privilege.
_USERISH_TABLE = re.compile(r"^(?:profiles?|users?|user_\w+|\w+_profiles?|\w+_users|members?|\w+_members?|"
                            r"memberships?|customers?|subscriptions?|wallets?|credits?|players?|students?|"
                            r"employees?|staff|accounts?)$")


def check_own_row_privileged(path: str, text: str, ctx: Any) -> List[Hit]:
    idx = _sql_index(ctx)
    hits = []
    seen: Set[Tuple[str, str]] = set()
    for (tkey, pname), p in sorted(idx.policies.items(), key=lambda kv: (kv[1]["cmd"] == "insert", kv[1]["line"])):
        if p["rel"] != path or not p["permissive"] or tkey in seen:
            continue
        cmd = p["cmd"]
        if cmd not in ("update", "all", "insert"):
            continue
        if not (p["roles"] or {"public"}) & {"authenticated", "public", "anon"}:
            continue
        exprs = [p["check"]] if cmd == "insert" else [p["using"], p["check"]]
        exprs = [e for e in exprs if e is not None]
        if not exprs or any(_expr_kind(e) != "owner" for e in exprs):
            continue
        info = idx.tables.get(tkey)
        if not info:
            continue
        if not _USERISH_TABLE.match(tkey[1]):
            continue
        cols = [c for c in sorted(info["cols"]) if _PRIV_COL.match(c)
                and not (tkey[1] in ("account", "accounts") and c == "balance")]
        if cmd != "insert":
            if tkey in idx.col_update_grant:
                cols = [c for c in cols if c in idx.col_update_grant[tkey]]
            elif tkey in idx.update_revoked:
                cols = []
        for fn in idx.triggers.get(tkey, set()):
            body = (idx.functions.get(fn) or {}).get("body", "")
            cols = [c for c in cols if not re.search(r"\b" + re.escape(c) + r"\b", body)]
        if not cols:
            continue
        seen.add(tkey)
        verb = "insert" if cmd == "insert" else "update"
        msg = ("policy on %s.%s lets each user %s their own row, including %s, so a user can set it themselves; "
               "limit the writable columns with a column grant or a BEFORE trigger" % (tkey[0], tkey[1], verb,
                                                                                      ", ".join(cols[:3])))
        hits.append(Hit(p["line"], p["evidence"], msg, "high"))
    return sorted(hits, key=lambda h: h.line)


def check_user_metadata(path: str, text: str, ctx: Any) -> List[Hit]:
    if path.endswith(".sql"):
        idx = _sql_index(ctx)
        hits = []
        for p in idx.policies.values():
            if p["rel"] == path and p.get("meta"):
                n, ev = p["meta"]
                hits.append(Hit(n, ev, "RLS policy reads user_metadata, which every user can edit with updateUser()"))
        # only the live definition of each function counts, not the ones a later migration replaced
        for f in idx.functions.values():
            if f["rel"] == path and f.get("meta"):
                n, ev = f["meta"]
                hits.append(Hit(n, ev, "role or plan read from user_metadata, which the user sets at sign-up and "
                                       "can edit with updateUser()"))
        for rel, n, ev, kind in idx.meta_hits:
            if rel != path:
                continue
            if kind == "backfill":
                hits.append(Hit(n, ev, "one-time data fix copies a role or plan from user_metadata; check the rows "
                                       "it touched", "low"))
            else:
                hits.append(Hit(n, ev, "role or plan read from user_metadata, which the user sets at sign-up and "
                                       "can edit with updateUser()"))
        return sorted(hits, key=lambda h: h.line)
    hits = []
    for i, line in enumerate(_code_lines(ctx, path), 1):
        if "user_metadata" in line and _CODE_META_ROLE.search(line):
            hits.append(Hit(i, line.strip()))
    return hits


_CODE_META_ROLE = re.compile(
    r"\buser_metadata\s*\??\.\s*" + _ROLEISH + r"\b|\buser_metadata\s*(?:\??\.)?\s*(?:\[|\.get\(\s*)\s*['\"]"
    + _ROLEISH + r"['\"]", re.I)


def check_definer_search_path(path: str, text: str, ctx: Any) -> List[Hit]:
    idx = _sql_index(ctx)
    hits = []
    for key, f in idx.functions.items():
        if f["rel"] != path or not f["definer"] or f["search_path"]:
            continue
        if key in idx.func_path_fixed or key in idx.func_invoker:
            continue
        ev = ctx.lines(path)[f["line"] - 1].strip() if f["line"] <= len(ctx.lines(path)) else ""
        hits.append(Hit(f["line"], ev, "security definer function %s.%s has no fixed search_path" % key))
    return hits


def _func_auth(idx: _SqlIndex) -> Tuple[Dict[Tuple[str, str], bool], Dict[Tuple[str, str], bool]]:
    """(checks the caller, has a fail-open check) per function, following calls
    into other indexed functions and guard helpers such as IF NOT is_admin() or
    PERFORM assert_role()."""
    by_name: Dict[str, List[Tuple[str, str]]] = {}
    for k in idx.functions:
        by_name.setdefault(k[1], []).append(k)
    safe: Dict[Tuple[str, str], bool] = {}
    fo: Dict[Tuple[str, str], bool] = {}
    for k, f in idx.functions.items():
        fo[k] = f["failopen"]
        safe[k] = f["auth"] and not f["failopen"]
        if not safe[k]:
            safe[k] = any(_GUARD_HELPER.match(g) for g in f["guards"] if g not in by_name)
    for _ in range(8):
        changed = False
        for k, f in idx.functions.items():
            callees = [c for c in f["calls"] if c in idx.functions and c != k]
            callees += [c for g in f["guards"] for c in by_name.get(g, []) if c != k]
            for c in callees:
                if safe[c] and not safe[k]:
                    safe[k] = changed = True
                if fo[c] and not fo[k] and not safe[k]:
                    fo[k] = changed = True
        if not changed:
            break
    return safe, fo


_PUBLIC_RPC = re.compile(r"(?i)(?:^|_)(?:public|guest|submit|contact|waitlist|newsletter|subscribe|feedback)(?:_|$)")


def check_definer_exposed(path: str, text: str, ctx: Any) -> List[Hit]:
    idx = _sql_index(ctx)
    safe, fo = ctx.memo("dataauth-func-auth", lambda: _func_auth(idx))
    table_names = {k[1] for k in idx.tables}
    hits: List[Hit] = []
    helpers: List[Tuple[int, str, str]] = []
    for key, f in idx.functions.items():
        if f["rel"] != path or not f["definer"] or f["trigger"]:
            continue
        if key[0] not in idx.exposed or key in idx.func_invoker:
            continue
        callers = idx.exec_roles(key) & {"public", "anon", "authenticated"}
        if not callers or safe.get(key):
            continue
        anon = bool(callers & {"public", "anon"})
        name = "%s.%s" % key
        ev = ctx.lines(path)[f["line"] - 1].strip() if f["line"] <= len(ctx.lines(path)) else ""
        if fo.get(key):
            if anon:
                hits.append(Hit(f["line"], ev, "security definer function %s is callable through /rest/v1/rpc by "
                                               "anon, and its role check starts with auth.uid() IS NOT NULL AND, so "
                                               "a caller with no session skips it" % name, "high"))
            continue
        rtype = f["returns"]
        scalar = rtype in _SCALAR_RET or bool(rtype and rtype not in _TEXTY_RET and rtype not in table_names)
        if f["secret"]:
            sev, what = "critical", ", reads secrets or Vault data"
        elif f["dml"]:
            sev, what = "high", ", writes data"
        elif scalar:
            helpers.append((f["line"], ev, name))
            continue
        elif f["personal"]:
            sev, what = ("high" if anon else "medium"), ", returns personal data (email, phone or auth.users)"
        else:
            sev, what = "medium", ""
        who = "anon" if anon else "any signed-in user"
        msg = ("security definer function %s is callable through /rest/v1/rpc by %s, bypasses RLS%s and never "
               "checks who is calling" % (name, who, what))
        if key in idx.func_anon_grant and sev != "critical" and _PUBLIC_RPC.search(key[1]):
            # granted to anon on purpose for a public form or page: check the input limits, not the caller
            sev = "low"
            msg += "; it is granted to anon on purpose, so confirm it validates its input and limits the rate"
        if key in idx.func_svc_grant and "public" in callers:
            msg += ("; GRANT TO service_role does not remove the default EXECUTE for PUBLIC, anon and "
                    "authenticated, so add revoke execute on function %s from public, anon, authenticated" % name)
        elif callers == {"public"}:
            msg += ("; EXECUTE was revoked from anon and authenticated, but PUBLIC still holds it and every role "
                    "inherits PUBLIC, so revoke it from public too")
        hits.append(Hit(f["line"], ev, msg, sev))
    if helpers:
        helpers.sort()
        names = [h[2] for h in helpers]
        shown = ", ".join(names[:5]) + (", ..." if len(names) > 5 else "")
        msg = ("%d read-only security definer helper%s (%s) return only a flag or an id and are callable through "
               "/rest/v1/rpc; low impact, but revoke execute from public and anon (and from authenticated when only "
               "policies use them)" % (len(names), "s" if len(names) > 1 else "", shown))
        hits.append(Hit(helpers[0][0], helpers[0][1], msg, "low"))
    return hits


def check_view_rls(path: str, text: str, ctx: Any) -> List[Hit]:
    idx = _sql_index(ctx)
    hits = []
    for key, v in idx.views.items():
        if v["rel"] != path or key[0] not in idx.exposed or idx.hidden(key):
            continue
        if v.get("aggregate"):
            continue
        name = "%s.%s" % key
        if v["materialized"]:
            msg = "materialized view %s is exposed to the Data API and cannot enforce RLS" % name
            sev = "critical" if v["auth_users"] else "high"
        elif v["invoker"]:
            continue
        elif v["auth_users"]:
            msg = "view %s exposes auth.users to the Data API and skips RLS" % name
            sev = "critical"
        else:
            msg = ("view %s runs with its owner's rights, so it skips the RLS policies of the tables it reads; "
                   "add security_invoker" % name)
            sev = "high"
        ev = ctx.lines(path)[v["line"] - 1].strip() if v["line"] <= len(ctx.lines(path)) else ""
        hits.append(Hit(v["line"], ev, msg, sev))
    return hits


_SEED_FILE = re.compile(r"(?i)(?:^|/)(?:seeds?|fixtures?|dev[-_]?data|demo[-_]?data)(?:/|[^/]*\.sql$)|(?:^|/)[^/]*seed[^/]*\.sql$")
_MIGRATION_DIR = re.compile(r"(?i)(?:^|/)(?:migrations?|drizzle|schemas?)/")


def check_seeded_auth_users(path: str, text: str, ctx: Any) -> List[Hit]:
    if _SEED_FILE.search(path) or not _MIGRATION_DIR.search(path):
        return []
    hits = []
    for rel, n, ev, pw in _sql_index(ctx).auth_inserts:
        if rel != path:
            continue
        msg = ("migration inserts accounts straight into auth.users%s; migrations run in production, so these "
               "accounts go live there: move them to supabase/seed.sql or delete them after deploy"
               % (" with a fixed password hash" if pw else ""))
        hits.append(Hit(n, ev, msg))
    return hits


def check_admin_by_email(path: str, text: str, ctx: Any) -> List[Hit]:
    idx = _sql_index(ctx)
    found = []
    for (tkey, pname), p in idx.policies.items():
        if p["rel"] == path and p.get("email_admin"):
            found.append((p["line"], p["evidence"], "policy on %s.%s" % tkey))
    for key, f in idx.functions.items():
        if f["rel"] == path and f.get("email_admin") and f["definer"]:
            ev = ctx.lines(path)[f["line"] - 1].strip() if f["line"] <= len(ctx.lines(path)) else ""
            found.append((f["line"], ev, "function %s.%s" % key))
    if not found:
        return []
    found.sort()
    what = sorted({w for _, _, w in found})
    msg = ("%s grant%s access by comparing the JWT email to a fixed address; with email confirmation off, or "
           "before the owner signs up, anyone who registers that address gets it. Use a roles table or an "
           "app_metadata claim" % (", ".join(what[:3]) + (", ..." if len(what) > 3 else ""),
                                   "s" if len(what) == 1 else ""))
    return [Hit(found[0][0], found[0][1], msg)]


# ---------------------------------------------------------------------------
# Supabase: client and server code
# ---------------------------------------------------------------------------

_SVC_REF = re.compile(r"service[_-]?role|supabase_?service_?key|\bservice_?key\b|\bsb_secret_|supabase_?secret_?key|"
                      r"SUPABASE_SECRET", re.I)
_SVC_LITERAL = re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}")
_SB_PREFIX_LIT = re.compile(r"""(['"`])sb_(?:secret|publishable)_\1""")
_IMPORT_RX = re.compile(r"""(?:\bfrom\s+|\bimport\s*\(\s*|\brequire\s*\(\s*|^\s*import\s+)['"]((?:\.{1,2}/|@/|~/)[^'"]+)['"]""",
                        re.M)
_RESOLVE_EXTS = ("", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", "/index.ts", "/index.tsx", "/index.js",
                 "/index.jsx")


def _resolve_import(ctx: Any, rel: str, spec: str) -> Optional[str]:
    if spec.startswith(("@/", "~/")):
        bases = ["src/" + spec[2:], spec[2:]]
        top = rel.split("/", 1)[0]
        if top not in ("src", "app", "pages", "components", "lib") and "/" in rel:
            bases.insert(0, top + "/src/" + spec[2:])
            bases.insert(1, top + "/" + spec[2:])
    else:
        base = os.path.normpath(os.path.join(os.path.dirname(rel), spec)).replace("\\", "/")
        if base.startswith(".."):
            return None
        bases = [base]
    files = ctx.memo("dataauth-fileset", lambda: set(ctx.files))
    for b in bases:
        for ext in _RESOLVE_EXTS:
            if b + ext in files:
                return b + ext
    return None


def _svc_line_hits(ctx: Any, rel: str) -> List[Tuple[int, str]]:
    """Lines that reference the service key by a non-public name.

    Literal keys are left to find_secrets.py and public-prefixed names
    (NEXT_PUBLIC_..., VITE_...) to the secret-public-env-prefix rule, so the
    same line is not reported twice."""
    out = []
    for i, line in enumerate(_code_lines(ctx, rel), 1):
        if not line:
            continue
        # the bare 'sb_secret_' prefix in a key-type check (value.startsWith('sb_secret_')) names no key
        line = _SB_PREFIX_LIT.sub("", line)
        if not _SVC_REF.search(line):
            continue
        if _SVC_LITERAL.search(line) or _PUBLIC_ENV.search(line):
            continue
        out.append((i, line.strip()))
    return out


def check_service_key_client(path: str, text: str, ctx: Any) -> List[Hit]:
    hits: List[Hit] = []
    seen: Set[Tuple[str, int]] = set()
    for rel in ctx.client_files:
        if _is_test(rel):
            continue
        for n, ev in _svc_line_hits(ctx, rel):
            if (rel, n) not in seen:
                seen.add((rel, n))
                hits.append(Hit(n, ev, None, None, rel))
        for m in _IMPORT_RX.finditer(ctx.read(rel)):
            target = _resolve_import(ctx, rel, m.group(1))
            if not target or target == rel or ctx.is_client_file(target) or _is_test(target):
                continue
            ttext = ctx.read(target)
            if _SERVER_ONLY.search(ttext) or _USE_SERVER.match(ttext):
                continue
            for n, ev in _svc_line_hits(ctx, target):
                if (target, n) not in seen:
                    seen.add((target, n))
                    hits.append(Hit(n, ev, "Supabase service role key used in a module that client code imports "
                                           "(%s); the admin client belongs on the server only" % rel, None, target))
    return hits


_GETSESSION = re.compile(r"\.auth\s*\.\s*getSession\s*\(\s*\)")
_VERIFIED_USER = re.compile(r"\.auth\s*\.\s*(?:getUser|getClaims)\s*\(")
_NEXT_MW_FILE = re.compile(r"(?:^|/)(?:src/)?(?:middleware|proxy)\.(?:ts|js|mjs|cjs)$")
_SERVER_FILE_NAME = re.compile(
    r"(?:^|/)route\.(?:ts|js|mjs|tsx|jsx)$|(?:^|/)pages/api/|(?:^|/)app/(?:.*/)?api/|\.server\.(?:ts|js)$|"
    r"(?:^|/)\+(?:page|layout)\.server\.|(?:^|/)\+server\.|(?:^|/)hooks\.server\.|(?:^|/)supabase/functions/|"
    r"(?:^|/)(?:server|api|backend)/")
_SERVER_MARKERS = re.compile(r"""from\s+['"]next/headers['"]|\bcreateServerClient\s*\(|\bgetServerSideProps\b|"""
                             r"""\bcreateRouteHandlerClient\b|\bcreateServerComponentClient\b|\bcreateMiddlewareClient\b|"""
                             r"""from\s+['"][@~./\w-]*supabase/server['"]""")


_HTTP_EXPORT = re.compile(r"export\s+(?:async\s+)?(?:function|const)\s+(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")


def check_getsession_server(path: str, text: str, ctx: Any) -> List[Hit]:
    if not _GETSESSION.search(text) or _VERIFIED_USER.search(text):
        return []
    if ctx.is_client_file(path) or _USE_CLIENT.match(text):
        return []
    # TanStack Router route files (createFileRoute) run in the browser unless they declare server handlers
    if re.search(r"\bcreateFileRoute\s*\(", text) and not re.search(r"\bcreateServerFn\b|\bserver\s*:\s*\{", text):
        return []
    gate = bool(_NEXT_MW_FILE.search(path))
    named = bool(_SERVER_FILE_NAME.search(path))
    if named and re.search(r"(?:^|/)route\.\w+$", path) and not _HTTP_EXPORT.search(text) and not re.search(
            r"(?:^|/)(?:app/(?:.*/)?api|pages/api|server|api|backend|supabase/functions)/", path):
        named = False
    if not (gate or named or _USE_SERVER.match(text) or _SERVER_MARKERS.search(text)):
        return []
    hits = []
    for i, line in enumerate(_code_lines(ctx, path), 1):
        if _GETSESSION.search(line):
            if gate and re.match(r"\s*(?:await\s+)?[\w$.]*\.auth\s*\.\s*getSession\s*\(\s*\)\s*;?\s*$", line):
                # result thrown away: the auth-helpers idiom that only refreshes the cookie
                hits.append(Hit(i, line.strip(), "middleware calls getSession() only to refresh the cookie; use "
                                                 "getClaims() or the updateSession helper so any later check reads "
                                                 "a verified user", "low"))
            elif gate and not _mw_gates(ctx, path):
                hits.append(Hit(i, line.strip(), "middleware decides from supabase.auth.getSession(), which is not "
                                                 "verified; it does not turn anyone away here, but anything it "
                                                 "decides from the session can be forged", "medium"))
            elif gate:
                hits.append(Hit(i, line.strip(), "middleware or proxy trusts supabase.auth.getSession(); the cookie "
                                                 "is not verified, so a forged session passes the gate", "high"))
            else:
                hits.append(Hit(i, line.strip()))
    return hits


# ---------------------------------------------------------------------------
# Firebase rules
# ---------------------------------------------------------------------------

_C_COMMENTS = re.compile(r"//[^\n]*|/\*.*?\*/", re.S)
_FB_TOK = re.compile(
    r"(?P<match>\bmatch\s+(?P<path>/(?:[^\s{};]|\{[^{}\s]*\})*)\s*\{)"
    r"|(?P<func>\bfunction\s+\w+\s*\([^)]*\)\s*\{)"
    r"|(?P<allow>\ballow\s+(?P<ops>[A-Za-z][A-Za-z,\s]*?)\s*(?::\s*(?P<cond>[^;]*?))?\s*;)"
    r"|(?P<open>\{)|(?P<close>\})", re.S)
_FB_FUNC = re.compile(r"\bfunction\s+(\w+)\s*\(\s*\)\s*\{\s*return\s+([^;]*?)\s*;?\s*\}", re.S)
_FB_ANY_AUTH = {
    "request.auth!=null", "request.auth.uid!=null", "null!=request.auth", "null!=request.auth.uid",
    "request.auth!=null&&request.auth.uid!=null", "request.auth.uid!=null&&request.auth!=null",
}
_FB_WRITE = {"write", "create", "update", "delete"}
_FB_READ = {"read", "get", "list"}
_RT_ANY_AUTH = {"auth!=null", "auth!==null", "auth.uid!=null", "auth.uid!==null", "null!=auth", "null!==auth"}


def _blank_comments(text: str) -> str:
    return _C_COMMENTS.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _fb_parse(ctx: Any, rel: str) -> Dict[str, Any]:
    def build() -> Dict[str, Any]:
        clean = _blank_comments(ctx.read(rel))
        funcs = {m.group(1): m.group(2) for m in _FB_FUNC.finditer(clean)}
        stack: List[Optional[str]] = []
        allows = []
        for m in _FB_TOK.finditer(clean):
            if m.group("match"):
                stack.append(m.group("path").strip())
            elif m.group("func") or m.group("open"):
                stack.append(None)
            elif m.group("allow"):
                ops = set(re.findall(r"[a-z]+", m.group("ops").lower()))
                cond = m.group("cond")
                if cond is not None:
                    cond = re.sub(r"^\s*if\b", "", cond).strip()
                segs: List[str] = []
                for p in stack:
                    if p:
                        segs.extend(s for s in p.split("/") if s)
                if segs[:3] and (segs[0] == "databases" and segs[2:3] == ["documents"]):
                    segs = segs[3:]
                elif segs[:3] and segs[0] == "b" and segs[2:3] == ["o"]:
                    segs = segs[3:]
                line, ev = _line_at(ctx, rel, m.start())
                allows.append({"line": line, "evidence": ev, "ops": ops, "cond": cond, "segs": segs})
            elif m.group("close"):
                if stack:
                    stack.pop()
        storage = bool(re.search(r"\bservice\s+firebase\.storage\b", clean)) or rel.endswith("storage.rules")
        return {"allows": allows, "funcs": funcs, "clean": clean, "storage": storage}
    return ctx.memo(("dataauth-fb", rel), build)


def _fb_resolve(cond: Optional[str], funcs: Dict[str, str]) -> Optional[str]:
    if cond is None:
        return None
    c = cond.strip()
    for _ in range(3):
        m = re.fullmatch(r"(\w+)\(\s*\)", c)
        if not (m and m.group(1) in funcs):
            break
        c = funcs[m.group(1)].strip()
    return c


def _split_oror(n: str) -> List[str]:
    """Split a whitespace-free rules expression on top-level ||."""
    out, depth, start, i = [], 0, 0, 0
    while i < len(n):
        c = n[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "|" and n.startswith("||", i) and depth == 0:
            out.append(n[start:i])
            start = i + 2
            i += 2
            continue
        i += 1
    out.append(n[start:])
    return [x for x in out if x]


def _fb_kind(cond: Optional[str], funcs: Dict[str, str], depth: int = 0) -> str:
    c = _fb_resolve(cond, funcs)
    if c is None:
        return "open"
    n = re.sub(r"\s+", "", c)
    while n.startswith("(") and n.endswith(")") and _balanced(n, 1) == n[1:-1]:
        n = n[1:-1]
    if n == "true":
        return "open"
    if n == "false":
        return "closed"
    if re.fullmatch(r"request\.time<timestamp\.date\([\d,]+\)", n):
        return "test"
    if n in _FB_ANY_AUTH:
        return "any-auth"
    parts = _split_oror(n)
    if len(parts) > 1 and depth < 4:
        # an OR is as open as its most open branch: isAdmin() || isSignedIn() lets every user in
        kinds = [_fb_kind(p, funcs, depth + 1) for p in parts]
        for want in ("open", "test", "any-auth"):
            if want in kinds:
                return want
    return "other"


def _fb_scope(segs: List[str]) -> Tuple[bool, str, str]:
    """(whole database?, last static segment, display path)."""
    root = bool(segs) and bool(re.fullmatch(r"\{\w+=\*\*\}", segs[0]))
    static = [s for s in segs if not s.startswith("{")]
    coll = static[-1] if static else ""
    return root, coll, "/" + "/".join(segs)


def _private_doc(name: str) -> bool:
    return bool(name) and bool(_PRIVATE_NAME.search(name) or _PRIVATE_DOC.match(name))


def _rtdb_rules(ctx: Any, rel: str) -> List[Dict[str, Any]]:
    def build() -> List[Dict[str, Any]]:
        text = ctx.read(rel)
        toks = [(m.group(0), m.start()) for m in
                re.finditer(r'"(?:[^"\\\n]|\\.)*"|//[^\n]*|/\*.*?\*/|[{}\[\]:,]|[^\s{}\[\]:,"]+', text, re.S)
                if not m.group(0).startswith(("//", "/*"))]
        out = []
        stack: List[str] = []
        pending: Optional[str] = None
        for i, (tok, off) in enumerate(toks):
            nxt = toks[i + 1][0] if i + 1 < len(toks) else ""
            if tok == "{":
                stack.append(pending if pending is not None else "")
                pending = None
            elif tok == "[":
                stack.append("[")
                pending = None
            elif tok in ("}", "]"):
                if stack:
                    stack.pop()
                pending = None
            elif tok in (":", ","):
                continue
            elif stack and stack[-1] == "[":
                continue
            elif nxt == ":" and tok.startswith('"'):
                pending = tok[1:-1]
            else:
                if pending in (".read", ".write") and len(stack) >= 2 and stack[1] == "rules":
                    val = tok[1:-1] if tok.startswith('"') else tok
                    line, ev = _line_at(ctx, rel, off)
                    out.append({"key": pending, "value": val, "line": line, "evidence": ev, "path": stack[2:]})
                pending = None
        return out
    return ctx.memo(("dataauth-rtdb", rel), build)


def _rt_kind(value: str, depth: int = 0) -> str:
    n = re.sub(r"\s+", "", value)
    while n.startswith("(") and n.endswith(")") and _balanced(n, 1) == n[1:-1]:
        n = n[1:-1]
    if n == "true":
        return "open"
    if n == "false":
        return "closed"
    if re.fullmatch(r"now<\d{9,}", n):
        return "test"
    if n in _RT_ANY_AUTH:
        return "any-auth"
    parts = _split_oror(n)
    if len(parts) > 1 and depth < 4:
        kinds = [_rt_kind(p, depth + 1) for p in parts]
        for want in ("open", "test", "any-auth"):
            if want in kinds:
                return want
    return "other"


def _rt_scope(path: List[str]) -> Tuple[bool, str, str]:
    static = [p for p in path if not p.startswith("$")]
    return (not path), (static[-1] if static else ""), "/" + "/".join(path)


def check_firebase_open(path: str, text: str, ctx: Any) -> List[Hit]:
    hits = []
    if path.endswith(".json"):
        for r in _rtdb_rules(ctx, path):
            if _rt_kind(r["value"]) != "open":
                continue
            root, coll, shown = _rt_scope(r["path"])
            if r["key"] == ".write":
                sev = "critical" if (root or _private_doc(coll)) else "high"
                msg = "Realtime Database rule lets anyone, logged out, write %s" % ("the whole database" if root else shown)
            else:
                if not (root or _private_doc(coll)):
                    continue
                sev = "critical" if root else "high"
                msg = "Realtime Database rule lets anyone, logged out, read %s" % ("the whole database" if root else shown)
            hits.append(Hit(r["line"], r["evidence"], msg, sev))
        return hits
    info = _fb_parse(ctx, path)
    noun = "file" if info["storage"] else "document"
    for a in info["allows"]:
        if _fb_kind(a["cond"], info["funcs"]) != "open":
            continue
        root, coll, shown = _fb_scope(a["segs"])
        if not a["segs"]:
            continue
        ops = a["ops"]
        where = ("every %s" % noun) if root else shown
        if ops & {"write", "update", "delete"}:
            hits.append(Hit(a["line"], a["evidence"], "rule lets anyone, logged out, change or delete %s" % where,
                            "critical"))
        elif ops & {"create"}:
            hits.append(Hit(a["line"], a["evidence"], "rule lets anyone, logged out, create %ss under %s; fine "
                                                      "only for a public form with field validation" % (noun, shown),
                            "critical" if root else "high"))
        elif ops & _FB_READ and (root or _private_doc(coll)):
            hits.append(Hit(a["line"], a["evidence"], "rule lets anyone, logged out, read %s" % where,
                            "critical" if root else "high"))
    return hits


def check_firebase_test_mode(path: str, text: str, ctx: Any) -> List[Hit]:
    hits = []
    if path.endswith(".json"):
        for r in _rtdb_rules(ctx, path):
            if _rt_kind(r["value"]) == "test":
                hits.append(Hit(r["line"], r["evidence"]))
        return hits
    info = _fb_parse(ctx, path)
    for a in info["allows"]:
        if _fb_kind(a["cond"], info["funcs"]) == "test":
            hits.append(Hit(a["line"], a["evidence"]))
    return hits


def check_firebase_any_auth(path: str, text: str, ctx: Any) -> List[Hit]:
    hits = []
    if path.endswith(".json"):
        for r in _rtdb_rules(ctx, path):
            if _rt_kind(r["value"]) != "any-auth":
                continue
            root, coll, shown = _rt_scope(r["path"])
            if r["key"] == ".write":
                msg = "any signed-in user can write %s" % ("the whole database" if root else shown)
            elif root or _private_doc(coll):
                msg = "any signed-in user can read %s" % ("the whole database" if root else shown)
            else:
                continue
            hits.append(Hit(r["line"], r["evidence"], msg))
        return hits
    info = _fb_parse(ctx, path)
    noun = "file" if info["storage"] else "document"
    for a in info["allows"]:
        if _fb_kind(a["cond"], info["funcs"]) != "any-auth" or not a["segs"]:
            continue
        root, coll, shown = _fb_scope(a["segs"])
        ops = a["ops"]
        if root:
            msg = "any signed-in user can %s every %s" % ("read and write" if ops & _FB_WRITE else "read", noun)
        elif ops & {"write", "update", "delete"}:
            msg = "any signed-in user can change or delete every %s under %s, not just their own" % (noun, shown)
        elif ops & _FB_READ and _private_doc(coll):
            msg = "any signed-in user can read every %s under %s, not just their own" % (noun, shown)
        else:
            continue
        hits.append(Hit(a["line"], a["evidence"], msg))
    return hits


_FB_ROLE_GET = re.compile(
    r"get\(\s*/databases/\$\(\s*database\s*\)/documents/(\w+)/\$\(\s*request\.auth\.uid\s*\)\s*\)\s*\.\s*data\s*"
    r"(?:\.\s*(\w+)|\[\s*['\"](\w+)['\"]\s*\])")
_FB_ROLE_FIELD = re.compile(r"^" + _ROLEISH + r"$", re.I)
_FB_FIELD_GUARD = re.compile(r"affectedKeys|\bdiff\s*\(|hasOnly|hasAny|hasAll|\.keys\s*\(")


_FB_EMAIL_CMP = re.compile(r"request\.auth\.token\.email\s*(?:==\s*['\"][^'\"\s]+@[^'\"\s]+['\"]|in\s*\[[^\]]*@)|"
                           r"['\"][^'\"\s]+@[^'\"\s]+['\"]\s*==\s*request\.auth\.token\.email")
_FB_ANY_FUNC = re.compile(r"\bfunction\s+(\w+)\s*\([^)]*\)\s*\{(.*?)\}", re.S)


def _fb_email_admin(ctx: Any, rel: str, info: Dict[str, Any]) -> List[Hit]:
    """Admin recognised by a fixed token email with no email_verified check."""
    clean = info["clean"]
    first = _FB_EMAIL_CMP.search(clean)
    if not first or re.search(r"\bemail_verified\b", clean):
        return []
    bodies = {m.group(1): m.group(2) for m in _FB_ANY_FUNC.finditer(clean)}
    users = {n for n, b in bodies.items() if _FB_EMAIL_CMP.search(b)}
    for _ in range(5):
        more = {n for n, b in bodies.items() if n not in users and any(re.search(r"\b%s\s*\(" % u, b) for u in users)}
        if not more:
            break
        users |= more
    writes = False
    used = False
    for a in info["allows"]:
        cond = a["cond"] or ""
        if _FB_EMAIL_CMP.search(cond) or any(re.search(r"\b%s\s*\(" % u, cond) for u in users):
            used = True
            writes = writes or bool(a["ops"] & _FB_WRITE)
    if not used:
        return []
    line, ev = _line_at(ctx, rel, first.start())
    msg = ("admin is recognised by a fixed email in request.auth.token.email without "
           "request.auth.token.email_verified == true; anyone who signs up with that address through a provider "
           "that does not verify it gets admin. Use a custom claim set with the Admin SDK")
    return [Hit(line, ev, msg, "high" if writes else "medium")]


def check_firebase_role_field(path: str, text: str, ctx: Any) -> List[Hit]:
    info = _fb_parse(ctx, path)
    email_hits = _fb_email_admin(ctx, path, info)
    if info["storage"]:
        return email_hits
    roles: Dict[str, Set[str]] = {}
    for m in _FB_ROLE_GET.finditer(info["clean"]):
        field = m.group(2) or m.group(3)
        if _FB_ROLE_FIELD.match(field):
            roles.setdefault(m.group(1), set()).add(field)
    if not roles:
        return email_hits
    hits = email_hits
    for a in info["allows"]:
        segs = a["segs"]
        if len(segs) < 2 or segs[-2] not in roles or not segs[-1].startswith("{"):
            continue
        if not a["ops"] & {"write", "update", "create"}:
            continue
        cond = _fb_resolve(a["cond"], info["funcs"]) or ""
        if "request.auth.uid" not in cond or _FB_FIELD_GUARD.search(cond):
            continue
        fields = roles[segs[-2]]
        if any(re.search(r"\b" + re.escape(f) + r"\b", cond) for f in fields):
            continue
        field = sorted(fields)[0]
        hits.append(Hit(a["line"], a["evidence"],
                        "users can write their own %s document, and the rules read %s from it to grant access, so a "
                        "user can give themselves that %s" % (segs[-2], field, field)))
    return hits


# ---------------------------------------------------------------------------
# Next.js middleware and proxy
# ---------------------------------------------------------------------------

_CVE_LINES = (((11, 1, 4), (12, 3, 5)), ((13, 0, 0), (13, 5, 9)), ((14, 0, 0), (14, 2, 25)), ((15, 0, 0), (15, 2, 3)))
_MW_AUTH = re.compile(r"(?i)auth|session|token|jwt|cookie|clerk|getUser|getClaims|login|signin|sign-in")
# Middleware handed over to an auth library, e.g. export { default } from 'next-auth/middleware'.
_MW_AUTH_LIB = re.compile(r"""from\s+['"](?:next-auth/middleware|@clerk/nextjs(?:/server)?|@kinde-oss/[\w/-]+|"""
                          r"""@auth0/nextjs-auth0[\w/-]*)['"]|\bwithAuth\s*\(|\bclerkMiddleware\s*\(|"""
                          r"""\bauthMiddleware\s*\(|\bexport\s*\{\s*auth\s+as\s+(?:middleware|proxy|default)\b""")
_MW_FILE_CVE = re.compile(r"(?:^|/)(?:src/)?middleware\.(?:ts|js|mjs|cjs)$|(?:^|/)pages/(?:.*/)?_middleware\.(?:ts|js|tsx|jsx)$")
_MW_EXPORT = re.compile(r"export\s+(?:async\s+)?function\s+(?:middleware|proxy)\b|export\s+default\b|"
                        r"export\s+const\s+(?:middleware|proxy)\b|export\s*\{[^}]*\b(?:middleware|proxy|default)\b")


# What a middleware does to a signed-out user when it really gates: a redirect or rewrite to a
# login or denied page, a 401 or 403, or an auth library's protect().
_MW_BLOCK = re.compile(
    r"(?is)\bredirect\s*\([^;]{0,200}?(?:log-?in|sign-?in|/auth\b|unauthori[sz]ed|denied|forbidden)|"
    r"\bnew\s+URL\s*\(\s*['\"`]/(?:log-?in|sign-?in|auth)\b|\b40[13]\b|unauthori[sz]ed|"
    r"\brewrite\s*\([^;]{0,200}?(?:log-?in|sign-?in|denied|forbidden|unauthori[sz]ed|40[13])|\.protect\s*\(")


def _mw_gates(ctx: Any, rel: str) -> bool:
    """True when a middleware (or the local helper it calls, e.g. updateSession) reads
    the session and turns signed-out users away; a cookie refresh does not count."""
    def build() -> bool:
        t = _blank_comments(ctx.read(rel))
        texts = [t]
        for m in _IMPORT_RX.finditer(t):
            target = _resolve_import(ctx, rel, m.group(1))
            if target and target != rel:
                texts.append(_blank_comments(ctx.read(target)))
        allt = "\n".join(texts)
        if _MW_AUTH_LIB.search(t):
            return True
        return bool(_MW_AUTH.search(allt) and _MW_BLOCK.search(allt))
    return ctx.memo(("dataauth-mw-gates", rel), build)


def _next_cve(ver: Optional[str]) -> Optional[str]:
    """Patched version to upgrade to when ver is hit by CVE-2025-29927, else None."""
    if not ver:
        return None
    v = ver.strip().lstrip("=v")
    if re.match(r"(?:latest|canary|next|\*|x\b|workspace:|file:|link:|git|http|npm:|github:)", v, re.I):
        return None
    if any(op in v for op in (">", "<", "||", " - ")):
        return None
    t = wc.parse_version(v)
    if t is None:
        return None
    t = tuple(t) + (0,) * (3 - len(t))
    if v.startswith("^"):
        return "12.3.5" if t[0] == 11 else None
    for lo, hi in _CVE_LINES:
        if v.startswith("~"):
            if lo[:2] <= t[:2] < hi[:2]:
                return "%d.%d.%d" % hi
        elif lo <= t < hi:
            return "%d.%d.%d" % hi
    return None


def _next_package(ctx: Any) -> Tuple[str, int, str]:
    for rel in sorted(ctx.glob("package.json"), key=lambda r: (r.count("/"), r)):
        data = ctx.json(rel)
        if not isinstance(data, dict):
            continue
        for sec in ("dependencies", "devDependencies"):
            block = data.get(sec)
            if isinstance(block, dict) and "next" in block:
                for i, line in enumerate(ctx.lines(rel), 1):
                    if re.search(r'"next"\s*:', line):
                        return rel, i, line.strip()
                return rel, 1, ""
    return "package.json", 1, ""


def check_next_cve(path: str, text: str, ctx: Any) -> List[Hit]:
    if "next" not in ctx.deps:
        return []
    ver = ctx.next_version
    fixed = _next_cve(ver)
    if not fixed:
        return []
    mws = [f for f in ctx.files if _MW_FILE_CVE.search(f) and not _is_test(f) and _MW_EXPORT.search(ctx.read(f))]
    if not mws:
        return []
    gates = [f for f in mws if _mw_gates(ctx, f)]
    rel, line, ev = _next_package(ctx)
    # The CVE patch floor is not a safe target: every release below 15.5.24 / 16.3.6 carries later
    # critical advisories (GHSA-2xp9-vwfh-vxw4, GHSA-p293-qw3h-jr36, GHSA-vcvr-r3jv-pc5j).
    target = ("upgrade to the latest patch of a supported major (as of 2026-10 at least 15.5.24 or 16.3.6); %s "
              "closes only this CVE and is hit by later critical advisories" % fixed)
    if gates:
        msg = ("Next.js %s lets one request header skip %s, which turns signed-out users away (CVE-2025-29927); %s"
               % (ver, gates[0], target))
        sev = "critical"
    else:
        msg = "Next.js %s lets one request header skip %s (CVE-2025-29927); %s" % (ver, mws[0], target)
        sev = "medium"
    return [Hit(line, ev, msg, sev, rel)]


_ROUTE_GLOBS = ["**/app/**/route.{ts,js,mjs,tsx,jsx}", "**/pages/api/**/*.{ts,js,mjs,tsx,jsx}"]
_ROUTE_SKIP = re.compile(
    r"(?i)/(?:auth|login|logout|signin|signup|sign-in|sign-up|register|webhooks?|callback|cron|health|status|"
    r"public|og|stripe|trpc|\[\.\.\.nextauth\]|nextauth|uploadthing|inngest|revalidate|clerk|polar|lemon\w*)(?:/|$|\.)")
_AUTH_VOCAB = re.compile(
    r"(?i)\b(?:auth|getServerSession|getSession|getUser|getClaims|currentUser|verifySession|requireAuth|"
    r"requireUser|withAuth|getAuth|getToken|validateRequest|getCurrentUser|session|jwtVerify|verifyToken|"
    r"verifyJwt|verify\w*(?:Token|Session|Signature|Jwt)|authorization|apiKey|api_key|x-api-key|secret|signature|"
    r"clerk|kinde|lucia|cookies|bearer)\b")
_MUTATING_EXPORT = re.compile(r"export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\b|"
                              r"export\s+const\s+(POST|PUT|PATCH|DELETE)\b")
_DATA_WRITE = re.compile(r"\.(?:create|createMany|update|updateMany|upsert|delete|deleteMany|insert|destroy|save|"
                         r"remove|findByIdAndUpdate|findByIdAndDelete)\s*\(|\b(?:INSERT\s+INTO|DELETE\s+FROM)\b|"
                         r"\bUPDATE\s+\w+\s+SET\b", re.I)
_SB_USER_CLIENT = re.compile(r"\bcreateServerClient\s*\(|\bcreateRouteHandlerClient\b|"
                             r"""from\s+['"][@~./\w-]*supabase/server['"]""")
_SB_ADMIN_FILE = re.compile(r"service[_-]?role|\bsb_secret_|SUPABASE_SECRET|supabaseAdmin|adminClient|serviceClient|"
                            r"createAdminClient|createServiceClient|supabase_admin|SERVICE_KEY", re.I)


def _mw_state(ctx: Any) -> Dict[str, Any]:
    def build() -> Dict[str, Any]:
        files = [f for f in ctx.files if _NEXT_MW_FILE.search(f) and not _is_test(f)]
        state = {"auth": False, "api_excluded": False, "file": ""}
        for f in files:
            t = _blank_comments(ctx.read(f))
            if not _MW_EXPORT.search(t) or not _mw_gates(ctx, f):
                continue
            state["auth"] = True
            state["file"] = f
            m = re.search(r"\bmatcher\s*:\s*(\[[^\]]*\]|'[^']*'|\"[^\"]*\")", t, re.S)
            if m:
                pats = re.findall(r"'([^']*)'|\"([^\"]*)\"", m.group(1))
                pats = [a or b for a, b in pats]
                covers = False
                for p in pats:
                    if p.startswith("/api") or p.startswith("/(api"):
                        covers = True
                    elif p in ("/:path*", "/(.*)", "/((.*))", "/:path*/") or (
                            p.startswith("/((?!") and not re.search(r"\(\?![^)]*\bapi\b", p)):
                        covers = True
                state["api_excluded"] = not covers
            break
        return state
    return ctx.memo("dataauth-mw-state", build)


def check_middleware_only_auth(path: str, text: str, ctx: Any) -> List[Hit]:
    state = _mw_state(ctx)
    if not state["auth"] or _ROUTE_SKIP.search("/" + path) or _is_test(path):
        return []
    clean = _blank_comments(text)
    pages_api = "/pages/api/" in "/" + path
    first = _MUTATING_EXPORT.search(clean)
    if not first and not pages_api:
        return []
    if not _DATA_WRITE.search(clean) or _AUTH_VOCAB.search(clean):
        return []
    if _SB_USER_CLIENT.search(clean) and not _SB_ADMIN_FILE.search(clean):
        return []
    off = first.start() if first else (_DATA_WRITE.search(clean).start())
    line, ev = _line_at(ctx, path, off)
    if state["api_excluded"]:
        return [Hit(line, ev, "the middleware matcher skips /api, so this route that writes data has no auth "
                              "check at all", "high")]
    return [Hit(line, ev, "this route writes data and relies only on %s for auth; check the user inside the "
                          "handler too" % state["file"], "medium")]


# ---------------------------------------------------------------------------
# IDOR: by-id lookups with no ownership check
# ---------------------------------------------------------------------------

_OWNER_WORDS = (r"(?:user|owner|author|creator|created_?by|session|uid|account|tenant|member|org|organization|"
                r"team|workspace|profile|customer|viewer)")
_JS_FN_START = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\b"
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+[\w$]+\s*(?::[^=]+)?=\s*(?:async\b|function\b|\([^)]*\)\s*(?::[^=]+)?=>|[\w$]+\s*=>)"
    r"|\b(?:router|app|server|api|route|r|fastify|hono)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\("
    r"|^\s*(?:(?:public|private|protected|static|async)\s+)*(?!(?:if|for|while|switch|catch|with|return|else|do)\b)"
    r"[\w$]+\s*\([^)]*\)\s*(?::\s*[^{]+)?\{\s*$"
    # top-level handlers wrapped in a helper: export const GET = withAuth(async (...) => ...),
    # export const { POST } = serve(...), export const x = adminProcedure.input(...), Deno.serve(...)
    r"|^(?:export\s+)?(?:const|let|var)\s+(?:[\w$]+|\{[^}]*\})\s*(?::[^=]+)?=\s*[\w$.]+(?:<[^>]*>)?\s*\(\s*"
    r"(?:async\b|function\b|\(|$)"
    r"|^(?:export\s+)?(?:const|let|var)\s+[\w$]+\s*(?::[^=]+)?=\s*[\w$]*(?:[Pp]rocedure|[Aa]ction[Cc]lient)\b"
    r"|^\s*(?:Deno\s*\.\s*)?serve\s*\(")
_PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+\w+\s*\(")
_PHP_FN = re.compile(r"^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+(\w+)\s*\(")

_REQ_SRC = re.compile(
    r"\b(?:req|request|ctx|context|event|evt|c)\s*\.\s*(?:params|query|body|nextUrl|url|json\s*\(|formData\s*\(|req\.)"
    r"|\bparams\b|\bsearchParams\b|\bformData\s*\.\s*get\s*\(|\bquery\s*\.\s*\w+|\bbody\s*\.\s*\w+"
    r"|\binput\s*\.\s*\w+|\bargs\s*\.\s*\w+|\buseParams\b|\bgetRouterParam\s*\(|\bgetQuery\s*\(|\breadBody\s*\("
    r"|\bparsedInput\b")
_OWNER_SRC = re.compile(
    r"(?i)\bsession\b|\bauth\s*\(|\bgetUser\b|\bcurrentUser\b|\bgetServerSession\b|\bverifySession\b|\brequireUser\b|"
    r"\brequireAuth\b|\bgetAuth\b|\bclaims\b|\buser\s*\??\.\s*(?:id|uid|sub)\b|\b(?:req|request|locals)\s*\.\s*user\b|"
    r"\bauth\s*\.\s*uid\b|\bme\s*\??\.\s*id\b")
# Owner-like names a JS comparison can involve (row.userId !== session.user.id, x.programId !== programId).
_CMP_WORDS = (r"(?:user|owner|author|creator|created_?by|session|uid|account|tenant|member|org|organization|team|"
              r"workspace|profile|customer|viewer|project|program|partner|company|me|current)")
_JS_CMP = re.compile(r"([\w$.?()\[\]'\"`]+)\s*(!==|===|!=|==)\s*(!*[\w$.?()\[\]'\"`]+)")
_OWNER_OPERAND = re.compile(r"(?i)\b\w*" + _CMP_WORDS + r"\w*(?:\(\))?(?:\??\.(?:id|_id|uid|sub|toString\(\)))+"
                            r"|\b\w*" + _CMP_WORDS + r"(?:id|_id|uid)\b|\??\." + _CMP_WORDS + r"\b")
_JS_AUTHZ = re.compile(
    r"(?i)\b(?:authorize|can|ability|assert\w*|ensure\w*|require(?:Owner|Admin|Role|Permission|Access)\w*|"
    r"(?:check|verify|validate|require)\w*(?:Own|Owner|Owns|Access|Permission|Member|Membership|Admin|Role)\w*|"
    r"has(?:Role|Permission|Access)|isOwner|canAccess|canEdit|canDelete)\s*\("
    r"|\bforbidden\b|\bstatus\s*:\s*403\b|\b403\b|\bisAdmin\b|\bis_admin\b"
    r"|\.role\s*(?:!==|===|!=|==)\s*['\"`]|['\"`]\w+['\"`]\s*(?:!==|===|!=|==)\s*[\w$.?]*\.role\b"
    r"|\.roles?\s*\??\.\s*(?:includes|some|has)\s*\(")
_OWNER_KEY = (r"(?:[a-z]\w*?)?(?:[Uu]ser|[Oo]wner|[Aa]uthor|[Cc]reator|[Tt]enant|[Oo]rg|[Oo]rganization|[Tt]eam|"
              r"[Ww]orkspace|[Aa]ccount|[Mm]ember|[Cc]ustomer|[Pp]rofile|[Pp]roject|[Pp]rogram|[Pp]artner|[Cc]ompany|"
              r"[Cc]lub|[Gg]roup|[Ss]tore|[Ss]hop|[Ss]ite|[Mm]erchant|[Hh]ousehold|[Ff]amily|[Bb]oard|[Ss]pace)"
              r"_?[iI]d|created_?[bB]y(?:_?[iI]d)?|uid|user|owner|author")
_JS_KEY_VAL = re.compile(r"[{,]\s*['\"]?(" + _OWNER_KEY + r")['\"]?\s*(?::\s*([^,}\n]+?))?\s*(?=[,}\n])")
_SB_EQ_KEY = re.compile(r"""\.(?:eq|match)\(\s*['"`](\w+)['"`]\s*,\s*([^)]+?)\s*\)""")
_USER_KEY = re.compile(r"(?i)^(?:user_?id|owner_?id|author_?id|created_?by(?:_?id)?|creator_?id|uid|customer_?id|"
                       r"profile_?id)$")
_PUBLISHED_KEY = re.compile(r"(?i)\b(?:published|is_?public|public|visibility|is_?published|status|approved)\s*:")
_LITERAL = re.compile(r"""^(?:true|false|null|undefined|-?\d[\w.]*|['"`].*|\{\s*\}|\[\s*\])$""")

_PRISMA_CALL = re.compile(
    r"\b(?:this\s*\.\s*)?(?:prisma|db|tx|client|database|orm)\s*\.\s*(?:query\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\.\s*"
    r"(findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|update|delete|upsert)\s*\(")
_PRISMA_MANY = re.compile(
    r"\b(?:this\s*\.\s*)?(?:prisma|db|tx|client|database|orm)\s*\.\s*(?:query\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\.\s*"
    r"(findMany|findFirst|findUnique|count|aggregate|groupBy|updateMany|deleteMany)\s*\(")
_MONGO_BYID = re.compile(
    r"\b([A-Z][\w$]*)\s*\.\s*(findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findByPk)\s*\(\s*([^,)]+)")
_MONGO_ONE = re.compile(
    r"\b([A-Z][\w$]*)\s*\.\s*(findOne|findOneAndUpdate|findOneAndDelete|findOneAndRemove|deleteOne|updateOne|destroy)"
    r"\s*\(\s*\{\s*(?:where\s*:\s*\{\s*)?['\"]?(_id|id)['\"]?\s*(?::\s*([^,}]+?))?\s*\}")
# Sequelize v4 find() is findOne(); only with a where clause, so Array.find stays out.
_SEQ_FIND = re.compile(r"\b([A-Z][\w$]*)\s*\.\s*(find)\s*\(\s*\{\s*where\s*:\s*\{\s*['\"]?(id)['\"]?\s*:\s*([^,}]+?)\s*\}")
_MONGO_FILTER = re.compile(
    r"(?:\b([A-Z][\w$]*)|\.collection\(\s*['\"`](\w+)['\"`]\s*\))\s*\.\s*(find|findOne|countDocuments|deleteMany|"
    r"updateMany|deleteOne|updateOne)\s*\(\s*\{([^{}]*)\}")
_SB_FROM = re.compile(r"""\.from\(\s*['"`](\w+)['"`]\s*\)""")
_SB_EQ_ID = re.compile(r"""\.eq\(\s*['"`]id['"`]\s*,\s*([^)]+?)\s*\)""")
_SQL_BYID = re.compile(
    r"(?is)['\"`]\s*(?:select\b[^'\"`]*?\bfrom\s+\"?(\w+)\"?|update\s+\"?(\w+)\"?\s+set\b|delete\s+from\s+\"?(\w+)\"?)"
    r"[^'\"`]*?\bwhere\s+(?:\"?\w+\"?\.)?\"?id\"?\s*=\s*(\$1|\?|:id|@id|\$\{([^}]+)\})"
    r"(?:\s+(?:limit\s+1|returning\s+[\w*, ]+))?\s*;?\s*['\"`]")
_MUTATING_METHODS = {"update", "delete", "upsert", "findByIdAndUpdate", "findByIdAndDelete", "findByIdAndRemove",
                     "findOneAndUpdate", "findOneAndDelete", "findOneAndRemove", "deleteOne", "updateOne", "destroy",
                     "updateMany", "deleteMany"}
_UNWRAP = re.compile(r"^(?:Number|parseInt|parseFloat|String|BigInt|ObjectId|new\s+ObjectId|Types\.ObjectId|"
                     r"new\s+Types\.ObjectId|mongoose\.Types\.ObjectId|z\.\w+\(\)\.parse|decodeURIComponent)\s*\(\s*(.*?)"
                     r"\s*(?:,\s*\d+\s*)?\)$")
# Callers whose ids come from a signed payload, not from an end user: cron jobs, queue
# and workflow callbacks, payment-provider webhooks.
_SIGNED_CALLER = re.compile(r"\bwithCron\b|\bverify\w*Signature\w*\s*\(|\bverifySignatureAppRouter\b|"
                            r"\bnew\s+Receiver\s*\(|\.constructEvent(?:Async)?\s*\(|\bnew\s+Webhook\s*\(|"
                            r"\bwebhooks?\s*\.\s*verify\s*\(|\bCRON_SECRET\b")
_UPSTASH_SERVE = re.compile(r"""from\s+['"]@upstash/workflow(?:/[\w-]+)?['"][\s\S]*\bserve\s*(?:<[^>]*>)?\s*\(""")
# Wrappers and procedures that only admins or staff pass.
_ADMIN_WRAP = re.compile(r"\bwith(?:Admin|SuperAdmin|Staff|Internal)\w*\s*\(|"
                         r"\b(?:admin|superAdmin|superadmin|staff|internal)(?:Procedure|ActionClient|Action)\b|"
                         r"\brequire(?:Admin|SuperAdmin|Staff)\w*\s*\(")
_WRAPPED = re.compile(r"=\s*with\w+\s*\(|\.(?:action|mutation|query)\s*\(|[Pp]rocedure\b|\bserve\s*(?:<[^>]*>)?\s*\(")
_CTX_OWNER_NAMES = {"session", "user", "workspace", "partner", "program", "org", "organization", "team", "project",
                    "tenant", "account", "ctx", "context", "me", "currentUser", "viewer", "member", "membership",
                    "authUser", "profile", "emailAccount", "emailAccountId", "userId"}
_PUBLIC_ASSET_PATH = re.compile(r"(?i)(?:logo|avatar|favicon|og-image|opengraph|(?:^|[/.])og(?:[/.]|$))")
# A read that returns only these columns shows what a public profile page shows anyway.
_PUBLIC_COLS = {"id", "user_id", "username", "display_name", "name", "full_name", "avatar_url", "avatar", "bio",
                "image_url", "handle", "slug", "created_at"}
_SB_CLIENT_DEF = re.compile(r"(?:const|let|var)\s+([\w$]+)\s*(?::[^=]+)?=\s*(?:await\s+)?createClient\s*\(")


def _block(lines: List[str], idx: int, start_rx: "re.Pattern[str]", up: int = 80, down: int = 80) -> Tuple[int, int]:
    start = idx
    for j in range(idx, max(-1, idx - up), -1):
        if start_rx.search(lines[j]):
            start = j
            break
    else:
        start = max(0, idx - up)
    end = min(len(lines), idx + down)
    for j in range(idx + 1, min(len(lines), idx + down)):
        if start_rx.search(lines[j]):
            end = j
            break
    return start, end


def _js_unwrap(value: str) -> str:
    v = value.strip()
    for _ in range(4):
        v = re.sub(r"\s+as\s+(?:[\w<>\[\]|. ]+|\{.*)$", "", v).strip()
        v = re.sub(r"\s*(?:\?\?|\|\|)\s*['\"`][^'\"`]*['\"`]$", "", v).strip()
        v = v.rstrip("!").lstrip("+").strip()
        if v.startswith("(") and v.endswith(")") and _balanced(v, 1) == v[1:-1]:
            v = v[1:-1].strip()
        m = _UNWRAP.match(v)
        if not m:
            break
        v = m.group(1).strip()
    return v


def _js_assigned(block: str, name: str) -> Optional[str]:
    esc = re.escape(name)
    rx = re.compile(r"(?:const|let|var)\s+(?:\{[^}=]*\b" + esc + r"\b[^}]*\}|\[[^\]]*\b" + esc + r"\b[^\]]*\]|"
                    + esc + r"\b)\s*(?::[^=\n]+)?=\s*([^\n;]+)")
    m = rx.search(block)
    return m.group(1) if m else None


def _owner_rx(owners: Set[str]) -> Optional["re.Pattern[str]"]:
    if not owners:
        return None
    return re.compile(r"^(?:" + "|".join(re.escape(o) for o in sorted(owners)) + r")\b")


def _js_value_kind(value: str, block: str, sig: str, server_action: bool, owners: Optional[Set[str]] = None,
                   depth: int = 0) -> Optional[str]:
    """'input' (from the request), 'owner' (from the session or an auth wrapper) or None."""
    v = _js_unwrap(value)
    if not v:
        return None
    orx = _owner_rx(owners or set())
    if _OWNER_SRC.search(v):
        return "owner"
    if _REQ_SRC.search(v):
        return "input"
    if orx and orx.match(v):
        return "owner"
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", v):
        return None
    rhs = _js_assigned(block, v)
    if rhs is not None:
        r = _js_unwrap(rhs)
        if _OWNER_SRC.search(r):
            return "owner"
        if _REQ_SRC.search(r) or re.search(r"\b(?:req|request)\s*\.\s*(?:json|formData|text)\s*\(", r):
            return "input"
        if orx and re.search(r"\b(?:" + "|".join(re.escape(o) for o in sorted(owners or set())) + r")\b", r):
            return "owner"
        # one more hop: const json = await req.json(); const { id } = json
        if depth == 0 and re.fullmatch(r"(?:await\s+)?[A-Za-z_$][\w$]*", r) and r != v:
            return _js_value_kind(r.replace("await", "").strip(), block, sig, server_action, owners, 1)
        return None
    if re.search(r"\b" + re.escape(v) + r"\b", sig):
        if re.search(r"\b(?:ctx|context)\s*:\s*\{[^}]*\b" + re.escape(v) + r"\b", sig):
            return "owner"
        if server_action or _REQ_SRC.search(sig):
            return "input"
    if owners and v in owners:
        return "owner"
    return None


def _where_body(span: str) -> Optional[str]:
    m = re.search(r"\bwhere\s*:\s*\{", span)
    if not m:
        return None
    return _balanced(span, m.end(), "{", "}")


def _where_id_value(body: str) -> Optional[str]:
    """The id value of a where clause that filters on the id alone."""
    parts = [p.strip() for p in _split_top(body) if p.strip()]
    if len(parts) != 1:
        return None
    p = parts[0]
    if ":" in p:
        key, val = p.split(":", 1)
        key = key.strip().strip("'\"")
        if key in ("id", "_id", "uuid"):
            return val.strip()
        return None
    return p if p in ("id", "_id", "uuid") else None


def _user_key_values(body: str) -> List[Tuple[str, str]]:
    """(key, value) pairs of a filter object whose key names the row's user."""
    out = []
    parts = [p.strip() for p in _split_top(body) if p.strip()]
    if any(_PUBLISHED_KEY.match(p) for p in parts):
        return []
    for p in parts:
        key, _, val = p.partition(":")
        key = key.strip().strip("'\"")
        if _USER_KEY.match(key):
            out.append((key, val.strip() or key))
    return out


def _js_sig(lines: List[str], start: int) -> str:
    sig = []
    for ln in lines[start:start + 6]:
        sig.append(ln)
        if "{" in ln or "=>" in ln:
            break
    return " ".join(sig)


def _js_cb_params(block: str) -> str:
    """Parameter list of the first async callback in a block (wrapped handlers)."""
    m = re.search(r"\basync\s*(?:function\s*[\w$]*\s*)?\(", block[:1200])
    if not m:
        return ""
    return _balanced(block, m.end()) or ""


def _js_owner_cmp(block: str) -> bool:
    """A comparison of an owner id with something that is not a literal or a length."""
    for m in _JS_CMP.finditer(block):
        a, b = m.group(1).strip("()!"), m.group(3).strip("()!")
        if _LITERAL.match(a) or _LITERAL.match(b):
            continue
        if re.search(r"\.(?:length|size|count)\b", a + " " + b):
            continue
        if _OWNER_OPERAND.search(a) or _OWNER_OPERAND.search(b):
            return True
    return False


_NOT_FILTER_CALL = re.compile(r"(?i)^(?:render|json|send|status|log|info|warn|error|debug|redirect|track|capture\w*|"
                              r"emit|set\w*|push|create|createMany|insert|insertMany|upsert|update|assign|stringify)$")


def _filter_object(code: str, pos: int) -> bool:
    """True when the object literal around pos looks like a query filter or helper
    argument (where: {...}, find({...}), getXOrThrow({...})), not response data."""
    depth = 0
    i = pos
    while i >= 0:
        c = code[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                break
            depth -= 1
        i -= 1
    if i < 0:
        return False
    before = code[max(0, i - 120):i].rstrip()
    if re.search(r"\b(?:where|filter|match|query)\s*:\s*$", before):
        return True
    if re.search(r"\b(?:data|create|update|select|include|orderBy|headers|body)\s*:\s*$", before):
        return False
    call = re.search(r"([\w$]+)\s*\(\s*$", before)
    if call:
        return not _NOT_FILTER_CALL.match(call.group(1))
    return bool(re.search(r"=\s*$", before))


def _js_owner_scoped(block: str, sig: str, action: bool, owners: Set[str]) -> bool:
    """A filter or helper argument keyed by an owner (projectId: workspace.id, userId) whose
    value does not come from the request."""
    # column lists in strings ('id, user_id, email') are not filters
    code = re.sub(r"'[^'\n]*'|\"[^\"\n]*\"|`[^`]*`", "''", block)
    for m in _JS_KEY_VAL.finditer(code):
        if not _filter_object(code, m.start()):
            continue
        val = (m.group(2) or m.group(1)).strip()
        if _LITERAL.match(val) or val in ("string", "number"):
            continue
        if _js_value_kind(val, block, sig, action, owners) != "input":
            return True
    for m in _SB_EQ_KEY.finditer(block):
        if re.fullmatch(r"(?i)" + _OWNER_KEY, m.group(1)) and m.group(1) != "id":
            if _js_value_kind(m.group(2), block, sig, action, owners) != "input":
                return True
    return False


def _sb_clients(text: str) -> Dict[str, str]:
    """Supabase client variables: 'admin' (service key) or 'user' (anon or publishable key, so RLS applies)."""
    out = {}
    for m in _SB_CLIENT_DEF.finditer(text):
        args = _balanced(text, m.end()) or text[m.end():m.end() + 400]
        if _SB_ADMIN_FILE.search(args):
            out[m.group(1)] = "admin"
        elif re.search(r"ANON|PUBLISHABLE|NEXT_PUBLIC_|VITE_|EXPO_PUBLIC_|\bPUBLIC_", args):
            out[m.group(1)] = "user"
    return out


def _signed_sibling(ctx: Any, rel: str) -> bool:
    """A handler module next to a route.ts that verifies a webhook or queue signature."""
    if re.search(r"(?:^|/)route\.\w+$", rel):
        return False
    folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
    base = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    for ext in ("ts", "js", "mjs", "tsx"):
        route = (folder + "/" if folder else "") + "route." + ext
        t = ctx.read(route) if route in ctx.memo("dataauth-fileset", lambda: set(ctx.files)) else ""
        if t and _SIGNED_CALLER.search(t) and re.search(r"['\"]\./" + re.escape(base) + r"(?:\.\w+)?['\"]", t):
            return True
    return False


def _public_read_tables(ctx: Any) -> Set[str]:
    """Tables with a select policy USING (true) for anon or public, per the migrations."""
    def build() -> Set[str]:
        idx = _sql_index(ctx)
        out = set()
        for (tkey, _), p in idx.policies.items():
            if p["permissive"] and p["cmd"] in ("select", "all") and _expr_kind(p["using"]) == "true" and \
                    (p["roles"] or {"public"}) & {"anon", "public"}:
                out.add(tkey[1])
        return out
    return ctx.memo("dataauth-public-read", build)


_IDOR_JS_HINT = re.compile(r"\.(?:find\w*|update\w*|delete\w*|upsert|destroy|count\w*|from|eq|aggregate|groupBy)\s*\(|"
                           r"(?i:\bwhere\s+(?:[\w\"]+\.)?\"?id\"?\s*=)")


def _idor_js(rel: str, text: str, ctx: Any) -> List[Hit]:
    if ctx.is_client_file(rel) or _USE_CLIENT.match(text):
        return []
    if _SIGNED_CALLER.search(text) or _UPSTASH_SERVE.search(text) or _signed_sibling(ctx, rel):
        return []
    lines = _code_lines(ctx, rel)
    file_action = bool(_USE_SERVER.match(text))
    admin_sb = bool(_SB_ADMIN_FILE.search(text))
    clients = _sb_clients(text) if ".from(" in text else {}
    public_asset = bool(_PUBLIC_ASSET_PATH.search(rel))
    hits: List[Hit] = []
    for i, line in enumerate(lines):
        if not line or len(line) > 500 or not _IDOR_JS_HINT.search(line):
            continue
        # (model, value, mutation, kind): kind "id" for a by-id lookup, "owner" for a filter on the row's user
        found: List[Tuple[str, str, bool, str]] = []
        span = "\n".join(lines[i:i + 8])
        m = _PRISMA_CALL.search(line)
        if m:
            body = _where_body(span[span.find(m.group(0)):])
            if body is not None:
                val = _where_id_value(body)
                if val:
                    found.append((m.group(1), val, m.group(2) in _MUTATING_METHODS, "id"))
        m = _PRISMA_MANY.search(line)
        if m:
            body = _where_body(span[span.find(m.group(0)):])
            if body is not None:
                for _, val in _user_key_values(body):
                    found.append((m.group(1), val, m.group(2) in _MUTATING_METHODS, "owner"))
        for m in _MONGO_BYID.finditer(line):
            found.append((m.group(1), m.group(3), m.group(2) in _MUTATING_METHODS, "id"))
        for rx in (_MONGO_ONE, _SEQ_FIND):
            m = rx.search(span[:600])
            if m and m.start() < len(line):
                found.append((m.group(1), m.group(4) or m.group(3), m.group(2) in _MUTATING_METHODS, "id"))
        m = _MONGO_FILTER.search(line)
        if m:
            for _, val in _user_key_values(m.group(4)):
                found.append((m.group(1) or m.group(2), val, m.group(3) in _MUTATING_METHODS, "owner"))
        m = _SB_FROM.search(line)
        if m and (admin_sb or clients):
            before = "\n".join(lines[max(0, i - 2):i]) + "\n" + line[:m.start()]
            recv = re.search(r"([\w$]+)\s*$", before)
            kind = clients.get(recv.group(1)) if recv else None
            if kind == "admin" or (kind is None and admin_sb):
                chain = span[span.find(m.group(0)):][:500].split(";")[0]
                mut = bool(re.search(r"\.(?:update|delete|upsert)\s*\(", chain))
                sel = re.search(r"\.select\(\s*['\"`]([^'\"`]*)['\"`]", chain)
                public_cols = bool(sel) and not mut and all(
                    c.strip().lower() in _PUBLIC_COLS for c in sel.group(1).split(",") if c.strip())
                if re.search(r"\.(?:select|update|delete|upsert)\s*\(", chain) and not public_cols:
                    e = _SB_EQ_ID.search(chain)
                    if e:
                        found.append((m.group(1), e.group(1), mut, "id"))
                    for k in _SB_EQ_KEY.finditer(chain):
                        if _USER_KEY.match(k.group(1)):
                            found.append((m.group(1), k.group(2), mut, "owner"))
        m = _SQL_BYID.search(line)
        if m:
            table = m.group(1) or m.group(2) or m.group(3)
            if m.group(5):
                val = m.group(5)
            else:
                rest = span[span.find(m.group(0)) + len(m.group(0)) - 1:]
                p = (re.match(r"['\"`]\s*,\s*\[\s*([^,\]]+)", rest)
                     or re.match(r"['\"`]\s*\)\s*\.\s*(?:get|all|run|first)\(\s*([^,)]+)", rest))
                val = p.group(1) if p else ""
            if val:
                found.append((table, val, bool(m.group(2) or m.group(3)), "id"))
        if not found:
            continue
        start, end = _block(lines, i, _JS_FN_START)
        block = "\n".join(lines[start:end])
        head = "\n".join(lines[start:start + 3])
        if _ADMIN_WRAP.search(head):
            continue
        params = _js_cb_params(block)
        sig = _js_sig(lines, start) + " " + params
        exported = bool(re.match(r"\s*export\b", lines[start]))
        action = (file_action and exported) or bool(re.search(r"""['"]use server['"]""", block)) or \
            bool(re.search(r"\.(?:action|mutation)\s*\(", head + block[:400]))
        owners: Set[str] = set()
        if _WRAPPED.search(head + "\n" + block[:400]):
            owners = {n for n in re.findall(r"[\w$]+", params) if n in _CTX_OWNER_NAMES}
            for cm in re.finditer(r"\b(?:ctx|context)\s*:\s*\{([^}]*)\}", params):
                owners.update(re.findall(r"[\w$]+", cm.group(1)))
        for model, value, mutation, kind in found:
            if _js_value_kind(value, block, sig, action, owners) != "input":
                continue
            if not mutation and (_PUBLIC_MODEL.match(model) or public_asset or
                                 model.lower() in _public_read_tables(ctx)):
                continue
            if _js_owner_cmp(block) or _JS_AUTHZ.search(block) or _js_owner_scoped(block, sig, action, owners):
                continue
            if kind == "owner":
                msg = ("%s is filtered by a user id taken from the request, not from the session; anyone can pass "
                       "another user's id" % model)
            else:
                verb = "changed or deleted" if mutation else "read"
                msg = ("%s is %s by an id from the request with no ownership check nearby; one user may reach "
                       "another user's record" % (model, verb))
            hits.append(Hit(i + 1, line.strip(), msg))
            break
    return hits


_PY_ANCHORS = [
    re.compile(r"\.query\(\s*([\w.]+)\s*\)\s*\.get\(\s*(\w+)\s*\)"),
    re.compile(r"\b([A-Z]\w*)\.query\.(?:get|get_or_404)\(\s*(\w+)\s*\)"),
    re.compile(r"\b(?:db|session|db\.session|self\.session|sess|self\.db)\.(?:get|get_or_404)\(\s*([A-Z]\w*)\s*,\s*(\w+)\s*\)"),
    re.compile(r"\.query\(\s*([\w.]+)\s*\)\s*\.filter\(\s*[\w.]+\.id\s*==\s*(\w+)\s*\)"),
    re.compile(r"\b([A-Z]\w*)\.query\.filter_by\(\s*id\s*=\s*(\w+)\s*\)"),
    re.compile(r"\bselect\(\s*([\w.]+)\s*\)\s*\.where\(\s*[\w.]+\.id\s*==\s*(\w+)\s*\)"),
    re.compile(r"\b([A-Z]\w*)\.objects\.(?:get|filter)\(\s*(?:pk|id)\s*=\s*(\w+)\s*\)"),
    re.compile(r"\bget_object_or_404\(\s*([A-Z]\w*)\s*,\s*(?:pk|id)\s*=\s*(\w+)\s*\)"),
]
_PY_ROUTE = re.compile(r"@\w+(?:\.\w+)*\.(?:get|post|put|patch|delete|route|api_route|api_view)\s*\(|@api_view|@action\s*\(")
# Comparisons with None (user is None) and the model class itself (user = User.query...) are not owner checks.
_PY_OWNER = re.compile(
    r"(?i)" + _OWNER_WORDS + r"\w*(?:\.\w+)*\s*(?:!=|==|\bis\s+not\b|\bis\b(?!_))(?!\s*(?:None|0|''|\"\")\b)"
    r"|(?:!=|==)\s*(?:self\.)?(?-i:request\.user|current_user|g\.user|user)\b"
    r"|\b(?:owner|user|author|created_by|account|tenant|org|team)(?:_id)?\s*=\s*(?-i:request\.user|current_user|"
    r"user\b(?!\s*\.\s*(?:query|objects))|g\.user|self\.request\.user)"
    r"|\.filter(?:_by)?\([^)]*(?:owner|user_id|user=|author|created_by|tenant|account_id)")
_PY_AUTHZ = re.compile(
    r"(?i)abort\(\s*403|status_code\s*=\s*403|HTTPException\(\s*(?:status_code\s*=\s*)?403|"
    r"status\.HTTP_403|PermissionDenied|\bForbidden\b|has_object_permission|check_object_permissions|is_staff|"
    r"is_superuser|is_admin|\.role\s*(?:!=|==|in\b|not\s+in\b)|admin_required|permission_required|user_passes_test|"
    r"staff_member_required|roles_required|\bPermission\s*\(|\bhas_permission\b|\.can\s*\(|\brequires\s*\(|"
    r"\bIs\w*(?:Moderator|Admin|Owner|Member)\w*\s*\(")
_PY_MUTATION = re.compile(r"\.delete\(|\.save\(|setattr\(|\.update\(|\.commit\(|\.merge\(")
_PY_RAW = re.compile(r"\brequest\.(?:args|json|get_json|form|data|POST|GET|values|query_params|path_params)\b|"
                     r"\bkwargs\s*\[|\bjson\.loads\(\s*request\.|\.validated_data\b|\bcleaned_data\b")
# User and profile rows read by id usually back a public profile page; only private fields make it a leak.
_PROFILE_MODEL = re.compile(r"(?i)^(?:users?|profiles?|members?|authors?|accounts?)$")
_PY_PRIVATE_FIELD = re.compile(r"\b(?:email|phone|token|password|address|ssn|secret|api_key)\b")
_DRF_CLASS = re.compile(
    r"^class\s+(\w+)\(\s*([^)]*\b(?:ModelViewSet|ReadOnlyModelViewSet|RetrieveUpdateDestroyAPIView|RetrieveAPIView|"
    r"UpdateAPIView|DestroyAPIView|RetrieveUpdateAPIView|RetrieveDestroyAPIView|DetailView|UpdateView|DeleteView)"
    r"\b[^)]*)\)\s*:")
_DRF_SAFE_PERMS = {"IsAuthenticated", "AllowAny", "IsAuthenticatedOrReadOnly", "permissions.IsAuthenticated",
                   "permissions.AllowAny", "permissions.IsAuthenticatedOrReadOnly"}


def _py_block(lines: List[str], idx: int) -> Tuple[int, int, str]:
    start = None
    indent = ""
    for j in range(idx, max(-1, idx - 150), -1):
        m = _PY_DEF.match(lines[j])
        if m:
            start, indent = j, m.group(1)
            break
    if start is None:
        return idx, idx + 1, ""
    deco = start
    while deco > 0 and lines[deco - 1].strip().startswith("@"):
        deco -= 1
    end = len(lines)
    for j in range(start + 1, min(len(lines), start + 200)):
        ln = lines[j]
        if not ln.strip():
            continue
        cur = ln[:len(ln) - len(ln.lstrip())]
        if len(cur) <= len(indent) and not ln.lstrip().startswith((")", "]", "}")):
            end = j
            break
    sig_lines = []
    for ln in lines[start:start + 8]:
        sig_lines.append(ln)
        if ln.rstrip().endswith(":"):
            break
    return deco, end, " ".join(sig_lines)


def _idor_py(rel: str, text: str, ctx: Any) -> List[Hit]:
    lines = _code_lines(ctx, rel)
    hits: List[Hit] = []
    for i, line in enumerate(lines):
        if not line:
            continue
        for rx in _PY_ANCHORS:
            m = rx.search(line)
            if not m:
                continue
            model, var = m.group(1).split(".")[-1], m.group(2)
            start, end, sig = _py_block(lines, i)
            if not sig:
                break
            block = "\n".join(lines[start:end])
            is_input = False
            if re.search(r"\b" + re.escape(var) + r"\b", sig.split(")", 1)[0] if ")" in sig else sig):
                if _PY_ROUTE.search(block[:block.find("def ")] if "def " in block else "") or \
                        re.search(r"def\s+\w+\s*\(\s*(?:self\s*,\s*)?request\b", sig):
                    is_input = True
            else:
                a = re.search(r"\b" + re.escape(var) + r"\s*=\s*([^\n]+)", block)
                if a and _PY_RAW.search(a.group(1)):
                    is_input = True
                elif a:
                    # one more hop: content = request.json; customer_id = content['id']
                    h = re.match(r"\s*(\w+)\s*(?:\[|\.get\s*\()", a.group(1))
                    b = re.search(r"\b" + re.escape(h.group(1)) + r"\s*=\s*([^\n]+)", block) if h else None
                    if b and _PY_RAW.search(b.group(1)):
                        is_input = True
            if not is_input:
                break
            after = "\n".join(lines[i:end])
            mutation = bool(_PY_MUTATION.search(after)) or bool(
                re.search(r"\.(?:put|patch|delete)\s*\(|methods\s*=\s*\[[^\]]*['\"](?:PUT|PATCH|DELETE|POST)",
                          block[:block.find("def ")] if "def " in block else ""))
            if not mutation and _PUBLIC_MODEL.match(model):
                break
            if not mutation and _PROFILE_MODEL.match(model) and not _PY_PRIVATE_FIELD.search(after):
                break
            if _PY_OWNER.search(block) or _PY_AUTHZ.search(block):
                break
            verb = "changed or deleted" if mutation else "read"
            hits.append(Hit(i + 1, line.strip(), "%s is %s by an id from the URL or body with no ownership check "
                                                 "nearby; one user may reach another user's record" % (model, verb)))
            break
    hits.extend(_idor_drf(rel, lines))
    return hits


def _idor_drf(rel: str, lines: List[str]) -> List[Hit]:
    hits = []
    for i, line in enumerate(lines):
        m = _DRF_CLASS.match(line)
        if not m:
            continue
        body = []
        for ln in lines[i + 1:i + 120]:
            if ln.strip() and not ln[:1].isspace():
                break
            body.append(ln)
        text = "\n".join(body)
        qs = re.search(r"^\s+queryset\s*=\s*(\w+)\.objects\.all\(\)", text, re.M)
        bases = m.group(2)
        django_cbv = bool(re.search(r"\b(?:DetailView|UpdateView|DeleteView)\b", bases))
        if not qs and django_cbv:
            qs = re.search(r"^\s+model\s*=\s*(\w+)\s*$", text, re.M)
        if not qs or re.search(r"def\s+(?:get_(?:queryset|object)|test_func|has_permission|dispatch)\b", text):
            continue
        if re.search(r"\b(?:UserPassesTestMixin|PermissionRequiredMixin|AccessMixin|\w*Owner\w*Mixin)\b", bases):
            continue
        perms = re.search(r"permission_classes\s*=\s*[\[(]([^\])]*)[\])]", text)
        if perms:
            names = {p.strip() for p in perms.group(1).split(",") if p.strip()}
            if names - _DRF_SAFE_PERMS:
                continue
        read_only = not re.search(r"ModelViewSet|Update|Destroy|Delete", bases) or "ReadOnlyModelViewSet" in bases
        if read_only and _PUBLIC_MODEL.match(qs.group(1)):
            continue
        kind = "Django view" if django_cbv else "DRF view"
        hits.append(Hit(i + 1, line.strip(), "%s serves any %s by id with no per-user get_queryset or object "
                                             "permission; any user can reach any row" % (kind, qs.group(1))))
    return hits


_PHP_AUTHZ = re.compile(
    r"(?i)\bauthorize\s*\(|Gate::|->can\s*\(|->cannot\s*\(|\bcan\s*\(|abort_if|abort_unless|abort\(\s*403|"
    r"\buser_id\b|->user\(\)->|->user\(\)\s*->\s*id|auth\(\)->id\(\)|Auth::id\(\)|auth\(\)->user\(\)|->is\s*\(|"
    r"->isNot\s*\(|\bpolicy\b|\b403\b|->owner\b|->where\(\s*['\"](?:user_id|owner_id|team_id|tenant_id|author_id)|"
    r"\w+ForUser\s*\(")
_PHP_FIND = re.compile(r"\b([A-Z]\w*)::(?:find|findOrFail|firstWhere)\(\s*\$(\w+)\s*\)")
# Typed parameters that Laravel injects but that are not route-bound models.
_PHP_NOT_MODEL = re.compile(r"^(?:Authenticatable|Guard|StatefulGuard|Carbon\w*|DateTime\w*|Route|Collection|Request|"
                            r"Response|Closure|Container|Application|Str|Arr|Session\w*|Cache\w*|Log\w*|Logger\w*)$|"
                            r"Interface$|Repository|Service$|Manager$|Factory$|Helper$|Handler$|Validator$|Contract$")
_PHP_GATE_MW = r"(?:admin|is_?admin|auth\.admin|role:admin[^'\"]*|can:[^'\"]*|permission:[^'\"]*|owner)"
_PHP_ADMIN_GROUP = re.compile(
    r"'middleware'\s*=>\s*(?:\[[^\]]*['\"]" + _PHP_GATE_MW + r"['\"][^\]]*\]|['\"]" + _PHP_GATE_MW + r"['\"])|"
    r"->middleware\(\s*(?:\[[^\]]*)?['\"]" + _PHP_GATE_MW + r"['\"]")


def _php_models(ctx: Any) -> Dict[str, str]:
    """Model class name -> file, for app/Models/*.php."""
    return ctx.memo("dataauth-php-models", lambda: {f.rsplit("/", 1)[-1][:-4]: f for f in ctx.glob("*.php")
                                                    if "/Models/" in "/" + f})


def _php_scoped_binding(ctx: Any, cls: str) -> bool:
    """The model resolves route keys through the signed-in user (routeBinder,
    resolveRouteBinding or a global scope on auth()), so a foreign id is a 404."""
    f = _php_models(ctx).get(cls)
    if not f:
        return False
    t = ctx.read(f)
    m = re.search(r"function\s+(?:resolveRouteBinding|resolveChildRouteBinding|routeBinder)\s*\(", t)
    if m and re.search(r"auth\(\)|Auth::|->user\(\)|\buser\(\)", t[m.end():m.end() + 3000]):
        return True
    return bool(re.search(r"addGlobalScope", t) and re.search(r"auth\(\)|Auth::", t))


def _php_admin_controllers(ctx: Any) -> List[Tuple[str, Optional[str]]]:
    """(controller, namespace tail) for routes grouped under an admin or can: middleware."""
    def build() -> List[Tuple[str, Optional[str]]]:
        out: List[Tuple[str, Optional[str]]] = []
        for f in ctx.glob("routes/*.php", "routes/**/*.php"):
            t = ctx.read(f)
            for m in _PHP_ADMIN_GROUP.finditer(t):
                fm = re.compile(r"function\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?\{").search(t, m.end())
                if not fm or fm.start() - m.end() > 600 or ";" in t[m.end():fm.start()]:
                    continue
                ns = re.search(r"'namespace'\s*=>\s*'([^']+)'", t[max(0, m.start() - 300):fm.start()])
                tail = ns.group(1).replace("\\\\", "\\").rstrip("\\").rsplit("\\", 1)[-1] if ns else None
                body = _balanced(t, fm.end(), "{", "}") or ""
                out.extend((c, tail) for c in set(re.findall(r"\b(\w+Controller)\b", body)))
        return out
    return ctx.memo("dataauth-php-admin", build)


def _idor_php(rel: str, text: str, ctx: Any) -> List[Hit]:
    cm = re.search(r"\bclass\s+(\w+Controller)\b", text)
    if not cm:
        return []
    if re.search(r"authorizeResource\s*\(|middleware\(\s*['\"]can:|#\[\s*(?:Authorize|Can)\b", text):
        return []
    for cls, tail in _php_admin_controllers(ctx):
        if cls == cm.group(1) and (tail is None or "/" + tail + "/" in "/" + rel):
            return []
    models = _php_models(ctx)
    lines = _code_lines(ctx, rel)
    hits: List[Hit] = []
    for i, line in enumerate(lines):
        m = _PHP_FN.match(line)
        if not m:
            continue
        name = m.group(1)
        sig = line
        j = i
        while ")" not in sig and j + 1 < len(lines) and j < i + 6:
            j += 1
            sig += " " + lines[j]
        params = sig[sig.find("(") + 1:]
        end = len(lines)
        for k in range(i + 1, min(len(lines), i + 150)):
            if _PHP_FN.match(lines[k]):
                end = k
                break
        block = "\n".join(lines[i:end])
        # a custom FormRequest can authorize() the call itself
        if re.search(r"\b(?!Request\b)[A-Z]\w*Request\s+\$", params):
            continue
        if _PHP_AUTHZ.search(block):
            continue
        params_m = re.sub(r"#\[\s*CurrentUser\s*\]\s*\??[A-Z]\w*\s+\$\w+", "", params)
        bound = [b for b in re.findall(r"\b([A-Z]\w*)\s+\$(\w+)", params_m)
                 if not b[0].endswith("Request") and not _PHP_NOT_MODEL.search(b[0])]
        if models:
            bound = [b for b in bound if b[0] in models]
        bound = [b for b in bound if not _php_scoped_binding(ctx, b[0])]
        mutation_name = name in ("update", "destroy", "delete", "edit")
        if name in ("show", "edit", "update", "destroy", "delete") and bound:
            model = bound[0][0]
            if mutation_name or not _PUBLIC_MODEL.match(model):
                hits.append(Hit(i + 1, line.strip(), "%s is bound from the route and %s with no authorize() or "
                                                     "ownership check; one user may reach another user's record"
                                % (model, "changed or deleted" if mutation_name and name != "edit" else "returned")))
                continue
        for k in range(i, end):
            f = _PHP_FIND.search(lines[k])
            if not f or not re.search(r"\$" + re.escape(f.group(2)) + r"\b", params):
                continue
            after = "\n".join(lines[k:end])
            mutation = bool(re.search(r"->(?:update|delete|fill|save|forceDelete)\s*\(", after))
            if not mutation and _PUBLIC_MODEL.match(f.group(1)):
                continue
            hits.append(Hit(k + 1, lines[k].strip(), "%s is loaded by an id from the request with no ownership "
                                                     "check nearby; one user may reach another user's record"
                            % f.group(1)))
            break
    return hits


def check_idor(path: str, text: str, ctx: Any) -> List[Hit]:
    if path.endswith(_JS_EXTS):
        return _idor_js(path, text, ctx)
    if path.endswith(".py"):
        return _idor_py(path, text, ctx)
    if path.endswith(".php"):
        return _idor_php(path, text, ctx)
    return []


# ---------------------------------------------------------------------------
# Client-only auth
# ---------------------------------------------------------------------------

_ROLE_KEYS = (r"(?:is_?admin|admin|role|user_?role|roles|is_?logged_?in|logged_?in|is_?authenticated|authenticated|"
              r"is_?auth|auth_?status|is_?pro|is_?premium|is_?paid|is_?subscribed|"
              r"access_?level|permissions?|is_?vip|vip|is_?staff|is_?owner)")
_CLIENT_ROLE_FLAG = (
    r"(?i)\b(?:localStorage|sessionStorage)\s*\.\s*getItem\(\s*['\"`]" + _ROLE_KEYS + r"['\"`]\s*\)"
    r"|\b(?:localStorage|sessionStorage)\s*(?:\.\s*|\[\s*['\"`])(?:isAdmin|is_admin|role|userRole|isLoggedIn|"
    r"isAuthenticated|isPro|isPremium)\b"
    r"|\bgetItem\(\s*['\"`](?:user|currentUser|auth|profile|session|userData|user_data|authUser)['\"`]\s*\)"
    r"[^\n;]{0,40}?\)\s*\??\.\s*(?:role|isAdmin|is_admin|admin|isPro|is_pro|plan|tier|permissions)\b"
    r"|\bCookies\s*\.\s*get\(\s*['\"](?:role|isAdmin|is_admin|admin|userRole|user_role)['\"]\s*\)")

_PW_IDENT = r"[\w$.\[\]'\"]*?(?:pass(?:word|wd|code|phrase)?|pwd|\bpin|secret|access_?code|admin_?key|unlock_?code)[\w$]*"
_PW_CMP = re.compile(
    r"(?i)(?P<lhs>" + _PW_IDENT + r")\s*(?:===|==|!==|!=)\s*(?P<q>['\"`])(?P<lit>[^'\"`\n]{3,64})(?P=q)"
    r"|(?P<q2>['\"`])(?P<lit2>[^'\"`\n]{3,64})(?P=q2)\s*(?:===|==|!==|!=)\s*(?P<rhs>" + _PW_IDENT + r")\b")
_PW_ENV_CMP = re.compile(
    r"(?i)(?:===|==|!==|!=)\s*(?P<env>(?:import\.meta\.env\.VITE_|process\.env\.(?:NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|VITE_))"
    r"\w*(?:PASS|PWD|PIN|SECRET|CODE|KEY)\w*)"
    r"|(?P<env2>(?:import\.meta\.env\.VITE_|process\.env\.(?:NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_|VITE_))"
    r"\w*(?:PASS|PWD|PIN|SECRET|CODE)\w*)\s*(?:===|==|!==|!=)")
_PW_ENV_FLAG = re.compile(r"(?i)\.(?:VITE_|NEXT_PUBLIC_|REACT_APP_|EXPO_PUBLIC_)?(?:\w+_)?(?:DISABLE|ENABLE|ALLOW|USE|SHOW|"
                          r"HIDE|FEATURE|FLAG|IS|HAS)_\w*|_(?:AUTH|AUTHENTICATION|ENABLED|DISABLED|MODE|LOGIN|FLOW)$")
_PW_FLAG_LIT = re.compile(r"""(?i)\s*(['"`]?)(?:true|false|1|0|yes|no|on|off|enabled|disabled)\1\s*(?:[;),&|?]|$)""")
_PW_LIT_OK = {
    "password", "text", "new-password", "current-password", "strong", "weak", "medium", "hidden", "visible",
    "show", "hide", "email", "phone", "pin", "otp", "reset", "change", "forgot", "sms", "totp", "none", "null",
    "undefined", "true", "false", "string", "number", "object", "function", "boolean", "required", "invalid",
    "valid", "error", "success", "pending", "idle", "loading", "magic", "magic_link", "magiclink", "oauth",
    "passkey", "credentials", "code", "token", "default", "secret", "on", "off", "fair", "good", "very strong",
    "very weak", "too short", "mismatch", "match", "empty", "set", "unset", "verify", "confirm", "login",
    "signup", "sign-in", "sign-up", "recovery", "password_recovery", "passwordless",
}
_PW_IDENT_OK = re.compile(r"(?i)type|strength|field|label|mode|visib|show|hidden|error|confirm|status|state|policy|"
                          r"length|score|level|match|method|step|view|tab|screen|provider|variant|kind|rule|hint|"
                          r"placeholder|name\b|autocomplete|input_?type|reset|forgot|event|action|route|page|"
                          r"\.key\b|key\]|code_?type|expired|attempt")


_PW_SEG_SNAKE = re.compile(r"(?i)(?:[a-z0-9]+_)*(?:pass(?:word|wd|code|phrase)?|pwd|pin|pin_?code|secret|"
                           r"access_?code|admin_?key|unlock_?code)")
_PW_SEG_CAMEL = re.compile(r"[a-z][a-zA-Z0-9]*(?:Password|Passwd|Pwd|Passcode|Passphrase|Pin|PinCode|Secret|AccessCode|"
                           r"UnlockCode|AdminKey)")


def _pw_name(ident: str) -> bool:
    """True when the last name in ident is a password-like name (not bypass, pinned, compass)."""
    segs = [s for s in re.split(r"[.\[\]'\"$?!]+", ident) if s]
    if not segs:
        return False
    seg = segs[-1]
    return bool(_PW_SEG_SNAKE.fullmatch(seg) or _PW_SEG_CAMEL.fullmatch(seg))


def check_client_password(path: str, text: str, ctx: Any) -> List[Hit]:
    html = path.lower().endswith((".html", ".htm"))
    if not html and not ctx.is_client_file(path):
        return []
    if _is_test(path):
        return []
    hits = []
    for i, line in enumerate(_code_lines(ctx, path), 1):
        if not line or len(line) > 400:
            continue
        hit = None
        for m in _PW_CMP.finditer(line):
            ident = m.group("lhs") or m.group("rhs") or ""
            lit = (m.group("lit") if m.group("lit") is not None else m.group("lit2")) or ""
            if lit.strip().lower() in _PW_LIT_OK or _PW_IDENT_OK.search(ident):
                continue
            if "${" in lit or not _pw_name(ident):
                continue
            hit = Hit(i, line.strip(), "password compared to a value that ships in the client code; anyone can "
                                       "read it in the browser")
            break
        if hit is None:
            e = _PW_ENV_CMP.search(line)
            # import.meta.env.VITE_DISABLE_PASSWORD_LOGIN === "true" is a feature flag, not a password
            if e and not _PW_ENV_FLAG.search(e.group("env") or e.group("env2")) and not (
                    e.group("env2") and _PW_FLAG_LIT.match(line[e.end():])):
                hit = Hit(i, line.strip(), "password compared to %s, a public env var that is baked into the bundle"
                          % (e.group("env") or e.group("env2")))
        if hit is not None:
            hits.append(hit)
    return hits


# ---------------------------------------------------------------------------
# Mass assignment
# ---------------------------------------------------------------------------

_BODY_NAMES = (r"(?:body|data|payload|input|values|fields|updates|changes|attrs|attributes|formData|json|reqBody|"
               r"requestBody|form|rawBody|parsedBody|formValues)")
_RAW_JS = r"(?:req\.body|request\.body|ctx\.request\.body|await\s+(?:req|request)\.json\(\s*\))"
_MA_JS = [
    re.compile(r"\.(?:insert|upsert|update)\(\s*(?P<v>" + _RAW_JS + r"|Object\.fromEntries\(\s*(?:await\s+)?[\w$.]+"
               r"(?:\.entries\(\))?\s*\)|" + _BODY_NAMES + r")\s*[,)]"),
    re.compile(r"\b(?!(?:Object|Array|JSON|Promise|Reflect|Math|Date|Number|String|Response|NextResponse|Buffer|"
               r"Intl|Symbol|Crypto)\b)[A-Z][\w$]*\s*\.\s*(?:create|insertMany|bulkCreate|findByIdAndUpdate|"
               r"findOneAndUpdate|updateOne|updateMany|update|build)\(\s*(?:[^,()]+,\s*)?(?P<v>" + _RAW_JS + r"|"
               + _BODY_NAMES + r")\s*[,)]"),
    re.compile(r"\bnew\s+(?!(?:Date|Error|URL|Map|Set|Response|NextResponse|Request|Headers|Blob|File|FormData|"
               r"URLSearchParams|Promise|RegExp|Array|Object|Buffer|TextEncoder|TextDecoder|Uint8Array|"
               r"WeakMap|Proxy|Intl)\b)[A-Z][\w$]*\(\s*(?P<v>" + _RAW_JS + r"|" + _BODY_NAMES + r")\s*\)"),
    re.compile(r"\bObject\.assign\(\s*[\w$.]+\s*,\s*(?P<v>" + _RAW_JS + r"|" + _BODY_NAMES + r")\s*\)"),
    re.compile(r"\.(?:insert|update|upsert|create|save)\(\s*\{\s*\.\.\.(?P<v>" + _RAW_JS + r"|" + _BODY_NAMES + r")\b"),
]
_PRISMA_WRITE = re.compile(r"\.(?:create|update|upsert|createMany|updateMany)\(\s*\{")
_PRISMA_DATA = re.compile(r"\bdata\s*:\s*(?:\{\s*\.\.\.\s*)?(?P<v>" + _RAW_JS + r"|" + _BODY_NAMES + r")\s*[,}\n]"
                          r"|[{,]\s*(?P<s>data)\s*[,}]")
_RAW_ASSIGN_JS = re.compile(r"\b(?:req|request|ctx\.request)\.body\b|\b(?:req|request)\.json\s*\(|Object\.fromEntries\s*\(|"
                            r"(?:req|request)\.formData\s*\(|JSON\.parse\s*\(\s*(?:await\s+)?(?:req|request|event)\b|"
                            r"\breadBody\s*\(|\bevent\.body\b")
# hmac.update(req.body) in webhook signature code is hashing, not a database write
_HASH_CTX = re.compile(r"(?i)createHmac|createHash|createCipher\w*|\bhmac\b|\bhasher\b|\bdigest\b|\bsignature\b")


def _ma_js(rel: str, text: str, ctx: Any) -> List[Hit]:
    if ctx.is_client_file(rel) or _USE_CLIENT.match(text):
        return []
    lines = _code_lines(ctx, rel)
    file_action = bool(_USE_SERVER.match(text))
    hits: List[Hit] = []
    for i, line in enumerate(lines):
        if not line or len(line) > 500 or _HASH_CTX.search(line):
            continue
        recv = re.search(r"([\w$]+)\s*\.\s*update\(", line)
        if recv and re.search(re.escape(recv.group(1)) + r"\s*=\s*[^;\n]*create(?:Hmac|Hash)\b", text):
            continue
        cands = [m.group("v") for rx in _MA_JS for m in rx.finditer(line)]
        p = _PRISMA_WRITE.search(line)
        if p:
            span = "\n".join(lines[i:i + 8])[p.start():][:600]
            # only the argument object of this call, not code that follows it
            arg = _balanced(span, span.find("{") + 1, "{", "}")
            d = _PRISMA_DATA.search("{" + arg + "}") if arg is not None else None
            if d:
                cands.append(d.group("v") or d.group("s"))
        if not cands:
            continue
        start, end = _block(lines, i, _JS_FN_START)
        block = "\n".join(lines[start:end])
        sig = _js_sig(lines, start)
        action = file_action or bool(re.search(r"""['"]use server['"]""", block))
        for v in cands:
            v = re.sub(r"\s+", " ", v)
            raw = False
            if re.match(_RAW_JS + r"$", v) or v.startswith("Object.fromEntries"):
                raw = True
            else:
                rhs = _js_assigned(block, v)
                if rhs is not None:
                    raw = bool(_RAW_ASSIGN_JS.search(rhs)) and not re.search(r"\.(?:parse|safeParse|validate|pick|omit)\s*\(", rhs)
                elif action and re.search(r"\b" + re.escape(v) + r"\b", sig) and not re.search(
                        r"\b" + re.escape(v) + r"\s*\.\s*(?:get|getAll)\s*\(", block):
                    raw = True
            if raw:
                hits.append(Hit(i + 1, line.strip(), "the request body goes straight into a create or update; a "
                                                     "client can set role, price, credits or owner fields"))
                break
    return hits + _ma_js_privileged(rel, lines, file_action, {h.line for h in hits})


_PRIV_KEY = re.compile(r"(?i)^(?:role|roles|user_?role|is_?admin|admin|permissions|plan|tier|credits|balance|"
                       r"is_?verified|email_?verified|is_?staff|is_?superuser|is_?premium|is_?pro|access_?level)$")
_PRIV_WRITE = re.compile(r"\.(?:insert|update|upsert|create|save|updateOne|updateMany|findByIdAndUpdate|"
                         r"findOneAndUpdate)\(")
_CHAT_OBJ = re.compile(r"(?i)^(?:content|message|text|parts|prompt)\b")
_USERISH_MODEL = re.compile(r"(?i)^(?:profiles?|users?|user_?\w+|\w+_?profiles?|members?|\w+_?members?|memberships?|"
                            r"customers?|subscriptions?|accounts?|staff|employees?)$")


def _ma_js_privileged(rel: str, lines: List[str], file_action: bool, seen: Set[int]) -> List[Hit]:
    """A role, plan or credits field picked out of the request and written as is."""
    hits: List[Hit] = []
    for i, line in enumerate(lines):
        if not line or i + 1 in seen or len(line) > 500:
            continue
        for p in _PRIV_WRITE.finditer(line):
            span = "\n".join(lines[i:i + 10])[p.end():][:800].lstrip()
            if not span.startswith("{"):
                continue
            obj = _balanced(span, 1, "{", "}") or ""
            parts = [x.strip() for x in _split_top(obj) if x.strip()]
            data = [x for x in parts if re.match(r"data\s*:\s*\{", x)]
            if data:
                inner = data[0].split(":", 1)[1].strip()
                parts = [x.strip() for x in _split_top(_balanced(inner, 1, "{", "}") or "") if x.strip()]
            if any(_CHAT_OBJ.match(x) for x in parts):
                continue
            ctx_text = "\n".join(lines[max(0, i - 3):i + 1])
            tm = (list(re.finditer(r"""\.from\(\s*['"`](\w+)['"`]\s*\)""", ctx_text)) or
                  list(re.finditer(r"\b(?:prisma|db|tx|client)\s*\.\s*(\w+)\s*\.\s*\w+\(", ctx_text)) or
                  list(re.finditer(r"\b([A-Z]\w*)\s*\.\s*\w+\(", ctx_text)))
            target = tm[-1].group(1) if tm else ""
            for part in parts:
                key, _, val = part.partition(":")
                key = key.strip().strip("'\"")
                if not _PRIV_KEY.match(key):
                    continue
                # role or plan on a non-user table (a job title, a chat role, a meal plan) grants nothing
                if key.lower() in ("role", "roles", "plan", "tier") and target and not _USERISH_MODEL.match(target):
                    continue
                start, end = _block(lines, i, _JS_FN_START)
                block = "\n".join(lines[start:end])
                sig = _js_sig(lines, start) + " " + _js_cb_params(block)
                action = (file_action and bool(re.match(r"\s*export\b", lines[start]))) or bool(
                    re.search(r"""['"]use server['"]""", block))
                if _js_value_kind(val.strip() or key, block, sig, action) != "input" or _JS_AUTHZ.search(block):
                    continue
                hits.append(Hit(i + 1, line.strip(), "%s is taken from the request and written as is, with no "
                                                     "server-side role check; any caller can grant it to themselves"
                                % key))
                break
            if hits and hits[-1].line == i + 1:
                break
    return hits


_MA_PY = [
    re.compile(r"\b[A-Z]\w*\(\s*\*\*\s*(?P<v>request\.(?:json|get_json\(\s*\)|form(?:\.to_dict\(\s*\))?|data|"
               r"POST(?:\.dict\(\s*\))?|args(?:\.to_dict\(\s*\))?)|await\s+request\.json\(\s*\)|[a-z_]\w*)\s*\)"),
    re.compile(r"\.objects\.(?:create|update|update_or_create|get_or_create)\(\s*\*\*\s*(?P<v>request\.(?:data|POST|GET)"
               r"(?:\.dict\(\s*\))?|[a-z_]\w*)\s*\)"),
    re.compile(r"\.update\(\s*\*\*\s*(?P<v>request\.\w+(?:\(\s*\))?|[a-z_]\w*)\s*\)"),
    re.compile(r"\bfor\s+(?P<k>\w+)\s*,\s*(?P<val>\w+)\s+in\s+(?P<v>request\.(?:json|get_json\(\s*\)|form|data|POST)|"
               r"[a-z_]\w*)\.items\(\s*\)\s*:"),
]
_RAW_PY = re.compile(r"^(?:await\s+)?(?:request\.(?:json|get_json|form|data|POST|args|values)\b|"
                     r"json\.loads\(\s*request\.(?:body|data|get_data))")


def _ma_py(rel: str, text: str, ctx: Any) -> List[Hit]:
    lines = _code_lines(ctx, rel)
    hits: List[Hit] = []
    for i, line in enumerate(lines):
        if not line or "**" not in line and " in " not in line:
            continue
        for n, rx in enumerate(_MA_PY):
            m = rx.search(line)
            if not m:
                continue
            v = m.group("v")
            if n == 3:
                nxt = "\n".join(lines[i + 1:i + 4])
                if not re.search(r"setattr\(\s*\w+\s*,\s*" + m.group("k") + r"\s*,\s*" + m.group("val") + r"\s*\)", nxt):
                    continue
            raw = v.startswith(("request.", "await request"))
            if not raw:
                start, end, sig = _py_block(lines, i)
                block = "\n".join(lines[start:i + 1])
                a = None
                for a in re.finditer(r"^\s*" + re.escape(v) + r"\s*(?::[^=\n]+)?=\s*([^\n]+)", block, re.M):
                    pass
                if a is not None:
                    raw = bool(_RAW_PY.match(a.group(1).strip()))
                elif re.search(r"\b" + re.escape(v) + r"\s*:\s*(?:dict|Dict\b|typing\.Dict|Any\b|Mapping)", sig):
                    raw = True
            if raw:
                hits.append(Hit(i + 1, line.strip(), "request data goes straight into a model create or update; a "
                                                     "client can set role, price, credits or owner fields"))
                break
    return hits + _ma_py_privileged(lines, {h.line for h in hits})


_PY_PRIV_NAMES = r"(?:is_staff|is_superuser|is_admin|is_verified|role|roles|user_role|plan|tier|credits|balance|access_level)"
_PY_PRIV_ATTR = re.compile(r"^\s*[\w.]+\.(" + _PY_PRIV_NAMES + r")\s*=(?!=)\s*(.+?)\s*$")
_PY_PRIV_SETATTR = re.compile(r"\bsetattr\(\s*[\w.]+\s*,\s*['\"](" + _PY_PRIV_NAMES + r")['\"]\s*,\s*(.+)\)\s*$")
_PY_GROUP_ADD = re.compile(r"\.(groups|user_permissions)\s*\.\s*(?:add|set)\(\s*(.+)\)\s*$")
_PY_NOT_VAR = {"self", "request", "none", "true", "false", "int", "str", "bool", "float", "len", "list", "dict", "set"}


def _py_from_request(expr: str, block: str, hops: int = 3) -> bool:
    """True when expr reads request data directly or through up to `hops` local assignments
    (post_data = request.POST.dict(); level = post_data['level']; grp = Group.objects.get(name=level))."""
    if _PY_RAW.search(expr):
        return True
    if hops <= 0:
        return False
    code = re.sub(r"'[^'\n]*'|\"[^\"\n]*\"", "''", expr)
    for name in set(re.findall(r"(?<![.\w])([a-z_]\w*)\b(?!\s*=(?!=))(?!\s*\()", code)):
        if name in _PY_NOT_VAR:
            continue
        rhs = None
        for m in re.finditer(r"^\s*" + re.escape(name) + r"\s*(?::[^=\n]+)?=(?!=)\s*([^\n]+)", block, re.M):
            rhs = m.group(1)
        if rhs is not None and _py_from_request(rhs, block, hops - 1):
            return True
    return False


def _ma_py_privileged(lines: List[str], seen: Set[int]) -> List[Hit]:
    """A role, staff flag, group or permission set from request data with no admin check."""
    hits: List[Hit] = []
    for i, line in enumerate(lines):
        if not line or i + 1 in seen:
            continue
        m = _PY_PRIV_ATTR.match(line) or _PY_PRIV_SETATTR.search(line)
        g = None if m else _PY_GROUP_ADD.search(line)
        if not (m or g):
            continue
        start, _, sig = _py_block(lines, i)
        if not sig:
            continue
        block = "\n".join(lines[start:i + 1])
        # the assignment itself (user.is_staff = ...) is not a role check
        near = [ln for ln in lines[start:i + 1]
                if not (_PY_PRIV_ATTR.match(ln) or _PY_PRIV_SETATTR.search(ln))]
        if _PY_AUTHZ.search("\n".join(near)):
            continue
        if not _py_from_request((m or g).group(2), block):
            continue
        if m:
            msg = ("%s is set from request data with no admin check; any caller can grant it to themselves"
                   % m.group(1))
        else:
            msg = ("a group or permission chosen in the request is added to a user with no admin check; any "
                   "signed-in user can grant themselves admin")
        hits.append(Hit(i + 1, line.strip(), msg))
    return hits


_MA_PHP = re.compile(
    r"(?:::|->)(?P<fn>create|forceCreate|firstOrCreate|updateOrCreate|update|fill|forceFill|insert)\(\s*"
    r"(?:array_merge\(\s*)?(?:\$request->(?:all|input|post|json)\(\s*\)|request\(\)->(?:all|input)\(\s*\)|"
    r"Input::all\(\s*\)|\$_POST\b|\$request->json\(\)->all\(\s*\))")
_PHP_SENSITIVE = re.compile(r"""['"](?:role|roles|is_?admin|admin|permissions?|credits|balance|price|amount|total|"""
                            r"""user_id|owner_id|team_id|tenant_id|is_?verified|verified|email_verified_at|plan|"""
                            r"""subscription|is_?pro|is_?premium|approved|is_?approved)['"]""", re.I)


def _php_model_guard(ctx: Any, model: str) -> str:
    """'safe', 'unsafe' or 'unknown' for a model's mass-assignment guard."""
    def unguarded() -> bool:
        return any("Model::unguard()" in ctx.read(f) for f in ctx.glob("*.php") if "Provider" in f)
    if ctx.memo("dataauth-php-unguard", unguarded):
        return "unsafe"
    files = [f for f in ctx.glob(model + ".php") if "/Models/" in "/" + f or f.startswith("app/")]
    if not files:
        return "unknown"
    t = ctx.read(files[0])
    fill = re.search(r"\$fillable\s*=\s*\[([^\]]*)\]", t, re.S)
    if fill:
        return "unsafe" if _PHP_SENSITIVE.search(fill.group(1)) else "safe"
    guarded = re.search(r"\$guarded\s*=\s*\[([^\]]*)\]", t, re.S)
    if guarded:
        return "unsafe" if not guarded.group(1).strip() else "safe"
    if re.search(r"#\[\s*(?:Unguarded|Fillable)", t):
        return "unknown"
    return "safe"


def _ma_php(rel: str, text: str, ctx: Any) -> List[Hit]:
    lines = _code_lines(ctx, rel)
    hits: List[Hit] = []
    for i, line in enumerate(lines):
        m = _MA_PHP.search(line)
        if not m:
            continue
        fn = m.group("fn")
        if fn in ("forceCreate", "forceFill"):
            hits.append(Hit(i + 1, line.strip(), "%s() with the whole request skips $fillable; a client can set any "
                                                 "column" % fn))
            continue
        model = None
        cm = re.search(r"\b([A-Z]\w*)::" + fn + r"\(", line)
        if cm:
            model = cm.group(1)
        else:
            vm = re.search(r"\$(\w+)\s*->" + fn + r"\(", line)
            if vm:
                for k in range(i, max(-1, i - 60), -1):
                    t = re.search(r"\b([A-Z]\w*)\s+\$" + re.escape(vm.group(1)) + r"\b", lines[k])
                    if t:
                        model = t.group(1)
                        break
        state = _php_model_guard(ctx, model) if model else "unknown"
        if state == "safe":
            continue
        why = "its $fillable includes privileged columns or it is unguarded" if state == "unsafe" else "check its $fillable"
        hits.append(Hit(i + 1, line.strip(), "the whole request goes into %s; %s" % (model or "a model", why)))
    return hits


def check_mass_assignment(path: str, text: str, ctx: Any) -> List[Hit]:
    if path.endswith(_JS_EXTS):
        return _ma_js(path, text, ctx)
    if path.endswith(".py"):
        return _ma_py(path, text, ctx)
    if path.endswith(".php"):
        return _ma_php(path, text, ctx)
    return []


def check_serializer_all(path: str, text: str, ctx: Any) -> List[Hit]:
    lines = _code_lines(ctx, path)
    hits = []
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)fields\s*=\s*['\"]__all__['\"]", line)
        ex = None if m else re.match(r"^(\s*)exclude\s*=\s*[\[(]([^\])]*)[\])]", line)
        if ex:
            m = ex
        if not m:
            continue
        ind = len(m.group(1))
        meta = None
        for j in range(i - 1, max(-1, i - 40), -1):
            ln = lines[j]
            if ln.strip() and len(ln) - len(ln.lstrip()) < ind:
                meta = j
                break
        if meta is None or not re.match(r"\s*class\s+Meta\b", lines[meta]):
            continue
        mind = len(lines[meta]) - len(lines[meta].lstrip())
        owner = None
        for j in range(meta - 1, max(-1, meta - 200), -1):
            ln = lines[j]
            if ln.strip() and len(ln) - len(ln.lstrip()) < mind:
                owner = ln
                break
        if not owner or not re.search(r"class\s+\w+\(.*(?:ModelSerializer|HyperlinkedModelSerializer|ModelForm)\b", owner):
            continue
        meta_body = "\n".join(lines[meta:meta + 25])
        if ex:
            # exclude on the User model leaves every flag it does not name writable
            if not re.search(r"^\s*model\s*=\s*(?:\w+\.)*(?:\w*User|get_user_model\(\s*\))\s*$", meta_body, re.M):
                continue
            missing = [f for f in ("is_superuser", "is_staff") if f not in ex.group(2)]
            ro = re.search(r"read_only_fields\s*=\s*[\[(]([^\])]*)[\])]", meta_body)
            missing = [f for f in missing if not (ro and f in ro.group(1))]
            if missing:
                hits.append(Hit(i + 1, line.strip(), "form or serializer for the User model uses exclude and leaves "
                                                     "%s writable; a client can sign up as a superuser. List the "
                                                     "allowed fields instead" % " and ".join(missing), "high"))
            continue
        if re.search(r"\bread_only_fields\b", meta_body):
            hits.append(Hit(i + 1, line.strip(), "fields = '__all__' with read_only_fields; any column added later "
                                                 "becomes writable by clients", "low"))
        else:
            hits.append(Hit(i + 1, line.strip()))
    return hits


# ---------------------------------------------------------------------------
# Password hashing and JWT handling
# ---------------------------------------------------------------------------

_PW_ARG = re.compile(r"(?i)\b(?:password|passwd|pwd|pass|plain_?password|plainpassword|raw_?password|"
                     r"new_?password|newpassword|user_?password|userpassword)\b")
_HASH_PATTERNS = [
    re.compile(r"(?i)createHash\(\s*['\"](md5|sha1|sha224|sha256|sha384|sha512)['\"]\s*\)\s*\.update\(\s*(?P<arg>[^)\n]{0,80})"),
    re.compile(r"(?i)\b(?:CryptoJS\s*\.\s*)?(md5|sha1|sha256|sha512|MD5|SHA1|SHA256|SHA512)\(\s*(?P<arg>[^)\n]{0,60})"),
    re.compile(r"(?i)\bhashlib\.(md5|sha1|sha224|sha256|sha384|sha512)\(\s*(?P<arg>[^)\n]{0,80})"),
    re.compile(r"(?i)\bhashlib\.new\(\s*['\"](md5|sha1|sha256|sha512)['\"]\s*,\s*(?P<arg>[^)\n]{0,80})"),
    re.compile(r"(?i)\bhash\(\s*['\"](md5|sha1|sha256|sha512)['\"]\s*,\s*(?P<arg>[^)\n]{0,60})"),
]


# A fingerprint, cache key or etag of a stored hash is not how the password is stored.
_HASH_NOT_STORAGE = re.compile(r"(?i)fingerprint|\betag\b|checksum|cache_?key|cachekey")
# $user['password'] or user.password_hash is the stored (already slow) hash, not the plain password.
_HASH_STORED_ARG = re.compile(r"""(?i)\$\w+\[\s*['"]password['"]\s*\]|\.(?:password_hash|hashed_password|passwordHash)\b""")
_SLOW_HASH = re.compile(r"(?i)\bbcrypt|\bargon2|\bscrypt|\.exec\(\s*['\"]hash['\"]|password_hash\s*\(")


_DJANGO_WEAK_HASHER = re.compile(r"""PASSWORD_HASHERS\s*=\s*[\[(]\s*['"]django\.contrib\.auth\.hashers\."""
                                 r"""((?:Unsalted)?(?:MD5|SHA1)|Crypt)PasswordHasher['"]""")


def check_weak_password_hash(path: str, text: str, ctx: Any) -> List[Hit]:
    if re.search(r"pwnedpasswords|haveibeenpwned", text, re.I):
        return []
    hits = []
    lines = _code_lines(ctx, path)
    if path.endswith(".py"):
        dm = _DJANGO_WEAK_HASHER.search(text)
        if dm and not re.search(r"(?i)(?:^|/)(?:test\w*|\w*_test|testing|ci)\.py$|/tests?/", path):
            n, ev = _line_at(ctx, path, dm.start())
            # the fast hasher inside an "if testing" block only speeds up the test suite
            above = "\n".join(lines[max(0, n - 6):n - 1])
            in_test = lines[n - 1][:1].isspace() and re.search(r"(?i)\bif\b[^\n]*\btest", above)
            if lines[n - 1] and not in_test:
                hits.append(Hit(n, ev, "PASSWORD_HASHERS puts %sPasswordHasher first, so Django stores new passwords "
                                       "with it; put Argon2PasswordHasher or PBKDF2PasswordHasher first" % dm.group(1)))
    for i, line in enumerate(lines):
        if not line:
            continue
        joined = line
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        if "createHash(" in line and ".update(" not in line and nxt.strip().startswith(".update("):
            joined = line.rstrip() + nxt.strip()
        if _HASH_NOT_STORAGE.search(joined):
            continue
        for rx in _HASH_PATTERNS:
            m = rx.search(joined)
            if m and _PW_ARG.search(m.group("arg")) and not re.search(r"(?i)reset|token|otp|nonce|salt_?only", m.group("arg")):
                if _HASH_STORED_ARG.search(m.group("arg")):
                    continue
                # a pre-hash whose digest goes straight into bcrypt, argon2 or scrypt
                if _SLOW_HASH.search("\n".join(lines[i + 1:i + 6])) or (
                        _SLOW_HASH.search(text) and re.match(r"\s*\$?(?:password|passwd|pwd|pass)\s*=", line, re.I)):
                    continue
                hits.append(Hit(i + 1, line.strip(), "password hashed with fast %s; use argon2id, scrypt or bcrypt"
                                % m.group(1).lower()))
                break
    return hits


_JWT_PY_NOVERIFY = re.compile(r"jwt\.decode\((?:[^()]|\([^()]*\)){0,300}?(?:[\"']verify_signature[\"']\s*:\s*False|"
                              r"\bverify\s*=\s*False)", re.S)
_JWT_NONE = re.compile(r"(?i)\balgorithms?\s*[=:]\s*\[?\s*['\"]none['\"]")
_JWT_IMPORT = re.compile(r"""(?:from\s+['"]jsonwebtoken['"]|require\(\s*['"]jsonwebtoken['"]\s*\))""")
_JWT_DECODE_LIB = re.compile(r"""(?:from\s+['"](?:jwt-decode|jose)['"]|require\(\s*['"](?:jwt-decode|jose)['"]\s*\))""")


_TOKEN_ENDPOINT = re.compile(r"""(?i)['"]https://[^'"]+/token['"]|\bfetch_token\s*\(|grant_type['"]?\s*[:=,]\s*['"]"""
                             r"""authorization_code|TOKEN_OBTAIN_URL|token_endpoint""")


def check_jwt_not_verified(path: str, text: str, ctx: Any) -> List[Hit]:
    hits: List[Hit] = []
    lines = _code_lines(ctx, path)
    for i, line in enumerate(lines, 1):
        if line and _JWT_NONE.search(line):
            hits.append(Hit(i, line.strip(), "JWT algorithm 'none' accepted or used; tokens are not signed"))
    if path.endswith(".py"):
        token_endpoint = bool(_TOKEN_ENDPOINT.search(text))
        for m in _JWT_PY_NOVERIFY.finditer(text):
            n, ev = _line_at(ctx, path, m.start())
            if not lines[n - 1]:
                continue
            if token_endpoint and re.search(r"\bid_token\b", m.group(0)):
                # OIDC Core 3.1.3.7: an id_token taken straight from the provider's token endpoint over TLS
                hits.append(Hit(n, ev, "jwt.decode() skips the signature of an id_token; fine only when the token "
                                       "comes straight from the provider's token endpoint over TLS, never when it "
                                       "arrives from the browser", "low"))
                continue
            hits.append(Hit(n, ev, "jwt.decode() with signature checks turned off; anyone can forge the claims"))
        return hits
    if ctx.is_client_file(path) or _USE_CLIENT.match(text):
        return hits
    server = bool(_NEXT_MW_FILE.search(path) or _SERVER_FILE_NAME.search(path) or _USE_SERVER.match(text) or
                  re.search(r"\b(?:req|request)\s*,\s*(?:res|reply)\b|\bexpress\b|\bNextRequest\b|next/headers", text))
    if not server:
        return hits
    if _JWT_IMPORT.search(text) and not re.search(r"\.verify\s*\(", text):
        for i, line in enumerate(lines, 1):
            if line and re.search(r"\bjwt\s*\.\s*decode\s*\(", line):
                hits.append(Hit(i, line.strip(), "jsonwebtoken decode() reads the claims without checking the "
                                                 "signature; use jwt.verify() with a pinned algorithm"))
    if _JWT_DECODE_LIB.search(text) and not re.search(r"\bjwtVerify\s*\(|\.verify\s*\(", text):
        for i, line in enumerate(lines, 1):
            if line and re.search(r"\b(?:jwtDecode|jwt_decode|decodeJwt)\s*\(", line):
                hits.append(Hit(i, line.strip(), "server code decodes a JWT without verifying it; anyone can forge "
                                                 "the claims"))
    return hits


# ---------------------------------------------------------------------------
# Admin routes, cookies, hardcoded bypasses, service-role functions
# ---------------------------------------------------------------------------

_ADMIN_PATH = re.compile(r"(?:^|/)(?:app/(?:.*/)?api|pages/api|src/routes/api)/(?:.*/)?admin(?:/|\.|$)")
_ROLE_CHECK = re.compile(
    r"(?i)\b(?:is_?admin|isSuperAdmin|requireAdmin\w*|require_?admin\w*|ensureAdmin\w*|assertAdmin\w*|checkAdmin\w*|"
    r"adminOnly|admin_required|hasRole|has_role|requireRole|checkRole|authorize|isStaff|is_staff|is_superuser|"
    r"permission_required|hasPermission|can\w*)\b|\.role\s*(?:!==|===|!=|==|\bin\b)|\.roles?\s*\??\.\s*(?:includes|some|has)"
    r"|['\"`]admin['\"`]\s*(?:!==|===|!=|==)|\bwith(?:Admin|SuperAdmin|Staff)\w*\s*\(|\badminProcedure\b|\b403\b")
_EXPRESS_ROUTE = re.compile(r"\b(?:router|app|r|api)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*(['\"`])"
                            r"(/(?:[^'\"`]*/)?admin(?:/[^'\"`]*)?)\2\s*,")


def _mw_admin_gate(ctx: Any) -> bool:
    """A Next.js middleware or proxy that checks a role for /admin paths."""
    for f in ctx.files:
        if _NEXT_MW_FILE.search(f) and not _is_test(f):
            t = _blank_comments(ctx.read(f))
            if "admin" in t and _ROLE_CHECK.search(t):
                return True
    return False


def _py_route_decorators(lines: List[str]) -> List[Tuple[int, str, Set[str]]]:
    """(line, function name, other decorators) for each decorated route function."""
    out = []
    deco: List[str] = []
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith("@"):
            deco.append(s)
            continue
        m = re.match(r"(?:async\s+)?def\s+(\w+)\s*\(", s)
        if m and deco and not line[:1].isspace() and any(_PY_ROUTE.search(d) for d in deco):
            names = {re.sub(r"\(.*$", "", d[1:]).split(".")[-1] for d in deco if not _PY_ROUTE.search(d)}
            out.append((i + 1 - len(deco), m.group(1), names))
        if s and not s.startswith("@"):
            deco = []
    return out


_AUTH_DECO = re.compile(r"(?i)^(?:\w*_required|requires?_\w+|\w*auth\w*|roles_accepted|permission\w*)$")
_PUBLIC_ROUTE = re.compile(r"(?i)login|logout|signin|signup|sign_up|sign_in|register|reset|forgot|health|webhook|"
                           r"static|callback|verify|confirm|index|home|public|about|status|create_user|new_user|"
                           r"create_account|join|token")


def check_admin_route_no_role(path: str, text: str, ctx: Any) -> List[Hit]:
    if _is_test(path):
        return []
    hits: List[Hit] = []
    if path.endswith(".py"):
        lines = _code_lines(ctx, path)
        if re.search(r"before_(?:app_)?request", text):
            return []
        routes = _py_route_decorators(lines)
        counts: Dict[str, int] = {}
        for _, _, names in routes:
            for n in names:
                if _AUTH_DECO.match(n):
                    counts[n] = counts.get(n, 0) + 1
        for deco, have in counts.items():
            lacking = [r for r in routes if deco not in r[2]]
            if have < 3 or not lacking or len(lacking) > max(1, have // 4):
                continue
            for line, name, names in lacking:
                if _PUBLIC_ROUTE.search(name):
                    continue
                other = sorted(n for n in names if _AUTH_DECO.match(n))
                msg = ("route %s lacks @%s, which the other %d routes in this file use%s" %
                       (name, deco, have, "; it only has @" + other[0] if other else ""))
                hits.append(Hit(line, lines[line - 1].strip(), msg, "medium"))
        return hits
    if not path.endswith(_JS_EXTS) or ctx.is_client_file(path):
        return []
    clean = _blank_comments(text)
    if _ADMIN_PATH.search("/" + path) and (_HTTP_EXPORT.search(clean) or "/pages/api/" in "/" + path):
        if _ROLE_CHECK.search(clean) or _mw_admin_gate(ctx):
            return []
        m = _HTTP_EXPORT.search(clean) or re.search(r"export\s+default\b", clean)
        line, ev = _line_at(ctx, path, m.start() if m else 0)
        who = ("only checks that someone is signed in" if _AUTH_VOCAB.search(clean) else "checks nobody at all")
        hits.append(Hit(line, ev, "admin route %s; any user can call it. Check the caller's role on the server"
                        % who, "high"))
        return hits
    if re.search(r"\b(?:router|app)\s*\.\s*use\s*\([^)]*(?:admin|role|isAdmin|requireAdmin)", clean, re.I):
        return []
    for m in _EXPRESS_ROUTE.finditer(clean):
        args = _balanced(clean, clean.find("(", m.start()) + 1) or ""
        parts = [p.strip() for p in _split_top(args)][1:]
        if not parts:
            continue
        handler, chain = parts[-1], parts[:-1]
        if any(_ROLE_CHECK.search(c) for c in chain):
            continue
        inline = bool(re.match(r"(?:async\s*)?(?:function\b|\()", handler))
        if inline and _ROLE_CHECK.search(handler):
            continue
        line, ev = _line_at(ctx, path, m.start())
        if inline:
            hits.append(Hit(line, ev, "admin route %s has no role check in its middleware or handler" % m.group(3),
                            "high"))
        else:
            hits.append(Hit(line, ev, "admin route %s has no role check in its middleware; confirm %s checks the "
                                      "role" % (m.group(3), handler[:60]), "medium"))
    return hits


_COOKIE_ID = r"(?:user_?id|userid|uid|role|user_?role|is_?admin|admin|user_?type|access_?level|username)"
_COOKIE_TRUST = re.compile(
    r"\$_COOKIE\s*\[\s*['\"]" + _COOKIE_ID + r"['\"]\s*\]"
    r"|\b(?:req|request)\s*\.\s*cookies\s*(?:\.\s*" + _COOKIE_ID + r"\b|\[\s*['\"]" + _COOKIE_ID + r"['\"]\s*\]|"
    r"\.\s*get\s*\(\s*['\"](?:user[-_]?id|uid|role|user[-_]?role|is[-_]?admin|admin|access[-_]?level)['\"])"
    r"|\bcookies\s*\(\s*\)\s*\.\s*get\s*\(\s*['\"](?:user[-_]?id|uid|role|user[-_]?role|is[-_]?admin|admin)['\"]",
    re.I)


def check_cookie_identity(path: str, text: str, ctx: Any) -> List[Hit]:
    if _is_test(path) or (not path.endswith(".php") and ctx.is_client_file(path)):
        return []
    hits = []
    for i, line in enumerate(_code_lines(ctx, path), 1):
        if not line or "cookie" not in line.lower():
            continue
        m = _COOKIE_TRUST.search(line)
        if not m or re.search(r"\bset_?cookie|setcookie|\.set\s*\(|res\.cookie\s*\(|signedCookies", line, re.I):
            continue
        hits.append(Hit(i, line.strip()))
    return hits


_BYPASS_IDENT = r"[\w$.]*?(?:otp|code|pin|passcode|verification_?code|verificationCode|otpCode|smsCode)"
_BYPASS_CMP = re.compile(r"(?i)\b(?P<id>" + _BYPASS_IDENT + r")\s*(?:===|==)\s*(['\"`]?)(?P<lit>\d{4,8})\2(?!\w)")
_BYPASS_PAIR = re.compile(r"(?i)\b[\w$.]*?(?:phone|mobile|email|user(?:name)?|login)\w*\s*(?:===|==)\s*['\"`][^'\"`]{3,}"
                          r"['\"`]")
_BYPASS_GRANT = re.compile(r"(?i)\b\w*(?:approved|verified|valid|authenticated|authorized|ok)\w*\s*=\s*true\b|"
                           r"\bsignIn\w*\s*\(|\bcreateSession\s*\(|\bgenerateLink\s*\(|\bissue\w*Token\s*\(|"
                           r"\blogin_user\s*\(|\blogin\s*\(")


def check_hardcoded_auth_bypass(path: str, text: str, ctx: Any) -> List[Hit]:
    if _is_test(path) or not re.search(r"(?i)otp|verif|login|sign-?in|2fa|mfa|auth", path + "\n" + text[:4000]):
        return []
    if path.endswith(_JS_EXTS) and ctx.is_client_file(path):
        return []
    lines = _code_lines(ctx, path)
    hits = []
    for i, line in enumerate(lines):
        m = _BYPASS_CMP.search(line) if line else None
        if not m or re.search(r"(?i)\b(?:err|error|e|ex|exc|res|response|status|http|result)\w*\s*\??\.\s*code$",
                                  m.group("id")):
            continue
        near = "\n".join(lines[i:i + 4])
        if not (_BYPASS_PAIR.search(line) or _BYPASS_GRANT.search(near)):
            continue
        hits.append(Hit(i + 1, line.strip()))
    return hits


_ADMIN_CLIENT = re.compile(r"\bsupabaseAdmin\b|\bcreateAdminClient\s*\(|\bcreateServiceClient\s*\(|"
                           r"\.auth\s*\.\s*admin\s*\.")
_CLIENT_ARGS = re.compile(r"\bcreateClient\s*(?:<[^>]*>)?\s*\(")
_REQ_READ = re.compile(r"\b(?:req|request|c\.req)\s*\.\s*(?:json|formData|text)\s*\(|\bsearchParams\b|"
                       r"\b(?:req|request)\s*\.\s*(?:body|query|params)\b")
_CALLER_TELL = re.compile(
    r"\.auth\s*\.\s*(?:getUser|getClaims)\s*\(|\bverify\w*\s*\(|\btimingSafeEqual\b|\.constructEvent\w*\s*\(|"
    r"\bCRON_SECRET\b|(?:!==|===|!=|==)\s*(?:`Bearer|['\"]Bearer|Deno\.env\.get|process\.env\.)|"
    r"(?:Deno\.env\.get\([^)]*\)|process\.env\.\w+)\s*(?:!==|===|!=|==)|\b(?:getServerSession|currentUser|"
    r"requireAuth|requireUser|withAuth|getAuth|auth)\s*\(|\bwith(?:Auth|Session|User|Workspace|Admin)\w*\s*\(|"
    r"\bjwtVerify\b|\bsecret\w*\s*(?:!==|===)|(?:!==|===)\s*\w*[Ss]ecret\b|\b\w*Auth\w*Middleware\s*\(|"
    r"\bget(?:Server)?(?:Profile|User|Session|CurrentUser|AuthUser)\s*\(|\b401\b|\bauthorizedIPs\b")


def _uses_admin_client(clean: str) -> bool:
    if _ADMIN_CLIENT.search(clean):
        return True
    for m in _CLIENT_ARGS.finditer(clean):
        args = _balanced(clean, m.end()) or ""
        if re.search(r"SERVICE_ROLE|service_role|SUPABASE_SECRET|SECRET_KEY|sb_secret_", args):
            return True
    return False


_WITH_SUPABASE = re.compile(r"\bwithSupabase\s*(?:<[^>()]*>)?\s*\(\s*")


def _with_supabase_checks_caller(clean: str) -> bool:
    """@supabase/server's withSupabase() rejects a request that lacks the credential its auth mode names:
    'user' (the default, a valid JWT) or 'secret' / 'secret:<name>' (a secret API key). 'publishable' and
    'none' let anyone in, and so does a list that contains them; a mode held in a variable proves nothing."""
    for m in _WITH_SUPABASE.finditer(clean):
        if not clean.startswith("{", m.end()):
            return True  # handler only: auth defaults to 'user'
        opts = _balanced(clean, m.end() + 1, "{", "}")
        if opts is None:
            continue
        k = re.search(r"(?:^|[,{\s])auth\s*:\s*", opts)
        if not k:
            return True  # no auth key: defaults to 'user'
        val = opts[k.end():]
        if val.startswith("["):
            modes = re.findall(r"['\"`]([^'\"`]*)['\"`]", _balanced(val, 1, "[", "]") or "")
        else:
            lm = re.match(r"(['\"`])([^'\"`]*)\1", val)
            modes = [lm.group(2)] if lm else []
        if modes and all(re.match(r"(?:user|secret)(?::|$)", x) for x in modes):
            return True
    return False


def _fn_jwt_off(ctx: Any, name: str) -> bool:
    text = ctx.read("supabase/config.toml")
    m = re.search(r"(?ms)^\s*\[functions\.\"?" + re.escape(name) + r"\"?\]\s*$(.*?)(?=^\s*\[|\Z)", text or "")
    return bool(m and re.search(r"^\s*verify_jwt\s*=\s*false\b", m.group(1), re.M))


def check_service_role_no_caller(path: str, text: str, ctx: Any) -> List[Hit]:
    fn = re.match(r"(?:.*/)?supabase/functions/([^/_][^/]*)/index\.(?:ts|js|mjs)$", path)
    route = bool(re.search(r"(?:^|/)app/(?:.*/)?route\.(?:ts|js|mjs)$|(?:^|/)pages/api/|(?:^|/)src/routes/api/", path))
    if not (fn or route) or _is_test(path):
        return []
    clean = _blank_comments(text)
    if not _uses_admin_client(clean) or not _REQ_READ.search(clean) or _CALLER_TELL.search(clean):
        return []
    if _with_supabase_checks_caller(clean):
        return []
    # payment and webhook callbacks are judged by the payment rules (signature checks); sign-in and
    # OTP functions run before there is a caller to check
    if re.search(r"(?i)webhook|ipn|callback|stripe|paypal|razorpay|cron|otp|login|sign-?in|sign-?up|register|"
                 r"magic-?link|reset-?password|forgot", path):
        return []
    # a Next.js or TanStack route that only reads is left to data-idor-by-id
    if route and not (_DATA_WRITE.search(clean) or re.search(r"\.auth\s*\.\s*admin\s*\.|\.rpc\s*\(", clean)):
        return []
    m = _REQ_READ.search(clean)
    line, ev = _line_at(ctx, path, m.start())
    if fn:
        off = _fn_jwt_off(ctx, fn.group(1))
        msg = ("Edge Function uses the service role key and acts on request input without checking the caller; %s"
               % ("config.toml sets verify_jwt = false, so anyone on the internet can call it" if off else
                  "verify_jwt only proves the request carries a valid JWT, and the public anon key is one"))
        msg += ". Check the caller with getUser() or getClaims(), or compare a shared secret"
        return [Hit(line, ev, msg, "critical" if off else "high")]
    return [Hit(line, ev, "route uses the service role key and acts on request input without checking the caller; "
                          "verify the user (getUser(), getClaims()) or a shared secret before touching data", "high")]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

_SB_REF = "stack-supabase.md"
_FB_REF = "stack-firebase.md"
_DA_REF = "data-and-auth.md"

RULES: List[Rule] = [
    Rule(
        id="data-supabase-rls-disabled",
        skill=SKILL, klass="Supabase table without RLS", severity="critical",
        stacks=["supabase"], file_globs=["*.sql"], check=check_rls_disabled,
        message="Supabase table in an exposed schema never gets RLS enabled",
        why=("The query works from the browser without any policy, so the agent never writes one. Tables made "
             "with raw SQL migrations do not get RLS automatically, and the anon key ships in the bundle."),
        fp_trap=("Tables in a schema that is not exposed (private, extensions), tables whose grants to anon and "
                 "authenticated are revoked, and RLS turned on by a DO block or event trigger are fine. RLS "
                 "switched on in the dashboard but never written to a migration also shows here: confirm with "
                 "the Security Advisor or supabase db advisors (CLI 2.81 or newer) before reporting; "
                 "supabase db lint only runs plpgsql_check and says nothing about RLS."),
        fix_ref=_SB_REF + "#enable-rls-and-owner-policies", confidence="high", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-policy-allows-all",
        skill=SKILL, klass="Supabase policy open to everyone", severity="high",
        stacks=["supabase"], file_globs=["*.sql"], check=check_permissive_policy,
        message="RLS policy uses true (or only 'is signed in') where it should check the row owner",
        why=("USING (true) is the fastest way to stop a query from returning nothing, and the dashboard "
             "templates offer it. It turns RLS back off for that command."),
        fp_trap=("A read policy USING (true) on a genuinely public table (catalog, published posts) with no "
                 "write policy and no private columns is fine, and is only reported when the table name or its "
                 "columns look private. An insert-only policy on a public form table with no owner column is "
                 "fine. Restrictive policies are ignored. A schema that shares every table among signed-in "
                 "users (a one-team CRM) is reported once per file; it is fine when public sign-ups are off."),
        fix_ref=_SB_REF + "#permissive-policies", confidence="high", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-own-row-privileged",
        skill=SKILL, klass="user can edit own privilege column", severity="high",
        stacks=["supabase"], file_globs=["*.sql"], check=check_own_row_privileged,
        message="own-row insert or update policy on a table with a role, plan, credits or verified column",
        why=("auth.uid() = id looks like a complete policy, but RLS works on rows, not columns: the owner can "
             "change every column of their row, including role, is_verified, plan or credits."),
        fp_trap=("Fine when a column grant (grant update (name, bio) ...) leaves the privileged column out, "
                 "when update is revoked from authenticated, or when a BEFORE INSERT or UPDATE trigger on the "
                 "table resets or rejects that column. Confirm the column really grants something."),
        fix_ref=_SB_REF + "#permissive-policies", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-seeded-auth-users",
        skill=SKILL, klass="demo accounts in a migration", severity="medium",
        stacks=["supabase"], file_globs=["*.sql"], check=check_seeded_auth_users,
        message="migration inserts accounts into auth.users, so they exist in production too",
        why=("To make a demo work the agent inserts users with a known password and email_confirmed_at = now() "
             "into a migration, and migrations run against the production database."),
        fp_trap=("supabase/seed.sql and other seed files only run locally and are not reported. An insert that "
                 "creates a service account with a random password the team rotates is rarer but fine."),
        fix_ref=_SB_REF + "#edge-functions-and-seed-accounts", confidence="high", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-admin-by-email",
        skill=SKILL, klass="admin decided by a fixed email", severity="medium",
        stacks=["supabase"], file_globs=["*.sql"], check=check_admin_by_email,
        message="policy or definer function grants access by comparing the JWT email to a fixed address",
        why=("A bootstrap admin is the owner's email written into a policy. With email confirmation off, or "
             "before the owner signs up, anyone can register that address and get the admin rights."),
        fp_trap=("Safe only while email confirmation is on and the owner already holds the account; a roles "
                 "table or app_metadata claim is the durable fix."),
        fix_ref=_SB_REF + "#user-metadata-in-policies", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-user-metadata-authz",
        skill=SKILL, klass="access decided by user_metadata", severity="high",
        stacks=["supabase"], file_globs=["*.sql"] + _WEB_GLOBS + ["*.py"], exclude_globs=_TEST_GLOBS,
        check=check_user_metadata,
        message="role or plan read from user_metadata, which the user can edit",
        why=("Sign-up code passes a role in options.data, and the agent reads it back for access checks "
             "without knowing that every user can rewrite user_metadata with updateUser()."),
        fp_trap=("Copying display fields such as full_name or avatar_url from raw_user_meta_data in a sign-up "
                 "trigger is fine and is not reported. app_metadata (raw_app_meta_data) is server-only and is "
                 "the right place for roles. Only the last definition of a function counts; one-time backfill "
                 "statements are reported as low."),
        fix_ref=_SB_REF + "#user-metadata-in-policies", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-definer-search-path",
        skill=SKILL, klass="security definer without search_path", severity="medium",
        stacks=["supabase"], file_globs=["*.sql"], check=check_definer_search_path,
        message="security definer function without a fixed search_path",
        why=("Agents copy security definer to get past an RLS error and leave out set search_path, so the "
             "function resolves unqualified names through a path the caller can influence."),
        fp_trap=("A later ALTER FUNCTION ... SET search_path fixes it and is taken into account. Functions "
                 "with set search_path = '' (or a fixed list, quoted or not as pg_dump writes it) are fine."),
        fix_ref=_SB_REF + "#security-definer-functions", confidence="high", needs_confirmation=False,
    ),
    Rule(
        id="data-supabase-definer-exposed",
        skill=SKILL, klass="RLS-bypassing RPC", severity="medium",
        stacks=["supabase"], file_globs=["*.sql"], check=check_definer_exposed,
        message="security definer function in an exposed schema that never checks the caller",
        why=("A security definer function runs as its owner and ignores RLS. In the public schema it is "
             "callable by anon and authenticated through /rest/v1/rpc."),
        fp_trap=("Trigger functions, functions that check auth.uid() or auth.jwt() (directly or through a "
                 "guard helper such as IF NOT is_admin() THEN RAISE), functions in a private schema and "
                 "functions whose EXECUTE was revoked from public, anon and authenticated are not reported. "
                 "PUBLIC holds EXECUTE by default, so a revoke from anon alone or a grant to service_role "
                 "changes nothing. Read-only helpers that return a flag or an id are grouped as low; a "
                 "function granted to anon on purpose for a public form is low but still needs input limits."),
        fix_ref=_SB_REF + "#security-definer-functions", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-view-bypasses-rls",
        skill=SKILL, klass="view bypassing RLS", severity="high",
        stacks=["supabase"], file_globs=["*.sql"], check=check_view_rls,
        message="view in an exposed schema runs with its owner's rights and skips RLS",
        why=("Agents add a convenience view that joins several tables. Created by postgres, it ignores the "
             "callers' RLS and leaks rows the base-table policies block."),
        fp_trap=("Views created WITH (security_invoker = true) or later altered to it are fine, as are views "
                 "whose select grant is revoked from anon and authenticated, views over data that is public "
                 "anyway, and views that select only aggregates (count, exists) and no row data."),
        fix_ref=_SB_REF + "#views-and-rls", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-service-key-client",
        skill=SKILL, klass="service role key in client code", severity="high",
        stacks=["supabase"], file_globs=[], once=True, check=check_service_key_client,
        message="Supabase service role or secret key referenced in client code; the admin client must stay on the server",
        why=("When a query fails under RLS, swapping in the service role key makes it work, so agents create "
             "an admin client next to the browser client, often in a module the browser code imports."),
        fp_trap=("The service key in Edge Functions, API routes, Server Actions or files with import "
                 "'server-only' is correct and is not reported. A non-public env var reads as undefined in the "
                 "browser, so the key is one prefix away from leaking rather than leaked: confirm whether the "
                 "bundler inlines it. Literal keys are reported by find_secrets.py and public-prefixed names by "
                 "secret-public-env-prefix, both as critical. The bare 'sb_secret_' prefix in a key-type "
                 "check (Lovable's generated client) names no key and is ignored."),
        fix_ref=_SB_REF + "#service-role-key", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-supabase-getsession-server",
        skill=SKILL, klass="unverified session on the server", severity="medium",
        stacks=["supabase"], file_globs=_JS_GLOBS + ["*.svelte"], exclude_globs=_TEST_GLOBS,
        check=check_getsession_server,
        message="server code trusts supabase.auth.getSession(), which reads the cookie without verifying it",
        why=("getSession() is the call agents remember from client code; on the server it returns whatever the "
             "cookie says without checking the JWT."),
        fp_trap=("getSession() in browser code is fine, including TanStack Router route files "
                 "(createFileRoute). A file that also calls getUser() or getClaims() to verify the user (the "
                 "SvelteKit safeGetSession pattern) is not reported. A middleware that calls getSession() only "
                 "to refresh the cookie is reported as low."),
        fix_ref=_SB_REF + "#getclaims-over-getsession", confidence="high", needs_confirmation=True,
    ),
    Rule(
        id="data-firebase-rules-open",
        skill=SKILL, klass="open Firebase rules", severity="critical",
        stacks=["firebase"], file_globs=["*.rules", "*.rules.json"], check=check_firebase_open,
        message="Firebase rule lets anyone, logged out, read or write this data",
        why=("allow read, write: if true is the rule that makes the first write succeed, and tutorials ship "
             "it. Firebase clients talk straight to the database, so the rules are the only gate."),
        fp_trap=("allow read: if true on a collection that is public by design (leaderboard, published posts) "
                 "with restricted writes is fine and is only reported when the path looks private. The "
                 "firebaseConfig apiKey in client code is not a secret and is never the bug."),
        fix_ref=_FB_REF + "#owner-only-rules", confidence="high", needs_confirmation=True,
    ),
    Rule(
        id="data-firebase-test-mode",
        skill=SKILL, klass="Firebase test-mode rules", severity="critical",
        stacks=["firebase"], file_globs=["*.rules", "*.rules.json"], check=check_firebase_test_mode,
        message="Firebase test-mode rule: everyone can read and write until a date",
        why=("The console's test mode writes request.time < timestamp.date(...) and the project ships with it. "
             "Until the date everything is open; after it, everything breaks."),
        fp_trap="None in production. In a local emulator-only rules file it is harmless; check firebase.json.",
        fix_ref=_FB_REF + "#test-mode-rules", confidence="high", needs_confirmation=False,
    ),
    Rule(
        id="data-firebase-any-auth",
        skill=SKILL, klass="any signed-in user allowed", severity="high",
        stacks=["firebase"], file_globs=["*.rules", "*.rules.json"], check=check_firebase_any_auth,
        message="rule only checks request.auth != null, so any signed-in user reaches every user's data",
        why=("request.auth != null looks secure, but anyone can sign up (or sign in anonymously) and then read "
             "or change every other user's documents."),
        fp_trap=("Data that is genuinely shared by all signed-in users (a team workspace where every member is "
                 "trusted) is fine. Create-only rules and reads of non-private paths are not reported. An OR is "
                 "as open as its most open branch: isAdmin() || isSignedIn() counts as any signed-in user."),
        fix_ref=_FB_REF + "#any-signed-in-user", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-firebase-role-field",
        skill=SKILL, klass="role in a user-writable document", severity="high",
        stacks=["firebase"], file_globs=["*.rules"], check=check_firebase_role_field,
        message="rules read a role from a document its owner can write",
        why=("Agents store role or isAdmin on users/{uid} and let the owner edit their own document, so the "
             "role check reads a value the user controls."),
        fp_trap=("Fine when the write rule blocks the role field (affectedKeys().hasOnly([...]), "
                 "diff(...)) or only the Admin SDK writes the document. Custom claims "
                 "(request.auth.token.admin) are the right fix. A fixed admin email is fine only together with "
                 "request.auth.token.email_verified == true."),
        fix_ref=_FB_REF + "#roles-with-custom-claims", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-nextjs-middleware-cve",
        skill=SKILL, klass="Next.js middleware bypass (CVE-2025-29927)", severity="critical",
        stacks=["nextjs"], file_globs=[], once=True, check=check_next_cve,
        message="Next.js version lets a request header skip middleware (CVE-2025-29927)",
        why=("Agents pin the Next.js version they were trained on and put auth in middleware; self-hosted "
             "apps on 11.1.4 to 15.2.2 can be bypassed with one header."),
        fp_trap=("Apps hosted on Vercel were shielded at the edge, but should still upgrade. A caret range with "
                 "no lockfile installs a release past this CVE, but on 12, 13 and 14 it still installs versions "
                 "with later critical advisories; the version reported is the lockfile or node_modules version "
                 "when one exists. A middleware that only refreshes a session cookie is reported as medium. "
                 "Never recommend the CVE patch floor itself (12.3.5, 13.5.9, 14.2.25, 15.2.3) as the target."),
        fix_ref=_DA_REF + "#cve-2025-29927", confidence="high", needs_confirmation=True,
    ),
    Rule(
        id="data-nextjs-middleware-only-auth",
        skill=SKILL, klass="middleware as the only gate", severity="medium",
        stacks=["nextjs"], file_globs=_ROUTE_GLOBS, exclude_globs=_TEST_GLOBS, check=check_middleware_only_auth,
        message="route writes data with no auth check of its own; only middleware or proxy guards it",
        why=("Agents put the auth gate in one convenient place and assume everything behind it is covered. "
             "Matchers often skip /api, and middleware is meant for optimistic checks only."),
        fp_trap=("Routes that are public on purpose, webhook and auth callback routes, and routes that query "
                 "Supabase with the user's session (RLS still applies) are not reported. Confirm the matcher "
                 "and whether the route is meant to be public."),
        fix_ref=_DA_REF + "#middleware-and-proxy", confidence="low", needs_confirmation=True,
    ),
    Rule(
        id="data-idor-by-id",
        skill=SKILL, klass="IDOR / missing ownership check", severity="high",
        stacks=["node", "python", "php"], file_globs=_JS_GLOBS + ["*.py", "*.php"],
        exclude_globs=_TEST_GLOBS + ["**/migrations/**", "**/seed*/**", "seed.*", "**/scripts/**"],
        check=check_idor,
        message="record looked up by an id from the request with no ownership check nearby",
        why=("The agent checks that someone is logged in, then fetches by the id from the URL or body and "
             "stops. In a one-user demo both versions return the same data."),
        fp_trap=("A by-id query followed by an owner check (row.userId !== session.user.id), a where clause "
                 "or earlier scoped lookup that includes the owner (projectId: workspace.id), admin-only "
                 "wrappers and procedures (withAdmin, adminProcedure), signed cron, queue and webhook "
                 "handlers, public resources, tenant-scoped clients, Laravel models whose route binding is "
                 "scoped to the user, and DRF views with get_queryset are fine. Supabase queries through a "
                 "client built from the anon key and the caller's token are covered by RLS. A filter on "
                 "user_id taken from the request is reported too."),
        fix_ref=_DA_REF + "#ownership-checks", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-admin-route-no-role",
        skill=SKILL, klass="admin route without a role check", severity="high",
        stacks=["node", "python"], file_globs=_JS_GLOBS + ["*.py"],
        exclude_globs=_TEST_GLOBS + ["**/migrations/**"], check=check_admin_route_no_role,
        message="admin route or endpoint with no server-side role check",
        why=("The admin screen is hidden in the UI, so the agent stops at 'is logged in' (or at nothing) on the "
             "API route behind it, and one decorator gets left off when a route is added later."),
        fp_trap=("A middleware or proxy that checks the role for /admin paths, a role check inside a handler "
                 "defined in another module, and a blueprint-wide before_request check are fine; confirm before "
                 "reporting. For a route missing a decorator its siblings use, check whether it is public on purpose."),
        fix_ref=_DA_REF + "#client-side-checks", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-cookie-identity",
        skill=SKILL, klass="identity from an unsigned cookie", severity="high",
        stacks=["*"], file_globs=_JS_GLOBS + ["*.py", "*.php"], exclude_globs=_TEST_GLOBS,
        check=check_cookie_identity,
        message="server reads the user id or role from a plain cookie the client can edit",
        why=("Setting a user_id or role cookie at login is the shortest way to remember who is signed in, and "
             "nothing in the demo shows that the browser can rewrite it."),
        fp_trap=("A signed or encrypted cookie (Express signedCookies, a signed session, a verified JWT) is fine; "
                 "a cookie used only to pick a UI default is harmless. Confirm what the value decides."),
        fix_ref=_DA_REF + "#sessions-and-jwts", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-hardcoded-auth-bypass",
        skill=SKILL, klass="hardcoded login or OTP bypass", severity="high",
        stacks=["*"], file_globs=_JS_GLOBS + ["*.py", "*.php"], exclude_globs=_TEST_GLOBS,
        check=check_hardcoded_auth_bypass,
        message="login or OTP check accepts a fixed code written in the server code",
        why=("A demo or app-store reviewer account needs to get past SMS or email codes, so the agent adds "
             "if (phone === '...' && code === '123456') and it ships to production."),
        fp_trap=("A bypass behind an env flag that is off in production, or a provider's published test number, "
                 "is fine. Error-code comparisons (error.code === '23505') are not reported."),
        fix_ref=_DA_REF + "#sessions-and-jwts", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-service-role-no-caller-check",
        skill=SKILL, klass="service-role function with no caller check", severity="high",
        stacks=["supabase"], file_globs=_JS_GLOBS, exclude_globs=_TEST_GLOBS, check=check_service_role_no_caller,
        message="Edge Function or route uses the service role key on request input without checking the caller",
        why=("verify_jwt is on by default and looks like auth, but the public anon key is itself a valid JWT. "
             "With the service role client every query skips RLS, so the function is the only gate."),
        fp_trap=("Functions that call getUser() or getClaims(), compare a shared secret or verify a webhook "
                 "signature are not reported, nor are handlers wrapped in @supabase/server withSupabase() with "
                 "auth 'user' (the default) or 'secret'; 'publishable' or 'none' lets anyone in and is still "
                 "reported. A deliberately public endpoint (contact form) still needs input "
                 "limits and rate limiting; confirm what it can change."),
        fix_ref=_SB_REF + "#edge-functions-and-seed-accounts", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-client-role-flag",
        skill=SKILL, klass="client-side role check", severity="high",
        stacks=["*"], file_globs=_WEB_GLOBS, exclude_globs=_TEST_GLOBS, client_only=True,
        pattern=_CLIENT_ROLE_FLAG,
        message="role or login flag read from browser storage; anyone can flip it in devtools",
        why=("The UI is the only surface the agent can see, so it gates admin screens on a localStorage flag "
             "and never adds the same check on the server."),
        fp_trap=("Fine as a UI hint when the server or RLS enforces the same rule independently. Confirm the "
                 "API routes, Server Actions or tables behind the screen check the role server-side."),
        fix_ref=_DA_REF + "#client-side-checks", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-client-password-check",
        skill=SKILL, klass="password checked in the browser", severity="critical",
        stacks=["*"], file_globs=_WEB_GLOBS + ["*.html", "*.htm"], exclude_globs=_TEST_GLOBS,
        check=check_client_password,
        message="password or PIN compared to a value shipped in client code",
        why=("A quick admin gate is a string compare in the component, sometimes against a VITE_ or "
             "NEXT_PUBLIC_ variable, and both end up in the JavaScript bundle."),
        fp_trap=("Comparisons of input types or state names ('password', 'text', 'strong') are ignored, as are "
                 "feature flags (VITE_DISABLE_PASSWORD_LOGIN === 'true'). A check that only toggles UI while a "
                 "server verifies the password is fine; a test fixture is not shipped code."),
        fix_ref=_DA_REF + "#client-side-checks", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-mass-assignment",
        skill=SKILL, klass="mass assignment", severity="high",
        stacks=["node", "python", "php"], file_globs=_JS_GLOBS + ["*.py", "*.php"],
        exclude_globs=_TEST_GLOBS + ["**/migrations/**", "**/seed*/**", "seed.*"],
        check=check_mass_assignment,
        message="request data written into a create or update without an allow-list (whole body, or a role field)",
        why=("Spreading the body is the shortest code that makes the form work, and the TypeScript type or "
             "the UI looks like a whitelist, but neither is enforced at runtime."),
        fp_trap=("A body built from an explicit allow-list ({ title, content }), a value parsed by a schema "
                 "that strips unknown keys, Laravel models with a safe $fillable (or the default guarded "
                 "model) and Pydantic input models without privileged fields are fine. A role or plan field "
                 "from the request is fine behind a server-side admin check; a chat message's role and a job "
                 "title are not privileges."),
        fix_ref=_DA_REF + "#mass-assignment", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-serializer-all-fields",
        skill=SKILL, klass="writable __all__ serializer", severity="medium",
        stacks=["django"], file_globs=["*.py"], exclude_globs=_TEST_GLOBS + ["**/migrations/**"],
        check=check_serializer_all,
        message="ModelSerializer or ModelForm with fields = '__all__' lets clients write every column",
        why="fields = '__all__' is the shortest Meta block, and it exposes role, owner and price columns too.",
        fp_trap=("A serializer used only for output, or one whose sensitive columns are all in "
                 "read_only_fields, is safe today but fragile: new columns become writable. Reported as low "
                 "when read_only_fields is present. A User form or serializer with exclude = [...] is reported "
                 "when is_superuser or is_staff stays writable."),
        fix_ref=_DA_REF + "#mass-assignment", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-weak-password-hash",
        skill=SKILL, klass="fast password hash", severity="high",
        stacks=["*"], file_globs=_JS_GLOBS + ["*.py", "*.php"], exclude_globs=_TEST_GLOBS,
        check=check_weak_password_hash,
        message="password hashed with MD5 or SHA instead of a password hash",
        why="Hand-rolled sign-up code reaches for the hash function it knows, not a slow password hash.",
        fp_trap=("Hashing a reset token or an API key with SHA-256 is fine. SHA-1 of a password for a "
                 "haveibeenpwned range check is fine and skipped. PBKDF2, bcrypt, scrypt and argon2 are not "
                 "matched; neither is a fingerprint of the stored hash or a pre-hash fed straight into bcrypt. "
                 "A fast PASSWORD_HASHERS entry inside test settings is fine."),
        fix_ref=_DA_REF + "#password-hashing", confidence="medium", needs_confirmation=True,
    ),
    Rule(
        id="data-jwt-not-verified",
        skill=SKILL, klass="JWT decoded but not verified", severity="high",
        stacks=["*"], file_globs=_JS_GLOBS + ["*.py"], exclude_globs=_TEST_GLOBS,
        check=check_jwt_not_verified,
        message="server reads JWT claims without verifying the signature",
        why=("decode() returns the claims and looks like it works, so agents use it in middleware and API "
             "routes instead of verify()."),
        fp_trap=("Decoding in browser code to read exp for the UI is fine. Peeking at the header before a real "
                 "verify call in the same file is not reported. An OIDC id_token taken straight from the "
                 "provider's token endpoint over TLS may skip the signature (OIDC Core 3.1.3.7) and is low."),
        fix_ref=_DA_REF + "#sessions-and-jwts", confidence="medium", needs_confirmation=True,
    ),
]
