"""Check what an app exposes on its own running URL (read-only).

Usage:
  python3 check_live.py [--json] [--output FILE] [--i-own-this HOST] [--timeout S]
                        [--max-findings N] [--checks LIST] URL

Always-on checks: bundle, files, maps, headers, cookies, cors, debug.
Opt-in checks (each needs its own flag and only runs against your own app; the
flag adds its check even when --checks names other checks):
  --webhook-path PATH            forge one unsigned POST to a Stripe webhook route
  --ratelimit-path PATH [--n N] [--ratelimit-body JSON] [--auth-bearer-env VAR]
                                 send a modest burst to a metered endpoint
  --supabase-url URL --anon-key KEY [--baas-table T]   logged-out Supabase read
  --firebase-project ID [--rtdb-url URL] [--baas-collection C]
                                 logged-out Firestore / Realtime Database read
                                 (without --rtdb-url: the databaseURL the bundle
                                 check finds in firebaseConfig, else the default)
An opt-in probe that gets no clear answer (route not found, server error,
rejected key, unreachable host) is reported as inconclusive, never as passed.
Paths may be written with or without the leading slash; a Git Bash rewritten
path (C:/Program Files/Git/api/x) is turned back into /api/x.

Safety:
  The URL must be an app you own. localhost / 127.0.0.1 / [::1] / *.localhost /
  *.test run without asking; any other host needs --i-own-this HOST matching the
  URL. Every request is read-only (GET / HEAD / OPTIONS, plus the opt-in webhook
  and rate-limit probes to your own endpoint). Secret values are masked and no
  discovered key is ever sent anywhere.

Exit codes: 0 nothing found, 1 findings, 2 usage or runtime error, or a
requested opt-in probe gave no answer and nothing else was found, 3 refused
(the URL, --supabase-url or --rtdb-url is not a host you own / confirmed).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urljoin, urlsplit

import urllib.error
import urllib.request

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import _secret_patterns as sp  # noqa: E402
import _wardcore as wc  # noqa: E402
import find_secrets as fs  # noqa: E402

SCRIPT = "check_live"
SKILL = "live-exposure"
USER_AGENT = "ward-live-check"

ALWAYS_CHECKS = ["bundle", "files", "maps", "headers", "cookies", "cors", "debug"]
OPT_IN_CHECKS = ["webhook", "ratelimit", "baas"]

# Hard caps so a check can never turn into a flood.
MAX_JS = 30               # same-origin scripts fetched for the bundle check
MAX_RATELIMIT = 120       # upper bound on --n no matter what the user passes
DEFAULT_RATELIMIT = 60
BASE_BUDGET = 80          # requests allowed before the rate-limit burst
MAX_BODY = 3 * 1024 * 1024
CORS_PROBE_ORIGIN = "https://ward-cors-probe.example"

# Files worth probing. Content, not status code, decides if one is exposed.
PROBE_FILES = [
    (".env", "critical"), (".env.local", "critical"), (".env.production", "critical"),
    (".env.development", "high"), (".env.backup", "critical"),
    (".git/HEAD", "critical"), (".git/config", "critical"),
    ("backup.zip", "high"), ("backup.sql", "high"), ("dump.sql", "high"),
    ("db.sqlite", "high"), ("database.sqlite", "high"), ("db.sqlite3", "high"),
    ("docker-compose.yml", "high"), (".npmrc", "high"), (".DS_Store", "low"),
    ("config.php.bak", "high"), ("wp-config.php.bak", "critical"),
]

SECURITY_HEADERS = [
    ("content-security-policy", "medium", "Content-Security-Policy"),
    ("strict-transport-security", "medium", "Strict-Transport-Security (HSTS)"),
    ("x-content-type-options", "medium", "X-Content-Type-Options: nosniff"),
    ("referrer-policy", "low", "Referrer-Policy"),
    ("x-frame-options", "low", "X-Frame-Options"),
    ("permissions-policy", "low", "Permissions-Policy"),
]


# ---------------------------------------------------------------------------
# Host gate (re-exported for callers and tests)
# ---------------------------------------------------------------------------

def check_host(url: str, allow_flag: Any = None) -> Tuple[str, bool]:
    """Return (host, ok). ok is True only for a host the user owns. See
    _wardcore.require_owned_host. The caller exits with EXIT_REFUSED when ok
    is False; this runs before any network request."""
    return wc.require_owned_host(url, allow_flag)


def _normalize_url(url: str) -> str:
    raw = (url or "").strip()
    if "://" not in raw:
        raw = "http://" + raw
    return raw


# Git Bash (MSYS) rewrites an argument like /api/chat into C:/Program Files/Git/api/chat
# before Python sees it. A URL path can never be a drive path, so undo that.
_MSYS_ROOT = re.compile(r"^[A-Za-z]:[/\\](?:.*?[/\\])?(?:Git|msys64|msys32|msys2|cygwin64|cygwin)[/\\](.*)$", re.I)


def clean_url_path(value: Optional[str], flag: str) -> Tuple[Optional[str], Optional[str]]:
    """Normalize a --*-path argument. Returns (path, error). Accepts 'api/chat'
    and '/api/chat'; recovers '/api/chat' from a Git Bash rewritten
    'C:/Program Files/Git/api/chat'; refuses any other drive path."""
    if value is None:
        return None, None
    v = value.strip()
    if not v:
        return None, "%s is empty" % flag
    if re.match(r"^[A-Za-z]:[/\\]", v):
        m = _MSYS_ROOT.match(v)
        if not m:
            return None, ("%s looks like a Windows file path (%s), not a URL path. In Git Bash, write it "
                          "without the leading slash (api/chat) or run with MSYS_NO_PATHCONV=1" % (flag, v))
        v = m.group(1)
    if "://" in v:
        return None, "%s must be a path on the app (like /api/chat), not a full URL" % flag
    v = v.replace("\\", "/")
    return ("/" + v.lstrip("/")), None


# ---------------------------------------------------------------------------
# Tiny read-only HTTP client
# ---------------------------------------------------------------------------

class BudgetError(Exception):
    """Raised when a scan would exceed its request budget."""


class Response:
    def __init__(self, status: int, headers: Any, body: bytes, final_url: str) -> None:
        self.status = status
        self.headers = headers
        self.body = body
        self.final_url = final_url

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str) -> Optional[str]:
        return self.headers.get(name) if self.headers is not None else None

    def set_cookies(self) -> List[str]:
        if self.headers is None:
            return []
        getter = getattr(self.headers, "get_all", None)
        if getter is not None:
            return [c for c in (getter("Set-Cookie") or []) if c]
        one = self.headers.get("Set-Cookie")
        return [one] if one else []


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        return None


class Client:
    """Makes a bounded number of read-only requests with a timeout and a polite
    User-Agent. Does not verify TLS, because self-signed staging certificates are
    normal; this tool only reads, never sends credentials."""

    def __init__(self, timeout: float = 10.0, budget: int = BASE_BUDGET) -> None:
        self.timeout = timeout
        self.budget = budget
        self.used = 0
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self._ctx = ctx
        self._follow = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
        self._noredir = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ctx))

    def request(self, url: str, method: str = "GET", data: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None, follow: bool = True) -> Response:
        if self.used >= self.budget:
            raise BudgetError("request budget of %d reached" % self.budget)
        self.used += 1
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        opener = self._follow if follow else self._noredir
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                body = resp.read(MAX_BODY)
                return Response(getattr(resp, "status", 0) or resp.getcode() or 0,
                                resp.headers, body, resp.geturl())
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read(MAX_BODY)
            except Exception:
                pass
            return Response(exc.code, exc.headers, body, url)


def _is_html(body: bytes) -> bool:
    head = body[:600].lstrip().lower()
    return head.startswith(b"<!doctype") or head.startswith(b"<html") or b"<head" in head[:200]


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def _finding(rule: str, severity: str, message: str, *, klass: str, evidence: str = "",
             confidence: str = "high", needs_confirmation: bool = False,
             fix_ref: str = "", file: str = "", extra: Optional[Dict[str, Any]] = None) -> wc.Finding:
    return wc.Finding(
        skill=SKILL, klass=klass, severity=severity, file=file, line=0, rule=rule,
        message=message, evidence=evidence, fix_ref=fix_ref or "interpreting.md",
        confidence=confidence, needs_confirmation=needs_confirmation, extra=extra or {})


_SCRIPT_SRC = re.compile(r"""<script[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_BUNDLE_PATHS = re.compile(r"""(?:/_next/static/|/assets/|/static/js/|/_app/immutable/)[^"'\s<>()]+?\.m?js""")


def _collect_scripts(page_url: str, html: str) -> List[str]:
    base_host = urlsplit(page_url).netloc
    seen: List[str] = []
    out: List[str] = []

    def add(ref: str) -> None:
        if not ref or ref.startswith(("data:", "blob:")):
            return
        absu = urljoin(page_url, ref)
        parts = urlsplit(absu)
        if parts.scheme not in ("http", "https"):
            return
        if parts.netloc and parts.netloc != base_host:
            return
        clean = absu.split("#", 1)[0]
        if clean in seen:
            return
        seen.append(clean)
        out.append(clean)

    for m in _SCRIPT_SRC.finditer(html):
        if m.group(1).split("?", 1)[0].lower().endswith((".js", ".mjs")):
            add(m.group(1))
    for m in _BUNDLE_PATHS.finditer(html):
        add(m.group(0))
    return out[:MAX_JS]


def check_bundle(client: Client, base_url: str, meta: Dict[str, Any]) -> List[wc.Finding]:
    """Fetch the page and its same-origin scripts, then look for secrets and
    inline data blobs. Public-by-design keys (anon JWT, Stripe pk_) are counted,
    not reported."""
    out: List[wc.Finding] = []
    try:
        page = client.request(base_url)
    except (urllib.error.URLError, BudgetError, OSError) as exc:
        meta.setdefault("warnings", []).append("bundle: could not fetch the page: %s" % exc)
        return out
    html = page.text()
    sources = [("page", base_url, html)]
    scripts = _collect_scripts(page.final_url or base_url, html)
    meta["scripts_found"] = len(scripts)
    for js_url in scripts:
        try:
            r = client.request(js_url)
        except (urllib.error.URLError, BudgetError, OSError):
            continue
        if r.status == 200 and not _is_html(r.body):
            sources.append(("js", js_url, r.text()))
    meta["bundle_js"] = [u for _k, u, _t in sources if _k == "js"]

    for _kind, _url, text in sources:
        db_url = firebase_database_url(text)
        if db_url:
            meta["firebase_database_url"] = db_url
            break

    public: Dict[str, int] = {}
    for _kind, url, text in sources:
        rel = urlsplit(url).path or url
        findings, pubs = fs.scan_text(text, rel, "bundle")
        for name, _line in pubs:
            public[name] = public.get(name, 0) + 1
        for f in findings:
            if f.severity == "info":
                f.message += " in the served page/bundle. Confirm whether the key is restricted"
            else:
                f.message += " in the shipped JavaScript bundle (public to anyone who loads the page)"
            f.needs_confirmation = f.severity == "info"
            out.append(f)
    if public:
        meta["public_keys_in_bundle"] = dict(sorted(public.items()))
    return out


def check_files(client: Client, base_url: str, meta: Dict[str, Any]) -> List[wc.Finding]:
    """Probe for sensitive files served over HTTP. Decided by content, so an SPA
    that answers 200 with index.html for every path is not a false positive."""
    out: List[wc.Finding] = []
    for rel, severity in PROBE_FILES:
        url = urljoin(base_url.rstrip("/") + "/", rel)
        try:
            r = client.request(url, follow=False)
        except (urllib.error.URLError, BudgetError, OSError):
            continue
        if r.status not in (200, 206):
            continue
        body = r.body
        if not body or _is_html(body):
            continue
        text = r.text()
        if not _file_looks_exposed(rel, text):
            continue
        secrets, _pub = fs.scan_text(text, rel, "exposed-file")
        kinds = sorted({s.rule for s in secrets if s.severity != "info"})
        detail = ("; leaks " + ", ".join(kinds)) if kinds else ""
        out.append(_finding(
            "exposed-file", severity, "%s is downloadable over HTTP%s" % (rel, detail),
            klass="exposed file", evidence=describe_exposed(rel, text, len(body)),
            fix_ref="interpreting.md#files", needs_confirmation=False,
            extra={"path": "/" + rel}))
    return out


_KEY_LINE = re.compile(r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]")
_NPMRC_KEY = re.compile(r"(?m)^\s*([^=\s#;]+)\s*=")
_SQL_STMT = re.compile(r"(?i)\b(create table|insert into|drop table|alter table|copy)\b")


def describe_exposed(rel: str, text: str, size: int) -> str:
    """Evidence for an exposed file that never contains a value: key names for
    env / YAML / .npmrc / ini style files, section names for git config,
    statement counts for SQL dumps, and only size for anything else."""
    name = rel.rsplit("/", 1)[-1]
    if rel.endswith(".git/HEAD"):
        ref = text.strip().split("\n", 1)[0]
        return "git HEAD: %s" % (ref if ref.startswith("ref: refs/") and len(ref) < 120 else "(a commit id)")
    if rel.endswith(".git/config"):
        sections = sorted(set(re.findall(r"(?m)^\s*\[([A-Za-z]+)", text)))
        return "git config sections: %s (values hidden)" % (", ".join(sections[:10]) or "none")
    if name.endswith((".sql", ".dump")):
        counts: Dict[str, int] = {}
        for m in _SQL_STMT.finditer(text):
            k = m.group(1).upper()
            counts[k] = counts.get(k, 0) + 1
        summary = ", ".join("%d %s" % (n, k) for k, n in sorted(counts.items()))
        return "SQL dump, %d bytes: %s (contents hidden)" % (size, summary or "no statements seen")
    if (name.startswith(".env") or name.endswith(".env") or name == ".npmrc"
            or name.endswith((".yml", ".yaml", ".bak", ".ini", ".cfg"))):
        keys: List[str] = []
        rx = _NPMRC_KEY if name == ".npmrc" else _KEY_LINE
        for m in rx.finditer(text):
            k = m.group(1)
            if k not in keys:
                keys.append(k)
        if keys:
            more = " and %d more" % (len(keys) - 15) if len(keys) > 15 else ""
            return "keys: %s%s (values hidden)" % (", ".join(keys[:15]), more)
        return "%d bytes (contents hidden)" % size
    return "%d bytes, not an HTML page (contents hidden)" % size


def _file_looks_exposed(rel: str, text: str) -> bool:
    low = text.lstrip()
    name = rel.rsplit("/", 1)[-1]
    if rel.endswith(".git/HEAD"):
        return low.startswith("ref:") or re.match(r"^[0-9a-f]{40}", low) is not None
    if rel.endswith(".git/config"):
        return "[core]" in text or "[remote" in text
    if name == ".DS_Store":
        return text[:4] == "\x00\x00\x00\x01" or "Bud1" in text[:16]
    if name.startswith(".env") or name.endswith(".env"):
        return re.search(r"(?m)^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=", text) is not None
    if name.endswith((".sql", ".dump")):
        return re.search(r"(?i)\b(create table|insert into|drop table|-- mysql dump|postgres)\b", text) is not None
    if name.endswith((".yml", ".yaml")):
        return re.search(r"(?m)^\s*\w[\w-]*\s*:", text) is not None
    if name == ".npmrc":
        return "=" in text and "<html" not in low
    # zip / sqlite / other binaries: a non-HTML body on a probe path is enough.
    return True


def check_maps(client: Client, base_url: str, meta: Dict[str, Any]) -> List[wc.Finding]:
    """A production source map (<bundle>.js.map) that returns {"version":3 leaks
    the original source; sourcesContent means the full text is included."""
    out: List[wc.Finding] = []
    js_urls = list(meta.get("bundle_js") or [])
    if not js_urls:
        try:
            page = client.request(base_url)
            js_urls = _collect_scripts(page.final_url or base_url, page.text())
        except (urllib.error.URLError, BudgetError, OSError):
            js_urls = []
    checked = 0
    for js_url in js_urls:
        if checked >= 3:
            break
        checked += 1
        map_url = js_url + ".map"
        try:
            r = client.request(map_url, follow=False)
        except (urllib.error.URLError, BudgetError, OSError):
            continue
        head = r.text()[:200].lstrip()
        looks_map = head.startswith('{"version":3') or head.startswith('{"version": 3')
        if r.status == 200 and looks_map:
            has_src = '"sourcesContent"' in r.text()[:20000]
            msg = "source map is public" + (" and includes the original source text" if has_src else "")
            out.append(_finding(
                "source-map-exposed", "medium" if not has_src else "high",
                "%s: %s" % (map_url.rsplit("/", 1)[-1], msg), klass="source map",
                evidence=head[:80], fix_ref="interpreting.md#maps", needs_confirmation=False,
                extra={"url": map_url}))
    return out


def check_headers(client: Client, base_url: str, meta: Dict[str, Any]) -> List[wc.Finding]:
    """Report security response headers that are missing on the main page."""
    try:
        r = client.request(base_url)
    except (urllib.error.URLError, BudgetError, OSError) as exc:
        meta.setdefault("warnings", []).append("headers: could not fetch the page: %s" % exc)
        return []
    https = urlsplit(r.final_url or base_url).scheme == "https"
    present = set()
    if r.headers is not None:
        present = {k.lower() for k in r.headers.keys()}
    missing = []
    for key, _sev, label in SECURITY_HEADERS:
        if key == "strict-transport-security" and not https:
            continue  # HSTS only applies over HTTPS
        if key not in present:
            missing.append(label)
    if not missing:
        return []
    worst = "medium" if any(x in " ".join(missing) for x in ("Content-Security", "HSTS", "nosniff")) else "low"
    return [_finding(
        "missing-security-headers", worst,
        "missing security headers: %s" % ", ".join(missing), klass="security headers",
        evidence=", ".join(missing), fix_ref="interpreting.md#headers",
        confidence="high", needs_confirmation=False)]


def _cookie_flags(raw: str) -> Dict[str, Any]:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts else ""
    low = raw.lower()
    samesite = ""
    m = re.search(r"samesite\s*=\s*([a-z]+)", low)
    if m:
        samesite = m.group(1)
    return {"name": name, "httponly": "httponly" in low, "secure": "secure" in low, "samesite": samesite}


def check_cookies(client: Client, base_url: str, meta: Dict[str, Any],
                  login_path: Optional[str] = None, login_body: Optional[str] = None) -> List[wc.Finding]:
    """Inspect Set-Cookie flags. Reads cookies from the main page, and from an
    optional login request the user points at (--cookie-path / --cookie-body)."""
    out: List[wc.Finding] = []
    cookies: List[str] = []
    https = urlsplit(base_url).scheme == "https"
    try:
        cookies.extend(client.request(base_url, follow=False).set_cookies())
    except (urllib.error.URLError, BudgetError, OSError):
        pass
    if login_path:
        url = urljoin(base_url.rstrip("/") + "/", login_path.lstrip("/"))
        try:
            if login_body is not None:
                r = client.request(url, method="POST", data=login_body.encode("utf-8"),
                                   headers={"Content-Type": "application/json"}, follow=False)
            else:
                r = client.request(url, follow=False)
            cookies.extend(r.set_cookies())
        except (urllib.error.URLError, BudgetError, OSError):
            pass
    seen = set()
    for raw in cookies:
        flags = _cookie_flags(raw)
        if not flags["name"] or flags["name"] in seen:
            continue
        seen.add(flags["name"])
        problems = []
        severity = "low"
        if not flags["httponly"]:
            problems.append("no HttpOnly (readable by any script)")
            severity = "medium"
        if https and not flags["secure"]:
            problems.append("no Secure")
            severity = "medium"
        if flags["samesite"] == "none":
            problems.append("SameSite=None (sent cross-site)")
            severity = "medium"
        if not problems:
            continue
        out.append(_finding(
            "weak-cookie", severity,
            "cookie '%s': %s" % (flags["name"], "; ".join(problems)), klass="cookie flags",
            evidence=flags["name"], fix_ref="interpreting.md#cookies",
            confidence="medium", needs_confirmation=True, extra={"cookie": flags["name"]}))
        if len(out) >= 8:
            break
    return out


def check_cors(client: Client, base_url: str, meta: Dict[str, Any],
               path: Optional[str] = None) -> List[wc.Finding]:
    """Send an arbitrary Origin and see whether the app reflects it with
    credentials. A fixed allow-list that does not echo our probe is not flagged."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/")) if path else base_url
    try:
        r = client.request(url, headers={"Origin": CORS_PROBE_ORIGIN})
    except (urllib.error.URLError, BudgetError, OSError) as exc:
        meta.setdefault("warnings", []).append("cors: request failed: %s" % exc)
        return []
    acao = (r.header("Access-Control-Allow-Origin") or "").strip()
    acac = (r.header("Access-Control-Allow-Credentials") or "").strip().lower()
    if not acao:
        return []
    reflected = acao == CORS_PROBE_ORIGIN or acao.lower() == "null"
    if reflected and acac == "true":
        return [_finding(
            "cors-reflects-origin-with-credentials", "high",
            "the API reflects an arbitrary Origin and allows credentials (any site can read "
            "a logged-in user's responses)", klass="CORS",
            evidence="Access-Control-Allow-Origin: %s; Allow-Credentials: true" % acao,
            fix_ref="interpreting.md#cors", confidence="high", needs_confirmation=False)]
    if acao == "*" and acac == "true":
        # Browsers forbid this combination, but it signals an over-broad config.
        return [_finding(
            "cors-wildcard-with-credentials", "medium",
            "CORS allows '*' together with credentials (browsers reject it, but the config is wrong)",
            klass="CORS", evidence="Access-Control-Allow-Origin: *; Allow-Credentials: true",
            fix_ref="interpreting.md#cors", confidence="high", needs_confirmation=False)]
    return []


_DEBUG_FINGERPRINTS = [
    (r"you're seeing this error because you have\s*<code>debug = true", "Django DEBUG=True page", "high"),
    (r"using the urlconf defined in", "Django DEBUG=True page", "high"),
    (r"werkzeug|__debugger__|werkzeug debugger", "Werkzeug debugger", "critical"),
    (r"whoops\\?, looks like something went wrong|ignition", "Laravel debug page", "high"),
    (r"webpack-hmr|react-refresh|__nextjs_original-stack-frame|turbopack-hmr", "Next.js dev server", "medium"),
]


def check_debug(client: Client, base_url: str, meta: Dict[str, Any]) -> List[wc.Finding]:
    """Ask for a path that should 404 and for the Vite dev client; report the
    debug/dev-server fingerprints in the response."""
    out: List[wc.Finding] = []
    probe = urljoin(base_url.rstrip("/") + "/", "ward-does-not-exist-" + "abc123")
    bodies = []
    for url in (probe, urljoin(base_url.rstrip("/") + "/", "@vite/client")):
        try:
            r = client.request(url, follow=False)
            bodies.append((url, r))
        except (urllib.error.URLError, BudgetError, OSError):
            continue
    found = set()
    for url, r in bodies:
        text = r.text()[:20000]
        low = text.lower()
        if url.endswith("@vite/client") and r.status == 200 and ("import" in text or "hmr" in low) and not _is_html(r.body):
            if "vite" not in found:
                found.add("vite")
                out.append(_finding(
                    "dev-server-in-production", "high",
                    "the Vite dev server is serving this app (not a production build)",
                    klass="debug mode", evidence="/@vite/client returns a module",
                    fix_ref="interpreting.md#debug", needs_confirmation=False))
            continue
        for rx, label, sev in _DEBUG_FINGERPRINTS:
            if label in found:
                continue
            if re.search(rx, low):
                found.add(label)
                out.append(_finding(
                    "debug-mode-enabled", sev,
                    "%s is reachable (detailed errors or a dev server in production)" % label,
                    klass="debug mode", evidence=label, fix_ref="interpreting.md#debug",
                    needs_confirmation=False))
    return out


def _inconclusive(meta: Dict[str, Any], check: str, message: str) -> None:
    """Record that an opt-in probe the user asked for gave no answer. The run
    then exits 2 instead of 0 when nothing else was found."""
    meta.setdefault("warnings", []).append("%s: %s" % (check, message))
    if check not in meta.setdefault("inconclusive", []):
        meta["inconclusive"].append(check)


def check_webhook(client: Client, base_url: str, path: str, meta: Dict[str, Any]) -> List[wc.Finding]:
    """One forged, unsigned POST to a Stripe webhook route. A 2xx means it acts
    on unverified events; only 400/401/403 count as a rejected signature.
    404/405/501 mean the route or method was not found, a 3xx went somewhere
    else, and a 5xx or another 4xx cannot tell verification from a crash or a
    body check: those are reported as inconclusive, never as verified."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    body = json.dumps({
        "id": "evt_ward_probe", "type": "checkout.session.completed",
        "data": {"object": {"id": "cs_ward_probe", "payment_status": "paid"}},
    }).encode("utf-8")
    forged_sig = "t=1,v1=" + "0" * 64
    try:
        r = client.request(url, method="POST", data=body, headers={
            "Content-Type": "application/json", "Stripe-Signature": forged_sig}, follow=False)
    except (urllib.error.URLError, BudgetError, OSError) as exc:
        _inconclusive(meta, "webhook", "request to %s failed (%s); webhook not tested" % (path, exc))
        return []
    s = r.status
    if 200 <= s < 300:
        return [_finding(
            "webhook-accepts-forged", "critical",
            "the Stripe webhook accepted a forged, unsigned event (%d). Anyone who knows the URL "
            "can grant themselves paid access" % s, klass="payment webhook",
            evidence="POST %s -> %d with an invalid signature" % (path, s),
            fix_ref="interpreting.md#webhook", needs_confirmation=False, extra={"status": s})]
    if s in (400, 401, 403):
        meta.setdefault("notes", []).append(
            "webhook: %s rejected a forged event with %d (the signature check refused it)" % (path, s))
    elif s in (404, 405, 501):
        _inconclusive(meta, "webhook", (
            "%s returned %d: route or method not found, webhook not tested. Check the path and the host "
            "(Supabase Edge Functions live on <ref>.supabase.co/functions/v1/<name>)" % (path, s)))
    elif 300 <= s < 400:
        _inconclusive(meta, "webhook", "%s redirected (%d to %s), webhook not tested; point --webhook-path at "
                                       "the handler itself" % (path, s, r.header("Location") or "?"))
    elif s >= 500:
        _inconclusive(meta, "webhook", (
            "%s answered %d: inconclusive, the handler errored. Check its logs: failing closed because the "
            "signing secret is missing is fine, crashing after acting on the event is not" % (path, s)))
    else:
        _inconclusive(meta, "webhook", (
            "%s answered %d: inconclusive, cannot tell a signature check from a body check. Confirm in the "
            "code that constructEvent (or the provider's verify call) runs on the raw body first" % (path, s)))
    return []


def check_ratelimit(client: Client, base_url: str, path: str, n: int, meta: Dict[str, Any],
                    method: str = "POST", body: Optional[str] = None,
                    bearer: Optional[str] = None) -> List[wc.Finding]:
    """Send a modest burst to a metered endpoint and count the responses. No 429
    across the burst means no rate limit; all 401/403 means auth is blocking first.
    body is the JSON to POST (default a small probe object); bearer is a test
    session token sent as Authorization: Bearer, so a route that checks auth
    first can be measured as a logged-in user."""
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    n = max(1, min(int(n), MAX_RATELIMIT))
    client.budget += n  # the burst gets its own allowance on top of BASE_BUDGET
    codes: Dict[int, int] = {}
    data = None
    headers: Dict[str, str] = {}
    if method == "POST":
        data = (body if body is not None else '{"ward":"ratelimit-probe"}').encode("utf-8")
        headers["Content-Type"] = "application/json"
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    sent = 0
    error = ""
    for _ in range(n):
        try:
            r = client.request(url, method=method, data=data, headers=headers or None, follow=False)
        except (urllib.error.URLError, BudgetError, OSError) as exc:
            error = str(exc)
            break
        sent += 1
        codes[r.status] = codes.get(r.status, 0) + 1
    meta.setdefault("ratelimit", {})[path] = {"sent": sent, "codes": dict(sorted(codes.items()))}
    if sent == 0:
        _inconclusive(meta, "ratelimit", "no request to %s got an answer (%s); rate limit not tested"
                      % (path, error or "no response"))
        return []
    blocked = sum(c for s, c in codes.items() if s in (401, 403))
    if blocked >= sent:
        if bearer:
            _inconclusive(meta, "ratelimit", "%s refused the given session token on all %d calls (%s); "
                                             "rate limit not tested" % (path, sent, dict(sorted(codes.items()))))
        else:
            meta.setdefault("notes", []).append(
                "ratelimit: %s blocks unauthenticated calls (%d). To measure the logged-in limit, export a test "
                "user's token and re-run with --auth-bearer-env VAR" % (path, sent))
        return []
    if any(s == 429 for s in codes):
        meta.setdefault("notes", []).append("ratelimit: %s returned 429 (a limiter is active)" % path)
        return []
    ok = sum(c for s, c in codes.items() if 200 <= s < 300)
    if ok == 0:
        hint = ""
        if any(s in (400, 422) for s in codes):
            hint = "; the probe body was refused, pass a valid one with --ratelimit-body"
        elif any(s in (404, 405, 501) for s in codes):
            hint = "; route or method not found, check --ratelimit-path and --ratelimit-method"
        elif any(s in (401, 403) for s in codes) and not bearer:
            hint = "; pass a test session with --auth-bearer-env VAR"
        elif any(s >= 500 for s in codes):
            hint = "; the handler errored, check its logs and the probe body (--ratelimit-body)"
        _inconclusive(meta, "ratelimit", "inconclusive for %s: no 2xx and no 429 (codes %s)%s"
                      % (path, dict(sorted(codes.items())), hint))
        return []
    return [_finding(
        "no-rate-limit", "medium",
        "%d requests to %s with no 429 and no auth block: no rate limit at or below %d per window "
        "(read the limiter config%s)" % (sent, path, sent,
                                         ", or re-run with a higher --n" if sent < MAX_RATELIMIT else ""),
        klass="rate limit", evidence="codes: %s" % dict(sorted(codes.items())),
        fix_ref="interpreting.md#ratelimit", confidence="medium", needs_confirmation=True)]


def _json_array(text: str) -> Optional[list]:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, list) else None


def check_baas_supabase(client: Client, supabase_url: str, anon_key: str, tables: Sequence[str],
                        meta: Dict[str, Any], token_a: Optional[str] = None,
                        token_b: Optional[str] = None) -> List[wc.Finding]:
    """Logged-out read of the user's own Supabase tables with the user's own anon
    key. Rows returned without logging in means row level security is open.
    Every table that gives no clear answer (wrong key, missing table, network
    error) gets a warning; when none does, the probe is inconclusive."""
    out: List[wc.Finding] = []
    root = supabase_url.rstrip("/")
    answered = 0
    for table in tables:
        url = "%s/rest/v1/%s?select=*&limit=2" % (root, table)
        hdrs = {"apikey": anon_key, "Authorization": "Bearer " + anon_key}
        try:
            r = client.request(url, headers=hdrs, follow=False)
        except (urllib.error.URLError, BudgetError, OSError) as exc:
            meta.setdefault("warnings", []).append("baas: %s: request failed (%s)" % (table, exc))
            continue
        body = r.text()[:2000]
        low = body.lower()
        if r.status in (401, 403) and ("42501" in body or "permission denied" in low):
            answered += 1
            meta.setdefault("notes", []).append(
                "baas: %s refuses the anon role (%d, no grant): closed to logged-out reads" % (table, r.status))
            continue
        if r.status in (401, 403):
            meta.setdefault("warnings", []).append(
                "baas: %s: %d, the anon key was rejected (check --anon-key: the anon / publishable key of "
                "this project)" % (table, r.status))
            continue
        if r.status == 404 or "pgrst205" in low or "42p01" in low:
            meta.setdefault("warnings", []).append(
                "baas: %s: %d, table not exposed or misspelled (check --baas-table and the exposed schemas)"
                % (table, r.status))
            continue
        if r.status != 200:
            meta.setdefault("warnings", []).append("baas: %s: unexpected status %d" % (table, r.status))
            continue
        rows = _json_array(r.text())
        if rows is None:
            meta.setdefault("warnings", []).append(
                "baas: %s: 200 but not a JSON array (is --supabase-url the project URL?)" % table)
            continue
        answered += 1
        if rows:
            out.append(_finding(
                "supabase-rls-open", "critical",
                "the Supabase table '%s' returns rows to the logged-out anon key: row level "
                "security is missing or permissive" % table, klass="open database",
                evidence="GET /rest/v1/%s returned %d row(s) with no session" % (table, len(rows)),
                fix_ref="interpreting.md#baas", needs_confirmation=False, extra={"table": table}))
        elif token_a and token_b:
            out.extend(_supabase_cross_user(client, root, anon_key, table, token_a, token_b))
    if tables and answered == 0:
        _inconclusive(meta, "baas", "no Supabase table gave a clear answer (see the warnings above); "
                                    "row level security not tested")
    return out


def _supabase_cross_user(client: Client, root: str, anon_key: str, table: str,
                         token_a: str, token_b: str) -> List[wc.Finding]:
    url = "%s/rest/v1/%s?select=*&limit=50" % (root, table)

    def read(token: str) -> Optional[list]:
        try:
            r = client.request(url, headers={"apikey": anon_key, "Authorization": "Bearer " + token},
                               follow=False)
        except (urllib.error.URLError, BudgetError, OSError):
            return None
        return _json_array(r.text()) if r.status == 200 else None

    rows_a, rows_b = read(token_a), read(token_b)
    if not rows_a or not rows_b:
        return []
    def ids(rows: list) -> set:
        return {json.dumps(r.get("id"), sort_keys=True) for r in rows if isinstance(r, dict) and "id" in r}
    shared = ids(rows_a) & ids(rows_b)
    if shared and (ids(rows_a) == ids(rows_b)):
        return [_finding(
            "supabase-cross-user-read", "high",
            "two different users see the same rows in '%s': the policy may not scope rows to the "
            "owner (confirm these rows are not meant to be shared)" % table, klass="open database",
            evidence="users A and B both read %d identical row(s)" % len(shared),
            fix_ref="interpreting.md#baas", confidence="low", needs_confirmation=True,
            extra={"table": table})]
    return []


FIRESTORE_API = "https://firestore.googleapis.com"


def default_rtdb_url(project: str) -> str:
    """The Realtime Database URL of a project's default us-central1 instance.
    Other regions use https://<name>.<region>.firebasedatabase.app instead."""
    return "https://%s-default-rtdb.firebaseio.com" % project


_FB_DB_URL = re.compile(
    r"""databaseURL["']?\s*[:=]\s*["'](https://[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"""
    r"""\.(?:firebaseio\.com|firebasedatabase\.app))/?["']""")


def firebase_database_url(text: str) -> Optional[str]:
    """The Realtime Database URL in an app's firebaseConfig (databaseURL), when
    the shipped page or bundle carries one. Only Firebase database hosts count."""
    m = _FB_DB_URL.search(text or "")
    return m.group(1) if m else None


def check_baas_firebase(client: Client, project: str, collections: Sequence[str],
                        meta: Dict[str, Any], rtdb_url: Optional[str] = None,
                        firestore_api: str = FIRESTORE_API) -> List[wc.Finding]:
    """Logged-out read of the user's own Firestore and Realtime Database.
    Documents returned without a token means the Security Rules are open.
    rtdb_url is the database URL from the app's firebaseConfig (databaseURL);
    without it the default us-central1 URL is tried, and a database it cannot
    reach is reported as not checked instead of clean."""
    out: List[wc.Finding] = []
    answered = 0
    rtdb_base = (rtdb_url or default_rtdb_url(project)).rstrip("/")
    rtdb_ok: Optional[bool] = None
    for coll in collections:
        url = "%s/v1/projects/%s/databases/(default)/documents/%s?pageSize=2" % (firestore_api.rstrip("/"),
                                                                                project, coll)
        try:
            r = client.request(url, follow=False)
        except (urllib.error.URLError, BudgetError, OSError) as exc:
            meta.setdefault("warnings", []).append("baas: firestore %s: request failed (%s)" % (coll, exc))
            r = None
        if r is not None:
            if r.status == 200:
                answered += 1
                try:
                    data = json.loads(r.text())
                except ValueError:
                    data = None
                if isinstance(data, dict) and data.get("documents"):
                    out.append(_finding(
                        "firebase-rules-open", "critical",
                        "the Firestore collection '%s' is readable with no authentication: the Security "
                        "Rules are open" % coll, klass="open database",
                        evidence="GET /documents/%s returned %d document(s)" % (coll, len(data["documents"])),
                        fix_ref="interpreting.md#baas", needs_confirmation=False, extra={"collection": coll}))
                else:
                    meta.setdefault("notes", []).append(
                        "baas: Firestore '%s' answered 200 with no documents: the rules allow a logged-out list, "
                        "it is just empty now" % coll)
            elif r.status in (401, 403):
                answered += 1
                meta.setdefault("notes", []).append("baas: Firestore '%s' refuses logged-out reads (%d)" % (coll, r.status))
            elif r.status == 404:
                meta.setdefault("warnings", []).append(
                    "baas: firestore %s: 404, project or (default) database not found (check --firebase-project)" % coll)
            else:
                meta.setdefault("warnings", []).append("baas: firestore %s: unexpected status %d" % (coll, r.status))

        if rtdb_ok is False:
            continue
        rurl = "%s/%s.json?shallow=true" % (rtdb_base, coll.strip("/"))
        try:
            r = client.request(rurl, follow=False)
        except (urllib.error.URLError, BudgetError, OSError) as exc:
            rtdb_ok = False
            meta.setdefault("warnings", []).append(
                "baas: Realtime Database not checked: %s did not answer (%s). A database outside us-central1 "
                "lives at https://<name>.<region>.firebasedatabase.app; pass the app's databaseURL with "
                "--rtdb-url" % (rtdb_base, exc))
            continue
        txt = r.text().strip()
        low = txt.lower()
        if r.status in (401, 403) or "permission denied" in low:
            rtdb_ok = True
            answered += 1
            continue
        parsed = True
        try:
            json.loads(txt or "null")
        except ValueError:
            parsed = False
        if r.status == 200 and parsed:
            rtdb_ok = True
            answered += 1
            if txt and txt != "null":
                out.append(_finding(
                    "firebase-rtdb-open", "critical",
                    "the Realtime Database path '%s' is readable with no authentication" % coll,
                    klass="open database", evidence="GET /%s.json returned data with no token" % coll,
                    fix_ref="interpreting.md#baas", needs_confirmation=False, extra={"path": coll}))
            continue
        rtdb_ok = False
        detail = ""
        try:
            err = json.loads(txt).get("error") if parsed else None
            if isinstance(err, str):
                detail = ": " + " ".join(err.split())[:200]
        except (ValueError, AttributeError):
            pass
        meta.setdefault("warnings", []).append(
            "baas: Realtime Database not checked: %s answered %d%s. Pass the app's databaseURL with --rtdb-url "
            "(outside us-central1 it is https://<name>.<region>.firebasedatabase.app)" % (rtdb_base, r.status, detail))
    if collections and answered == 0:
        _inconclusive(meta, "baas", "neither Firestore nor the Realtime Database gave a clear answer; "
                                    "Firebase rules not tested")
    return out


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def run(url: str, checks: Optional[Sequence[str]] = None, timeout: float = 10.0,
        webhook_path: Optional[str] = None, ratelimit_path: Optional[str] = None,
        ratelimit_n: int = DEFAULT_RATELIMIT, ratelimit_method: str = "POST",
        supabase_url: Optional[str] = None, anon_key: Optional[str] = None,
        baas_tables: Optional[Sequence[str]] = None, firebase_project: Optional[str] = None,
        baas_collections: Optional[Sequence[str]] = None, token_a: Optional[str] = None,
        token_b: Optional[str] = None, cookie_path: Optional[str] = None,
        cookie_body: Optional[str] = None, cors_path: Optional[str] = None,
        client: Optional[Client] = None, ratelimit_body: Optional[str] = None,
        ratelimit_bearer: Optional[str] = None, rtdb_url: Optional[str] = None,
        firestore_api: str = FIRESTORE_API) -> Tuple[List[wc.Finding], List[str], Dict[str, Any]]:
    """Run the selected checks against url (already host-gated). Returns
    (findings, warnings, meta). An opt-in probe whose flag is given always runs,
    even when --checks lists other checks. meta["inconclusive"] names the
    requested probes that gave no answer."""
    base_url = _normalize_url(url)
    client = client or Client(timeout=timeout)
    meta: Dict[str, Any] = {}
    findings: List[wc.Finding] = []

    baas_ready = bool((supabase_url and anon_key) or firebase_project)
    requested = list(checks) if checks else list(ALWAYS_CHECKS)
    for name, given in (("webhook", webhook_path), ("ratelimit", ratelimit_path), ("baas", baas_ready)):
        if given and name not in requested:
            requested.append(name)
            if checks:
                meta.setdefault("notes", []).append(
                    "%s: added to --checks because its flag was given" % name)
    ran: List[str] = []

    for name in requested:
        try:
            if name == "bundle":
                findings += check_bundle(client, base_url, meta)
            elif name == "files":
                findings += check_files(client, base_url, meta)
            elif name == "maps":
                findings += check_maps(client, base_url, meta)
            elif name == "headers":
                findings += check_headers(client, base_url, meta)
            elif name == "cookies":
                findings += check_cookies(client, base_url, meta, cookie_path, cookie_body)
            elif name == "cors":
                findings += check_cors(client, base_url, meta, cors_path)
            elif name == "debug":
                findings += check_debug(client, base_url, meta)
            elif name == "webhook":
                if not webhook_path:
                    _inconclusive(meta, "webhook", "skipped, no --webhook-path given")
                    continue
                findings += check_webhook(client, base_url, webhook_path, meta)
            elif name == "ratelimit":
                if not ratelimit_path:
                    _inconclusive(meta, "ratelimit", "skipped, no --ratelimit-path given")
                    continue
                findings += check_ratelimit(client, base_url, ratelimit_path, ratelimit_n, meta, ratelimit_method,
                                            body=ratelimit_body, bearer=ratelimit_bearer)
            elif name == "baas":
                if not baas_ready:
                    _inconclusive(meta, "baas", "skipped, give --supabase-url + --anon-key or --firebase-project")
                    continue
                if supabase_url and anon_key:
                    tables = baas_tables or ["profiles", "users", "todos", "messages", "posts"]
                    findings += check_baas_supabase(client, supabase_url, anon_key, tables, meta, token_a, token_b)
                if firebase_project:
                    colls = baas_collections or ["users", "messages", "posts"]
                    db_url = rtdb_url
                    if not db_url and meta.get("firebase_database_url"):
                        db_url = meta["firebase_database_url"]
                        meta.setdefault("notes", []).append(
                            "baas: Realtime Database URL taken from the app's firebaseConfig (%s)" % db_url)
                    findings += check_baas_firebase(client, firebase_project, colls, meta, rtdb_url=db_url,
                                                    firestore_api=firestore_api)
            else:
                meta.setdefault("warnings", []).append("unknown check: %s" % name)
                continue
            ran.append(name)
        except BudgetError as exc:
            meta.setdefault("warnings", []).append("%s: %s" % (name, exc))
            if name in OPT_IN_CHECKS and name not in meta.setdefault("inconclusive", []):
                meta["inconclusive"].append(name)
            break

    meta["checks_run"] = ran
    meta["requests_made"] = client.used
    meta.pop("bundle_js", None)  # internal: only used to hand script URLs to the maps check
    warnings = list(meta.pop("warnings", []))
    return wc.sort_findings(findings), warnings, meta


def _parse_list(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [p.strip() for p in value.split(",") if p.strip()]


def _owned_list(values: Optional[Sequence[str]]) -> List[str]:
    out: List[str] = []
    for v in values or []:
        out.extend(p.strip() for p in str(v).split(",") if p.strip())
    return out


def check_service_url(url: str, owned: Sequence[str], suffixes: Sequence[str], flag: str) -> Optional[str]:
    """Gate a second host the probe will contact (a Supabase project, a Realtime
    Database). Local hosts, hosts ending in one of suffixes, and hosts named by
    --i-own-this pass; anything else, and plain http on a non-local host (the
    key would travel in clear), is refused. Returns an error message or None."""
    host, local = wc.require_owned_host(url)
    if not host:
        return "error: %s is not a valid http(s) URL" % flag
    if local:
        return None
    scheme = urlsplit(url if "://" in url else "https://" + url).scheme.lower()
    if scheme != "https":
        return "error: %s must use https:// for a non-local host (the key would be sent in clear)" % flag
    if any(host == s.lstrip(".") or host.endswith(s) for s in suffixes):
        return None
    if owned and wc.require_owned_host(url, list(owned))[1]:
        return None
    return ("refused: %s points at %s, which is not a %s host. If it is your own project, pass "
            "--i-own-this %s" % (flag, host, " / ".join("*" + s for s in suffixes), host))


def main(argv: Optional[Sequence[str]] = None) -> int:
    wc.setup_io()
    ap = argparse.ArgumentParser(
        prog="check_live.py",
        description="Check what your own running app exposes over HTTP: secrets in the bundle, a "
                    "reachable .env or .git, source maps, missing headers, weak cookies, permissive "
                    "CORS, debug mode, and (opt-in) an unverified webhook, an unthrottled endpoint, "
                    "or an open Supabase/Firebase read. Read-only. Exit 0 = clean, 1 = findings, "
                    "2 = error or a requested opt-in probe gave no answer, 3 = refused (not your host).",
        epilog="Git Bash on Windows rewrites /api/x into a Windows path; the script undoes that, or write "
               "paths without the leading slash (api/x).")
    ap.add_argument("url", help="your own app URL (localhost, *.test, or a host you pass --i-own-this)")
    wc.add_common_args(ap)
    ap.add_argument("--i-own-this", metavar="HOST", dest="i_own_this", action="append",
                    help="confirm you own this host (must match the URL host); repeat it, or use a comma list, "
                         "for a custom Supabase or database host")
    ap.add_argument("--timeout", type=float, default=10.0, metavar="S", help="per-request timeout (default 10)")
    ap.add_argument("--checks", metavar="LIST",
                    help="comma list of checks to run (default: %s); an opt-in flag below adds its check"
                         % ",".join(ALWAYS_CHECKS))
    ap.add_argument("--cookie-path", metavar="PATH", help="also request this path and inspect its Set-Cookie flags")
    ap.add_argument("--cookie-body", metavar="JSON", help="JSON body to POST to --cookie-path (for a test login)")
    ap.add_argument("--cors-path", metavar="PATH", help="path to send the CORS probe to (default: /)")
    ap.add_argument("--webhook-path", metavar="PATH", help="opt-in: forge one unsigned POST to this Stripe webhook route")
    ap.add_argument("--ratelimit-path", metavar="PATH", help="opt-in: send a burst to this metered endpoint")
    ap.add_argument("--ratelimit-method", default="POST", choices=["GET", "POST"], help="method for the burst (default POST)")
    ap.add_argument("--ratelimit-body", metavar="JSON",
                    help="JSON body for the burst, valid for the endpoint, so input checks do not answer first")
    ap.add_argument("--auth-bearer-env", metavar="VAR",
                    help="name of an environment variable holding a test user's session token; the burst sends "
                         "it as Authorization: Bearer (the token never goes on the command line)")
    ap.add_argument("--n", type=int, default=DEFAULT_RATELIMIT, metavar="N",
                    help="burst size for --ratelimit-path (default %d, capped at %d)" % (DEFAULT_RATELIMIT, MAX_RATELIMIT))
    ap.add_argument("--supabase-url", metavar="URL",
                    help="opt-in: your own Supabase project URL (https://<ref>.supabase.co) for a logged-out read")
    ap.add_argument("--anon-key", metavar="KEY", help="your own Supabase anon/publishable key (never a secret key)")
    ap.add_argument("--baas-table", metavar="LIST", help="comma list of Supabase tables to test")
    ap.add_argument("--firebase-project", metavar="ID", help="opt-in: your own Firebase project id for a logged-out read")
    ap.add_argument("--rtdb-url", metavar="URL",
                    help="your Realtime Database URL (databaseURL in firebaseConfig); needed outside us-central1")
    ap.add_argument("--baas-collection", metavar="LIST", help="comma list of Firestore collections / RTDB paths to test")
    ap.add_argument("--token-a", metavar="JWT", help="a logged-in user A access token (optional cross-user read)")
    ap.add_argument("--token-b", metavar="JWT", help="a logged-in user B access token (optional cross-user read)")
    args = ap.parse_args(argv)

    owned = _owned_list(args.i_own_this)
    host, ok = check_host(args.url, owned or None)
    if not ok:
        sys.stderr.write(wc.refusal_message(host) + "\n")
        return wc.EXIT_REFUSED

    checks = _parse_list(args.checks)
    if checks:
        unknown = [c for c in checks if c not in ALWAYS_CHECKS + OPT_IN_CHECKS]
        if unknown:
            sys.stderr.write("error: unknown check(s): %s\n" % ", ".join(unknown))
            return wc.EXIT_ERROR

    paths: Dict[str, Optional[str]] = {}
    for flag, value in (("--webhook-path", args.webhook_path), ("--ratelimit-path", args.ratelimit_path),
                        ("--cors-path", args.cors_path), ("--cookie-path", args.cookie_path)):
        clean, err = clean_url_path(value, flag)
        if err:
            sys.stderr.write("error: %s\n" % err)
            return wc.EXIT_ERROR
        paths[flag] = clean

    if args.ratelimit_body is not None:
        try:
            json.loads(args.ratelimit_body)
        except ValueError as exc:
            sys.stderr.write("error: --ratelimit-body is not valid JSON: %s\n" % exc)
            return wc.EXIT_ERROR
    bearer = None
    if args.auth_bearer_env:
        bearer = os.environ.get(args.auth_bearer_env, "").strip()
        if not bearer:
            sys.stderr.write("error: environment variable %s is empty or not set\n" % args.auth_bearer_env)
            return wc.EXIT_ERROR

    for flag, value, suffixes in (("--supabase-url", args.supabase_url, (".supabase.co", ".supabase.in")),
                                  ("--rtdb-url", args.rtdb_url, (".firebaseio.com", ".firebasedatabase.app"))):
        if not value:
            continue
        err = check_service_url(value, owned, suffixes, flag)
        if err:
            sys.stderr.write(err + "\n")
            return wc.EXIT_REFUSED if err.startswith("refused") else wc.EXIT_ERROR
    if args.supabase_url and not args.anon_key:
        sys.stderr.write("error: --supabase-url needs --anon-key (the project's anon / publishable key)\n")
        return wc.EXIT_ERROR
    if args.firebase_project and not re.fullmatch(r"[a-z0-9][a-z0-9-]{2,62}", args.firebase_project):
        sys.stderr.write("error: --firebase-project must be a project id (lowercase letters, digits, dashes)\n")
        return wc.EXIT_ERROR

    try:
        findings, warnings, meta = run(
            args.url, checks=checks, timeout=args.timeout,
            webhook_path=paths["--webhook-path"], ratelimit_path=paths["--ratelimit-path"],
            ratelimit_n=args.n, ratelimit_method=args.ratelimit_method,
            supabase_url=args.supabase_url, anon_key=args.anon_key,
            baas_tables=_parse_list(args.baas_table), firebase_project=args.firebase_project,
            baas_collections=_parse_list(args.baas_collection),
            token_a=args.token_a, token_b=args.token_b,
            cookie_path=paths["--cookie-path"], cookie_body=args.cookie_body, cors_path=paths["--cors-path"],
            ratelimit_body=args.ratelimit_body, ratelimit_bearer=bearer, rtdb_url=args.rtdb_url)
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return wc.EXIT_ERROR
    except Exception as exc:  # a failed scan is a runtime error, not a crash
        sys.stderr.write("error: check failed: %s: %s\n" % (type(exc).__name__, exc))
        return wc.EXIT_ERROR

    report_meta = {"host": host}
    report_meta.update(meta)
    code = None
    if meta.get("inconclusive") and wc.exit_code_for(findings) == wc.EXIT_OK:
        code = wc.EXIT_ERROR  # a probe the user asked for gave no answer: not a clean result
    return wc.emit(findings, as_json=args.json, out_file=args.output, max_findings=args.max_findings,
                   target=_normalize_url(args.url), script=SCRIPT, meta=report_meta, warnings=warnings,
                   exit_code=code)


if __name__ == "__main__":
    sys.exit(main())
