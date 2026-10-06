"""Secret exposure rules (threats-exposure classes 1 to 3).

Raw secret values are find_secrets.py's job. These rules look for the code
shapes that put a server secret where the browser or the mobile app can read
it, and for signing secrets that are guessable:

- secret-shaped names behind a public env prefix (NEXT_PUBLIC_, VITE_, ...)
- bundler config that inlines env values (next.config env, Vite define, ...)
- LLM SDKs switched into browser mode, provider APIs called from client code
- Supabase admin calls and the Firebase Admin SDK in client code
- endpoints and props that send the server environment to the client
- signing secrets with a literal fallback, or hardcoded as literals

Each rule is a _wardcore.Rule; see its docstring for the fields.
"""

from __future__ import annotations

import bisect
import hashlib
import io
import re
import tokenize
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

import _wardcore as wc
from _wardcore import Hit, Rule

try:
    import _secret_patterns as _sp
except Exception:  # pragma: no cover - ships beside this file
    _sp = None

SKILL = "secrets"

# ---------------------------------------------------------------------------
# File sets
# ---------------------------------------------------------------------------

_JS = ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.mts", "*.cts"]
_JS_UI = _JS + ["*.vue", "*.svelte", "*.astro"]
_ENV_FILES = [".env", ".env.*", "*.env"]

# Code that never ships: tests, fixtures, docs, examples, type declarations.
_NOT_SHIPPED = [
    "**/test/**", "**/tests/**", "**/__tests__/**", "**/__mocks__/**", "**/fixtures/**",
    "**/__fixtures__/**", "**/e2e/**", "**/cypress/**", "**/playwright/**", "**/docs/**",
    "**/examples/**", "**/example/**", "*.test.*", "*.spec.*", "*.stories.*", "*.story.*",
    "*.d.ts", "conftest.py", "test_*.py", "*_test.py",
    # test runner configs and setup files: they only run in tests
    "playwright.config.*", "playwright-ct.config.*", "vitest.config.*", "vitest.workspace.*", "vitest.setup.*",
    "jest.config.*", "jest.setup.*", "setupTests.*", "cypress.config.*", "karma.conf.*", "wdio.conf.*", "*.e2e.*",
]

# Settings modules that only a developer machine or the test runner loads.
_DEV_SETTINGS = [
    "**/settings/dev*.py", "**/settings/local*.py", "**/settings/test*.py", "**/settings/ci.py",
    "dev_settings.py", "local_settings.py", "test_settings.py", "settings_dev.py",
    "settings_local.py", "settings_test.py",
]

# ---------------------------------------------------------------------------
# Env var name classification
# ---------------------------------------------------------------------------

_PUBLIC_MARKERS = frozenset({"PUBLISHABLE", "ANON", "PUBLIC", "SITEKEY", "PK"})
# Trailing parts that do not change what the value is.
_NEUTRAL_TAIL = frozenset({
    "PROD", "PRODUCTION", "DEV", "DEVELOPMENT", "LIVE", "TEST", "STAGING", "LOCAL", "V1", "V2",
    "V3", "B64", "BASE64", "JSON", "RAW", "HEX", "VALUE", "STRING", "STR",
})
_KEY_TAIL = frozenset({"KEY", "KEYS", "TOKEN", "ACCESS"})
_PASSWORD_LAST = frozenset({"PASSWORD", "PASSWD", "PASS", "PWD", "PASSPHRASE"})
_KEYISH_LAST = frozenset({"KEY", "KEYS", "APIKEY", "TOKEN", "TOKENS", "AUTHTOKEN"})
# Providers whose API keys are always server secrets.
_PROVIDERS = frozenset({
    "OPENAI", "ANTHROPIC", "CLAUDE", "GEMINI", "GENAI", "GENERATIVE", "GROQ", "MISTRAL", "COHERE",
    "REPLICATE", "OPENROUTER", "DEEPSEEK", "PERPLEXITY", "XAI", "GROK", "TOGETHER", "FIREWORKS",
    "ELEVENLABS", "HUGGINGFACE", "HF", "RESEND", "SENDGRID", "MAILGUN", "POSTMARK", "BREVO",
    "TWILIO", "GITHUB", "GITLAB", "SLACK", "DISCORD", "TELEGRAM", "NOTION", "AIRTABLE", "PINECONE",
    "LANGSMITH", "LANGCHAIN", "TAVILY", "SERPAPI", "FIRECRAWL", "ASSEMBLYAI", "DEEPGRAM",
    "STABILITY", "RUNWAY", "VOYAGE",
})
_DB_PARTS = frozenset({"DATABASE", "DB", "POSTGRES", "POSTGRESQL", "PG", "MONGO", "MONGODB", "MYSQL",
                       "MARIADB", "REDIS"})
_URLISH = frozenset({"URL", "URI", "DSN", "CONNECTION", "CONN", "CONNSTR", "CONNECTIONSTRING"})
_SIGNING_PARTS = frozenset({"JWT", "JWS", "JWE", "SESSION", "SESSIONS", "COOKIE", "COOKIES", "SIGNING",
                            "ENCRYPTION", "ENCRYPT", "CIPHER", "HMAC", "NEXTAUTH", "IRON", "CSRF",
                            "XSRF", "TOTP"})
_SIGNING_LAST = frozenset({"KEY", "SECRET", "SALT", "PEPPER"})
_SIGNING_NAMES = frozenset({"APP_KEY", "AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
                            "SECRET_KEY", "SECRET_KEY_BASE", "AUTH_SECRET", "APP_SECRET",
                            "SECURITY_PASSWORD_SALT"})
# Token-shaped names that are public by design for these services.
_PUBLIC_TOKEN_PROVIDERS = frozenset({"MAPBOX", "CESIUM", "CONTENTFUL", "STORYBLOK"})
_PRIVILEGED = frozenset({"MANAGEMENT", "PREVIEW", "ADMIN", "WRITE", "SECRET", "PRIVATE", "SERVICE", "SK"})
_NOT_A_CREDENTIAL = frozenset({"CSRF", "XSRF", "DEVICE", "PUSH"})
# Key-shaped names that are usually public client ids.
_PUBLIC_KEY_PROVIDERS = frozenset({
    "FIREBASE", "MAPS", "GMAPS", "MAPBOX", "MAPTILER", "RECAPTCHA", "TURNSTILE", "HCAPTCHA", "SENTRY",
    "POSTHOG", "ALGOLIA", "MIXPANEL", "AMPLITUDE", "SEGMENT", "PUSHER", "ONESIGNAL", "REVENUECAT",
    "GA", "GTM", "VAPID", "MEASUREMENT", "PLAUSIBLE", "UMAMI", "HOTJAR", "INTERCOM", "CRISP",
})

STRONG_KINDS = frozenset({"service", "password", "signing", "secret", "private", "admin", "provider", "db"})
FALLBACK_KINDS = frozenset({"service", "password", "signing", "secret", "private", "admin"})

_KIND_TEXT = {
    "service": "a Supabase service key (bypasses row level security)",
    "password": "a password",
    "signing": "a signing or encryption secret",
    "secret": "a secret",
    "private": "a private key",
    "admin": "an admin or master key",
    "provider": "a paid API key",
    "db": "a database connection string",
    "token": "an access token or webhook",
    "key": "an API key",
}


def _seq(parts: Sequence[str], a: str, b: str) -> bool:
    return any(parts[i] == a and parts[i + 1] == b for i in range(len(parts) - 1))


def camel_to_upper(name: str) -> str:
    """openaiApiKey -> OPENAI_API_KEY; names already in UPPER_SNAKE stay as they are."""
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).upper()


def classify_name(name: str, loose: bool = False) -> Optional[str]:
    """What an env var name says its value is, or None when it reads as public
    or harmless.

    Strong kinds: service, password, signing, secret, private, admin, provider,
    db. "token" covers tokens and webhook URLs (often secret, sometimes public).
    With loose=True, any other name ending in KEY returns "key".
    The name should not carry a public prefix (strip NEXT_PUBLIC_ first).
    """
    parts = [p for p in re.split(r"_+", (name or "").upper()) if p]
    if not parts:
        return None
    if any(p in _PUBLIC_MARKERS for p in parts) or _seq(parts, "SITE", "KEY"):
        return None
    core = list(parts)
    while len(core) > 1 and core[-1] in _NEUTRAL_TAIL:
        core.pop()
    last = core[-1]
    upper = "_".join(core)

    if "SERVICEROLE" in core or _seq(core, "SERVICE", "ROLE") or ("SUPABASE" in core and _seq(core, "SERVICE", "KEY")):
        return "service"
    if last in _PASSWORD_LAST:
        return "password"
    if upper in _SIGNING_NAMES or (last in _SIGNING_LAST and any(p in _SIGNING_PARTS for p in core[:-1])):
        return "signing"
    for i, p in enumerate(core):
        tail = core[i + 1:]
        if p in ("SECRET", "SECRETS") and all(t in _KEY_TAIL for t in tail):
            return "secret"
        if p == "PRIVATE" and tail[:1] == ["KEY"] and all(t in _KEY_TAIL for t in tail):
            return "private"
        if p in ("ADMIN", "MASTER", "ROOT"):
            rest = tail[1:] if tail[:1] == ["API"] else tail
            if rest[:1] and rest[0] in ("KEY", "TOKEN", "SECRET") and all(t in _KEY_TAIL for t in rest[1:]):
                return "admin"
    if last == "SK":
        return "secret"
    if _seq(core, "SERVICE", "ACCOUNT") and last in ("ACCOUNT", "KEY", "CREDENTIAL", "CREDENTIALS"):
        return "private"
    if last in _KEYISH_LAST and any(p in _PROVIDERS for p in core[:-1]):
        return "provider"
    if last in _URLISH and any(p in _DB_PARTS for p in core) and not any(p in ("REST", "HTTP", "HTTPS") for p in core):
        return "db"
    if last in ("TOKEN", "TOKENS", "AUTHTOKEN", "BEARER", "WEBHOOK") or (
            "WEBHOOK" in core and last in ("URL", "URI", "ENDPOINT")):
        if any(p in _NOT_A_CREDENTIAL for p in core):
            return None
        if any(p in _PUBLIC_TOKEN_PROVIDERS for p in core) and not any(p in _PRIVILEGED for p in core):
            return None
        return "token"
    if loose and last in ("KEY", "KEYS", "APIKEY", "SECRET"):
        if any(p in _PUBLIC_KEY_PROVIDERS for p in core):
            return None
        return "key"
    return None


# ---------------------------------------------------------------------------
# Small text helpers
# ---------------------------------------------------------------------------

_OPENERS = {"(": ")", "[": "]", "{": "}"}


def _skip_string(text: str, j: int, end: int) -> int:
    q = text[j]
    k = j + 1
    while k < end:
        c = text[k]
        if c == "\\":
            k += 2
            continue
        if c == q:
            return k + 1
        if c == "\n" and q != "`":
            return k + 1
        k += 1
    return end


def block_end(text: str, i: int, limit: int = 6000) -> int:
    """text[i] is (, [ or {. Index just past the matching closer, skipping
    strings and // comments. Stops at i + limit."""
    if i >= len(text) or text[i] not in _OPENERS:
        return i
    stack = [_OPENERS[text[i]]]
    end = min(len(text), i + limit)
    j = i + 1
    while j < end:
        ch = text[j]
        if ch in "\"'`":
            j = _skip_string(text, j, end)
            continue
        if ch == "/" and text[j + 1:j + 2] == "/":
            nl = text.find("\n", j)
            j = end if nl == -1 else nl
            continue
        if ch in _OPENERS:
            stack.append(_OPENERS[ch])
        elif ch in ")]}":
            if ch == stack[-1]:
                stack.pop()
            if not stack:
                return j + 1
        j += 1
    return end


def split_args(text: str, i: int, limit: int = 4000) -> List[Tuple[str, int]]:
    """Top-level arguments of the call whose ( is at text[i], as (text, offset)."""
    close = block_end(text, i, limit)
    inner_end = close - 1 if text[close - 1:close] == ")" else close
    args: List[Tuple[str, int]] = []
    depth = 0
    start = j = i + 1
    while j < inner_end:
        ch = text[j]
        if ch in "\"'`":
            j = _skip_string(text, j, inner_end)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append((text[start:j], start))
            start = j + 1
        j += 1
    args.append((text[start:inner_end], start))
    return args


_LITERAL_RX = re.compile(r"""^\s*[rbuRBU]{0,2}(['"`])((?:(?!\1)[^\\]|\\.)*)\1\s*$""", re.S)


def literal_value(expr: str) -> Optional[str]:
    """The value of a plain string literal expression, or None (also None for
    template literals with ${...})."""
    m = _LITERAL_RX.match(expr or "")
    if not m:
        return None
    if m.group(1) == "`" and "${" in m.group(2):
        return None
    return m.group(2)


def _py_string_spans(ctx: wc.ScanContext, rel: str) -> List[Tuple[int, int]]:
    """(start, end) offsets of every string literal in a Python file, so that
    code shapes quoted inside docs strings or rule data are not reported."""
    def build() -> List[Tuple[int, int]]:
        text = ctx.read(rel)
        starts = [0] + [m.end() for m in re.finditer("\n", text)]

        def off(pos: Tuple[int, int]) -> int:
            row, col = pos
            return starts[row - 1] + col if 0 < row <= len(starts) else len(text)

        spans: List[Tuple[int, int]] = []
        fstart = getattr(tokenize, "FSTRING_START", -1)
        fend = getattr(tokenize, "FSTRING_END", -1)
        open_f: List[int] = []
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.STRING:
                    spans.append((off(tok.start), off(tok.end)))
                elif tok.type == fstart:
                    open_f.append(off(tok.start))
                elif tok.type == fend and open_f:
                    spans.append((open_f.pop(), off(tok.end)))
        except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
            pass
        spans.sort()
        return spans
    return ctx.memo(("ward-secrets", "py-strings", rel), build)


def in_py_string(ctx: wc.ScanContext, rel: str, offset: int) -> bool:
    spans = _py_string_spans(ctx, rel)
    i = bisect.bisect_right(spans, (offset, 1 << 60)) - 1
    return i >= 0 and spans[i][0] <= offset < spans[i][1]


def in_js_string(line: str, col: int) -> bool:
    """True when column col of a JS line sits inside a string or after //."""
    q = ""
    i = 0
    while i < col and i < len(line):
        c = line[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = ""
        elif c in "\"'`":
            q = c
        elif c == "/" and line[i + 1:i + 2] == "/":
            return True
        i += 1
    return bool(q)


def _quoted(ctx: wc.ScanContext, rel: str, offset: int) -> bool:
    """True when offset is inside a string literal (Python: real tokens; JS and
    PHP: quote parity on the line)."""
    if rel.endswith(".py"):
        return in_py_string(ctx, rel, offset)
    text = ctx.read(rel)
    a = text.rfind("\n", 0, offset) + 1
    return in_js_string(text[a:offset + 1], offset - a)


def offset_of(ctx: wc.ScanContext, rel: str, n: int, col: int = 0) -> int:
    """Character offset of column col on line n (1-based)."""
    starts = ctx.memo(("ward-secrets", "line-starts", rel),
                      lambda: [0] + [m.end() for m in re.finditer("\n", ctx.read(rel))])
    return (starts[n - 1] if 0 < n <= len(starts) else 0) + col


def _line(ctx: wc.ScanContext, rel: str, n: int) -> str:
    ls = ctx.lines(rel)
    return ls[n - 1] if 0 < n <= len(ls) else ""


def _comment(ctx: wc.ScanContext, rel: str, n: int) -> bool:
    return wc.is_comment_line(_line(ctx, rel, n), rel)


# Known public or guessable signing values. Lowercase.
_WEAK_VALUES = frozenset({
    "secret", "secretkey", "secret-key", "secret_key", "mysecret", "my-secret", "my_secret",
    "mysecretkey", "supersecret", "super-secret", "super_secret", "supersecretkey", "topsecret",
    "keyboard cat", "shhhhh", "shhh", "changeme", "change-me", "change_me", "changethis",
    "password", "pass", "test", "testing", "dev", "development", "default", "jwt", "jwtsecret",
    "jwt-secret", "jwt_secret", "secret123", "s3cr3t", "abc123", "key", "token", "it-is-very-secret",
    "your-super-secret-jwt-token-with-at-least-32-characters-long",
    "complex_password_at_least_32_characters_long", "dev-secret", "dev_secret", "devsecret",
})
_WEAK_PREFIXES = ("django-insecure-", "your-", "your_", "change", "replace", "insecure", "dev-", "dev_",
                  "test-", "test_", "my-secret", "my_secret", "supersecret", "super-secret", "secret-")
# SHA-256 of signing keys published in framework tutorials. Hashes only.
_PUBLISHED_KEY_HASHES = {
    "570dad43de1af4c925f92c16a68a50936da42b7dd6fdeb24850507a1199aac89": "the FastAPI JWT tutorial key",
}


def weak_secret(value: str) -> bool:
    """True when a signing value is short, a placeholder, or a published example."""
    v = (value or "").strip()
    low = v.lower()
    if low in _WEAK_VALUES or low.startswith(_WEAK_PREFIXES):
        return True
    if hashlib.sha256(v.encode("utf-8", "replace")).hexdigest() in _PUBLISHED_KEY_HASHES:
        return True
    if len(v) < 16:
        return True
    if _sp is not None and _sp.is_placeholder(v):
        return True
    return False


_SERVER_DIRS = frozenset({"server", "servers", "backend", "api", "functions", "lambda", "lambdas",
                          "supabase", "netlify", "scripts", "cron", "workers", "worker", "prisma"})
_SERVER_FILE_RX = re.compile(
    r"(?:^|/)pages/api/|(?:^|/)app/(?:.*/)?api/|(?:^|/)route\.(?:js|jsx|ts|tsx|mjs)$|\.server\.[a-z]+$"
    r"|(?:^|/)\+(?:page|layout)\.server\.|(?:^|/)\+server\.|\+api\.[a-z]+$|(?:^|/)(?:src/)?(?:middleware|proxy)\.[a-z]+$")
# The block comment body cannot run past its own */, which keeps the match linear
# on files full of doc comments.
_USE_SERVER_RX = re.compile(
    r"""\A(?:\s|//[^\n]*\n|/\*(?:[^*]|\*(?!/))*\*/)*["']use server["']|import\s+["']server-only["']""")


def definitely_server(rel: str, text: str) -> bool:
    """True for files that only run on a server (API routes, server folders,
    'use server', import 'server-only')."""
    dirs = rel.split("/")[:-1]
    if dirs and dirs[0] in _SERVER_DIRS:
        return True
    if any(d in ("server", "backend") for d in dirs):
        return True
    if _SERVER_FILE_RX.search(rel):
        return True
    return bool(_USE_SERVER_RX.search(text[:4000]))


_BYOK_RX = re.compile(
    r"(?i)\b(?:localStorage|sessionStorage|AsyncStorage|SecureStore|chrome\.storage)\b[^\n]{0,80}(?:key|token)"
    r"|\bbyok\b|bring[ _-]?your[ _-]?own|\buser(?:Api)?Key\b|\bapiKeyInput\b|\bkeyInput\b|\buser_api_key\b")


# ---------------------------------------------------------------------------
# 1. Secret-shaped names behind a public env prefix
# ---------------------------------------------------------------------------

# (prefix, npm packages that make it public)
_PREFIXES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("NEXT_PUBLIC_", ("next",)),
    ("EXPO_PUBLIC_", ("expo",)),
    ("NUXT_PUBLIC_", ("nuxt",)),
    ("REACT_APP_", ("react-scripts", "@craco/craco", "react-app-rewired")),
    ("VUE_APP_", ("@vue/cli-service",)),
    ("GATSBY_", ("gatsby",)),
    ("VITE_", ("vite", "laravel-vite-plugin", "@sveltejs/kit", "astro", "nuxt", "@remix-run/dev",
               "@react-router/dev", "vitepress")),
    ("PUBLIC_", ("@sveltejs/kit", "astro")),
)
_PUBLIC_PREFIXES = tuple(p for p, _ in _PREFIXES)
_ENV_NAME_RX = re.compile(
    r"(?<![A-Za-z0-9_$])(NEXT_PUBLIC_|EXPO_PUBLIC_|NUXT_PUBLIC_|REACT_APP_|VUE_APP_|GATSBY_|VITE_|PUBLIC_)"
    r"([A-Z0-9][A-Z0-9_]*)(?![A-Za-z0-9_])")
_RN_IMPORT_RX = re.compile(r"""import\s*\{([^}]*)\}\s*from\s*['"](@env|react-native-dotenv)['"]""")
_RN_CONFIG_IMPORT_RX = re.compile(r"""import\s+(\w+)\s+from\s*['"]react-native-config['"]""")


def _active_prefixes(ctx: wc.ScanContext) -> FrozenSet[str]:
    def build() -> FrozenSet[str]:
        out: Set[str] = set()
        for prefix, pkgs in _PREFIXES:
            if any(p in ctx.deps for p in pkgs):
                out.add(prefix)
        if ctx.glob("next.config.*"):
            out.add("NEXT_PUBLIC_")
        if ctx.glob("vite.config.*"):
            out.add("VITE_")
        if ctx.has_stack("expo"):
            out.add("EXPO_PUBLIC_")
        if not ctx.glob("package.json"):
            # No manifest to go by: treat the framework prefixes as public.
            out |= {p for p in _PUBLIC_PREFIXES if p != "PUBLIC_"}
        return frozenset(out)
    return ctx.memo(("ward-secrets", "prefixes"), build)


def _env_value(line: str, name: str) -> Optional[str]:
    m = re.match(r"\s*(?:export\s+)?%s\s*[=:]\s*(.*)$" % re.escape(name), line)
    if not m:
        return None
    v = m.group(1).strip()
    if v[:1] in ("'", '"'):
        end = v.find(v[0], 1)
        return v[1:end] if end > 0 else v[1:]
    return v.split(" #", 1)[0].strip()


def _public_value(value: str) -> bool:
    v = (value or "").strip()
    if not v:
        return False
    if v.startswith(("pk_", "pk.", "sb_publishable_", "phc_")):
        return True
    return bool(_sp is not None and _sp.public_by_design(v))


def _env_public_names(ctx: wc.ScanContext) -> FrozenSet[str]:
    """Names whose value in a local env file is public by design (pk_, anon JWT, ...)."""
    def build() -> FrozenSet[str]:
        out: Set[str] = set()
        for rel in ctx.glob(*_ENV_FILES):
            for line in ctx.lines(rel):
                m = re.match(r"\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=", line)
                if m and _public_value(_env_value(line, m.group(1)) or ""):
                    out.add(m.group(1))
        return frozenset(out)
    return ctx.memo(("ward-secrets", "env-public-names"), build)


def _strip_member_chain(before: str) -> str:
    """Drop a trailing member chain such as 'process.env.' or 'env?.' from before."""
    j = len(before)
    while True:
        k = j
        while k > 0 and before[k - 1] in " \t":
            k -= 1
        if k == 0 or before[k - 1] != ".":
            break
        k -= 1
        if k > 0 and before[k - 1] == "?":
            k -= 1
        while k > 0 and before[k - 1] in " \t":
            k -= 1
        m = k
        while m > 0 and (before[m - 1].isalnum() or before[m - 1] in "_$"):
            m -= 1
        if m == k:
            break
        j = m
    return before[:j]


def _presence_only(line: str, start: int, end: int) -> bool:
    """True when the env reference at line[start:end] is only tested for being
    set (!!env.X, Boolean(X), X ? a : b, if (X), X && ...), not used as a value."""
    before = _strip_member_chain(line[:start])
    after = line[end:]
    if _BOOL_BEFORE_RX.search(before) or _BOOL_AFTER_RX.search(after):
        return True
    return bool(re.search(r"\bif\s*\(\s*$", before) and re.match(r"\s*\)", after))


def _pubenv_occurrences(rel: str, text: str, ctx: wc.ScanContext) -> List[Tuple[int, str, str, str, bool]]:
    """(line, name, kind, mechanism, value_use) for every secret-shaped public
    name in a file, one entry per name and line. value_use is False when the
    line only checks that the variable is set."""
    def build() -> List[Tuple[int, str, str, str, bool]]:
        active = _active_prefixes(ctx)
        public_names = _env_public_names(ctx)
        is_env = wc.is_env_file(rel)
        code = rel.endswith(tuple(x[1:] for x in _JS_UI))
        out: List[Tuple[int, str, str, str, bool]] = []
        seen: Set[Tuple[str, int]] = set()
        if active:
            for i, line in enumerate(ctx.lines(rel), 1):
                if "_" not in line or wc.is_comment_line(line, rel):
                    continue
                for m in _ENV_NAME_RX.finditer(line):
                    prefix, rest = m.group(1), m.group(2)
                    name = prefix + rest
                    if prefix not in active or (name, i) in seen or name in public_names:
                        continue
                    kind = classify_name(rest)
                    if kind is None:
                        continue
                    if is_env and _public_value(_env_value(line, name) or ""):
                        continue
                    seen.add((name, i))
                    value_use = not (code and _presence_only(line, m.start(), m.end()))
                    out.append((i, name, kind, prefix, value_use))
        if code:
            names_seen: Set[str] = set()
            for m in _RN_IMPORT_RX.finditer(text):
                n = ctx.line_of(rel, m.start())
                for item in m.group(1).split(","):
                    name = item.strip().split(" as ")[0].strip()
                    if name and name not in names_seen and classify_name(name):
                        names_seen.add(name)
                        out.append((n, name, classify_name(name) or "", m.group(2), True))
            cm = _RN_CONFIG_IMPORT_RX.search(text)
            if cm:
                rx = re.compile(r"\b%s\.([A-Z][A-Z0-9_]*)\b" % re.escape(cm.group(1)))
                for m in rx.finditer(text):
                    name = m.group(1)
                    n = ctx.line_of(rel, m.start())
                    if name in names_seen or _comment(ctx, rel, n):
                        continue
                    kind = classify_name(name)
                    if kind:
                        names_seen.add(name)
                        out.append((n, name, kind, "react-native-config", True))
        return out
    return ctx.memo(("ward-secrets", "pubenv-all", rel), build)


def _pubenv_scan(rel: str, text: str, ctx: wc.ScanContext) -> List[Tuple[int, str, str, str]]:
    """(line, name, kind, mechanism) for each distinct secret-shaped public name in a file."""
    def build() -> List[Tuple[int, str, str, str]]:
        out: List[Tuple[int, str, str, str]] = []
        seen: Set[str] = set()
        for n, name, kind, mech, _use in sorted(_pubenv_occurrences(rel, text, ctx)):
            if name not in seen:
                seen.add(name)
                out.append((n, name, kind, mech))
        return out
    return ctx.memo(("ward-secrets", "pubenv", rel), build)


def _pubenv_message(name: str, kind: str, mech: str) -> str:
    if mech.endswith("_"):
        how = "the %s prefix inlines its value into the client bundle" % mech
    else:
        how = "values from %s are compiled into the app bundle" % mech
    return "%s: %s, and the name says it is %s" % (name, how, _KIND_TEXT.get(kind, "a secret"))


def check_public_env_secret(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    return [Hit(n, _line(ctx, rel, n), _pubenv_message(name, kind, mech))
            for n, name, kind, mech in _pubenv_scan(rel, text, ctx) if kind in STRONG_KINDS]


# Browser log ingest tokens (Axiom, Better Stack / Logtail, Datadog RUM client
# tokens) are meant to ship to the browser when they can only send data.
_INGEST_PARTS = frozenset({"AXIOM", "LOGTAIL", "BETTERSTACK", "INGEST", "LOGFLARE"})


def _ingest_only(name: str) -> bool:
    parts = [p for p in name.upper().split("_") if p]
    if any(p in _INGEST_PARTS for p in parts) or _seq(parts, "BETTER", "STACK"):
        return True
    if parts[-1:] == ["TOKEN"] and "SOURCE" in parts:
        return True
    return ("DATADOG" in parts or "DD" in parts) and "CLIENT" in parts


_ENV_SCHEMA_RX = re.compile(r"(?i)(?:^|/)(?:env|environment|config|constants|settings)(?:\.[\w-]+)?\.[cm]?[jt]sx?$"
                            r"|(?:^|/)[^/]*env[^/]*\.[cm]?[jt]sx?$")


def _site_rank(rel: str) -> int:
    """Where a variable is best reported: its env file, then an env schema
    module, then other code, then CI and deploy config."""
    if wc.is_env_file(rel):
        return 0
    if _ENV_SCHEMA_RX.search(rel):
        return 1
    if rel.endswith(tuple(x[1:] for x in _JS_UI)):
        return 2
    if rel.endswith(".html"):
        return 3
    return 4


def _token_sites(ctx: wc.ScanContext) -> Dict[str, Tuple[str, int, str, List[Tuple[str, int]]]]:
    """name -> (file, line, mechanism, other places) for every token-shaped
    public env name in the project, so each variable is reported once."""
    def build() -> Dict[str, Tuple[str, int, str, List[Tuple[str, int]]]]:
        occ: Dict[str, List[Tuple[str, int, str, bool]]] = {}
        for rel in ctx.files:
            if not wc.match_any(rel, _PUBENV_GLOBS) or wc.match_any(rel, _NOT_SHIPPED):
                continue
            text = ctx.read(rel)
            if not text:
                continue
            for n, name, kind, mech, use in _pubenv_occurrences(rel, text, ctx):
                if kind == "token":
                    occ.setdefault(name, []).append((rel, n, mech, use))
        out: Dict[str, Tuple[str, int, str, List[Tuple[str, int]]]] = {}
        for name, items in occ.items():
            uses = [o for o in items if o[3]]
            if not uses:
                continue
            best = min(uses, key=lambda o: (_site_rank(o[0]), o[0], o[1]))
            others: List[Tuple[str, int]] = []
            files_seen = {best[0]}
            for rel, n, _mech, _use in sorted(items):
                if rel not in files_seen:
                    files_seen.add(rel)
                    others.append((rel, n))
            out[name] = (best[0], best[1], best[2], others)
        return out
    return ctx.memo(("ward-secrets", "token-sites"), build)


def check_public_env_token(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    hits: List[Hit] = []
    for name, (site, n, mech, others) in sorted(_token_sites(ctx).items()):
        if site != rel:
            continue
        also = ""
        if others:
            shown = ", ".join("%s:%d" % o for o in others[:4])
            more = " and %d more" % (len(others) - 4) if len(others) > 4 else ""
            also = " (also in %s%s)" % (shown, more)
        msg = _pubenv_message(name, "token", mech)
        if _ingest_only(name):
            hits.append(Hit(n, _line(ctx, rel, n), msg + "; it looks like a log ingest token, which is public by "
                            "design when it can only send logs: check its permissions allow ingest only" + also,
                            "info"))
        else:
            hits.append(Hit(n, _line(ctx, rel, n), msg + "; check the value is meant to be public" + also))
    return hits


# ---------------------------------------------------------------------------
# 2. Bundler config that inlines env values
# ---------------------------------------------------------------------------

_CFG_RX = re.compile(r"(?:^|/)(next|vite|webpack|craco|vue|astro|nuxt|app)\.config\.(?:js|cjs|mjs|ts|mts|cts)$")
_DEFINE_PLUGIN = (r"\bDefinePlugin\s*\(\s*\{", r"\bEnvironmentPlugin\s*\(\s*[\[{]")
_CFG_OPENERS: Dict[str, Tuple[str, ...]] = {
    "next": (r"(?<![\w$.])env\s*:\s*\{", r"\bpublicRuntimeConfig\s*:\s*\{") + _DEFINE_PLUGIN,
    "vite": (r"\bdefine\s*:\s*\{",),
    "astro": (r"\bdefine\s*:\s*\{",),
    "webpack": _DEFINE_PLUGIN,
    "craco": _DEFINE_PLUGIN,
    "vue": _DEFINE_PLUGIN,
    "nuxt": (r"\bpublic\s*:\s*\{",),
    "app": (r"\bextra\s*:\s*\{",),
}
_WHOLE_ENV_RX = re.compile(r"(?:(?<=\.\.\.)|(?<![\w.'\"`$]))process\.env(?![\w$])(?!\s*(?:\.|\[|\?\.))")
_NAMED_ENV_RX = re.compile(r"(?<![\w$])process\.env(?:\.|\?\.|\[\s*['\"`])([A-Za-z_][A-Za-z0-9_]*)")
_QUOTED_DEFINE_KEY_RX = re.compile(r"""['"](?:process\.env|import\.meta\.env)\.([A-Za-z_][A-Za-z0-9_]*)['"]\s*:""")
_OBJ_KEY_RX = re.compile(r"""(?m)^\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?\s*:""")
_QUOTED_NAME_RX = re.compile(r"""['"]([A-Z][A-Z0-9_]{2,})['"]""")
_LOADENV_ALL_RX = re.compile(r"""\bloadEnv\s*\((?:[^()]|\([^()]*\))*?,\s*(['"])\1\s*\)""")
_LOADENV_VAR_RX = re.compile(r"""(?:const|let|var)\s+(\w+)\s*=\s*loadEnv\s*\((?:[^()]|\([^()]*\))*?,\s*(['"])\2\s*\)""")


def _cfg_name_severity(name: str) -> Optional[str]:
    if not name or name.startswith(_PUBLIC_PREFIXES) or name in ("NODE_ENV",):
        return None
    # camelCase object keys are app-chosen labels: only clear secret names count.
    kind = classify_name(camel_to_upper(name), loose=name.upper() == name)
    if kind in STRONG_KINDS:
        return "critical"
    if kind == "token":
        return "high"
    if kind == "key":
        return "medium"
    return None


def check_bundler_inlines_env(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    m = _CFG_RX.search(rel)
    if not m:
        return []
    tool = m.group(1)
    if tool == "app" and not ctx.has_stack("expo"):
        return []
    openers = _CFG_OPENERS.get(tool, ())
    env_vars: Set[str] = set(v.group(1) for v in _LOADENV_VAR_RX.finditer(text))
    found: Dict[int, Tuple[str, str]] = {}
    rank = wc.SEVERITY_RANK

    def add(offset: int, sev: str, msg: str) -> None:
        n = ctx.line_of(rel, offset)
        if _comment(ctx, rel, n):
            return
        old = found.get(n)
        if old is None or rank[sev] < rank[old[0]]:
            found[n] = (sev, msg)

    for op in openers:
        for om in re.finditer(op, text):
            start = om.end() - 1
            end = block_end(text, start)
            block = text[start:end]
            is_list = text[start] == "["
            for wm in _WHOLE_ENV_RX.finditer(block):
                if block[max(0, wm.start() - 12):wm.start()].rstrip().endswith("Object.keys("):
                    continue
                add(start + wm.start(), "critical",
                    "the whole process.env is inlined into the client bundle, every server secret included")
            for var in env_vars:
                rx = re.compile(r"[:(,]\s*(?:JSON\.stringify\(\s*)?%s\s*\)?\s*(?=[,}\n])" % re.escape(var))
                for vm in rx.finditer(block):
                    add(start + vm.start(), "critical",
                        "every env var loaded with loadEnv(mode, dir, '') is inlined into the client bundle")
                for vm in re.finditer(r"(?<![\w$.])%s\.([A-Za-z_][A-Za-z0-9_]*)" % re.escape(var), block):
                    sev = _cfg_name_severity(vm.group(1))
                    if sev:
                        add(start + vm.start(), sev, "%s is inlined into the client bundle by the bundler config"
                            % vm.group(1))
            names: List[Tuple[int, str]] = [(x.start(), x.group(1)) for x in _NAMED_ENV_RX.finditer(block)]
            names += [(x.start(), x.group(1)) for x in _QUOTED_DEFINE_KEY_RX.finditer(block)]
            if is_list or "EnvironmentPlugin" in op:
                names += [(x.start(), x.group(1)) for x in _QUOTED_NAME_RX.finditer(block)]
            if tool in ("next", "nuxt", "app") and "DefinePlugin" not in op:
                for x in _OBJ_KEY_RX.finditer(block):
                    rest = block[x.end():block.find("\n", x.end()) if "\n" in block[x.end():] else len(block)]
                    if re.search(r"process\.env\.(?:%s)" % "|".join(_PUBLIC_PREFIXES), rest):
                        continue
                    names.append((x.start(1), x.group(1)))
            for off, name in names:
                sev = _cfg_name_severity(name)
                if sev:
                    add(start + off, sev, "%s is inlined into the client bundle by %s" % (name, rel.rsplit("/", 1)[-1]))
    return [Hit(n, _line(ctx, rel, n), msg, sev) for n, (sev, msg) in sorted(found.items())]


# ---------------------------------------------------------------------------
# 3. LLM SDK in browser mode, provider APIs called from client code
# ---------------------------------------------------------------------------

_DANGER_RX = re.compile(r"""dangerouslyAllowBrowser\s*:\s*true\b|['"]anthropic-dangerous-direct-browser-access['"]\s*:\s*['"]?true""")
_APIKEY_EXPR_RX = re.compile(r"""(?:\bapiKey|['"]x-api-key['"]|\bAuthorization)\s*:\s*([^\n]+)""")
_APIKEY_SHORTHAND_RX = re.compile(r"""[{,]\s*apiKey\s*[,}\n]""")
_BUILD_TIME_RX = re.compile(r"""import\.meta\.env|process\.env|\bConstants\b|expoConfig|\bConfig\.|^\s*['"`]""")


def _key_source(expr: str, text: str, env_imports: Set[str]) -> str:
    """'build' (env, config or literal), 'user' (typed in at runtime) or 'unknown'."""
    e = expr.strip()
    if _BYOK_RX.search(e):
        return "user"
    if e[:1] == "`" and "${" in e:
        inner = re.search(r"\$\{([^}]*)\}", e)
        return _key_source(inner.group(1), text, env_imports) if inner else "unknown"
    if _BUILD_TIME_RX.search(e):
        return "build"
    ident = re.match(r"([A-Za-z_$][\w$]*)", e)
    if ident and ident.group(1) in env_imports:
        return "build"
    return "unknown"


def check_llm_sdk_in_browser(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    if definitely_server(rel, text) or _BYOK_RX.search(text):
        return []
    env_imports: Set[str] = set()
    for m in _RN_IMPORT_RX.finditer(text):
        env_imports |= {x.strip().split(" as ")[-1].strip() for x in m.group(1).split(",") if x.strip()}
    hits: List[Hit] = []
    for m in _DANGER_RX.finditer(text):
        n = ctx.line_of(rel, m.start())
        if _comment(ctx, rel, n) or _quoted(ctx, rel, m.start()):
            continue
        lo = max(0, n - 13)
        window = "\n".join(ctx.lines(rel)[lo:n + 3])
        src = "unknown"
        em = None
        for em in _APIKEY_EXPR_RX.finditer(window):
            pass
        if em is not None:
            src = _key_source(em.group(1), text, env_imports)
        elif _APIKEY_SHORTHAND_RX.search(window):
            dm = re.search(r"(?:const|let|var)\s+apiKey\s*=\s*([^\n;]+)", text)
            if dm:
                src = _key_source(dm.group(1), text, env_imports)
        if src == "user":
            continue
        if src == "build":
            hits.append(Hit(n, _line(ctx, rel, n), "LLM SDK runs in the browser with a key from the build or "
                            "the source, so every visitor can read the key", "critical"))
        else:
            hits.append(Hit(n, _line(ctx, rel, n), "LLM SDK is switched into browser mode; unless each user "
                            "types in their own key, the key ships to every visitor", "medium"))
    return hits


_PROVIDER_HOSTS = (
    r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.mistral\.ai"
    r"|openrouter\.ai/api|api\.deepseek\.com|api\.x\.ai|api\.cohere\.(?:ai|com)|api\.replicate\.com"
    r"|api\.elevenlabs\.io|api\.perplexity\.ai|api\.together\.(?:xyz|ai)|api\.fireworks\.ai"
    r"|api\.sendgrid\.com|api\.resend\.com|api\.postmarkapp\.com|api\.mailgun\.net|api\.twilio\.com")


# ---------------------------------------------------------------------------
# 4. Endpoints and props that send the server environment to the client
# ---------------------------------------------------------------------------

_JS_SINK_RX = re.compile(
    r"\b(?:res|resp|response|reply|ctx|c)\s*(?:\.\s*(?:status|code)\s*\(\s*\d+\s*\)\s*)?\.\s*(?:json|jsonp|send|end|write)\s*\("
    r"|\b(?:Response|NextResponse)\s*\.\s*json\s*\("
    r"|\bnew\s+Response\s*\("
    r"|(?<![\w.$])json\s*\("
    r"|\bprops\s*:\s*(?=[{(]|process\b)"
    r"|\bctx\.body\s*=\s*")
_JSX_PROP_RX = re.compile(r"""(?<![\w$])[A-Za-z][\w-]*\s*=\s*\{\s*process\.env\.([A-Z][A-Z0-9_]*)\s*\}""")
_BOOL_BEFORE_RX = re.compile(r"(?:!\s*|\bBoolean\s*\(\s*|\btypeof\s+)$")
_BOOL_AFTER_RX = re.compile(r"^\s*(?:===|!==|==|!=|\?(?![.?])|&&|\.length\b|\.(?:startsWith|endsWith|includes|slice|substring|substr)\b)")

_PY_RESP = (r"(?:jsonify|JSONResponse|JsonResponse|ORJSONResponse|UJSONResponse|make_response|HttpResponse"
            r"|PlainTextResponse|Response)")
_PY_DUMP_TARGET = (r"(?:\{[^}\n]*:\s*)?(?:json\.dumps\s*\(\s*)?(?:dict\s*\(\s*)?(?:\*\*\s*)?"
                   r"(?:os\.environ(?:\.copy\(\s*\))?|app\.config|current_app\.config|settings\.__dict__|vars\(\s*settings\s*\)"
                   r"|settings\.(?:dict|model_dump)\(\s*\))(?![\w.\[])(?!\s*,)")
_PY_RESP_DUMP_RX = re.compile(r"\b" + _PY_RESP + r"\s*\(\s*" + _PY_DUMP_TARGET)
_PY_RETURN_DUMP_RX = re.compile(r"^\s*return\s+" + _PY_DUMP_TARGET)
_PY_NAMED_RX = re.compile(r"""os\.(?:environ\.get|getenv)\(\s*['"](\w+)['"]|os\.environ\[\s*['"](\w+)['"]\s*\]""")
_PY_SEND_LINE_RX = re.compile(r"\breturn\b|\b" + _PY_RESP + r"\s*\(")
_PHP_DUMP_RX = re.compile(
    r"\bphpinfo\s*\(\s*\)"
    r"|\b(?:json_encode|var_dump|print_r|var_export)\s*\(\s*(?:\$_ENV|\$_SERVER|getenv\s*\(\s*\))(?![\w\[])"
    r"|response\(\)\s*->\s*json\s*\(\s*(?:\$_ENV|\$_SERVER|getenv\s*\(\s*\)|config\s*\(\s*\))(?![\w\[])")
_JINJA_CONFIG_RX = re.compile(r"\{\{\s*config\s*(?:\|\s*(?:tojson|safe|pprint)\s*)*\}\}")
_EJS_ENV_RX = re.compile(r"<%[-=]\s*(?:JSON\.stringify\s*\(\s*)?process\.env\s*\)?\s*%>")


def _strong_name(name: str) -> bool:
    return not name.startswith(_PUBLIC_PREFIXES) and classify_name(name) in STRONG_KINDS


def _value_context(region: str, start: int, end: int) -> bool:
    """False when an env reference is only tested (!!x, x === y, x ? a : b, ...)."""
    return not (_BOOL_BEFORE_RX.search(region[max(0, start - 12):start]) or _BOOL_AFTER_RX.search(region[end:end + 16]))


# Calls that hand their argument through unchanged (or merely encoded), so a
# secret inside them still reaches the client. Matched on the last name part.
_PASSTHROUGH = frozenset({
    "String", "stringify", "parse", "encodeURIComponent", "encodeURI", "btoa", "from", "toString", "trim",
    "assign", "entries", "fromEntries", "values", "structuredClone", "str", "dict", "dumps", "repr",
    "jsonify", "JSONResponse", "JsonResponse", "ORJSONResponse", "UJSONResponse", "make_response",
    "HttpResponse", "PlainTextResponse", "Response", "json", "send",
})
_NOT_CALLEES = frozenset({"if", "for", "while", "switch", "return", "await", "typeof", "catch", "function",
                          "async", "yield", "in", "of", "and", "or", "not", "else", "elif", "print"})
_CALLEE_RX = re.compile(r"([A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)*)\s*$")


def _callee(s: str, i: int) -> str:
    """Name of the function called by the ( at s[i], or '' for a plain group."""
    m = _CALLEE_RX.search(s[max(0, i - 80):i])
    if not m:
        return ""
    name = re.sub(r"\s+", "", m.group(1)).replace("?.", ".")
    last = name.rsplit(".", 1)[-1]
    return "" if last in _NOT_CALLEES else name


def call_context(s: str, k: int, py: bool = False) -> Tuple[bool, List[str]]:
    """Walk s up to index k. Returns (k sits in the text part of a string,
    callees of the call parentheses still open at k, outermost first).
    JS template ${...} bodies count as code. A ( at index 0 is the sink call
    itself and is left out."""
    opens: List[Tuple[str, str, int]] = []
    q = ""
    tmpl_text = False
    i = 0
    while i < k:
        c = s[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q or (c == "\n" and not py):
                q = ""
            i += 1
            continue
        if tmpl_text:
            if c == "\\":
                i += 2
                continue
            if c == "`":
                tmpl_text = False
            elif c == "$" and s[i + 1:i + 2] == "{":
                opens.append(("${", "", i))
                tmpl_text = False
                i += 2
                continue
            i += 1
            continue
        if c in "'\"":
            q = c
        elif c == "`" and not py:
            tmpl_text = True
        elif c == "#" and py:
            nl = s.find("\n", i)
            i = k if nl == -1 else nl
            continue
        elif c == "/" and s[i + 1:i + 2] == "/" and not py:
            nl = s.find("\n", i)
            i = k if nl == -1 else nl
            continue
        elif c in "([{":
            opens.append((c, _callee(s, i) if c == "(" else "", i))
        elif c in ")]}" and opens:
            ch = opens.pop()[0]
            if ch == "${":
                tmpl_text = True
        i += 1
    callees = [name for ch, name, pos in opens if ch == "(" and pos > 0]
    return bool(q) or tmpl_text, callees


def _passed_through(callees: Sequence[str]) -> bool:
    """True when every enclosing call only hands the value on (String(x),
    JSON.stringify(x), ...). A secret passed to jwt.sign or createHmac is used,
    not sent."""
    return all((not c) or c.rsplit(".", 1)[-1] in _PASSTHROUGH for c in callees)


def _js_env_sent(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    hits: List[Hit] = []
    if "process" not in text and "props" not in text:
        return hits
    for sm in _JS_SINK_RX.finditer(text):
        if _quoted(ctx, rel, sm.start()):
            continue
        i = sm.end()
        if text[i - 1:i] == "(":
            start, end = i - 1, block_end(text, i - 1, 3000)
        else:
            j = i
            while j < len(text) and text[j] in " \t":
                j += 1
            if j < len(text) and text[j] in "{(":
                start, end = j, block_end(text, j, 3000)
            else:
                nl = text.find("\n", j)
                start, end = j, (len(text) if nl == -1 else nl)
        region = text[start:end]
        if "process.env" not in region:
            continue
        for wm in _WHOLE_ENV_RX.finditer(region):
            before = region[max(0, wm.start() - 14):wm.start()]
            if re.search(r"Object\.keys\(\s*$", before):
                continue
            in_text, callees = call_context(region, wm.start())
            if in_text or not _passed_through(callees):
                continue
            hits.append(Hit(ctx.line_of(rel, start + wm.start()), "",
                            "sends the whole process.env to the client, every server secret included"))
        for nm in _NAMED_ENV_RX.finditer(region):
            name = nm.group(1)
            if not (_strong_name(name) and _value_context(region, nm.start(), nm.end())):
                continue
            in_text, callees = call_context(region, nm.start())
            if in_text or not _passed_through(callees):
                continue
            hits.append(Hit(ctx.line_of(rel, start + nm.start()), "",
                            "sends %s (%s) to the client" % (name, _KIND_TEXT[classify_name(name) or "secret"])))
    if rel.endswith((".jsx", ".tsx")):
        for jm in _JSX_PROP_RX.finditer(text):
            if _strong_name(jm.group(1)) and not _quoted(ctx, rel, jm.start()):
                hits.append(Hit(ctx.line_of(rel, jm.start()), "",
                                "renders %s into a component prop, so it lands in the HTML or the RSC payload"
                                % jm.group(1)))
    return hits


_PY_DEF_RX = re.compile(r"^\s*(?:async\s+)?def\s+\w+\s*\(([^)]*)")
_PY_ROUTE_DECO_RX = re.compile(r"^\s*@\w+(?:\.\w+)*\.(?:get|post|put|patch|delete|route|api_route|websocket)\s*\(|^\s*@api_view")


def _in_route(lines: Sequence[str], i: int) -> bool:
    """True when line i (1-based) sits in a function that looks like a request
    handler: a route decorator above the def, or a request parameter."""
    for k in range(i - 1, max(-1, i - 81), -1):
        dm = _PY_DEF_RX.match(lines[k])
        if not dm:
            continue
        if re.search(r"\brequest\b", dm.group(1)):
            return True
        for j in range(k - 1, max(-1, k - 6), -1):
            if _PY_ROUTE_DECO_RX.match(lines[j]):
                return True
            if not lines[j].strip().startswith("@"):
                break
        return False
    return False


def _py_env_sent(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    hits: List[Hit] = []
    if "os.environ" not in text and "os.getenv" not in text and "config" not in text and "settings" not in text:
        return hits
    lines = ctx.lines(rel)
    for i, line in enumerate(lines, 1):
        dm = _PY_RESP_DUMP_RX.search(line) or (_in_route(lines, i) and _PY_RETURN_DUMP_RX.search(line))
        if dm:
            if not in_py_string(ctx, rel, offset_of(ctx, rel, i, dm.start())):
                hits.append(Hit(i, line, "returns the whole environment or app config, every server secret included"))
            continue
        if not _PY_SEND_LINE_RX.search(line) or not _in_route(lines, i):
            continue
        for nm in _PY_NAMED_RX.finditer(line):
            name = nm.group(1) or nm.group(2)
            if in_py_string(ctx, rel, offset_of(ctx, rel, i, nm.start())):
                continue
            before = line[max(0, nm.start() - 10):nm.start()]
            after = line[nm.end():nm.end() + 20]
            if re.search(r"(?:bool\s*\(|not\s+)$", before) or re.search(r"^[^)]*\)\s*(?:is\s|==|!=)", after):
                continue
            if not _passed_through(call_context(line, nm.start(), py=True)[1]):
                continue
            if _strong_name(name):
                hits.append(Hit(i, line, "returns %s (%s) to the client" % (name, _KIND_TEXT[classify_name(name) or "secret"])))
    return hits


def check_env_sent_to_client(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    hits: List[Hit] = []
    if rel.endswith(tuple(x[1:] for x in _JS_UI)):
        hits = _js_env_sent(rel, text, ctx)
    elif rel.endswith(".py"):
        hits = _py_env_sent(rel, text, ctx)
    elif rel.endswith(".php"):
        for i, line in enumerate(ctx.lines(rel), 1):
            pm = _PHP_DUMP_RX.search(line)
            if pm and not in_js_string(line, pm.start()):
                hits.append(Hit(i, line, "prints or returns the whole environment (phpinfo, $_ENV, $_SERVER, getenv())"))
    elif rel.endswith(".ejs"):
        for i, line in enumerate(ctx.lines(rel), 1):
            if _EJS_ENV_RX.search(line):
                hits.append(Hit(i, line, "renders the whole process.env into the page"))
    elif rel.endswith((".html", ".jinja", ".jinja2", ".j2")):
        if ctx.has_stack("flask") and "templates/" in "/" + rel:
            for i, line in enumerate(ctx.lines(rel), 1):
                if _JINJA_CONFIG_RX.search(line):
                    hits.append(Hit(i, line, "renders the whole Flask config (SECRET_KEY included) into the page"))
    out: List[Hit] = []
    seen: Set[int] = set()
    for h in hits:
        if h.line in seen or _comment(ctx, rel, h.line):
            continue
        seen.add(h.line)
        out.append(Hit(h.line, h.evidence or _line(ctx, rel, h.line), h.message))
    return out


# ---------------------------------------------------------------------------
# 5. Firebase Admin SDK or a service account file on the client side
# ---------------------------------------------------------------------------

_ADMIN_IMPORT_RX = re.compile(
    r"""(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*|^\s*import\s+)['"](firebase-admin(?:/[\w-]+)?)['"]""", re.M)
_SA_IMPORT_RX = re.compile(
    r"""(?:\bfrom\s+|\brequire\s*\(\s*|\bimport\s*\(\s*)['"]([^'"\n]*(?:service[-_]?account|adminsdk)[^'"\n]*\.json)['"]""",
    re.I)
_SA_NAME_RX = re.compile(r"(?i)(?:service[-_]?account|firebase[-_]adminsdk|adminsdk)[^/]*\.json$")
_SA_TYPE_RX = re.compile(r'"type"\s*:\s*"service_account"')
_SERVED_DIRS = frozenset({"public", "static", "www", "wwwroot", "htdocs", "public_html"})


def _nested_package(ctx: wc.ScanContext, rel: str) -> Optional[str]:
    """Folder (with trailing /) of the nearest package.json above rel, when it
    is not the project root."""
    parts = rel.split("/")[:-1]
    while parts:
        d = "/".join(parts) + "/"
        if ctx.exists(d + "package.json"):
            return d
        parts.pop()
    return None


def _server_package_not_imported(ctx: wc.ScanContext, rel: str) -> bool:
    """True when rel belongs to a nested server-side package (generated admin
    SDK code such as Firebase Data Connect's dataconnect-admin-generated, or any
    package that depends on firebase-admin) that no client file outside it
    imports. Such a package sits under src/ but never reaches the bundle."""
    pkg_dir = _nested_package(ctx, rel)
    if pkg_dir is None:
        return False

    def build() -> bool:
        data = ctx.json(pkg_dir + "package.json")
        data = data if isinstance(data, dict) else {}
        name = data.get("name") if isinstance(data.get("name"), str) else ""
        deps: Set[str] = set()
        for section in ("dependencies", "peerDependencies", "optionalDependencies"):
            block = data.get(section)
            if isinstance(block, dict):
                deps.update(block)
        folder = pkg_dir.rstrip("/").rsplit("/", 1)[-1]
        server_pkg = ("admin-generated" in name or "admin-generated" in folder or "firebase-admin" in deps)
        if not server_pkg:
            return False
        needles = ["/%s/" % folder, "/%s'" % folder, '/%s"' % folder]
        if name:
            needles += ["'%s" % name, '"%s' % name, "`%s" % name]
        for f in ctx.client_files:
            if f.startswith(pkg_dir):
                continue
            t = ctx.read(f)
            if any(n in t for n in needles):
                return False
        return True
    return bool(ctx.memo(("ward-secrets", "server-package", pkg_dir), build))


def check_admin_sdk_client(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    if rel.endswith(".json"):
        if not any(d in _SERVED_DIRS for d in rel.split("/")[:-1]):
            return []
        tm = _SA_TYPE_RX.search(text)
        if (tm and '"private_key"' in text) or _SA_NAME_RX.search(rel):
            n = ctx.line_of(rel, tm.start()) if tm else 1
            return [Hit(n, _line(ctx, rel, n), "service account key file sits in a folder the web server serves")]
        return []
    if not ctx.is_client_file(rel):
        return []
    if _server_package_not_imported(ctx, rel):
        return []
    hits: List[Hit] = []
    for m in _ADMIN_IMPORT_RX.finditer(text):
        n = ctx.line_of(rel, m.start(1))
        if not _comment(ctx, rel, n):
            hits.append(Hit(n, _line(ctx, rel, n), "Firebase Admin SDK imported in client code; it needs a "
                            "service account that grants full access to the project"))
    for m in _SA_IMPORT_RX.finditer(text):
        n = ctx.line_of(rel, m.start(1))
        if not _comment(ctx, rel, n):
            hits.append(Hit(n, _line(ctx, rel, n), "service account JSON imported in client code, so its "
                            "private key ships in the bundle"))
    return hits


# ---------------------------------------------------------------------------
# 6. Signing secrets with a literal fallback
# ---------------------------------------------------------------------------

_STR = r"""(['"`])((?:(?!\{q})[^\\\n]|\\.){1,300})\{q}"""


def _lit(group: int) -> str:
    return _STR.replace("{q}", str(group))


_FALLBACK_RXS: Dict[str, List["re.Pattern[str]"]] = {
    "js": [
        re.compile(r"""(?<![\w$])(?:process\.env|import\.meta\.env)(?:\.|\?\.|\[\s*['"])([A-Za-z_][A-Za-z0-9_]*)['"]?\s*\]?\s*(?:\|\||\?\?)\s*""" + _lit(2)),
    ],
    "py": [
        re.compile(r"""os\.(?:environ\.get|getenv)\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*(?:default\s*=\s*)?[rbu]?""" + _lit(2)),
        re.compile(r"""os\.environ\.setdefault\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*[rbu]?""" + _lit(2)),
        re.compile(r"""(?<![\w.])(?:config|env(?:\.str)?)\(\s*['"]([A-Z][A-Z0-9_]*)['"]\s*,\s*default\s*=\s*[rbu]?""" + _lit(2)),
    ],
    "php": [
        re.compile(r"""(?<![\w>$])env\(\s*['"]([A-Z][A-Z0-9_]*)['"]\s*,\s*""" + _lit(2) + r"""\s*\)"""),
        re.compile(r"""getenv\(\s*['"](\w+)['"]\s*\)\s*\?:\s*""" + _lit(2)),
        re.compile(r"""\$_(?:ENV|SERVER)\[\s*['"](\w+)['"]\s*\]\s*\?\?\s*""" + _lit(2)),
    ],
    "compose": [
        re.compile(r"""\$\{([A-Z][A-Z0-9_]*):?-([^}\n]{1,200})\}"""),
    ],
}
_JS_DESTRUCT_RX = re.compile(r"""\{([^{}]{1,2000})\}\s*=\s*process\.env\b""")
_JS_DEFAULT_RX = re.compile(r"""\b([A-Z][A-Z0-9_]*)\s*=\s*""" + _lit(2))
_PYDANTIC_FIELD_RX = re.compile(
    r"""^\s+([a-z_][a-z0-9_]*)\s*:\s*(?:str|SecretStr|Optional\[str\]|bytes)\s*=\s*(?:SecretStr\(\s*)?[rbu]?""" + _lit(2))
_GUARD_RX = re.compile(r"\bthrow\b|\braise\b|process\.exit|sys\.exit|\babort\s*\(|ImproperlyConfigured")
_PROD_RX = re.compile(r"production|NODE_ENV|APP_ENV|\bDEBUG\b|\bENV\b")


def _family(rel: str) -> Optional[str]:
    name = rel.rsplit("/", 1)[-1].lower()
    if name.startswith(("docker-compose", "compose.")) or name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "compose"
    if rel.endswith(".py"):
        return "py"
    if rel.endswith(".php"):
        return "php"
    if rel.endswith(tuple(x[1:] for x in _JS_UI)):
        return "js"
    return None


def _guarded(ctx: wc.ScanContext, rel: str, n: int) -> bool:
    window = ctx.window(rel, n, 4, 4)
    return bool(_GUARD_RX.search(window) and _PROD_RX.search(window))


# A fallback password only matters when it guards a way in (an admin login),
# not when it is the app's own credential for a local database or SMTP.
_INBOUND = frozenset({"ADMIN", "DASHBOARD", "BASIC", "AUTH", "LOGIN", "SITE", "APP", "PANEL", "MASTER",
                      "SUPERUSER", "UI", "OWNER", "STAFF"})


def _fallback_kind_ok(name: str, fam: str) -> bool:
    up = camel_to_upper(name)
    kind = classify_name(up)
    if kind not in FALLBACK_KINDS:
        return False
    if kind == "password":
        return any(p in _INBOUND for p in up.split("_"))
    if fam == "compose":
        return kind in ("signing", "secret", "admin", "private")
    return True


# Compose files and Dockerfiles named for a dev, local, test or CI stack.
_DEV_STACK_RX = re.compile(
    r"(?i)(?:^|/)(?:(?:docker-)?compose[.-](?:dev|development|local|test|testing|e2e|ci)(?:[.-][\w-]+)?\.ya?ml"
    r"|dockerfile[.-](?:dev|development|local|test)|(?:dev|development|local|test)\.dockerfile)$")
# Docker Compose loads compose.override.yml next to the main file by default; it usually holds dev settings.
_OVERRIDE_STACK_RX = re.compile(r"(?i)(?:^|/)(?:docker-)?compose\.override\.ya?ml$")


def _mask_literal(line: str, value: str) -> str:
    """line with the literal value masked (quoted occurrences first), so short
    secrets that the generic redaction misses never reach the evidence."""
    if not value:
        return line
    masked = wc.mask(value)
    out, n = re.subn(r"""(['"`])%s\1""" % re.escape(value), lambda m: m.group(1) + masked + m.group(1), line)
    if n:
        return out
    return line.replace(value, masked) if len(value) >= 3 else line


def check_secret_fallback(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    fam = _family(rel)
    if fam is None:
        return []
    if fam == "compose" and _DEV_STACK_RX.search(rel):
        return []
    override = fam == "compose" and bool(_OVERRIDE_STACK_RX.search(rel))
    cands: List[Tuple[int, str, str]] = []
    for rx in _FALLBACK_RXS.get(fam, []):
        for m in rx.finditer(text):
            value = m.group(3) if fam != "compose" else m.group(2)
            cands.append((m.start(), m.group(1), value))
    if fam == "js":
        for dm in _JS_DESTRUCT_RX.finditer(text):
            for km in _JS_DEFAULT_RX.finditer(dm.group(1)):
                cands.append((dm.start(1) + km.start(), km.group(1), km.group(3)))
    if fam == "py" and "BaseSettings" in text:
        for i, line in enumerate(ctx.lines(rel), 1):
            pm = _PYDANTIC_FIELD_RX.match(line)
            if pm:
                cands.append((offset_of(ctx, rel, i, pm.start(1)), pm.group(1), pm.group(3)))
    hits: List[Hit] = []
    seen: Set[int] = set()
    for off, name, value in sorted(cands):
        if not value.strip() or value.strip().startswith("${"):
            continue
        if not _fallback_kind_ok(name, fam) or lookup_name(name, value):
            continue
        n = ctx.line_of(rel, off)
        if n in seen or _comment(ctx, rel, n) or _guarded(ctx, rel, n):
            continue
        if fam != "compose" and _quoted(ctx, rel, off):
            continue
        seen.add(n)
        evidence = _mask_literal(_line(ctx, rel, n), value)
        if override:
            hits.append(Hit(n, evidence, "%s falls back to a literal in compose.override, which Docker Compose loads "
                            "by default next to the main file; fine for a dev-only stack, but make sure the server "
                            "does not have this file" % name, "low"))
        elif weak_secret(value):
            hits.append(Hit(n, evidence, "%s falls back to a guessable literal when the env var is "
                            "missing, and that value then signs or protects production data" % name, "critical"))
        else:
            hits.append(Hit(n, evidence, "%s falls back to a literal kept in the source when the env "
                            "var is missing" % name))
    return hits


# ---------------------------------------------------------------------------
# 7. Signing secrets hardcoded as literals
# ---------------------------------------------------------------------------

_JWT_CALL_RX = re.compile(r"\b(?:jwt|jsonwebtoken|JWT|jose)\s*\.\s*(?:sign|verify|encode|decode)\s*\(")
_TEXT_ENCODER_RX = re.compile(r"""new\s+TextEncoder\(\s*\)\s*\.\s*encode\(\s*(['"`])((?:(?!\1)[^\\\n]|\\.){1,300})\1\s*\)""")
_COOKIE_PARSER_RX = re.compile(r"""\bcookieParser\(\s*(['"`])((?:(?!\1)[^\\\n]|\\.){1,300})\1""")
_AUTH_LIB_RX = re.compile(
    r"""['"](?:next-auth[^'"]*|@auth/[^'"]+|better-auth[^'"]*|express-session|cookie-session|cookie-parser"""
    r"""|@fastify/(?:session|secure-session|jwt|cookie)|fastify-jwt|hono/jwt|hono/cookie|koa-session|koa-jwt"""
    r"""|iron-session|jsonwebtoken|jose|passport-jwt|express-jwt|@nestjs/jwt|lucia)['"]""")
_JS_SECRET_KEY_RX = re.compile(
    r"""(?<![\w$.])(secret|secretOrKey|secretOrPrivateKey|jwtSecret|sessionSecret|cookieSecret|signingSecret|signingKey|authSecret)"""
    r"""\s*:\s*\[?\s*""" + _lit(2))
_JS_CONST_RX = re.compile(r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*\w+\s*)?=\s*""" + _lit(2))
_HMAC_JS_RX = re.compile(r"\bcreateHmac\s*\(")
_HMAC_PY_RX = re.compile(r"\bhmac\s*\.\s*(?:new|digest)\s*\(")
_CONFIG_PATH_RX = re.compile(
    r"(?i)(?:^|/)(?:config|configs|conf|settings)/"
    r"|(?:^|/)[^/]*(?:config|settings|keys|secrets|constants|env)[^/]*\.[cm]?[jt]sx?$")
_PY_ASSIGN_RX = re.compile(
    r"""^\s*((?:app|application|self|cls)\.)?([A-Za-z_][A-Za-z0-9_]*)\s*(:\s*[\w\[\]]+\s*)?=\s*[rbuRBU]{0,2}(['"])(.{1,300}?)\4\s*(?:#.*)?$""")
_PY_CONFIG_SET_RX = re.compile(
    r"""\b(?:app|application)\.config\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\]\s*=\s*[rbuRBU]{0,2}(['"])(.{1,300}?)\2""")
_PY_CONFIG_UPDATE_RX = re.compile(
    r"""\bapp\.config\.(?:update|from_mapping)\s*\([^)\n]*?\b([A-Z_][A-Z0-9_]*)\s*=\s*[rbuRBU]{0,2}(['"])(.{1,300}?)\2""")
_PY_SIGNING = frozenset({"SECRET_KEY", "SECRET", "APP_SECRET", "APP_SECRET_KEY", "FLASK_SECRET_KEY",
                         "DJANGO_SECRET_KEY", "SECURITY_PASSWORD_SALT", "WTF_CSRF_SECRET_KEY"})


_TOKEN_SECRET_PARTS = frozenset({"ACCESS", "REFRESH", "JWT", "AUTH", "APP", "API", "ID", "TOKEN", "SECRET"})


def _signing_name(name: str) -> bool:
    up = camel_to_upper(name)
    if up in _PY_SIGNING or classify_name(up) == "signing":
        return True
    parts = [p for p in up.split("_") if p]
    # SECRET_KEY_HMAC, SECRET_KEY_JWT: Flask and FastAPI apps keep several signing keys this way.
    if up.startswith("SECRET_KEY_") and not any(p in ("ID", "NAME", "PATH", "FILE", "URL", "LEN", "LENGTH")
                                                for p in parts):
        return True
    # TOKEN_SECRET, ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET: the key that signs the app's tokens.
    return parts[-2:] == ["TOKEN", "SECRET"] and all(p in _TOKEN_SECRET_PARTS for p in parts)


_NAME_LIKE_RX = re.compile(r"_?[a-z][a-z0-9]*(?:[._:-][a-z0-9]+)*")


def lookup_name(var: str, value: str) -> bool:
    """True when an ambiguous *_KEY constant (SESSION_KEY, JWT_KEY, ...) holds
    a storage or cookie name such as 'user_session', not a signing key."""
    up = camel_to_upper(var)
    if up in _PY_SIGNING or up in _SIGNING_NAMES or up.split("_")[-1] != "KEY":
        return False
    v = value.strip()
    if len(v) > 40 or not _NAME_LIKE_RX.fullmatch(v) or sum(c.isdigit() for c in v) > 2:
        return False
    return not re.search(r"secret|change|passw|insecure", v)


def _literal_hit(ctx: wc.ScanContext, rel: str, offset: int, value: str, what: str) -> Optional[Hit]:
    n = ctx.line_of(rel, offset)
    if not value or "${" in value or value.startswith(("{{", "%(")) or _comment(ctx, rel, n):
        return None
    if _quoted(ctx, rel, offset):
        return None
    evidence = _mask_literal(_line(ctx, rel, n), value)
    if weak_secret(value):
        return Hit(n, evidence, "%s is a guessable or published value; anyone can forge tokens or "
                   "sessions with it" % what, "critical")
    return Hit(n, evidence, "%s is hardcoded in the source; anyone who can read the code can forge "
               "tokens or sessions" % what)


def _js_literal_secrets(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    hits: List[Optional[Hit]] = []
    for m in _JWT_CALL_RX.finditer(text):
        args = split_args(text, m.end() - 1)
        if len(args) >= 2:
            arg, off = args[1]
            value = literal_value(arg)
            if value is not None:
                if not _quoted(ctx, rel, m.start()):
                    hits.append(_literal_hit(ctx, rel, off + len(arg) - len(arg.lstrip()), value,
                                             "the JWT signing secret"))
    for m in _TEXT_ENCODER_RX.finditer(text):
        if re.search(r"(?i)secret|jwt|signing|key", _line(ctx, rel, ctx.line_of(rel, m.start()))):
            hits.append(_literal_hit(ctx, rel, m.start(), m.group(2), "the signing key"))
    for m in _COOKIE_PARSER_RX.finditer(text):
        hits.append(_literal_hit(ctx, rel, m.start(), m.group(2), "the cookie signing secret"))
    for m in _HMAC_JS_RX.finditer(text):
        args = split_args(text, m.end() - 1)
        if len(args) >= 2:
            arg, off = args[1]
            value = literal_value(arg)
            if value is not None and not _quoted(ctx, rel, m.start()):
                hits.append(_literal_hit(ctx, rel, off + len(arg) - len(arg.lstrip()), value, "the HMAC key"))
    auth = bool(_AUTH_LIB_RX.search(text))
    # A config module that only exports values has no auth import; the names say what they are.
    config = bool(_CONFIG_PATH_RX.search(rel))
    for m in _JS_SECRET_KEY_RX.finditer(text):
        if not (auth or config):
            # Outside auth code and config modules only the unambiguous names count
            # (jwtSecret, cookieSecret, ...), and not when the value is a field name.
            value = m.group(3)
            if m.group(1) == "secret" or (_NAME_LIKE_RX.fullmatch(value) and value.lower() not in _WEAK_VALUES):
                continue
        hits.append(_literal_hit(ctx, rel, m.start(), m.group(3), "the %s value" % m.group(1)))
    if auth or config:
        for m in _JS_CONST_RX.finditer(text):
            if _signing_name(m.group(1)) and not lookup_name(m.group(1), m.group(3)):
                hits.append(_literal_hit(ctx, rel, m.start(), m.group(3), m.group(1)))
    return [h for h in hits if h is not None]


def _py_literal_secrets(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    hits: List[Optional[Hit]] = []
    pydantic = "BaseSettings" in text
    for i, line in enumerate(ctx.lines(rel), 1):
        if "=" not in line:
            continue
        am = _PY_ASSIGN_RX.match(line)
        if am and _signing_name(am.group(2)) and not (pydantic and am.group(3)):
            name = am.group(2)
            if lookup_name(name, am.group(5)):
                continue
            later = re.compile(r"(?m)^\s*(?:app\.)?%s\s*=\s*(?!['\"rbuRBU]{0,2}['\"])\S" % re.escape(name))
            if not later.search(text):
                hit = _literal_hit(ctx, rel, offset_of(ctx, rel, i, am.start(2)), am.group(5), name)
                over = _prod_override(ctx, rel, name) if hit is not None else None
                if over is not None:
                    prod, selected = over
                    if selected:
                        continue
                    hit = Hit(hit.line, hit.evidence, "%s is a literal in %s, but %s replaces it from the environment; "
                              "it only matters where these base settings are loaded directly, so check "
                              "DJANGO_SETTINGS_MODULE in wsgi.py, manage.py and the deploy config"
                              % (name, rel.rsplit("/", 1)[-1], prod.rsplit("/", 1)[-1]), "medium")
                hits.append(hit)
            continue
        for rx in (_PY_CONFIG_SET_RX, _PY_CONFIG_UPDATE_RX):
            cm = rx.search(line)
            if cm and _signing_name(cm.group(1)):
                hits.append(_literal_hit(ctx, rel, offset_of(ctx, rel, i, cm.start()), cm.group(3), cm.group(1)))
                break
    for m in re.finditer(r"\bjwt\s*\.\s*(?:encode|decode)\s*\(", text):
        args = split_args(text, m.end() - 1)
        if len(args) >= 2:
            value = literal_value(args[1][0])
            if value is not None:
                hits.append(_literal_hit(ctx, rel, m.start(), value, "the JWT signing key"))
    for m in _HMAC_PY_RX.finditer(text):
        args = split_args(text, m.end() - 1)
        if args:
            value = literal_value(args[0][0])
            if value is not None:
                hits.append(_literal_hit(ctx, rel, m.start(), value, "the HMAC key"))
    return [h for h in hits if h is not None]


_PROD_SETTINGS_RX = re.compile(r"(?i)^(?:prod|production|live|deploy|deployment)\w*\.py$")
_DEPLOY_FILES = ["Dockerfile", "Dockerfile.*", "*.dockerfile", "Procfile", "docker-compose*.yml", "docker-compose*.yaml",
                 "compose.yml", "compose.yaml", "fly.toml", "render.yaml", "app.yaml", "app.json", "*.service",
                 "wsgi.py", "asgi.py", "manage.py", "gunicorn*.py", ".env", ".env.*"]


def _prod_override(ctx: wc.ScanContext, rel: str, name: str) -> Optional[Tuple[str, bool]]:
    """Django split settings: (production module, selected) when a sibling
    production settings module star-imports rel and assigns name from
    something other than a literal. selected is True when a Dockerfile,
    Procfile, compose file, wsgi.py, manage.py or similar sets
    DJANGO_SETTINGS_MODULE to that module. None when nothing overrides it."""
    if "/" not in rel:
        return None
    d, base = rel.rsplit("/", 1)
    stem = base[:-3]
    for f in ctx.files:
        if not f.startswith(d + "/") or "/" in f[len(d) + 1:] or f == rel:
            continue
        if not _PROD_SETTINGS_RX.match(f.rsplit("/", 1)[-1]):
            continue
        t = ctx.read(f)
        if not re.search(r"(?m)^\s*from\s+(?:\.|[\w.]+\.)?%s\s+import\s+\*" % re.escape(stem), t):
            continue
        if not re.search(r"""(?m)^\s*%s\s*=\s*(?![rbuRBU]{0,2}['"])\S""" % re.escape(name), t):
            continue
        module = f[:-3].replace("/", ".")
        tail = ".".join(module.split(".")[-2:])
        rx = re.compile(r"DJANGO_SETTINGS_MODULE[\"']?(?:\s*[,=:]\s*|\s+)[\"']?[\w.]*%s\b" % re.escape(tail))
        selected = any(rx.search(ctx.read(x)) for x in ctx.glob(*_DEPLOY_FILES))
        return f, selected
    return None


def check_hardcoded_signing_secret(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    if rel.endswith(".py"):
        hits = _py_literal_secrets(rel, text, ctx)
    elif rel.endswith(tuple(x[1:] for x in _JS_UI)):
        hits = _js_literal_secrets(rel, text, ctx)
    else:
        return []
    out: List[Hit] = []
    seen: Set[int] = set()
    for h in hits:
        if h.line not in seen:
            seen.add(h.line)
            out.append(h)
    return out


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

_PUBENV_GLOBS = (_ENV_FILES + _JS_UI + [
    "*.html", "app.json", "eas.json", "vercel.json", "netlify.toml", "package.json", "Dockerfile",
    "Dockerfile.*", "*.dockerfile", "docker-compose*.yml", "docker-compose*.yaml", "compose.yml",
    "compose.yaml", ".github/workflows/*.yml", ".github/workflows/*.yaml",
])

RULES: List[Rule] = [
    Rule(
        id="secret-public-env-prefix",
        skill=SKILL,
        klass="server secret behind a public env prefix",
        severity="critical",
        stacks=["*"],
        file_globs=_PUBENV_GLOBS,
        exclude_globs=_NOT_SHIPPED,
        pattern="check_public_env_secret",
        message="a secret-shaped env var uses a prefix that inlines it into the client bundle",
        why=("The agent sees 'X is undefined in the browser' and the shortest fix is to rename the variable with "
             "NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_ or REACT_APP_, which copies the value into every bundle."),
        fp_trap=("Publishable, anon and site keys are public by design: NEXT_PUBLIC_SUPABASE_ANON_KEY, "
                 "*_PUBLISHABLE_KEY, VITE_FIREBASE_API_KEY, *_RECAPTCHA_SITE_KEY, Sentry DSN and PostHog keys are "
                 "not reported. A prefix the project's framework does not expose (VITE_ in a Next.js app) is not "
                 "reported. Check the value when the name is ambiguous."),
        fix_ref="secrets.md#public-env-prefixes",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-public-env-token",
        skill=SKILL,
        klass="token behind a public env prefix",
        severity="high",
        stacks=["*"],
        file_globs=_PUBENV_GLOBS,
        exclude_globs=_NOT_SHIPPED,
        pattern="check_public_env_token",
        message="a token or webhook env var uses a prefix that inlines it into the client bundle",
        why=("Agents expose API tokens and webhook URLs to the browser so a client component can call the "
             "service directly instead of going through a server route."),
        fp_trap=("Some tokens are public by design: Mapbox pk. tokens, Cesium ion and Contentful or Storyblok "
                 "delivery tokens. A value in .env that is public by design (pk_, pk., anon JWT) is not reported. "
                 "Browser log ingest tokens (Axiom, Better Stack / Logtail source tokens, Datadog client tokens) "
                 "are reported as info: they are fine when they can only send logs. Each variable is reported once, "
                 "at its env file or env schema, with the other places listed; lines that only test whether it is "
                 "set (!!env.X, if (X)) do not count. Read the provider docs for the token type before moving it."),
        fix_ref="secrets.md#public-env-prefixes",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-bundler-inlines-env",
        skill=SKILL,
        klass="bundler config inlines server env",
        severity="critical",
        stacks=["*"],
        file_globs=["next.config.*", "vite.config.*", "webpack.config.*", "craco.config.*", "vue.config.*",
                    "astro.config.*", "nuxt.config.*", "app.config.*"],
        pattern="check_bundler_inlines_env",
        message="bundler config inlines a server env value (or all of process.env) into the client bundle",
        why=("Next.js copies every key under next.config env into the bundle whatever its prefix, and Vite define "
             "or webpack DefinePlugin replace process.env.X with the literal value. Agents use them to make a key "
             "'available' in client code, and some app-builder templates ship define blocks that inline GEMINI_API_KEY."),
        fp_trap=("Public values (site URL, NODE_ENV, version strings, publishable keys) in these blocks are fine. "
                 "Vite loadEnv(mode, dir) without the third '' argument only loads VITE_ variables, so inlining "
                 "that env object is safe. serverRuntimeConfig (Next.js 15 and older) stays on the server; Next.js 16 "
                 "removed both runtime config options."),
        fix_ref="secrets.md#bundler-config-that-inlines-env",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-llm-sdk-in-browser",
        skill=SKILL,
        klass="LLM SDK running in the browser",
        severity="high",
        stacks=["*"],
        file_globs=_JS_UI,
        exclude_globs=_NOT_SHIPPED,
        pattern="check_llm_sdk_in_browser",
        message="LLM SDK set to run in the browser (dangerouslyAllowBrowser or the Anthropic direct browser header)",
        why=("The OpenAI and Anthropic SDKs refuse to run in a browser until this flag is set. Agents set it to "
             "clear the error instead of moving the call to a server route, so the key ships to every visitor."),
        fp_trap=("Bring-your-own-key tools where each user types their own key at runtime (kept in localStorage or "
                 "state) are a legitimate use and are not reported. Files that only run on the server are skipped."),
        fix_ref="secrets.md#call-third-party-apis-from-server-code",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-provider-call-from-client",
        skill=SKILL,
        klass="paid API called straight from client code",
        severity="high",
        stacks=["*"],
        file_globs=_JS_UI,
        exclude_globs=_NOT_SHIPPED,
        pattern=r"""['"`]https?://(?:""" + _PROVIDER_HOSTS + r""")""",
        client_only=True,
        unless_file=_BYOK_RX.pattern,
        message="client code calls an LLM or email provider API directly, so the provider key must be in the bundle",
        why=("No-backend SPAs and Expo apps have no server to hold the key, so agents call the provider from the "
             "browser or the app with the key attached."),
        fp_trap=("Bring-your-own-key tools that send the user's own key are fine. A URL string used only for "
                 "display or docs is not a call. Calls from server routes are not reported."),
        fix_ref="secrets.md#call-third-party-apis-from-server-code",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-supabase-admin-in-client",
        skill=SKILL,
        klass="Supabase admin API in client code",
        severity="critical",
        stacks=["*"],
        file_globs=_JS_UI,
        exclude_globs=_NOT_SHIPPED,
        pattern=r"\.auth\.admin\.\w+",
        client_only=True,
        message="supabase.auth.admin is called from client code; it only works with the service key, which bypasses RLS",
        why=("Agents build admin screens (list users, delete users, invite) in the frontend and then hand the "
             "browser client the service_role key so the admin calls stop failing."),
        fp_trap=("The same call in a server route, a Server Action ('use server'), an Edge Function or a file "
                 "that imports 'server-only' is correct and is not reported."),
        fix_ref="secrets.md#admin-keys-stay-on-the-server",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-env-sent-to-client",
        skill=SKILL,
        klass="server environment sent to the client",
        severity="critical",
        stacks=["*"],
        file_globs=_JS_UI + ["*.py", "*.php", "*.ejs", "*.html", "*.jinja", "*.jinja2", "*.j2"],
        exclude_globs=_NOT_SHIPPED,
        pattern="check_env_sent_to_client",
        message="a response, page prop or template sends server env values or the whole config to the client",
        why=("Agents add a /api/config endpoint, getServerSideProps props or a component prop so the frontend can "
             "read a key it needs, and sometimes return the whole process.env or os.environ to 'debug' it."),
        fp_trap=("Returning an explicit allow-list of public values (site URL, publishable key, anon key) is the "
                 "correct pattern and is not reported. Checks such as !!process.env.KEY or key === undefined only "
                 "send a boolean and are not reported."),
        fix_ref="secrets.md#never-send-the-environment",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-admin-sdk-in-client",
        skill=SKILL,
        klass="admin SDK or service account on the client side",
        severity="critical",
        stacks=["*"],
        file_globs=_JS_UI + ["*.json"],
        exclude_globs=_NOT_SHIPPED,
        pattern="check_admin_sdk_client",
        message="Firebase Admin SDK or a service account key file is reachable from the client",
        why=("Agents import firebase-admin or a downloaded serviceAccountKey.json into frontend code to skip "
             "Security Rules, or drop the key file in public/ so the app can fetch it."),
        fp_trap=("The Firebase web config (apiKey, authDomain, projectId) is public by design and is not this "
                 "finding. firebase-admin in Cloud Functions, API routes or other server code is correct. A nested "
                 "server package under src/ (its own package.json that depends on firebase-admin, such as the admin "
                 "SDK Firebase Data Connect generates) is skipped while no client file imports it."),
        fix_ref="secrets.md#admin-keys-stay-on-the-server",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-signing-fallback",
        skill=SKILL,
        klass="signing secret with a literal fallback",
        severity="high",
        stacks=["*"],
        file_globs=_JS_UI + ["*.py", "*.php", "docker-compose*.yml", "docker-compose*.yaml", "compose.yml",
                             "compose.yaml", "Dockerfile", "Dockerfile.*"],
        exclude_globs=_NOT_SHIPPED + _DEV_SETTINGS,
        pattern="check_secret_fallback",
        message="a secret env var falls back to a literal when it is missing, so production can run with a known value",
        why=("Agents write process.env.JWT_SECRET || 'secret' or os.getenv('SECRET_KEY', 'dev') so the app starts "
             "without a .env file. When the variable is missing in production the literal signs every session."),
        fp_trap=("A fallback that only applies outside production (the code throws when NODE_ENV is production and "
                 "the variable is unset) is fine. Fallbacks for public values or for API keys that only fail a "
                 "request are not reported. Test and dev-only settings files, test runner configs (playwright, "
                 "vitest, jest, cypress) and dev, local, test or CI compose files and Dockerfiles are skipped; "
                 "compose.override files are reported as low."),
        fix_ref="secrets.md#fail-closed-on-missing-env",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="secret-hardcoded-signing-key",
        skill=SKILL,
        klass="hardcoded or default signing secret",
        severity="high",
        stacks=["*"],
        file_globs=_JS_UI + ["*.py"],
        exclude_globs=_NOT_SHIPPED + _DEV_SETTINGS,
        pattern="check_hardcoded_signing_secret",
        message="a JWT, session or framework signing secret is a literal in the source",
        why=("Tutorials and READMEs show literal secrets ('keyboard cat', the FastAPI tutorial key, "
             "django-insecure- keys from startproject) and agents copy them to make auth work."),
        fp_trap=("Throwaway keys in test settings, conftest.py and dev-only settings modules are fine as long as "
                 "production never loads them; check DJANGO_SETTINGS_MODULE or the app factory. A literal that is "
                 "replaced from the environment later in the same file is not reported. In Django split settings, "
                 "a literal in base.py that a production module (from .base import *) replaces from the "
                 "environment is skipped when the deploy config selects that module, and medium otherwise."),
        fix_ref="secrets.md#signing-secrets",
        confidence="high",
        needs_confirmation=True,
    ),
]
