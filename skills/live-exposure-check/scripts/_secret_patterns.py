"""Secret patterns and false-positive filters shared by find_secrets.py and check_live.py.

Copied byte for byte into live-exposure-check/scripts/. Python 3.9+, standard
library only, no network.

Data:
  HIGH_CONFIDENCE   list of (name, regex, severity): values that are secrets.
  ANCHORS           name -> literal text every match of that pattern contains
                    (None = no anchor). A pattern only runs on text holding
                    one of its anchors, which keeps large files fast.
  PUBLIC_BY_DESIGN  list of (name, regex, note): keys that are meant to be public.
                    An empty regex means the shape is ambiguous and only the note
                    applies.
  PLACEHOLDERS      lowercase markers of fake or template values.
  DESCRIPTIONS      name -> one-line description used in messages.
  ROTATION_REF      name -> rotation.md section for the fix pointer.

Functions:
  decode_jwt_role(token)    -> {"role", "iss", "ref", "class"}
  is_placeholder(value)     -> bool
  public_by_design(value)   -> name or None
  find_secrets_in_text(text)-> list of SecretHit (secrets and info notes)
  find_context_secrets(text, rel) -> list of SecretHit for shapes that need the
                              file type (Gradle signing passwords, a literal
                              password passed to a sign-up or create-user call)
  find_public_keys(text)    -> list of (name, line) for public keys seen
  redact(text)              -> text with every secret-shaped value masked
"""

from __future__ import annotations

import base64
import binascii
import bisect
import hashlib
import json
import re
from collections import namedtuple
from typing import Dict, List, Optional, Tuple

# Regexes follow the research table (gitleaks-compatible where noted there).
HIGH_CONFIDENCE: List[Tuple[str, str, str]] = [
    ("stripe-live-secret-key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{10,99}\b", "critical"),
    ("stripe-test-secret-key", r"\b(?:sk|rk)_test_[A-Za-z0-9]{10,99}\b", "high"),
    ("stripe-webhook-secret", r"\bwhsec_[A-Za-z0-9]{20,}\b", "high"),
    ("stripe-org-key", r"\bsk_org_[A-Za-z0-9_]{20,200}\b", "critical"),
    ("openai-api-key", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}", "critical"),
    ("openai-legacy-key", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b", "critical"),
    ("anthropic-api-key", r"\bsk-ant-api03-[A-Za-z0-9_-]{93}AA\b", "critical"),
    ("anthropic-admin-key", r"\bsk-ant-admin01-[A-Za-z0-9_-]{93}AA\b", "critical"),
    ("aws-access-key-id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b", "critical"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b", "critical"),
    ("github-fine-grained-token", r"\bgithub_pat_\w{82}\b", "critical"),
    ("supabase-secret-key", r"\bsb_secret_[A-Za-z0-9_-]{20,}", "critical"),
    ("supabase-access-token", r"\bsbp_[A-Za-z0-9_]{40,100}\b", "critical"),
    ("sendgrid-api-key", r"\bSG\.[A-Za-z0-9_.=-]{66}(?![A-Za-z0-9_.=-])", "high"),
    ("slack-bot-token", r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*", "high"),
    ("mapbox-secret-token", r"\bsk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}", "high"),
    # Extra distinctive prefixes (gitleaks shapes) common in apps built with coding agents.
    ("openrouter-api-key", r"\bsk-or-v1-[a-f0-9]{64}\b", "critical"),
    ("groq-api-key", r"\bgsk_[A-Za-z0-9]{52}\b", "critical"),
    ("xai-api-key", r"\bxai-[A-Za-z0-9]{80}\b", "critical"),
    ("huggingface-token", r"\bhf_[A-Za-z]{34}\b", "high"),
    ("npm-access-token", r"\bnpm_[A-Za-z0-9]{36}\b", "critical"),
    ("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20}\b", "critical"),
    ("gitlab-token-routable", r"\bglpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b", "critical"),
    ("google-oauth-client-secret", r"\bGOCSPX-[A-Za-z0-9_-]{28}\b", "high"),
    ("discord-bot-token", r"\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}\b", "high"),
    ("private-key", r"-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY", "critical"),
    ("gcp-service-account", r"\"type\"\s*:\s*\"service_account\"", "critical"),
    ("database-url-password",
     r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp)://[^:\s/]+:[^@\s]+@", "high"),
    ("laravel-app-key", r"APP_KEY=base64:[A-Za-z0-9+/]{43}=", "critical"),
]

DESCRIPTIONS: Dict[str, str] = {
    "stripe-live-secret-key": "Stripe live secret or restricted key",
    "stripe-test-secret-key": "Stripe test-mode secret or restricted key (no real money, still a secret)",
    "stripe-webhook-secret": ("Webhook signing secret (whsec_: Stripe, or Svix-based senders such as Clerk and "
                              "Resend; lets anyone forge webhook events)"),
    "stripe-org-key": "Stripe organization API key (reaches every account in the organization)",
    "openai-api-key": "OpenAI API key",
    "openai-legacy-key": "OpenAI API key (legacy format)",
    "anthropic-api-key": "Anthropic API key",
    "anthropic-admin-key": "Anthropic admin API key",
    "aws-access-key-id": "AWS access key ID (find and rotate the paired secret key too)",
    "github-token": "GitHub token",
    "github-fine-grained-token": "GitHub fine-grained personal access token",
    "supabase-secret-key": "Supabase secret key (bypasses row level security)",
    "supabase-access-token": ("Supabase personal access token (Management API access to the account's projects, "
                              "including their secret keys)"),
    "sendgrid-api-key": "SendGrid API key",
    "slack-bot-token": "Slack bot token",
    "mapbox-secret-token": "Mapbox secret token",
    "openrouter-api-key": "OpenRouter API key",
    "groq-api-key": "Groq API key",
    "xai-api-key": "xAI API key",
    "huggingface-token": "Hugging Face access token",
    "npm-access-token": "npm access token (can publish packages under your name)",
    "gitlab-token": "GitLab personal access token",
    "gitlab-token-routable": "GitLab personal access token",
    "google-oauth-client-secret": "Google OAuth client secret",
    "discord-bot-token": "Discord bot token (full control of the bot)",
    "private-key": "Private key",
    "gcp-service-account": "Google Cloud / Firebase service account key file (full admin access)",
    "database-url-password": "Database URL with an inline password",
    "laravel-app-key": "Laravel APP_KEY (signs and encrypts sessions and cookies)",
    "supabase-service-role-jwt": "Supabase service_role key (bypasses row level security)",
    "supabase-demo-service-role-jwt": (
        "Supabase service_role key from the published self-hosting demo (anyone can mint tokens for this instance)"),
    "supabase-demo-anon-jwt": (
        "Self-hosted Supabase still uses the published demo keys, so its JWT secret is public"),
    "google-api-key": (
        "Google API key: public only while restricted. Check its application and API restrictions, "
        "and that the Gemini / Generative Language API is not in its allowed APIs"),
    "supabase-local-demo-jwt": (
        "Supabase CLI local default key (the published demo key, paired with a local URL here): fine for local "
        "development and CI, never reuse it on a hosted or self-hosted project"),
    "aws-access-key-id-presigned": (
        "AWS access key ID inside a presigned request or SigV4 credential scope: not a secret on its own, but "
        "check that the paired secret access key is not committed anywhere"),
    "gradle-signing-password": (
        "Android signing password (storePassword / keyPassword) as a literal; with the keystore it lets anyone "
        "sign builds as you. If the upload key leaked, reset it through Play App Signing"),
    "hardcoded-login-password": "Literal password passed to a sign-up, sign-in or create-user call",
}

ROTATION_REF: Dict[str, str] = {
    "stripe-live-secret-key": "rotation.md#stripe",
    "stripe-test-secret-key": "rotation.md#stripe",
    "stripe-webhook-secret": "rotation.md#stripe",
    "stripe-org-key": "rotation.md#stripe",
    "openai-api-key": "rotation.md#openai",
    "openai-legacy-key": "rotation.md#openai",
    "anthropic-api-key": "rotation.md#anthropic",
    "anthropic-admin-key": "rotation.md#anthropic",
    "aws-access-key-id": "rotation.md#aws",
    "github-token": "rotation.md#github",
    "github-fine-grained-token": "rotation.md#github",
    "supabase-secret-key": "rotation.md#supabase",
    "supabase-access-token": "rotation.md#supabase",
    "supabase-service-role-jwt": "rotation.md#supabase",
    "supabase-demo-service-role-jwt": "rotation.md#supabase",
    "supabase-demo-anon-jwt": "rotation.md#supabase",
    "sendgrid-api-key": "rotation.md#other-providers",
    "slack-bot-token": "rotation.md#other-providers",
    "mapbox-secret-token": "rotation.md#other-providers",
    "openrouter-api-key": "rotation.md#other-providers",
    "groq-api-key": "rotation.md#other-providers",
    "xai-api-key": "rotation.md#other-providers",
    "huggingface-token": "rotation.md#other-providers",
    "npm-access-token": "rotation.md#other-providers",
    "gitlab-token": "rotation.md#other-providers",
    "gitlab-token-routable": "rotation.md#other-providers",
    "google-oauth-client-secret": "rotation.md#google",
    "discord-bot-token": "rotation.md#other-providers",
    "private-key": "rotation.md#private-keys",
    "gcp-service-account": "rotation.md#google",
    "google-api-key": "rotation.md#google",
    "database-url-password": "rotation.md#database",
    "laravel-app-key": "rotation.md#signing-secrets",
    "supabase-local-demo-jwt": "rotation.md#supabase",
    "aws-access-key-id-presigned": "rotation.md#aws",
    "gradle-signing-password": "rotation.md#private-keys",
    "hardcoded-login-password": "rotation.md#order-of-work",
}

# Literal text that every match of a pattern contains. A pattern only runs on
# text holding at least one of its anchors (a plain substring test), so large
# files such as translation catalogs do not pay for every regex. None means
# the pattern has no literal anchor and always runs.
ANCHORS: Dict[str, Optional[Tuple[str, ...]]] = {
    "stripe-live-secret-key": ("_live_",),
    "stripe-test-secret-key": ("_test_",),
    "stripe-webhook-secret": ("whsec_",),
    "stripe-org-key": ("sk_org_",),
    "openai-api-key": ("sk-",),
    "openai-legacy-key": ("T3BlbkFJ",),
    "anthropic-api-key": ("sk-ant-api03-",),
    "anthropic-admin-key": ("sk-ant-admin01-",),
    "aws-access-key-id": ("AKIA", "ASIA", "ABIA", "ACCA"),
    "github-token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "github-fine-grained-token": ("github_pat_",),
    "supabase-secret-key": ("sb_secret_",),
    "supabase-access-token": ("sbp_",),
    "sendgrid-api-key": ("SG.",),
    "slack-bot-token": ("xoxb-",),
    "mapbox-secret-token": ("sk.eyJ",),
    "openrouter-api-key": ("sk-or-v1-",),
    "groq-api-key": ("gsk_",),
    "xai-api-key": ("xai-",),
    "huggingface-token": ("hf_",),
    "npm-access-token": ("npm_",),
    "gitlab-token": ("glpat-",),
    "gitlab-token-routable": ("glpat-",),
    "google-oauth-client-secret": ("GOCSPX-",),
    "discord-bot-token": None,
    "private-key": ("-----BEGIN",),
    "gcp-service-account": ("service_account",),
    "database-url-password": ("://",),
    "laravel-app-key": ("APP_KEY=base64:",),
    # PUBLIC_BY_DESIGN entries and the JWT / Google key scans
    "stripe-publishable-key": ("pk_live_", "pk_test_"),
    "supabase-publishable-key": ("sb_publishable_",),
    "supabase-anon-jwt": (".ey",),
    "firebase-web-api-key": ("AIza",),
    "sentry-dsn": ("sentry",),
    "posthog-project-key": ("phc_",),
    "mapbox-public-token": ("pk.eyJ",),
    "jwt": (".ey",),
    "google-api-key": ("AIza",),
}


def _anchored(name: str, text: str) -> bool:
    """False when text cannot hold a match of pattern name (none of its anchors occurs)."""
    anchors = ANCHORS.get(name)
    return anchors is None or any(a in text for a in anchors)

JWT_PATTERN = r"\bey[A-Za-z0-9_-]{17,}\.ey[A-Za-z0-9_-]{17,}\.[A-Za-z0-9_-]{10,}"
GOOGLE_API_KEY_PATTERN = r"\bAIza[\w-]{35}\b"

PUBLIC_BY_DESIGN: List[Tuple[str, str, str]] = [
    ("stripe-publishable-key", r"\bpk_(?:live|test)_[A-Za-z0-9]{10,99}\b",
     "Stripe publishable key: safe to ship to the browser."),
    ("supabase-publishable-key", r"\bsb_publishable_[A-Za-z0-9_-]{20,}",
     "Supabase publishable key: public by design. Data safety depends on row level security."),
    ("supabase-anon-jwt", JWT_PATTERN,
     "Supabase anon key (a JWT with role anon): public by design. Data safety depends on row level security."),
    ("firebase-web-api-key", GOOGLE_API_KEY_PATTERN,
     "Firebase web config apiKey: not a secret. Data safety depends on Security Rules and App Check."),
    ("sentry-dsn", r"https://[0-9a-f]{32}@[\w.-]*sentry[\w.-]*/\d+", "Sentry DSN: public by design."),
    ("posthog-project-key", r"\bphc_[A-Za-z0-9]{20,}", "PostHog project key: public by design."),
    ("mapbox-public-token", r"\bpk\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "Mapbox public token (pk.)."),
    ("recaptcha-site-key", "",
     "reCAPTCHA site key (6L..., 40 chars) is public; the secret key has the same shape, so check the name."),
    ("turnstile-site-key", "",
     "Cloudflare Turnstile site key (0x4AAAA...) is public; the secret key looks alike, so check the name."),
    ("algolia-search-key", "", "Algolia search-only key is public; the admin key is secret."),
    ("revenuecat-public-key", "", "RevenueCat public SDK keys (appl_, goog_, amzn_) are public."),
    ("pusher-app-key", "", "Pusher app key is public; the Pusher secret is not."),
    ("onesignal-app-id", "", "OneSignal app ID is public."),
]

# Lowercase markers. A value containing any of them is treated as fake.
PLACEHOLDERS: List[str] = [
    "your-api-key", "your_api_key", "yourapikey", "your-key", "your_key", "yourkey",
    "your-secret", "your_secret", "yoursecret", "your-token", "your_token", "your-password",
    "your_password", "your", "keyhere", "tokenhere", "secrethere",
    "<your", "<insert", "<replace", "<api", "<secret", "<token", "<key",
    "changeme", "change-me", "change_me", "change-this", "change_this", "replaceme",
    "replace-me", "replace_me", "placeholder", "example", "sample", "dummy", "redacted",
    "notreal", "not-real", "not_real", "not-a-real", "fake", "xxxx", "****", "....",
    "0000000000", "1234567890", "0123456789", "abcdefghij", "-here", "_here", "todo", "fixme",
    "insert-", "insert_",
]

# SHA-256 of keys that vendors print in their own docs. Everyone shares them,
# so they are not leaks. Only hashes are stored here.
KNOWN_DOC_EXAMPLES: Dict[str, str] = {
    "2cafc0970149a84f3b9e62eaf169f36f59907a3b3e31f7b82e68c69cd27f7326": "Stripe docs test key",
    "f2d6ca16515033e5dce14eba840b979d27b5cbae24bb3e5bf484339667f86397": "Stripe docs test key (older)",
}

# Self-hosting / docker defaults that are not leaks on their own.
_WEAK_DB_PASSWORDS = frozenset({
    "password", "pass", "passwd", "postgres", "root", "secret", "admin", "mysql", "redis",
    "mongo", "mongodb", "user", "pwd", "test", "guest", "example", "changeme", "123456", "1234",
    "dev", "local", "docker", "default",
})
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal"})
SECRET_JWT_ROLES = frozenset({"service_role", "supabase_admin"})

SecretHit = namedtuple("SecretHit", "name value line start end severity kind message")
SecretHit.__doc__ = """One match: kind is "secret" (report it) or "note" (info only, e.g. Google keys)."""

_COMPILED = [(n, re.compile(rx), sev) for n, rx, sev in HIGH_CONFIDENCE]
_JWT_RX = re.compile(JWT_PATTERN)
_GOOGLE_RX = re.compile(GOOGLE_API_KEY_PATTERN)
_PUBLIC_COMPILED = [(n, re.compile(rx), note) for n, rx, note in PUBLIC_BY_DESIGN if rx]
# Complete template or reference tokens: ${VAR}, {{ var }}, %(name)s, <your-key>,
# process.env / os.environ / getenv. Loose pieces such as "%(" or "%s" are not
# enough: random keys (Django's get_random_secret_key) contain them by chance.
_TEMPLATE_RX = re.compile(
    r"\$\{[^}\s]*\}|\{\{[^}]*\}\}|%\([A-Za-z_]\w*\)[sdr]|<[A-Za-z][\w .:/-]*>|process\.env|os\.environ|getenv")
# Templates that only count when they are the whole value: %s, $VAR, $(cmd).
_TEMPLATE_WHOLE_RX = re.compile(r"(?:%s|\$[A-Za-z_]\w*|\$\([^)]*\))")


def _is_template(value: str) -> bool:
    v = (value or "").strip()
    return bool(_TEMPLATE_RX.search(v) or _TEMPLATE_WHOLE_RX.fullmatch(v))


# ---------------------------------------------------------------------------
# Classification helpers
# ---------------------------------------------------------------------------

def decode_jwt_role(token: str) -> Dict[str, Optional[str]]:
    """Decode a JWT payload locally (no signature check, no network).

    Returns {"role", "iss", "ref", "class"} where class is:
      "secret"       role service_role (or supabase_admin): a server-only key
      "public"       role anon: public by design
      "demo-secret"  service_role signed with the published supabase-demo issuer
      "demo-public"  anon key from the published supabase-demo issuer
      "unknown"      any other role (user session tokens and the like)
      "invalid"      not a decodable JWT
    """
    out: Dict[str, Optional[str]] = {"role": None, "iss": None, "ref": None, "class": "invalid"}
    parts = (token or "").strip().split(".")
    if len(parts) < 2:
        return out
    seg = parts[1]
    try:
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, binascii.Error):
        return out
    if not isinstance(payload, dict):
        return out
    role, iss, ref = payload.get("role"), payload.get("iss"), payload.get("ref")
    out["role"] = role if isinstance(role, str) else None
    out["iss"] = iss if isinstance(iss, str) else None
    out["ref"] = ref if isinstance(ref, str) else None
    demo = out["iss"] == "supabase-demo"
    if out["role"] in SECRET_JWT_ROLES:
        out["class"] = "demo-secret" if demo else "secret"
    elif out["role"] == "anon":
        out["class"] = "demo-public" if demo else "public"
    else:
        out["class"] = "unknown"
    return out


def is_placeholder(value: str) -> bool:
    """True for template or fake values: placeholder words, ${VAR} style
    templates, values with almost no character variety (sk_live_xxxx...) and
    keys that vendors publish in their docs (KNOWN_DOC_EXAMPLES)."""
    if not value:
        return True
    if hashlib.sha256(value.encode("utf-8", "replace")).hexdigest() in KNOWN_DOC_EXAMPLES:
        return True
    low = value.lower()
    if any(p in low for p in PLACEHOLDERS):
        return True
    if _is_template(value):
        return True
    alnum = re.sub(r"[^A-Za-z0-9]", "", value)
    if len(alnum) >= 16 and len(set(alnum[-16:])) <= 4:
        return True
    return False


def public_by_design(value: str) -> Optional[str]:
    """Name of the PUBLIC_BY_DESIGN entry the whole value matches, else None.
    JWTs count as public only when their role is anon."""
    for name, rx, _note in _PUBLIC_COMPILED:
        if rx.fullmatch(value):
            if name == "supabase-anon-jwt" and decode_jwt_role(value)["class"] != "public":
                continue
            return name
    return None


def _line_text(text: str, start: int, end: int) -> str:
    a = text.rfind("\n", 0, start) + 1
    b = text.find("\n", end)
    return text[a:b if b != -1 else len(text)]


def _private_key_has_body(text: str, end: int) -> bool:
    """A real PEM block has a base64 line right after the header. A mention of
    the header in code or docs does not."""
    tail = text[end:end + 1200].replace("\\r", "").replace("\\n", "\n")
    lines = tail.split("\n")[1:6]
    for ln in lines:
        s = ln.strip().strip("\"',+;` ")
        if re.fullmatch(r"[A-Za-z0-9+/=]{40,}", s) and not is_placeholder(s):
            return True
    return False


def _service_account_ok(text: str, start: int) -> bool:
    lo, hi = max(0, start - 4000), min(len(text), start + 6000)
    window = text[lo:hi]
    m = re.search(r"\"private_key\"\s*:\s*\"(-----BEGIN[^\"]*)\"", window)
    if not m:
        return False
    return _private_key_has_body(m.group(1), m.group(1).find("PRIVATE KEY") + len("PRIVATE KEY"))


def _db_url_ok(text: str, m: "re.Match[str]") -> bool:
    """Report a DB URL only when it has a real-looking password and a non-local host."""
    creds = m.group(0).split("://", 1)[1][:-1]
    user, _, pw = creds.partition(":")
    if not pw or is_placeholder(pw) or _is_template(creds) or pw.lower() in _WEAK_DB_PASSWORDS:
        return False
    if pw.startswith(("$", "%", "{", "<", "[")):
        return False
    bare = pw.strip("[]<>{}()*")
    if not bare or bare.lower() in _WEAK_DB_PASSWORDS or re.fullmatch(r"[A-Z]+(?:_[A-Z]+)+", bare):
        return False
    hm = re.match(r"\[?[^/:?#\s\"'`<>\]]*", text[m.end():])
    host = (hm.group(0) if hm else "").lower().lstrip("[")
    if not host or host in _LOCAL_HOSTS or "." not in host:
        return False
    if any(p in host for p in ("example", "your", "host.", "hostname", "xxx")):
        return False
    return True


def _discord_ok(value: str) -> bool:
    """The first part of a Discord token is the bot's numeric id in base64."""
    head = value.split(".", 1)[0]
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decode(head + "=" * (-len(head) % 4))
        except (ValueError, TypeError, binascii.Error):
            continue
        if raw.isdigit() and 15 <= len(raw) <= 21:
            return True
    return False


def _mixed_case(value: str) -> bool:
    return any(c.islower() for c in value) and any(c.isupper() for c in value)


def _firebase_context(text: str, low_text: str, start: int, end: int) -> bool:
    line = _line_text(text, start, end).lower()
    if "firebase" in line:
        return True
    names = ("apikey", "api_key", "current_key", "<string>")
    compact = line.replace("-", "").replace(" ", "")
    if any(n in compact for n in names):
        return any(k in low_text for k in ("firebase", "authdomain", "initializeapp", "google_app_id",
                                            "mobilesdk_app_id"))
    return False


class _Lines:
    def __init__(self, text: str) -> None:
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def find_secrets_in_text(text: str) -> List[SecretHit]:
    """Every secret (and every Google-key note) in text, in order of position.

    Applies the placeholder filter, the public-by-design list, JWT role decoding
    and the per-pattern checks (PEM body present, service account has a key,
    DB URL has a real password on a non-local host). Each (name, value) pair is
    reported once per text, at its first position.
    """
    if not text:
        return []
    lines = _Lines(text)
    hits: List[SecretHit] = []
    seen = set()

    def add(name: str, value: str, start: int, end: int, severity: str, kind: str) -> None:
        key = (name, value)
        if key in seen:
            return
        seen.add(key)
        hits.append(SecretHit(name, value, lines.line(start), start, end, severity, kind,
                              DESCRIPTIONS.get(name, name)))

    for name, rx, sev in _COMPILED:
        if not _anchored(name, text):
            continue
        for m in rx.finditer(text):
            value = m.group(0)
            if name == "private-key":
                if not _private_key_has_body(text, m.end()):
                    continue
            elif name == "gcp-service-account":
                if not _service_account_ok(text, m.start()):
                    continue
            elif name == "database-url-password":
                if not _db_url_ok(text, m):
                    continue
            elif name == "discord-bot-token" and not _discord_ok(value):
                continue
            elif name == "huggingface-token" and not _mixed_case(value[3:]):
                continue
            elif is_placeholder(value):
                continue
            if public_by_design(value):
                continue
            if name == "aws-access-key-id" and _aws_presigned(text, m.start(), m.end()):
                add("aws-access-key-id-presigned", value, m.start(), m.end(), "info", "note")
                continue
            add(name, value, m.start(), m.end(), sev, "secret")

    if _anchored("jwt", text):
        target = None
        for m in _JWT_RX.finditer(text):
            cls = decode_jwt_role(m.group(0))["class"]
            if cls == "secret":
                add("supabase-service-role-jwt", m.group(0), m.start(), m.end(), "critical", "secret")
            elif cls in ("demo-secret", "demo-public"):
                if target is None:
                    target = _supabase_target(text)
                if target == "local":
                    add("supabase-local-demo-jwt", m.group(0), m.start(), m.end(), "info", "note")
                elif cls == "demo-secret":
                    add("supabase-demo-service-role-jwt", m.group(0), m.start(), m.end(), "critical", "secret")
                else:
                    add("supabase-demo-anon-jwt", m.group(0), m.start(), m.end(), "high", "secret")

    low_text = None
    if _anchored("google-api-key", text):
        for m in _GOOGLE_RX.finditer(text):
            if is_placeholder(m.group(0)):
                continue
            if low_text is None:
                low_text = text.lower()
            if _firebase_context(text, low_text, m.start(), m.end()):
                continue
            add("google-api-key", m.group(0), m.start(), m.end(), "info", "note")

    # A service account file also matches the private-key pattern; keep one finding.
    sa = [h.start for h in hits if h.name == "gcp-service-account"]
    if sa:
        hits = [h for h in hits if not (h.name == "private-key" and any(abs(h.start - s) < 8000 for s in sa))]
    # The short GitLab pattern can match the start of a routable token.
    routable = [(h.start, h.end) for h in hits if h.name == "gitlab-token-routable"]
    if routable:
        hits = [h for h in hits if not (h.name == "gitlab-token" and any(a <= h.start < b for a, b in routable))]
    hits.sort(key=lambda h: h.start)
    return hits


_SIGV4_SCOPE_RX = re.compile(r"/\d{8}/[a-z0-9-]+/[a-z0-9-]+/aws4_request")
_AMZ_CREDENTIAL_RX = re.compile(r"(?i)x-amz-credential['\"]?\s*[:=]\s*['\"]?$")


def _aws_presigned(text: str, start: int, end: int) -> bool:
    """True when an access key ID is the start of a SigV4 credential scope
    (AKIA.../20240101/us-east-1/s3/aws4_request) or the value of
    X-Amz-Credential, as in a presigned URL or POST policy."""
    if _SIGV4_SCOPE_RX.match(text, end, end + 80):
        return True
    return bool(_AMZ_CREDENTIAL_RX.search(text[max(0, start - 40):start]))


_URL_HOST_RX = re.compile(r"https?://([A-Za-z0-9_.-]+|\[[0-9A-Fa-f:]+\])(?::(\d{2,5}))?")
_DOC_HOSTS = frozenset({"supabase.com", "www.supabase.com", "app.supabase.com", "supabase.io", "github.com"})


def _supabase_target(text: str) -> Optional[str]:
    """Where the Supabase URLs in text point: "hosted" when any is a non-local
    project URL, "local" when they only point at the local CLI stack
    (127.0.0.1:543xx, localhost, host.docker.internal, supabase_kong_*),
    None when no Supabase URL is present."""
    local = hosted = False
    for m in _URL_HOST_RX.finditer(text):
        host = m.group(1).lower().strip("[]")
        port = m.group(2) or ""
        if host in _DOC_HOSTS:
            continue
        is_local = (host in _LOCAL_HOSTS or host == "::1" or host.startswith("supabase_kong") or host == "kong"
                    or host.endswith((".localhost", ".local")))
        line = _line_text(text, m.start(), m.end()).lower()
        supa = ("supabase" in line or "supabase" in host or port.startswith("543") or host == "kong")
        if not supa:
            continue
        if is_local:
            local = True
        else:
            hosted = True
    if hosted:
        return "hosted"
    return "local" if local else None


# ---------------------------------------------------------------------------
# Context patterns: shapes that are only secrets in a known file type
# ---------------------------------------------------------------------------

_GRADLE_LITERAL_RX = re.compile(
    r"""(?m)^[ \t]*(storePassword|keyPassword|signingPassword)[ \t]*(?:=[ \t]*)?(['"])([^'"\n$]{4,200})\2""")
_GRADLE_PROPS_RX = re.compile(
    r"""(?im)^[ \t]*([\w.-]*(?:store|key|signing|keystore)[_.-]?password)[ \t]*[=:][ \t]*([^\s#][^\n#]*?)[ \t]*$""")
# The Android debug keystore's published default password.
_ANDROID_DEBUG_PASSWORDS = frozenset({"android"})

_LOGIN_CALL_RX = re.compile(
    r"\b(createUser|createUserWithEmailAndPassword|signUp|signInWithPassword|signInWithEmailAndPassword)\s*\(")
_POSITIONAL_PASSWORD_CALLS = frozenset({"createUserWithEmailAndPassword", "signInWithEmailAndPassword"})
_CREATE_CALLS = frozenset({"createUser", "createUserWithEmailAndPassword", "signUp"})
_PW_PROP_LITERAL_RX = re.compile(r"""\bpass(?:word|wd)?\s*:\s*(['"`])([^'"`\n]{1,200})\1""")
_PW_PROP_IDENT_RX = re.compile(r"""\bpass(?:word|wd)?\s*:\s*([A-Za-z_$][\w$]*)\s*[,}\n]""")
_PW_SHORTHAND_RX = re.compile(r"""[{,]\s*(pass(?:word|wd)?|pwd)\s*(?=[,}])""")
_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")
# Test code and local seed data log in with throwaway passwords on purpose.
_LOGIN_SKIP_PATH_RX = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|e2e|cypress|playwright|fixtures?|__fixtures__|mocks?|__mocks__"
    r"|seeds?|seeders?|stories|examples?|docs?)/|\.(?:test|spec|stories|e2e|cy)\.[a-z]+$|(?:^|/)[^/]*seed[^/]*$",
    re.I)


def _call_args(text: str, i: int, limit: int = 800) -> List[Tuple[str, int]]:
    """Top-level arguments of the call whose ( is at text[i], as (text, offset)."""
    out: List[Tuple[str, int]] = []
    depth = 0
    start = i + 1
    j = i + 1
    end = min(len(text), i + limit)
    while j < end:
        c = text[j]
        if c in "\"'`":
            q = c
            j += 1
            while j < end and text[j] != q:
                j += 2 if text[j] == "\\" else 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                out.append((text[start:j], start))
                return out
            depth -= 1
        elif c == "," and depth == 0:
            out.append((text[start:j], start))
            start = j + 1
        j += 1
    out.append((text[start:end], start))
    return out


def _js_literal(expr: str) -> Optional[Tuple[str, int]]:
    """(value, offset of the value inside expr) for a plain string literal expression."""
    m = re.match(r"""\s*(['"`])([^'"`\n]*)\1\s*$""", expr)
    if not m or (m.group(1) == "`" and "${" in m.group(2)):
        return None
    return m.group(2), m.start(2)


def _declared_literal(text: str, ident: str) -> Optional[Tuple[str, int]]:
    m = re.search(r"""\b(?:const|let|var)\s+%s\s*(?::\s*\w+\s*)?=\s*(['"`])([^'"`\n]{1,200})\1"""
                  % re.escape(ident), text)
    if not m or (m.group(1) == "`" and "${" in m.group(2)):
        return None
    return m.group(2), m.start(2)


def _real_password(value: str) -> bool:
    v = value.strip()
    return len(v) >= 6 and v == value and not is_placeholder(v) and "${" not in v


def find_context_secrets(text: str, rel: str) -> List[SecretHit]:
    """Secrets whose shape only means something in a known file type.

    - Gradle build files and gradle.properties: a literal storePassword,
      keyPassword or *_STORE_PASSWORD / *_KEY_PASSWORD (Android release signing).
      The Android debug default ("android") and placeholders are skipped.
    - JS/TS: a literal password (inline, or a const in the same file) passed to
      createUser, createUserWithEmailAndPassword, signUp, signInWithPassword or
      signInWithEmailAndPassword. Test, seed and example paths are skipped.
    """
    if not text or not rel:
        return []
    name = rel.rsplit("/", 1)[-1].lower()
    lines = None
    hits: List[SecretHit] = []
    seen = set()

    def add(kind_name: str, value: str, start: int, severity: str, message: str) -> None:
        nonlocal lines
        if (kind_name, value) in seen:
            return
        seen.add((kind_name, value))
        if lines is None:
            lines = _Lines(text)
        hits.append(SecretHit(kind_name, value, lines.line(start), start, start + len(value), severity, "secret",
                              message))

    if name.endswith((".gradle", ".gradle.kts")) or name == "gradle.properties":
        found: List[Tuple[str, int]] = []
        if name == "gradle.properties":
            found = [(m.group(2), m.start(2)) for m in _GRADLE_PROPS_RX.finditer(text)]
        elif "Password" in text:
            found = [(m.group(3), m.start(3)) for m in _GRADLE_LITERAL_RX.finditer(text)]
        for value, start in found:
            v = value.strip().strip("'\"")
            if len(v) < 4 or v.lower() in _ANDROID_DEBUG_PASSWORDS or is_placeholder(v) or _is_template(v):
                continue
            if v.startswith(("System.getenv", "project.", "providers.", "$")):
                continue
            add("gradle-signing-password", value, start, "high", DESCRIPTIONS["gradle-signing-password"])
        return hits

    if not name.endswith(_JS_EXTS) or _LOGIN_SKIP_PATH_RX.search(rel) or "ass" not in text:
        return hits
    for m in _LOGIN_CALL_RX.finditer(text):
        call = m.group(1)
        args = _call_args(text, m.end() - 1)
        found_lit: Optional[Tuple[str, int]] = None
        region, base = (args[0] if args else ("", m.end()))
        if call in _POSITIONAL_PASSWORD_CALLS and len(args) >= 3:
            expr, off = args[2]
            lit = _js_literal(expr)
            if lit:
                found_lit = (lit[0], off + lit[1])
            else:
                ident = re.fullmatch(r"\s*([A-Za-z_$][\w$]*)\s*", expr)
                if ident:
                    found_lit = _declared_literal(text, ident.group(1))
        else:
            pm = _PW_PROP_LITERAL_RX.search(region)
            if pm:
                found_lit = (pm.group(2), base + pm.start(2))
            else:
                im = _PW_PROP_IDENT_RX.search(region) or _PW_SHORTHAND_RX.search(region)
                if im:
                    found_lit = _declared_literal(text, im.group(1))
        if not found_lit or not _real_password(found_lit[0]):
            continue
        severity = "high" if call in _CREATE_CALLS else "medium"
        add("hardcoded-login-password", found_lit[0], found_lit[1], severity,
            "%s: %s gets a password written in the source, so anyone who reads the code can sign in with it. "
            "Change that password, then read it from the environment or prompt for it" % (
                DESCRIPTIONS["hardcoded-login-password"], call))
    return hits


def find_public_keys(text: str) -> List[Tuple[str, int]]:
    """(name, line) for each public-by-design key in text, once per distinct value."""
    if not text:
        return []
    lines = _Lines(text)
    out = []
    seen = set()
    low_text = None
    for name, rx, _note in _PUBLIC_COMPILED:
        if not _anchored(name, text):
            continue
        for m in rx.finditer(text):
            v = m.group(0)
            if v in seen or is_placeholder(v):
                continue
            if name == "supabase-anon-jwt" and decode_jwt_role(v)["class"] != "public":
                continue
            if name == "firebase-web-api-key":
                if low_text is None:
                    low_text = text.lower()
                if not _firebase_context(text, low_text, m.start(), m.end()):
                    continue
            seen.add(v)
            out.append((name, lines.line(m.start())))
    return out


_REDACT_RX = [rx for _n, rx, _s in _COMPILED] + [_JWT_RX, _GOOGLE_RX] + [rx for _n, rx, _x in _PUBLIC_COMPILED]


def _mask(s: str) -> str:
    n = len(s)
    k = 4 if n >= 20 else (2 if n >= 16 else 0)  # nothing shown under 16, like _wardcore.mask
    return "%s[%d chars]%s" % (s[:k], n - 2 * k, s[n - k:] if k else "")


def redact(text: str) -> str:
    """Mask every secret-shaped or key-shaped value in text (same format as _wardcore.mask)."""
    if not text:
        return text
    out = text
    for rx in _REDACT_RX:
        out = rx.sub(lambda m: m.group(0) if "chars]" in m.group(0) else _mask(m.group(0)), out)
    return out
