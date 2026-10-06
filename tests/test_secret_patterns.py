import base64
import re

import pytest

import _secret_patterns as sp
from conftest import _fake_token as tok
from conftest import _make_jwt as jwt

# Built at run time so no realistic secret is ever stored in this file.
AWS_BODY = "Q7WE2RT3YU4IO5PA"
PEM_BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" + tok("", 13)


def samples():
    return {
        "stripe-live-secret-key": "sk_" + "live_" + tok(),
        "stripe-test-secret-key": "rk_" + "test_" + tok(),
        "stripe-webhook-secret": "whsec_" + tok("", 32),
        "openai-api-key": "sk-" + "proj-" + tok("", 48),
        "openai-legacy-key": "sk-" + tok("", 20) + "T3Blbk" + "FJ" + tok("", 20),
        "anthropic-api-key": "sk-" + "ant-api03-" + tok("", 93) + "AA",
        "anthropic-admin-key": "sk-" + "ant-admin01-" + tok("", 93) + "AA",
        "aws-access-key-id": "AK" + "IA" + AWS_BODY,
        "github-token": "gh" + "p_" + tok("", 36),
        "github-fine-grained-token": "github_" + "pat_" + tok("", 82),
        "supabase-secret-key": "sb_" + "secret_" + tok("", 32),
        "sendgrid-api-key": "S" + "G." + tok("", 22) + "." + tok("", 43),
        "slack-bot-token": "xo" + "xb-" + "4958203716" + "2-" + "8273645190" + "3-" + tok("", 24),
        "mapbox-secret-token": "sk" + ".eyJ" + tok("", 30) + "." + tok("", 22),
        "laravel-app-key": "APP_KEY=" + "base64:" + tok("", 43) + "=",
        "openrouter-api-key": "sk-" + "or-v1-" + "3f9a1c2b7e8d4a6f0b5c9e1d2a7f4b8c" * 2,
        "groq-api-key": "gs" + "k_" + tok("", 52),
        "xai-api-key": "xa" + "i-" + tok("", 80),
        "huggingface-token": "h" + "f_" + ("QwErTyUiOpAsDfGhJkLzXcVbNm" * 2)[:34],
        "npm-access-token": "np" + "m_" + tok("", 36),
        "gitlab-token": "gl" + "pat-" + tok("", 20),
        "gitlab-token-routable": "gl" + "pat-" + tok("", 31) + ".01" + "q7w9e2r",
        "supabase-access-token": "sb" + "p_" + tok("", 40),
        "stripe-org-key": "sk_" + "org_" + tok("", 32),
        "google-oauth-client-secret": "GOC" + "SPX-" + tok("", 28),
        "discord-bot-token": base64.b64encode(b"804512937165019136").decode().rstrip("=")
        + "." + tok("", 6) + "." + tok("", 38),
    }


@pytest.mark.parametrize("name", sorted(samples()))
def test_each_pattern_matches_its_sample(name):
    value = samples()[name]
    text = "const k = '%s'\n" % value
    hits = sp.find_secrets_in_text(text)
    assert [h.name for h in hits] == [name], hits
    assert hits[0].line == 1
    assert hits[0].kind == "secret"
    assert hits[0].severity in ("critical", "high")
    assert name in sp.DESCRIPTIONS and name in sp.ROTATION_REF


def test_pattern_table_shape():
    names = [n for n, _rx, _s in sp.HIGH_CONFIDENCE]
    assert len(names) == len(set(names))
    for name, rx, sev in sp.HIGH_CONFIDENCE:
        re.compile(rx)
        assert sev in ("critical", "high", "medium", "low")
    for name, rx, note in sp.PUBLIC_BY_DESIGN:
        if rx:
            re.compile(rx)
        assert note


def test_stripe_live_is_critical_test_is_high():
    by = {h.name: h.severity for h in sp.find_secrets_in_text(
        "a=%s\nb=%s\n" % ("sk_" + "live_" + tok(), "sk_" + "test_" + tok()))}
    assert by == {"stripe-live-secret-key": "critical", "stripe-test-secret-key": "high"}


@pytest.mark.parametrize("value", [
    "sk_" + "live_" + "x" * 24,
    "sk_" + "test_" + "X" * 30,
    "sk_" + "live_" + "your-api-key-goes-here",
    "sk_" + "live_" + "YOURSTRIPEKEYHERE1234",
    "sk_" + "test_" + "1234567890abcdef",
    "AK" + "IA" + "IOSFODNN7" + "EXAMPLE",
    "gh" + "p_" + "0" * 36,
    "sb_" + "secret_" + "replace_me_with_real_key",
    "sk-" + "proj-" + "placeholder-placeholder-1",
    "sk_" + "test_" + "4eC39HqLyjW" + "DarjtT1zdp7dc",
])
def test_placeholders_are_not_reported(value):
    assert sp.is_placeholder(value)
    assert sp.find_secrets_in_text("KEY=%s\n" % value) == []


def test_placeholder_markers():
    assert sp.is_placeholder("${STRIPE_SECRET_KEY}")
    assert sp.is_placeholder("<your key>")
    assert sp.is_placeholder("")
    assert not sp.is_placeholder("sk_" + "live_" + tok())


@pytest.mark.parametrize("text", [
    "pk_" + "live_" + tok(),
    "pk_" + "test_" + tok(),
    "sb_" + "publishable_" + tok("", 30),
    "https://" + "3f9a1c2b7e8d4a6f0b5c9e1d2a7f4b8c" + "@o123.ingest.sentry.io/456",
    "phc_" + tok("", 40),
    "pk" + ".eyJ" + tok("", 30) + "." + tok("", 22),
])
def test_public_by_design_not_reported(text):
    assert sp.find_secrets_in_text("x = '%s'\n" % text) == []
    assert sp.public_by_design(text)
    assert sp.find_public_keys("x = '%s'\n" % text)


def test_supabase_anon_jwt_is_public_service_role_is_secret():
    anon = jwt({"iss": "supabase", "ref": "abcdefghijklmnop", "role": "anon"})
    service = jwt({"iss": "supabase", "ref": "abcdefghijklmnop", "role": "service_role"})
    assert sp.decode_jwt_role(anon) == {"role": "anon", "iss": "supabase", "ref": "abcdefghijklmnop",
                                        "class": "public"}
    assert sp.decode_jwt_role(service)["class"] == "secret"
    assert sp.find_secrets_in_text("NEXT_PUBLIC_SUPABASE_ANON_KEY=%s\n" % anon) == []
    assert sp.public_by_design(anon) == "supabase-anon-jwt"
    assert [n for n, _l in sp.find_public_keys("k=%s" % anon)] == ["supabase-anon-jwt"]
    hits = sp.find_secrets_in_text("SUPABASE_KEY=%s\n" % service)
    assert [(h.name, h.severity) for h in hits] == [("supabase-service-role-jwt", "critical")]
    assert sp.public_by_design(service) is None


def test_supabase_demo_keys():
    demo_anon = jwt({"role": "anon", "iss": "supabase-demo"})
    demo_service = jwt({"role": "service_role", "iss": "supabase-demo"})
    assert sp.decode_jwt_role(demo_anon)["class"] == "demo-public"
    assert sp.decode_jwt_role(demo_service)["class"] == "demo-secret"
    names = {h.name: h.severity for h in sp.find_secrets_in_text("a=%s\nb=%s\n" % (demo_anon, demo_service))}
    assert names == {"supabase-demo-anon-jwt": "high", "supabase-demo-service-role-jwt": "critical"}


def test_other_jwts_are_ignored():
    user = jwt({"sub": "123", "role": "authenticated"})
    assert sp.decode_jwt_role(user)["class"] == "unknown"
    assert sp.find_secrets_in_text("t=%s" % user) == []
    assert sp.decode_jwt_role("not-a-jwt")["class"] == "invalid"
    assert sp.decode_jwt_role("eyJhbGciOiJIUzI1NiJ9.!!!.sig")["class"] == "invalid"
    assert sp.decode_jwt_role("")["class"] == "invalid"


def test_google_key_firebase_context_vs_note():
    key = "AI" + "za" + tok("", 35)
    firebase = "const firebaseConfig = {\n  apiKey: '%s',\n  authDomain: 'x.firebaseapp.com',\n}\n" % key
    assert sp.find_secrets_in_text(firebase) == []
    assert [n for n, _l in sp.find_public_keys(firebase)] == ["firebase-web-api-key"]
    assert sp.find_secrets_in_text("VITE_FIREBASE_API_KEY=%s\n" % key) == []
    hits = sp.find_secrets_in_text("GOOGLE_MAPS_KEY=%s\n" % key)
    assert [(h.name, h.severity, h.kind) for h in hits] == [("google-api-key", "info", "note")]


def test_private_key_needs_a_body():
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    real = header + "\n" + PEM_BODY + "\n" + PEM_BODY + "\n-----END RSA PRIVATE KEY-----\n"
    hits = sp.find_secrets_in_text(real)
    assert [h.name for h in hits] == ["private-key"]
    escaped = '{"key": "' + "-----BEGIN " + "PRIVATE KEY-----\\n" + PEM_BODY + '\\n-----END PRIVATE KEY-----\\n"}'
    assert [h.name for h in sp.find_secrets_in_text(escaped)] == ["private-key"]
    code = "if (pem.startsWith('-----BEGIN " + "PRIVATE KEY')) {\n  return parsePrivateKeyFromPemStringWithValidation(pem)\n}\n"
    assert sp.find_secrets_in_text(code) == []
    docs = header + "\nMIIE...\n-----END RSA PRIVATE KEY-----\n"
    assert sp.find_secrets_in_text(docs) == []


def test_service_account_reported_once():
    pk = "-----BEGIN " + "PRIVATE KEY-----\\n" + PEM_BODY + "\\n-----END PRIVATE KEY-----\\n"
    sa = ('{\n  "type": "service_account",\n  "project_id": "demo",\n  "private_key_id": "%s",\n'
          '  "private_key": "%s",\n  "client_email": "x@demo.iam.gserviceaccount.com"\n}\n') % (tok("", 40), pk)
    hits = sp.find_secrets_in_text(sa)
    assert [(h.name, h.line) for h in hits] == [("gcp-service-account", 2)]
    no_key = '{"type": "service_account", "private_key": "process.env.KEY"}'
    assert sp.find_secrets_in_text(no_key) == []


@pytest.mark.parametrize("url,reported", [
    ("postgres://app:" + tok("", 20) + "@db.prod-cluster.internal.net:5432/app", True),
    ("mongodb+srv://admin:" + tok("", 16) + "@cluster0.ab12c.mongodb.net/db", True),
    ("postgres://postgres:postgres@localhost:5432/app", False),
    ("postgres://app:" + tok("", 20) + "@localhost:5432/app", False),
    ("postgres://app:" + tok("", 20) + "@db:5432/app", False),
    ("postgresql://user:password@db.example.com/x", False),
    ("postgres://${DB_USER}:${DB_PASS}@db.prod.net/app", False),
    ("mysql://root:<password>@db.prod.net/app", False),
    ("redis://default:" + tok("", 20) + "@your-host.upstash.io:6379", False),
])
def test_database_urls(url, reported):
    hits = sp.find_secrets_in_text("DATABASE_URL=%s\n" % url)
    assert bool(hits) is reported, hits
    if reported:
        assert hits[0].name == "database-url-password"


def test_identifier_chains_are_not_discord_tokens():
    code = "x = NotificationServiceProviderX.render.someVeryLongPropertyNameThatIsLong9\n"
    assert sp.find_secrets_in_text(code) == []
    letters_only = "token = hf_" + "abcdefghijklmnopqrstuvwxyzabcdefgh" + "\n"
    assert sp.find_secrets_in_text(letters_only) == []


def test_same_value_reported_once_per_text_and_lines():
    key = "sk_" + "live_" + tok()
    text = "a\nx=%s\ny=%s\n" % (key, key)
    hits = sp.find_secrets_in_text(text)
    assert len(hits) == 1 and hits[0].line == 2


def test_redact_masks_every_secret_shape():
    key = "sk_" + "live_" + tok()
    anon = jwt({"role": "anon"})
    out = sp.redact("a=%s b=%s c=%s" % (key, anon, "pk_" + "live_" + tok()))
    assert key not in out and anon not in out and "pk_" + "live_" + tok() not in out
    assert out.count("chars]") == 3
    assert sp.redact(out) == out
    assert sp.redact("") == ""


def test_mask_matches_wardcore_thresholds():
    import _wardcore as wc
    for n in (8, 12, 15, 16, 19, 20, 40):
        value = tok("", n)[:n]
        assert sp._mask(value) == wc.mask(value), n
    assert sp._mask(tok("", 14)[:14]) == "[14 chars]"


def test_scanner_source_does_not_flag_itself():
    from pathlib import Path
    from conftest import SCRIPTS_DIR
    for name in ("_secret_patterns.py", "find_secrets.py", "_wardcore.py", "scan_app.py"):
        text = (Path(SCRIPTS_DIR) / name).read_text(encoding="utf-8")
        assert [h for h in sp.find_secrets_in_text(text) if h.kind == "secret"] == [], name


# --- anchors, templates and the newer shapes ------------------------------------------------

def test_every_pattern_has_an_anchor_entry_and_samples_contain_one():
    names = [n for n, _rx, _s in sp.HIGH_CONFIDENCE] + [n for n, rx, _note in sp.PUBLIC_BY_DESIGN if rx]
    for name in names + ["jwt", "google-api-key"]:
        assert name in sp.ANCHORS, name
    for name, value in samples().items():
        anchors = sp.ANCHORS[name]
        assert anchors is None or any(a in value for a in anchors), name


def test_text_without_anchors_skips_patterns_but_still_finds_secrets():
    filler = "msgid \"Hello\"\nmsgstr \"Hallo\"\n" * 2000
    assert sp.find_secrets_in_text(filler) == []
    key = "sk_" + "live_" + tok()
    hits = sp.find_secrets_in_text(filler + "x=%s\n" % key)
    assert [h.name for h in hits] == ["stripe-live-secret-key"]


def test_routable_gitlab_token_reported_once():
    value = "gl" + "pat-" + tok("", 20) + "-" + tok("", 10) + ".01" + "q7w9e2r"
    assert [h.name for h in sp.find_secrets_in_text("t = '%s'\n" % value)] == ["gitlab-token-routable"]


@pytest.mark.parametrize("value", [
    # random keys may contain %( or %s by chance (Django's get_random_secret_key alphabet has both)
    "q7w%(e9rt2yu4io6pa8sd1fg3hj5kl0zmcvbnn!@#$^&*-_=+)ab",
    "zx%s!q7we9rt2yu4io6pa8sd1fg3hj5kl0zmcv",
])
def test_random_values_with_percent_signs_are_not_templates(value):
    assert not sp.is_placeholder(value)


@pytest.mark.parametrize("value", [
    "${SECRET_KEY}", "{{ secret_key }}", "%(secret)s", "%s", "$SECRET_KEY", "<your-secret>", "<API_KEY>",
    "process.env.SECRET",
])
def test_templates_are_placeholders(value):
    assert sp.is_placeholder(value)


@pytest.mark.parametrize("url,reported", [
    ("postgresql://postgres:[password]@db.[project-ref].supabase.co:5432/postgres", False),
    ("postgres://app:{password}@db.prod.net/app", False),
    ("postgres://app:YOUR_DB_PASSWORD@db.prod.net/app", False),
    # a real password may contain %( and still be reported
    ("postgres://app:" + "Q7w%(E9rT2yU4iO6pA8" + "@db.prod-cluster.internal.net:5432/app", True),
])
def test_database_url_placeholders(url, reported):
    hits = sp.find_secrets_in_text("DATABASE_URL=%s\n" % url)
    assert bool(hits) is reported, hits


def test_supabase_demo_keys_with_a_local_url_are_info():
    demo_service = jwt({"role": "service_role", "iss": "supabase-demo"})
    demo_anon = jwt({"role": "anon", "iss": "supabase-demo"})
    for url in ("http://127.0.0.1:54321", "http://localhost:54321", "http://host.docker.internal:54321",
                "http://supabase_kong_myapp:8000"):
        text = "VITE_SUPABASE_URL=%s\nSERVICE_ROLE_KEY=%s\nANON_KEY=%s\n" % (url, demo_service, demo_anon)
        got = [(h.name, h.severity, h.kind) for h in sp.find_secrets_in_text(text)]
        assert got == [("supabase-local-demo-jwt", "info", "note")] * 2, (url, got)
    hosted = "SUPABASE_URL=https://abcdefgh.supabase.co\nLOCAL=http://127.0.0.1:54321\nKEY=%s\n" % demo_service
    assert [(h.name, h.severity) for h in sp.find_secrets_in_text(hosted)] == [
        ("supabase-demo-service-role-jwt", "critical")]


def test_aws_key_in_a_presigned_credential_scope_is_a_note():
    key_id = "AK" + "IA" + AWS_BODY
    for text in ("'x-amz-credential': '%s/20220405/eu-central-1/s3/aws4_request',\n" % key_id,
                 "https://b.s3.amazonaws.com/k?X-Amz-Credential=%s%%2F20240101%%2Fus-east-1" % key_id):
        got = [(h.name, h.severity, h.kind) for h in sp.find_secrets_in_text(text)]
        assert got == [("aws-access-key-id-presigned", "info", "note")], (text, got)
    assert [h.name for h in sp.find_secrets_in_text("AWS_ACCESS_KEY_ID=%s\n" % key_id)] == ["aws-access-key-id"]


def test_webhook_secret_description_names_svix_senders():
    assert "Svix" in sp.DESCRIPTIONS["stripe-webhook-secret"]


# --- context patterns ---------------------------------------------------------------------------

GRADLE_RELEASE = (
    "android {\n    signingConfigs {\n        release {\n            storeFile file('upload.keystore')\n"
    "            storePassword '%s'\n            keyAlias 'upload'\n            keyPassword '%s'\n        }\n"
    "    }\n}\n")


def test_gradle_literal_signing_passwords():
    pw = tok("", 14)
    hits = sp.find_context_secrets(GRADLE_RELEASE % (pw, pw), "android/app/build.gradle")
    assert [(h.name, h.severity, h.line) for h in hits] == [("gradle-signing-password", "high", 5)]
    props = "android.useAndroidX=true\nMYAPP_UPLOAD_STORE_PASSWORD=%s\n" % pw
    assert [h.line for h in sp.find_context_secrets(props, "android/gradle.properties")] == [2]


@pytest.mark.parametrize("rel,text", [
    ("android/app/build.gradle", "signingConfigs {\n  release {\n    storePassword System.getenv('STORE_PW')\n"
                                 "    keyPassword keystoreProperties['keyPassword']\n  }\n  debug {\n"
                                 "    storePassword 'android'\n  }\n}\n"),
    ("android/app/build.gradle.kts", "storePassword = providers.gradleProperty(\"pw\").get()\n"),
    ("android/gradle.properties", "MYAPP_UPLOAD_STORE_PASSWORD=*****\nMYAPP_UPLOAD_KEY_PASSWORD=*****\n"),
    ("src/app.ts", "storePassword 'not-gradle-at-all'\n"),
])
def test_gradle_safe_shapes(rel, text):
    assert sp.find_context_secrets(text, rel) == []


def test_literal_password_passed_to_create_user():
    pw = tok("", 12)
    text = ("const admin = require('firebase-admin')\nconst email = 'owner@example.invalid'\n"
            "const password = '%s'\nawait admin.auth().createUser({ email, password, displayName: 'Owner' })\n" % pw)
    hits = sp.find_context_secrets(text, "scripts/create-admin.cjs")
    assert [(h.name, h.severity, h.line) for h in hits] == [("hardcoded-login-password", "high", 3)]
    inline = "await supabase.auth.signInWithPassword({ email: 'demo@x.invalid', password: '%s' })\n" % pw
    assert [(h.name, h.severity) for h in sp.find_context_secrets(inline, "src/Login.tsx")] == [
        ("hardcoded-login-password", "medium")]
    positional = "const pw = '%s'\nsignInWithEmailAndPassword(auth, 'a@x.invalid', pw)\n" % pw
    assert [h.line for h in sp.find_context_secrets(positional, "src/login.js")] == [1]


@pytest.mark.parametrize("rel,text", [
    # the password comes from the form
    ("src/Signup.tsx", "const [password, setPassword] = useState('')\n"
                       "await supabase.auth.signUp({ email, password })\n"),
    ("src/login.ts", "await signInWithEmailAndPassword(auth, email, form.password)\n"),
    ("src/admin.ts", "await admin.auth().createUser({ email, password: process.env.ADMIN_PASSWORD })\n"),
    # tests and seed data log in with throwaway passwords on purpose
    ("e2e/login.spec.ts", "await page.signInWithPassword({ email: 'a@x.invalid', password: 'Q7wE9rT2yU4i' })\n"),
    ("supabase/seed.ts", "await auth.admin.createUser({ email: 'a@x.invalid', password: 'Q7wE9rT2yU4i' })\n"),
    ("scripts/create-user.ts", "await auth.admin.createUser({ email, password: 'changeme' })\n"),
])
def test_login_password_safe_shapes(rel, text):
    assert sp.find_context_secrets(text, rel) == []
