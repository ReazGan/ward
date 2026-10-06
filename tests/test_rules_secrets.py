import hashlib
import json
import re
from pathlib import Path

import pytest

import _rules_secrets as rs
from conftest import REPO_ROOT

NEXT_PKG = json.dumps({"dependencies": {"next": "14.2.30", "react": "18.2.0"}})
VITE_PKG = json.dumps({"dependencies": {"react": "18", "react-dom": "18"}, "devDependencies": {"vite": "5"}})
EXPO_PKG = json.dumps({"dependencies": {"expo": "51", "react-native": "0.74"}})
CRA_PKG = json.dumps({"dependencies": {"react": "18", "react-scripts": "5"}})
EXPRESS_PKG = json.dumps({"dependencies": {"express": "4"}})


def _found(scan_rules, root, rule):
    res = scan_rules(root, rule_ids=[rule])
    assert not [w for w in res.warnings if rule in str(w)], res.warnings
    return [(f.file, f.line, f.severity) for f in res.findings if f.rule == rule]


def _files(scan_rules, root, rule):
    return sorted({f for f, _, _ in _found(scan_rules, root, rule)})


# --- name classification -----------------------------------------------------------------

@pytest.mark.parametrize("name,kind", [
    ("OPENAI_API_KEY", "provider"), ("GEMINI_API_KEY", "provider"), ("ANTHROPIC_API_KEY", "provider"),
    ("STRIPE_SECRET_KEY", "secret"), ("AWS_SECRET_ACCESS_KEY", "secret"), ("CLERK_SECRET_KEY", "secret"),
    ("SUPABASE_SERVICE_ROLE_KEY", "service"), ("SUPABASE_SERVICE_KEY", "service"), ("JWT_SECRET", "signing"),
    ("NEXTAUTH_SECRET", "signing"), ("SECRET_KEY", "signing"), ("DB_PASSWORD", "password"),
    ("DATABASE_URL", "db"), ("FIREBASE_PRIVATE_KEY", "private"), ("ALGOLIA_ADMIN_KEY", "admin"),
    ("GITHUB_TOKEN", "provider"), ("STRIPE_SK", "secret"), ("OPENAI_API_KEY_PROD", "provider"),
    ("API_TOKEN", "token"), ("DISCORD_WEBHOOK_URL", "token"), ("SENTRY_AUTH_TOKEN", "token"),
    ("GOOGLE_SERVICE_ACCOUNT_KEY", "private"),
])
def test_classify_secret_names(name, kind):
    assert rs.classify_name(name) == kind


@pytest.mark.parametrize("name", [
    "SUPABASE_ANON_KEY", "SUPABASE_URL", "STRIPE_PUBLISHABLE_KEY", "FIREBASE_API_KEY", "RECAPTCHA_SITE_KEY",
    "TURNSTILE_SITEKEY", "SENTRY_DSN", "POSTHOG_KEY", "MAPBOX_ACCESS_TOKEN", "PASSWORD_MIN_LENGTH",
    "PASSWORD_RESET_URL", "SECRET_SANTA_URL", "GITHUB_CLIENT_ID", "PRIVATE_BETA", "PRIVATE_KEY_ID",
    "INCLUDE_CREDENTIALS", "CSRF_TOKEN", "UPSTASH_REDIS_REST_URL", "VAPID_PUBLIC_KEY", "API_URL",
    "OPENAI_MODEL", "SERVICE_ACCOUNT_EMAIL", "GOOGLE_MAPS_API_KEY", "API_KEY",
])
def test_classify_public_or_harmless_names(name):
    assert rs.classify_name(name) is None


def test_classify_loose_mode():
    assert rs.classify_name("API_KEY", loose=True) == "key"
    assert rs.classify_name("GOOGLE_MAPS_API_KEY", loose=True) is None
    assert rs.classify_name("FIREBASE_API_KEY", loose=True) is None
    assert rs.camel_to_upper("openaiApiKey") == "OPENAI_API_KEY"


def test_weak_secret_values(monkeypatch):
    for v in ("secret", "keyboard cat", "changeme", "django-insecure-abc", "your-secret-key", "short-one"):
        assert rs.weak_secret(v), v
    assert not rs.weak_secret("Q7wE9rT2yU4iO6pA8sD1fG3hJ5kL0zMc")
    # Published tutorial keys are stored as hashes only.
    made_up = "4f1c" * 16
    monkeypatch.setitem(rs._PUBLISHED_KEY_HASHES, hashlib.sha256(made_up.encode()).hexdigest(), "test key")
    assert rs.weak_secret(made_up)


def test_split_args_and_block_end():
    text = "jwt.sign({ id: user.id, role }, 'k', { expiresIn: '1h' })"
    args = rs.split_args(text, text.index("("))
    assert [a.strip() for a, _ in args] == ["{ id: user.id, role }", "'k'", "{ expiresIn: '1h' }"]
    assert rs.literal_value(args[1][0]) == "k"
    assert rs.literal_value("`a${b}`") is None
    assert rs.block_end("{ a: '}', b: { c: 1 } } tail", 0) == len("{ a: '}', b: { c: 1 } }")


def test_call_context():
    s = "({ token: jwt.sign({ id }, process.env.JWT_SECRET), k: String(process.env.KEY), t: `a${process.env.T}` })"
    assert rs.call_context(s, s.index("process.env.JWT")) == (False, ["jwt.sign"])
    assert rs.call_context(s, s.index("process.env.KEY")) == (False, ["String"])
    assert rs.call_context(s, s.index("process.env.T")) == (False, [])
    q = "({ e: 'set process.env.X' })"
    assert rs.call_context(q, q.index("process"))[0] is True
    py = 'return {"t": jwt.encode(p, os.getenv("S")), "k": str(os.getenv("K"))}'
    assert rs.call_context(py, py.index('os.getenv("S")'), py=True)[1] == ["jwt.encode"]
    assert rs._passed_through(rs.call_context(py, py.index('os.getenv("K")'), py=True)[1])


def test_lookup_name():
    assert rs.lookup_name("SESSION_KEY", "user_session")
    assert rs.lookup_name("jwtKey", "jwt")
    assert not rs.lookup_name("SESSION_KEY", "Q7wE9rT2yU4iO6pA8sD1fG3h")
    assert not rs.lookup_name("SESSION_KEY", "my-secret")
    assert not rs.lookup_name("SECRET_KEY", "cart")
    assert not rs.lookup_name("SESSION_SECRET", "user_session")


def test_in_js_string():
    line = "const doc = 'call jwt.sign(p, \"x\")'; jwt.sign(p, k)"
    assert rs.in_js_string(line, line.index("jwt"))
    assert not rs.in_js_string(line, line.rindex("jwt"))
    assert rs.in_js_string("// jwt.sign(p, 'x')", 3)


# --- secret-public-env-prefix / secret-public-env-token -----------------------------------

@pytest.mark.parametrize("files,where", [
    ({"package.json": NEXT_PKG, ".env.local": "NEXT_PUBLIC_OPENAI_API_KEY=\nNEXT_PUBLIC_SITE_URL=http://localhost\n"},
     ".env.local"),
    ({"package.json": NEXT_PKG,
      "app/chat/page.tsx": "'use client'\nconst key = process.env.NEXT_PUBLIC_OPENAI_API_KEY\n"}, "app/chat/page.tsx"),
    ({"package.json": VITE_PKG,
      "src/lib/supabase.ts": "export const s = createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY)\n"},
     "src/lib/supabase.ts"),
    ({"package.json": EXPO_PKG, "app/index.tsx": "const k = process.env.EXPO_PUBLIC_OPENAI_API_KEY\n"},
     "app/index.tsx"),
    ({"package.json": CRA_PKG, "src/pay.js": "const s = process.env.REACT_APP_STRIPE_SECRET_KEY\n"}, "src/pay.js"),
    ({"package.json": EXPO_PKG, "app/chat.tsx": "import { OPENAI_API_KEY, API_URL } from '@env'\n"}, "app/chat.tsx"),
    ({"package.json": NEXT_PKG,
      ".github/workflows/deploy.yml": "env:\n  NEXT_PUBLIC_DATABASE_URL: ${{ secrets.DB_URL }}\n"},
     ".github/workflows/deploy.yml"),
    ({"package.json": VITE_PKG, ".env": "VITE_GEMINI_API_KEY=\n"}, ".env"),
])
def test_public_env_prefix_fires(tmp_path, write_tree, scan_rules, files, where):
    write_tree(tmp_path, files)
    assert _files(scan_rules, tmp_path, "secret-public-env-prefix") == [where]


@pytest.mark.parametrize("files", [
    {"package.json": NEXT_PKG, ".env.local": (
        "NEXT_PUBLIC_SUPABASE_URL=https://x.supabase.co\nNEXT_PUBLIC_SUPABASE_ANON_KEY=\n"
        "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=\nNEXT_PUBLIC_RECAPTCHA_SITE_KEY=\nNEXT_PUBLIC_SENTRY_DSN=\n"
        "NEXT_PUBLIC_POSTHOG_KEY=\nNEXT_PUBLIC_PASSWORD_MIN_LENGTH=8\nNEXT_PUBLIC_FIREBASE_API_KEY=\n")},
    {"package.json": VITE_PKG, "src/firebase.ts": "const c = { apiKey: import.meta.env.VITE_FIREBASE_API_KEY }\n"},
    # server-only names without a public prefix are correct
    {"package.json": NEXT_PKG, "app/api/chat/route.ts": "const k = process.env.OPENAI_API_KEY\n"},
    # VITE_ is not exposed by Next.js
    {"package.json": NEXT_PKG, "lib/x.ts": "const k = process.env.VITE_OPENAI_API_KEY\n"},
    # commented out, tests, docs
    {"package.json": NEXT_PKG, ".env": "# NEXT_PUBLIC_OPENAI_API_KEY=\n"},
    {"package.json": NEXT_PKG, "tests/env.test.ts": "expect(process.env.NEXT_PUBLIC_OPENAI_API_KEY).toBeUndefined()\n"},
    {"package.json": NEXT_PKG, "README.md": "Never set NEXT_PUBLIC_OPENAI_API_KEY.\n"},
])
def test_public_env_prefix_safe(tmp_path, write_tree, scan_rules, files):
    write_tree(tmp_path, files)
    assert _found(scan_rules, tmp_path, "secret-public-env-prefix") == []
    assert _found(scan_rules, tmp_path, "secret-public-env-token") == []


def test_public_env_token(tmp_path, write_tree, scan_rules, fake_token):
    write_tree(tmp_path, {
        "package.json": NEXT_PKG,
        ".env": ("NEXT_PUBLIC_API_TOKEN=\nNEXT_PUBLIC_DISCORD_WEBHOOK_URL=\nNEXT_PUBLIC_MAPBOX_TOKEN=\n"
                 "NEXT_PUBLIC_CSRF_TOKEN=\nNEXT_PUBLIC_MAP_TOKEN=pk.%s\n" % fake_token("", 30)),
    })
    found = _found(scan_rules, tmp_path, "secret-public-env-token")
    assert [ln for _, ln, _ in found] == [1, 2]
    assert _found(scan_rules, tmp_path, "secret-public-env-prefix") == []


def test_public_env_once_per_name_per_file(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": NEXT_PKG,
        "lib/a.ts": "const a = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY\nconst b = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY\n",
    })
    assert len(_found(scan_rules, tmp_path, "secret-public-env-prefix")) == 1


# --- secret-bundler-inlines-env ------------------------------------------------------------

def test_next_config_env_block(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": NEXT_PKG,
        "next.config.js": ("module.exports = {\n  env: {\n    OPENAI_API_KEY: process.env.OPENAI_API_KEY,\n"
                           "    NEXT_PUBLIC_SITE_URL: process.env.NEXT_PUBLIC_SITE_URL,\n    APP_VERSION: '1.0.0',\n  },\n"
                           "  serverRuntimeConfig: { secret: process.env.SESSION_SECRET },\n}\n"),
    })
    assert _found(scan_rules, tmp_path, "secret-bundler-inlines-env") == [("next.config.js", 3, "critical")]


def test_vite_define_loadenv_all(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": VITE_PKG,
        "vite.config.ts": ("import { defineConfig, loadEnv } from 'vite'\n"
                           "export default defineConfig(({ mode }) => {\n"
                           "  const env = loadEnv(mode, '.', '')\n"
                           "  return {\n"
                           "    define: {\n"
                           "      'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),\n"
                           "      'process.env.NODE_ENV': JSON.stringify(mode),\n"
                           "      __APP_VERSION__: JSON.stringify(env.npm_package_version),\n"
                           "    },\n  }\n})\n"),
    })
    assert _found(scan_rules, tmp_path, "secret-bundler-inlines-env") == [("vite.config.ts", 6, "critical")]


@pytest.mark.parametrize("config", [
    "export default { define: { 'process.env': process.env } }\n",
    "const env = loadEnv(mode, process.cwd(), '')\nexport default { define: { 'process.env': env } }\n",
])
def test_vite_define_whole_env(tmp_path, write_tree, scan_rules, config):
    write_tree(tmp_path, {"package.json": VITE_PKG, "vite.config.js": config})
    found = _found(scan_rules, tmp_path, "secret-bundler-inlines-env")
    assert len(found) == 1 and found[0][2] == "critical"


def test_vite_define_safe(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": VITE_PKG,
        "vite.config.ts": ("const env = loadEnv(mode, process.cwd())\n"
                           "export default { define: { 'process.env': env, 'process.env.NODE_ENV': '\"production\"' } }\n"),
    })
    assert _found(scan_rules, tmp_path, "secret-bundler-inlines-env") == []


def test_webpack_define_plugin_and_expo_extra(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": EXPO_PKG,
        "webpack.config.js": ("new webpack.DefinePlugin({\n"
                              "  'process.env.STRIPE_SECRET_KEY': JSON.stringify(process.env.STRIPE_SECRET_KEY),\n"
                              "  'process.env.NODE_ENV': JSON.stringify('production'),\n})\n"),
        "app.config.js": ("export default {\n  expo: {\n    extra: {\n      apiUrl: process.env.API_URL,\n"
                          "      openaiApiKey: process.env.OPENAI_API_KEY,\n      publicKey: process.env.EXPO_PUBLIC_KEY,\n"
                          "      eas: { projectId: 'abc' },\n    },\n  },\n}\n"),
    })
    found = _found(scan_rules, tmp_path, "secret-bundler-inlines-env")
    assert [(f, ln) for f, ln, _ in found] == [("app.config.js", 5), ("webpack.config.js", 2)]


# --- secret-llm-sdk-in-browser ----------------------------------------------------------

def test_llm_sdk_in_browser_build_time_key(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": VITE_PKG,
        "src/lib/ai.ts": ("import OpenAI from 'openai'\nexport const ai = new OpenAI({\n"
                          "  apiKey: import.meta.env.VITE_OPENAI_API_KEY,\n  dangerouslyAllowBrowser: true,\n})\n"),
        "src/lib/claude.ts": ("export const c = new Anthropic({ apiKey: key, dangerouslyAllowBrowser: true })\n"),
    })
    assert _found(scan_rules, tmp_path, "secret-llm-sdk-in-browser") == [
        ("src/lib/ai.ts", 4, "critical"), ("src/lib/claude.ts", 1, "medium")]


@pytest.mark.parametrize("files", [
    {"package.json": VITE_PKG, "src/byok.ts": (
        "const key = localStorage.getItem('openai_key')\n"
        "export const ai = new OpenAI({ apiKey: key, dangerouslyAllowBrowser: true })\n")},
    {"package.json": NEXT_PKG, "app/api/chat/route.ts": (
        "const ai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY, dangerouslyAllowBrowser: true })\n")},
    {"package.json": VITE_PKG, "src/ai.ts": "const ai = new OpenAI({ dangerouslyAllowBrowser: false })\n"},
    {"package.json": VITE_PKG, "src/ai.test.ts": "new OpenAI({ apiKey: 'x', dangerouslyAllowBrowser: true })\n"},
])
def test_llm_sdk_in_browser_safe(tmp_path, write_tree, scan_rules, files):
    write_tree(tmp_path, files)
    assert _found(scan_rules, tmp_path, "secret-llm-sdk-in-browser") == []


# --- secret-provider-call-from-client ---------------------------------------------------

def test_provider_call_from_client(tmp_path, write_tree, scan_rules):
    call = "await fetch('https://api.openai.com/v1/chat/completions', { method: 'POST' })\n"
    write_tree(tmp_path, {
        "package.json": VITE_PKG,
        "src/api/chat.ts": call,
        "server/index.js": call,
        "src/byok.ts": "const key = localStorage.getItem('apiKey')\n" + call,
        "src/note.ts": "// " + call,
    })
    assert _files(scan_rules, tmp_path, "secret-provider-call-from-client") == ["src/api/chat.ts"]


# --- secret-supabase-admin-in-client ----------------------------------------------------

def test_supabase_admin_in_client(tmp_path, write_tree, scan_rules):
    admin = "const { data } = await supabase.auth.admin.listUsers()\n"
    write_tree(tmp_path, {"package.json": VITE_PKG, "src/pages/Admin.tsx": admin,
                          "supabase/functions/admin/index.ts": admin})
    assert _files(scan_rules, tmp_path, "secret-supabase-admin-in-client") == ["src/pages/Admin.tsx"]

    other = tmp_path / "next"
    write_tree(other, {
        "package.json": NEXT_PKG,
        "app/api/users/route.ts": admin,
        "lib/admin.ts": "import 'server-only'\n" + admin,
        "app/admin/actions.ts": "'use server'\n" + admin,
        "app/admin/panel.tsx": "'use client'\n" + admin,
    })
    assert _files(scan_rules, other, "secret-supabase-admin-in-client") == ["app/admin/panel.tsx"]


# --- secret-env-sent-to-client -----------------------------------------------------------

@pytest.mark.parametrize("files,line", [
    ({"package.json": EXPRESS_PKG, "server.js": "app.get('/api/config', (req, res) => res.json(process.env))\n"}, 1),
    ({"package.json": EXPRESS_PKG, "routes/cfg.js": "router.get('/c', (req, res) => {\n  res.status(200).json({\n"
      "    url: process.env.SUPABASE_URL,\n    openaiKey: process.env.OPENAI_API_KEY,\n  })\n})\n"}, 4),
    ({"package.json": NEXT_PKG, "app/api/key/route.ts": (
        "export async function GET() {\n  return NextResponse.json({ key: process.env.ANTHROPIC_API_KEY })\n}\n")}, 2),
    ({"package.json": NEXT_PKG, "pages/index.tsx": (
        "export async function getServerSideProps() {\n  return { props: { env: process.env } }\n}\n")}, 2),
    ({"package.json": NEXT_PKG, "app/page.tsx": (
        "export default function Page() {\n  return <Chat apiKey={process.env.OPENAI_API_KEY} />\n}\n")}, 2),
    ({"app.py": "from flask import Flask, jsonify\nimport os\napp = Flask(__name__)\n@app.route('/debug')\n"
      "def debug():\n    return jsonify(dict(os.environ))\n"}, 6),
    ({"main.py": "import os\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get('/config')\n"
      "def config():\n    return {\"key\": os.getenv(\"OPENAI_API_KEY\")}\n"}, 6),
    ({"public/info.php": "<?php\nphpinfo();\n"}, 2),
    # wrappers that only encode the value still send it
    ({"package.json": EXPRESS_PKG, "server.js": "app.get('/k', (req, res) => res.json({ k: String(process.env.OPENAI_API_KEY) }))\n"}, 1),
    ({"package.json": EXPRESS_PKG, "server.js": "app.get('/k', (req, res) => {\n  res.send(`key=${process.env.STRIPE_SECRET_KEY}`)\n})\n"}, 2),
    ({"main.py": "import os\nfrom flask import Flask, jsonify\napp = Flask(__name__)\n@app.route('/k')\n"
      "def k():\n    return jsonify({\"key\": str(os.environ[\"OPENAI_API_KEY\"])})\n"}, 6),
])
def test_env_sent_to_client_fires(tmp_path, write_tree, scan_rules, files, line):
    write_tree(tmp_path, files)
    found = _found(scan_rules, tmp_path, "secret-env-sent-to-client")
    assert [ln for _, ln, _ in found] == [line], found


@pytest.mark.parametrize("files", [
    {"package.json": EXPRESS_PKG, "server.js": (
        "app.get('/api/public-config', (req, res) => {\n  res.json({ supabaseUrl: process.env.SUPABASE_URL,\n"
        "    stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY, anon: process.env.SUPABASE_ANON_KEY })\n})\n"
        "app.get('/health', (req, res) => res.json({ openai: !!process.env.OPENAI_API_KEY,\n"
        "  stripe: Boolean(process.env.STRIPE_SECRET_KEY), mode: process.env.NODE_ENV }))\n"
        "app.get('/names', (req, res) => res.json(Object.keys(process.env)))\n"
        "const doc = 'never do res.json(process.env)'\n")},
    {"tools.py": "import os, subprocess\n\ndef run(cmd):\n    return dict(os.environ, PYTHONUTF8='1')\n\n"
                 "def call(cmd):\n    subprocess.run(cmd, env=dict(os.environ))\n"},
    {"main.py": "import os\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get('/ok')\ndef ok():\n"
                "    return {\"configured\": bool(os.getenv(\"OPENAI_API_KEY\"))}\n"
                "DOC = \"\"\"\nreturn jsonify(dict(os.environ))\n\"\"\"\n"},
    {"index.php": "<?php\nprint_r($_SERVER['REQUEST_URI']);\n$e = 'phpinfo()';\n"},
    # the secret is used to sign the response, not sent in it
    {"package.json": EXPRESS_PKG, "routes/auth.js": (
        "router.post('/login', async (req, res) => {\n"
        "  res.json({ token: jwt.sign({ id: u.id }, process.env.JWT_SECRET, { expiresIn: '1h' }) })\n})\n"
        "app.get('/sig', (req, res) => res.send(crypto.createHmac('sha256', process.env.SIGNING_SECRET).update(x).digest('hex')))\n"
        "app.get('/e', (req, res) => res.status(500).json({ error: 'set process.env.OPENAI_API_KEY first' }))\n")},
    {"main.py": "import os, jwt\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.post('/login')\ndef login():\n"
                "    return {\"token\": jwt.encode({'sub': 1}, os.getenv(\"JWT_SECRET\"), algorithm='HS256')}\n"},
])
def test_env_sent_to_client_safe(tmp_path, write_tree, scan_rules, files):
    write_tree(tmp_path, files)
    assert _found(scan_rules, tmp_path, "secret-env-sent-to-client") == []


# --- secret-admin-sdk-in-client ----------------------------------------------------------

def test_admin_sdk_in_client(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": json.dumps({"dependencies": {"react": "18", "firebase": "10", "firebase-admin": "12"},
                                    "devDependencies": {"vite": "5"}}),
        "src/lib/admin.ts": "import admin from 'firebase-admin'\nimport sa from './serviceAccountKey.json'\n",
        "src/lib/firebase.ts": "import { initializeApp } from 'firebase/app'\nexport const app = initializeApp(cfg)\n",
        "functions/src/index.ts": "import * as admin from 'firebase-admin'\nadmin.initializeApp()\n",
        "public/serviceAccountKey.json": json.dumps({"type": "service_account", "project_id": "demo",
                                                     "private_key": "redacted", "client_email": "x@demo.invalid"}),
        "public/manifest.json": json.dumps({"name": "demo"}),
    })
    found = _found(scan_rules, tmp_path, "secret-admin-sdk-in-client")
    assert [(f, ln) for f, ln, _ in found] == [
        ("public/serviceAccountKey.json", 1), ("src/lib/admin.ts", 1), ("src/lib/admin.ts", 2)]


# --- secret-signing-fallback ------------------------------------------------------------

@pytest.mark.parametrize("path,text,sev", [
    ("lib/auth.ts", "const secret = process.env.JWT_SECRET || 'secret'\n", "critical"),
    ("lib/auth.ts", "const s = process.env.SESSION_SECRET ?? 'Q7wE9rT2yU4iO6pA8sD1fG3hJ5kL0zMc'\n", "high"),
    ("lib/auth.ts", "const { NEXTAUTH_SECRET = 'dev' } = process.env\n", "critical"),
    ("lib/admin.ts", "if (pw === (process.env.ADMIN_PASSWORD || 'admin123')) ok()\n", "critical"),
    ("app/config.py", "SECRET_KEY = os.getenv('SECRET_KEY', 'dev')\n", "critical"),
    ("mysite/settings.py", "SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'django-insecure-abc123')\n", "critical"),
    ("app/core/config.py", "class Settings(BaseSettings):\n    jwt_secret: str = \"changeme\"\n", "critical"),
    ("config/jwt.php", "<?php return ['secret' => env('JWT_SECRET', 'secret')];\n", "critical"),
    ("docker-compose.yml", "services:\n  api:\n    environment:\n      JWT_SECRET: ${JWT_SECRET:-changeme}\n", "critical"),
])
def test_signing_fallback_fires(tmp_path, write_tree, scan_rules, path, text, sev):
    write_tree(tmp_path, {path: text})
    found = _found(scan_rules, tmp_path, "secret-signing-fallback")
    assert len(found) == 1 and found[0][0] == path and found[0][2] == sev, found


@pytest.mark.parametrize("path,text", [
    ("server.js", "const port = process.env.PORT || '3000'\nconst url = process.env.API_URL || 'http://localhost'\n"),
    ("db.js", "const pw = process.env.DB_PASSWORD || 'postgres'\n"),
    ("ai.js", "const key = process.env.OPENAI_API_KEY || ''\nconst k2 = process.env.OPENAI_API_KEY || 'sk-placeholder'\n"),
    ("auth.js", "if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {\n"
                "  throw new Error('JWT_SECRET is required')\n}\nconst s = process.env.JWT_SECRET || 'dev-only'\n"),
    ("tests/auth.test.ts", "const s = process.env.JWT_SECRET || 'secret'\n"),
    ("mysite/settings/dev.py", "SECRET_KEY = os.getenv('SECRET_KEY', 'dev')\n"),
    ("docs_helper.py", "WHY = \"agents write os.getenv('SECRET_KEY', 'dev') to start without .env\"\n"),
    ("docker-compose.yml", "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-postgres}\n"),
])
def test_signing_fallback_safe(tmp_path, write_tree, scan_rules, path, text):
    write_tree(tmp_path, {path: text})
    assert _found(scan_rules, tmp_path, "secret-signing-fallback") == []


# --- secret-hardcoded-signing-key -------------------------------------------------------

@pytest.mark.parametrize("path,text,sev", [
    ("routes/auth.js", "const jwt = require('jsonwebtoken')\nconst t = jwt.sign({ id: u.id, role }, 'secret')\n",
     "critical"),
    ("server.js", "const session = require('express-session')\napp.use(session({ secret: 'keyboard cat', resave: false }))\n",
     "critical"),
    ("src/index.ts", "import { jwt } from 'hono/jwt'\napp.use('/api/*', jwt({ secret: 'it-is-very-secret' }))\n",
     "critical"),
    ("auth.ts", "import NextAuth from 'next-auth'\nexport default NextAuth({ providers: [], secret: 'Q7wE9rT2yU4iO6pA8sD1fG3h' })\n",
     "high"),
    ("app.py", "from flask import Flask\napp = Flask(__name__)\napp.secret_key = 'dev'\n", "critical"),
    ("mysite/settings.py", "DEBUG = False\nSECRET_KEY = 'django-insecure-q7we9rt2yu4io6pa8sd1fg3h'\n", "critical"),
    ("auth.py", "import jwt\ntoken = jwt.encode(payload, \"Q7wE9rT2yU4iO6pA8sD1fG3hJ5kL\", algorithm=\"HS256\")\n", "high"),
    ("app/config.py", "app.config['SECRET_KEY'] = 'changeme'\n", "critical"),
])
def test_hardcoded_signing_key_fires(tmp_path, write_tree, scan_rules, path, text, sev):
    write_tree(tmp_path, {path: text})
    found = _found(scan_rules, tmp_path, "secret-hardcoded-signing-key")
    assert len(found) == 1 and found[0][0] == path and found[0][2] == sev, found


@pytest.mark.parametrize("path,text", [
    ("routes/auth.js", "const jwt = require('jsonwebtoken')\njwt.sign(p, process.env.JWT_SECRET)\n"
                       "jwt.sign(p, privateKey, { algorithm: 'RS256' })\n"),
    ("server.js", "const session = require('express-session')\napp.use(session({ secret: process.env.SESSION_SECRET }))\n"),
    ("totp.js", "const opts = { secret: 'shown-to-the-user-as-a-qr-code', digits: 6 }\nconst secret = 'abc'\n"),
    ("mysite/settings.py", "SECRET_KEY = 'django-insecure-q7we9rt2yu4io6pa8sd1fg3h'\n"
                           "SECRET_KEY = os.environ['DJANGO_SECRET_KEY']\n"),
    ("mysite/settings/local.py", "SECRET_KEY = 'dev'\n"),
    ("conftest.py", "SECRET_KEY = 'test'\n"),
    ("app.py", "import os\napp.secret_key = os.environ['FLASK_SECRET_KEY']\n"),
    ("docs.py", "EXAMPLE = '''\nSECRET_KEY = \"dev\"\n'''\nNOTE = \"jwt.encode(p, 'secret')\"\n"),
    ("lib/doc.js", "const jwt = require('jsonwebtoken')\nconst hint = \"do not write jwt.sign(p, 'secret')\"\n"),
    # *_KEY constants that hold a storage or cookie name, not a key
    ("lib/session.js", "const session = require('express-session')\nconst SESSION_KEY = 'user_session'\n"
                       "const JWT_KEY = 'jwt'\nreq.session[SESSION_KEY] = id\n"),
    ("shop/cart.py", "SESSION_KEY = 'cart'\n\ndef add(request):\n    request.session[SESSION_KEY] = []\n"),
])
def test_hardcoded_signing_key_safe(tmp_path, write_tree, scan_rules, path, text):
    write_tree(tmp_path, {path: text})
    assert _found(scan_rules, tmp_path, "secret-hardcoded-signing-key") == []


# --- rule metadata and references -------------------------------------------------------

def _slug(heading):
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def _anchors(path):
    out = set()
    for line in Path(path).read_text(encoding="utf-8").split("\n"):
        m = re.match(r"^#{1,6}\s+(.*)$", line)
        if m:
            out.add(_slug(m.group(1)))
    return out


DASHES = (chr(0x2014), chr(0x2013))
REF_DIRS = [REPO_ROOT / "skills" / "preflight-audit" / "references",
            REPO_ROOT / "skills" / "secure-by-default" / "references"]


@pytest.mark.parametrize("module", ["_rules_secrets", "_rules_supply"])
def test_rule_metadata_and_fix_refs(module):
    mod = __import__(module)
    prefix = "secret-" if module == "_rules_secrets" else "supply-"
    assert mod.RULES
    for r in mod.RULES:
        assert r.id.startswith(prefix), r.id
        assert r.message and r.why and r.fp_trap and r.fix_ref, r.id
        blob = r.why + r.fp_trap + r.message
        assert not any(d in blob for d in DASHES), r.id
        fname, _, anchor = r.fix_ref.partition("#")
        paths = [d / fname for d in REF_DIRS if (d / fname).exists()]
        assert paths, "%s: %s not found" % (r.id, fname)
        assert anchor in _anchors(paths[0]), "%s: no heading for #%s in %s" % (r.id, anchor, fname)


@pytest.mark.parametrize("ref", ["skills/secure-by-default/references/secrets.md",
                                 "skills/preflight-audit/references/supply-chain.md"])
def test_reference_files_style(ref):
    text = (REPO_ROOT / ref).read_text(encoding="utf-8")
    lines = text.rstrip("\n").split("\n")
    assert lines[-1].strip() == "LAST-VERIFIED: 2026-10-06"
    assert len(lines) <= 230
    assert not any(d in text for d in DASHES)
    assert not any(0x2600 <= ord(c) <= 0x27BF or ord(c) >= 0x1F000 for c in text)


# --- regressions: test runners, dev stacks, split settings, generated admin SDK -----------

@pytest.mark.parametrize("path", ["apps/web/playwright.config.mjs", "vitest.config.ts", "jest.config.js",
                                  "cypress.config.ts"])
def test_signing_fallback_skips_test_runner_configs(tmp_path, write_tree, scan_rules, path):
    write_tree(tmp_path, {path: "export default { webServer: { env: {\n"
                                "  AUTH_SECRET: process.env.AUTH_SECRET ?? 'secret',\n} } }\n"})
    assert _found(scan_rules, tmp_path, "secret-signing-fallback") == []


@pytest.mark.parametrize("path", ["docker-compose.dev.yaml", "docker-compose-local.yml", "docker-compose.test.yml",
                                  "Dockerfile.dev"])
def test_signing_fallback_skips_dev_stacks(tmp_path, write_tree, scan_rules, path):
    write_tree(tmp_path, {path: "services:\n  web:\n    environment:\n      SECRET_KEY: ${SECRET_KEY:-insecure-dev}\n"})
    assert _found(scan_rules, tmp_path, "secret-signing-fallback") == []


def test_signing_fallback_override_file_is_low(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {"docker-compose.override.yml":
                          "services:\n  web:\n    environment:\n      JWT_SECRET: ${JWT_SECRET:-changeme}\n"})
    found = _found(scan_rules, tmp_path, "secret-signing-fallback")
    assert found == [("docker-compose.override.yml", 4, "low")], found


SPLIT_BASE = "DEBUG = True\nSECRET_KEY = 'django-insecure-q7we9rt2yu4io6pa8sd1fg3h'\n"
SPLIT_PROD = "import os\nfrom .base import *  # noqa\n\nDEBUG = False\nSECRET_KEY = os.environ['DJANGO_SECRET_KEY']\n"


def test_django_split_settings_selected_by_deploy_config(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "mysite/settings/base.py": SPLIT_BASE,
        "mysite/settings/production.py": SPLIT_PROD,
        "Dockerfile": "FROM python:3.12\nENV DJANGO_SETTINGS_MODULE=mysite.settings.production\n",
    })
    assert _found(scan_rules, tmp_path, "secret-hardcoded-signing-key") == []


def test_django_split_settings_without_deploy_selection_is_medium(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "config/django/base.py": SPLIT_BASE,
        "config/django/production.py": SPLIT_PROD.replace("from .base", "from config.django.base"),
        "config/wsgi.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.django.base')\n",
    })
    res = scan_rules(tmp_path, rule_ids=["secret-hardcoded-signing-key"])
    found = [(f.file, f.line, f.severity, f.message) for f in res.findings]
    assert len(found) == 1 and found[0][:3] == ("config/django/base.py", 2, "medium"), found
    assert "production.py" in found[0][3]


def test_django_base_without_override_still_reported(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {"mysite/settings/base.py": SPLIT_BASE,
                          "mysite/settings/production.py": "from .base import *\nDEBUG = False\n"})
    assert _found(scan_rules, tmp_path, "secret-hardcoded-signing-key") == [
        ("mysite/settings/base.py", 2, "critical")]


GENERATED_ADMIN = {
    "package.json": json.dumps({"dependencies": {"react": "18", "firebase": "10",
                                                 "@dataconnect/admin-generated": "file:src/dataconnect-admin-generated"},
                                "devDependencies": {"vite": "5"}}),
    "src/dataconnect-admin-generated/package.json": json.dumps({"name": "@dataconnect/admin-generated",
                                                                "peerDependencies": {"firebase-admin": "^13"}}),
    "src/dataconnect-admin-generated/esm/index.esm.js": "import { validateAdminArgs } from 'firebase-admin/data-connect'\n",
    "src/App.tsx": "import { initializeApp } from 'firebase/app'\nexport default function App() { return null }\n",
}


def test_generated_admin_package_not_imported_by_client(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, GENERATED_ADMIN)
    assert _found(scan_rules, tmp_path, "secret-admin-sdk-in-client") == []


def test_generated_admin_package_import_check(tmp_path, write_tree, scan_rules):
    """The skip only holds while no client file outside the package imports it."""
    rel = "src/dataconnect-admin-generated/esm/index.esm.js"
    write_tree(tmp_path, GENERATED_ADMIN)
    ctx = scan_rules(tmp_path, rule_ids=["secret-admin-sdk-in-client"]).ctx
    assert rs._server_package_not_imported(ctx, rel) is True
    other = tmp_path / "other"
    files = dict(GENERATED_ADMIN)
    files["src/App.tsx"] = "import { listUsers } from '@dataconnect/admin-generated'\nexport default listUsers\n"
    write_tree(other, files)
    ctx = scan_rules(other, rule_ids=["secret-admin-sdk-in-client"]).ctx
    assert rs._server_package_not_imported(ctx, rel) is False


# --- regressions: public env tokens --------------------------------------------------------

def test_public_env_token_reported_once_per_variable(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": NEXT_PKG,
        "env.ts": "export const env = createEnv({ client: {\n  NEXT_PUBLIC_API_TOKEN: z.string(),\n} })\n",
        "lib/client.ts": "const t = env.NEXT_PUBLIC_API_TOKEN\nconst has = !!env.NEXT_PUBLIC_API_TOKEN\n",
        "lib/flag.ts": "const hasToken = !!process.env.NEXT_PUBLIC_API_TOKEN\n",
        ".github/workflows/ci.yml": "env:\n  NEXT_PUBLIC_API_TOKEN: ${{ secrets.T }}\n",
    })
    res = scan_rules(tmp_path, rule_ids=["secret-public-env-token"])
    found = [(f.file, f.line, f.severity, f.message) for f in res.findings]
    assert len(found) == 1 and found[0][:3] == ("env.ts", 2, "high"), found
    assert "lib/client.ts:1" in found[0][3] and ".github/workflows/ci.yml:2" in found[0][3]


def test_public_env_token_presence_check_only(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {
        "package.json": NEXT_PKG,
        "lib/flag.ts": "const hasToken = !!process.env.NEXT_PUBLIC_API_TOKEN\n"
                       "if (process.env.NEXT_PUBLIC_API_TOKEN) init()\n",
    })
    assert _found(scan_rules, tmp_path, "secret-public-env-token") == []


@pytest.mark.parametrize("name", ["NEXT_PUBLIC_AXIOM_TOKEN", "NEXT_PUBLIC_BETTER_STACK_SOURCE_TOKEN",
                                  "NEXT_PUBLIC_LOGTAIL_SOURCE_TOKEN", "NEXT_PUBLIC_DATADOG_CLIENT_TOKEN"])
def test_public_env_ingest_tokens_are_info(tmp_path, write_tree, scan_rules, name):
    write_tree(tmp_path, {"package.json": NEXT_PKG, "lib/log.ts": "const t = process.env.%s\n" % name})
    assert _found(scan_rules, tmp_path, "secret-public-env-token") == [("lib/log.ts", 1, "info")]


# --- regressions: evidence masking and missed shapes ------------------------------------------

@pytest.mark.parametrize("path,text,literal", [
    ("server.js", "const cookieParser = require('cookie-parser')\napp.use(cookieParser('kitty'))\n", "kitty"),
    ("auth.js", "const jwt = require('jsonwebtoken')\nconst t = jwt.sign({ a: 1 }, 'hunter2x')\n", "hunter2x"),
    ("lib/jose.ts", "import { SignJWT } from 'jose'\nconst key = new TextEncoder().encode('Zq9xW2vB')\n", "Zq9xW2vB"),
    ("lib/auth.ts", "const s = process.env.JWT_SECRET || 'Pw7kQ2zX'\n", "Pw7kQ2zX"),
])
def test_short_literals_are_masked_in_evidence(tmp_path, write_tree, scan_rules, path, text, literal):
    write_tree(tmp_path, {path: text})
    res = scan_rules(tmp_path, rule_ids=["secret-hardcoded-signing-key", "secret-signing-fallback"])
    assert res.findings, res.warnings
    for f in res.findings:
        assert literal not in f.evidence and "chars]" in f.evidence, f.evidence


@pytest.mark.parametrize("path,text,sev", [
    ("config/env/all.js", "module.exports = {\n  port: 4000,\n  cookieSecret: 'session-cookie-secret-key',\n}\n",
     "high"),
    ("config/keys.ts", "export const TOKEN_SECRET = 'Q7wE9rT2yU4iO6pA8sD1fG3h'\n", "high"),
    ("app/app.py", "app.config['SECRET_KEY_HMAC'] = 'secret'\n", "critical"),
    ("lib/sign.ts", "import crypto from 'crypto'\nexport const sig = (d) => crypto.createHmac('sha256', "
                    "'Q7wE9rT2yU4iO6pA8sD1fG3h').update(d).digest('hex')\n", "high"),
    ("app/sign.py", "import hmac, hashlib\nsig = hmac.new(b'dev', msg, hashlib.sha256).hexdigest()\n", "critical"),
])
def test_hardcoded_signing_key_more_shapes(tmp_path, write_tree, scan_rules, path, text, sev):
    write_tree(tmp_path, {path: text})
    found = _found(scan_rules, tmp_path, "secret-hardcoded-signing-key")
    assert len(found) == 1 and found[0][0] == path and found[0][2] == sev, found


@pytest.mark.parametrize("path,text", [
    # an unambiguous key name outside config and auth code that holds a field name
    ("lib/forms.js", "const fields = { signingKey: 'signing_key', label: 'Key' }\n"),
    ("lib/sign.ts", "export const sig = (k, d) => crypto.createHmac('sha256', k).update(d).digest('hex')\n"),
    ("app/sign.py", "import hmac\nsig = hmac.new(key, msg, 'sha256')\n"),
    ("config/limits.ts", "export const SECRET_KEY_LENGTH = '32'\nexport const MAX_TOKENS = '500'\n"),
])
def test_hardcoded_signing_key_more_safe_shapes(tmp_path, write_tree, scan_rules, path, text):
    write_tree(tmp_path, {path: text})
    assert _found(scan_rules, tmp_path, "secret-hardcoded-signing-key") == []
