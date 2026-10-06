"""Tests for the deployment rules in _rules_deploy.py.

Every rule gets vulnerable samples that must fire and safe variants (the
false-positive traps from the research) that must stay quiet.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import _rules_deploy as rd
import scan_app
from conftest import REPO_ROOT

REFS = REPO_ROOT / "skills" / "preflight-audit" / "references"
OWNED_REFS = ("stack-nextjs.md", "stack-express-node.md", "stack-laravel.md", "stack-expo-rn.md")
ALLOWED_REFS = OWNED_REFS + ("stack-python.md", "stack-supabase.md", "stack-firebase.md", "rotation.md",
                             "supply-chain.md")


def pkg(deps=None, dev=None, scripts=None):
    data = {"name": "app", "version": "1.0.0"}
    if deps:
        data["dependencies"] = deps
    if dev:
        data["devDependencies"] = dev
    if scripts:
        data["scripts"] = scripts
    return json.dumps(data, indent=2)


EXPRESS = {"package.json": pkg({"express": "4.19.2", "cors": "2.8.5", "cookie-parser": "1.4.6"})}
EXPRESS5 = {"package.json": pkg({"express": "5.1.0"})}
NEXT = {"package.json": pkg({"next": "15.2.3", "react": "19.0.0", "react-dom": "19.0.0"},
                            scripts={"dev": "next dev", "build": "next build", "start": "next start"}),
        "app/layout.tsx": "export default function Layout({ children }) { return children }\n",
        "app/page.tsx": "export default function Page() { return null }\n"}
VITE = {"package.json": pkg({"react": "18.3.1", "react-dom": "18.3.1"}, {"vite": "5.4.0"},
                            {"dev": "vite", "build": "vite build", "preview": "vite preview"})}
CRA = {"package.json": pkg({"react": "18.2.0", "react-scripts": "5.0.1"},
                           scripts={"start": "react-scripts start", "build": "react-scripts build"})}
FLASK = {"requirements.txt": "flask==3.0.3\n"}
FLASK_GUNICORN = {"requirements.txt": "flask==3.0.3\ngunicorn==22.0.0\n"}
FASTAPI = {"requirements.txt": "fastapi==0.115.0\nuvicorn==0.30.0\n"}
DJANGO = {"manage.py": "import django\n", "requirements.txt": "Django==5.1\ndjango-cors-headers==4.4\n"}
LARAVEL = {"artisan": "#!/usr/bin/env php\n",
           "composer.json": json.dumps({"require": {"php": "^8.2", "laravel/framework": "^11.0"},
                                        "require-dev": {"spatie/laravel-ignition": "^2.4"}})}
EXPO = {"package.json": pkg({"expo": "51.0.0", "react-native": "0.74.0"}, scripts={"start": "expo start"})}


def run(tmp_path, write_tree, scan_rules, files, rule, stacks=None):
    write_tree(tmp_path, files)
    return [f for f in scan_rules(tmp_path, rule_ids=[rule], stacks=stacks).findings if f.rule == rule]


def assert_case(tmp_path, write_tree, scan_rules, base, files, rule, fires, severity=None):
    tree = dict(base)
    tree.update(files)
    found = run(tmp_path, write_tree, scan_rules, tree, rule)
    if fires:
        assert found, "%s did not fire on %s" % (rule, sorted(files))
        if severity:
            assert found[0].severity == severity, [(f.severity, f.message) for f in found]
    else:
        assert not found, [(f.file, f.line, f.message) for f in found]
    return found


# --- rule metadata ----------------------------------------------------------------

def _slug(heading):
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def _anchors(path):
    out = set()
    for line in path.read_text(encoding="utf-8").split("\n"):
        m = re.match(r"#{1,6}\s+(.+?)\s*$", line)
        if m:
            out.add(_slug(m.group(1)))
    return out


def test_rule_metadata_is_complete():
    ids = set()
    for r in rd.RULES:
        assert r.id.startswith("deploy-"), r.id
        assert r.id not in ids
        ids.add(r.id)
        assert r.message and r.why and r.fp_trap and r.klass
        assert r.severity in ("critical", "high", "medium", "low", "info")
        assert r.confidence in ("high", "medium", "low")
        target, _, anchor = r.fix_ref.partition("#")
        assert target in ALLOWED_REFS and anchor, r.fix_ref
        for s in r.stacks:
            for part in s.split("+"):
                assert part == "*" or part in scan_app.KNOWN_STACKS, (r.id, part)


def test_rules_load_without_warnings():
    rules, warnings = scan_app.load_rules(("_rules_deploy",))
    assert [w for w in warnings if "_rules_deploy" in w] == []
    assert len(rules) == len(rd.RULES)


@pytest.mark.parametrize("name", OWNED_REFS)
def test_owned_reference_files(name):
    path = REFS / name
    text = path.read_text(encoding="utf-8")
    lines = text.rstrip("\n").split("\n")
    assert lines[-1].strip() == "LAST-VERIFIED: 2026-10-06"
    assert len(lines) <= 210
    assert chr(0x2014) not in text and chr(0x2013) not in text
    assert "\r" not in text


def test_fix_refs_point_at_real_headings():
    for r in rd.RULES:
        target, _, anchor = r.fix_ref.partition("#")
        if target not in OWNED_REFS:
            continue
        assert anchor in _anchors(REFS / target), r.fix_ref


# --- code scanner -----------------------------------------------------------------

def test_code_view_blanks_strings_and_comments():
    js = 'const a = "x{"; // c {\nconst b = `t ${ y + "}" } z`; const r = /[{]/g; f({ k: 1 })'
    v = rd._code_view(js, "js")
    assert len(v) == len(js)
    assert "{" not in v.split("\n")[0]
    assert "y +" in v and "/   /g" in v and "f({ k: 1 })" in v
    py = 'x = "a{"  # c (\ny = f"v {tok} {{lit}}"\nz = """m\n(l"""'
    pv = rd._code_view(py, "py")
    assert "tok" in pv and "lit" not in pv and "(" not in pv.split("\n")[0] and "(l" not in pv
    php = "$a = 'x(';  // y {\n$b = \"z\"; # w\n"
    assert rd._code_view(php, "php").count("(") == 0


# --- deploy-django-debug ----------------------------------------------------------

@pytest.mark.parametrize("path,text,fires", [
    ("proj/settings.py", "DEBUG = True\n", True),
    ("proj/settings.py", "DEBUG = int(os.environ.get('DEBUG', 1))\n", True),
    ("proj/settings/production.py", "DEBUG = bool(os.getenv('DEBUG', 'True'))\n", True),
    ("proj/settings.py", "DEBUG = os.environ.get('DJANGO_DEBUG') == '1'\n", False),
    ("proj/settings.py", "DEBUG = os.environ.get('DEBUG', '0') == '1'\n", False),
    ("proj/settings/dev.py", "DEBUG = True\n", False),
    ("proj/settings/local.py", "DEBUG = True\n", False),
])
def test_django_debug(tmp_path, write_tree, scan_rules, path, text, fires):
    assert_case(tmp_path, write_tree, scan_rules, DJANGO, {path: text}, "deploy-django-debug", fires)


# A settings package: base turns DEBUG on, production imports it and turns it off.
SETTINGS_PKG = {
    "proj/__init__.py": "",
    "proj/settings/__init__.py": "",
    "proj/settings/base.py": "import os\nDEBUG = True\nSECRET_KEY = os.environ.get('SECRET_KEY')\n",
    "proj/settings/production.py": "from .base import *  # noqa\n\nDEBUG = False\n",
}
PROD_DOCKERFILE = {"Dockerfile": "FROM python:3.12\nENV DJANGO_SETTINGS_MODULE=proj.settings.production\n"
                                 "CMD [\"gunicorn\", \"proj.wsgi\"]\n"}
# The Django-Styleguide layout: settings in config/django/, defaulted by wsgi.py.
STYLEGUIDE = {
    "config/__init__.py": "",
    "config/wsgi.py": "import os\nos.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.django.base')\n",
    "config/django/__init__.py": "",
    "config/django/base.py": ("from config.env import env\nDEBUG = env.bool('DJANGO_DEBUG', default=True)\n"
                              "from config.settings.cors import *  # noqa\n"),
    "config/settings/__init__.py": "",
    "config/settings/cors.py": "CORS_ALLOW_CREDENTIALS = True\nCORS_ALLOW_ALL_ORIGINS = True\n",
}
STYLEGUIDE_PROD = {"config/django/production.py": ("from config.env import env\nfrom .base import *  # noqa\n\n"
                                                    "DEBUG = env.bool('DJANGO_DEBUG', default=False)\n"
                                                    "CORS_ALLOW_ALL_ORIGINS = False\n")}


@pytest.mark.parametrize("files,where,sev", [
    # production named by the Dockerfile imports base and turns DEBUG off: quiet
    (dict(SETTINGS_PKG, **PROD_DOCKERFILE), None, None),
    # production module does not turn it off, so it inherits DEBUG = True
    (dict(SETTINGS_PKG, **dict(PROD_DOCKERFILE, **{"proj/settings/production.py": "from .base import *\n"})),
     "proj/settings/base.py", "high"),
    # the override comes before the import, so the import turns DEBUG back on
    (dict(SETTINGS_PKG, **dict(PROD_DOCKERFILE, **{"proj/settings/production.py": "DEBUG = False\nfrom .base import *\n"})),
     "proj/settings/base.py", "high"),
    # the deploy config runs base itself
    (dict(SETTINGS_PKG, **{"Dockerfile": "FROM python:3.12\nENV DJANGO_SETTINGS_MODULE=proj.settings.base\n"}),
     "proj/settings/base.py", "high"),
    # an overriding production.py exists but nothing names it: reported low
    (SETTINGS_PKG, "proj/settings/base.py", "low"),
    # settings module outside the usual names, found through wsgi.py's DJANGO_SETTINGS_MODULE
    (STYLEGUIDE, "config/django/base.py", "high"),
    (dict(STYLEGUIDE, **STYLEGUIDE_PROD), "config/django/base.py", "low"),
])
def test_django_debug_settings_modules(tmp_path, write_tree, scan_rules, files, where, sev):
    found = run(tmp_path, write_tree, scan_rules, dict(DJANGO, **files), "deploy-django-debug")
    if where is None:
        assert found == [], [(f.file, f.message) for f in found]
    else:
        assert [(f.file, f.severity) for f in found] == [(where, sev)], [(f.file, f.message) for f in found]
        if sev == "low":
            assert "production.py" in found[0].message


@pytest.mark.parametrize("extra,sev", [
    ({}, "high"),
    (STYLEGUIDE_PROD, "low"),
    (dict(STYLEGUIDE_PROD, **{"Procfile": "web: DJANGO_SETTINGS_MODULE=config.django.production gunicorn config.wsgi\n"}),
     None),
])
def test_django_cors_overridden_by_production(tmp_path, write_tree, scan_rules, extra, sev):
    found = run(tmp_path, write_tree, scan_rules, dict(DJANGO, **dict(STYLEGUIDE, **extra)),
                "deploy-cors-credentials-python")
    assert [f.severity for f in found] == ([sev] if sev else []), [(f.file, f.message) for f in found]


# --- deploy-flask-debug -----------------------------------------------------------

APP_TOP = "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0', debug=True)\n"
APP_MAIN = "from flask import Flask\napp = Flask(__name__)\n\nif __name__ == '__main__':\n    app.run(debug=True)\n"
APP_MAIN_PUBLIC = APP_MAIN.replace("debug=True", "host='0.0.0.0', port=5000, debug=True")
APP_FUNC = ("from flask import Flask\napp = Flask(__name__)\n\ndef main():\n    app.run(debug=True)\n\n"
            "if __name__ == '__main__':\n    main()\n")


@pytest.mark.parametrize("base,files,fires,sev", [
    (FLASK, {"app.py": APP_TOP}, True, "high"),
    (FLASK, {"app.py": APP_MAIN}, True, "medium"),
    (FLASK, {"app.py": APP_MAIN_PUBLIC}, True, "high"),
    (FLASK, {"app.py": APP_MAIN, "Procfile": "web: python app.py\n"}, True, "high"),
    (FLASK, {"app.py": "from flask import Flask\nfrom werkzeug.debug import DebuggedApplication\n"
                       "app = Flask(__name__)\napp.wsgi_app = DebuggedApplication(app.wsgi_app, evalex=True)\n"},
     True, "high"),
    (FLASK, {"Dockerfile": "FROM python:3.12\nENV FLASK_DEBUG=1\nCMD [\"gunicorn\", \"app:app\"]\n"}, True, "high"),
    (FLASK, {"Procfile": "web: flask run --host 0.0.0.0 --debug\n"}, True, "high"),
    (FLASK, {".env.production": "FLASK_DEBUG=1\n"}, True, "high"),
    (FLASK, {"run.py": "from app import create_app\napp = create_app()\napp.run(host='0.0.0.0', debug=True)\n"},
     True, "high"),
    # safe variants
    (FLASK_GUNICORN, {"app.py": APP_MAIN}, False, None),
    (FLASK, {"app.py": APP_MAIN, "Procfile": "web: gunicorn app:app\n"}, False, None),
    (FLASK, {"app.py": APP_FUNC, "Dockerfile": "FROM python:3.12\nCMD gunicorn -b 0.0.0.0:8000 app:app\n"}, False, None),
    (FLASK, {"app.py": "from flask import Flask\napp = Flask(__name__)\napp.run(debug=False)\n"}, False, None),
    (FLASK, {"app.py": "from flask import Flask\napp = Flask(__name__)\n# app.run(debug=True)\n"}, False, None),
    (FLASK, {"app.py": "from flask import Flask\napp = Flask(__name__)\ndebug = os.environ.get('FLASK_DEBUG') == '1'\n"
                       "app.run(debug=debug)\n"}, False, None),
    (FLASK, {".flaskenv": "FLASK_DEBUG=1\n", ".env": "FLASK_DEBUG=1\n"}, False, None),
    (FLASK, {"Dockerfile.dev": "FROM python:3.12\nENV FLASK_DEBUG=1\n"}, False, None),
    (FLASK, {"tests/test_app.py": APP_TOP}, False, None),
    (FASTAPI, {"main.py": "import uvicorn\nuvicorn.run(app, debug=True)\n"}, False, None),
    (FLASK, {"bot.py": "from mybot import bot\nbot.run(debug=True)\n"}, False, None),
])
def test_flask_debug(tmp_path, write_tree, scan_rules, base, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-flask-debug", fires, sev)


# --- deploy-laravel-debug ---------------------------------------------------------

@pytest.mark.parametrize("files,fires,sev", [
    ({".env.production": "APP_ENV=production\nAPP_DEBUG=true\n"}, True, "high"),
    ({".env": "APP_NAME=Shop\nAPP_ENV=production\nAPP_DEBUG=true\n"}, True, "high"),
    ({".env.staging": "APP_DEBUG=1\n"}, True, "high"),
    ({"config/app.php": "<?php\nreturn [\n    'debug' => true,\n];\n"}, True, "high"),
    ({"config/app.php": "<?php\nreturn [\n    'debug' => (bool) env('APP_DEBUG', true),\n];\n"}, True, "medium"),
    # safe variants
    ({".env": "APP_ENV=local\nAPP_DEBUG=true\n"}, False, None),
    ({".env.example": "APP_ENV=production\nAPP_DEBUG=true\n"}, False, None),
    ({".env.production": "APP_ENV=production\nAPP_DEBUG=false\n"}, False, None),
    ({".env.production": "APP_ENV=production\n# APP_DEBUG=true\n"}, False, None),
    ({"config/app.php": "<?php\nreturn [\n    'debug' => (bool) env('APP_DEBUG', false),\n];\n"}, False, None),
    ({"config/app.php": "<?php\nreturn [\n    // 'debug' => true,\n    'debug' => env('APP_DEBUG'),\n];\n"}, False, None),
])
def test_laravel_debug(tmp_path, write_tree, scan_rules, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, LARAVEL, files, "deploy-laravel-debug", fires, sev)


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_laravel_debug_committed_env(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, dict(LARAVEL, **{".env": "APP_ENV=local\nAPP_DEBUG=true\n"}))
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    assert run(tmp_path, write_tree, scan_rules, {}, "deploy-laravel-debug") == []
    subprocess.run(["git", "-C", str(tmp_path), "add", ".env"], check=True)
    found = run(tmp_path, write_tree, scan_rules, {}, "deploy-laravel-debug")
    assert found and found[0].severity == "medium" and "committed" in found[0].message


# --- deploy-laravel-ignition ------------------------------------------------------

def _composer(require, dev=None):
    return json.dumps({"require": dict({"laravel/framework": "^8.0"}, **require), "require-dev": dev or {}})


@pytest.mark.parametrize("files,fires,sev", [
    ({"composer.json": _composer({"facade/ignition": "^2.3"}),
      "composer.lock": json.dumps({"packages": [{"name": "facade/ignition", "version": "2.5.1"}]})}, True, "critical"),
    ({"composer.json": _composer({}, {"facade/ignition": "2.4.0"})}, True, "critical"),
    ({"composer.json": _composer({"spatie/laravel-ignition": "^2.4"})}, True, "low"),
    # safe variants
    ({"composer.json": _composer({}, {"spatie/laravel-ignition": "^2.4"})}, False, None),
    ({"composer.json": _composer({}, {"facade/ignition": "^2.3"}),
      "composer.lock": json.dumps({"packages-dev": [{"name": "facade/ignition", "version": "2.17.7"}]})}, False, None),
    ({"composer.json": _composer({}, {"facade/ignition": "^2.3"})}, False, None),
])
def test_laravel_ignition(tmp_path, write_tree, scan_rules, files, fires, sev):
    base = {"artisan": "#!/usr/bin/env php\n"}
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-laravel-ignition", fires, sev)


# --- deploy-dev-server-in-prod ----------------------------------------------------

@pytest.mark.parametrize("base,files,fires,sev", [
    (NEXT, {"Dockerfile": "FROM node:20\nWORKDIR /app\nCOPY . .\nRUN npm ci\nCMD [\"npm\", \"run\", \"dev\"]\n"},
     True, "medium"),
    (NEXT, {"Procfile": "web: npx next dev -p $PORT\n"}, True, "medium"),
    (NEXT, {"package.json": pkg({"next": "15.2.3"}, scripts={"dev": "next dev", "start": "next dev"})}, True, None),
    (VITE, {"ecosystem.config.js": "module.exports = { apps: [{ name: 'web', script: 'npm', args: 'run dev' }] }\n"},
     True, "medium"),
    (VITE, {"Dockerfile": "FROM node:20\nCOPY . .\nCMD npx vite --host 0.0.0.0\n"}, True, "medium"),
    (DJANGO, {"Procfile": "web: python manage.py runserver 0.0.0.0:$PORT\n"}, True, "medium"),
    (LARAVEL, {"Dockerfile": "FROM php:8.3\nCOPY . .\nCMD php artisan serve --host=0.0.0.0\n"}, True, "medium"),
    (CRA, {"Dockerfile": "FROM node:20\nCOPY . .\nCMD [\"npm\", \"start\"]\n"}, True, "medium"),
    (FASTAPI, {"Dockerfile": "FROM python:3.12\nCMD uvicorn main:app --host 0.0.0.0 --reload\n"}, True, "low"),
    (NEXT, {"docker-compose.prod.yml": "services:\n  web:\n    build: .\n    command: npm run dev\n"}, True, None),
    (EXPO, {"eas.json": json.dumps({"build": {"production": {"developmentClient": True}}}, indent=2)}, True, None),
    # safe variants
    (NEXT, {"Dockerfile": "FROM node:20 AS dev\nCMD [\"npm\", \"run\", \"dev\"]\n\nFROM node:20\nWORKDIR /app\n"
                          "COPY --from=dev /app .\nCMD [\"npm\", \"start\"]\n"}, False, None),
    (NEXT, {"Dockerfile.dev": "FROM node:20\nCMD [\"npm\", \"run\", \"dev\"]\n"}, False, None),
    (NEXT, {"docker-compose.yml": "services:\n  web:\n    command: npm run dev\n    volumes:\n      - .:/app\n"}, False, None),
    (NEXT, {"Procfile.dev": "web: next dev\n"}, False, None),
    (NEXT, {"Procfile": "web: npm run build && npm start\n"}, False, None),
    (VITE, {"Dockerfile": "FROM node:20\nRUN npm run build\nCMD [\"npx\", \"vite\", \"preview\", \"--host\"]\n"}, False, None),
    (CRA, {}, False, None),
    (EXPO, {}, False, None),
    (EXPO, {"eas.json": json.dumps({"build": {"development": {"developmentClient": True},
                                              "production": {"distribution": "store"}}})}, False, None),
    (FASTAPI, {"Dockerfile": "FROM python:3.12\nCMD [\"uvicorn\", \"main:app\", \"--host\", \"0.0.0.0\"]\n"}, False, None),
    (EXPRESS, {"Dockerfile": "FROM node:20\nCMD [\"node\", \"server.js\"]\n"}, False, None),
    (NEXT, {".devcontainer/Dockerfile": "FROM node:20\nCMD npm run dev\n"}, False, None),
])
def test_dev_server(tmp_path, write_tree, scan_rules, base, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-dev-server-in-prod", fires, sev)


def test_vite_host_message_does_not_promise_a_safe_version(tmp_path, write_tree, scan_rules):
    files = dict(VITE, **{"Dockerfile": "FROM node:20\nCOPY . .\nCMD npx vite --host 0.0.0.0\n"})
    found = run(tmp_path, write_tree, scan_rules, files, "deploy-dev-server-in-prod")
    assert found and "upgrading does not make it safe" in found[0].message


def test_dev_server_reported_once_via_start_script(tmp_path, write_tree, scan_rules):
    files = {"package.json": pkg({"next": "15.2.3"}, scripts={"dev": "next dev", "start": "next dev"}),
             "Dockerfile": "FROM node:20\nCOPY . .\nCMD [\"npm\", \"start\"]\n"}
    found = run(tmp_path, write_tree, scan_rules, files, "deploy-dev-server-in-prod")
    assert [f.file for f in found] == ["package.json"]


# --- deploy-express-node-env -------------------------------------------------------

SERVER = "const express = require('express')\nconst app = express()\napp.get('/', (req, res) => res.send('ok'))\napp.listen(3000)\n"
HANDLER = "\napp.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Internal error' }) })\n"


@pytest.mark.parametrize("files,fires", [
    ({"server.js": SERVER, "Dockerfile": "FROM node:20\nCOPY . .\nCMD [\"node\", \"server.js\"]\n"}, True),
    ({"server.js": SERVER, "ecosystem.config.js": "module.exports = { apps: [{ script: 'server.js' }] }\n"}, True),
    # safe variants
    ({"server.js": SERVER, "Dockerfile": "FROM node:20\nENV NODE_ENV=production\nCMD [\"node\", \"server.js\"]\n"}, False),
    ({"server.js": SERVER, "Dockerfile": "FROM node:20\nENV NODE_ENV production\nCMD node server.js\n"}, False),
    ({"server.js": SERVER + HANDLER, "Dockerfile": "FROM node:20\nCMD [\"node\", \"server.js\"]\n"}, False),
    # Prettier style: typed parameters on their own lines, trailing comma
    ({"server.ts": SERVER + "app.use(\n  (\n    err: Error | HttpError,\n    req: express.Request,\n"
                            "    res: express.Response<Body>,\n    next: express.NextFunction,\n  ) => {\n"
                            "    res.status(500).json({ error: 'Internal error' })\n  },\n)\n",
      "Dockerfile": "FROM node:20\nCMD [\"node\", \"server.js\"]\n"}, False),
    ({"server.js": SERVER + "app.use(function (err, _req, res, _next) { res.sendStatus(500) })\n",
      "Dockerfile": "FROM node:20\nCMD [\"node\", \"server.js\"]\n"}, False),
    ({"server.js": SERVER}, False),
    ({"server.js": SERVER, "render.yaml": "services:\n  - type: web\n    startCommand: node server.js\n    envVars:\n"
                                          "      - key: NODE_ENV\n        value: production\n"}, False),
])
def test_express_node_env(tmp_path, write_tree, scan_rules, files, fires):
    assert_case(tmp_path, write_tree, scan_rules, EXPRESS, files, "deploy-express-node-env", fires)


# --- deploy-error-stack-leak -------------------------------------------------------

@pytest.mark.parametrize("base,files,fires", [
    (EXPRESS, {"server.js": "app.use((err, req, res, next) => {\n  res.status(500).json({ error: err.message, stack: err.stack })\n})\n"}, True),
    (EXPRESS, {"server.js": "app.use(function (err, req, res, next) { res.status(500).send(err.stack) })\n"}, True),
    (NEXT, {"app/api/x/route.ts": "export async function GET() {\n  try { return Response.json({}) }\n"
                                  "  catch (e: any) { return NextResponse.json({ error: e.stack }, { status: 500 }) }\n}\n"}, True),
    (FASTAPI, {"main.py": "import traceback\n@app.get('/x')\ndef x():\n    try:\n        run()\n    except Exception:\n"
                          "        return {'error': traceback.format_exc()}\n"}, True),
    (FLASK, {"app.py": "import traceback\ndef h(e):\n    tb = traceback.format_exc()\n    return jsonify(error=tb), 500\n"}, True),
    (EXPRESS, {"server.js": "const errorhandler = require('errorhandler')\napp.use(errorhandler())\n"}, True),
    (EXPRESS, {"server.ts": "import errorHandler from 'errorhandler'\napp.use(errorHandler({ log: false }))\n"}, True),
    # safe variants
    (EXPRESS, {"server.js": "const errorhandler = require('errorhandler')\n"
                            "if (process.env.NODE_ENV === 'development') {\n  app.use(errorhandler())\n}\n"}, False),
    (EXPRESS, {"server.js": "const errorhandler = require('errorhandler')\n"
                            "if ('development' == app.get('env')) app.use(errorhandler())\n"}, False),
    (EXPRESS, {"server.js": "const errorhandler = require('errorhandler')\nif (process.env.NODE_ENV === 'production') {\n"
                            "  app.use(prodHandler)\n} else {\n  app.use(errorhandler())\n}\n"}, False),
    (EXPRESS, {"server.js": "// const errorhandler = require('errorhandler')\n// app.use(errorhandler())\n"}, False),
    (EXPRESS, {"server.js": "app.use((err, req, res, next) => {\n  console.error(err.stack)\n  res.status(500).json({ error: 'Internal error' })\n})\n"}, False),
    (EXPRESS, {"server.js": "app.use((err, req, res, next) => {\n  res.status(500).json({ error: 'x', stack: process.env.NODE_ENV === 'production' ? undefined : err.stack })\n})\n"}, False),
    (EXPRESS, {"server.js": "app.use((err, req, res, next) => {\n  if (process.env.NODE_ENV !== 'production') {\n    return res.status(500).send(err.stack)\n  }\n  res.sendStatus(500)\n})\n"}, False),
    (FASTAPI, {"main.py": "import traceback, logging\ndef x():\n    try:\n        run()\n    except Exception:\n"
                          "        logging.error(traceback.format_exc())\n        return {'error': 'Internal error'}\n"}, False),
    (EXPRESS, {"server.test.js": "res.status(500).json({ stack: err.stack })\n"}, False),
])
def test_error_stack_leak(tmp_path, write_tree, scan_rules, base, files, fires):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-error-stack-leak", fires)


# --- deploy-static-project-root ---------------------------------------------------

@pytest.mark.parametrize("base,files,fires,sev", [
    (EXPRESS, {"server.js": "const app = express()\napp.use(express.static(__dirname))\n"}, True, "high"),
    (EXPRESS, {"server.js": "app.use(express.static('.'))\n"}, True, "high"),
    (EXPRESS, {"server.js": "app.use('/', express.static(process.cwd()))\n"}, True, "high"),
    (EXPRESS, {"src/server.js": "app.use(express.static(path.join(__dirname, '..')))\n"}, True, "high"),
    (EXPRESS, {"server.js": "app.use(express.static(__dirname, { dotfiles: 'allow' }))\n"}, True, "critical"),
    (EXPRESS, {"server/index.js": "app.use(express.static(__dirname))\n"}, True, "medium"),
    (EXPRESS5, {"server.js": "app.use(express.static(path.resolve(__dirname)))\n"}, True, "high"),
    (FLASK, {"app.py": "from flask import Flask\napp = Flask(__name__, static_folder='.', static_url_path='')\n"}, True, "high"),
    (FLASK, {"app.py": "@app.route('/<path:p>')\ndef f(p):\n    return send_from_directory('.', p)\n"}, True, "high"),
    (FASTAPI, {"main.py": "app.mount('/', StaticFiles(directory='.', html=True), name='site')\n"}, True, "high"),
    ({}, {"firebase.json": json.dumps({"hosting": {"public": "."}}, indent=2)}, True, "high"),
    ({}, {"firebase.json": json.dumps({"hosting": {"public": ".", "ignore": ["firebase.json", "**/.*"]}})}, True, "medium"),
    ({}, {"Dockerfile": "FROM nginx:alpine\nCOPY . /usr/share/nginx/html\n"}, True, "high"),
    ({}, {"Dockerfile": "FROM php:8.3-apache\nCOPY . /var/www/html/\n", "index.php": "<?php echo 1;\n"}, True, "high"),
    (LARAVEL, {"Dockerfile": "FROM php:8.3-apache\nCOPY . /var/www/html\n", ".dockerignore": ".env\n.git\n"},
     True, "medium"),
    ({}, {"Procfile": "web: python -m http.server $PORT\n"}, True, "medium"),
    # safe variants
    (EXPRESS, {"server.js": "app.use(express.static(path.join(__dirname, 'public')))\n"}, False, None),
    (EXPRESS, {"server.js": "app.use(express.static('dist', { dotfiles: 'allow' }))\n"}, False, None),
    (EXPRESS, {"server.js": "// app.use(express.static(__dirname))\napp.use(express.static('public'))\n"}, False, None),
    (EXPRESS, {"server.js": "const s = 'express.static(__dirname)'\n"}, False, None),
    (FLASK, {"app.py": "app = Flask(__name__, static_folder='static')\n"}, False, None),
    (FLASK, {"app.py": "@app.route('/')\ndef i():\n    return send_from_directory('.', 'index.html')\n"}, False, None),
    (FASTAPI, {"main.py": "app.mount('/static', StaticFiles(directory='static'), name='static')\n"}, False, None),
    ({}, {"firebase.json": json.dumps({"hosting": {"public": "dist"}})}, False, None),
    ({}, {"Dockerfile": "FROM nginx:alpine\nCOPY --from=build /app/dist /usr/share/nginx/html\n"}, False, None),
    ({}, {"Dockerfile": "FROM php:8.3-apache\nCOPY . /var/www/html/\n", ".dockerignore": ".env*\n.git\n",
          "index.php": "<?php echo 1;\n"}, False, None),
    ({}, {"Procfile": "web: python -m http.server $PORT --directory dist\n"}, False, None),
])
def test_static_project_root(tmp_path, write_tree, scan_rules, base, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-static-project-root", fires, sev)


# --- deploy-directory-listing -----------------------------------------------------

@pytest.mark.parametrize("base,files,fires,sev", [
    (EXPRESS, {"server.js": "const serveIndex = require('serve-index')\n"
                            "app.use('/files', express.static('files'), serveIndex('files', { icons: true }))\n"}, True, "medium"),
    (EXPRESS, {"server.ts": "import serveIndex from 'serve-index'\napp.use('/support/logs', serveIndex('logs'))\n"}, True, "high"),
    ({}, {"nginx/site.conf": "server {\n  location /backups/ {\n    autoindex on;\n  }\n}\n"}, True, "high"),
    ({}, {"nginx.conf": "server {\n  location /downloads/ {\n    autoindex on;\n  }\n}\n"}, True, "medium"),
    ({}, {"public/.htaccess": "Options +Indexes\n"}, True, "medium"),
    ({}, {"Caddyfile": "example.com {\n  root * /srv\n  file_server browse\n}\n"}, True, "medium"),
    # safe variants
    ({}, {"public/.htaccess": "Options -Indexes\n"}, False, None),
    ({}, {".htaccess": "# To hide directory listing\nOptions All -Indexes\n"}, False, None),
    ({}, {"nginx.conf": "server {\n  # autoindex on;\n  autoindex off;\n}\n"}, False, None),
    ({}, {"Caddyfile": "example.com {\n  file_server\n}\n"}, False, None),
    (EXPRESS, {"server.js": "const serveIndex = require('serve-index')\nif (process.env.NODE_ENV === 'development') {\n"
                            "  app.use('/tmp', serveIndex('tmp'))\n}\n"}, False, None),
    (EXPRESS, {"server.js": "// app.use('/ftp', serveIndex('ftp'))\nconst s = 'serve-index'\n"}, False, None),
])
def test_directory_listing(tmp_path, write_tree, scan_rules, base, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-directory-listing", fires, sev)


def test_static_root_mentions_express4_git(tmp_path, write_tree, scan_rules):
    found = run(tmp_path, write_tree, scan_rules,
                dict(EXPRESS, **{"server.js": "app.use(express.static(__dirname))\n"}), "deploy-static-project-root")
    assert ".git" in found[0].message


# --- deploy-sensitive-file-public -------------------------------------------------

@pytest.mark.parametrize("files,fires,sev", [
    ({"public/.env": "X=1\n"}, True, "critical"),
    ({"public/backup.sql": "select 1;\n"}, True, "high"),
    ({"static/db.sqlite3": b"SQLite format 3\x00"}, True, "high"),
    ({"apps/web/public/server.key": "x\n"}, True, "critical"),
    ({"public/logs/app.log": "x\n"}, True, "medium"),
    # safe variants
    ({"public/.htaccess": "x\n", "public/robots.txt": "x\n", "public/.well-known/security.txt": "x\n",
      "public/favicon.ico": b"\x00\x01", "public/.gitkeep": ""}, False, None),
    ({"public/.env.example": "X=\n"}, False, None),
    ({"data/backup.sql": "x\n", ".env": "X=1\n"}, False, None),
    ({"node_modules/pkg/public/x.sql": "x\n"}, False, None),
])
def test_sensitive_file_public(tmp_path, write_tree, scan_rules, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, {}, files, "deploy-sensitive-file-public", fires, sev)


def test_git_folder_in_public(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {"public/.git/HEAD": "ref: refs/heads/main\n"})
    found = run(tmp_path, write_tree, scan_rules, {}, "deploy-sensitive-file-public")
    assert any(f.severity == "critical" and ".git" in f.file for f in found)


# --- CORS -------------------------------------------------------------------------

@pytest.mark.parametrize("files,fires,sev", [
    ({"server.js": "app.use(cors({ origin: true, credentials: true }))\n"}, True, "high"),
    ({"server.js": "const corsOptions = {\n  credentials: true,\n  origin: true,\n}\napp.use(cors(corsOptions))\n"}, True, "high"),
    ({"server.js": "app.use(cors({ origin: (origin, callback) => callback(null, true), credentials: true }))\n"}, True, "high"),
    ({"server.js": "app.use(cors({ origin: function (origin, cb) { cb(null, true) }, credentials: true }))\n"}, True, "high"),
    ({"server.js": "app.use(cors({ origin: /myapp\\.com/, credentials: true }))\n"}, True, "medium"),
    ({"server.js": "app.use((req, res, next) => {\n  res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n"
                   "  res.setHeader('Access-Control-Allow-Credentials', 'true')\n  next()\n})\n"}, True, "high"),
    ({"middleware.ts": "const res = NextResponse.next()\nres.headers.set('Access-Control-Allow-Origin', "
                       "request.headers.get('origin') ?? '*')\nres.headers.set('Access-Control-Allow-Credentials', 'true')\n"}, True, "high"),
    # safe variants
    ({"server.js": "app.use(cors())\n"}, False, None),
    ({"server.js": "app.use(cors({ origin: '*' }))\n"}, False, None),
    ({"server.js": "app.use(cors({ origin: '*', credentials: true }))\n"}, False, None),
    ({"server.js": "app.use(cors({ origin: true }))\n"}, False, None),
    ({"server.js": "const allowed = new Set(['https://app.example.com'])\n"
                   "app.use(cors({ origin: (o, cb) => cb(null, !o || allowed.has(o)), credentials: true }))\n"}, False, None),
    ({"server.js": "app.use(cors({ origin: ['https://app.example.com'], credentials: true }))\n"}, False, None),
    ({"server.js": "app.use(cors({ origin: /^https:\\/\\/app\\.example\\.com$/, credentials: true }))\n"}, False, None),
    ({"server.js": "const o = req.headers.origin\nif (ALLOWED.includes(o)) res.setHeader('Access-Control-Allow-Origin', o)\n"
                   "res.setHeader('Access-Control-Allow-Credentials', 'true')\n"}, False, None),
    ({"server.js": "res.setHeader('Access-Control-Allow-Origin', req.headers.origin)\n"}, False, None),
    ({"server.js": "// app.use(cors({ origin: true, credentials: true }))\n"}, False, None),
    ({"supabase/functions/x/index.ts": "export const corsHeaders = { 'Access-Control-Allow-Origin': '*' }\n"}, False, None),
])
def test_cors_node(tmp_path, write_tree, scan_rules, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, EXPRESS, files, "deploy-cors-credentials-node", fires, sev)


FASTAPI_CORS = ("from fastapi.middleware.cors import CORSMiddleware\napp.add_middleware(\n    CORSMiddleware,\n"
                "    allow_origins=[\"*\"],\n    allow_credentials=True,\n    allow_methods=[\"*\"],\n)\n")


@pytest.mark.parametrize("base,files,fires", [
    (FASTAPI, {"main.py": FASTAPI_CORS}, True),
    (FASTAPI, {"main.py": "origins = ['*']\napp.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True)\n"}, True),
    (FASTAPI, {"main.py": "middleware = [Middleware(CORSMiddleware, allow_origin_regex='.*', allow_credentials=True)]\n"}, True),
    (DJANGO, {"proj/settings.py": "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n"}, True),
    (DJANGO, {"proj/settings.py": "CORS_ORIGIN_ALLOW_ALL = True\nCORS_ALLOW_CREDENTIALS = True\n"}, True),
    (FLASK, {"app.py": "from flask_cors import CORS\nCORS(app, supports_credentials=True)\n"}, True),
    (FLASK, {"app.py": "CORS(app, resources={r'/api/*': {'origins': '*'}}, supports_credentials=True)\n"}, True),
    # safe variants
    (FASTAPI, {"main.py": FASTAPI_CORS.replace("    allow_credentials=True,\n", "")}, False),
    (FASTAPI, {"main.py": FASTAPI_CORS.replace('["*"],\n    allow_c', '["https://app.example.com"],\n    allow_c', 1)}, False),
    (DJANGO, {"proj/settings.py": "CORS_ALLOW_ALL_ORIGINS = True\n"}, False),
    (DJANGO, {"proj/settings.py": "CORS_ALLOWED_ORIGINS = ['https://app.example.com']\nCORS_ALLOW_CREDENTIALS = True\n"}, False),
    (DJANGO, {"proj/settings/dev.py": "CORS_ALLOW_ALL_ORIGINS = True\nCORS_ALLOW_CREDENTIALS = True\n"}, False),
    (FLASK, {"app.py": "CORS(app)\n"}, False),
    (FLASK, {"app.py": "CORS(app, origins=['https://app.example.com'], supports_credentials=True)\n"}, False),
    (FLASK, {"app.py": "# CORS(app, supports_credentials=True)\n"}, False),
])
def test_cors_python(tmp_path, write_tree, scan_rules, base, files, fires):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-cors-credentials-python", fires)


@pytest.mark.parametrize("text,fires", [
    ("<?php\nreturn [\n    'allowed_origins' => ['*'],\n    'supports_credentials' => true,\n];\n", True),
    ("<?php\nreturn [\n    'allowed_origins' => ['*'],\n    'supports_credentials' => false,\n];\n", False),
    ("<?php\nreturn [\n    'allowed_origins' => [env('FRONTEND_URL')],\n    'supports_credentials' => true,\n];\n", False),
])
def test_cors_laravel(tmp_path, write_tree, scan_rules, text, fires):
    assert_case(tmp_path, write_tree, scan_rules, LARAVEL, {"config/cors.php": text},
                "deploy-cors-credentials-laravel", fires)


# --- cookies ----------------------------------------------------------------------

@pytest.mark.parametrize("files,fires", [
    ({"server.js": "app.use(session({ secret: s, cookie: { secure: false } }))\n"}, True),
    ({"server.js": "app.use(session({\n  secret: s,\n  cookie: {\n    httpOnly: false,\n    secure: true,\n  },\n}))\n"}, True),
    ({"server.js": "res.cookie('token', jwt)\n"}, True),
    ({"server.js": "res.cookie('session', id, { secure: true, sameSite: 'lax' })\n"}, True),
    ({"server.js": "res.cookie('auth_token', t, { httpOnly: true, secure: true, sameSite: 'none' })\n"}, True),
    ({"server.js": "const opts = { httpOnly: false, secure: true }\nres.cookie('sid', id, opts)\n"}, True),
    ({"app/api/login/route.ts": "import { cookies } from 'next/headers'\nexport async function POST() {\n"
                                "  (await cookies()).set('session', token, { secure: true })\n}\n"}, True),
    ({"app/actions.ts": "'use server'\nimport { cookies } from 'next/headers'\nexport async function login() {\n"
                        "  const cookieStore = await cookies()\n  cookieStore.set({ name: 'accessToken', value: t, secure: true })\n}\n"}, True),
    ({"server.js": "res.setHeader('Set-Cookie', `token=${t}; Path=/; Secure`)\n"}, True),
    # safe variants
    ({"server.js": "app.use(session({ secret: s, cookie: { secure: process.env.NODE_ENV === 'production', sameSite: 'lax' } }))\n"}, False),
    ({"server.js": "app.use(session({ secret: s, resave: false, saveUninitialized: false }))\n"}, False),
    ({"server.js": "res.cookie('token', jwt, { httpOnly: true, secure: true, sameSite: 'lax' })\n"}, False),
    ({"server.js": "res.cookie('theme', 'dark', { httpOnly: false })\n"}, False),
    ({"server.js": "res.cookie('XSRF-TOKEN', req.csrfToken(), { httpOnly: false, secure: true })\n"}, False),
    ({"server.js": "res.cookie('token', jwt, cookieOptionsFromConfig)\n"}, False),
    ({"server.js": "res.cookie('token', jwt, { ...baseCookie })\n"}, False),
    ({"server.js": "const transport = nodemailer.createTransport({ host, port: 587, secure: false })\n"}, False),
    ({"server.js": "if (process.env.NODE_ENV !== 'production') {\n  app.use(session({ cookie: { secure: false } }))\n}\n"}, False),
    ({"src/components/Banner.tsx": "'use client'\nimport Cookies from 'js-cookie'\nCookies.set('token', t)\n"}, False),
    ({"server.js": "// res.cookie('token', jwt)\n"}, False),
    ({"app/api/logout/route.ts": "response.cookies.set(SESSION_COOKIE, \"\", { path: \"/\", maxAge: 0 })\n"}, False),
    ({"server.js": "res.cookie('token', 'x', { expires: new Date(0) })\n"}, False),
    ({"app/api/login/route.ts": "response.cookies.set(SESSION_COOKIE, createSessionToken(), {\n  httpOnly: true,\n"
                                "  secure: process.env.NODE_ENV === 'production',\n  sameSite: 'lax',\n})\n"}, False),
])
def test_cookie_node(tmp_path, write_tree, scan_rules, files, fires):
    assert_case(tmp_path, write_tree, scan_rules, EXPRESS, files, "deploy-cookie-flags-node", fires)


@pytest.mark.parametrize("base,files,fires", [
    (FASTAPI, {"main.py": "response.set_cookie(key='access_token', value=token)\n"}, True),
    (FASTAPI, {"main.py": "response.set_cookie('session', sid, secure=True)\n"}, True),
    (FLASK, {"app.py": "resp.set_cookie('token', t, httponly=True, secure=False)\n"}, True),
    (FLASK, {"app.py": "app.config['SESSION_COOKIE_HTTPONLY'] = False\n"}, True),
    (DJANGO, {"proj/settings.py": "SESSION_COOKIE_HTTPONLY = False\n"}, True),
    # safe variants
    (FASTAPI, {"main.py": "response.set_cookie(key='access_token', value=token, httponly=True, secure=True, samesite='lax')\n"}, False),
    (FASTAPI, {"main.py": "response.set_cookie('theme', 'dark')\n"}, False),
    (FASTAPI, {"main.py": "response.set_cookie('session', sid, httponly=settings.COOKIE_HTTPONLY, secure=True)\n"}, False),
    (FASTAPI, {"main.py": "response.set_cookie('csrftoken', tok)\n"}, False),
    (FASTAPI, {"main.py": "response.set_cookie(**cookie_kwargs)\n"}, False),
    (FASTAPI, {"main.py": "response.set_cookie('session', '', max_age=0)\n"}, False),
    (FLASK, {"app.py": "resp.set_cookie('token', '', expires=0)\n"}, False),
    (DJANGO, {"proj/settings/dev.py": "SESSION_COOKIE_HTTPONLY = False\n"}, False),
])
def test_cookie_python(tmp_path, write_tree, scan_rules, base, files, fires):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-cookie-flags-python", fires)


@pytest.mark.parametrize("text,fires", [
    ("<?php\nreturn [\n    'http_only' => false,\n];\n", True),
    ("<?php\nreturn [\n    'secure' => false,\n];\n", True),
    ("<?php\nreturn [\n    'same_site' => 'none',\n];\n", True),
    ("<?php\nreturn [\n    'secure' => env('SESSION_SECURE_COOKIE'),\n    'http_only' => true,\n    'same_site' => 'lax',\n];\n", False),
    ("<?php\nreturn [\n    // 'http_only' => false,\n    'http_only' => true,\n];\n", False),
])
def test_laravel_session(tmp_path, write_tree, scan_rules, text, fires):
    assert_case(tmp_path, write_tree, scan_rules, LARAVEL, {"config/session.php": text},
                "deploy-laravel-session-cookie", fires)


@pytest.mark.parametrize("files,fires", [
    ({"login.php": "<?php\nsetcookie('session', $id);\n"}, True),
    ({"login.php": "<?php\nsetcookie(\"auth_token\", $t, time() + 3600, \"/\", \"\", true, false);\n"}, True),
    ({"login.php": "<?php\nsetcookie('remember_me', $t, ['expires' => time() + 60, 'secure' => true]);\n"}, True),
    ({"login.php": "<?php\n\\setcookie('sid', $id, time() + 3600, '/');\n"}, True),
    ({"login.php": "<?php\n$exp = time() + 3600;\nsetcookie('session', $id, $exp);\n"}, True),
    ({"boot.php": "<?php\nini_set('session.cookie_httponly', '0');\nsession_start();\n"}, True),
    ({"boot.php": "<?php\nsession_set_cookie_params(['lifetime' => 0, 'httponly' => false]);\n"}, True),
    ({"index.php": "<?php\n", "php.ini": "; session\nsession.cookie_httponly = 0\n"}, True),
    # safe variants
    ({"login.php": "<?php\nsetcookie('theme', 'dark');\nsetcookie('lang', $lang, time() + 86400);\n"}, False),
    ({"login.php": "<?php\nsetcookie('session', $id, ['expires' => 0, 'httponly' => true, 'secure' => true, "
                   "'samesite' => 'Lax']);\n"}, False),
    ({"login.php": "<?php\nsetcookie('session', $id, 0, '/', '', true, true);\n"}, False),
    ({"logout.php": "<?php\nsetcookie('session', '', time() - 3600, '/');\n"}, False),
    ({"login.php": "<?php\n$opts = ['httponly' => true, 'secure' => true];\nsetcookie('session', $id, $opts);\n"}, False),
    ({"login.php": "<?php\nsetcookie('sid', $id, 0, '/', '', $secure, $httponly);\n"}, False),
    ({"lib.php": "<?php\nfunction issue($id, $options) {\n  setcookie('session', $id, $options);\n}\n"}, False),
    ({"login.php": "<?php\n// setcookie('session', $id);\n$csrf = 'setcookie(\"token\", $t)';\n"}, False),
    ({"login.php": "<?php\nsetcookie('XSRF-TOKEN', $csrf);\n"}, False),
    ({"boot.php": "<?php\nini_set('session.cookie_httponly', '1');\nini_set('session.cookie_secure', 1);\n"}, False),
])
def test_cookie_php(tmp_path, write_tree, scan_rules, files, fires):
    assert_case(tmp_path, write_tree, scan_rules, {}, files, "deploy-cookie-flags-php", fires)


# --- security headers -------------------------------------------------------------

@pytest.mark.parametrize("files,fires", [
    ({"next.config.js": "module.exports = { reactStrictMode: true }\n"}, True),
    ({}, True),
    # header names in comments do not count as headers being set
    ({"next.config.js": "// TODO: add Content-Security-Policy and X-Frame-Options headers before launch\n"
                        "module.exports = { reactStrictMode: true }\n"}, True),
    ({"next.config.js": "/* NOTE the absence of a headers() block: no X-Frame-Options */\nmodule.exports = {}\n",
      "middleware.ts": "// no CSP, no X-Frame-Options (clickjacking), no HSTS\nexport function middleware() {}\n"}, True),
    ({"next.config.mjs": "export default {}\n", "netlify.toml": "# TODO: set X-Frame-Options\n[build]\n  publish = 'out'\n"}, True),
    # safe variants
    ({"next.config.js": "module.exports = {\n  async headers() {\n    return [{ source: '/(.*)', headers: securityHeaders }]\n  },\n}\n"}, False),
    ({"next.config.mjs": "export default {}\n", "middleware.ts": "res.headers.set('Content-Security-Policy', csp)\n"}, False),
    ({"next.config.mjs": "export default {}\n", "src/proxy.ts": "res.headers.set('X-Frame-Options', 'DENY')\n"}, False),
    ({"next.config.mjs": "export default {}\n", "vercel.json": json.dumps({"headers": [{"source": "/(.*)", "headers": [
        {"key": "X-Content-Type-Options", "value": "nosniff"}]}]})}, False),
    ({"next.config.mjs": "export default {}\n", "public/_headers": "/*\n  Strict-Transport-Security: max-age=63072000\n"}, False),
])
def test_nextjs_headers(tmp_path, write_tree, scan_rules, files, fires):
    found = assert_case(tmp_path, write_tree, scan_rules, NEXT, files, "deploy-nextjs-no-security-headers", fires)
    if fires:
        assert found[0].severity == "low" and found[0].needs_confirmation


def test_nextjs_headers_points_at_nested_manifest(tmp_path, write_tree, scan_rules):
    files = {"web/package.json": pkg({"next": "15.2.3"}),
             "web/app/page.tsx": "export default function Page() { return null }\n"}
    found = run(tmp_path, write_tree, scan_rules, files, "deploy-nextjs-no-security-headers", stacks="all")
    assert [f.file for f in found] == ["web/package.json"]
    assert (tmp_path / found[0].file).is_file()


def test_nextjs_headers_skipped_with_header_package(tmp_path, write_tree, scan_rules):
    files = dict(NEXT, **{"package.json": pkg({"next": "15.2.3", "@nosecone/next": "1.0.0"}),
                          "next.config.js": "module.exports = {}\n"})
    assert run(tmp_path, write_tree, scan_rules, files, "deploy-nextjs-no-security-headers") == []


@pytest.mark.parametrize("files,fires", [
    ({"server.js": SERVER}, True),
    ({"server.js": "const helmet = require('helmet')\n" + SERVER + "app.use(helmet({ contentSecurityPolicy: false }))\n",
      "package.json": pkg({"express": "4.19.2", "helmet": "7.1.0"})}, True),
    # installed but never wired up
    ({"server.js": "// const helmet = require('helmet')\n" + SERVER + "/*\napp.use(helmet.frameguard())\n"
                   "app.use(helmet.hsts())\n*/\n// res.setHeader('X-Frame-Options', 'DENY')\n",
      "package.json": pkg({"express": "4.19.2", "helmet": "2.0.0"})}, True),
    ({"server.js": SERVER, "package.json": pkg({"express": "4.19.2", "helmet": "7.1.0"}),
      "views/tutorial.html": "<pre>app.use(helmet.xframe());</pre>\n"}, True),
    # safe variants
    ({"server.js": "const helmet = require('helmet')\n" + SERVER + "app.use(helmet())\n",
      "package.json": pkg({"express": "4.19.2", "helmet": "7.1.0"})}, False),
    ({"server.js": SERVER, "lib/security.ts": "import secureHeaders from 'helmet'\nexport const sec = secureHeaders()\n",
      "package.json": pkg({"express": "4.19.2", "helmet": "7.1.0"})}, False),
    ({"server.js": SERVER + "app.use(helmet.hsts())\napp.use(helmet.noSniff())\n",
      "package.json": pkg({"express": "4.19.2", "helmet": "7.1.0"})}, False),
    ({"server.js": SERVER + "app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next() })\n"}, False),
    ({"server.js": SERVER, "nginx/site.conf": "add_header Strict-Transport-Security \"max-age=31536000\";\n"}, False),
])
def test_express_helmet(tmp_path, write_tree, scan_rules, files, fires):
    found = assert_case(tmp_path, write_tree, scan_rules, EXPRESS, files, "deploy-express-no-helmet", fires)
    if fires:
        assert found[0].severity == "low"


# --- source maps ------------------------------------------------------------------

@pytest.mark.parametrize("base,files,fires,sev", [
    (NEXT, {"next.config.js": "module.exports = { productionBrowserSourceMaps: true }\n"}, True, "medium"),
    (VITE, {"vite.config.ts": "export default defineConfig({\n  plugins: [react()],\n  build: {\n    sourcemap: true,\n  },\n})\n"}, True, "medium"),
    (VITE, {"vite.config.js": "export default { build: { rollupOptions: { output: { sourcemap: 'inline' } } } }\n"}, True, "medium"),
    (VITE, {"vite.config.js": "export default { build: { sourcemap: 'hidden' } }\n"}, True, "low"),
    (EXPRESS, {"webpack.prod.js": "module.exports = { mode: 'production', devtool: 'source-map' }\n"}, True, "medium"),
    (CRA, {}, True, "low"),
    # safe variants
    (NEXT, {"next.config.js": "module.exports = { productionBrowserSourceMaps: false }\n"}, False, None),
    (NEXT, {"next.config.js": "module.exports = withSentryConfig({ productionBrowserSourceMaps: true }, "
                              "{ sourcemaps: { deleteSourcemapsAfterUpload: true } })\n"}, False, None),
    (VITE, {"vite.config.ts": "export default defineConfig({ css: { devSourcemap: true }, build: { outDir: 'dist' } })\n"}, False, None),
    (VITE, {"vite.config.ts": "export default defineConfig({ build: { sourcemap: true }, plugins: [sentryVitePlugin({ "
                              "sourcemaps: { filesToDeleteAfterUpload: ['./dist/**/*.map'] } })] })\n"}, False, None),
    (VITE, {"vite.config.ts": "export default defineConfig({ esbuild: { sourcemap: true } })\n"}, False, None),
    (EXPRESS, {"webpack.config.js": "module.exports = { mode: 'development', devtool: 'eval-source-map' }\n"}, False, None),
    (EXPRESS, {"webpack.prod.js": "module.exports = { mode: 'production', devtool: 'hidden-source-map' }\n"}, False, None),
    (CRA, {".env.production": "GENERATE_SOURCEMAP=false\n"}, False, None),
    (CRA, {"package.json": pkg({"react-scripts": "5.0.1"}, scripts={"build": "GENERATE_SOURCEMAP=false react-scripts build"})}, False, None),
])
def test_source_maps(tmp_path, write_tree, scan_rules, base, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-source-maps", fires, sev)


MIT_TEXT = ("MIT License\n\nCopyright (c) 2026 Example\n\nPermission is hereby granted, free of charge, to any person "
            "obtaining a copy of this software...\n")
VITE_MAPS = {"vite.config.ts": "export default defineConfig({ build: { sourcemap: true } })\n"}


@pytest.mark.parametrize("files,sev", [
    # open-source LICENSE file: the maps reveal code that is already public
    (dict(VITE_MAPS, LICENSE=MIT_TEXT), "low"),
    ({"theme/vite.config.mjs": "export default { build: { sourcemap: true } }\n",
      "theme/package.json": pkg({"vite": "5.4.0"}), "LICENSE": "Redistribution and use in source and binary forms, "
                                                               "with or without modification, are permitted...\n"}, "low"),
    # npm init writes "license": "ISC" into every package.json; that alone is not open source
    (dict(VITE_MAPS, **{"package.json": json.dumps({"name": "app", "license": "ISC", "devDependencies": {"vite": "5.4.0"}})}),
     "medium"),
    (dict(VITE_MAPS, LICENSE="Copyright (c) 2026 Example Ltd. All rights reserved.\n"), "medium"),
])
def test_source_maps_open_source(tmp_path, write_tree, scan_rules, files, sev):
    found = assert_case(tmp_path, write_tree, scan_rules, VITE, files, "deploy-source-maps", True, sev)
    assert ("open-source" in found[0].message) == (sev == "low")


# --- logging ----------------------------------------------------------------------

@pytest.mark.parametrize("files,fires,sev", [
    ({"server.js": "console.log(process.env)\n"}, True, "high"),
    ({"server.js": "console.log('env', JSON.stringify(process.env, null, 2))\n"}, True, "high"),
    ({"server.js": "app.use((req, res, next) => { console.log(req.headers); next() })\n"}, True, "medium"),
    ({"server.js": "logger.info('auth', req.headers.authorization)\n"}, True, "high"),
    ({"routes/auth.js": "router.post('/login', (req, res) => {\n  console.log(req.body)\n})\n"}, True, "medium"),
    ({"server.js": "app.post('/api/signup', async (req, res) => {\n  console.log('signup', req.body)\n})\n"}, True, "medium"),
    ({"server.js": "console.log('pw', req.body.password)\n"}, True, "high"),
    ({"lib/auth.ts": "const token = jwt.sign(p, s)\nconsole.log('Generated token:', token)\n"}, True, "medium"),
    ({"lib/auth.ts": "console.log(`issued ${accessToken} for ${user.id}`)\n"}, True, "medium"),
    ({"server.js": "console.log({ email, password })\n"}, True, "medium"),
    ({"server.js": "console.log('secret is', process.env.JWT_SECRET)\n"}, True, "medium"),
    ({"server.js": "console.log('issued', issuedToken)\n"}, True, "medium"),
    ({"server.js": "const t = await getSession()\nconsole.log('session', t.accessToken)\n"}, True, "medium"),
    ({"server.js": "console.log('tok', JSON.stringify({ token }))\n"}, True, "medium"),
    ({"lib/oauth.ts": "const newToken = await res.json()\nconsole.log('refreshed', newToken)\n"}, True, "medium"),
    ({"server.js": "if (process.env.NODE_ENV === 'production') {\n  console.info('reset link', token)\n}\n"}, True, "medium"),
    # a rejected key is still the key someone sent (often a near miss of a real one)
    ({"lib/api-auth.ts": "logger.warn('rejected key', { invalidApiKey })\n"}, True, "medium"),
    ({"scripts/server.js": "const app = express()\nconsole.log('tok', token)\napp.listen(3000)\n"}, True, "medium"),
    # local scripts, seeds and emulators: terminal output, reported low
    ({"scripts/run-emulator.ts": "console.log(`  API_KEY=${emulator.apiKey}`)\n"}, True, "low"),
    ({"scripts/create-admin.cjs": "const password = 'change-me-now'\nconsole.log('Password:', password)\n"
                                  "process.exit(0)\n"}, True, "low"),
    ({"packages/db/seed/seed.ts": "const ADMIN_PASSWORD = 'password'\nconsole.log(`Admin password: ${ADMIN_PASSWORD}`)\n"},
     True, "low"),
    ({"src/cli/user.js": "const password = await generatePassword()\n"
                         "logger.info(`User created. Generated password: ${password}`)\n"}, True, "low"),
    # safe variants
    ({"lib/internal-api.ts": "logger.error('Invalid API key', {\n  keyHash: apiKey ? hash(apiKey) : null,\n"
                             "  keyLength: apiKey?.length,\n})\n"}, False, None),
    ({"app/api/hook/route.ts": "logger.warn('bad signature', {\n  secretFingerprint: getSecretFingerprint(\n"
                               "    env.WEBHOOK_SECRET,\n  ),\n})\n"}, False, None),
    ({"lib/build.mjs": "console.log(output.replaceAll(token, '[redacted]').trim())\n"}, False, None),
    ({"lib/model.ts": "logger.warn(warningMessages.missingCredentials, { provider })\n"}, False, None),
    ({"lib/form.ts": "console.error(errors.password, strings.apiKey)\n"}, False, None),
    ({"app/api/set-password/route.ts": "if (process.env.NODE_ENV === \"development\") {\n"
                                       "  console.info('Password reset URL:', `${base}/reset/${token}`)\n}\n"}, False, None),
    ({"server.js": "if (process.env.NODE_ENV !== 'production') console.log('reset link', token)\n"}, False, None),
    ({"server.js": "if (isDev)\n  console.log('reset link', token)\n"}, False, None),
    ({"server.js": "isDevelopment && console.debug('session', sessionToken)\n"}, False, None),
    ({"lib/oauth.ts": "const newToken = await response.json()\nif (!response.ok) {\n"
                      "  console.error('refresh failed', newToken)\n  throw new Error('refresh failed')\n}\n"}, False, None),
    ({"app/api/webhook/route.ts": "logger.info('Received validation request', { validationToken })\n"}, False, None),
    ({"lib/import.ts": "console.error(`Link not found for coupon ${coupon.token}`, checkoutToken)\n"}, False, None),
    ({"server.js": "console.log('Token refreshed for user', user.id)\n"}, False, None),
    ({"server.js": "console.log('has auth header:', !!req.headers.authorization)\n"}, False, None),
    ({"server.js": "console.log('auth', req.headers.authorization ? 'present' : 'missing')\n"}, False, None),
    ({"server.js": "console.log('api key set:', apiKey ? 'yes' : 'no', 'len', token.length)\n"}, False, None),
    ({"server.js": "console.log(process.env.NODE_ENV)\n"}, False, None),
    ({"server.js": "console.log(Object.keys(req.headers))\n"}, False, None),
    ({"routes/posts.js": "router.post('/posts', (req, res) => {\n  console.log(req.body)\n})\n"}, False, None),
    ({"server.js": "console.log({ userId, route, status })\n"}, False, None),
    ({"server.js": "console.log('usage', usage.total_tokens, maxTokens)\n"}, False, None),
    ({"server.js": "const logger = pino({ redact: ['req.headers.authorization'] })\nlogger.info(req.headers)\n"}, False, None),
    ({"server.js": "// console.log(process.env)\n"}, False, None),
    ({"server.test.js": "console.log(process.env)\n"}, False, None),
    ({"src/components/Login.tsx": "'use client'\nexport function L() { console.log(token); return null }\n"}, False, None),
])
def test_log_node(tmp_path, write_tree, scan_rules, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, EXPRESS, files, "deploy-log-secrets-node", fires, sev)


def test_log_node_literal_credential_message(tmp_path, write_tree, scan_rules):
    files = {"scripts/create-admin.cjs": "const password = 'change-me-now'\nconsole.log('Password:', password)\n"}
    found = run(tmp_path, write_tree, scan_rules, dict(EXPRESS, **files), "deploy-log-secrets-node")
    assert "string literal" in found[0].message and "rotation.md" in found[0].message
    assert "change-me-now" not in found[0].message


def test_express_helmet_installed_but_unused_message(tmp_path, write_tree, scan_rules):
    files = {"server.js": "// const helmet = require('helmet')\n" + SERVER,
             "package.json": pkg({"express": "4.19.2", "helmet": "7.1.0"})}
    found = run(tmp_path, write_tree, scan_rules, dict(EXPRESS, **files), "deploy-express-no-helmet")
    assert found and "never called" in found[0].message


def test_cors_fp_trap_states_the_browser_rule():
    rule = [r for r in rd.RULES if r.id == "deploy-cors-credentials-node"][0]
    assert "never send cookies" not in rule.fp_trap and "read a credentialed response" in rule.fp_trap


@pytest.mark.parametrize("base,files,fires,sev", [
    (FLASK, {"app.py": "import os\nprint(os.environ)\n"}, True, "high"),
    (FLASK, {"app.py": "logger.debug(dict(os.environ))\n"}, True, "high"),
    (FASTAPI, {"main.py": "print(request.headers)\n"}, True, "medium"),
    (FASTAPI, {"main.py": "logger.info(request.headers.get('Authorization'))\n"}, True, "high"),
    (FLASK, {"auth.py": "@app.post('/login')\ndef login():\n    print(request.json)\n"}, True, "medium"),
    (FLASK, {"app.py": "logging.info('pw %s', request.form['password'])\n"}, True, "high"),
    (FASTAPI, {"main.py": "print(f'issued token {token}')\n"}, True, "medium"),
    (FASTAPI, {"config.py": "print('key', settings.OPENAI_API_KEY)\n"}, True, "medium"),
    # safe variants
    (FLASK, {"app.py": "print(os.environ.get('PORT'))\n"}, False, None),
    (FASTAPI, {"main.py": "print('token saved')\n"}, False, None),
    (FASTAPI, {"main.py": "logger.info('token length %d', len(token))\n"}, False, None),
    (FASTAPI, {"main.py": "print('api key set' if api_key else 'missing')\n"}, False, None),
    (FASTAPI, {"main.py": "print(usage.total_tokens, max_tokens)\n"}, False, None),
    (FLASK, {"posts.py": "@app.post('/posts')\ndef create():\n    print(request.json)\n"}, False, None),
    (FLASK, {"app.py": "# print(os.environ)\n"}, False, None),
    (FLASK, {"tests/test_app.py": "print(os.environ)\n"}, False, None),
])
def test_log_python(tmp_path, write_tree, scan_rules, base, files, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, base, files, "deploy-log-secrets-python", fires, sev)


@pytest.mark.parametrize("text,fires,sev", [
    ("<?php\nLog::info($request->all());\n", True, "medium"),
    ("<?php\nLog::debug('login', ['pw' => $request->input('password')]);\n", True, "high"),
    ("<?php\nlogger()->info('auth', [$request->bearerToken()]);\n", True, "high"),
    ("<?php\nLog::info(config());\n", True, "high"),
    # safe variants
    ("<?php\nLog::info($request->except(['password', 'password_confirmation']));\n", False, None),
    ("<?php\nLog::info('login', ['user' => $user->id]);\n", False, None),
    ("<?php\n// Log::info($request->all());\n", False, None),
    ("<?php\n$this->info($request->path());\n", False, None),
])
def test_log_laravel(tmp_path, write_tree, scan_rules, text, fires, sev):
    assert_case(tmp_path, write_tree, scan_rules, LARAVEL, {"app/Http/Controllers/AuthController.php": text},
                "deploy-log-secrets-laravel", fires, sev)


# --- whole-module decoys ----------------------------------------------------------

def test_safe_projects_produce_no_deploy_findings(tmp_path, write_tree, scan_rules):
    """Realistic, correctly configured projects: no rule in this module may fire."""
    files = {
        "package.json": pkg({"next": "15.2.3", "react": "19.0.0", "express": "5.1.0", "helmet": "8.0.0",
                             "cors": "2.8.5"},
                            scripts={"dev": "next dev", "build": "next build", "start": "next start"}),
        "app/layout.tsx": "export default function L({ children }) { return children }\n",
        "app/page.tsx": "export default function P() { return null }\n",
        "next.config.mjs": ("const securityHeaders = [{ key: 'X-Content-Type-Options', value: 'nosniff' }]\n"
                            "export default { async headers() { return [{ source: '/(.*)', headers: securityHeaders }] } }\n"),
        "server/index.js": ("import express from 'express'\nimport helmet from 'helmet'\nimport cors from 'cors'\n"
                            "const app = express()\napp.use(helmet())\n"
                            "const allowed = new Set((process.env.CORS_ORIGINS || '').split(','))\n"
                            "app.use(cors({ origin: (o, cb) => cb(null, !o || allowed.has(o)), credentials: true }))\n"
                            "app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore' }))\n"
                            "app.post('/login', (req, res) => {\n  console.log('login attempt', req.body.email)\n"
                            "  res.cookie('session', id, { httpOnly: true, secure: true, sameSite: 'lax' })\n"
                            "  res.json({ ok: true })\n})\n"
                            "app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Internal error' }) })\n"
                            "app.listen(3000)\n"),
        "Dockerfile": "FROM node:20\nENV NODE_ENV=production\nRUN npm ci && npm run build\nCMD [\"npm\", \"start\"]\n",
        "docker-compose.yml": "services:\n  web:\n    command: npm run dev\n",
        "public/robots.txt": "User-agent: *\n",
        "public/.well-known/security.txt": "Contact: mailto:x@example.test\n",
        "requirements.txt": "fastapi\nuvicorn\n",
        "api/main.py": ("import os, logging\nfrom fastapi.middleware.cors import CORSMiddleware\n"
                        "app.add_middleware(CORSMiddleware, allow_origins=os.environ['CORS_ORIGINS'].split(','), "
                        "allow_credentials=True)\n"
                        "def login(response):\n    response.set_cookie('session', sid, httponly=True, secure=True, samesite='lax')\n"
                        "    logging.info('login ok for %s', user_id)\n"),
    }
    write_tree(tmp_path, files)
    rules, _warnings = scan_app.load_rules(("_rules_deploy",))
    res = scan_app.run_scan(tmp_path, rules=rules)
    assert res.findings == [], [(f.rule, f.file, f.line, f.message) for f in res.findings]
