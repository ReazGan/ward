"""Every skill must work when its folder is copied alone, the way npx skills,
gh skill and gemini skills install it. Each skill folder is copied into a
temp dir with nothing else from the repo, then its scripts run from a
different working directory.
"""

import ast
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import sysconfig
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from conftest import REPO_ROOT

SKILLS = REPO_ROOT / "skills"
CHECKER = REPO_ROOT / ".github" / "scripts" / "check_frontmatter.py"


def _skill_names():
    if not SKILLS.is_dir():
        return []
    return sorted(p.name for p in SKILLS.iterdir() if p.is_dir() and not p.name.startswith("."))


def _scripts(skill_dir):
    d = skill_dir / "scripts"
    return sorted(d.glob("*.py")) if d.is_dir() else []


def _entry_scripts(skill_dir):
    return [p for p in _scripts(skill_dir) if not p.name.startswith("_")]


@pytest.fixture
def isolated(tmp_path):
    """Copy one skill folder alone into tmp; returns (skill_dir, workdir)."""
    def make(name):
        dest = tmp_path / "installed" / name
        shutil.copytree(str(SKILLS / name), str(dest),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
        work = tmp_path / "work"
        work.mkdir(exist_ok=True)
        return dest, work
    return make


def run(script, *args, cwd, timeout=180):
    env = dict(os.environ)
    for k in ("PYTHONPATH", "PYTHONUTF8", "PYTHONIOENCODING", "PYTHONHOME"):
        env.pop(k, None)
    # -E ignores PYTHON* variables, -s skips user site-packages: nothing from
    # the repo or this test run can leak into the script's imports.
    return subprocess.run([sys.executable, "-E", "-s", str(script)] + [str(a) for a in args], cwd=str(cwd),
                          capture_output=True, encoding="utf-8", errors="replace", env=env, timeout=timeout)


# --- imports -----------------------------------------------------------------

_STDLIB_DIRS = {os.path.normcase(os.path.realpath(p)) for p in
                (sysconfig.get_paths().get("stdlib"), sysconfig.get_paths().get("platstdlib")) if p}


def _is_stdlib(mod):
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return mod in names
    if mod in sys.builtin_module_names:
        return True
    try:
        spec = importlib.util.find_spec(mod)
    except (ImportError, ValueError):
        return False
    if spec is None:
        return False
    if spec.origin in ("built-in", "frozen"):
        return True
    origin = os.path.normcase(os.path.realpath(spec.origin or ""))
    return any(origin.startswith(d + os.sep) for d in _STDLIB_DIRS) and "site-packages" not in origin


def _top_imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend((a.name.split(".")[0], node.lineno, 0) for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            out.append(((node.module or "").split(".")[0], node.lineno, node.level))
    return out


@pytest.mark.parametrize("name", _skill_names())
def test_scripts_import_only_stdlib_and_siblings(name):
    d = SKILLS / name
    scripts = _scripts(d)
    if not scripts:
        pytest.skip("%s has no scripts" % name)
    siblings = {p.stem for p in scripts} | {p.name for p in (d / "scripts").iterdir() if p.is_dir()}
    bad = []
    for script in scripts:
        try:
            imports = _top_imports(script)
        except SyntaxError:
            continue  # reported by test_wardcore.test_all_scripts_parse_as_python39
        for mod, line, level in imports:
            where = "%s:%d" % (script.relative_to(REPO_ROOT).as_posix(), line)
            if level:
                bad.append("%s relative import (scripts are not a package)" % where)
            elif mod == "__future__" or mod in siblings:
                continue
            elif not _is_stdlib(mod):
                bad.append("%s imports %s, which is not in the standard library" % (where, mod))
    assert bad == [], bad


@pytest.mark.parametrize("name", _skill_names())
def test_no_paths_outside_the_skill(name):
    """No script reads ../ or the plugin root; npx skills copies one folder."""
    bad = []
    for script in _scripts(SKILLS / name):
        text = script.read_text(encoding="utf-8")
        for token in ("CLAUDE_PLUGIN_ROOT", "parent.parent.parent"):
            if token in text:
                bad.append("%s uses %s" % (script.name, token))
    assert bad == [], bad


# --- run each script from an isolated copy -----------------------------------

@pytest.mark.parametrize("name", _skill_names())
def test_help_runs_from_an_isolated_copy(name, isolated):
    if not _entry_scripts(SKILLS / name):
        pytest.skip("%s has no scripts to run" % name)
    d, work = isolated(name)
    for script in _entry_scripts(d):
        r = run(script, "--help", cwd=work)
        assert r.returncode == 0, "%s --help: %s" % (script.name, r.stderr)
        assert "usage" in r.stdout.lower(), script.name


@pytest.mark.parametrize("name", _skill_names())
def test_skill_md_resolves_inside_the_copy(name, isolated):
    if not (SKILLS / name / "SKILL.md").is_file():
        pytest.skip("%s/SKILL.md is not written yet" % name)
    d, work = isolated(name)
    r = subprocess.run([sys.executable, str(CHECKER), str(d)], cwd=str(work), capture_output=True,
                       encoding="utf-8", errors="replace")
    # Only the folder-escape and missing-file problems matter here; the
    # full lint runs in test_skill_frontmatter.py.
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith("error:")
             and ("leaves the skill folder" in ln or "outside the skill folder" in ln or "uses ../" in ln)]
    assert lines == [], "\n".join(lines)


def _project(root, files):
    for rel, text in files.items():
        p = Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return Path(root)


def _skip_unless(d, script):
    if not (d / "scripts" / script).is_file():
        pytest.skip("%s is not written yet" % script)


def test_preflight_scan_app_smoke(isolated, tmp_path):
    _skip_unless(SKILLS / "preflight-audit", "scan_app.py")
    d, work = isolated("preflight-audit")
    proj = _project(tmp_path / "app", {
        "package.json": json.dumps({"name": "demo", "dependencies": {"express": "^4.19.2"}}),
        "server.js": "const express = require('express');\nconst app = express();\napp.listen(3000);\n",
        "caf\u00e9/notes.md": "Non-ASCII path, still fine.\n",
    })
    r = run(d / "scripts" / "scan_app.py", "--json", proj, cwd=work)
    assert r.returncode in (0, 1), r.stderr
    rep = json.loads(r.stdout)
    assert rep["tool"] == "ward" and isinstance(rep["findings"], list)
    assert "express" in rep.get("stacks", [])
    r = run(d / "scripts" / "scan_app.py", "--list-rules", cwd=work)
    assert r.returncode == 0, r.stderr


INSTALL_DIRS = (".claude/skills", ".agents/skills")


@pytest.mark.parametrize("script", ["scan_app.py", "find_secrets.py"])
def test_project_install_does_not_flag_ward_itself(tmp_path, script):
    """npx skills installs into the user's project (.claude/skills, .agents/skills).
    Scanning that project must not report ward's own rule data as findings."""
    _skip_unless(SKILLS / "preflight-audit", script)
    proj = _project(tmp_path / "app", {
        "package.json": json.dumps({"name": "demo", "dependencies": {"next": "14.2.30"}}),
        "app/page.tsx": "export default function Page() { return <main>hi</main>; }\n",
    })
    for install in INSTALL_DIRS:
        for name in _skill_names():
            shutil.copytree(str(SKILLS / name), str(proj / install / name),
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    work = tmp_path / "work"
    work.mkdir()
    r = run(proj / ".claude" / "skills" / "preflight-audit" / "scripts" / script, "--json", proj, cwd=work)
    assert r.returncode in (0, 1), r.stderr
    own = [f for f in json.loads(r.stdout)["findings"] if f["file"].startswith(INSTALL_DIRS)]
    assert own == [], ["%s %s:%s" % (f["rule"], f["file"], f["line"]) for f in own]


def test_project_install_does_not_change_detected_stacks(tmp_path):
    """ward's own .py files under .claude/skills must not make a Next.js app look like Python."""
    _skip_unless(SKILLS / "preflight-audit", "scan_app.py")
    proj = _project(tmp_path / "app", {
        "package.json": json.dumps({"name": "demo", "dependencies": {"next": "14.2.30"}}),
        "app/page.tsx": "export default function Page() { return <main>hi</main>; }\n",
    })
    shutil.copytree(str(SKILLS / "preflight-audit"), str(proj / ".claude" / "skills" / "preflight-audit"),
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    work = tmp_path / "work"
    work.mkdir()
    r = run(proj / ".claude" / "skills" / "preflight-audit" / "scripts" / "scan_app.py", "--json", proj, cwd=work)
    assert r.returncode in (0, 1), r.stderr
    rep = json.loads(r.stdout)
    assert "nextjs" in rep["stacks"]
    assert "python" not in rep["stacks"], rep["stacks"]


def test_preflight_find_secrets_smoke(isolated, tmp_path, fake_token):
    _skip_unless(SKILLS / "preflight-audit", "find_secrets.py")
    d, work = isolated("preflight-audit")
    secret = fake_token("sk_" + "live_", 32)
    proj = _project(tmp_path / "app", {"src/pay.js": "const stripeKey = \"%s\";\n" % secret})
    r = run(d / "scripts" / "find_secrets.py", "--json", proj, cwd=work)
    assert r.returncode == 1, r.stdout + r.stderr
    assert secret not in r.stdout and secret not in r.stderr
    assert json.loads(r.stdout)["summary"]["total"] >= 1


def test_preflight_gen_rules_md_smoke(isolated, tmp_path):
    _skip_unless(SKILLS / "preflight-audit", "gen_rules_md.py")
    d, work = isolated("preflight-audit")
    out = tmp_path / "rules.md"
    r = run(d / "scripts" / "gen_rules_md.py", "--output", out, cwd=work)
    assert r.returncode == 0, r.stderr
    assert out.read_text(encoding="utf-8").startswith("# Rule reference")


def test_live_find_secrets_smoke(isolated, tmp_path, fake_token):
    _skip_unless(SKILLS / "live-exposure-check", "find_secrets.py")
    d, work = isolated("live-exposure-check")
    secret = fake_token("sk_" + "live_", 32)
    proj = _project(tmp_path / "bundle", {"main.js": "var k=\"%s\";\n" % secret})
    r = run(d / "scripts" / "find_secrets.py", "--json", proj, cwd=work)
    assert r.returncode == 1, r.stdout + r.stderr
    assert secret not in r.stdout


def test_live_check_refuses_a_host_it_does_not_own(isolated):
    _skip_unless(SKILLS / "live-exposure-check", "check_live.py")
    d, work = isolated("live-exposure-check")
    r = run(d / "scripts" / "check_live.py", "--json", "https://shop.example.invalid/", cwd=work, timeout=60)
    assert r.returncode == 3, r.stdout + r.stderr


class _Page(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = b"<!doctype html><html><head><title>demo</title></head><body>ok</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        else:
            body = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(404 if self.path not in ("/", "/index.html") else 200)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_live_check_runs_against_localhost(isolated):
    _skip_unless(SKILLS / "live-exposure-check", "check_live.py")
    d, work = isolated("live-exposure-check")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Page)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        url = "http://127.0.0.1:%d/" % server.server_address[1]
        r = run(d / "scripts" / "check_live.py", "--json", url, cwd=work, timeout=120)
    finally:
        server.shutdown()
        server.server_close()
    assert r.returncode in (0, 1), r.stdout + r.stderr
    rep = json.loads(r.stdout)
    assert rep["tool"] == "ward" and isinstance(rep["findings"], list)
