import json
import re
import os
import shutil
import subprocess

import pytest

import find_secrets
from conftest import _fake_token as tok
from conftest import _make_jwt as jwt

HAS_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAS_GIT, reason="git not installed")


def live_key():
    return "sk_" + "live_" + tok()


def git(cwd, *args, tmp=None):
    env = dict(os.environ)
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid",
    })
    if tmp is not None:
        cfg = tmp / "empty.gitconfig"
        cfg.write_text("", encoding="utf-8")
        env["GIT_CONFIG_GLOBAL"] = str(cfg)
    r = subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"] + list(args),
                       cwd=str(cwd), capture_output=True, encoding="utf-8", errors="replace", env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout


def init_repo(path, tmp):
    path.mkdir(parents=True, exist_ok=True)
    git(path, "init", "-q", tmp=tmp)
    return path


def report(r):
    assert r.returncode in (0, 1), r.stderr
    return json.loads(r.stdout)


# --- source scan --------------------------------------------------------------------

def test_source_secret_found_and_masked(tmp_path, write_tree, run_script):
    key = live_key()
    write_tree(tmp_path / "app", {"src/config.js": "export const stripe = '%s'\n" % key})
    r = run_script("find_secrets.py", "--json", tmp_path / "app")
    assert r.returncode == 1
    assert key not in r.stdout and key not in r.stderr
    rep = report(r)
    f = rep["findings"][0]
    assert f["rule"] == "stripe-live-secret-key" and f["severity"] == "critical"
    assert f["file"] == "src/config.js" and f["line"] == 1
    assert f["fix_ref"] == "rotation.md#stripe"
    assert "sk_l[" in f["evidence"]
    r2 = run_script("find_secrets.py", tmp_path / "app")
    assert key not in r2.stdout and "CRITICAL" in r2.stdout


def test_public_keys_not_reported_but_counted(tmp_path, write_tree, run_script):
    anon = jwt({"iss": "supabase", "role": "anon", "ref": "abcdefghijklmnopqrst"})
    write_tree(tmp_path, {
        "src/supabase.ts": "createClient(url, '%s')\n" % anon,
        "src/pay.ts": "loadStripe('%s')\n" % ("pk_" + "live_" + tok()),
    })
    r = run_script("find_secrets.py", "--json", tmp_path)
    assert r.returncode == 0
    rep = report(r)
    assert rep["findings"] == []
    assert rep["public_keys_not_reported"] == {"stripe-publishable-key": 1, "supabase-anon-jwt": 1}


def test_service_role_jwt_found(tmp_path, write_tree, run_script):
    service = jwt({"iss": "supabase", "role": "service_role"})
    write_tree(tmp_path, {"src/admin.ts": "createClient(url, '%s')\n" % service})
    rep = report(run_script("find_secrets.py", "--json", tmp_path))
    assert [f["rule"] for f in rep["findings"]] == ["supabase-service-role-jwt"]


def test_env_file_without_git(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {".env": "STRIPE_SECRET_KEY=%s\n" % live_key()})
    rep = report(run_script("find_secrets.py", "--json", tmp_path))
    assert rep["findings"][0]["severity"] == "critical"
    assert "no .gitignore covers" in rep["findings"][0]["message"]

    write_tree(tmp_path, {".gitignore": "node_modules\n.env*\n!.env.example\n"})
    r = run_script("find_secrets.py", "--json", tmp_path)
    assert r.returncode == 0
    rep = report(r)
    assert [(f["rule"], f["severity"]) for f in rep["findings"]] == [("secret-in-ignored-file", "info")]


def test_env_file_without_git_nested_gitignore(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {
        ".gitignore": "node_modules\n",
        "web/.gitignore": ".env.local\n",
        "web/.env.local": "STRIPE_SECRET_KEY=%s\n" % live_key(),
        "api/.env.local": "STRIPE_SECRET_KEY=%s\n" % live_key(),
    })
    rep = report(run_script("find_secrets.py", "--json", tmp_path))
    got = sorted((f["file"], f["rule"], f["severity"]) for f in rep["findings"])
    assert got == [("api/.env.local", "stripe-live-secret-key", "critical"),
                   ("web/.env.local", "secret-in-ignored-file", "info")]


def test_example_env(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {".env.example": "STRIPE_SECRET_KEY=sk_test_...\nDATABASE_URL=postgres://user:password@localhost/db\n"})
    assert report(run_script("find_secrets.py", "--json", tmp_path))["findings"] == []
    write_tree(tmp_path, {".env.example": "STRIPE_SECRET_KEY=%s\n" % live_key()})
    rep = report(run_script("find_secrets.py", "--json", tmp_path))
    f = rep["findings"][0]
    assert f["confidence"] == "medium" and "env template" in f["message"]


def test_placeholders_and_docs(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {
        "README.md": "Set STRIPE_SECRET_KEY=%s\n" % ("sk_" + "live_" + "x" * 24),
        "src/a.ts": "const k = process.env.STRIPE_SECRET_KEY\n",
        "package-lock.json": json.dumps({"packages": {"": {"name": "x"}}}),
    })
    r = run_script("find_secrets.py", "--json", tmp_path)
    assert r.returncode == 0 and report(r)["findings"] == []


def test_test_paths_get_medium_confidence(tmp_path, write_tree):
    write_tree(tmp_path, {"tests/fixtures/keys.py": "K = '%s'\n" % live_key()})
    findings, warnings, meta = find_secrets.run(tmp_path)
    assert findings[0].confidence == "medium"


def test_info_only_exits_zero(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {"maps.ts": "const MAPS_KEY = '%s'\n" % ("AI" + "za" + tok("", 35))})
    r = run_script("find_secrets.py", "--json", tmp_path)
    assert r.returncode == 0
    assert [f["rule"] for f in report(r)["findings"]] == ["google-api-key"]


def test_utf8_paths_and_output(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {"\u015fifre/g\u00fcvenlik.js": "// \u00e7\u00f6z\u00fcm\nconst k = '%s'\n" % live_key()})
    r = run_script("find_secrets.py", tmp_path, env={"PYTHONIOENCODING": "cp1252"})
    assert r.returncode == 1, r.stderr
    assert "\u015fifre/g\u00fcvenlik.js:2" in r.stdout


def test_single_file_target(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {"a.js": "k='%s'\n" % live_key(), "b.js": "k='%s'\n" % live_key()})
    rep = report(run_script("find_secrets.py", "--json", tmp_path / "a.js"))
    assert [f["file"] for f in rep["findings"]] == ["a.js"]


def test_cli_errors_and_caps(tmp_path, write_tree, run_script):
    assert run_script("find_secrets.py", tmp_path / "missing").returncode == 2
    assert run_script("find_secrets.py", "--help").returncode == 0
    files = {"f%d.js" % i: "k='%s'\n" % ("sk_" + "live_" + tok("", 20 + i)) for i in range(6)}
    write_tree(tmp_path, files)
    out = tmp_path / "out" / "full.json"
    r = run_script("find_secrets.py", "--json", "--max-findings", "2", "--output", out, tmp_path)
    rep = report(r)
    assert len(rep["findings"]) == 2 and rep["summary"]["total"] == 6
    assert len(json.loads(out.read_text(encoding="utf-8"))["findings"]) == 6


def test_scan_text_api():
    findings, public = find_secrets.scan_text("a\nb = '%s'\n" % live_key(), "bundle.js", "bundle")
    assert [(f.rule, f.line, f.extra["source"]) for f in findings] == [("stripe-live-secret-key", 2, "bundle")]
    assert public == []


# --- build output ---------------------------------------------------------------------

@pytest.mark.parametrize("rel,kind", [
    ("dist/assets/index-abc.js", "build"),
    ("build/static/js/main.js", "build"),
    ("out/index.html", "build"),
    ("apps/web/dist/a.js", "build"),
    (".next/static/chunks/app/page-1.js", "served"),
    (".next/server/app/index.html", "served"),
    (".next/server/app/index.rsc", "served"),
    (".next/server/pages/about.json", "served"),
    (".next/server/chunks/123.js", None),
    (".next/server/app/page.js", None),
    ("public/build/assets/app.js", "served"),
    (".output/public/_nuxt/a.js", "served"),
    ("src/app.js", None),
])
def test_build_kind(rel, kind):
    assert find_secrets.build_kind(rel) == kind


def test_build_output_scan(tmp_path, write_tree, run_script):
    key = live_key()
    write_tree(tmp_path, {
        "src/main.ts": "export {}\n",
        "dist/assets/index.js": "var a=1;var k='%s';\n" % key,
        ".next/static/chunks/main.js": "x='%s'\n" % ("sk-" + "proj-" + tok("", 40)),
        ".next/server/app/index.html": "<script>k='%s'</script>\n" % ("gh" + "p_" + tok("", 36)),
        ".next/server/chunks/srv.js": "k='%s'\n" % ("sb_" + "secret_" + tok("", 30)),
        ".next/cache/x.js": "k='%s'\n" % ("sk_" + "test_" + tok()),
    })
    rep = report(run_script("find_secrets.py", "--json", tmp_path))
    assert rep["findings"] == []
    rep = report(run_script("find_secrets.py", "--json", "--build-output", tmp_path))
    got = {(f["file"], f["rule"]) for f in rep["findings"]}
    assert got == {
        ("dist/assets/index.js", "stripe-live-secret-key"),
        (".next/static/chunks/main.js", "openai-api-key"),
        (".next/server/app/index.html", "github-token"),
    }
    served = [f for f in rep["findings"] if f["file"].startswith(".next/static")][0]
    assert "served to browsers" in served["message"]


def test_build_output_missing_warns(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {"src/a.ts": "x"})
    r = run_script("find_secrets.py", "--json", "--build-output", tmp_path)
    assert r.returncode == 0
    assert any("no build output" in w for w in report(r)["warnings"])


# --- git ---------------------------------------------------------------------------------

@needs_git
def test_git_tracked_ignored_untracked(tmp_path, write_tree, run_script):
    repo = init_repo(tmp_path / "repo", tmp_path)
    write_tree(repo, {
        ".gitignore": ".env\n",
        ".env": "STRIPE_SECRET_KEY=%s\n" % live_key(),
        "config.js": "k='%s'\n" % ("sk-" + "proj-" + tok("", 40)),
    })
    git(repo, "add", ".gitignore", "config.js", tmp=tmp_path)
    git(repo, "commit", "-q", "-m", "init", tmp=tmp_path)
    write_tree(repo, {"new.js": "k='%s'\n" % ("gh" + "p_" + tok("", 36))})
    rep = report(run_script("find_secrets.py", "--json", repo))
    by_file = {f["file"]: f for f in rep["findings"]}
    assert by_file[".env"]["severity"] == "info" and by_file[".env"]["rule"] == "secret-in-ignored-file"
    assert "tracked by git" in by_file["config.js"]["message"]
    assert "does not ignore yet" in by_file["new.js"]["message"]


@needs_git
def test_git_history_finds_deleted_secret(tmp_path, write_tree, run_script):
    repo = init_repo(tmp_path / "repo", tmp_path)
    key = live_key()
    write_tree(repo, {"a.txt": "hello\n"})
    git(repo, "add", ".", tmp=tmp_path)
    git(repo, "commit", "-q", "-m", "one", tmp=tmp_path)
    write_tree(repo, {"src/pay.js": "line1\nline2\nconst k = '%s'\n" % key})
    git(repo, "add", ".", tmp=tmp_path)
    git(repo, "commit", "-q", "-m", "add key", tmp=tmp_path)
    first = git(repo, "rev-parse", "HEAD", tmp=tmp_path).strip()
    write_tree(repo, {"src/pay.js": "line1\nline2\nconst k = process.env.KEY\n", "src/other.js": "k='%s'\n" % key})
    git(repo, "add", ".", tmp=tmp_path)
    git(repo, "commit", "-q", "-m", "move key", tmp=tmp_path)
    (repo / "src" / "other.js").unlink()
    git(repo, "add", "-A", tmp=tmp_path)
    git(repo, "commit", "-q", "-m", "remove key", tmp=tmp_path)

    r = run_script("find_secrets.py", "--json", repo)
    assert r.returncode == 0 and report(r)["findings"] == []

    r = run_script("find_secrets.py", "--json", "--git-history", repo)
    assert r.returncode == 1
    assert key not in r.stdout
    rep = report(r)
    hist = [f for f in rep["findings"] if f["extra"]["source"] == "git-history"]
    assert len(hist) == 1
    f = hist[0]
    assert f["rule"] == "stripe-live-secret-key"
    assert f["file"] == "src/pay.js" and f["line"] == 3
    assert f["extra"]["commit"] == first
    assert f["extra"]["occurrences"] == 2
    assert "git history" in f["message"]


@needs_git
def test_git_history_from_subfolder(tmp_path, write_tree, run_script):
    repo = init_repo(tmp_path / "repo", tmp_path)
    write_tree(repo, {"web/src/a.js": "k='%s'\n" % live_key(), "api/b.js": "k='%s'\n" % ("gh" + "p_" + tok("", 36))})
    git(repo, "add", ".", tmp=tmp_path)
    git(repo, "commit", "-q", "-m", "x", tmp=tmp_path)
    rep = report(run_script("find_secrets.py", "--json", "--git-history", repo / "web"))
    hist = [(f["file"], f["rule"]) for f in rep["findings"] if f["extra"]["source"] == "git-history"]
    assert hist == [("src/a.js", "stripe-live-secret-key")]


def test_git_history_not_a_repo(tmp_path, write_tree, run_script):
    write_tree(tmp_path, {"a.txt": "x"})
    r = run_script("find_secrets.py", "--json", "--git-history", tmp_path)
    assert r.returncode == 0
    assert any("git" in w for w in report(r)["warnings"])


def test_git_missing(monkeypatch, tmp_path, write_tree):
    write_tree(tmp_path, {"a.txt": "x"})
    monkeypatch.setattr(find_secrets, "_git_exe", lambda: None)
    findings, warnings = find_secrets.scan_git_history(tmp_path)
    assert findings == [] and "not found" in warnings[0]
    tracked, ignored = find_secrets.git_file_status(tmp_path, ["a.txt"])
    assert tracked is None and ignored is None


# --- fakes, evidence, containers, env files ----------------------------------------------------

def _rules(findings):
    return [(f.file, f.rule, f.severity) for f in findings]


def test_comment_marked_fake_value(tmp_path, write_tree):
    secret = "whsec_" + tok("", 32)
    write_tree(tmp_path, {
        "tests/webhooks.test.ts": "const s = '%s' // dummy secret for the signature test\n" % secret,
        "lib/local-dev.ts": "// Throwaway value, not a real key.\nexport const S = '%s'\n" % secret[:-1] + "Z",
    })
    got = sorted(_rules(find_secrets.run(tmp_path)[0]))
    assert got == [("lib/local-dev.ts", "stripe-webhook-secret", "low"),
                   ("tests/webhooks.test.ts", "stripe-webhook-secret", "info")], got


def test_unmarked_value_in_test_file_keeps_its_severity(tmp_path, write_tree):
    write_tree(tmp_path, {"tests/pay.test.ts": "const k = '%s'\n" % live_key()})
    findings = find_secrets.run(tmp_path)[0]
    assert [(f.severity, f.confidence) for f in findings] == [("critical", "medium")]


def test_single_line_private_key_evidence_hides_the_body(tmp_path, write_tree):
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC" + tok("", 40)
    pem = "-----BEGIN " + "RSA PRIVATE KEY-----\n" + body + "\n" + body[::-1] + "\n-----END RSA PRIVATE KEY-----"
    write_tree(tmp_path, {"lib/keys.ts": "export const privateKey = '%s'\n" % pem,
                          "infra/main.tf": "  private_key = \"%s\"\n" % pem})
    findings = find_secrets.run(tmp_path)[0]
    assert sorted(f.file for f in findings) == ["infra/main.tf", "lib/keys.ts"]
    for f in findings:
        assert f.rule == "private-key"
        assert not re.search(r"[A-Za-z0-9+/=]{12,}", f.evidence), f.evidence


def test_keystore_files_reported_by_name(tmp_path, write_tree):
    write_tree(tmp_path, {
        "android/app/release.keystore": b"\xfe\xed\xfe\xed\x00\x00\x00\x02",
        "android/app/debug.keystore": b"\xfe\xed\xfe\xed\x00\x00\x00\x02",
        "certs/client.p12": b"0\x82\x01\x00",
        "node_modules/pkg/test.p12": b"0\x82\x01\x00",
    })
    got = sorted(_rules(find_secrets.run(tmp_path)[0]))
    assert got == [("android/app/release.keystore", "private-key-file", "high"),
                   ("certs/client.p12", "private-key-file", "high")], got


def test_gradle_and_create_user_passwords_found_through_scan(tmp_path, write_tree):
    pw = tok("", 14)
    write_tree(tmp_path, {
        "android/app/build.gradle": "signingConfigs {\n  release {\n    storePassword \"%s\"\n  }\n}\n" % pw,
        "scripts/create-admin.cjs": "const password = '%s'\nawait admin.auth().createUser({ email, password })\n" % pw,
    })
    got = sorted(_rules(find_secrets.run(tmp_path)[0]))
    assert got == [("android/app/build.gradle", "gradle-signing-password", "high"),
                   ("scripts/create-admin.cjs", "hardcoded-login-password", "high")], got


def test_demo_key_in_a_test_env_file_is_info(tmp_path, write_tree):
    demo = jwt({"role": "service_role", "iss": "supabase-demo"})
    write_tree(tmp_path, {".env.e2e": "SERVICE_ROLE_KEY=%s\n" % demo, ".gitignore": ".env*\n"})
    got = _rules(find_secrets.run(tmp_path)[0])
    assert got == [(".env.e2e", "supabase-local-demo-jwt", "info")], got


def test_ignored_non_env_file_without_git_is_info(tmp_path, write_tree):
    write_tree(tmp_path, {".gitignore": "secrets/\n*.local.json\n", "secrets/keys.json": "{\"k\": \"%s\"}\n" % live_key(),
                          "config.local.json": "{\"k\": \"%s\"}\n" % ("gh" + "p_" + tok("", 36))})
    got = sorted(_rules(find_secrets.run(tmp_path)[0]))
    assert got == [("config.local.json", "secret-in-ignored-file", "info"),
                   ("secrets/keys.json", "secret-in-ignored-file", "info")], got


def test_env_file_without_secrets_and_without_gitignore_is_a_note(tmp_path, write_tree):
    write_tree(tmp_path, {".env": "VITE_SUPABASE_URL=https://abcdefgh.supabase.co\n"})
    got = _rules(find_secrets.run(tmp_path)[0])
    assert got == [(".env", "env-file-tracked", "info")], got
    write_tree(tmp_path, {".gitignore": ".env\n"})
    assert find_secrets.run(tmp_path)[0] == []


def test_translation_catalog_scan_is_fast(tmp_path, write_tree):
    import time
    po = "".join('msgid "Line %d of the settings screen"\nmsgstr "Zeile %d"\n\n' % (i, i) for i in range(20000))
    write_tree(tmp_path, {"locales/de/messages.po": po})
    t0 = time.time()
    assert find_secrets.run(tmp_path)[0] == []
    assert time.time() - t0 < 5


@needs_git
def test_tracked_env_file_note(tmp_path, write_tree):
    repo = init_repo(tmp_path / "repo", tmp_path)
    write_tree(repo, {".env": "VITE_SUPABASE_URL=https://abcdefgh.supabase.co\n", "app.js": "x\n"})
    git(repo, "add", ".", tmp=tmp_path)
    git(repo, "commit", "-q", "-m", "init", tmp=tmp_path)
    findings = find_secrets.run(repo)[0]
    assert [(f.file, f.rule, f.severity, f.extra.get("git")) for f in findings] == [
        (".env", "env-file-tracked", "info", "tracked")]
    assert "git rm --cached .env" in findings[0].message


@needs_git
def test_shallow_clone_warns(tmp_path, write_tree):
    src = init_repo(tmp_path / "src", tmp_path)
    for i in range(3):
        write_tree(src, {"f%d.txt" % i: "x%d\n" % i})
        git(src, "add", ".", tmp=tmp_path)
        git(src, "commit", "-q", "-m", "c%d" % i, tmp=tmp_path)
    git(tmp_path, "clone", "-q", "--depth", "1", "file://" + src.as_posix(), "shallow", tmp=tmp_path)
    _findings, warnings = find_secrets.scan_git_history(tmp_path / "shallow")
    assert any("shallow" in w and "--unshallow" in w for w in warnings), warnings
    _findings, warnings = find_secrets.scan_git_history(src)
    assert not any("shallow" in w for w in warnings)
