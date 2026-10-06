import ast
import io
import json
import os
from pathlib import Path

import pytest

import _wardcore as wc
from conftest import SCRIPTS_DIR


# --- exit codes and constants ------------------------------------------------

def test_exit_codes():
    assert (wc.EXIT_OK, wc.EXIT_FINDINGS, wc.EXIT_ERROR, wc.EXIT_REFUSED) == (0, 1, 2, 3)
    assert wc.SEVERITIES == ("critical", "high", "medium", "low", "info")


def test_setup_io_does_not_crash_under_capture():
    wc.setup_io()


def test_all_scripts_parse_as_python39():
    for p in sorted(SCRIPTS_DIR.glob("*.py")):
        ast.parse(p.read_text(encoding="utf-8"), filename=str(p), feature_version=(3, 9))


def test_scripts_have_no_dash_characters_or_emoji():
    bad = ("\u2014", "\u2013")
    for p in sorted(SCRIPTS_DIR.glob("*.py")):
        text = p.read_text(encoding="utf-8")
        for ch in bad:
            assert ch not in text, "%s contains a long dash" % p.name
        assert not any(0x2600 <= ord(c) <= 0x27BF or ord(c) >= 0x1F000 for c in text), p.name


# --- paths --------------------------------------------------------------------

def test_convert_msys_path():
    assert wc.convert_msys_path("/c/Users/me/app", windows=True) == "C:/Users/me/app"
    assert wc.convert_msys_path("/d", windows=True) == "D:/"
    assert wc.convert_msys_path("/cygdrive/e/x", windows=True) == "E:/x"
    assert wc.convert_msys_path("/mnt/c/x", windows=True) == "C:/x"
    assert wc.convert_msys_path("/usr/local", windows=True) == "/usr/local"
    assert wc.convert_msys_path("/c/Users/me", windows=False) == "/c/Users/me"
    assert wc.convert_msys_path("C:\\Users\\me", windows=True) == "C:\\Users\\me"


def test_norm_resolves(tmp_path):
    (tmp_path / "a b").mkdir()
    p = wc.norm(str(tmp_path / "a b"))
    assert p.is_absolute() and p.exists()
    if os.name == "nt":
        # backslash is a separator only on Windows; on POSIX it is a filename character
        assert wc.norm(str(tmp_path).replace("/", "\\")) == tmp_path.resolve()
    assert wc.norm('"%s"' % tmp_path) == tmp_path.resolve()
    assert wc.norm(None) == Path(".").resolve()


def test_rel_posix(tmp_path):
    f = tmp_path / "x" / "y.txt"
    assert wc.rel_posix(f, tmp_path) == "x/y.txt"


# --- walking and reading --------------------------------------------------------

def test_iter_text_files_skips(tmp_path, write_tree):
    write_tree(tmp_path, {
        "src/app.js": "ok",
        "src/build/route.js": "kept: build under src is a source folder",
        "node_modules/lib/index.js": "skip",
        ".git/config": "skip",
        "dist/assets/app.js": "build",
        ".next/static/chunk.js": "build",
        "public/build/app.js": "build",
        ".env": "A=1",
        ".env.example": "A=",
        "package-lock.json": "{}",
        "venv2/pyvenv.cfg": "home = x",
        "venv2/lib/x.py": "skip",
    })
    (tmp_path / "img.png").write_bytes(b"\x89PNG\r\n")
    (tmp_path / "blob.dat").write_bytes(b"abc\x00def")
    rels = [t.rel for t in wc.iter_text_files(tmp_path)]
    assert "src/app.js" in rels
    assert "src/build/route.js" in rels
    assert ".env" in rels
    assert "package-lock.json" in rels
    for gone in ("node_modules/lib/index.js", ".git/config", "dist/assets/app.js", ".next/static/chunk.js",
                 "public/build/app.js", ".env.example", "img.png", "blob.dat", "venv2/lib/x.py"):
        assert gone not in rels
    with_build = [t.rel for t in wc.iter_text_files(tmp_path, want_build=True)]
    assert "dist/assets/app.js" in with_build and ".next/static/chunk.js" in with_build
    with_examples = [t.rel for t in wc.iter_text_files(tmp_path, skip_examples=False)]
    assert ".env.example" in with_examples


def test_iter_text_files_skips_installed_ward_skills(tmp_path, write_tree):
    fm = "---\nname: %s\ndescription: \"x\"\n---\nbody\n"
    write_tree(tmp_path, {
        "app/page.tsx": "ok",
        ".claude/skills/preflight-audit/SKILL.md": fm % "preflight-audit",
        ".claude/skills/preflight-audit/scripts/_wardcore.py": "x = 1\n",
        ".agents/skills/secure-by-default/SKILL.md": fm % "secure-by-default",
        ".agents/skills/secure-by-default/references/secrets.md": "# s\n",
        # same name but not ward (no _wardcore.py): kept
        "tools/live-exposure-check/SKILL.md": fm % "live-exposure-check",
        "tools/live-exposure-check/scripts/check.py": "y = 2\n",
        # another skill: kept
        ".claude/skills/other/SKILL.md": fm % "other",
        ".claude/skills/other/scripts/run.py": "z = 3\n",
    })
    rels = [t.rel for t in wc.iter_text_files(tmp_path)]
    assert "app/page.tsx" in rels
    assert not any(r.startswith((".claude/skills/preflight-audit/", ".agents/skills/secure-by-default/"))
                   for r in rels), rels
    assert "tools/live-exposure-check/scripts/check.py" in rels
    assert ".claude/skills/other/scripts/run.py" in rels
    # scanning a ward skill folder directly still works
    direct = [t.rel for t in wc.iter_text_files(tmp_path / ".claude" / "skills" / "preflight-audit")]
    assert "scripts/_wardcore.py" in direct


def test_iter_text_files_single_file_and_utf8(tmp_path, write_tree):
    write_tree(tmp_path, {"\u015fifre.txt": "g\u00fcvenlik \u0131\u011f"})
    files = list(wc.iter_text_files(tmp_path / "\u015fifre.txt"))
    assert len(files) == 1
    assert files[0].rel == "\u015fifre.txt"
    assert "g\u00fcvenlik" in files[0].text


def test_read_text_bom_and_size(tmp_path):
    p = tmp_path / "a.txt"
    p.write_bytes(b"\xef\xbb\xbfhello")
    assert wc.read_text(p) == "hello"
    assert wc.read_text(p, max_bytes=2) is None
    assert wc.read_text(tmp_path / "missing") is None


def test_file_kind_helpers():
    assert wc.is_lockfile("a/b/yarn.lock")
    assert not wc.is_lockfile("yarn.lock.txt")
    assert wc.is_env_file(".env") and wc.is_env_file("cfg/.env.production") and wc.is_env_file("prod.env")
    assert not wc.is_env_file("environment.ts")
    assert wc.is_example_file(".env.example") and wc.is_example_file(".env.local.sample")
    assert wc.is_example_file(".env.template") and not wc.is_example_file(".env.local")
    assert wc.is_build_path("dist/a.js") and wc.is_build_path("web/.next/static/x.js")
    assert not wc.is_build_path("app/build/page.tsx")


# --- globs -----------------------------------------------------------------------

@pytest.mark.parametrize("rel,pattern,expected", [
    ("a/b/c.py", "*.py", True),
    ("c.py", "*.py", True),
    ("a/settings.py", "settings.py", True),
    ("proj/settings/base.py", "settings/*.py", False),
    ("proj/settings/base.py", "**/settings/*.py", True),
    ("settings/base.py", "**/settings/*.py", True),
    ("app/api/x/route.ts", "app/**/route.ts", True),
    ("app/route.ts", "app/**/route.ts", True),
    ("src/app/route.ts", "app/**/route.ts", False),
    ("src/a.tsx", "*.{ts,tsx}", True),
    ("src/a.js", "*.{ts,tsx}", False),
    ("a/b.py", "a/?.py", True),
    ("a/bc.py", "a/?.py", False),
    ("x.min.js", "*.[mc]js", False),
    ("x.mjs", "*.[mc]js", True),
])
def test_glob_match(rel, pattern, expected):
    assert wc.glob_match(rel, pattern) is expected


# --- masking and redaction ----------------------------------------------------------

def test_mask_never_reveals_value():
    value = "sk_" + "live_" + "Q7wE9rT2yU4iO6pA8sD1fG3h"
    m = wc.mask(value)
    assert value not in m
    assert m.startswith("sk_l") and m.endswith("fG3h")
    assert "[24 chars]" in m
    assert wc.mask("abcdefghijklmnop") == "ab[12 chars]op"
    assert wc.mask("abcdefghijklmn") == "[14 chars]"  # short values show only their length
    assert wc.mask("hunter22") == "[8 chars]"
    assert wc.mask("") == "[0 chars]"


def test_redact_masks_url_credentials_but_not_placeholders():
    pw = "Zq" + "8rTw" + "2x"
    out = wc.redact("DATABASE_URL=postgres://appuser:%s@db.internal:5432/app" % pw)
    assert pw not in out and "postgres://appuser:[8 chars]@db.internal:5432/app" in out
    for keep in ("postgres://${DB_USER}:${DB_PASS}@db/app", "mysql://root:<password>@db/app",
                 "postgresql://postgres:[password]@db.ref.supabase.co:5432/postgres", "https://example.com/a:b@c"):
        assert wc.redact(keep) == keep


def test_redact_masks_assignments_and_tokens():
    out = wc.redact("session({ secret: 'keyboard cat' })")
    assert "keyboard cat" not in out
    out = wc.redact("JWT_SECRET=mysupersecretvalue")
    assert "mysupersecretvalue" not in out
    tok = "Ab12Cd34Ef56Gh78Ij90Kl12Mn34"
    assert tok not in wc.redact("token is " + tok)
    assert wc.redact("const key = process.env.STRIPE_SECRET_KEY") == "const key = process.env.STRIPE_SECRET_KEY"
    assert wc.redact("SECRET_KEY = settings.BASE_SECRET") == "SECRET_KEY = settings.BASE_SECRET"
    assert wc.redact("import Thing from './components/AuthProviderWrapper'") == \
        "import Thing from './components/AuthProviderWrapper'"
    assert "if (password === 'hunter22')" != wc.redact("if (password === 'hunter22')")


def test_clip_long_line():
    line = "a" * 500 + "NEEDLE" + "b" * 500
    out = wc.clip(line, 500, 506, 100)
    assert "NEEDLE" in out and len(out) <= 110


# --- findings and emit ------------------------------------------------------------

def _f(sev, rule="r", file="a.py", line=1):
    return wc.Finding(skill="s", klass="k", severity=sev, file=file, line=line, rule=rule,
                      message="msg " + sev, evidence="ev", fix_ref="x.md", confidence="high")


def test_finding_defaults():
    f = _f("high")
    assert f.id == "r@a.py:1"
    assert wc.Finding(severity="bogus").severity == "medium"
    d = f.to_dict()
    assert set(d) >= {"id", "skill", "klass", "severity", "file", "line", "rule", "message",
                      "evidence", "fix_ref", "confidence", "needs_confirmation"}
    assert "extra" not in d
    g = wc.Finding(rule="x", file="f", line=2, extra={"commit": "abcdef1234567890"})
    assert "commit abcdef123456" in g.where
    assert g.to_dict()["extra"]["commit"]


def test_exit_code_for():
    assert wc.exit_code_for([]) == 0
    assert wc.exit_code_for([_f("info")]) == 0
    assert wc.exit_code_for([_f("info"), _f("low")]) == 1


def test_emit_human():
    buf = io.StringIO()
    code = wc.emit([_f("low", line=3), _f("critical")], target="T", script="scan_app",
                   meta={"stacks": ["django"], "empty": []}, stream=buf)
    out = buf.getvalue()
    assert code == 1
    assert "2 findings: 1 critical, 1 low" in out
    assert out.index("CRITICAL") < out.index("LOW")
    assert "stacks: django" in out and "empty" not in out
    assert "r  a.py:1  msg critical" in out


def test_emit_empty_human():
    buf = io.StringIO()
    assert wc.emit([], target="T", stream=buf) == 0
    assert "No findings." in buf.getvalue()


def test_emit_json_cap_and_output(tmp_path):
    findings = [_f("medium", line=i) for i in range(1, 11)]
    buf = io.StringIO()
    out_file = tmp_path / "sub" / "report.json"
    code = wc.emit(findings, as_json=True, out_file=str(out_file), max_findings=3, target="T",
                   script="x", warnings=["w1"], stream=buf)
    assert code == 1
    rep = json.loads(buf.getvalue())
    assert rep["tool"] == "ward" and rep["script"] == "x" and rep["target"] == "T"
    assert len(rep["findings"]) == 3
    assert rep["summary"]["total"] == 10 and rep["summary"]["shown"] == 3
    assert rep["summary"]["medium"] == 10
    assert rep["warnings"] == ["w1"]
    full = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(full["findings"]) == 10


def test_emit_human_cap_message():
    buf = io.StringIO()
    wc.emit([_f("high", line=i) for i in range(5)], max_findings=2, stream=buf)
    assert "showing 2 of 5" in buf.getvalue()


# --- host gate -----------------------------------------------------------------------

@pytest.mark.parametrize("url,flag,ok", [
    ("http://localhost:3000", None, True),
    ("http://127.0.0.1:8000/x", None, True),
    ("http://[::1]:8080/", None, True),
    ("https://app.localhost", None, True),
    ("http://shop.test/a", None, True),
    ("localhost:3000", None, True),
    ("http://LOCALHOST.", None, True),
    ("https://example.com", None, False),
    ("https://example.com", "example.com", True),
    ("https://example.com", "https://example.com/", True),
    ("https://example.com:8443/x", "EXAMPLE.com:8443", True),
    ("https://staging.example.com", "example.com", False),
    ("https://example.com", ["other.com", "example.com"], True),
    ("http://localhost@evil.example", None, False),
    ("http://evil.example#@localhost", None, False),
    ("http://localhost.evil.example", None, False),
    ("http://127.0.0.1.nip.io", None, False),
    ("http://evil.test.example", None, False),
    ("file:///etc/passwd", None, False),
    ("", None, False),
])
def test_require_owned_host(url, flag, ok):
    host, allowed = wc.require_owned_host(url, flag)
    assert allowed is ok


def test_refusal_message_names_flag():
    host, ok = wc.require_owned_host("https://example.com")
    assert host == "example.com" and not ok
    assert "--i-own-this example.com" in wc.refusal_message(host)


# --- small helpers -----------------------------------------------------------------

def test_comment_lines():
    assert wc.is_comment_line("  # DEBUG = True", "settings.py")
    assert wc.is_comment_line("// x", "a.ts")
    assert wc.is_comment_line(" * x", "a.ts")
    assert wc.is_comment_line("-- x", "a.sql")
    assert wc.is_comment_line("# APP_DEBUG=true", ".env.production")
    assert not wc.is_comment_line("DEBUG = True", "settings.py")
    assert not wc.is_comment_line("# heading", "notes.unknownext")


def test_parse_version():
    assert wc.parse_version("^14.2.3") == (14, 2, 3)
    assert wc.parse_version("15") == (15,)
    assert wc.parse_version("latest") is None
    assert wc.version_lt("14.2.24", "14.2.25") is True
    assert wc.version_lt("14.2.25", "14.2.25") is False
    assert wc.version_lt("15", "14.2.25") is False
    assert wc.version_lt(None, "1.0") is None


def test_validate_rule():
    good = wc.Rule(id="x-y", skill="s", klass="k", severity="high", stacks=["*"], file_globs=["*.py"],
                   pattern="a", message="m")
    assert wc.validate_rule(good) == []
    bad = wc.Rule(id="X Y", skill="s", klass="k", severity="huge", stacks=[], file_globs=[], message="")
    errs = " ".join(wc.validate_rule(bad))
    for word in ("bad id", "severity", "stacks", "file_globs", "pattern", "message"):
        assert word in errs
    once = wc.Rule(id="o", skill="s", klass="k", severity="low", stacks=["*"], file_globs=[], once=True,
                   check=lambda p, t, c: [], message="m")
    assert wc.validate_rule(once) == []
    assert wc.validate_rule("nope")


def test_rule_applies_and_wants_file():
    r = wc.Rule(id="r", skill="s", klass="k", severity="low", stacks=["nextjs-app+supabase", "expo"],
                file_globs=["*.ts"], exclude_globs=["**/tests/**"], pattern="x", message="m")
    assert r.applies_to({"nextjs-app", "supabase"})
    assert not r.applies_to({"nextjs-app"})
    assert r.applies_to({"expo"})
    assert r.applies_to(set(), force_all=True)
    assert r.wants_file("src/a.ts") and not r.wants_file("src/tests/a.ts") and not r.wants_file("a.js")


# --- scan context --------------------------------------------------------------------

def test_scan_context_read_memo_and_lines(tmp_path, write_tree):
    write_tree(tmp_path, {"a.txt": "one\r\ntwo\nthree", "b/c.js": "x"})
    ctx = wc.ScanContext(tmp_path)
    assert ctx.files == ["a.txt", "b/c.js"]
    assert ctx.lines("a.txt") == ["one", "two", "three"]
    assert ctx.line_of("a.txt", 0) == 1
    assert ctx.line_of("a.txt", ctx.read("a.txt").index("three")) == 3
    assert ctx.window("a.txt", 2, 1, 0) == "one\ntwo"
    assert ctx.read("missing.txt") == ""
    assert ctx.read("../outside.txt") == ""
    calls = []
    assert ctx.memo("k", lambda: calls.append(1) or 42) == 42
    assert ctx.memo("k", lambda: calls.append(1) or 43) == 42
    assert calls == [1]
    assert ctx.glob("*.js") == ["b/c.js"]
    assert ctx.exists("b") and not ctx.exists("nope")
    assert ctx.json("a.txt") is None


def test_installed_version_sources(tmp_path, write_tree):
    write_tree(tmp_path, {"package-lock.json": json.dumps({"packages": {"node_modules/next": {"version": "14.2.3"}}})})
    ctx = wc.ScanContext(tmp_path)
    ctx.deps = {"next": "^14.0.0"}
    assert ctx.installed_version("next") == "14.2.3"
    assert ctx.next_version == "14.2.3"

    other = tmp_path / "y"
    write_tree(other, {"yarn.lock": '"next@^13.0.0":\n  version "13.5.1"\n  resolved "x"\n'})
    ctx2 = wc.ScanContext(other)
    ctx2.deps = {"next": "^13.0.0"}
    assert ctx2.installed_version("next") == "13.5.1"

    third = tmp_path / "p"
    write_tree(third, {"pnpm-lock.yaml": "packages:\n  /@next/env@15.0.0:\n    x\n  /next@15.1.0(react@19):\n    y\n"})
    ctx3 = wc.ScanContext(third)
    ctx3.deps = {"next": "15"}
    assert ctx3.installed_version("next") == "15.1.0"

    fourth = tmp_path / "q"
    fourth.mkdir()
    ctx4 = wc.ScanContext(fourth)
    ctx4.deps = {"next": "^12.1.0"}
    assert ctx4.installed_version("next") == "^12.1.0"
    ctx4.deps = {}
    assert ctx4.next_version is None


def test_minified_detection(tmp_path, write_tree):
    write_tree(tmp_path, {"a.min.js": "x", "b.js": "var a=1;" * 2000, "c.js": "a\nb\n"})
    ctx = wc.ScanContext(tmp_path)
    assert ctx.is_minified("a.min.js")
    assert ctx.is_minified("b.js")
    assert not ctx.is_minified("c.js")


# --- stateful comment view ------------------------------------------------------------

def test_code_view_blanks_block_comments_and_keeps_offsets():
    text = ("const a = 1;\n"
            "/*\n"
            "app.use(csrf())\n"
            "*/\n"
            "const url = 'https://x.example/*not a comment*/'; // tail BAD\n"
            "const re = /\\/*foo/; const b = 2;\n")
    view = wc.code_view(text, "server.js")
    assert len(view) == len(text) and view.count("\n") == text.count("\n")
    assert "csrf" not in view
    assert "'https://x.example/*not a comment*/'" in view
    assert "tail BAD" not in view
    assert "const b = 2;" in view  # a regex literal holding /* does not open a comment


def test_code_view_other_languages():
    py = 's = "# not a comment"  # real comment\nx = 1\n'
    v = wc.code_view(py, "a.py")
    assert '"# not a comment"' in v and "real comment" not in v
    php = ("<?php\n#[Route('/x')]\nfunction a() {} # gone\n/* block\n$x = 1; */\n$y = 2; // tail\n?>\n"
           "<p>it is // html</p>\n")
    v = wc.code_view(php, "a.php")
    assert "#[Route('/x')]" in v and "gone" not in v and "$x = 1" not in v and "$y = 2;" in v
    assert "tail" not in v and "<p>it is // html</p>" in v  # outside <?php ?> is left alone
    blade = "{{-- {!! $old !!} --}}\n{!! $new !!}\n"
    v = wc.code_view(blade, "views/a.blade.php")
    assert "$old" not in v and "{!! $new !!}" in v
    sql = "select '--keep' from t; -- drop\n/* gone */ select 1;\n"
    v = wc.code_view(sql, "a.sql")
    assert "'--keep'" in v and "drop" not in v and "gone" not in v
    # hash-style config files are left to the line-based check
    assert wc.code_view("url: http://x#frag  # c\n", "a.yml") == "url: http://x#frag  # c\n"


def test_scan_context_code_lines_and_in_comment(tmp_path, write_tree):
    write_tree(tmp_path, {"a.ts": "ok()\n/* one\n   two BAD */\nreal() // BAD\n"})
    ctx = wc.ScanContext(tmp_path)
    lines = ctx.code_lines("a.ts")
    assert lines[0] == "ok()" and "BAD" not in lines[1] + lines[2] + lines[3]
    assert lines[3].strip() == "real()"
    text = ctx.read("a.ts")
    assert ctx.in_comment("a.ts", text.index("two"))
    assert not ctx.in_comment("a.ts", text.index("real"))
    assert ctx.in_comment("a.ts", text.rindex("BAD"))


def test_match_any_mixed_globs():
    pats = ["*.py", "app/**/route.ts", "settings.py"]
    assert wc.match_any("x/y.py", pats)
    assert wc.match_any("app/api/route.ts", tuple(pats))
    assert not wc.match_any("src/app/route.ts", pats)
    assert not wc.match_any("a.js", [])
    assert wc.match_any("deep/settings.py", ("settings.py",))


# --- per-rule cap, compact JSON, ignored -------------------------------------------------

def test_select_shown_per_rule_and_report():
    noisy = [_f("high", rule="noisy", line=i) for i in range(1, 30)]
    rare = [_f("medium", rule="rare", line=1)]
    ordered = wc.sort_findings(noisy + rare)
    shown = wc.select_shown(ordered, 40, per_rule=5)
    assert [f.rule for f in shown].count("noisy") == 5 and "rare" in [f.rule for f in shown]
    rep = wc.build_report(ordered, shown=40, per_rule=5, compact=True)
    assert rep["summary"]["total"] == 30 and rep["summary"]["shown"] == 6
    assert rep["summary"]["by_rule"] == {"noisy": 29, "rare": 1}
    assert rep["summary"]["capped_rules"]["noisy"] == {"total": 29, "shown": 5}
    assert "id" not in rep["findings"][0] and "skill" not in rep["findings"][0]
    assert rep["findings"][0]["rule"] == "noisy"


def test_emit_per_rule_human_and_ignored():
    buf = io.StringIO()
    ign = _f("low", rule="fp", line=9)
    ign.extra["ignore_reason"] = "reviewed"
    code = wc.emit([_f("high", rule="noisy", line=i) for i in range(1, 10)], max_findings=40, per_rule=3,
                   ignored=[ign], stream=buf)
    out = buf.getvalue()
    assert code == 1
    assert out.count("noisy  a.py") == 3
    assert "noisy 9 (3 shown)" in out and "Ignored (recorded false positives): 1" in out
    buf = io.StringIO()
    assert wc.emit([], ignored=[ign], stream=buf, as_json=True) == 0
    rep = json.loads(buf.getvalue())
    assert rep["summary"]["ignored"] == 1 and rep["ignored"] == ["fp@a.py:9  # reviewed"]


def test_emit_exit_code_override():
    assert wc.emit([], stream=io.StringIO(), exit_code=wc.EXIT_ERROR) == wc.EXIT_ERROR


def test_finding_compact_dict():
    d = _f("high").to_dict(compact=True)
    assert "id" not in d and "skill" not in d and d["rule"] == "r"
    assert "id" in _f("high").to_dict()


def test_rule_anchors_must_be_a_list():
    r = wc.Rule(id="x", skill="s", klass="k", severity="low", stacks=["*"], file_globs=["*.py"],
                pattern="a", message="m", anchors="abc")
    assert any("anchors" in e for e in wc.validate_rule(r))


# --- client classification in monorepos -------------------------------------------------

def _ctx_with_stacks(tmp_path, write_tree, files):
    import scan_app
    write_tree(tmp_path, files)
    ctx = wc.ScanContext(tmp_path)
    scan_app.detect_stacks(ctx)
    return ctx


def test_client_files_expo_app_with_sibling_express_server(tmp_path, write_tree):
    ctx = _ctx_with_stacks(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"expo": "51", "react-native": "0.74"}}),
        "app/(tabs)/index.tsx": "export default function Home() {}",
        "src/lib/api.ts": "export const get = 1",
        "link/package.json": json.dumps({"dependencies": {"express": "4", "pg": "8"}}),
        "link/src/index.ts": "const app = express(); app.listen(3000)",
        "link/src/routes/create.ts": "export function create(req, res) {}",
        "og/package.json": json.dumps({"dependencies": {"express": "4", "react": "18", "satori": "0.10"}}),
        "og/src/index.ts": "app.get('/x', render)",
        "shared/util.ts": "export const x = 1",
    })
    client = set(ctx.client_files)
    assert {"app/(tabs)/index.tsx", "src/lib/api.ts", "shared/util.ts"} <= client
    for server in ("link/src/index.ts", "link/src/routes/create.ts", "og/src/index.ts"):
        assert server not in client, server


def test_client_files_server_roots_inside_packages_and_nested(tmp_path, write_tree):
    ctx = _ctx_with_stacks(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"expo": "51"}}),
        "examples/maps/supabase/functions/private/index.ts": "Deno.serve(() => new Response('x'))",
        "apps/web/package.json": json.dumps({"dependencies": {"react": "18"}, "devDependencies": {"vite": "5"}}),
        "apps/web/src/App.tsx": "export default function App() {}",
        "apps/web/supabase/functions/hook/index.ts": "Deno.serve(() => new Response('x'))",
        "apps/web/scripts/seed.ts": "await seed()",
    })
    client = set(ctx.client_files)
    assert "apps/web/src/App.tsx" in client
    for server in ("examples/maps/supabase/functions/private/index.ts",
                   "apps/web/supabase/functions/hook/index.ts", "apps/web/scripts/seed.ts"):
        assert server not in client, server


TS_MIDDLEWARE = (
    "import { createMiddleware } from '@tanstack/react-start'\n"
    "export const requireAuth = createMiddleware({ type: 'function' }).server(async ({ next }) => {\n"
    "  const { data } = await client.auth.getClaims(token)\n"
    "  return next({ context: { userId: data.claims.sub } })\n"
    "})\n"
    "export const logRequests = createMiddleware().server(async ({ next }) => next())\n")
TS_FUNCTIONS = (
    "import { createServerFn } from '@tanstack/react-start'\n"
    "export const listNotes = createServerFn({ method: 'POST' })\n"
    "  .middleware([requireAuth])\n"
    "  .handler(async ({ data, context }) => db.notes(context.userId))\n"
    "export const openFn = createServerFn({ method: 'GET' })\n"
    "  .middleware([logRequests])\n"
    "  .handler(async ({ data }) => fetch(data.url))\n")
TS_ROUTE = (
    "import { createFileRoute } from '@tanstack/react-router'\n"
    "export const Route = createFileRoute('/api/public/hook')({\n"
    "  server: { handlers: {\n"
    "    POST: async ({ request }) => Response.json({ ok: true }),\n"
    "    GET: async () => new Response('ok'),\n"
    "  } },\n"
    "})\n")


def test_tanstack_start_helpers(tmp_path, write_tree):
    ctx = _ctx_with_stacks(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"@tanstack/react-start": "1", "react": "19"},
                                    "devDependencies": {"vite": "7"}}),
        "src/integrations/auth-middleware.ts": TS_MIDDLEWARE,
        "src/lib/notes.functions.ts": TS_FUNCTIONS,
        "src/routes/api/public/hook.ts": TS_ROUTE,
        "src/routes/index.tsx": "export const Route = createFileRoute('/')({ component: Home })",
        "src/lib/db.server.ts": "export const db = 1",
        "src/components/Card.tsx": "export function Card() {}",
    })
    assert "tanstack-start" in ctx.stacks and "vite-spa" not in ctx.stacks
    assert ctx.tanstack_kind("src/lib/notes.functions.ts") == "functions"
    assert ctx.tanstack_kind("src/routes/api/public/hook.ts") == "route-handlers"
    assert ctx.tanstack_kind("src/lib/db.server.ts") == "server"
    assert ctx.tanstack_kind("src/routes/index.tsx") == "client"
    assert ctx.tanstack_auth_middlewares() == {"requireAuth"}
    got = {f["name"]: f for f in ctx.tanstack_server_fns("src/lib/notes.functions.ts")}
    assert got["listNotes"]["auth"] is True and got["listNotes"]["method"] == "POST"
    assert got["openFn"]["auth"] is False and got["openFn"]["middleware"] == ["logRequests"]
    assert got["openFn"]["line"] == 5 and got["openFn"]["handler_offset"] > 0
    assert ctx.tanstack_route_handlers("src/routes/api/public/hook.ts") == [("POST", 4), ("GET", 5)]
    client = set(ctx.client_files)
    assert {"src/routes/index.tsx", "src/components/Card.tsx"} <= client
    for server in ("src/lib/notes.functions.ts", "src/routes/api/public/hook.ts", "src/lib/db.server.ts",
                   "src/integrations/auth-middleware.ts"):
        assert server not in client, server
