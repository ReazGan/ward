import json
import sys
import types

import pytest

import _wardcore as wc
import gen_rules_md
import scan_app
from _wardcore import Hit, Rule


def _rule(**kw):
    base = dict(id="t-rule", skill="test", klass="test class", severity="medium", stacks=["*"],
                file_globs=["*.py"], pattern=r"BAD", message="bad thing")
    base.update(kw)
    return Rule(**base)


def _ids(result):
    return [(f.rule, f.file, f.line) for f in result.findings]


# --- stack detection -------------------------------------------------------------

NEXT_PKG = json.dumps({"dependencies": {"next": "14.1.0", "react": "18.2.0", "@supabase/supabase-js": "2"}})


@pytest.mark.parametrize("files,expected,absent", [
    ({"package.json": NEXT_PKG, "app/layout.tsx": "x", "app/page.tsx": "x"},
     {"node", "nextjs", "nextjs-app", "supabase"}, {"nextjs-pages", "react-vite"}),
    ({"package.json": json.dumps({"dependencies": {"next": "12.3.0"}}), "pages/index.js": "x"},
     {"nextjs-pages"}, {"nextjs-app"}),
    ({"package.json": json.dumps({"dependencies": {"next": "15.0.0"}})}, {"nextjs-app"}, {"nextjs-pages"}),
    ({"package.json": json.dumps({"dependencies": {"react": "18", "react-dom": "18"},
                                  "devDependencies": {"vite": "5"}})},
     {"react-vite", "vite-spa"}, {"nextjs"}),
    ({"package.json": json.dumps({"dependencies": {"vue": "3"}, "devDependencies": {"vite": "5"}})},
     {"vite-spa"}, {"react-vite"}),
    ({"package.json": json.dumps({"dependencies": {"react-scripts": "5"}})}, {"cra"}, set()),
    ({"package.json": json.dumps({"dependencies": {"express": "4", "stripe": "14", "openai": "4"}})},
     {"express", "node", "stripe", "llm"}, set()),
    ({"package.json": json.dumps({"dependencies": {"expo": "51", "react-native": "0.74"}})},
     {"expo", "react-native"}, set()),
    ({"app.json": json.dumps({"expo": {"name": "x"}})}, {"expo"}, {"node"}),
    ({"firebase.json": "{}"}, {"firebase"}, set()),
    ({"package.json": json.dumps({"dependencies": {"@prisma/client": "5"}})}, {"prisma"}, set()),
    ({"prisma/schema.prisma": "model A {}"}, {"prisma"}, set()),
    ({"supabase/config.toml": "x"}, {"supabase"}, set()),
    ({"requirements.txt": "FastAPI==0.110\nuvicorn[standard]\nanthropic>=0.30\n"}, {"fastapi", "python", "llm"}, {"flask"}),
    ({"pyproject.toml": '[project]\ndependencies = ["flask>=3", "stripe"]\n'}, {"flask", "stripe", "python"}, set()),
    ({"pyproject.toml": '[tool.poetry.dependencies]\npython = "^3.11"\nDjango = "^5.0"\n'}, {"django"}, set()),
    ({"manage.py": "import django", "app/settings.py": "x"}, {"django", "python"}, set()),
    ({"main.py": "from fastapi import FastAPI\napp = FastAPI()\n"}, {"fastapi"}, set()),
    ({"composer.json": json.dumps({"require": {"laravel/framework": "^11.0", "laravel/cashier": "15"}})},
     {"laravel", "php", "stripe"}, set()),
    ({"artisan": "#!/usr/bin/env php"}, {"laravel", "php"}, set()),
    ({"index.php": "<?php echo 1;"}, {"php"}, {"laravel"}),
])
def test_detect_stacks(tmp_path, write_tree, files, expected, absent):
    write_tree(tmp_path, files)
    ctx = wc.ScanContext(tmp_path)
    scan_app.detect_stacks(ctx)
    assert expected <= ctx.stacks, ctx.stacks
    assert not (absent & ctx.stacks), ctx.stacks


@pytest.mark.parametrize("files,managers", [
    ({"package.json": "{}", "pnpm-lock.yaml": "x"}, ["pnpm"]),
    ({"package.json": "{}", "yarn.lock": "x"}, ["yarn"]),
    ({"package.json": "{}", "package-lock.json": "{}"}, ["npm"]),
    ({"package.json": json.dumps({"packageManager": "bun@1.1.0"})}, ["bun"]),
    ({"requirements.txt": "flask"}, ["pip"]),
    ({"pyproject.toml": "x", "uv.lock": "x", "requirements.txt": "flask"}, ["uv"]),
    ({"composer.json": "{}", "composer.lock": "{}"}, ["composer"]),
])
def test_package_managers(tmp_path, write_tree, files, managers):
    write_tree(tmp_path, files)
    ctx = wc.ScanContext(tmp_path)
    scan_app.detect_stacks(ctx)
    assert ctx.package_managers == managers


def test_deps_merged_root_first(tmp_path, write_tree):
    write_tree(tmp_path, {
        "package.json": json.dumps({"dependencies": {"next": "14.2.0"}, "devDependencies": {"vite": "5"}}),
        "apps/web/package.json": json.dumps({"dependencies": {"next": "13.0.0", "stripe": "1"}}),
    })
    ctx = wc.ScanContext(tmp_path)
    scan_app.detect_stacks(ctx)
    assert ctx.deps["next"] == "14.2.0"
    assert ctx.deps["stripe"] == "1"
    assert "vite" in ctx.dev_deps and "vite" not in ctx.prod_deps


def test_parse_stack_arg():
    assert scan_app.parse_stack_arg(None, {"a"}) == ({"a"}, False)
    assert scan_app.parse_stack_arg("django,flask", {"a"}) == ({"django", "flask"}, False)
    assert scan_app.parse_stack_arg("+supabase", {"a"}) == ({"a", "supabase"}, False)
    assert scan_app.parse_stack_arg("all", {"a"}) == ({"a"}, True)


# --- the example rule in _rules_deploy.py ----------------------------------------------

DJANGO = {"manage.py": "import django\n"}


@pytest.mark.parametrize("path,text,fires", [
    ("proj/settings.py", "DEBUG = True\n", True),
    ("proj/settings/production.py", "DEBUG = True\n", True),
    ("proj/settings.py", "DEBUG = os.environ.get('DEBUG', True)\n", True),
    ("proj/settings.py", "DEBUG = env.bool('DEBUG', default=True)\n", True),
    ("proj/settings.py", "DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'\n", False),
    ("proj/settings.py", "DEBUG = False\n", False),
    ("proj/settings.py", "# DEBUG = True\n", False),
    ("proj/settings.py", "class Dev:\n    DEBUG = True\n", False),
    ("proj/settings/dev.py", "DEBUG = True\n", False),
    ("proj/settings/local.py", "DEBUG = True\n", False),
    ("proj/local_settings.py", "DEBUG = True\n", False),
    ("proj/tests/settings.py", "DEBUG = True\n", False),
    ("proj/views.py", "DEBUG = True\n", False),
])
def test_django_debug_rule(tmp_path, write_tree, scan_rules, path, text, fires):
    write_tree(tmp_path, dict(DJANGO, **{path: text}))
    res = scan_rules(tmp_path, rule_ids=["deploy-django-debug"])
    assert ("deploy-django-debug" in res.rule_ids) is fires


def test_django_rule_not_run_for_other_stacks(tmp_path, write_tree, scan_rules):
    write_tree(tmp_path, {"package.json": "{}", "settings.py": "DEBUG = True\n"})
    assert scan_rules(tmp_path, rule_ids=["deploy-django-debug"]).findings == []
    assert scan_rules(tmp_path, rule_ids=["deploy-django-debug"], stacks="+django").rule_ids == ["deploy-django-debug"]
    assert scan_rules(tmp_path, rule_ids=["deploy-django-debug"], stacks="all").rule_ids == ["deploy-django-debug"]


# --- engine behaviour with synthetic rules ------------------------------------------------

def test_regex_line_numbers_and_evidence(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "ok\nx = BAD\nok\n# BAD in a comment\ny = BAD\n"})
    res = scan_app.run_scan(tmp_path, rules=[_rule()])
    assert _ids(res) == [("t-rule", "a.py", 2), ("t-rule", "a.py", 5)]
    f = res.findings[0]
    assert f.evidence == "x = BAD"
    assert f.message == "bad thing" and f.skill == "test" and f.klass == "test class"
    assert f.needs_confirmation is True


def test_multiline_regex(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "a\nstart(\n  BAD\n)\nstart(\n ok\n)\n"})
    rule = _rule(pattern=r"start\(\s*BAD", multiline=True)
    res = scan_app.run_scan(tmp_path, rules=[rule])
    assert _ids(res) == [("t-rule", "a.py", 2)]


def test_check_callable_and_hit_overrides(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "one\ntwo\n", "b.py": "three\n"})

    def check(path, text, ctx):
        assert isinstance(ctx, wc.ScanContext)
        if path == "a.py":
            return [(2, "two"), Hit(1, "one", "custom message", "critical")]
        return [Hit(1, "x", None, None, "other.py")]

    res = scan_app.run_scan(tmp_path, rules=[_rule(pattern="", check=check)])
    got = {(f.file, f.line): f for f in res.findings}
    assert got[("a.py", 1)].severity == "critical" and got[("a.py", 1)].message == "custom message"
    assert got[("a.py", 2)].severity == "medium"
    assert ("other.py", 1) in got
    assert res.findings[0].severity == "critical"


def test_check_by_name_in_module(tmp_path, write_tree):
    mod = types.ModuleType("_rules_fake_for_test")

    def check_fake(path, text, ctx):
        return [(1, "found")]

    mod.check_fake = check_fake
    mod.RULES = [_rule(id="fake-rule", pattern="check_fake")]
    sys.modules["_rules_fake_for_test"] = mod
    try:
        rules, warnings = scan_app.load_rules(("_rules_fake_for_test",))
        assert warnings == [] and [r.id for r in rules] == ["fake-rule"]
        assert rules[0].module == "_rules_fake_for_test"
        write_tree(tmp_path, {"a.py": "x"})
        res = scan_app.run_scan(tmp_path, rules=rules)
        assert res.rule_ids == ["fake-rule"]
    finally:
        del sys.modules["_rules_fake_for_test"]


def test_broken_rule_does_not_stop_scan(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "BAD\n", "b.py": "BAD\n"})

    def boom(path, text, ctx):
        raise RuntimeError("kaboom")

    rules = [_rule(id="broken", pattern="", check=boom), _rule(id="good")]
    res = scan_app.run_scan(tmp_path, rules=rules)
    assert sorted(set(res.rule_ids)) == ["good"]
    assert any("broken" in str(w) and "kaboom" in str(w) for w in res.warnings)


def test_bad_return_value_is_a_warning(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "x"})
    res = scan_app.run_scan(tmp_path, rules=[_rule(pattern="", check=lambda p, t, c: ["nonsense"])])
    assert res.findings == [] and res.warnings


def test_invalid_regex_and_invalid_rule_are_warnings(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "BAD"})
    rules = [_rule(id="bad-regex", pattern="("), _rule(id="bad-sev", severity="nope"), _rule(id="fine")]
    res = scan_app.run_scan(tmp_path, rules=rules)
    assert res.rule_ids == ["fine"]
    text = " ".join(str(w) for w in res.warnings)
    assert "bad-regex" in text and "bad-sev" in text


def test_load_rules_handles_missing_module_and_duplicates():
    mod = types.ModuleType("_rules_dup_for_test")
    mod.RULES = [_rule(id="deploy-django-debug")]
    sys.modules["_rules_dup_for_test"] = mod
    try:
        rules, warnings = scan_app.load_rules(("_rules_deploy", "_rules_dup_for_test", "_rules_missing_xyz"))
        ids = [r.id for r in rules]
        deploy_only, _ = scan_app.load_rules(("_rules_deploy",))
        assert ids.count("deploy-django-debug") == 1
        assert ids == [r.id for r in deploy_only]
        joined = " ".join(warnings)
        assert "duplicate rule id deploy-django-debug" in joined
        assert "_rules_missing_xyz" in joined
    finally:
        del sys.modules["_rules_dup_for_test"]


def test_unknown_stack_names_warn(tmp_path, write_tree):
    mod = types.ModuleType("_rules_typo_for_test")
    mod.RULES = [_rule(id="typo", stacks=["nextjs-ap", "supabase+fierbase"])]
    sys.modules["_rules_typo_for_test"] = mod
    try:
        rules, warnings = scan_app.load_rules(("_rules_typo_for_test",))
        assert [r.id for r in rules] == ["typo"]
        assert "fierbase" in warnings[0] and "nextjs-ap" in warnings[0]
    finally:
        del sys.modules["_rules_typo_for_test"]
    write_tree(tmp_path, {"a.py": "x"})
    res = scan_app.run_scan(tmp_path, rules=[_rule()], stacks="+djnago")
    assert any("djnago" in str(w) for w in res.warnings)


def test_dedupe_sort_and_min_severity(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "BAD BAD\nLOW\n"})
    rules = [_rule(id="hi", severity="high"), _rule(id="lo", severity="low", pattern="LOW"),
             _rule(id="hi2", severity="high", pattern="BAD", multiline=True)]
    res = scan_app.run_scan(tmp_path, rules=rules)
    assert _ids(res) == [("hi", "a.py", 1), ("hi2", "a.py", 1), ("lo", "a.py", 2)]
    res = scan_app.run_scan(tmp_path, rules=rules, min_severity="high")
    assert [f.rule for f in res.findings] == ["hi", "hi2"]


def test_filters_unless_exclude_comments(tmp_path, write_tree):
    write_tree(tmp_path, {
        "a.py": "BAD\nBAD  # ok-here\n",
        "b.py": "SAFE_MARKER\nBAD\n",
        "tests/c.py": "BAD\n",
        "d.py": "# BAD\n",
    })
    rule = _rule(unless_file="SAFE_MARKER", unless_line="ok-here", exclude_globs=["tests/**"])
    res = scan_app.run_scan(tmp_path, rules=[rule])
    assert _ids(res) == [("t-rule", "a.py", 1)]
    res = scan_app.run_scan(tmp_path, rules=[_rule(skip_comments=False, file_globs=["d.py"])])
    assert _ids(res) == [("t-rule", "d.py", 1)]


def test_max_per_file(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "BAD\n" * 30})
    res = scan_app.run_scan(tmp_path, rules=[_rule(max_per_file=5)])
    assert len(res.findings) == 5
    assert "(and 25 more in this file)" in res.findings[-1].message


def test_minified_files_skipped_unless_asked(tmp_path, write_tree):
    write_tree(tmp_path, {"lib.min.js": "BAD"})
    assert scan_app.run_scan(tmp_path, rules=[_rule(file_globs=["*.js"])]).findings == []
    res = scan_app.run_scan(tmp_path, rules=[_rule(file_globs=["*.js"], include_minified=True)])
    assert len(res.findings) == 1


def test_once_rule(tmp_path, write_tree):
    write_tree(tmp_path, {"package.json": "{}"})

    def check(path, text, ctx):
        assert path == "" and text == ""
        return [Hit(1, "no lockfile", None, None, "package.json"), (0, "project level")]

    res = scan_app.run_scan(tmp_path, rules=[_rule(pattern="", check=check, once=True, file_globs=[])])
    assert sorted((f.file, f.line) for f in res.findings) == [("", 0), ("package.json", 1)]


def test_stack_filter_and_all(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "BAD"})
    rule = _rule(stacks=["laravel"])
    assert scan_app.run_scan(tmp_path, rules=[rule]).findings == []
    assert len(scan_app.run_scan(tmp_path, rules=[rule], stacks="all").findings) == 1
    assert len(scan_app.run_scan(tmp_path, rules=[rule], stacks=["laravel"]).findings) == 1


def test_evidence_is_redacted(tmp_path, write_tree, fake_token):
    key = fake_token("sk_" + "live_")
    write_tree(tmp_path, {"a.py": "STRIPE = '%s'  # BAD\n" % key})
    res = scan_app.run_scan(tmp_path, rules=[_rule(skip_comments=False)])
    ev = res.findings[0].evidence
    assert key not in ev and "chars]" in ev


def test_cross_file_index_with_memo(tmp_path, write_tree):
    write_tree(tmp_path, {"schema.sql": "create table notes ();\n", "client.ts": "from('notes')\nfrom('other')\n"})
    calls = []

    def tables(ctx):
        calls.append(1)
        return set(__import__("re").findall(r"create table (\w+)", ctx.read("schema.sql")))

    def check(path, text, ctx):
        known = ctx.memo("tables", lambda: tables(ctx))
        out = []
        for i, line in enumerate(ctx.lines(path), 1):
            for t in __import__("re").findall(r"from\('(\w+)'\)", line):
                if t not in known:
                    out.append((i, line))
        return out

    res = scan_app.run_scan(tmp_path, rules=[_rule(pattern="", check=check, file_globs=["*.ts", "*.sql"])])
    assert _ids(res) == [("t-rule", "client.ts", 2)]
    assert calls == [1]


def test_single_file_target(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "BAD", "b.py": "BAD"})
    res = scan_app.run_scan(tmp_path / "a.py", rules=[_rule()])
    assert [f.file for f in res.findings] == ["a.py"]


# --- client file heuristic --------------------------------------------------------------

def _ctx(tmp_path, write_tree, files):
    write_tree(tmp_path, files)
    ctx = wc.ScanContext(tmp_path)
    scan_app.detect_stacks(ctx)
    return ctx


def test_client_files_nextjs(tmp_path, write_tree):
    ctx = _ctx(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"next": "14.2.30", "react": "18"}}),
        "app/layout.tsx": "export default function L() {}",
        "app/page.tsx": "export default async function Page() { const x = await db() }",
        "app/dash/widget.tsx": "// note\n'use client'\nexport function W() {}",
        "app/api/chat/route.ts": "'use client'\nexport async function POST() {}",
        "components/Counter.tsx": "import {useState} from 'react'\nconst [a, b] = useState(0)",
        "components/Card.tsx": "export function Card() { return null }",
        "lib/server-stuff.ts": "import 'server-only'\nexport const x = 1",
        "actions.ts": "'use server'\nexport async function act() {}",
        "middleware.ts": "export function middleware() {}",
        "pages/legacy.tsx": "export default function P() {}",
        "pages/ssr.tsx": "export async function getServerSideProps() {}",
        "pages/api/x.ts": "export default function h() {}",
        "utils/supabase/client.ts": "'use client'\nexport const s = 1",
        "next.config.js": "module.exports = {}",
    })
    client = set(ctx.client_files)
    assert {"app/dash/widget.tsx", "components/Counter.tsx", "pages/legacy.tsx", "utils/supabase/client.ts"} <= client
    for server in ("app/layout.tsx", "app/page.tsx", "app/api/chat/route.ts", "components/Card.tsx",
                   "lib/server-stuff.ts", "actions.ts", "middleware.ts", "pages/ssr.tsx", "pages/api/x.ts",
                   "next.config.js"):
        assert server not in client, server


def test_client_files_vite_spa(tmp_path, write_tree):
    ctx = _ctx(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"react": "18", "react-dom": "18"}, "devDependencies": {"vite": "5"}}),
        "src/App.tsx": "export default function App() {}",
        "src/lib/supabase.ts": "export const s = 1",
        "src/api/client.ts": "export const get = 1",
        "src/server/db.ts": "export const db = 1",
        "server/index.js": "const express = require('express')",
        "vite.config.ts": "export default {}",
        "src/App.test.tsx": "test()",
    })
    client = set(ctx.client_files)
    assert {"src/App.tsx", "src/lib/supabase.ts", "src/api/client.ts"} <= client
    for server in ("src/server/db.ts", "server/index.js", "vite.config.ts", "src/App.test.tsx"):
        assert server not in client, server


def test_client_files_expo_and_express(tmp_path, write_tree):
    ctx = _ctx(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"expo": "51", "react-native": "0.74"}}),
        "app/(tabs)/index.tsx": "export default function Home() {}",
        "app/api/chat+api.ts": "export function POST() {}",
        "index.js": "registerRootComponent(App)",
        "app.config.ts": "export default {}",
        "supabase/functions/x/index.ts": "Deno.serve()",
    })
    client = set(ctx.client_files)
    assert {"app/(tabs)/index.tsx", "index.js"} <= client
    for server in ("app/api/chat+api.ts", "app.config.ts", "supabase/functions/x/index.ts"):
        assert server not in client, server

    other = tmp_path / "srv"
    ctx2 = _ctx(other, write_tree, {
        "package.json": json.dumps({"dependencies": {"express": "4"}}),
        "index.js": "app.listen()",
        "routes/users.js": "router.get()",
        "public/js/app.js": "document.querySelector('x')",
        "client/src/App.jsx": "x",
    })
    client2 = set(ctx2.client_files)
    assert client2 == {"public/js/app.js", "client/src/App.jsx"}


def test_client_only_rule(tmp_path, write_tree):
    write_tree(tmp_path, {
        "package.json": json.dumps({"dependencies": {"react": "18"}, "devDependencies": {"vite": "5"}}),
        "src/a.ts": "BAD",
        "server/b.ts": "BAD",
    })
    res = scan_app.run_scan(tmp_path, rules=[_rule(file_globs=["*.ts"], client_only=True)])
    assert [f.file for f in res.findings] == ["src/a.ts"]


# --- CLI -----------------------------------------------------------------------------------

def test_cli_json_and_exit_codes(tmp_path, write_tree, run_script):
    write_tree(tmp_path, dict(DJANGO, **{"proj/settings.py": "DEBUG = True\n"}))
    r = run_script("scan_app.py", "--json", tmp_path)
    assert r.returncode == 1, r.stderr
    rep = json.loads(r.stdout)
    assert rep["tool"] == "ward" and rep["script"] == "scan_app"
    assert "django" in rep["stacks"]
    assert rep["findings"][0]["rule"] == "deploy-django-debug"
    assert rep["findings"][0]["file"] == "proj/settings.py" and rep["findings"][0]["line"] == 1
    assert rep["summary"]["high"] == 1
    assert rep["warnings"] == []

    clean = tmp_path / "clean"
    write_tree(clean, {"README.md": "hello"})
    r = run_script("scan_app", clean)
    assert r.returncode == 0, r.stderr
    assert "No findings." in r.stdout


def test_cli_human_output_file_and_only(tmp_path, write_tree, run_script):
    write_tree(tmp_path, dict(DJANGO, **{"proj/settings.py": "DEBUG = True\n"}))
    out = tmp_path / "report.json"
    r = run_script("scan_app.py", "--output", out, tmp_path)
    assert r.returncode == 1
    assert "HIGH" in r.stdout and "deploy-django-debug" in r.stdout and "proj/settings.py:1" in r.stdout
    assert json.loads(out.read_text(encoding="utf-8"))["summary"]["total"] == 1
    r = run_script("scan_app.py", "--only", "critical", tmp_path)
    assert r.returncode == 0


def test_cli_errors(tmp_path, run_script):
    assert run_script("scan_app.py", tmp_path / "missing").returncode == 2
    assert run_script("scan_app.py", "--only", "severe", tmp_path).returncode == 2
    r = run_script("scan_app.py", "--help")
    assert r.returncode == 0 and "--list-rules" in r.stdout


def test_cli_list_rules(run_script):
    r = run_script("scan_app.py", "--list-rules")
    assert r.returncode == 0
    ids = r.stdout.split()
    assert "deploy-django-debug" in ids
    assert ids == run_script("scan_app.py", "--list-rules").stdout.split()
    r = run_script("scan_app.py", "--list-rules", "--json")
    data = json.loads(r.stdout)
    entry = [d for d in data if d["id"] == "deploy-django-debug"][0]
    assert entry["module"] == "_rules_deploy" and entry["severity"] == "high"


def test_cli_git_bash_style_path(tmp_path, write_tree, run_script):
    if sys.platform != "win32":
        pytest.skip("drive letter paths only exist on Windows")
    write_tree(tmp_path, {"README.md": "x"})
    p = tmp_path.resolve().as_posix()
    msys = "/" + p[0].lower() + p[2:]
    r = run_script("scan_app.py", "--json", msys, env={"MSYS_NO_PATHCONV": "1"})
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["target"].lower() == p.lower()


# --- rules.md generator --------------------------------------------------------------------

def test_gen_rules_md_render_and_check(tmp_path, run_script):
    rules, warnings = scan_app.load_rules()
    assert warnings == []
    text = gen_rules_md.render(rules)
    assert "### deploy-django-debug" in text
    assert "False-positive trap:" in text and "[stack-python.md#django-debug](stack-python.md#django-debug)" in text
    assert "\r" not in text and "\u2014" not in text
    assert gen_rules_md.render(rules) == text

    out = tmp_path / "rules.md"
    r = run_script("gen_rules_md.py", "--output", out)
    assert r.returncode == 0, r.stderr
    assert out.read_text(encoding="utf-8") == text
    assert run_script("gen_rules_md.py", "--check", "--output", out).returncode == 0
    out.write_text(text + "\nhand edit\n", encoding="utf-8")
    assert run_script("gen_rules_md.py", "--check", "--output", out).returncode == 1
    assert run_script("gen_rules_md.py", "--check", "--output", tmp_path / "none.md").returncode == 1


def test_gen_rules_md_severity_note_and_header():
    a = _rule(id="xss-thing", severity="high", severity_note="medium when the source cannot be traced")
    a.module = "_rules_injection"
    text = gen_rules_md.render([a])
    assert text.startswith("# Rule reference\n")
    assert "**high** (medium when the source cannot be traced) | confidence" in text
    assert "<!-- Generated" in text and "--explain" in text
    assert "\nDo not edit this file by hand" not in text


def test_downgrading_rule_shows_its_severity_note():
    rules, _warnings = scan_app.load_rules()
    rule = {r.id: r for r in rules}["xss-react-dangerous-html"]
    assert rule.severity == "high" and rule.severity_note.startswith("medium when")
    text, missing = scan_app.explain(["xss-react-dangerous-html"])
    assert not missing and "high (medium when" in text
    assert "**high** (medium when" in gen_rules_md.render([rule])


def test_gen_rules_md_groups_by_module_order():
    a = _rule(id="b-rule", severity="low")
    a.module = "_rules_supply"
    b = _rule(id="a-rule", severity="critical")
    b.module = "_rules_dataauth"
    c = _rule(id="c-rule", severity="critical")
    c.module = "_rules_supply"
    text = gen_rules_md.render([a, b, c])
    assert text.index("## Data access and auth") < text.index("## Supply chain")
    assert text.index("### c-rule") < text.index("### b-rule")


# --- stack detection per package -----------------------------------------------------------

def _stacks(tmp_path, write_tree, files):
    write_tree(tmp_path, files)
    ctx = wc.ScanContext(tmp_path)
    scan_app.detect_stacks(ctx)
    return ctx


def test_spa_decided_per_package_not_by_docs_site(tmp_path, write_tree):
    ctx = _stacks(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"react": "19", "react-dom": "19"},
                                    "devDependencies": {"vite": "7", "@vitejs/plugin-react": "5"}}),
        "src/App.tsx": "export default function App() {}",
        "doc/package.json": json.dumps({"dependencies": {"astro": "5", "@astrojs/starlight": "0.30"}}),
    })
    assert {"vite-spa", "react-vite"} <= ctx.stacks
    assert "src/App.tsx" in ctx.client_files


def test_spa_with_vite_hoisted_to_workspace_root(tmp_path, write_tree):
    ctx = _stacks(tmp_path, write_tree, {
        "package.json": json.dumps({"private": True, "devDependencies": {"vite": "7"}}),
        "apps/web/package.json": json.dumps({"dependencies": {"vue": "3"}}),
        "apps/web/src/main.ts": "createApp(App).mount('#app')",
    })
    assert "vite-spa" in ctx.stacks and "react-vite" not in ctx.stacks
    assert "apps/web/src/main.ts" in ctx.client_files


def test_nextjs_pages_only_under_a_next_app(tmp_path, write_tree):
    ctx = _stacks(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"next": "15.1.0", "react": "19"}}),
        "app/page.tsx": "export default function P() {}",
        "tests/pages/login.ts": "export class LoginPage {}",
        "ui/marketplace/pages/list.tsx": "export function List() {}",
    })
    assert "nextjs-app" in ctx.stacks and "nextjs-pages" not in ctx.stacks
    ctx2 = _stacks(tmp_path / "two", write_tree, {
        "package.json": json.dumps({"private": True}),
        "apps/site/package.json": json.dumps({"dependencies": {"next": "14.2.0"}}),
        "apps/site/src/pages/index.tsx": "export default function P() {}",
    })
    assert "nextjs-pages" in ctx2.stacks


@pytest.mark.parametrize("files,python", [
    ({"composer.json": "{}", "index.php": "<?php", ".github/workflows/scripts/commit-checker.py": "import sys"}, False),
    ({"package.json": "{}", "scripts/gen.py": "print(1)", "tools/a.py": "x", "docs/conf.py": "x"}, False),
    ({"package.json": "{}", "docs/requirements.txt": "sphinx\n"}, False),
    ({"requirements.txt": "requests\n", "a.py": "x"}, True),
    ({"pkg/a.py": "x", "pkg/b.py": "x", "pkg/c.py": "x"}, True),
    ({"app.py": "from flask import Flask\n"}, True),
])
def test_python_stack_ignores_tooling_scripts(tmp_path, write_tree, files, python):
    ctx = _stacks(tmp_path, write_tree, files)
    assert ("python" in ctx.stacks) is python, ctx.stacks


@pytest.mark.parametrize("composer_dep", ["laravel/ai", "prism-php/prism", "openai-php/client", "openai-php/laravel"])
def test_llm_stack_from_composer(tmp_path, write_tree, composer_dep):
    ctx = _stacks(tmp_path, write_tree, {"composer.json": json.dumps({"require": {composer_dep: "^1.0"}})})
    assert "llm" in ctx.stacks


def test_deno_edge_function_imports(tmp_path, write_tree):
    ctx = _stacks(tmp_path, write_tree, {
        "package.json": json.dumps({"dependencies": {"react": "18"}, "devDependencies": {"vite": "5"}}),
        "supabase/functions/pay/index.ts": 'import Stripe from "npm:stripe@17.2.0";\n'
                                            'import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.3";\n',
        "supabase/functions/deno.json": json.dumps({"imports": {"axios": "npm:axios@1.14.1"}}),
    })
    assert {"stripe", "supabase"} <= ctx.stacks
    assert ctx.deno_deps["stripe"] == [("17.2.0", "supabase/functions/pay/index.ts", 1)]
    assert ctx.deno_deps["@supabase/supabase-js"][0][0] == "2.39.3"
    assert ctx.deno_deps["axios"][0][:2] == ("1.14.1", "supabase/functions/deno.json")
    assert "axios" in ctx.deps


def test_llm_stack_from_direct_api_call(tmp_path, write_tree):
    ctx = _stacks(tmp_path, write_tree, {
        "supabase/functions/chat/index.ts": "const r = await fetch('https://api.openai.com/v1/chat/completions', opts)\n",
    })
    assert "llm" in ctx.stacks
    ctx2 = _stacks(tmp_path / "none", write_tree, {"src/a.ts": "fetch('/api/chat')\n"})
    assert "llm" not in ctx2.stacks


def test_parse_stack_arg_mixed_list_is_additive():
    assert scan_app.parse_stack_arg("+stripe,llm", {"node"}) == ({"node", "stripe", "llm"}, False)
    assert scan_app.parse_stack_arg("+stripe, +llm", {"node"}) == ({"node", "stripe", "llm"}, False)
    assert scan_app.parse_stack_arg("stripe,llm", {"node"}) == ({"stripe", "llm"}, False)


def test_stack_replace_warns_about_dropped_stacks(tmp_path, write_tree):
    write_tree(tmp_path, {"package.json": json.dumps({"dependencies": {"express": "4"}}), "a.py": "BAD"})
    res = scan_app.run_scan(tmp_path, rules=[_rule()], stacks="django")
    assert any("express" in str(w) and "'+'" in str(w) for w in res.warnings)
    res = scan_app.run_scan(tmp_path, rules=[_rule()], stacks="+django")
    assert not any("replaced" in str(w) for w in res.warnings)


# --- comments, anchors, vendored code ------------------------------------------------------

def test_regex_rule_skips_block_comments_and_comment_tails(tmp_path, write_tree):
    write_tree(tmp_path, {"a.js": (
        "ok(BAD)\n"
        "/*\n"
        "   old(BAD)\n"
        "*/\n"
        "keep() // BAD later\n"
        "const s = '/* BAD in a string */'\n"
        "x(1) /* note */ y(BAD)\n")})
    res = scan_app.run_scan(tmp_path, rules=[_rule(file_globs=["*.js"])])
    assert [f.line for f in res.findings] == [1, 6, 7]
    res = scan_app.run_scan(tmp_path, rules=[_rule(file_globs=["*.js"], pattern=r"old\(BAD\)", multiline=True)])
    assert res.findings == []


def test_anchors_prefilter(tmp_path, write_tree):
    write_tree(tmp_path, {"a.py": "x = BAD\n", "b.py": "import thing\nx = BAD\n"})
    calls = []

    def check(path, text, ctx):
        calls.append(path)
        return [(1, "x")]

    res = scan_app.run_scan(tmp_path, rules=[_rule(pattern="", check=check, anchors=["thing"])])
    assert calls == ["b.py"] and [f.file for f in res.findings] == ["b.py"]


def test_vendored_code_is_not_scanned(tmp_path, write_tree):
    write_tree(tmp_path, {
        "lib/composer.json": json.dumps({"require": {"phpmailer/phpmailer": "7.1", "simplepie/simplepie": "1"},
                                         "config": {"vendor-dir": "./"}}),
        "lib/phpmailer/phpmailer/src/PHPMailer.php": "<?php BAD",
        "lib/simplepie/simplepie/src/Parser.php": "<?php BAD",
        "lib/Minz/Request.php": "<?php BAD",
        "composer.json": json.dumps({"autoload": {
            "psr-4": {"App\\": "app/", "Gregwar\\Captcha\\": "libs/Captcha"},
            "psr-0": {"PicoDb": "libs/picodb/lib"}}}),
        "app/Controller.php": "<?php BAD",
        "libs/Captcha/CaptchaBuilder.php": "<?php BAD",
        "libs/picodb/lib/PicoDb/Table.php": "<?php BAD",
        "public/v1/lib/leaflet/leaflet-src.js": "BAD",
        "public/js/vendor-thing.js": "/* @preserve\n * Lib 1.6.0 */\nBAD",
        "public/js/app.js": "BAD",
    })
    res = scan_app.run_scan(tmp_path, rules=[_rule(file_globs=["*.php", "*.js"])])
    assert sorted(f.file for f in res.findings) == ["app/Controller.php", "lib/Minz/Request.php", "public/js/app.js"]
    assert res.vendored == 6


def test_psr4_lib_dirs_kept_when_project_has_no_own_namespace(tmp_path, write_tree):
    write_tree(tmp_path, {
        "composer.json": json.dumps({"autoload": {"psr-4": {"MyLib\\": "lib/MyLib"}}}),
        "lib/MyLib/Thing.php": "<?php BAD",
    })
    res = scan_app.run_scan(tmp_path, rules=[_rule(file_globs=["*.php"])])
    assert [f.file for f in res.findings] == ["lib/MyLib/Thing.php"]


# --- CLI: per-rule cap, compact JSON, ignore file, --explain ---------------------------------

def _seed_django(tmp_path, write_tree, extra=None):
    files = dict(DJANGO, **{"proj/settings.py": "DEBUG = True\n"})
    files.update(extra or {})
    write_tree(tmp_path, files)


def test_cli_json_is_compact_and_full_output_keeps_ids(tmp_path, write_tree, run_script):
    _seed_django(tmp_path, write_tree)
    out = tmp_path / "full.json"
    r = run_script("scan_app.py", "--json", "--output", out, tmp_path)
    rep = json.loads(r.stdout)
    f = rep["findings"][0]
    assert "id" not in f and "skill" not in f and f["rule"] == "deploy-django-debug"
    assert rep["summary"]["by_rule"] == {"deploy-django-debug": 1}
    full = json.loads(out.read_text(encoding="utf-8"))
    assert full["findings"][0]["id"] == "deploy-django-debug@proj/settings.py:1"


def test_cli_ignore_file(tmp_path, write_tree, run_script):
    _seed_django(tmp_path, write_tree, {
        ".ward-ignore": "# reviewed\ndeploy-django-debug@proj/settings.py:1  # dev only, prod uses settings_prod\n"
                        "redirect-open@nowhere.ts  # stale\n"})
    r = run_script("scan_app.py", "--json", tmp_path)
    assert r.returncode == 0, r.stdout
    rep = json.loads(r.stdout)
    assert rep["findings"] == [] and rep["summary"]["ignored"] == 1
    assert rep["ignored"] == ["deploy-django-debug@proj/settings.py:1  # dev only, prod uses settings_prod"]
    assert any("matched no finding" in w and "redirect-open@nowhere.ts" in w for w in rep["warnings"])
    assert run_script("scan_app.py", "--no-ignore", tmp_path).returncode == 1
    r = run_script("scan_app.py", "--ignore", tmp_path / "missing.txt", tmp_path)
    assert r.returncode == 2 and "does not exist" in r.stderr
    other = tmp_path / "other.txt"
    other.write_text("deploy-*@proj/*.py\n", encoding="utf-8")
    assert run_script("scan_app.py", "--ignore", other, tmp_path).returncode == 0


def test_cli_explain(run_script):
    r = run_script("scan_app.py", "--explain", "deploy-django-debug")
    assert r.returncode == 0
    assert r.stdout.startswith("### deploy-django-debug") and "False-positive trap:" in r.stdout
    assert "references/stack-python.md#django-debug" in r.stdout
    r = run_script("scan_app.py", "--explain", "deploy-django-debug,no-such-rule")
    assert r.returncode == 2 and "no-such-rule" in r.stderr


# --- worker processes --------------------------------------------------------------------------

def test_auto_jobs_only_for_large_projects():
    assert scan_app.auto_jobs(10, 60) == 1
    assert scan_app.auto_jobs(scan_app.PARALLEL_MIN_FILES, 1) == 1
    assert 1 <= scan_app.auto_jobs(scan_app.PARALLEL_MIN_FILES, 60) <= scan_app.MAX_JOBS


def _seed_several(tmp_path, write_tree):
    _seed_django(tmp_path, write_tree, {
        "proj/settings.py": "DEBUG = True\nALLOWED_HOSTS = ['*']\n",
        "shop/views.py": ("from django.db import connection\n"
                          "def item(request):\n"
                          "    with connection.cursor() as c:\n"
                          "        c.execute(\"SELECT * FROM items WHERE id = '%s'\" % request.GET['id'])\n"),
    })


def test_worker_processes_give_the_same_result(tmp_path, write_tree):
    _seed_several(tmp_path, write_tree)
    one = scan_app.run_scan(tmp_path, jobs=1)
    two = scan_app.run_scan(tmp_path, jobs=2)
    assert len(set(one.rule_ids)) >= 2, one.rule_ids
    assert [f.to_dict() for f in two.findings] == [f.to_dict() for f in one.findings]
    assert two.warnings == one.warnings and two.rules_run == one.rules_run


def test_worker_pool_failure_falls_back_to_one_process(tmp_path, write_tree, monkeypatch):
    import concurrent.futures

    def no_pool(*args, **kwargs):
        raise OSError("process pools are not available here")

    _seed_several(tmp_path, write_tree)
    want = [f.to_dict() for f in scan_app.run_scan(tmp_path, jobs=1).findings]
    monkeypatch.setattr(concurrent.futures, "ProcessPoolExecutor", no_pool)
    assert [f.to_dict() for f in scan_app.run_scan(tmp_path, jobs=4).findings] == want


def test_cli_jobs_flag(tmp_path, write_tree, run_script):
    _seed_several(tmp_path, write_tree)
    one = json.loads(run_script("scan_app.py", "--json", "--jobs", "1", tmp_path).stdout)
    two = json.loads(run_script("scan_app.py", "--json", "--jobs", "2", tmp_path).stdout)
    assert one["findings"] and one["findings"] == two["findings"]
