"""Tests for .github/scripts/check_frontmatter.py and a lint of the real SKILL.md files."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT

CHECKER = REPO_ROOT / ".github" / "scripts" / "check_frontmatter.py"
EXPECTED = ("secure-by-default", "preflight-audit", "live-exposure-check")


def _load(path):
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cf = _load(CHECKER)

GOOD_DESC = ("Checks a thing in the user's app and explains how to fix it. Use when the user asks "
             "whether the app is ready, mentions Supabase or Stripe, or is about to deploy a build.")

HEADER = (
    "Paths in this file are relative to this skill's folder. Use the absolute path to run a script.\n"
    "Run a script and read its output; do not read the script's source (saves tokens).\n"
    "If python3 is missing or prints \"Python was not found\" (Windows), use py -3 or python.\n"
    "Runtime checks run only against an app you own (localhost, 127.0.0.1, a .localhost or .test host, "
    "or a host you pass --i-own-this). Never point them at anyone else's site.\n"
)


def frontmatter(name="demo-skill", desc=GOOD_DESC, extra=""):
    return ("---\n"
            "name: %s\n"
            "description: \"%s\"\n"
            "license: MIT\n"
            "compatibility: \"Python 3.9+ standard library.\"\n"
            "metadata:\n"
            "  author: ReazGan\n"
            "  version: \"0.1.0\"\n"
            "%s"
            "---\n" % (name, desc, extra))


def make_skill(root, name="demo-skill", text=None, files=None, raw=None):
    d = Path(root) / name
    d.mkdir(parents=True, exist_ok=True)
    if raw is not None:
        (d / "SKILL.md").write_bytes(raw)
    else:
        if text is None:
            text = frontmatter(name) + HEADER + "\n# Demo\n\nRun `python3 scripts/run_me.py --help`.\n"
        with open(d / "SKILL.md", "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    for rel, content in (files or {}).items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
    return d


def errors(problems):
    return [p.message for p in problems if p.level == "error"]


def warnings(problems):
    return [p.message for p in problems if p.level == "warning"]


def has(messages, needle):
    return any(needle in m for m in messages)


SCRIPT = {"scripts/run_me.py": "print('ok')\n"}


# --- the real skills ---------------------------------------------------------

def _real(name):
    d = REPO_ROOT / "skills" / name
    if not (d / "SKILL.md").is_file():
        pytest.skip("%s/SKILL.md is not written yet" % name)
    return cf.check_skill(d, base=REPO_ROOT)


def _is_missing_file(p):
    return "does not exist in the skill" in p.message or "points to a missing file" in p.message


def _fmt(probs):
    return "\n".join("%s:%s %s" % (p.path, p.line, p.message) for p in probs)


@pytest.mark.parametrize("name", EXPECTED)
def test_real_skill_frontmatter_and_text(name):
    probs = [p for p in _real(name) if p.level == "error" and not _is_missing_file(p)]
    assert probs == [], _fmt(probs)


@pytest.mark.parametrize("name", EXPECTED)
def test_real_skill_referenced_files_exist(name):
    probs = [p for p in _real(name) if p.level == "error" and _is_missing_file(p)]
    assert probs == [], _fmt(probs)


def test_every_rule_fix_ref_resolves_inside_preflight_audit():
    """A fix_ref must name a file and heading in preflight-audit/references, so
    it can be followed when preflight-audit is installed on its own."""
    import scan_app

    rules, warnings = scan_app.load_rules()
    assert warnings == []
    refs_dir = REPO_ROOT / "skills" / "preflight-audit" / "references"
    cache = {}
    bad = []
    for r in rules:
        name, _, anchor = r.fix_ref.partition("#")
        path = refs_dir / name
        if not path.is_file():
            bad.append("%s: %s is not in preflight-audit/references" % (r.id, name))
            continue
        if path not in cache:
            cache[path] = cf._anchors(path.read_text(encoding="utf-8"))
        if anchor and anchor not in cache[path]:
            bad.append("%s: no heading for #%s in %s" % (r.id, anchor, name))
    assert bad == [], "\n".join(bad)


def test_real_repo_root_has_no_plugin_components():
    probs = [p for p in cf.check_repo_layout(REPO_ROOT) if p.level == "error"]
    assert probs == [], probs


def test_cli_runs_on_this_repo():
    r = subprocess.run([sys.executable, str(CHECKER)], capture_output=True, encoding="utf-8", errors="replace")
    assert r.returncode in (0, 1), r.stderr
    assert "checked" in r.stdout


# --- a good skill ------------------------------------------------------------

def test_good_skill_is_clean(tmp_path):
    d = make_skill(tmp_path, files=SCRIPT)
    probs = cf.check_skill(d)
    assert errors(probs) == []
    assert warnings(probs) == []


def test_good_skill_with_references_and_links(tmp_path):
    body = (HEADER + "\n# Demo\n\nSee [the guide](references/guide.md#setup) and references/other.md.\n"
            "```\npython3 scripts/run_me.py --json PROJECT_DIR\n```\n"
            "Code like `items[i](x)` is fine inside backticks only when fenced:\n"
            "```js\nconst y = items[i](x); import a from '../lib';\n```\n")
    files = dict(SCRIPT)
    files["references/guide.md"] = "# Guide\n\n## Setup\n\nSee [other](other.md) and [web](https://example.com).\n"
    files["references/other.md"] = "# Other\n"
    d = make_skill(tmp_path, text=frontmatter() + body, files=files)
    probs = cf.check_skill(d)
    assert errors(probs) == [], probs
    assert warnings(probs) == [], probs


# --- file format -------------------------------------------------------------

def test_bom_is_an_error(tmp_path):
    good = (frontmatter() + HEADER).encode("utf-8")
    d = make_skill(tmp_path, raw=b"\xef\xbb\xbf" + good)
    assert has(errors(cf.check_skill(d)), "BOM")


def test_crlf_is_an_error(tmp_path):
    good = (frontmatter() + HEADER).replace("\n", "\r\n").encode("utf-8")
    d = make_skill(tmp_path, raw=good)
    assert has(errors(cf.check_skill(d)), "CRLF")


def test_line_one_must_be_dashes(tmp_path):
    d = make_skill(tmp_path, text="\n" + frontmatter() + HEADER)
    assert has(errors(cf.check_skill(d)), "line 1 must be exactly ---")


def test_unclosed_frontmatter(tmp_path):
    d = make_skill(tmp_path, text="---\nname: demo-skill\ndescription: \"%s\"\n\n# body\n" % GOOD_DESC)
    assert has(errors(cf.check_skill(d)), "not closed")


def test_lowercase_skill_md_is_an_error(tmp_path):
    d = tmp_path / "demo-skill"
    d.mkdir()
    (d / "skill.md").write_text(frontmatter(), encoding="utf-8")
    msgs = errors(cf.check_skill(d))
    assert has(msgs, "exactly SKILL.md") or has(msgs, "no SKILL.md")


def test_missing_skill_md(tmp_path):
    d = tmp_path / "demo-skill"
    d.mkdir()
    assert has(errors(cf.check_skill(d)), "no SKILL.md")


# --- keys --------------------------------------------------------------------

@pytest.mark.parametrize("line,needle", [
    ("version: \"0.1.0\"\n", "metadata.version"),
    ("argument-hint: \"[path]\"\n", "breaks skills-ref"),
    ("when_to_use: \"always\"\n", "breaks skills-ref"),
    ("color: blue\n", "unexpected key"),
])
def test_extra_keys_are_errors(tmp_path, line, needle):
    d = make_skill(tmp_path, text=frontmatter(extra=line) + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), needle)


def test_duplicate_key(tmp_path):
    d = make_skill(tmp_path, text=frontmatter(extra="license: MIT\n") + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), "duplicate key license")


def test_allowed_tools_warns_and_list_form_errors(tmp_path):
    d = make_skill(tmp_path, text=frontmatter(extra="allowed-tools: Bash Read\n") + HEADER, files=SCRIPT)
    probs = cf.check_skill(d)
    assert errors(probs) == []
    assert has(warnings(probs), "allowed-tools")
    d2 = make_skill(tmp_path / "b", text=frontmatter(extra="allowed-tools: [Bash, Read]\n") + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d2)), "flow lists")


def test_block_scalar_is_an_error(tmp_path):
    text = frontmatter().replace("compatibility: \"Python 3.9+ standard library.\"", "compatibility: |")
    d = make_skill(tmp_path, text=text + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), "block scalars")


def test_metadata_values_must_be_strings(tmp_path):
    text = frontmatter().replace("version: \"0.1.0\"", "version: 1.0")
    d = make_skill(tmp_path, text=text + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), "metadata.version must be a string")
    text = frontmatter().replace("version: \"0.1.0\"", "version: 0.1.0")
    d2 = make_skill(tmp_path / "b", text=text + HEADER, files=SCRIPT)
    assert errors(cf.check_skill(d2)) == []


def test_nested_map_in_metadata_is_an_error(tmp_path):
    text = frontmatter().replace("  author: ReazGan\n", "  author:\n    name: x\n")
    d = make_skill(tmp_path, text=text + HEADER, files=SCRIPT)
    msgs = errors(cf.check_skill(d))
    assert has(msgs, "nested maps") or has(msgs, "unexpected indented")


# --- name --------------------------------------------------------------------

@pytest.mark.parametrize("name,needle", [
    ("Demo-Skill", "lowercase"),
    ("demo--skill", "lowercase"),
    ("-demo", "lowercase"),
    ("a" * 65, "longer than 64"),
    ("security-review", "built-in"),
    ("review", "built-in"),
    ("verify", "built-in"),
    ("claude-helper", "claude or anthropic"),
    ("my-anthropic-tool", "claude or anthropic"),
    ("synced", "reserved"),
])
def test_bad_names(tmp_path, name, needle):
    d = make_skill(tmp_path, name=name, text=frontmatter(name=name) + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), needle)


def test_name_must_match_folder(tmp_path):
    d = make_skill(tmp_path, name="demo-skill", text=frontmatter(name="other-name") + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), "must equal the folder name")


def test_missing_name_and_description(tmp_path):
    d = make_skill(tmp_path, text="---\nlicense: MIT\n---\n" + HEADER)
    msgs = errors(cf.check_skill(d))
    assert has(msgs, "missing name") and has(msgs, "missing description")


# --- description -------------------------------------------------------------

def test_description_must_be_double_quoted(tmp_path):
    text = frontmatter().replace("description: \"%s\"" % GOOD_DESC, "description: '%s'" % GOOD_DESC.replace("'", "''"))
    d = make_skill(tmp_path, text=text + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), "double-quoted")


def test_unquoted_description_with_colon_is_invalid_yaml(tmp_path):
    text = frontmatter().replace("description: \"%s\"" % GOOD_DESC, "description: Use when: deploying")
    d = make_skill(tmp_path, text=text + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), "invalid YAML")


@pytest.mark.parametrize("desc,level,needle", [
    ("Checks the <app> for holes. " + GOOD_DESC, "error", "< or >"),
    ("x" * 1025, "error", "max 1024"),
    (GOOD_DESC + " " + "More detail. " * 25, "warning", "aim for"),
    ("Short one.", "warning", "aim for"),
    ("", "error", "empty"),
])
def test_description_limits(tmp_path, desc, level, needle):
    d = make_skill(tmp_path, text=frontmatter(desc=desc) + HEADER, files=SCRIPT)
    probs = cf.check_skill(d)
    msgs = errors(probs) if level == "error" else warnings(probs)
    assert has(msgs, needle), probs


def test_compatibility_limit(tmp_path):
    text = frontmatter().replace("Python 3.9+ standard library.", "y" * 501)
    d = make_skill(tmp_path, text=text + HEADER, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), "compatibility is 501")


# --- body --------------------------------------------------------------------

def test_body_line_limit(tmp_path):
    body = HEADER + "line\n" * 496  # header is 4 lines, so exactly 500
    d = make_skill(tmp_path, text=frontmatter() + body, files=SCRIPT)
    assert errors(cf.check_skill(d)) == []
    d2 = make_skill(tmp_path / "b", text=frontmatter() + body + "one too many\n", files=SCRIPT)
    assert has(errors(cf.check_skill(d2)), "body is 501 lines")


def test_missing_standing_rules_header_warns(tmp_path):
    d = make_skill(tmp_path, text=frontmatter() + "# Demo\n\nBody.\n")
    probs = cf.check_skill(d)
    assert errors(probs) == []
    assert has(warnings(probs), "standing-rules header")


def test_rules_only_skill_needs_only_the_paths_line(tmp_path):
    paths_only = "Paths in this file are relative to this skill's folder.\n"
    d = make_skill(tmp_path, text=frontmatter() + paths_only + "\n# Demo\n\nBody.\n")
    assert not has(warnings(cf.check_skill(d)), "standing-rules header")
    d2 = make_skill(tmp_path / "b", text=frontmatter() + paths_only + "\n# Demo\n\nBody.\n", files=SCRIPT)
    assert has(warnings(cf.check_skill(d2)), "standing-rules header")


def test_missing_script_and_reference(tmp_path):
    body = HEADER + "Run `python3 scripts/missing.py`. Read references/nope.md.\n"
    d = make_skill(tmp_path, text=frontmatter() + body)
    msgs = errors(cf.check_skill(d))
    assert has(msgs, "scripts/missing.py") and has(msgs, "references/nope.md")


def test_glob_mentions_are_not_checked(tmp_path):
    body = HEADER + "Load only the matching references/stack-*.md file.\n"
    d = make_skill(tmp_path, text=frontmatter() + body)
    assert errors(cf.check_skill(d)) == []


@pytest.mark.parametrize("link,needle", [
    ("[x](../other-skill/SKILL.md)", "leaves the skill folder"),
    ("[x](/etc/hosts)", "absolute link"),
    ("[x](references/missing.md)", "missing file"),
])
def test_bad_links(tmp_path, link, needle):
    d = make_skill(tmp_path, text=frontmatter() + HEADER + link + "\n")
    assert has(errors(cf.check_skill(d)), needle)


def test_reference_links_are_checked(tmp_path):
    files = {"references/a.md": "# A\n\nSee [b](b.md) and [up](../../x.md) and [c](b.md#nope).\n",
             "references/b.md": "# B\n"}
    d = make_skill(tmp_path, text=frontmatter() + HEADER + "See references/a.md.\n", files=files)
    probs = cf.check_skill(d)
    assert has(errors(probs), "leaves the skill folder")
    assert has(warnings(probs), "no heading with anchor #nope")


def test_anchor_slugs_match_github():
    text = "# Stripe (rotate + webhook roll)\n## Other providers\n## Other providers\n```\n# not a heading\n```\n"
    anchors = cf._anchors(text)
    assert "stripe-rotate--webhook-roll" in anchors
    assert "other-providers" in anchors and "other-providers-1" in anchors
    assert "not-a-heading" not in anchors


@pytest.mark.parametrize("cmd,needle", [
    ("python3 scripts/run_me.py --json . | jq .", "a pipe"),
    ("python3 scripts/run_me.py $(pwd)", "command substitution"),
    ("python3 scripts/run_me.py . 2>/dev/null", "2>/dev/null"),
    ("python3 scripts/run_me.py . && echo done", "&&"),
    ("python3 ../other/scripts/run_me.py", "uses ../"),
    ("./scripts/run_me.py --json .", "through the interpreter"),
])
def test_bash_only_commands(tmp_path, cmd, needle):
    body = HEADER + "```\n%s\n```\n" % cmd
    d = make_skill(tmp_path, text=frontmatter() + body, files=SCRIPT)
    assert has(errors(cf.check_skill(d)), needle)


def test_code_snippets_are_not_commands(tmp_path):
    body = HEADER + "```js\nif (a && b) { run(x | y) }\nconst p = require('../db');\n```\n"
    d = make_skill(tmp_path, text=frontmatter() + body, files=SCRIPT)
    assert errors(cf.check_skill(d)) == []


@pytest.mark.parametrize("text,needle", [
    ("A long dash \u2014 here.", "dash"),
    ("A range 1\u20132.", "dash"),
    ("Done \u2705", "emoji"),
    ("Saved in C:\\Users\\someone\\app", "home folder"),
    ("Saved in /Users/someone/app", "home folder"),
])
def test_text_rules(tmp_path, text, needle):
    d = make_skill(tmp_path, text=frontmatter() + HEADER + text + "\n", files=SCRIPT)
    assert has(errors(cf.check_skill(d)), needle)


def test_api_routes_are_not_home_paths(tmp_path):
    d = make_skill(tmp_path, text=frontmatter() + HEADER + "GET /users/:id and /api/users/me\n", files=SCRIPT)
    assert errors(cf.check_skill(d)) == []


def test_dash_in_script_and_reference(tmp_path):
    files = {"scripts/run_me.py": "# a \u2014 b\n", "references/r.md": "x \u2013 y\n"}
    d = make_skill(tmp_path, text=frontmatter() + HEADER + "See references/r.md.\n", files=files)
    probs = errors(cf.check_skill(d))
    assert sum(1 for m in probs if "dash" in m) == 2


# --- repo layout -------------------------------------------------------------

@pytest.mark.parametrize("entry,is_dir", [
    ("hooks", True), ("agents", True), ("commands", True), ("bin", True),
    (".mcp.json", False), ("CLAUDE.md", False), ("settings.json", False), ("SKILL.md", False),
])
def test_root_plugin_components(tmp_path, entry, is_dir):
    make_skill(tmp_path / "skills", files=SCRIPT)
    target = tmp_path / entry
    if is_dir:
        target.mkdir()
    else:
        target.write_text("{}\n", encoding="utf-8")
    probs = cf.check_repo_layout(tmp_path)
    assert any(entry in p.path for p in probs if p.level == "error")


def test_repo_without_skills(tmp_path):
    assert has(errors(cf.check_repo_layout(tmp_path)), "no skills/ folder")


def test_cli_exit_codes(tmp_path):
    root = tmp_path / "repo"
    make_skill(root / "skills", files=SCRIPT)
    ok = subprocess.run([sys.executable, str(CHECKER), str(root)], capture_output=True, encoding="utf-8")
    assert ok.returncode == 0, ok.stdout
    assert "1 skill checked, 0 errors" in ok.stdout
    make_skill(root / "skills", name="Bad_Name", text=frontmatter(name="Bad_Name"))
    bad = subprocess.run([sys.executable, str(CHECKER), str(root)], capture_output=True, encoding="utf-8")
    assert bad.returncode == 1
    usage = subprocess.run([sys.executable, str(CHECKER), "--nope"], capture_output=True, encoding="utf-8")
    assert usage.returncode == 2


def test_single_skill_folder_mode(tmp_path):
    d = make_skill(tmp_path, files=SCRIPT)
    r = subprocess.run([sys.executable, str(CHECKER), str(d)], capture_output=True, encoding="utf-8")
    assert r.returncode == 0, r.stdout
    assert "1 skill checked" in r.stdout


def test_reference_may_link_back_to_skill_md(tmp_path):
    files = {"references/a.md": "# A\n\nBack to [the skill](../SKILL.md).\n"}
    d = make_skill(tmp_path, text=frontmatter() + HEADER + "See references/a.md.\n", files=files)
    assert errors(cf.check_skill(d)) == []
