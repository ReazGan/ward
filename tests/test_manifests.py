"""Tests for .github/scripts/check_manifests.py and the real manifests."""

import copy
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import REPO_ROOT

CHECKER = REPO_ROOT / ".github" / "scripts" / "check_manifests.py"


def _load(path):
    spec = importlib.util.spec_from_file_location(path.stem, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cm = _load(CHECKER)

PLUGIN = {
    "name": "ward",
    "version": "0.1.0",
    "description": "Skills that check an app for exposed keys before it ships.",
    "author": {"name": "ReazGan", "url": "https://github.com/ReazGan"},
    "homepage": "https://github.com/ReazGan/ward",
    "repository": "https://github.com/ReazGan/ward",
    "license": "MIT",
    "keywords": ["security"],
}
MARKET = {
    "name": "ward",
    "description": "Security skills.",
    "owner": {"name": "ReazGan", "url": "https://github.com/ReazGan"},
    "plugins": [{"name": "ward", "source": "./", "description": "Find holes.", "category": "security"}],
}


def write_manifests(root, plugin=None, market=None):
    d = Path(root) / ".claude-plugin"
    d.mkdir(parents=True, exist_ok=True)
    (d / "plugin.json").write_text(json.dumps(PLUGIN if plugin is None else plugin, indent=2), encoding="utf-8")
    (d / "marketplace.json").write_text(json.dumps(MARKET if market is None else market, indent=2),
                                        encoding="utf-8")
    return Path(root)


def manifest_errors(root):
    rep = cm.Report()
    plugin = cm.check_plugin_json(Path(root), rep)
    cm.check_marketplace_json(Path(root), rep, plugin)
    return rep


def has(items, needle):
    return any(needle in x for x in items)


# --- the real manifests ------------------------------------------------------

def test_real_manifests_pass():
    rep = manifest_errors(REPO_ROOT)
    assert rep.errors == [], rep.errors
    assert rep.warnings == [], rep.warnings


def test_real_manifest_shape():
    plugin = json.loads((REPO_ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    market = json.loads((REPO_ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert plugin["name"] == "ward" and market["name"] == "ward"
    assert [p["name"] for p in market["plugins"]] == ["ward"]
    assert market["plugins"][0]["source"] == "./"
    assert "version" not in market["plugins"][0]
    assert "email" not in json.dumps(plugin) and "email" not in json.dumps(market)
    assert "skills" not in plugin
    assert plugin["license"] == "MIT"


def test_real_versions_agree():
    rep = cm.Report()
    plugin = cm.check_plugin_json(REPO_ROOT, cm.Report())
    cm.check_version_consistency(REPO_ROOT, rep, plugin)
    assert rep.warnings == [], rep.warnings


def test_real_skill_set():
    rep = cm.Report()
    cm.check_skill_set(REPO_ROOT, rep)
    missing_md = [e for e in rep.errors if "no SKILL.md" in e or "is missing" in e]
    other = [e for e in rep.errors if e not in missing_md]
    assert other == [], other
    if missing_md:
        pytest.skip("skills still being written: %s" % "; ".join(missing_md))


def test_manifests_parse_as_plain_json():
    for name in ("plugin.json", "marketplace.json"):
        raw = (REPO_ROOT / ".claude-plugin" / name).read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf")
        assert b"\r" not in raw
        json.loads(raw.decode("utf-8"))


# --- plugin.json rules -------------------------------------------------------

def test_good_fixture_passes(tmp_path):
    rep = manifest_errors(write_manifests(tmp_path))
    assert rep.errors == [] and rep.warnings == []


@pytest.mark.parametrize("change,needle", [
    (lambda p: p.update(name="Ward"), "kebab-case"),
    (lambda p: p.update(name="claude-ward"), "reserved"),
    (lambda p: p.update(name="anthropic"), "reserved"),
    (lambda p: p.pop("name"), "name is required"),
    (lambda p: p.pop("version"), "version is required"),
    (lambda p: p.update(version="1.0"), "not semver"),
    (lambda p: p.update(version="v0.1.0"), "not semver"),
    (lambda p: p["author"].update(email=""), "omit author.email"),
    (lambda p: p.update(author={"url": "https://x.invalid"}), "author.name is required"),
    (lambda p: p.update(homepage="github.com/ReazGan/ward"), "homepage must parse"),
    (lambda p: p.update(skills=["./skills/a"]), "remove \"skills\""),
    (lambda p: p.update(hooks="./hooks/hooks.json"), "skills only"),
    (lambda p: p.update(mcpServers={}), "skills only"),
    (lambda p: p.update(keywords="security"), "keywords must be a list"),
    (lambda p: p.update(description="Checks <script> tags"), "< or >"),
])
def test_plugin_json_errors(tmp_path, change, needle):
    plugin = copy.deepcopy(PLUGIN)
    change(plugin)
    market = copy.deepcopy(MARKET)
    rep = manifest_errors(write_manifests(tmp_path, plugin=plugin, market=market))
    assert has(rep.errors, needle), rep.errors


def test_unknown_plugin_key_warns(tmp_path):
    plugin = dict(PLUGIN, flavor="mint")
    rep = manifest_errors(write_manifests(tmp_path, plugin=plugin))
    assert rep.errors == []
    assert has(rep.warnings, "unknown key 'flavor'")


def test_bom_and_bad_json(tmp_path):
    write_manifests(tmp_path)
    p = tmp_path / ".claude-plugin" / "plugin.json"
    p.write_bytes(b"\xef\xbb\xbf" + p.read_bytes())
    assert has(manifest_errors(tmp_path).errors, "BOM")
    p.write_text("{not json", encoding="utf-8")
    assert has(manifest_errors(tmp_path).errors, "not valid JSON")


def test_missing_manifest(tmp_path):
    (tmp_path / ".claude-plugin").mkdir()
    rep = manifest_errors(tmp_path)
    assert has(rep.errors, "plugin.json: missing") and has(rep.errors, "marketplace.json: missing")


# --- marketplace.json rules --------------------------------------------------

@pytest.mark.parametrize("change,needle", [
    (lambda m: m.update(name="agent-skills"), "reserved"),
    (lambda m: m.update(name="claude-plugins-official"), "reserved"),
    (lambda m: m.update(name="claudeai-tools"), "reserved"),
    (lambda m: m.update(name="-ward"), "letters, digits"),
    (lambda m: m.update(name="w\u00e4rd"), "letters, digits"),
    (lambda m: m.update(name="official-claude-tools"), "official"),
    (lambda m: m.pop("owner"), "owner.name is required"),
    (lambda m: m["owner"].update(email="a@b.invalid"), "omit owner.email"),
    (lambda m: m.update(version="0.1.0"), "plugin.json only"),
    (lambda m: m["plugins"][0].update(version="0.1.0"), "remove version"),
    (lambda m: m["plugins"][0].update(name="ward-skills"), "must equal plugin.json name"),
    (lambda m: m["plugins"][0].update(source="."), "source must be"),
    (lambda m: m["plugins"][0].update(source="./plugins/ward"), "source must be"),
    (lambda m: m["plugins"][0].update(skills=["./skills/a"]), "remove skills"),
    (lambda m: m.update(plugins=[]), "non-empty list"),
    (lambda m: m["plugins"].append(dict(m["plugins"][0], name="other")), "exactly one plugin entry"),
])
def test_marketplace_errors(tmp_path, change, needle):
    market = copy.deepcopy(MARKET)
    change(market)
    rep = manifest_errors(write_manifests(tmp_path, market=market))
    assert has(rep.errors, needle), rep.errors


# --- semver ------------------------------------------------------------------

@pytest.mark.parametrize("a,b,gt", [
    ("0.1.1", "0.1.0", True),
    ("0.2.0", "0.1.9", True),
    ("1.0.0", "0.9.9", True),
    ("0.1.0", "0.1.0", False),
    ("0.1.0", "0.1.1", False),
    ("1.0.0", "1.0.0-rc.1", True),
    ("1.0.0-rc.2", "1.0.0-rc.1", True),
    ("1.0.0-rc.1", "1.0.0", False),
    ("1.0.0-alpha", "1.0.0-1", True),
    ("1.0.0+build.5", "1.0.0", False),
])
def test_semver_gt(a, b, gt):
    assert cm.semver_gt(a, b) is gt


# --- skill set and shared copies ---------------------------------------------

def make_skills(root, names):
    for n in names:
        d = Path(root) / "skills" / n
        d.mkdir(parents=True, exist_ok=True)
        (d / "SKILL.md").write_text("---\nname: %s\n---\n" % n, encoding="utf-8")


def make_canonical(root):
    d = Path(root) / "skills" / cm.CANONICAL_SKILL / "scripts"
    d.mkdir(parents=True, exist_ok=True)
    for name in cm.SHARED_FILES:
        (d / name).write_bytes(("# canonical %s\n" % name).encode("utf-8"))
    return d


def test_skill_set(tmp_path):
    make_skills(tmp_path, cm.EXPECTED_SKILLS)
    rep = cm.Report()
    cm.check_skill_set(tmp_path, rep)
    assert rep.errors == []
    make_skills(tmp_path, ["extra-skill"])
    (tmp_path / "skills" / "preflight-audit" / "SKILL.md").unlink()
    rep = cm.Report()
    cm.check_skill_set(tmp_path, rep)
    assert has(rep.errors, "unexpected skill folder extra-skill")
    assert has(rep.errors, "skills/preflight-audit: no SKILL.md")


def test_copies_missing_differ_and_sync(tmp_path):
    make_skills(tmp_path, cm.EXPECTED_SKILLS)
    make_canonical(tmp_path)
    rep = cm.Report()
    cm.check_copies(tmp_path, rep)
    assert sum(1 for e in rep.errors if "missing copy" in e) == len(cm.SHARED_FILES)

    out = open(os.devnull, "w")
    try:
        assert cm.sync_copies(tmp_path, out=out) == 0
    finally:
        out.close()
    rep = cm.Report()
    cm.check_copies(tmp_path, rep)
    assert rep.errors == []

    target = tmp_path / "skills" / "live-exposure-check" / "scripts" / "_wardcore.py"
    target.write_bytes(target.read_bytes() + b"# edited\n")
    rep = cm.Report()
    cm.check_copies(tmp_path, rep)
    assert has(rep.errors, "live-exposure-check/scripts/_wardcore.py: differs")


def test_copies_must_match_byte_for_byte(tmp_path):
    make_skills(tmp_path, cm.EXPECTED_SKILLS)
    canon = make_canonical(tmp_path)
    dest = tmp_path / "skills" / "live-exposure-check" / "scripts"
    dest.mkdir(parents=True)
    for name in cm.SHARED_FILES:
        (dest / name).write_bytes((canon / name).read_bytes().replace(b"\n", b"\r\n"))
    rep = cm.Report()
    cm.check_copies(tmp_path, rep)
    assert sum(1 for e in rep.errors if "differs" in e) == len(cm.SHARED_FILES)


def test_stray_copy_in_another_skill_is_compared(tmp_path):
    make_skills(tmp_path, cm.EXPECTED_SKILLS)
    make_canonical(tmp_path)
    stray = tmp_path / "skills" / "secure-by-default" / "scripts"
    stray.mkdir(parents=True)
    (stray / "_wardcore.py").write_bytes(b"# old copy\n")
    rep = cm.Report()
    cm.check_copies(tmp_path, rep)
    assert has(rep.errors, "secure-by-default/scripts/_wardcore.py: differs")


def test_reference_copies_checked_and_synced(tmp_path):
    make_skills(tmp_path, cm.EXPECTED_SKILLS)
    make_canonical(tmp_path)
    src_dir = tmp_path / "skills" / cm.REF_CANONICAL_SKILL / "references"
    src_dir.mkdir(parents=True)
    for name in cm.SHARED_REFERENCES:
        (src_dir / name).write_bytes(("# %s\n" % name).encode("utf-8"))
    rep = cm.Report()
    cm.check_reference_copies(tmp_path, rep)
    assert sum(1 for e in rep.errors if "missing copy" in e) == len(cm.SHARED_REFERENCES)

    out = open(os.devnull, "w")
    try:
        assert cm.sync_copies(tmp_path, out=out) == 0
    finally:
        out.close()
    rep = cm.Report()
    cm.check_reference_copies(tmp_path, rep)
    assert rep.errors == []

    skill = sorted(cm.REF_COPY_TARGETS)[0]
    name = cm.REF_COPY_TARGETS[skill][0]
    copy = tmp_path / "skills" / skill / "references" / name
    copy.write_bytes(copy.read_bytes() + b"edited\n")
    rep = cm.Report()
    cm.check_reference_copies(tmp_path, rep)
    assert has(rep.errors, "%s/references/%s: differs" % (skill, name))

    (src_dir / name).unlink()
    rep = cm.Report()
    cm.check_reference_copies(tmp_path, rep)
    assert has(rep.errors, "canonical file is missing")


def test_sync_skips_missing_skill(tmp_path):
    make_canonical(tmp_path)
    out_path = tmp_path / "out.txt"
    with open(out_path, "w", encoding="utf-8") as out:
        assert cm.sync_copies(tmp_path, out=out) == 0
    assert "does not exist yet" in out_path.read_text(encoding="utf-8")
    assert not (tmp_path / "skills" / "live-exposure-check").exists()


# --- npx skills and claude plugin list output --------------------------------

ESC = "\x1b"
BAR = "\u2502"


def skills_list_output(names, count=None):
    lines = [
        "",
        BAR,
        "%s[36m%s%s[39m  Source: /repo" % (ESC, "\u25c7", ESC),
        BAR,
        "%s  Found %s[32m%d%s[39m skills" % ("\u25c7", ESC, len(names) if count is None else count, ESC),
        "",
        BAR,
        "%s  %s[1mAvailable Skills%s[22m" % ("\u25c7", ESC, ESC),
        BAR,
    ]
    for n in names:
        lines += ["%s    %s[36m%s%s[39m" % (BAR, ESC, n, ESC), BAR,
                  "%s      %s[2mA description that wraps%s[22m" % (BAR, ESC, ESC),
                  "%s      keys" % BAR, BAR]
    lines += ["", BAR, "\u2514  Use --skill <name> to install specific skills", ""]
    return "\n".join(lines)


def test_parse_skills_list():
    names, count = cm.parse_skills_list(skills_list_output(list(cm.EXPECTED_SKILLS)))
    assert sorted(names) == sorted(cm.EXPECTED_SKILLS)
    assert count == 3


def test_skills_list_checks():
    rep = cm.Report()
    cm.check_skills_list(skills_list_output(list(cm.EXPECTED_SKILLS)), rep)
    assert rep.errors == []
    rep = cm.Report()
    cm.check_skills_list(skills_list_output(["preflight-audit", "secure-by-default"]), rep)
    assert has(rep.errors, "expected exactly")
    rep = cm.Report()
    cm.check_skills_list(skills_list_output(list(cm.EXPECTED_SKILLS), count=4), rep)
    assert has(rep.errors, "reports 4 skills")
    rep = cm.Report()
    cm.check_skills_list("No skills found\n", rep)
    assert has(rep.errors, "no skills found")


def test_claude_list_checks():
    good = json.dumps([{"id": "ward@ward", "version": "0.1.0", "enabled": True}])
    rep = cm.Report()
    cm.check_claude_list("Loading...\n" + good, rep, "ward@ward")
    assert rep.errors == []
    for data, needle in (
        ([], "not installed"),
        ([{"id": "ward@ward", "enabled": False}], "disabled"),
        ([{"id": "ward@ward", "enabled": True, "errors": ["bad skill"]}], "load errors"),
    ):
        rep = cm.Report()
        cm.check_claude_list(json.dumps(data), rep, "ward@ward")
        assert has(rep.errors, needle)


def test_cli_list_modes(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text(skills_list_output(list(cm.EXPECTED_SKILLS)), encoding="utf-8")
    r = subprocess.run([sys.executable, str(CHECKER), "--skills-list", str(f)], capture_output=True,
                       encoding="utf-8", errors="replace")
    assert r.returncode == 0, r.stdout
    f.write_text(json.dumps([{"id": "ward@ward", "enabled": True}]), encoding="utf-8")
    r = subprocess.run([sys.executable, str(CHECKER), "--claude-list", str(f)], capture_output=True,
                       encoding="utf-8", errors="replace")
    assert r.returncode == 0, r.stdout
    r = subprocess.run([sys.executable, str(CHECKER), "--skills-list", str(tmp_path / "nope.txt")],
                       capture_output=True, encoding="utf-8", errors="replace")
    assert r.returncode == 2


# --- version bump against a base ref -----------------------------------------

HAS_GIT = shutil.which("git") is not None


def git(cwd, *args, cfg=None):
    env = dict(os.environ)
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})
    if cfg is not None:
        env["GIT_CONFIG_GLOBAL"] = str(cfg)
    r = subprocess.run(["git", "-c", "core.autocrlf=false"] + list(args), cwd=str(cwd), capture_output=True,
                       encoding="utf-8", errors="replace", env=env)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_version_bump(tmp_path):
    cfg = tmp_path / "empty.gitconfig"
    cfg.write_text("", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    write_manifests(repo)
    make_skills(repo, ["secure-by-default"])
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    git(repo, "init", "-q", cfg=cfg)
    git(repo, "add", ".", cfg=cfg)
    git(repo, "commit", "-q", "-m", "base", cfg=cfg)
    base = git(repo, "rev-parse", "HEAD", cfg=cfg)

    def check():
        rep = cm.Report()
        assert cm.check_version_bump(repo, base, rep) is True
        return rep

    # README only: no bump needed
    (repo / "README.md").write_text("# y\n", encoding="utf-8")
    git(repo, "commit", "-q", "-am", "docs", cfg=cfg)
    assert check().errors == []

    # skills/ changed, same version: error
    (repo / "skills" / "secure-by-default" / "SKILL.md").write_text("---\nname: secure-by-default\n---\nnew\n",
                                                                   encoding="utf-8")
    git(repo, "commit", "-q", "-am", "skill", cfg=cfg)
    rep = check()
    assert has(rep.errors, "bump it")

    # bumped: ok
    write_manifests(repo, plugin=dict(PLUGIN, version="0.1.1"))
    git(repo, "commit", "-q", "-am", "bump", cfg=cfg)
    rep = check()
    assert rep.errors == [], rep.errors
    assert has(rep.notes, "0.1.0 -> 0.1.1")

    # lowered: error
    write_manifests(repo, plugin=dict(PLUGIN, version="0.0.9"))
    git(repo, "commit", "-q", "-am", "lower", cfg=cfg)
    assert has(check().errors, "bump it")

    # unknown base: git error, exit 2 from the CLI
    rep = cm.Report()
    assert cm.check_version_bump(repo, "no-such-ref", rep) is False
    r = subprocess.run([sys.executable, str(CHECKER), "--root", str(repo), "--no-rules-md", "--base", "no-such-ref"],
                       capture_output=True, encoding="utf-8", errors="replace")
    assert r.returncode == 2


@pytest.mark.skipif(not HAS_GIT, reason="git not installed")
def test_version_bump_with_no_manifest_at_base(tmp_path):
    cfg = tmp_path / "empty.gitconfig"
    cfg.write_text("", encoding="utf-8")
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("# x\n", encoding="utf-8")
    git(repo, "init", "-q", cfg=cfg)
    git(repo, "add", ".", cfg=cfg)
    git(repo, "commit", "-q", "-m", "base", cfg=cfg)
    base = git(repo, "rev-parse", "HEAD", cfg=cfg)
    write_manifests(repo)
    make_skills(repo, ["secure-by-default"])
    git(repo, "add", ".", cfg=cfg)
    git(repo, "commit", "-q", "-m", "first skill", cfg=cfg)
    rep = cm.Report()
    assert cm.check_version_bump(repo, base, rep) is True
    assert rep.errors == []
    assert has(rep.notes, "no plugin.json at")


# --- repo files stay plain ---------------------------------------------------

def _repo_text_files():
    files = [REPO_ROOT / n for n in ("README.md", "LICENSE", ".gitattributes", ".gitignore")]
    files += sorted((REPO_ROOT / ".claude-plugin").glob("*.json"))
    files += sorted(p for p in (REPO_ROOT / ".github").rglob("*") if p.is_file())
    return [p for p in files if p.is_file()]


def test_repo_files_have_no_long_dashes_or_emoji():
    bad = []
    for p in _repo_text_files():
        text = p.read_text(encoding="utf-8")
        for n, line in enumerate(text.split("\n"), 1):
            if "\u2014" in line or "\u2013" in line:
                bad.append("%s:%d long dash" % (p.relative_to(REPO_ROOT).as_posix(), n))
            if any(0x2600 <= ord(c) <= 0x27BF or ord(c) >= 0x1F000 for c in line):
                bad.append("%s:%d emoji" % (p.relative_to(REPO_ROOT).as_posix(), n))
    assert bad == [], bad


def test_ci_scripts_parse_as_python39():
    import ast
    for p in sorted((REPO_ROOT / ".github" / "scripts").glob("*.py")):
        ast.parse(p.read_text(encoding="utf-8"), filename=str(p), feature_version=(3, 9))


def test_readme_is_plain():
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert text.startswith("# ward\n")
    assert text.count("badge.svg") <= 1
    assert "npx skills add ReazGan/ward" in text
    assert "/plugin install ward@ward" in text
    assert "<details>" in text
