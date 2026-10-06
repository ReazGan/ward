"""Check the plugin and marketplace manifests and the packaging invariants.

Usage:
  python .github/scripts/check_manifests.py [--root DIR] [--base REF]
  python .github/scripts/check_manifests.py --sync
  python .github/scripts/check_manifests.py --skills-list FILE
  python .github/scripts/check_manifests.py --claude-list FILE

Default run:
  - .claude-plugin/plugin.json: valid name, semver version, URL homepage,
    author without email, no skills key, no hooks/agents/commands/MCP
  - .claude-plugin/marketplace.json: valid, not reserved name, one entry with
    the plugin's name, source "./", and no version (it lives in plugin.json)
  - skills/ holds exactly the expected skills
  - the shared scripts copied into other skills are byte-identical to the
    canonical files in skills/preflight-audit/scripts/
  - the secure-by-default references that preflight-audit rules point at are
    copied byte for byte into skills/preflight-audit/references/
  - references/rules.md matches gen_rules_md.py output
  - with --base REF: if the change touches skills/, the version was raised

--sync copies the canonical shared scripts and references into the skills
that need them.
--skills-list FILE checks saved output of "npx skills add . --list".
--claude-list FILE checks saved output of "claude plugin list --json".

Exit codes: 0 ok, 1 problems found, 2 usage or runtime error.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

EXPECTED_SKILLS = ("secure-by-default", "preflight-audit", "live-exposure-check")

CANONICAL_SKILL = "preflight-audit"
SHARED_FILES = ("_wardcore.py", "_secret_patterns.py", "find_secrets.py")
# Which skills carry copies of which shared files.
COPY_TARGETS = {"live-exposure-check": SHARED_FILES}

# Reference files written for secure-by-default that preflight-audit rules
# also point at. Copied so a preflight-audit-only install can follow every
# fix_ref. The canonical copy lives in secure-by-default.
REF_CANONICAL_SKILL = "secure-by-default"
SHARED_REFERENCES = ("data-and-auth.md", "secrets.md", "payments-and-abuse.md", "uploads-and-fetch.md")
REF_COPY_TARGETS = {"preflight-audit": SHARED_REFERENCES}

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
                       r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
                       r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")
KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

PLUGIN_KEYS = ("$schema", "name", "displayName", "version", "description", "author", "homepage",
               "repository", "license", "keywords")
# Component keys this pack does not ship in v1 (they would load always-on parts).
PLUGIN_COMPONENT_KEYS = ("commands", "agents", "hooks", "mcpServers", "lspServers", "outputStyles",
                         "monitors", "workflows", "themes", "settings", "userConfig")
RESERVED_PLUGIN_NAMES = ("claude", "anthropic", "anthropics", "claude-code", "claude-mods")
RESERVED_PLUGIN_PREFIXES = ("claude-", "anthropic-", "anthropics-", "cc-plugin-")
RESERVED_MARKETPLACES = (
    "claude-code-marketplace", "claude-code-plugins", "claude-plugins-official", "anthropic-marketplace",
    "anthropic-plugins", "agent-skills", "anthropic-agent-skills", "claude-community", "inline", "builtin",
    "skills-dir", "synced", "npm", "pip", "uv", "cargo", "github", "gh",
)
MARKETPLACE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")


class Report:
    """Collects errors and warnings with a short source label."""

    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.notes: List[str] = []

    def error(self, where: str, msg: str) -> None:
        self.errors.append("%s: %s" % (where, msg))

    def warn(self, where: str, msg: str) -> None:
        self.warnings.append("%s: %s" % (where, msg))

    def note(self, msg: str) -> None:
        self.notes.append(msg)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(path: Path, rep: Report, label: str) -> Optional[Any]:
    if not path.is_file():
        rep.error(label, "missing")
        return None
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        rep.error(label, "starts with a UTF-8 BOM")
        raw = raw[3:]
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        rep.error(label, "not valid JSON: %s" % exc)
        return None


def parse_semver(v: Any) -> Optional[Tuple[Tuple[int, int, int], Tuple[Any, ...]]]:
    """(major, minor, patch), prerelease parts; None if not semver."""
    if not isinstance(v, str):
        return None
    m = SEMVER_RE.match(v)
    if not m:
        return None
    core = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    pre: Tuple[Any, ...] = ()
    if m.group(4):
        pre = tuple(int(p) if p.isdigit() else p for p in m.group(4).split("."))
    return core, pre


def semver_gt(a: str, b: str) -> bool:
    """a > b by semver precedence (build metadata ignored)."""
    pa, pb = parse_semver(a), parse_semver(b)
    if pa is None or pb is None:
        return False
    if pa[0] != pb[0]:
        return pa[0] > pb[0]
    if not pa[1] and pb[1]:
        return True
    if pa[1] and not pb[1]:
        return False
    for x, y in zip(pa[1], pb[1]):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return x > y
        if isinstance(x, int):
            return False
        if isinstance(y, int):
            return True
        return x > y
    return len(pa[1]) > len(pb[1])


def _is_url(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parts = urlsplit(value)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _has_key(obj: Any, key: str) -> bool:
    if isinstance(obj, dict):
        return key in obj or any(_has_key(v, key) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_key(v, key) for v in obj)
    return False


# ---------------------------------------------------------------------------
# Manifest checks
# ---------------------------------------------------------------------------

def check_plugin_json(root: Path, rep: Report) -> Optional[Dict[str, Any]]:
    label = ".claude-plugin/plugin.json"
    data = load_json(root / ".claude-plugin" / "plugin.json", rep, label)
    if data is None:
        return None
    if not isinstance(data, dict):
        rep.error(label, "must be a JSON object")
        return None
    for k in data:
        if k in PLUGIN_COMPONENT_KEYS:
            rep.error(label, "%r is set; this pack ships skills only (no always-on components)" % k)
        elif k == "skills":
            rep.error(label, "remove \"skills\": skills/ is scanned by default and the key adds paths")
        elif k not in PLUGIN_KEYS:
            rep.warn(label, "unknown key %r (Claude Code strips it)" % k)

    name = data.get("name")
    if not isinstance(name, str) or not name:
        rep.error(label, "name is required")
    else:
        if not KEBAB_RE.match(name):
            rep.error(label, "name %r must be kebab-case" % name)
        if len(name) > 128:
            rep.error(label, "name is longer than 128 characters")
        if name in RESERVED_PLUGIN_NAMES or name.startswith(RESERVED_PLUGIN_PREFIXES):
            rep.error(label, "name %r is reserved" % name)
        elif re.search(r"(?:^|-)(?:claude|anthropic)(?:-|$)", name):
            rep.warn(label, "name %r contains claude or anthropic as a word" % name)

    version = data.get("version")
    if version is None:
        rep.error(label, "version is required (claude plugin validate --strict needs it)")
    elif parse_semver(version) is None:
        rep.error(label, "version %r is not semver (X.Y.Z)" % (version,))

    if not isinstance(data.get("description"), str) or not data["description"].strip():
        rep.error(label, "description is required")
    elif "<" in data["description"] or ">" in data["description"]:
        rep.error(label, "description must not contain < or >")

    author = data.get("author")
    if not isinstance(author, dict) or not isinstance(author.get("name"), str) or not author["name"].strip():
        rep.error(label, "author.name is required")
    else:
        if "email" in author:
            rep.error(label, "omit author.email (an empty value breaks loading, a real one publishes an address)")
        if "url" in author and not _is_url(author["url"]):
            rep.error(label, "author.url must be an http(s) URL")
    if "homepage" in data and not _is_url(data["homepage"]):
        rep.error(label, "homepage must parse as an http(s) URL or the plugin fails to load")
    if "repository" in data and not isinstance(data["repository"], str):
        rep.error(label, "repository must be a string")
    if not data.get("license"):
        rep.warn(label, "no license")
    kw = data.get("keywords")
    if kw is not None and (not isinstance(kw, list) or not all(isinstance(x, str) for x in kw)):
        rep.error(label, "keywords must be a list of strings")
    return data


def check_marketplace_json(root: Path, rep: Report, plugin: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    label = ".claude-plugin/marketplace.json"
    data = load_json(root / ".claude-plugin" / "marketplace.json", rep, label)
    if data is None:
        return None
    if not isinstance(data, dict):
        rep.error(label, "must be a JSON object")
        return None

    name = data.get("name")
    if not isinstance(name, str) or not name:
        rep.error(label, "name is required")
    else:
        if not name.isascii() or not MARKETPLACE_NAME_RE.match(name) or ".." in name:
            rep.error(label, "name %r: letters, digits, '.', '_' and '-' only, starting alphanumeric" % name)
        if name.lower() in RESERVED_MARKETPLACES or name.lower().startswith("claudeai-"):
            rep.error(label, "name %r is reserved" % name)
        elif re.search(r"(?i)(?:claude|anthropic).*official|official.*(?:claude|anthropic)", name):
            rep.error(label, "name %r looks like an official marketplace" % name)

    owner = data.get("owner")
    if not isinstance(owner, dict) or not isinstance(owner.get("name"), str) or not owner["name"].strip():
        rep.error(label, "owner.name is required")
    elif "email" in owner:
        rep.error(label, "omit owner.email")

    if "version" in data or (isinstance(data.get("metadata"), dict) and "version" in data["metadata"]):
        rep.error(label, "version belongs in plugin.json only")

    plugins = data.get("plugins")
    if not isinstance(plugins, list) or not plugins:
        rep.error(label, "plugins must be a non-empty list")
        return data
    if len(plugins) != 1:
        rep.error(label, "expected exactly one plugin entry, found %d" % len(plugins))
    for i, entry in enumerate(plugins):
        where = "%s plugins[%d]" % (label, i)
        if not isinstance(entry, dict):
            rep.error(where, "must be an object")
            continue
        if plugin is not None and entry.get("name") != plugin.get("name"):
            rep.error(where, "name %r must equal plugin.json name %r, or /plugin install fails"
                      % (entry.get("name"), plugin.get("name")))
        if entry.get("source") != "./":
            rep.error(where, "source must be \"./\" (the repo root is the plugin), found %r" % (entry.get("source"),))
        if "version" in entry:
            rep.error(where, "remove version: it lives in plugin.json only, a second copy draws a validate warning")
        if "skills" in entry:
            rep.error(where, "remove skills: with a root source it limits loading to the listed folders")
        if "strict" in entry:
            rep.warn(where, "strict is set; the plugin.json manifest is the source of truth here")
        if not isinstance(entry.get("description"), str) or not entry["description"].strip():
            rep.warn(where, "no description")
        elif "<" in entry["description"] or ">" in entry["description"]:
            rep.error(where, "description must not contain < or >")
    owner_email = isinstance(owner, dict) and "email" in owner
    if not owner_email and _has_key(data, "email"):
        rep.error(label, "remove email fields")
    return data


def check_skill_set(root: Path, rep: Report) -> None:
    skills = root / "skills"
    if not skills.is_dir():
        rep.error("skills/", "missing")
        return
    found = sorted(p.name for p in skills.iterdir() if p.is_dir() and not p.name.startswith("."))
    missing = [s for s in EXPECTED_SKILLS if s not in found]
    extra = [s for s in found if s not in EXPECTED_SKILLS]
    for s in missing:
        rep.error("skills/", "expected skill %s is missing" % s)
    for s in extra:
        rep.error("skills/", "unexpected skill folder %s (add it to EXPECTED_SKILLS if it is meant to ship)" % s)
    for s in found:
        if not (skills / s / "SKILL.md").is_file():
            rep.error("skills/%s" % s, "no SKILL.md")


def check_copies(root: Path, rep: Report) -> None:
    canon_dir = root / "skills" / CANONICAL_SKILL / "scripts"
    canon: Dict[str, bytes] = {}
    for name in SHARED_FILES:
        p = canon_dir / name
        if not p.is_file():
            rep.error("skills/%s/scripts/%s" % (CANONICAL_SKILL, name), "canonical file is missing")
            continue
        canon[name] = p.read_bytes()
    skills = root / "skills"
    if not skills.is_dir():
        return
    for skill in sorted(p for p in skills.iterdir() if p.is_dir() and p.name != CANONICAL_SKILL):
        wanted = COPY_TARGETS.get(skill.name, ())
        for name in SHARED_FILES:
            copy = skill / "scripts" / name
            label = "skills/%s/scripts/%s" % (skill.name, name)
            if not copy.is_file():
                if name in wanted:
                    rep.error(label, "missing copy (run: python .github/scripts/check_manifests.py --sync)")
                continue
            if name in canon and copy.read_bytes() != canon[name]:
                rep.error(label, "differs from skills/%s/scripts/%s (run --sync; never edit a copy)"
                          % (CANONICAL_SKILL, name))


def check_reference_copies(root: Path, rep: Report) -> None:
    canon_dir = root / "skills" / REF_CANONICAL_SKILL / "references"
    for skill, names in sorted(REF_COPY_TARGETS.items()):
        for name in names:
            src = canon_dir / name
            if not src.is_file():
                rep.error("skills/%s/references/%s" % (REF_CANONICAL_SKILL, name), "canonical file is missing")
                continue
            copy = root / "skills" / skill / "references" / name
            label = "skills/%s/references/%s" % (skill, name)
            if not copy.is_file():
                rep.error(label, "missing copy (run: python .github/scripts/check_manifests.py --sync)")
            elif copy.read_bytes() != src.read_bytes():
                rep.error(label, "differs from skills/%s/references/%s (run --sync; never edit a copy)"
                          % (REF_CANONICAL_SKILL, name))


def _sync_references(root: Path, out: Any) -> int:
    canon_dir = root / "skills" / REF_CANONICAL_SKILL / "references"
    changed = 0
    for skill, names in sorted(REF_COPY_TARGETS.items()):
        skill_dir = root / "skills" / skill
        if not skill_dir.is_dir():
            out.write("skip %s: skill folder does not exist yet\n" % skill)
            continue
        for name in names:
            src = canon_dir / name
            if not src.is_file():
                out.write("skip %s: skills/%s/references/%s does not exist yet\n"
                          % (name, REF_CANONICAL_SKILL, name))
                continue
            data = src.read_bytes()
            dest = skill_dir / "references" / name
            if dest.is_file() and dest.read_bytes() == data:
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            changed += 1
            out.write("copied %s -> skills/%s/references/%s\n" % (name, skill, name))
    return changed


def sync_copies(root: Path, out: Any = None) -> int:
    """Copy the canonical shared scripts into each skill in COPY_TARGETS and
    the shared references into each skill in REF_COPY_TARGETS."""
    out = out or sys.stdout
    canon_dir = root / "skills" / CANONICAL_SKILL / "scripts"
    changed = 0
    for skill, names in sorted(COPY_TARGETS.items()):
        skill_dir = root / "skills" / skill
        if not skill_dir.is_dir():
            out.write("skip %s: skill folder does not exist yet\n" % skill)
            continue
        dest_dir = skill_dir / "scripts"
        dest_dir.mkdir(parents=True, exist_ok=True)
        for name in names:
            src = canon_dir / name
            if not src.is_file():
                out.write("error: canonical %s is missing\n" % src.as_posix())
                return 2
            data = src.read_bytes()
            dest = dest_dir / name
            if dest.is_file() and dest.read_bytes() == data:
                continue
            dest.write_bytes(data)
            changed += 1
            out.write("copied %s -> skills/%s/scripts/%s\n" % (name, skill, name))
    changed += _sync_references(root, out)
    out.write("%d file%s updated\n" % (changed, "" if changed == 1 else "s"))
    return 0


def check_rules_md(root: Path, rep: Report) -> None:
    gen = root / "skills" / CANONICAL_SKILL / "scripts" / "gen_rules_md.py"
    if not gen.is_file():
        rep.error("gen_rules_md.py", "missing")
        return
    r = subprocess.run([sys.executable, str(gen), "--check"], cwd=str(root), capture_output=True,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip().splitlines()
        rep.error("skills/%s/references/rules.md" % CANONICAL_SKILL,
                  "out of date or not generated: %s" % (detail[-1] if detail else "exit %d" % r.returncode))


def check_version_consistency(root: Path, rep: Report, plugin: Optional[Dict[str, Any]]) -> None:
    """Warn when the version strings shown to users drift from plugin.json."""
    if not plugin or not isinstance(plugin.get("version"), str):
        return
    want = plugin["version"]
    core = root / "skills" / CANONICAL_SKILL / "scripts" / "_wardcore.py"
    if core.is_file():
        m = re.search(r'^VERSION\s*=\s*["\']([^"\']+)["\']', core.read_text(encoding="utf-8", errors="replace"), re.M)
        if m and m.group(1) != want:
            rep.warn("_wardcore.py", "VERSION %s differs from plugin.json %s" % (m.group(1), want))
    for skill in EXPECTED_SKILLS:
        md = root / "skills" / skill / "SKILL.md"
        if not md.is_file():
            continue
        text = md.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        fm = re.match(r"^---\n(.*?)\n---(?:\n|$)", text, re.S)
        if not fm:
            continue
        m = re.search(r"^[ ]+version:\s*[\"']?([^\"'\s]+)", fm.group(1), re.M)
        if m and m.group(1) != want:
            rep.warn("skills/%s/SKILL.md" % skill, "metadata.version %s differs from plugin.json %s"
                     % (m.group(1), want))


def _git(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git"] + list(args), cwd=str(root), capture_output=True, encoding="utf-8",
                          errors="replace")


def check_version_bump(root: Path, base: str, rep: Report) -> bool:
    """On a change that touches skills/, plugin.json version must be higher than at base.
    Returns False on a git error (the caller exits 2)."""
    if shutil.which("git") is None:
        rep.error("--base", "git is not installed")
        return False
    r = _git(root, "rev-parse", "--verify", "--quiet", base + "^{commit}")
    if r.returncode != 0:
        rep.error("--base", "cannot resolve %r (fetch it, for example with fetch-depth: 0)" % base)
        return False
    r = _git(root, "diff", "--name-only", base + "...HEAD")
    if r.returncode != 0:
        rep.error("--base", "git diff failed: %s" % r.stderr.strip())
        return False
    changed = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    touched = [p for p in changed if p.startswith("skills/")]
    if not touched:
        rep.note("version check: no changes under skills/ since %s" % base)
        return True
    r = _git(root, "show", "%s:.claude-plugin/plugin.json" % base)
    if r.returncode != 0:
        rep.note("version check: no plugin.json at %s, nothing to compare" % base)
        return True
    try:
        old = json.loads(r.stdout).get("version")
    except (ValueError, AttributeError):
        old = None
    cur = load_json(root / ".claude-plugin" / "plugin.json", Report(), "plugin.json") or {}
    new = cur.get("version") if isinstance(cur, dict) else None
    if not isinstance(old, str) or parse_semver(old) is None:
        rep.note("version check: base version %r is not semver, skipped" % (old,))
        return True
    if not isinstance(new, str) or not semver_gt(new, old):
        rep.error(".claude-plugin/plugin.json",
                  "%d file%s under skills/ changed since %s but version is %s (base %s); bump it, "
                  "or users never receive the change" % (len(touched), "" if len(touched) == 1 else "s",
                                                         base, new, old))
    else:
        rep.note("version check: %s -> %s" % (old, new))
    return True


# ---------------------------------------------------------------------------
# Saved CLI output checks
# ---------------------------------------------------------------------------

def parse_skills_list(text: str) -> Tuple[List[str], Optional[int]]:
    """Skill names and the "Found N skills" count from "npx skills add . --list" output."""
    clean = _ANSI.sub("", text).replace("\r", "")
    count = None
    m = re.search(r"Found\s+(\d+)\s+skills?", clean)
    if m:
        count = int(m.group(1))
    names: List[str] = []
    started = False
    for line in clean.split("\n"):
        if "Available Skills" in line:
            started = True
            continue
        if not started:
            continue
        # names sit at a shallow indent after the box rule; descriptions are deeper
        m = re.match(r"^[\u2502|]?(?: {1,4})([a-z0-9]+(?:-[a-z0-9]+)*)\s*$", line)
        if m and m.group(1) not in names:
            names.append(m.group(1))
    return names, count


def check_skills_list(text: str, rep: Report) -> None:
    names, count = parse_skills_list(text)
    label = "npx skills add . --list"
    if not names:
        rep.error(label, "no skills found in the output")
        return
    if sorted(names) != sorted(EXPECTED_SKILLS):
        rep.error(label, "discovered %s, expected exactly %s" % (", ".join(sorted(names)),
                                                                 ", ".join(sorted(EXPECTED_SKILLS))))
    if count is not None and count != len(EXPECTED_SKILLS):
        rep.error(label, "reports %d skills, expected %d" % (count, len(EXPECTED_SKILLS)))
    if not rep.errors:
        rep.note("npx skills discovered: %s" % ", ".join(names))


def check_claude_list(text: str, rep: Report, plugin_id: str) -> None:
    label = "claude plugin list --json"
    start = text.find("[")
    try:
        data = json.loads(text[start:]) if start >= 0 else None
    except ValueError as exc:
        rep.error(label, "not valid JSON: %s" % exc)
        return
    if not isinstance(data, list):
        rep.error(label, "expected a JSON list")
        return
    entry = next((e for e in data if isinstance(e, dict) and e.get("id") == plugin_id), None)
    if entry is None:
        rep.error(label, "%s is not installed" % plugin_id)
        return
    if entry.get("enabled") is False:
        rep.error(label, "%s is installed but disabled" % plugin_id)
    errs = entry.get("errors")
    if errs:
        rep.error(label, "%s has load errors: %s" % (plugin_id, json.dumps(errs, ensure_ascii=False)))
    if not rep.errors:
        rep.note("%s %s loads with no errors" % (plugin_id, entry.get("version", "")))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def run_checks(root: Path, base: Optional[str] = None, rules_md: bool = True) -> Tuple[Report, bool]:
    """Run the default checks. Returns (report, ok_to_trust) where ok_to_trust is
    False when a git error stopped the version check."""
    rep = Report()
    plugin = check_plugin_json(root, rep)
    check_marketplace_json(root, rep, plugin)
    check_skill_set(root, rep)
    check_copies(root, rep)
    check_reference_copies(root, rep)
    if rules_md:
        check_rules_md(root, rep)
    check_version_consistency(root, rep, plugin)
    ok = True
    if base:
        ok = check_version_bump(root, base, rep)
    return rep, ok


def _print(rep: Report) -> None:
    for n in rep.notes:
        sys.stdout.write("note: %s\n" % n)
    for w in rep.warnings:
        sys.stdout.write("warning: %s\n" % w)
    for e in rep.errors:
        sys.stdout.write("error: %s\n" % e)
    sys.stdout.write("%d error%s, %d warning%s\n" % (len(rep.errors), "" if len(rep.errors) == 1 else "s",
                                                   len(rep.warnings), "" if len(rep.warnings) == 1 else "s"))


def _read_file(path: str) -> Optional[str]:
    try:
        return Path(path).read_bytes().decode("utf-8", errors="replace")
    except OSError as exc:
        sys.stderr.write("error: cannot read %s: %s\n" % (path, exc))
        return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    ap = argparse.ArgumentParser(prog="check_manifests.py",
                                 description="Check plugin/marketplace manifests and packaging invariants.")
    ap.add_argument("--root", default=str(REPO_ROOT), help="repo root (default: this repo)")
    ap.add_argument("--base", metavar="REF", help="git ref to compare the version against (pull requests)")
    ap.add_argument("--no-rules-md", action="store_true", help="skip the rules.md freshness check")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--sync", action="store_true", help="copy the canonical shared scripts and references into other skills")
    mode.add_argument("--skills-list", metavar="FILE", help="check saved 'npx skills add . --list' output")
    mode.add_argument("--claude-list", metavar="FILE", help="check saved 'claude plugin list --json' output")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        sys.stderr.write("error: %s is not a folder\n" % root.as_posix())
        return 2

    if args.sync:
        return sync_copies(root)

    if args.skills_list:
        text = _read_file(args.skills_list)
        if text is None:
            return 2
        rep = Report()
        check_skills_list(text, rep)
        _print(rep)
        return 1 if rep.errors else 0

    if args.claude_list:
        text = _read_file(args.claude_list)
        if text is None:
            return 2
        rep = Report()
        plugin = check_plugin_json(root, Report()) or {}
        market = load_json(root / ".claude-plugin" / "marketplace.json", Report(), "marketplace.json") or {}
        plugin_id = "%s@%s" % (plugin.get("name", "?"), market.get("name", "?") if isinstance(market, dict) else "?")
        check_claude_list(text, rep, plugin_id)
        _print(rep)
        return 1 if rep.errors else 0

    rep, ok = run_checks(root, base=args.base, rules_md=not args.no_rules_md)
    _print(rep)
    if not ok:
        return 2
    return 1 if rep.errors else 0


if __name__ == "__main__":
    sys.exit(main())
