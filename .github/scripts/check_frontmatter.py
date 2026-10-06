"""Check every SKILL.md against the Agent Skills spec and this pack's rules.

Usage:
  python .github/scripts/check_frontmatter.py [PATH ...]

PATH is a repo root (a folder with skills/) or a single skill folder (a folder
with SKILL.md). The default is the repo this script lives in.

What it checks, per skill:
  - the file is named exactly SKILL.md, UTF-8, LF line endings, no BOM
  - line 1 is "---" and the frontmatter is closed by another "---"
  - only the Agent Skills keys: name, description, license, compatibility,
    metadata, allowed-tools; single-line scalars plus the metadata map
  - name: lowercase and dashes, at most 64 chars, equal to the folder name,
    not a Claude Code built-in command, no "claude" or "anthropic"
  - description: double-quoted, 1-1024 chars, no < or > (warns outside 150-400)
  - compatibility at most 500 chars, metadata values are strings
  - body at most 500 lines
  - every scripts/*.py and references/*.md the body names exists, and every
    relative link in SKILL.md and references/*.md points to a file inside
    the skill folder
  - no hardcoded home folder paths (C:\\Users\\..., /Users/...) in SKILL.md
    and references, no em or en dashes and no emoji in any shipped text
    or script
  - commands shown for scripts are a single program call (no pipes, $(...),
    &&, 2>/dev/null, heredocs), so they run the same in bash and PowerShell
Per repo:
  - every folder in skills/ has a SKILL.md
  - nothing at the repo root that Claude Code would load as a plugin
    component (hooks/, agents/, commands/, bin/, .mcp.json, CLAUDE.md, ...)

Exit codes: 0 no errors (warnings are printed), 1 errors, 2 usage error.
Standard library only.
"""

from __future__ import annotations

import json
import re
import sys
from collections import namedtuple
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

ALLOWED_KEYS = ("name", "description", "license", "compatibility", "metadata", "allowed-tools")

# Keys people add that break skills-ref, claude.ai uploads and the Skills API.
KEY_HINTS = {
    "version": "use metadata.version instead of a top-level version",
    "argument-hint": "Claude Code only, breaks skills-ref, claude.ai and the Skills API",
    "when_to_use": "Claude Code only, breaks skills-ref, claude.ai and the Skills API",
    "disable-model-invocation": "Claude Code only, breaks skills-ref, claude.ai and the Skills API",
    "user-invocable": "Claude Code only, breaks skills-ref, claude.ai and the Skills API",
}

NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Claude Code built-in commands and bundled skills (code.claude.com/docs/en/commands,
# 2026-10-05). A loose install of a skill with one of these names replaces it.
BUILTIN_NAMES = frozenset("""
add-dir advisor agents artifact-capabilities artifact-diagramming artifacts auto-mode-setup
autocompact autofix-pr background batch branch btw bug cd chrome claude-api claude-in-chrome
clear code-review color compact config context copy cost dataviz debug deep-research design
design-login design-sync desktop diff doctor effort exit export fast feedback
fewer-permission-prompts focus fork goal heapdump help hooks ide import init insights
install-github-app install-slack-app keybindings list-agents login logout loop mcp memory mobile
model output-style passes permissions plan plugin plugin-authoring powerup pr-comments
privacy-settings radio rate-limit-options recap release-notes reload-plugins reload-skills
remote-control remote-env rename resume review rewind run run-skill-generator sandbox schedule
scroll-speed security-review setup-bedrock setup-vertex simplify skill-doctor skills slides stats
status statusline stickers stop subtask tasks team-onboarding teleport terminal-setup theme tui
ultraplan ultrareview update-config upgrade usage usage-credits verify vim voice web-setup
workflow-authoring workflows
""".split())

RESERVED_NAMES = frozenset({"synced", "skills-dir", "inline", "builtin"})

# Root entries that load as plugin components when the marketplace source is "./".
ROOT_FORBIDDEN_DIRS = ("hooks", "agents", "commands", "bin", "output-styles", "monitors",
                       "workflows", "themes")
ROOT_FORBIDDEN_FILES = (".mcp.json", ".lsp.json", "settings.json", "CLAUDE.md", "SKILL.md")

# The standing-rules header every body opens with (spec section 2).
STANDING_RULES = (
    "Paths in this file are relative to this skill's folder.",
    "Run a script and read its output; do not read the script's source",
    "If python3 is missing or prints \"Python was not found\" (Windows), use py -3 or python.",
    "Runtime checks run only against an app you own",
)

MAX_BODY_LINES = 500
MAX_DESCRIPTION = 1024
DESC_WARN_LONG = 400
DESC_WARN_SHORT = 150
MAX_COMPATIBILITY = 500

DASHES = ("\u2014", "\u2013")
_INLINE_CODE = re.compile(r"(`+)(?:(?!\1).)+?\1")
_LINK_RE = re.compile(r"!?\[[^\]\n]*\]\(\s*<?([^)\s>]+)>?(?:\s+[\"'][^\"'\n]*[\"'])?\s*\)")
_MENTION_RE = re.compile(r"(?<![\w./-])((?:scripts/[\w.-]+\.py)|(?:references/[\w.-]+\.md))(?![\w/-])")
# A Windows or macOS home folder. Case-sensitive /Users/ so API routes like
# /users/:id are not flagged.
_HOME_PATH = re.compile(r"\b[A-Za-z]:[\\/]+(?:[Uu]sers|USERS)[\\/]|(?<![\w~.-])/Users/[A-Za-z0-9._-]")
_CMD_START = re.compile(r"^\s*(?:\$\s+)?(?:python3?|py\s+-3|python\.exe)\s")
_BAD_SHELL = (
    ("$(", "command substitution $(...)"),
    ("`", "backticks"),
    (" | ", "a pipe"),
    ("&&", "&& (not in PowerShell 5.1)"),
    ("2>/dev/null", "2>/dev/null"),
    ("<<", "a heredoc"),
    (" ~/", "~ expansion"),
)

Problem = namedtuple("Problem", "level path line message")


def _is_emoji(ch: str) -> bool:
    o = ord(ch)
    return 0x2600 <= o <= 0x27BF or o >= 0x1F000


def _rel(path: Path, base: Optional[Path]) -> str:
    if base is None:
        return path.as_posix()
    try:
        return path.relative_to(base).as_posix()
    except ValueError:
        return path.as_posix()


# ---------------------------------------------------------------------------
# A small YAML subset parser: single-line scalars plus one level of maps.
# ---------------------------------------------------------------------------

Scalar = namedtuple("Scalar", "value kind line")
# kind: "double", "single", "plain", "plain-nonstring", "map"

_PLAIN_NONSTRING = re.compile(
    r"^(?:~|null|Null|NULL|true|True|TRUE|false|False|FALSE|yes|Yes|YES|no|No|NO|on|On|ON|off|Off|OFF"
    r"|[-+]?\d+|[-+]?0x[0-9a-fA-F]+|[-+]?0o[0-7]+|[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?"
    r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$")
_KEY_LINE = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?:\s+(.*?))?\s*$")


def parse_scalar(raw: str) -> Tuple[Optional[Any], str, str]:
    """Parse one YAML scalar. Returns (value, kind, error)."""
    v = raw.strip()
    if not v:
        return "", "plain", ""
    c = v[0]
    if c == '"':
        i, n = 1, len(v)
        while i < n:
            if v[i] == "\\":
                i += 2
                continue
            if v[i] == '"':
                break
            i += 1
        if i >= n:
            return None, "double", "unterminated double-quoted string"
        rest = v[i + 1:].strip()
        if rest and not rest.startswith("#"):
            return None, "double", "text after the closing quote"
        try:
            return json.loads(v[:i + 1]), "double", ""
        except ValueError:
            return None, "double", "unsupported escape in double-quoted string"
    if c == "'":
        out, i, n = [], 1, len(v)
        while i < n:
            if v[i] == "'":
                if i + 1 < n and v[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                break
            out.append(v[i])
            i += 1
        if i >= n:
            return None, "single", "unterminated single-quoted string"
        rest = v[i + 1:].strip()
        if rest and not rest.startswith("#"):
            return None, "single", "text after the closing quote"
        return "".join(out), "single", ""
    if c in "|>":
        return None, "plain", "block scalars (| or >) are not allowed; keep values on one line"
    if c in "[{":
        return None, "plain", "flow lists and maps are not allowed; use a single-line string"
    if c in "&*!%@`" or v.startswith("- ") or v == "-":
        return None, "plain", "unsupported YAML syntax; quote the value"
    m = re.search(r"\s#", v)
    if m:
        v = v[:m.start()].rstrip()
    if ": " in v or v.endswith(":"):
        return None, "plain", "unquoted value contains ': ' (invalid YAML); double-quote it"
    if _PLAIN_NONSTRING.match(v):
        return v, "plain-nonstring", ""
    return v, "plain", ""


def parse_frontmatter(lines: Sequence[str], first_line: int = 2) -> Tuple[Dict[str, Scalar], List[Tuple[int, str]]]:
    """Parse frontmatter lines (without the --- fences).

    Returns ({key: Scalar}, [(line, error)]). A map value is a Scalar whose
    value is {subkey: Scalar} and kind "map".
    """
    data: Dict[str, Scalar] = {}
    errors: List[Tuple[int, str]] = []
    open_map: Optional[Dict[str, Scalar]] = None
    open_key = ""
    for idx, raw in enumerate(lines):
        n = first_line + idx
        if "\t" in raw[:len(raw) - len(raw.lstrip())]:
            errors.append((n, "tab used for indentation"))
            continue
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indented = raw[:1] in (" ",)
        if indented:
            if open_map is None:
                errors.append((n, "unexpected indented line (only metadata may hold nested keys)"))
                continue
            m = _KEY_LINE.match(stripped)
            if not m:
                errors.append((n, "cannot parse %r under %s" % (stripped, open_key)))
                continue
            sub, val = m.group(1), m.group(2)
            if val is None:
                errors.append((n, "%s.%s: nested maps are not allowed" % (open_key, sub)))
                continue
            value, kind, err = parse_scalar(val)
            if err:
                errors.append((n, "%s.%s: %s" % (open_key, sub, err)))
                continue
            if sub in open_map:
                errors.append((n, "duplicate key %s.%s" % (open_key, sub)))
            open_map[sub] = Scalar(value, kind, n)
            continue
        open_map = None
        m = _KEY_LINE.match(stripped)
        if not m:
            errors.append((n, "cannot parse frontmatter line %r" % stripped))
            continue
        key, val = m.group(1), m.group(2)
        if key in data:
            errors.append((n, "duplicate key %s" % key))
        if val is None:
            open_map = {}
            open_key = key
            data[key] = Scalar(open_map, "map", n)
            continue
        value, kind, err = parse_scalar(val)
        if err:
            errors.append((n, "%s: %s" % (key, err)))
            continue
        data[key] = Scalar(value, kind, n)
    return data, errors


# ---------------------------------------------------------------------------
# Per-skill checks
# ---------------------------------------------------------------------------

def _github_anchor(heading: str) -> str:
    text = heading.strip().lower()
    text = re.sub(r"[`*_~]", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"[^\w\- ]", "", text)
    return text.replace(" ", "-")


def _anchors(md_text: str) -> set:
    out = set()
    seen: Dict[str, int] = {}
    in_fence = False
    for line in md_text.split("\n"):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        a = _github_anchor(m.group(1))
        if a in seen:
            seen[a] += 1
            a = "%s-%d" % (a, seen[a])
        else:
            seen[a] = 0
        out.add(a)
    for m in re.finditer(r"<a\s+(?:name|id)=[\"']([^\"']+)[\"']", md_text):
        out.add(m.group(1))
    return out


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def _check_link_target(target: str, from_dir: Path, skill_dir: Path, rel_name: str, line: int,
                       problems: List[Problem], anchor_cache: Dict[Path, set]) -> None:
    t = target.strip()
    if not t or t.startswith("#"):
        return
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", t) and not re.match(r"^[a-zA-Z]:[\\/]", t):
        return  # http:, https:, mailto: and friends
    path_part, _, anchor = t.partition("#")
    path_part = path_part.split("?", 1)[0]
    if not path_part:
        return
    if path_part.startswith(("/", "\\")) or re.match(r"^[a-zA-Z]:[\\/]", path_part):
        problems.append(Problem("error", rel_name, line, "absolute link %r; use a path relative to the skill" % t))
        return
    dest = from_dir / path_part
    if not _inside(dest, skill_dir):
        problems.append(Problem("error", rel_name, line,
                                "link %r leaves the skill folder; skills are installed one folder at a time" % t))
        return
    if not dest.exists():
        problems.append(Problem("error", rel_name, line, "link %r points to a missing file" % t))
        return
    if anchor and dest.is_file() and dest.suffix.lower() == ".md":
        if dest not in anchor_cache:
            try:
                anchor_cache[dest] = _anchors(dest.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                anchor_cache[dest] = set()
        if anchor.lower() not in anchor_cache[dest]:
            problems.append(Problem("warning", rel_name, line, "link %r: no heading with anchor #%s" % (t, anchor)))


def _scan_text_rules(text: str, rel_name: str, problems: List[Problem], paths: bool = True) -> None:
    for n, line in enumerate(text.split("\n"), 1):
        for ch in DASHES:
            if ch in line:
                problems.append(Problem("error", rel_name, n, "contains an em or en dash; use a hyphen, comma or period"))
                break
        if any(_is_emoji(c) for c in line):
            problems.append(Problem("error", rel_name, n, "contains an emoji"))
        if paths and _HOME_PATH.search(line):
            problems.append(Problem("error", rel_name, n, "hardcoded home folder path"))


def _scan_commands(body_lines: Sequence[str], body_start: int, rel_name: str, problems: List[Problem]) -> None:
    in_fence = False
    for i, line in enumerate(body_lines):
        s = line.strip()
        if s.startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if not in_fence:
            continue
        n = body_start + i
        if re.match(r"^\s*(?:\./|bash\s+|sh\s+)scripts/", line):
            problems.append(Problem("error", rel_name, n,
                                    "run bundled scripts through the interpreter (python3 scripts/x.py), "
                                    "not as an executable"))
            continue
        if not _CMD_START.match(line):
            continue
        if re.search(r"(?<![\w.])\.\./", line):
            problems.append(Problem("error", rel_name, n,
                                    "command uses ../, but skills are installed one folder at a time"))
            continue
        for token, what in _BAD_SHELL:
            if token in line:
                problems.append(Problem("error", rel_name, n,
                                        "command uses %s; keep it one program call with flags so it runs "
                                        "in bash and PowerShell" % what))
                break


def check_skill(skill_dir: Path, base: Optional[Path] = None) -> List[Problem]:
    """Check one skill folder. Returns a list of Problems (errors and warnings)."""
    skill_dir = Path(skill_dir)
    problems: List[Problem] = []
    skill_md = skill_dir / "SKILL.md"
    rel_name = _rel(skill_md, base)
    folder = skill_dir.name

    names = [p.name for p in skill_dir.iterdir()] if skill_dir.is_dir() else []
    if "SKILL.md" not in names:
        wrong = [n for n in names if n.lower() == "skill.md"]
        if wrong:
            problems.append(Problem("error", _rel(skill_dir / wrong[0], base), 0,
                                    "must be named exactly SKILL.md (Linux clients are case-sensitive)"))
        else:
            problems.append(Problem("error", _rel(skill_dir, base), 0, "no SKILL.md in this skill folder"))
        return problems

    raw = skill_md.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        problems.append(Problem("error", rel_name, 1, "starts with a UTF-8 BOM; Claude Code then ignores the frontmatter"))
        raw = raw[3:]
    if b"\r" in raw:
        problems.append(Problem("error", rel_name, 0, "CRLF or CR line endings; use LF"))
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        problems.append(Problem("error", rel_name, 0, "not valid UTF-8: %s" % exc))
        return problems
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    if not lines or lines[0] != "---":
        problems.append(Problem("error", rel_name, 1, "line 1 must be exactly --- (frontmatter start)"))
        return problems
    close = None
    for i in range(1, len(lines)):
        if lines[i] == "---":
            close = i
            break
    if close is None:
        problems.append(Problem("error", rel_name, 1, "frontmatter is not closed by a --- line"))
        return problems

    data, parse_errors = parse_frontmatter(lines[1:close], first_line=2)
    for n, msg in parse_errors:
        problems.append(Problem("error", rel_name, n, msg))

    for key, sc in data.items():
        if key not in ALLOWED_KEYS:
            hint = KEY_HINTS.get(key, "only %s are allowed" % ", ".join(ALLOWED_KEYS))
            problems.append(Problem("error", rel_name, sc.line, "unexpected key %r: %s" % (key, hint)))

    def scalar(key: str) -> Optional[Scalar]:
        sc = data.get(key)
        if sc is not None and sc.kind == "map":
            problems.append(Problem("error", rel_name, sc.line, "%s must be a single-line value, not a map" % key))
            return None
        return sc

    # name
    sc = scalar("name")
    if sc is None:
        if "name" not in data:
            problems.append(Problem("error", rel_name, 1, "missing name"))
    else:
        name = str(sc.value)
        if sc.kind == "plain-nonstring":
            problems.append(Problem("error", rel_name, sc.line, "name must be a string"))
        if not NAME_RE.match(name):
            problems.append(Problem("error", rel_name, sc.line,
                                    "name %r must be lowercase letters, digits and single dashes" % name))
        if len(name) > 64:
            problems.append(Problem("error", rel_name, sc.line, "name is longer than 64 characters"))
        if name != folder:
            problems.append(Problem("error", rel_name, sc.line, "name %r must equal the folder name %r" % (name, folder)))
        if name in BUILTIN_NAMES:
            problems.append(Problem("error", rel_name, sc.line,
                                    "name %r is a Claude Code built-in; a loose install would replace it" % name))
        if name in RESERVED_NAMES or name.startswith("anthropic-skills"):
            problems.append(Problem("error", rel_name, sc.line, "name %r is reserved" % name))
        if "claude" in name or "anthropic" in name:
            problems.append(Problem("error", rel_name, sc.line, "name must not contain claude or anthropic"))

    # description
    sc = scalar("description")
    if sc is None:
        if "description" not in data:
            problems.append(Problem("error", rel_name, 1, "missing description"))
    else:
        desc = str(sc.value)
        if sc.kind != "double":
            problems.append(Problem("error", rel_name, sc.line, "description must be double-quoted"))
        if not desc.strip():
            problems.append(Problem("error", rel_name, sc.line, "description is empty"))
        if len(desc) > MAX_DESCRIPTION:
            problems.append(Problem("error", rel_name, sc.line,
                                    "description is %d chars (max %d)" % (len(desc), MAX_DESCRIPTION)))
        elif len(desc) > DESC_WARN_LONG:
            problems.append(Problem("warning", rel_name, sc.line,
                                    "description is %d chars; aim for %d-%d" % (len(desc), DESC_WARN_SHORT, DESC_WARN_LONG)))
        elif 0 < len(desc) < DESC_WARN_SHORT:
            problems.append(Problem("warning", rel_name, sc.line,
                                    "description is %d chars; aim for %d-%d" % (len(desc), DESC_WARN_SHORT, DESC_WARN_LONG)))
        if "<" in desc or ">" in desc:
            problems.append(Problem("error", rel_name, sc.line, "description must not contain < or >"))

    # license, compatibility
    sc = scalar("license")
    if "license" not in data:
        problems.append(Problem("warning", rel_name, 1, "no license key"))
    elif sc is not None and not str(sc.value).strip():
        problems.append(Problem("error", rel_name, sc.line, "license is empty"))
    sc = scalar("compatibility")
    if sc is not None:
        comp = str(sc.value)
        if not comp.strip():
            problems.append(Problem("error", rel_name, sc.line, "compatibility is empty"))
        if len(comp) > MAX_COMPATIBILITY:
            problems.append(Problem("error", rel_name, sc.line,
                                    "compatibility is %d chars (max %d)" % (len(comp), MAX_COMPATIBILITY)))

    # metadata
    md = data.get("metadata")
    if md is not None:
        if md.kind != "map":
            problems.append(Problem("error", rel_name, md.line, "metadata must be a map of string values"))
        else:
            for sub, val in md.value.items():
                if val.kind == "plain-nonstring":
                    problems.append(Problem("error", rel_name, val.line,
                                            "metadata.%s must be a string; quote it (%r)" % (sub, val.value)))
            if "version" not in md.value:
                problems.append(Problem("warning", rel_name, md.line, "metadata has no version"))
    else:
        problems.append(Problem("warning", rel_name, 1, "no metadata (author, version)"))

    # allowed-tools
    sc = data.get("allowed-tools")
    if sc is not None:
        if sc.kind == "map":
            problems.append(Problem("error", rel_name, sc.line, "allowed-tools must be a space-separated string"))
        problems.append(Problem("warning", rel_name, sc.line,
                                "allowed-tools is set; this pack leaves it out so the user sees a permission prompt"))

    # body
    body = lines[close + 1:]
    if body and body[-1] == "":
        body = body[:-1]
    body_start = close + 2
    if len(body) > MAX_BODY_LINES:
        problems.append(Problem("error", rel_name, body_start,
                                "body is %d lines (max %d); move detail to references/" % (len(body), MAX_BODY_LINES)))
    head = "\n".join(body[:30])
    # A skill with no scripts/ folder runs nothing, so only the paths line applies.
    required = STANDING_RULES if (skill_dir / "scripts").is_dir() else STANDING_RULES[:1]
    missing = [s for s in required if s not in head]
    if missing:
        problems.append(Problem("warning", rel_name, body_start,
                                "standing-rules header missing near the top: %r" % missing[0]))

    _scan_text_rules(text, rel_name, problems)
    _scan_commands(body, body_start, rel_name, problems)

    # Links are checked outside code fences (code like items[i](x) is not a
    # link). Script and reference mentions are checked everywhere, because
    # the commands that run them sit inside fences.
    anchor_cache: Dict[Path, set] = {}
    in_fence = False
    for i, line in enumerate(body):
        n = body_start + i
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
        elif not in_fence:
            for m in _LINK_RE.finditer(_INLINE_CODE.sub("", line)):
                _check_link_target(m.group(1), skill_dir, skill_dir, rel_name, n, problems, anchor_cache)
        for m in _MENTION_RE.finditer(line):
            target = m.group(1)
            if not (skill_dir / target).is_file():
                problems.append(Problem("error", rel_name, n, "names %s, which does not exist in the skill" % target))

    scripts_dir = skill_dir / "scripts"
    if scripts_dir.is_dir():
        for py in sorted(scripts_dir.rglob("*.py")):
            if "__pycache__" in py.parts:
                continue
            try:
                py_text = py.read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                problems.append(Problem("error", _rel(py, base), 0, "cannot read as UTF-8: %s" % exc))
                continue
            _scan_text_rules(py_text, _rel(py, base), problems, paths=False)

    ref_dir = skill_dir / "references"
    if ref_dir.is_dir():
        for ref in sorted(ref_dir.rglob("*.md")):
            ref_rel = _rel(ref, base)
            try:
                ref_text = ref.read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                problems.append(Problem("error", ref_rel, 0, "cannot read as UTF-8: %s" % exc))
                continue
            if ref_text.startswith("\ufeff"):
                problems.append(Problem("error", ref_rel, 1, "starts with a UTF-8 BOM"))
            if "\r" in ref_text:
                problems.append(Problem("error", ref_rel, 0, "CRLF or CR line endings; use LF"))
            _scan_text_rules(ref_text, ref_rel, problems)
            in_fence = False
            for n, line in enumerate(ref_text.split("\n"), 1):
                if line.lstrip().startswith(("```", "~~~")):
                    in_fence = not in_fence
                    continue
                if in_fence:
                    continue
                for m in _LINK_RE.finditer(_INLINE_CODE.sub("", line)):
                    _check_link_target(m.group(1), ref.parent, skill_dir, ref_rel, n, problems, anchor_cache)
    return problems


# ---------------------------------------------------------------------------
# Repo checks
# ---------------------------------------------------------------------------

def check_repo_layout(root: Path) -> List[Problem]:
    """Root entries Claude Code would load as plugin components, and skills/ structure."""
    root = Path(root)
    problems: List[Problem] = []
    for d in ROOT_FORBIDDEN_DIRS:
        if (root / d).is_dir():
            problems.append(Problem("error", d + "/", 0,
                                    "a root %s/ folder loads as a plugin component with source \"./\"" % d))
    for f in ROOT_FORBIDDEN_FILES:
        if (root / f).is_file():
            why = ("a root SKILL.md shadows skills/ in npx skills" if f == "SKILL.md"
                   else "loads as a plugin component or triggers a validate warning")
            problems.append(Problem("error", f, 0, "remove it: %s" % why))
    skills = root / "skills"
    if not skills.is_dir():
        problems.append(Problem("error", "skills/", 0, "no skills/ folder"))
        return problems
    folders = [p for p in sorted(skills.iterdir()) if p.is_dir() and not p.name.startswith(".")]
    if not folders:
        problems.append(Problem("error", "skills/", 0, "skills/ holds no skill folders"))
    for p in sorted(skills.iterdir()):
        if p.is_file() and p.name.lower() == "skill.md":
            problems.append(Problem("error", _rel(p, root), 0, "SKILL.md belongs in skills/<name>/, not in skills/"))
    return problems


def skill_dirs(root: Path) -> List[Path]:
    skills = Path(root) / "skills"
    if not skills.is_dir():
        return []
    return [p for p in sorted(skills.iterdir()) if p.is_dir() and not p.name.startswith(".")]


def check_path(path: Path) -> Tuple[List[Problem], int]:
    """Check a repo root or a single skill folder. Returns (problems, skills checked)."""
    path = Path(path)
    if (path / "SKILL.md").exists() or any(p.name.lower() == "skill.md" for p in path.iterdir()):
        if not (path / "skills").is_dir():
            return check_skill(path, base=path.parent), 1
    problems = check_repo_layout(path)
    dirs = skill_dirs(path)
    for d in dirs:
        problems.extend(check_skill(d, base=path))
    return problems, len(dirs)


def main(argv: Optional[Sequence[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    args = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in args):
        sys.stdout.write(__doc__)
        return 0
    unknown = [a for a in args if a.startswith("-")]
    if unknown:
        sys.stderr.write("error: unknown option %s\n" % unknown[0])
        return 2
    paths = [Path(a).resolve() for a in args] or [REPO_ROOT]
    errors = warnings = checked = 0
    for p in paths:
        if not p.is_dir():
            sys.stderr.write("error: %s is not a folder\n" % p.as_posix())
            return 2
        problems, n = check_path(p)
        checked += n
        for pr in problems:
            loc = pr.path + (":%d" % pr.line if pr.line else "")
            sys.stdout.write("%s: %s: %s\n" % (pr.level, loc, pr.message))
            if pr.level == "error":
                errors += 1
            else:
                warnings += 1
    sys.stdout.write("%d skill%s checked, %d error%s, %d warning%s\n" % (
        checked, "" if checked == 1 else "s", errors, "" if errors == 1 else "s",
        warnings, "" if warnings == 1 else "s"))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
