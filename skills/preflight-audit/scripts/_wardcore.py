"""Shared helpers for the ward scripts.

Every script in this folder imports from here. The file is copied byte for
byte into other skills' scripts/ folders, so it must stay self-contained:
Python 3.9+, standard library only, no imports of sibling modules.

What it provides:

- setup_io(): force UTF-8 on stdout/stderr and refuse Python < 3.9.
- norm(path): resolve a user path, including Git Bash style /c/Users/...
- walk_files / read_text / iter_text_files: find and read text files while
  skipping dependencies, VCS folders, build output, binaries and env templates.
- Finding: one reported problem. mask() hides secret values.
- emit(): print a report (human or JSON), optionally write the full JSON to a
  file, and return the exit code.
- require_owned_host(): the host gate for any check that sends requests.
- Rule and ScanContext: the contract between scan_app.py and the rule modules.
- Exit codes: EXIT_OK, EXIT_FINDINGS, EXIT_ERROR, EXIT_REFUSED.
"""

from __future__ import annotations

import bisect
import json
import os
import re
import sys
from collections import namedtuple
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

TOOL = "ward"
VERSION = "0.1.0"

# Exit codes shared by every script.
EXIT_OK = 0          # nothing found / check passed
EXIT_FINDINGS = 1    # findings / check failed
EXIT_ERROR = 2       # usage or runtime error
EXIT_REFUSED = 3     # refused: host not owned or not confirmed

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
CONFIDENCES = ("high", "medium", "low")

DEFAULT_MAX_FINDINGS = 200
DEFAULT_MAX_BYTES = 2 * 1024 * 1024


# ---------------------------------------------------------------------------
# Startup and paths
# ---------------------------------------------------------------------------

def setup_io() -> None:
    """Call first in every main(). Forces UTF-8 output and checks the Python version.

    Windows consoles default to cp1252/cp1254, which crashes on non-ASCII paths
    and evidence. Exits with EXIT_ERROR on Python older than 3.9.
    """
    if sys.version_info < (3, 9):
        sys.stderr.write("ward needs Python 3.9 or newer (found %d.%d).\n" % sys.version_info[:2])
        sys.exit(EXIT_ERROR)
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass


_MSYS_DRIVE = re.compile(r"^/(?:cygdrive/|mnt/)?([A-Za-z])(?:/(.*))?$")


def convert_msys_path(text: str, windows: Optional[bool] = None) -> str:
    """Turn a Git Bash / Cygwin / WSL drive path like /c/Users/x into C:/Users/x.

    Only applied on Windows (or when windows=True), because on macOS and Linux
    /c/... is a real path.
    """
    if windows is None:
        windows = os.name == "nt"
    if not windows:
        return text
    m = _MSYS_DRIVE.match(text.replace("\\", "/"))
    if not m:
        return text
    rest = m.group(2) or ""
    return "%s:/%s" % (m.group(1).upper(), rest)


def norm(path: Union[str, Path, None] = ".") -> Path:
    """Resolve a user-supplied path to an absolute Path.

    Accepts / and \\ separators, ~, and Git Bash drive paths (/c/...).
    The target defaults to the current directory.
    """
    if path is None or str(path).strip() == "":
        path = "."
    text = str(path).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1]
    text = convert_msys_path(text)
    return Path(text).expanduser().resolve()


def rel_posix(path: Union[str, Path], root: Union[str, Path]) -> str:
    """Path relative to root, with forward slashes, for stable output on every OS."""
    p = Path(path)
    r = Path(root)
    try:
        return p.relative_to(r).as_posix()
    except ValueError:
        try:
            return Path(os.path.relpath(str(p), str(r))).as_posix()
        except ValueError:
            return p.as_posix()


# ---------------------------------------------------------------------------
# File walking and reading
# ---------------------------------------------------------------------------

# Never descended into.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "bower_components", "jspm_packages",
    "__pycache__", ".venv", "venv", ".tox", ".nox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "site-packages", ".eggs", "vendor", "Pods", ".gradle", ".idea",
    ".terraform", ".serverless", ".vercel", ".netlify", ".turbo", ".cache",
    ".parcel-cache", ".expo", ".expo-shared", "coverage", ".nyc_output", ".angular",
    ".yarn", ".pnpm-store", ".dart_tool", ".docusaurus", ".sass-cache", "htmlcov",
    ".history", ".wrangler",
})

# Build output: skipped unless want_build=True. Unambiguous names.
BUILD_DIRS_ALWAYS = frozenset({".next", ".nuxt", ".output", ".svelte-kit", "storybook-static"})
# Build output names that can also be real route or source folders
# (app/build/page.tsx). Treated as build output unless nested in a source folder.
BUILD_DIRS_AMBIGUOUS = frozenset({"dist", "build", "out"})
SOURCE_PARENTS = frozenset({"src", "app", "pages", "components", "lib", "routes", "views"})

BINARY_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".heic", ".bmp", ".tif", ".tiff",
    ".ico", ".icns", ".psd", ".ai", ".sketch", ".fig", ".pdf", ".zip", ".gz", ".tgz",
    ".bz2", ".xz", ".7z", ".rar", ".tar", ".jar", ".war", ".ear", ".class", ".so",
    ".dll", ".exe", ".dylib", ".bin", ".o", ".a", ".lib", ".obj", ".pyc", ".pyo",
    ".pyd", ".whl", ".egg", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4",
    ".m4a", ".mov", ".avi", ".mkv", ".webm", ".wav", ".ogg", ".flac", ".aac",
    ".sqlite", ".sqlite3", ".db", ".mdb", ".wasm", ".node", ".lockb", ".glb", ".fbx",
    ".blend", ".stl", ".dmg", ".iso", ".apk", ".aab", ".ipa", ".hbc",
    ".keystore", ".jks", ".p12", ".pfx", ".der", ".xlsx", ".xls", ".docx", ".doc", ".pptx",
    ".ppt", ".odt", ".ods", ".odp", ".epub", ".parquet", ".pkl", ".pickle", ".npy", ".npz",
    ".h5", ".onnx", ".pt", ".ckpt", ".safetensors", ".msi", ".cab", ".deb", ".rpm", ".shp",
    ".shx", ".dbf", ".gpkg", ".swf", ".ytd", ".ydr", ".yft", ".ybn", ".ymap", ".ytyp", ".rpf",
})

LOCKFILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock", "composer.lock", "Gemfile.lock",
    "Cargo.lock", "go.sum",
})

_EXAMPLE_MARKERS = ("example", "sample", "template", "tmpl", "dist")

TextFile = namedtuple("TextFile", "path rel text")
TextFile.__doc__ = "A decoded text file: absolute Path, relative posix path, text."


def is_lockfile(rel: str) -> bool:
    """True for dependency lockfiles (kept for exact-prefix patterns, never for entropy)."""
    return rel.rsplit("/", 1)[-1] in LOCKFILES


def is_env_file(rel: str) -> bool:
    """True for dotenv style files: .env, .env.local, prod.env, ..."""
    name = rel.rsplit("/", 1)[-1].lower()
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def is_example_file(rel: str) -> bool:
    """True for committed env templates such as .env.example, .env.sample, .env.template."""
    name = rel.rsplit("/", 1)[-1].lower()
    if not (name.startswith(".env") or name.endswith(".env") or name.startswith("env.")):
        return False
    return any(m in name for m in _EXAMPLE_MARKERS)


def _is_build_dir(name: str, parent_parts: Sequence[str]) -> bool:
    if name in BUILD_DIRS_ALWAYS:
        return True
    if name in BUILD_DIRS_AMBIGUOUS:
        return not any(p in SOURCE_PARENTS for p in parent_parts)
    return False


def is_build_path(rel: str) -> bool:
    """True when a relative path sits inside a build output folder."""
    parts = rel.split("/")[:-1]
    for i, part in enumerate(parts):
        if _is_build_dir(part, parts[:i]):
            return True
        if part == "build" and i > 0 and parts[i - 1] == "public":
            return True
    return False


# ward's own skill folders. A project-scope install (.claude/skills/, .agents/skills/
# and so on) puts these scripts inside the app being scanned; they are not part
# of the app and must not change stack detection or produce findings.
WARD_SKILLS = frozenset({"secure-by-default", "preflight-audit", "live-exposure-check"})
_SKILL_NAME_RX = re.compile(r"^name:\s*[\"']?([A-Za-z0-9_-]+)", re.M)


def is_ward_skill_dir(path: Union[str, Path]) -> bool:
    """True when path is an installed copy of one of ward's own skills."""
    skill_md = os.path.join(str(path), "SKILL.md")
    if not os.path.isfile(skill_md):
        return False
    try:
        with open(skill_md, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(2048)
    except OSError:
        return False
    if not head.startswith("---"):
        return False
    m = _SKILL_NAME_RX.search(head)
    if not m or m.group(1) not in WARD_SKILLS:
        return False
    if m.group(1) == "secure-by-default":
        return True
    return os.path.isfile(os.path.join(str(path), "scripts", "_wardcore.py"))


def walk_files(root: Union[str, Path], want_build: bool = False, skip_examples: bool = True,
               max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[Path]:
    """Yield candidate text files under root in a stable (sorted) order.

    Skips SKIP_DIRS, Python virtualenvs, installed copies of ward's own skills,
    build output (unless want_build), binary extensions, files over max_bytes
    and, by default, env templates.
    Does not read file contents; read_text() does the binary sniff.
    If root is a file, yields just that file.
    """
    root = Path(root)
    if root.is_file():
        yield root
        return
    seen = set()
    for dirpath, dirnames, filenames in os.walk(str(root)):
        try:
            st = os.stat(dirpath)
            key = (st.st_dev, st.st_ino)
            if st.st_ino and key in seen:
                dirnames[:] = []
                continue
            seen.add(key)
        except OSError:
            dirnames[:] = []
            continue
        rel_dir = rel_posix(dirpath, root)
        parent_parts = [] if rel_dir in ("", ".") else rel_dir.split("/")
        keep = []
        for d in sorted(dirnames):
            if d in SKIP_DIRS or d.endswith(".egg-info"):
                continue
            if not want_build and (_is_build_dir(d, parent_parts)
                                   or (d == "build" and parent_parts and parent_parts[-1] == "public")):
                continue
            if os.path.exists(os.path.join(dirpath, d, "pyvenv.cfg")):
                continue
            if is_ward_skill_dir(os.path.join(dirpath, d)):
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            ext = os.path.splitext(name)[1]
            if ext in BINARY_EXTS or ext.lower() in BINARY_EXTS or name == ".DS_Store":
                continue
            if skip_examples and is_example_file(name):
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > max_bytes:
                    continue
            except OSError:
                continue
            yield Path(full)


def read_text(path: Union[str, Path], max_bytes: int = DEFAULT_MAX_BYTES) -> Optional[str]:
    """Read a file as UTF-8 (errors replaced). Returns None for binaries,
    unreadable files and files larger than max_bytes."""
    try:
        p = Path(path)
        if p.stat().st_size > max_bytes:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    head = data[:8192]
    if b"\x00" in head:
        return None
    text = data.decode("utf-8", errors="replace")
    sample = text[:4096]
    if sample and sample.count("\ufffd") > len(sample) * 0.3:
        return None
    if text.startswith("\ufeff"):
        text = text[1:]
    return text


def iter_text_files(root: Union[str, Path], want_build: bool = False, skip_examples: bool = True,
                    max_bytes: int = DEFAULT_MAX_BYTES) -> Iterator[TextFile]:
    """Yield TextFile(path, rel, text) for every decodable text file under root.

    rel is relative to root with forward slashes. See walk_files() for what is
    skipped. Lockfiles are kept (exact-prefix patterns still apply to them).
    """
    root = Path(root)
    base = root.parent if root.is_file() else root
    for p in walk_files(root, want_build=want_build, skip_examples=skip_examples, max_bytes=max_bytes):
        text = read_text(p, max_bytes=max_bytes)
        if text is None:
            continue
        yield TextFile(p, rel_posix(p, base), text)


# ---------------------------------------------------------------------------
# Globs
# ---------------------------------------------------------------------------

def _expand_braces(pattern: str) -> List[str]:
    m = re.search(r"\{([^{}]*)\}", pattern)
    if not m:
        return [pattern]
    out = []
    for alt in m.group(1).split(","):
        out.extend(_expand_braces(pattern[:m.start()] + alt + pattern[m.end():]))
    return out


def _glob_to_regex(pattern: str) -> str:
    i, n, out = 0, len(pattern), []
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 3] == "**/":
                out.append("(?:.*/)?")
                i += 3
                continue
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


@lru_cache(maxsize=4096)
def _compile_glob(pattern: str) -> Tuple[bool, "re.Pattern[str]"]:
    parts = [_glob_to_regex(p) for p in _expand_braces(pattern)]
    full = "/" in pattern
    return full, re.compile(r"\A(?:" + "|".join(parts) + r")\Z")


def glob_match(rel: str, pattern: str) -> bool:
    """Match a relative posix path against one glob.

    A pattern without "/" matches the file name anywhere ("*.py", "settings.py").
    A pattern with "/" matches the whole relative path ("app/**/route.ts").
    "**/" matches zero or more folders, "*" never crosses "/", "{a,b}" expands.
    """
    full, rx = _compile_glob(pattern)
    target = rel if full else rel.rsplit("/", 1)[-1]
    return rx.match(target) is not None


@lru_cache(maxsize=1024)
def _compile_glob_set(patterns: Tuple[str, ...]) -> Tuple[Optional["re.Pattern[str]"], Optional["re.Pattern[str]"]]:
    """One regex for the name-only globs and one for the full-path globs."""
    names, fulls = [], []
    for p in patterns:
        full, rx = _compile_glob(p)
        (fulls if full else names).append(rx.pattern)
    nrx = re.compile("|".join("(?:%s)" % x for x in names)) if names else None
    frx = re.compile("|".join("(?:%s)" % x for x in fulls)) if fulls else None
    return nrx, frx


def match_any(rel: str, patterns: Iterable[str]) -> bool:
    """True when rel matches at least one glob in patterns."""
    key = patterns if isinstance(patterns, tuple) else tuple(patterns)
    if not key:
        return False
    nrx, frx = _compile_glob_set(key)
    if frx is not None and frx.match(rel) is not None:
        return True
    return nrx is not None and nrx.match(rel.rsplit("/", 1)[-1]) is not None


# ---------------------------------------------------------------------------
# Masking
# ---------------------------------------------------------------------------

def mask(s: Any) -> str:
    """Hide a secret: first 4 + hidden length + last 4, e.g. 'sk_l[24 chars]wxyz'.

    Shorter values reveal less (2+2 under 20 chars, nothing under 16, so a
    short password shows only its length), and the full value is never printed.
    """
    s = "" if s is None else str(s)
    n = len(s)
    if n >= 20:
        k = 4
    elif n >= 16:
        k = 2
    else:
        k = 0
    hidden = n - 2 * k
    return "%s[%d chars]%s" % (s[:k], hidden, s[n - k:] if k else "")


_SECRET_WORDS = r"(?:secret|passw(?:or)?d|passwd|pwd|token|api[_-]?key|apikey|private[_-]?key|access[_-]?key|credential|auth[_-]?key)"
_QUOTED_ASSIGN = re.compile(
    r"(?i)(\b[\w.$-]*" + _SECRET_WORDS + r"[\w-]*[\"']?\s*(?:===|!==|==|!=|=>|:=|[:=])\s*)([\"'`])([^\"'`\n]{6,}?)\2")
_ENV_ASSIGN = re.compile(
    r"(?i)^(\s*(?:export\s+)?[A-Z0-9_.-]*" + _SECRET_WORDS + r"[A-Z0-9_]*\s*=\s*)([^\s#\"'`]{6,})")
_TOKENISH = re.compile(r"(?<![A-Za-z0-9_+=-])[A-Za-z0-9_+=-]{24,}(?![A-Za-z0-9_+=-])")
# scheme://user:PASSWORD@host: the password part.
_URL_CRED = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,20}://[^\s:/@'\"`]{1,64}:)([^\s@/'\"`]{1,200})(@)")
_DOTTED_NAME = re.compile(r"^[A-Za-z_$][\w$]{0,30}(?:\.[A-Za-z_$][\w$]{0,30})+$")


def _looks_like_token(s: str) -> bool:
    if not (any(c.isdigit() for c in s) and any(c.isalpha() for c in s)):
        return False
    if any(c.islower() for c in s) and any(c.isupper() for c in s):
        return True
    return re.fullmatch(r"[0-9a-fA-F-]{32,}", s) is not None


def _is_reference(value: str, quoted: bool) -> bool:
    """True when a value is a template or code reference rather than a literal."""
    v = value.strip()
    if v.startswith(("${", "{{", "%(", "<", "process.env", "import.meta", "os.environ", "os.getenv",
                     "env(", "getenv", "config(", "settings.")):
        return True
    if "${" in v or "{{" in v:
        return True
    if quoted:
        return False
    if v.startswith("$") or "(" in v or "[" in v:
        return True
    return bool(_DOTTED_NAME.match(v))


def redact(text: str, patterns: Iterable[Any] = ()) -> str:
    """Mask secret-looking values inside a line of evidence.

    Masks: matches of the given compiled regexes (or strings), passwords in
    scheme://user:password@host URLs, quoted values assigned to secret-named
    keys, KEY=value env lines with secret-named keys, and long mixed-case
    alphanumeric tokens. References like process.env.X and placeholders like
    ${DB_PASS} or <password> are left as they are.
    """
    if not text:
        return text
    out = text
    for p in patterns:
        rx = re.compile(p) if isinstance(p, str) else p
        out = rx.sub(lambda m: mask(m.group(0)) if "chars]" not in m.group(0) else m.group(0), out)

    def _u(m: "re.Match[str]") -> str:
        val = m.group(2)
        if "chars]" in val or val.startswith(("$", "{", "[", "<", "%")) or _is_reference(val, True):
            return m.group(0)
        return m.group(1) + mask(val) + m.group(3)

    out = _URL_CRED.sub(_u, out)

    def _q(m: "re.Match[str]") -> str:
        val = m.group(3)
        if _is_reference(val, True) or "chars]" in val:
            return m.group(0)
        return m.group(1) + m.group(2) + mask(val) + m.group(2)

    out = _QUOTED_ASSIGN.sub(_q, out)

    def _e(m: "re.Match[str]") -> str:
        val = m.group(2)
        if _is_reference(val, False) or "chars]" in val:
            return m.group(0)
        return m.group(1) + mask(val)

    out = _ENV_ASSIGN.sub(_e, out)

    def _t(m: "re.Match[str]") -> str:
        val = m.group(0)
        return mask(val) if _looks_like_token(val) else val

    return _TOKENISH.sub(_t, out)


def clip(text: str, start: int = 0, end: Optional[int] = None, width: int = 200) -> str:
    """Shorten a long line to about width chars around [start, end)."""
    text = text.strip("\r\n")
    if len(text) <= width:
        return text.strip()
    if end is None:
        end = start
    mid = (start + end) // 2
    lo = max(0, mid - width // 2)
    hi = min(len(text), lo + width)
    lo = max(0, hi - width)
    return ("..." if lo > 0 else "") + text[lo:hi].strip() + ("..." if hi < len(text) else "")


# ---------------------------------------------------------------------------
# Findings and output
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One reported problem.

    severity: critical | high | medium | low | info (info = a note, it does not
    fail the exit code). confidence: high | medium | low. evidence must already
    be masked. id defaults to "<rule>@<file>:<line>". extra holds script-specific
    data (for example {"commit": "..."} for git history hits) and is only
    written to JSON when non-empty.
    """
    id: str = ""
    skill: str = ""
    klass: str = ""
    severity: str = "medium"
    file: str = ""
    line: int = 0
    rule: str = ""
    message: str = ""
    evidence: str = ""
    fix_ref: str = ""
    confidence: str = "medium"
    needs_confirmation: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            self.severity = "medium"
        if self.confidence not in CONFIDENCES:
            self.confidence = "medium"
        try:
            self.line = int(self.line or 0)
        except (TypeError, ValueError):
            self.line = 0
        if not self.id:
            self.id = "%s@%s:%d" % (self.rule or "finding", self.file or "(project)", self.line)

    @property
    def where(self) -> str:
        loc = self.file or "(project)"
        if self.line:
            loc = "%s:%d" % (loc, self.line)
        commit = self.extra.get("commit") if self.extra else None
        if commit:
            loc += " (commit %s)" % str(commit)[:12]
        return loc

    def to_dict(self, compact: bool = False) -> Dict[str, Any]:
        """All fields as a dict. compact=True drops id and skill (id repeats
        rule@file:line), which keeps stdout JSON short; files keep everything."""
        d = {
            "id": self.id, "skill": self.skill, "klass": self.klass, "severity": self.severity,
            "file": self.file, "line": self.line, "rule": self.rule, "message": self.message,
            "evidence": self.evidence, "fix_ref": self.fix_ref, "confidence": self.confidence,
            "needs_confirmation": self.needs_confirmation,
        }
        if compact:
            del d["id"]
            del d["skill"]
        if self.extra:
            d["extra"] = self.extra
        return d


def sort_findings(findings: Iterable[Finding]) -> List[Finding]:
    """Most severe first, then by file, line and rule."""
    return sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.file, f.line, f.rule))


def summarize(findings: Sequence[Finding]) -> Dict[str, int]:
    """Counts per severity plus a total."""
    out = {s: 0 for s in SEVERITIES}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    out["total"] = len(findings)
    return out


def count_by_rule(findings: Sequence[Finding]) -> Dict[str, int]:
    """Findings per rule id, most frequent first."""
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def select_shown(ordered: Sequence[Finding], cap: Optional[int] = None,
                 per_rule: Optional[int] = None) -> List[Finding]:
    """The findings to print: in order, at most per_rule of each rule id (so one
    noisy rule cannot fill the window), at most cap in total."""
    out: List[Finding] = []
    seen: Dict[str, int] = {}
    for f in ordered:
        if cap is not None and len(out) >= cap:
            break
        if per_rule:
            n = seen.get(f.rule, 0)
            if n >= per_rule:
                continue
            seen[f.rule] = n + 1
        out.append(f)
    return out


def exit_code_for(findings: Iterable[Finding]) -> int:
    """EXIT_FINDINGS when any finding is above info, else EXIT_OK."""
    for f in findings:
        if f.severity != "info":
            return EXIT_FINDINGS
    return EXIT_OK


def build_report(findings: Sequence[Finding], target: str = "", script: str = "",
                 meta: Optional[Dict[str, Any]] = None, warnings: Optional[Sequence[Any]] = None,
                 shown: Optional[int] = None, per_rule: Optional[int] = None, compact: bool = False,
                 ignored: Optional[Sequence[Finding]] = None) -> Dict[str, Any]:
    """The JSON report shape shared by every script.

    shown caps the findings listed; per_rule caps how many of one rule id are
    listed (the summary still counts all of them, and summary.by_rule gives the
    count per rule). ignored are findings the project marked as reviewed false
    positives: they do not count, and are listed under summary.ignored.
    """
    ordered = sort_findings(findings)
    report: Dict[str, Any] = {"tool": TOOL, "script": script, "version": VERSION, "target": target}
    for k, v in (meta or {}).items():
        report[k] = v
    summary: Dict[str, Any] = summarize(ordered)
    if (shown is None or shown >= len(ordered)) and not per_rule:
        picked = list(ordered)
    else:
        picked = select_shown(ordered, shown, per_rule)
    summary["shown"] = len(picked)
    report["findings"] = [f.to_dict(compact) for f in picked]
    if per_rule:
        by_rule = count_by_rule(ordered)
        summary["by_rule"] = by_rule
        shown_rule = count_by_rule(picked)
        capped = {r: n for r, n in by_rule.items() if shown_rule.get(r, 0) < n and shown_rule.get(r, 0) >= per_rule}
        if capped:
            summary["capped_rules"] = {r: {"total": n, "shown": shown_rule.get(r, 0)} for r, n in capped.items()}
    if ignored:
        summary["ignored"] = len(ignored)
        report["ignored"] = ["%s@%s:%d%s" % (f.rule, f.file or "(project)", f.line,
                                              ("  # " + f.extra["ignore_reason"]) if f.extra.get("ignore_reason") else "")
                             for f in sort_findings(ignored)]
    report["summary"] = summary
    report["warnings"] = list(warnings or [])
    return report


def _warning_text(w: Any) -> str:
    if isinstance(w, dict):
        return w.get("message") or json.dumps(w, ensure_ascii=False)
    return str(w)


def emit(findings: Sequence[Finding], as_json: bool = False, out_file: Optional[Union[str, Path]] = None,
         max_findings: int = DEFAULT_MAX_FINDINGS, *, target: str = "", script: str = "",
         meta: Optional[Dict[str, Any]] = None, warnings: Optional[Sequence[Any]] = None,
         stream: Any = None, per_rule: Optional[int] = None, compact: bool = False,
         ignored: Optional[Sequence[Finding]] = None, exit_code: Optional[int] = None) -> int:
    """Print the report and return the exit code.

    Human mode (default): a header with counts by severity, then one line per
    finding "SEVERITY  rule  path:line  message" with masked evidence below it,
    capped at max_findings (and at per_rule findings of one rule id, when
    given). JSON mode prints the report dict, also capped; compact=True drops
    the id and skill fields there. out_file always receives the full, uncapped
    JSON report with every field. ignored findings (reviewed false positives)
    are counted under summary.ignored and never change the exit code.
    Warnings go to stderr in human mode and into "warnings" in JSON.
    Returns exit_code when given, else EXIT_FINDINGS if any non-info finding
    exists, EXIT_OK otherwise, or EXIT_ERROR if out_file cannot be written.
    """
    out = stream or sys.stdout
    ordered = sort_findings(findings)
    cap = max(0, int(max_findings)) if max_findings is not None else len(ordered)
    per_rule = max(0, int(per_rule)) if per_rule else None
    code = exit_code_for(ordered) if exit_code is None else exit_code

    if out_file:
        full = build_report(ordered, target, script, meta, warnings, ignored=ignored)
        if per_rule:
            full["summary"]["by_rule"] = count_by_rule(ordered)
        try:
            p = norm(out_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(full, fh, indent=2, ensure_ascii=False)
                fh.write("\n")
        except OSError as exc:
            sys.stderr.write("error: cannot write %s: %s\n" % (out_file, exc))
            return EXIT_ERROR

    if as_json:
        report = build_report(ordered, target, script, meta, warnings, shown=cap, per_rule=per_rule,
                              compact=compact, ignored=ignored)
        if out_file:
            report["output"] = str(out_file)
        out.write(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
        return code

    counts = summarize(ordered)
    name = "%s %s" % (TOOL, script) if script else TOOL
    out.write("%s: %s\n" % (name, target or "."))
    for k, v in (meta or {}).items():
        if v is None or v == "" or (isinstance(v, (list, tuple, dict)) and not v):
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v)
        elif isinstance(v, dict):
            v = ", ".join("%s=%s" % (a, b) for a, b in v.items())
        out.write("%s: %s\n" % (k.replace("_", " "), v))
    if not ordered:
        out.write("No findings.\n")
    else:
        parts = ["%d %s" % (counts[s], s) for s in SEVERITIES if counts.get(s)]
        out.write("%d finding%s: %s\n\n" % (len(ordered), "" if len(ordered) == 1 else "s", ", ".join(parts)))
        picked = select_shown(ordered, cap, per_rule)
        for f in picked:
            out.write("%-8s  %s  %s  %s\n" % (f.severity.upper(), f.rule, f.where, f.message))
            if f.evidence:
                out.write("          > %s\n" % f.evidence)
        if len(picked) < len(ordered):
            if per_rule:
                by_rule = count_by_rule(ordered)
                shown_rule = count_by_rule(picked)
                hidden = ["%s %d (%d shown)" % (r, n, shown_rule.get(r, 0)) for r, n in by_rule.items()
                          if shown_rule.get(r, 0) < n]
                if hidden:
                    out.write("\nPer rule, not all shown: %s\n" % ", ".join(hidden[:15]))
            out.write("\n(showing %d of %d; use --output FILE for the full list)\n" % (len(picked), len(ordered)))
    if ignored:
        out.write("Ignored (recorded false positives): %d\n" % len(ignored))
    if out_file:
        out.write("Full JSON report written to %s\n" % out_file)
    for w in warnings or []:
        sys.stderr.write("warning: %s\n" % _warning_text(w))
    return code


def add_common_args(parser: Any, max_default: int = DEFAULT_MAX_FINDINGS) -> None:
    """Add --json, --output FILE and --max-findings N to an argparse parser."""
    parser.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    parser.add_argument("--output", metavar="FILE", help="also write the full JSON report to FILE")
    parser.add_argument("--max-findings", type=int, default=max_default, metavar="N",
                        help="show at most N findings on stdout (default %d)" % max_default)


# ---------------------------------------------------------------------------
# Host gate for runtime checks
# ---------------------------------------------------------------------------

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


def _clean_host(value: str) -> str:
    v = (value or "").strip().lower()
    if "://" in v:
        v = urlsplit(v).hostname or ""
    elif v.startswith("["):
        v = v[1:].split("]", 1)[0]
    elif v.count(":") == 1:
        v = v.split(":", 1)[0]
    return v.strip("[]").rstrip(".")


def require_owned_host(url: str, allow_flag: Union[str, Sequence[str], None] = None) -> Tuple[str, bool]:
    """Decide whether a runtime check may send requests to url.

    Returns (host, ok). ok is True for localhost, 127.0.0.1, [::1], *.localhost
    and *.test. Any other host needs allow_flag (the --i-own-this value, a host
    or a list of hosts) to name exactly that host. The caller exits with
    EXIT_REFUSED when ok is False.
    """
    raw = (url or "").strip()
    if not raw:
        return "", False
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
        if parts.scheme.lower() not in ("http", "https"):
            return host, False
    except ValueError:
        return "", False
    if not host:
        return "", False
    if host in LOCAL_HOSTS or host.endswith(".localhost") or host.endswith(".test"):
        return host, True
    if not allow_flag:
        return host, False
    allowed = [allow_flag] if isinstance(allow_flag, str) else list(allow_flag)
    for a in allowed:
        if _clean_host(str(a)) == host:
            return host, True
    return host, False


def refusal_message(host: str) -> str:
    """Standard text printed when require_owned_host() refuses a URL."""
    return ("refused: %s is not a local host. Runtime checks only run against an app you own. "
            "If you own it, pass --i-own-this %s." % (host or "(no host)", host or "HOST"))


# ---------------------------------------------------------------------------
# Small helpers rule modules can use
# ---------------------------------------------------------------------------

_COMMENT_PREFIXES = {
    "hash": ("#",),
    "slash": ("//", "/*", "*", "*/"),
    "php": ("//", "#", "/*", "*", "*/"),
    "sql": ("--", "/*", "*"),
    "html": ("<!--",),
    "css": ("/*", "*", "*/"),
}
_EXT_STYLE = {
    ".py": "hash", ".sh": "hash", ".bash": "hash", ".zsh": "hash", ".yml": "hash",
    ".yaml": "hash", ".toml": "hash", ".rb": "hash", ".ini": "hash", ".cfg": "hash",
    ".conf": "hash", ".env": "hash", ".properties": "hash", ".tf": "hash", ".r": "hash",
    ".js": "slash", ".jsx": "slash", ".ts": "slash", ".tsx": "slash", ".mjs": "slash",
    ".cjs": "slash", ".mts": "slash", ".cts": "slash", ".java": "slash", ".kt": "slash",
    ".go": "slash", ".c": "slash", ".h": "slash", ".cpp": "slash", ".cs": "slash",
    ".swift": "slash", ".rs": "slash", ".dart": "slash", ".scss": "slash", ".less": "slash",
    ".gradle": "slash", ".json5": "slash", ".jsonc": "slash",
    ".php": "php", ".sql": "sql", ".html": "html", ".htm": "html", ".xml": "html",
    ".vue": "html", ".svelte": "html", ".md": "html", ".css": "css",
}
_NAME_STYLE = {"dockerfile": "hash", "procfile": "hash", "makefile": "hash", ".gitignore": "hash",
               ".dockerignore": "hash", ".npmrc": "hash", "gemfile": "hash"}


@lru_cache(maxsize=16384)
def comment_style(rel: str) -> Optional[str]:
    """Comment family for a file name: hash, slash, php, sql, html, css or None."""
    name = rel.rsplit("/", 1)[-1].lower()
    if name in _NAME_STYLE:
        return _NAME_STYLE[name]
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "hash"
    if is_env_file(name):
        return "hash"
    if name.endswith(".blade.php"):
        return "php"
    return _EXT_STYLE.get(os.path.splitext(name)[1])


def _comment_line_rx(style: str) -> "re.Pattern[str]":
    alts = []
    for p in _COMMENT_PREFIXES[style]:
        if p == "*":
            continue
        alts.append(re.escape(p))
    if style in ("slash", "php", "css", "sql"):
        alts.append(r"\*(?!\*)")
    return re.compile(r"\s*(?:%s)" % "|".join(alts))


_COMMENT_LINE_RX = {style: _comment_line_rx(style) for style in _COMMENT_PREFIXES}


def is_comment_line(line: str, rel: str) -> bool:
    """Heuristic: True when the whole line is a comment in this file's language.

    Line based, so it cannot see the inside of a /* ... */ block whose lines do
    not start with '*'. Use code_view() or ScanContext.code_lines() for that.
    """
    style = comment_style(rel)
    if not style:
        return False
    return _COMMENT_LINE_RX[style].match(line) is not None


# Stateful comment blanking. Each family is one alternation run with finditer,
# so strings (and JS regex literals) are consumed whole and a "//" or "/*"
# inside them is not taken for a comment. Only the "c" groups are comments.
_JS_REGEX_LIT = (r"(?:(?<=[(,=:\[!&|?{};])|(?<=\breturn)|(?<=\btypeof)|(?<=^))[ \t]*"
                 r"/(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n\[])+/[a-z]*")
_VIEW_RX = {
    "slash": re.compile(
        r"(?P<c>//[^\n]*|/\*.*?(?:\*/|\Z))"
        r"|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`|" + _JS_REGEX_LIT, re.S | re.M),
    "py": re.compile(
        r"(?P<c>#[^\n]*)"
        r"|[rRbBuUfF]{0,2}(?:\"\"\"(?:\\.|[^\\])*?(?:\"\"\"|\Z)|'''(?:\\.|[^\\])*?(?:'''|\Z)"
        r"|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*')", re.S),
    "php": re.compile(
        r"(?P<c>//[^\n]*?(?=\?>|\n|\Z)|#(?!\[)[^\n]*?(?=\?>|\n|\Z)|/\*.*?(?:\*/|\Z))"
        r"|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'", re.S),
    "blade": re.compile(r"(?P<c>\{\{--.*?(?:--\}\}|\Z)|<!--.*?(?:-->|\Z))", re.S),
    "css": re.compile(r"(?P<c>/\*.*?(?:\*/|\Z))|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S),
    "sql": re.compile(r"(?P<c>--[^\n]*|/\*.*?(?:\*/|\Z))|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"", re.S),
    "html": re.compile(r"(?P<c><!--.*?(?:-->|\Z))", re.S),
}
_PHP_REGION = re.compile(r"<\?(?:php\b|=)?(.*?)(?:\?>|\Z)", re.S)


def _view_family(rel: str) -> Optional[str]:
    name = rel.rsplit("/", 1)[-1].lower()
    if name.endswith(".blade.php"):
        return "blade"
    ext = os.path.splitext(name)[1]
    if ext == ".py":
        return "py"
    style = comment_style(rel)
    if style in ("slash", "php", "css", "sql", "html"):
        return style
    return None  # hash-style config files: '#' can sit inside URLs and values


def _blank(text: str, spans: List[Tuple[int, int]]) -> str:
    if not spans:
        return text
    out, pos = [], 0
    for a, b in spans:
        out.append(text[pos:a])
        out.append(re.sub(r"[^\n]", " ", text[a:b]))
        pos = b
    out.append(text[pos:])
    return "".join(out)


def comment_spans(text: str, rel: str) -> List[Tuple[int, int]]:
    """(start, end) offsets of the comments in text, for this file's language.

    Handles /* ... */ blocks, // and # line comments, <!-- --> and Blade
    {{-- --}}, and skips comment markers inside string literals. PHP comments are
    only looked for inside <?php ... ?> regions. Hash-style config files (YAML,
    shell, .env) return [] because '#' is too often part of a value there.
    """
    fam = _view_family(rel)
    if fam is None or not text:
        return []
    rx = _VIEW_RX[fam]
    spans: List[Tuple[int, int]] = []
    if fam == "php":
        for region in _PHP_REGION.finditer(text):
            base = region.start(1)
            for m in rx.finditer(region.group(1)):
                if m.group("c") is not None:
                    spans.append((base + m.start(), base + m.end()))
        return spans
    for m in rx.finditer(text):
        if m.group("c") is not None:
            spans.append((m.start(), m.end()))
    return spans


def code_view(text: str, rel: str) -> str:
    """text with every comment replaced by spaces. Newlines and offsets are kept,
    so line numbers and match positions stay valid. See comment_spans()."""
    return _blank(text, comment_spans(text, rel))


def parse_version(text: Optional[str]) -> Optional[Tuple[int, ...]]:
    """First dotted version in text as a tuple: '^14.2.3' -> (14, 2, 3), '15' -> (15,).
    Returns None when there is no number."""
    if not text:
        return None
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(text))
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None)


def version_lt(a: Optional[str], b: str) -> Optional[bool]:
    """a < b by dotted numbers (missing parts count as 0). None if a is unknown."""
    ta, tb = parse_version(a), parse_version(b)
    if ta is None or tb is None:
        return None
    n = max(len(ta), len(tb))
    return ta + (0,) * (n - len(ta)) < tb + (0,) * (n - len(tb))


# ---------------------------------------------------------------------------
# Rule contract (scan_app.py and the _rules_*.py modules)
# ---------------------------------------------------------------------------

Hit = namedtuple("Hit", "line evidence message severity file", defaults=(None, None, None))
Hit.__doc__ = """One match returned by a rule check.

A check may return plain (line, evidence) tuples or Hit objects. Optional
fields override the rule for this one hit: message, severity, and file (a
relative posix path, for checks that report on a different file than the one
they were called with, or for once=True rules).
"""


@dataclass
class Rule:
    """A static check run by scan_app.py. Each _rules_*.py exports RULES: List[Rule].

    Required: id (lowercase, dashes), skill (area name used to group rules.md),
    klass (short human class), severity, stacks, file_globs.

    Matching, pick one:
      pattern   a regex string (compiled by the engine) run per line, or over the
                whole file when multiline=True (line = line of the match start).
                It may instead be a callable or the name "check_<something>" of a
                function in the same module; then it works like check.
      check     callable(path, text, ctx) -> list of (line, evidence) or Hit.
                path is the relative posix path, text the file content, ctx the
                ScanContext. Line numbers are 1-based.

    stacks: detected stacks this rule applies to; ["*"] = all. An entry like
      "nextjs-app+supabase" needs both. file_globs / exclude_globs: see
      glob_match(). An empty file_globs list is only valid with once=True.

    Text for rules.md and output: message (one line), why (why agents produce
    it), fp_trap (the safe variant that must not be flagged), fix_ref (for
    example "stack-supabase.md#rls"), confidence, needs_confirmation.

    Extras:
      unless_file   regex; if it matches anywhere in the file, skip the file.
      unless_line   regex; if it matches the hit line, skip that hit.
      client_only   only run on files ctx.is_client_file() says ship to the client.
      skip_comments skip regex hits on comment lines (default True).
      include_minified  also scan minified files (default False).
      once          call check once per scan with path "" and text ""; hits must
                    name their file (Hit.file) or they are reported at project level.
      max_per_file  cap hits per file (default 20).
      anchors       literal strings; the engine skips a file whose text contains
                    none of them (a fast prefilter, case-sensitive). Leave empty
                    unless every possible hit needs one of these strings.
      severity_note shown next to the severity in rules.md when a check can
                    report a hit at another severity, for example
                    "medium when the HTML source cannot be traced".
      module        set by the engine to the module name that defined the rule.
    """
    id: str
    skill: str
    klass: str
    severity: str
    stacks: List[str]
    file_globs: List[str]
    pattern: Any = ""
    message: str = ""
    why: str = ""
    fp_trap: str = ""
    fix_ref: str = ""
    confidence: str = "medium"
    needs_confirmation: bool = True
    check: Optional[Callable[..., Any]] = None
    exclude_globs: List[str] = field(default_factory=list)
    multiline: bool = False
    unless_file: str = ""
    unless_line: str = ""
    client_only: bool = False
    skip_comments: bool = True
    include_minified: bool = False
    once: bool = False
    max_per_file: int = 20
    anchors: Sequence[str] = ()
    severity_note: str = ""
    module: str = ""

    def applies_to(self, stacks: Iterable[str], force_all: bool = False) -> bool:
        """True when this rule should run for the detected stacks."""
        if force_all or "*" in self.stacks:
            return True
        have = set(stacks)
        for entry in self.stacks:
            need = [s for s in entry.split("+") if s]
            if need and all(s in have for s in need):
                return True
        return False

    def wants_file(self, rel: str) -> bool:
        """True when rel matches file_globs and not exclude_globs."""
        return match_any(rel, self.file_globs) and not (self.exclude_globs and match_any(rel, self.exclude_globs))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "module": self.module, "skill": self.skill, "klass": self.klass,
            "severity": self.severity, "confidence": self.confidence, "stacks": list(self.stacks),
            "file_globs": list(self.file_globs), "message": self.message, "why": self.why,
            "fp_trap": self.fp_trap, "fix_ref": self.fix_ref,
            "needs_confirmation": self.needs_confirmation, "severity_note": self.severity_note,
        }


def validate_rule(rule: Any) -> List[str]:
    """Problems that stop a rule from running (empty list = fine)."""
    errs = []
    if not isinstance(rule, Rule):
        return ["not a Rule instance: %r" % (rule,)]
    if not rule.id or not re.match(r"^[a-z0-9][a-z0-9-]*$", rule.id):
        errs.append("bad id %r (lowercase letters, digits and dashes)" % rule.id)
    if rule.severity not in SEVERITY_RANK:
        errs.append("bad severity %r" % rule.severity)
    if rule.confidence not in CONFIDENCES:
        errs.append("bad confidence %r" % rule.confidence)
    if not rule.stacks or isinstance(rule.stacks, str):
        errs.append("stacks must be a non-empty list")
    if isinstance(rule.file_globs, str):
        errs.append("file_globs must be a list")
    elif not rule.file_globs and not rule.once:
        errs.append("file_globs is empty")
    if not rule.check and not rule.pattern:
        errs.append("needs a pattern or a check")
    if not rule.message:
        errs.append("message is empty")
    if isinstance(rule.anchors, str):
        errs.append("anchors must be a list of strings")
    return errs


# ---------------------------------------------------------------------------
# Scan context shared by all rules in one scan
# ---------------------------------------------------------------------------

CODE_EXTS = frozenset({".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte"})
# Server-side folders at any depth.
_SERVER_SEGMENTS = frozenset({
    "server", "servers", "backend", "lambda", "lambdas", "migrations", "__tests__", "test",
    "tests", "e2e", "cypress", "playwright", "__mocks__",
})
# Server-side as the first folder of the repo or of the nearest package
# (supabase/functions, functions/ for Firebase, ...).
_SERVER_ROOTS = frozenset({
    "api", "supabase", "functions", "netlify", "prisma", "scripts", "seed", "seeds", "cron",
    "edge-functions", "worker", "workers",
})
# Server-side folder pairs at any depth (examples/x/supabase/functions/...).
_SERVER_PAIRS = re.compile(r"(?:^|/)(?:supabase/functions|netlify/functions|netlify/edge-functions)/")
_SERVER_NAME = re.compile(
    r"(?:^|\.)server\.[a-z]+$|^\+(?:page|layout)\.server\.|^\+server\.|^hooks\.server\.|\+api\.[a-z]+$"
    r"|\.(?:test|spec|stories|story)\.[a-z]+$|\.config\.[a-z]+$|^\.eslintrc|\.functions\.[a-z]+$")
_ROOT_ENTRY = re.compile(r"^(?:server|app|index|main)\.(?:c|m)?js$")
_ROUTE_HANDLER = re.compile(r"^route\.(?:js|jsx|ts|tsx|mjs)$")
_MIDDLEWARE = re.compile(r"^(?:src/)?(?:middleware|proxy|instrumentation)\.(?:js|ts|mjs)$")
_USE_CLIENT = re.compile(r"""\A(?:\s|//[^\n]*(?:\n|\Z)|/\*(?:[^*]|\*(?!/))*\*/)*["']use client["']""")
_USE_SERVER = re.compile(r"""\A(?:\s|//[^\n]*(?:\n|\Z)|/\*(?:[^*]|\*(?!/))*\*/)*["']use server["']""")
_SERVER_ONLY = re.compile(r"""import\s+["']server-only["']""")
_CLIENT_HINTS = re.compile(r"\buse(?:State|Effect|LayoutEffect|Reducer|Ref|Transition|Optimistic)\s*\(|\son[A-Z][a-zA-Z]+=\{|\bwindow\.|\bdocument\.|\blocalStorage\b")
_PAGES_SERVER = re.compile(r"\bget(?:ServerSideProps|StaticProps|InitialProps)\b")

# npm packages that decide what kind of code a package.json directory holds.
SSR_PACKAGES = ("next", "nuxt", "@sveltejs/kit", "astro", "@remix-run/react", "@remix-run/node",
                "@tanstack/react-start", "@tanstack/start", "@tanstack/solid-start", "gatsby",
                "laravel-vite-plugin")
SPA_UI_PACKAGES = ("react", "react-dom", "vue", "svelte", "solid-js", "preact")
TANSTACK_START_PACKAGES = ("@tanstack/react-start", "@tanstack/start", "@tanstack/solid-start")
SERVER_PACKAGES = ("express", "fastify", "hono", "koa", "@nestjs/core", "@nestjs/common", "@hapi/hapi",
                   "restify", "polka", "@adonisjs/core", "@feathersjs/feathers")
_BROWSER_PACKAGES = ("react-native", "expo", "react-dom", "next", "vite", "vue", "svelte", "@angular/core",
                     "nuxt", "@sveltejs/kit", "react-scripts", "astro", "@remix-run/react", "solid-js",
                     "preact", "webpack-dev-server", "parcel") + TANSTACK_START_PACKAGES
_DEP_SECTIONS = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")

# TanStack Start server code markers.
_TS_SERVER_FN_CALL = re.compile(r"\bcreateServerFn\s*\(|\bcreateServerOnlyFn\s*\(|\bcreateMiddleware\s*\(")
_TS_SERVER_KEY = re.compile(r"\bserver\s*:\s*\{")
_TS_SERVER_FN = re.compile(r"(?:\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*)?\bcreateServerFn\s*\(")
_TS_MIDDLEWARE_DEF = re.compile(r"\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*createMiddleware\s*\(")
_TS_AUTH_CALL = re.compile(
    r"\.auth\s*\.\s*(?:getClaims|getUser)\s*\(|\bgetClaims\s*\(|\bverifyIdToken\s*\(|\bjwtVerify\s*\(|\bjwt\s*\.\s*verify\s*\(")
_TS_HANDLERS = re.compile(r"\bhandlers\s*:\s*\{")
_TS_METHOD_KEY = re.compile(r"(?<![\w$])(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY)\s*:")


def _ts_server_code(text: str) -> bool:
    """True when TanStack Start code defines server functions, middleware or route handlers."""
    return bool(_TS_SERVER_FN_CALL.search(text) or (_TS_HANDLERS.search(text) and _TS_SERVER_KEY.search(text)))


def _balanced_end(text: str, open_at: int, open_ch: str = "{", close_ch: str = "}", limit: int = 20000) -> int:
    """Offset just past the bracket that closes text[open_at] (rough: strings are not parsed)."""
    depth = 0
    end = min(len(text), open_at + limit)
    for i in range(open_at, end):
        c = text[i]
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
    return end


class ScanContext:
    """Shared state for one scan, passed to every rule check as ctx.

    Attributes:
      root            absolute Path of the scanned project
      files           relative posix paths of candidate text files (sorted)
      stacks          set of detected stack names (see scan_app.detect_stacks)
      package_managers  list such as ["pnpm"] or ["npm", "pip"]
      deps            merged package.json deps (dependencies, dev, peer, optional),
                      plus npm: / esm.sh imports of Deno code (see deno_deps)
      prod_deps       merged package.json "dependencies" only
      dev_deps        merged package.json "devDependencies"
      deno_deps       {name: [(version, file, line), ...]} from deno.json(c),
                      import_map.json and npm:/jsr:/esm.sh imports in supabase/functions
      py_deps         set of Python requirement names (lowercase, "-" for "_")
      composer_deps   merged composer.json require + require-dev
      composer_prod   composer.json "require" only
      warnings        internal warnings collected during the scan
    Methods: read, lines, json, exists, glob, line_of, window, memo,
    code_view, code_lines, in_comment, is_client_file, client_files,
    is_minified, has_stack, installed_version, next_version, warn,
    package_of, package_deps, tanstack_kind, tanstack_server_fns,
    tanstack_route_handlers, tanstack_auth_middlewares.
    """

    def __init__(self, root: Union[str, Path], files: Optional[Sequence[str]] = None,
                 stacks: Optional[Iterable[str]] = None, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.root = Path(root)
        self.max_bytes = max_bytes
        if files is None:
            files = [rel_posix(p, self.root) for p in walk_files(self.root, max_bytes=max_bytes)]
        self.files: List[str] = sorted(files)
        self._fileset = set(self.files)
        self.stacks = set(stacks or ())
        self.package_managers: List[str] = []
        self.deps: Dict[str, str] = {}
        self.prod_deps: Dict[str, str] = {}
        self.dev_deps: Dict[str, str] = {}
        self.deno_deps: Dict[str, List[Tuple[str, str, int]]] = {}
        self.py_deps: set = set()
        self.composer_deps: Dict[str, str] = {}
        self.composer_prod: Dict[str, str] = {}
        self.warnings: List[Any] = []
        self._text: Dict[str, str] = {}
        self._lines: Dict[str, List[str]] = {}
        self._starts: Dict[str, List[int]] = {}
        self._json: Dict[str, Any] = {}
        self._memo: Dict[Any, Any] = {}
        self._client: Dict[str, bool] = {}
        self._minified: Dict[str, bool] = {}
        self._spans: Dict[str, List[Tuple[int, int]]] = {}
        self._views: Dict[str, str] = {}
        self._code_lines: Dict[str, List[str]] = {}
        self._pkg_dirs: Optional[set] = None
        self._pkg_of: Dict[str, Optional[str]] = {}
        self._pkg_flags: Dict[Optional[str], Dict[str, bool]] = {}

    def set_files(self, files: Sequence[str]) -> None:
        """Replace the candidate file list (used to drop vendored code)."""
        self.files = sorted(files)
        self._fileset = set(self.files)
        self._pkg_dirs = None
        self._pkg_of = {}
        self._memo.pop("client_files", None)

    # -- reading -----------------------------------------------------------
    def _safe_path(self, rel: str) -> Optional[Path]:
        p = (self.root / rel)
        try:
            p = p.resolve()
            p.relative_to(self.root.resolve())
        except (ValueError, OSError):
            return None
        return p

    def read(self, rel: str) -> str:
        """Cached file text ('' when missing, binary or too large). Works for any
        path under root, not only those in files."""
        if rel in self._text:
            return self._text[rel]
        p: Optional[Path]
        if rel in self._fileset and not os.path.islink(os.path.join(str(self.root), rel)):
            p = self.root / rel  # found by the walk, so already under root
        else:
            p = self._safe_path(rel)
        text = read_text(p, self.max_bytes) if p is not None and p.is_file() else None
        self._text[rel] = text or ""
        return self._text[rel]

    def lines(self, rel: str) -> List[str]:
        """Cached lines of a file, without line endings. lines(rel)[n-1] is line n."""
        if rel not in self._lines:
            self._lines[rel] = [ln.rstrip("\r") for ln in self.read(rel).split("\n")]
        return self._lines[rel]

    def comment_spans(self, rel: str) -> List[Tuple[int, int]]:
        """Cached comment_spans() of a file."""
        if rel not in self._spans:
            self._spans[rel] = comment_spans(self.read(rel), rel)
        return self._spans[rel]

    def code_view(self, rel: str) -> str:
        """File text with comments (including /* */ blocks) blanked to spaces.
        Same length and newlines as read(rel)."""
        if rel not in self._views:
            self._views[rel] = _blank(self.read(rel), self.comment_spans(rel))
        return self._views[rel]

    def code_lines(self, rel: str) -> List[str]:
        """Lines of code_view(), with whole-line comments (is_comment_line) also
        blanked. Line n is code_lines(rel)[n-1]; use it instead of a per-line
        is_comment_line() loop so block comments count as comments."""
        if rel not in self._code_lines:
            out = []
            for ln in self.code_view(rel).split("\n"):
                ln = ln.rstrip("\r")
                out.append("" if is_comment_line(ln, rel) else ln)
            self._code_lines[rel] = out
        return self._code_lines[rel]

    def in_comment(self, rel: str, offset: int) -> bool:
        """True when the character at offset of read(rel) sits inside a comment."""
        spans = self.comment_spans(rel)
        if not spans:
            return False
        i = bisect.bisect_right(spans, (offset, float("inf"))) - 1
        return i >= 0 and spans[i][0] <= offset < spans[i][1]

    def json(self, rel: str) -> Any:
        """Cached parsed JSON of a file, or None if missing or invalid."""
        if rel not in self._json:
            try:
                self._json[rel] = json.loads(self.read(rel) or "null")
            except ValueError:
                self._json[rel] = None
        return self._json[rel]

    def exists(self, rel: str) -> bool:
        """True if rel exists under root (file or folder), even if skipped by the walk."""
        if rel in self._fileset:
            return True
        p = self._safe_path(rel)
        return p is not None and p.exists()

    def glob(self, *patterns: str) -> List[str]:
        """Files from self.files matching any of the globs (see glob_match)."""
        return [f for f in self.files if match_any(f, patterns)]

    def line_of(self, rel: str, offset: int) -> int:
        """1-based line number of a character offset in the file text."""
        if rel not in self._starts:
            text = self.read(rel)
            starts = [0]
            for m in re.finditer("\n", text):
                starts.append(m.end())
            self._starts[rel] = starts
        return bisect.bisect_right(self._starts[rel], offset)

    def line_offset(self, rel: str, line: int) -> int:
        """Character offset where 1-based line starts (end of text past the last line)."""
        self.line_of(rel, 0)
        starts = self._starts[rel]
        return starts[line - 1] if 0 < line <= len(starts) else len(self.read(rel))

    def window(self, rel: str, line: int, before: int = 3, after: int = 3) -> str:
        """Text of lines [line-before, line+after] (1-based, clamped)."""
        ls = self.lines(rel)
        lo = max(0, line - 1 - before)
        hi = min(len(ls), line + after)
        return "\n".join(ls[lo:hi])

    def memo(self, key: Any, fn: Callable[[], Any]) -> Any:
        """Compute fn() once per scan and cache it under key. Use for cross-file indexes."""
        if key not in self._memo:
            self._memo[key] = fn()
        return self._memo[key]

    def warn(self, message: str) -> None:
        """Record an internal warning (shown on stderr / in JSON warnings)."""
        self.warnings.append(message)

    # -- stacks and versions -----------------------------------------------
    def has_stack(self, *names: str) -> bool:
        """True if any of names is a detected stack."""
        return any(n in self.stacks for n in names)

    def installed_version(self, name: str) -> Optional[str]:
        """Best guess of an npm package's installed version: node_modules, then
        package-lock.json, yarn.lock, pnpm-lock.yaml, bun.lock, then the range
        in package.json (returned as written, e.g. '^14.2.3')."""
        return self.memo(("installed_version", name), lambda: self._installed_version(name))

    def _installed_version(self, name: str) -> Optional[str]:
        data = self.json("node_modules/%s/package.json" % name)
        if isinstance(data, dict) and data.get("version"):
            return str(data["version"])
        lock = self.json("package-lock.json")
        if isinstance(lock, dict):
            pk = lock.get("packages") or {}
            ent = pk.get("node_modules/" + name)
            if isinstance(ent, dict) and ent.get("version"):
                return str(ent["version"])
            dp = lock.get("dependencies") or {}
            ent = dp.get(name)
            if isinstance(ent, dict) and ent.get("version"):
                return str(ent["version"])
        esc = re.escape(name)
        yarn = self.read("yarn.lock")
        if yarn:
            m = re.search(r'(?m)^"?' + esc + r'@[^\n]*:\s*\n\s+version:?\s+"?([0-9][^"\s]*)', yarn)
            if m:
                return m.group(1)
        pnpm = self.read("pnpm-lock.yaml")
        if pnpm:
            m = re.search(r"""(?m)^\s*['"]?/?""" + esc + r"""[@/]([0-9][^'":(\s]*)""", pnpm)
            if m:
                return m.group(1)
        bun = self.read("bun.lock")
        if bun:
            m = re.search(r'"' + esc + r'@([0-9][^"]*)"', bun)
            if m:
                return m.group(1)
        return self.deps.get(name)

    @property
    def next_version(self) -> Optional[str]:
        """Installed or declared Next.js version string, or None."""
        if "next" not in self.deps:
            return None
        return self.installed_version("next")

    # -- packages (monorepos) -------------------------------------------------
    def package_dirs(self) -> set:
        """Folders ('' = root) that hold a package.json."""
        if self._pkg_dirs is None:
            dirs = set()
            for f in self.files:
                if f == "package.json":
                    dirs.add("")
                elif f.endswith("/package.json"):
                    dirs.add(f[:-len("/package.json")])
            self._pkg_dirs = dirs
        return self._pkg_dirs

    def package_of(self, rel: str) -> Optional[str]:
        """The folder of the nearest package.json above rel ('' = the root one),
        or None when no package.json covers it."""
        d = rel.rsplit("/", 1)[0] if "/" in rel else ""
        if d in self._pkg_of:
            return self._pkg_of[d]
        dirs = self.package_dirs()
        cur: Optional[str] = d
        found: Optional[str] = None
        while cur is not None:
            if cur in dirs:
                found = cur
                break
            cur = (cur.rsplit("/", 1)[0] if "/" in cur else "") if cur else None
        self._pkg_of[d] = found
        return found

    def package_deps(self, pkg: Optional[str]) -> Dict[str, str]:
        """All dependency sections of one package.json folder, merged."""
        if pkg is None:
            return {}
        data = self.json((pkg + "/" if pkg else "") + "package.json")
        out: Dict[str, str] = {}
        if isinstance(data, dict):
            for section in _DEP_SECTIONS:
                block = data.get(section)
                if isinstance(block, dict):
                    for k, v in block.items():
                        out.setdefault(k, v if isinstance(v, str) else str(v))
        return out

    def _flags(self, pkg: Optional[str]) -> Dict[str, bool]:
        """What kind of code a package folder holds; repo-wide stacks when the
        package names no framework (shared libraries) or there is no package."""
        if pkg in self._pkg_flags:
            return self._pkg_flags[pkg]
        flags = {"mobile": False, "server": False, "spa": False, "next": False, "tanstack": False}
        decided = False
        if pkg is not None:
            deps = self.package_deps(pkg)
            app_json = self.json((pkg + "/" if pkg else "") + "app.json")
            mobile = "expo" in deps or "react-native" in deps or (isinstance(app_json, dict) and "expo" in app_json)
            nxt = "next" in deps
            tanstack = any(k in deps for k in TANSTACK_START_PACKAGES)
            ssr = any(k in deps for k in SSR_PACKAGES)
            # Workspaces often hoist vite to the root package.json.
            vite = "vite" in deps or ("" in self.package_dirs() and "vite" in self.package_deps(""))
            spa = ("react-scripts" in deps or (vite and not ssr and any(k in deps for k in SPA_UI_PACKAGES)))
            server = (any(k in deps for k in SERVER_PACKAGES) and not any(k in deps for k in _BROWSER_PACKAGES))
            if mobile or nxt or tanstack or spa or server or ssr:
                flags.update(mobile=mobile, server=server, spa=spa, next=nxt, tanstack=tanstack)
                decided = True
        if not decided:
            flags.update(
                mobile=self.has_stack("expo", "react-native"),
                next="next" in self.deps or self.has_stack("nextjs-app", "nextjs-pages"),
                tanstack=self.has_stack("tanstack-start"),
            )
            flags["spa"] = self.has_stack("react-vite", "cra", "vite-spa") and not flags["next"]
        self._pkg_flags[pkg] = flags
        return flags

    # -- TanStack Start -------------------------------------------------------
    def tanstack_kind(self, rel: str) -> Optional[str]:
        """For code in a TanStack Start package: "server" (*.server.*, src/server.ts),
        "functions" (*.functions.* or a createServerFn / createMiddleware file),
        "route-handlers" (a route with server: { handlers }) or "client".
        None when rel is not code of a TanStack Start package."""
        ext = os.path.splitext(rel)[1].lower()
        if ext not in CODE_EXTS:
            return None
        if not self._flags(self.package_of(rel))["tanstack"]:
            return None
        name = rel.rsplit("/", 1)[-1]
        if re.search(r"(?:^|\.)server\.[a-z]+$", name):
            return "server"
        if re.search(r"\.functions\.[a-z]+$", name):
            return "functions"
        text = self.read(rel)
        if _TS_HANDLERS.search(text) and _TS_SERVER_KEY.search(text):
            return "route-handlers"
        if _TS_SERVER_FN_CALL.search(text):
            return "functions"
        return "client"

    def tanstack_auth_middlewares(self) -> set:
        """Names of createMiddleware() values whose body verifies the caller
        (getClaims, getUser, verifyIdToken, jwtVerify), across the project."""
        def build() -> set:
            names = set()
            for f in self.files:
                if os.path.splitext(f)[1].lower() not in CODE_EXTS:
                    continue
                text = self.read(f)
                if "createMiddleware" not in text:
                    continue
                code = self.code_view(f)
                defs = list(_TS_MIDDLEWARE_DEF.finditer(code))
                for i, m in enumerate(defs):
                    end = defs[i + 1].start() if i + 1 < len(defs) else len(code)
                    if _TS_AUTH_CALL.search(code, m.end(), min(end, m.end() + 8000)):
                        names.add(m.group(1))
            return names
        return self.memo("tanstack-auth-middlewares", build)

    def tanstack_server_fns(self, rel: str) -> List[Dict[str, Any]]:
        """createServerFn() definitions in a file: dicts with name, line, offset
        (of createServerFn), method, middleware (names), auth (a middleware that
        verifies the caller is attached) and handler_offset (of ".handler(", or -1)."""
        def build() -> List[Dict[str, Any]]:
            code = self.code_view(rel)
            if "createServerFn" not in code:
                return []
            auth_names = self.tanstack_auth_middlewares()
            found = list(_TS_SERVER_FN.finditer(code))
            out = []
            for i, m in enumerate(found):
                start = m.start() if m.group(1) is None else code.index("createServerFn", m.start())
                stop = found[i + 1].start() if i + 1 < len(found) else len(code)
                h = code.find(".handler(", start, stop)
                chain = code[start:h if h != -1 else min(stop, start + 4000)]
                mws: List[str] = []
                for mm in re.finditer(r"\.middleware\s*\(\s*\[([^\]]*)\]", chain):
                    mws.extend(x for x in re.findall(r"[A-Za-z_$][\w$]*", mm.group(1)))
                meth = re.search(r"""method\s*:\s*["'](\w+)["']""", chain)
                out.append({
                    "name": m.group(1) or "", "line": self.line_of(rel, start), "offset": start,
                    "method": (meth.group(1).upper() if meth else "GET"), "middleware": mws,
                    "auth": any(x in auth_names for x in mws), "handler_offset": h,
                })
            return out
        return self.memo(("tanstack-server-fns", rel), build)

    def tanstack_route_handlers(self, rel: str) -> List[Tuple[str, int]]:
        """(METHOD, line) for each handler in a route's server: { handlers: { ... } }."""
        def build() -> List[Tuple[str, int]]:
            code = self.code_view(rel)
            out: List[Tuple[str, int]] = []
            for m in _TS_HANDLERS.finditer(code):
                if not _TS_SERVER_KEY.search(code, max(0, m.start() - 400), m.start()):
                    continue
                brace = m.end() - 1
                body = code[brace:_balanced_end(code, brace)]
                for km in _TS_METHOD_KEY.finditer(body):
                    pre = body[:km.start()]
                    if pre.count("{") - pre.count("}") == 1:
                        out.append((km.group(1), self.line_of(rel, brace + km.start())))
            return out
        return self.memo(("tanstack-route-handlers", rel), build)

    # -- client / minified heuristics ---------------------------------------
    def is_minified(self, rel: str) -> bool:
        """True for *.min.js/css and files whose lines average over 300 chars."""
        if rel in self._minified:
            return self._minified[rel]
        name = rel.rsplit("/", 1)[-1]
        if re.search(r"\.min\.(?:js|css|mjs)$|[.-]bundle\.js$|\.chunk\.js$", name):
            res = True
        else:
            text = self.read(rel)
            n = text.count("\n") + 1
            res = len(text) > 5000 and len(text) / n > 300
        self._minified[rel] = res
        return res

    def is_client_file(self, rel: str) -> bool:
        """Heuristic: does this file's code ship to the browser or the mobile app?

        Decided per package in monorepos: the nearest package.json says what the
        folder is (Expo / React Native app, Next.js, a Vite or CRA SPA, TanStack
        Start, or a plain Node server such as Express or Hono). A package that
        names none of them falls back to the repo-wide stacks.
        Server markers win: "use server", import 'server-only', route.ts handlers,
        pages/api, root api/, middleware/proxy, *.server.*, *.functions.*, +server,
        +api, config, test and story files, folders like server/, backend/, and
        functions/, supabase/, prisma/, scripts/ at the top of the repo or of the
        package, supabase/functions/ at any depth, and any file of a package that
        depends on a Node server framework and on no browser or mobile framework.
        Client when: a "use client" directive; .vue/.svelte files; JS under
        public/ or static/; src/ in a Vite or CRA SPA; src/ in TanStack Start
        unless the file defines server functions, middleware or route handlers;
        resources/js/ in Laravel; any app code in an Expo / React Native package;
        a client/ or frontend/ folder; components/ folders (in Next.js only with
        "use client" or React hooks / event handlers); Next.js pages/ files without
        getServerSideProps, getStaticProps or getInitialProps.
        Unsure cases return False, so client_only rules stay quiet.
        """
        if rel in self._client:
            return self._client[rel]
        res = self._classify_client(rel)
        self._client[rel] = res
        return res

    def _classify_client(self, rel: str) -> bool:
        ext = os.path.splitext(rel)[1].lower()
        if ext not in CODE_EXTS:
            return False
        parts = rel.split("/")
        name = parts[-1]
        dirs = parts[:-1]
        pkg = self.package_of(rel)
        local = rel[len(pkg) + 1:] if pkg else rel
        ldirs = local.split("/")[:-1]
        flags = self._flags(pkg)
        mobile = flags["mobile"]
        if _SERVER_NAME.search(name) or _MIDDLEWARE.match(rel) or _MIDDLEWARE.match(local):
            return False
        if not ldirs and _ROOT_ENTRY.match(name) and not mobile:
            return False
        if (dirs and dirs[0] in _SERVER_ROOTS) or (ldirs and ldirs[0] in _SERVER_ROOTS):
            return False
        if _SERVER_PAIRS.search(rel):
            return False
        if any(d in _SERVER_SEGMENTS for d in dirs):
            return False
        joined = "/" + rel
        if "/pages/api/" in joined or re.search(r"/app/(?:.*/)?api/", joined):
            return False
        if _ROUTE_HANDLER.match(name) and "app" in dirs:
            return False
        text = self.read(rel)
        if _USE_SERVER.match(text) or _SERVER_ONLY.search(text):
            return False
        if _USE_CLIENT.match(text):
            return True
        if ext in (".vue", ".svelte"):
            return True
        if (dirs and dirs[0] in ("public", "static")) or (ldirs and ldirs[0] in ("public", "static")):
            return True
        if "client" in dirs or "frontend" in dirs:
            return True
        if flags["server"]:
            return False
        if mobile:
            return True
        if flags["tanstack"]:
            if _ts_server_code(text):
                return False
            return bool(ldirs) and ldirs[0] in ("src", "app")
        nextjs = flags["next"]
        if flags["spa"] and not nextjs and ldirs and ldirs[0] == "src":
            return True
        if self.has_stack("laravel") and rel.startswith("resources/js/"):
            return True
        if nextjs:
            if _CLIENT_HINTS.search(text) and not _PAGES_SERVER.search(text):
                return True
            pages_dir = (ldirs[:1] == ["pages"]) or (ldirs[:2] == ["src", "pages"])
            if pages_dir and not name.startswith("_document") and not _PAGES_SERVER.search(text):
                return True
            return False
        if "components" in dirs:
            return True
        return False

    @property
    def client_files(self) -> List[str]:
        """All files in self.files that is_client_file() accepts (cached)."""
        return self.memo("client_files", lambda: [f for f in self.files if self.is_client_file(f)])
