"""Find leaked secrets in a project: source files, build output and git history.

Usage:
  python3 find_secrets.py [--json] [--output FILE] [--git-history] [--build-output]
                          [--max-findings N] [TARGET]

TARGET is a folder or a single file (default: current folder). Every value is
masked (first 4 + length + last 4). Public-by-design keys (Stripe pk_,
Supabase anon / sb_publishable_, Firebase web apiKey, Sentry DSN, PostHog phc_)
are not reported; their counts appear under "public keys not reported".
Keystore and PKCS#12 files are reported by name, and an env file that git
tracks (or does not ignore) gets an info note even before a secret lands in it.
A value a nearby comment calls fake or throwaway drops to info in test paths
and to low elsewhere. --git-history warns when the clone is shallow.

Exit codes: 0 nothing found, 1 secrets found, 2 usage or runtime error.

Importable API (check_live.py uses scan_text):
  scan_text(text, rel, source) -> (findings, public_keys)
  scan_source(target) / scan_build_output(target) / scan_git_history(target)
  run(target, git_history=False, build_output=False) -> (findings, warnings, meta)
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import _secret_patterns as sp  # noqa: E402
import _wardcore as wc  # noqa: E402

SCRIPT = "find_secrets"
SKILL = "secrets"
KLASS = "exposed secret"
BUILD_MAX_BYTES = 16 * 1024 * 1024

_LOW_CONFIDENCE_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|spec|specs|fixtures?|__fixtures__|mocks?|__mocks__|docs?|examples?|stories"
    r"|e2e|cypress|playwright|testdata|test-data|__snapshots__)/"
    r"|\.(?:test|spec|stories|e2e|cy)\.[a-z]+$|(?:^|/)readme[^/]*$|\.mdx?$|local[-_]?testing[^/]*$", re.I)

# A comment on the line, or just above it, that calls the value fake.
_FAKE_MARKER_RX = re.compile(
    r"(?i)\b(?:fake|dummy|throw-?away|not\s+(?:a\s+)?real|placeholder"
    r"|(?:example|sample|mock(?:ed)?)\s+(?:key|secret|token|value|password)"
    r"|test(?:ing)?[\s_-]+(?:only|secret|key|token|value|password|fixture))\b")
_COMMENT_START_RX = re.compile(r"^\s*(?://|#|/?\*|<!--|--|;)")
# Env files that only a test run or CI job loads.
_TEST_ENV_NAMES = frozenset({".env.test", ".env.e2e", ".env.ci", ".env.testing"})
# Hits whose line can hold the rest of a key body: show only the masked match.
_WHOLE_LINE_SECRETS = frozenset({"private-key", "gcp-service-account"})
_B64_RUN_RX = re.compile(r"[A-Za-z0-9+/=]{12,}")


# ---------------------------------------------------------------------------
# Turning pattern hits into findings
# ---------------------------------------------------------------------------

def _evidence(text: str, hit: "sp.SecretHit") -> str:
    a = text.rfind("\n", 0, hit.start) + 1
    b = text.find("\n", hit.end)
    b = len(text) if b == -1 else b
    line = text[a:b]
    s, e = hit.start - a, min(hit.end, b) - a
    masked = wc.mask(hit.value)
    if hit.name in _WHOLE_LINE_SECRETS:
        # A key stored on one line (escaped newlines in JSON, JS or Terraform)
        # puts its base64 body after the header; never print any of it.
        prefix = _B64_RUN_RX.sub(lambda m: "[%d chars]" % len(m.group(0)), line[:s])[-60:]
        return wc.clip(wc.redact(sp.redact(prefix)) + masked + " ...", 0, None, 160).strip()
    line = line[:s] + masked + line[e:]
    line = wc.redact(sp.redact(line))
    return wc.clip(line, s, s + len(masked), 160)


def _marked_fake(text: str, hit: "sp.SecretHit") -> bool:
    """True when the hit's line, or the comment lines just above it, call the
    value fake, dummy, throwaway or a test secret."""
    a = text.rfind("\n", 0, hit.start) + 1
    b = text.find("\n", hit.end)
    line = text[a:hit.start] + " " + text[hit.end:len(text) if b == -1 else b]
    if _FAKE_MARKER_RX.search(line):
        return True
    end = a - 1
    for _ in range(4):
        if end <= 0:
            break
        start = text.rfind("\n", 0, end) + 1
        prev = text[start:end]
        end = start - 1
        if not prev.strip():
            continue
        if not _COMMENT_START_RX.match(prev):
            break
        if _FAKE_MARKER_RX.search(prev):
            return True
    return False


def _classify(text: str, rel: str, hit: "sp.SecretHit") -> Tuple[str, str, str, str, str]:
    """(rule, severity, kind, message, confidence) for one hit in file rel."""
    name, severity, kind, message = hit.name, hit.severity, hit.kind, hit.message
    test_path = bool(_LOW_CONFIDENCE_PATH.search(rel))
    conf = "high" if kind == "secret" else "medium"
    if test_path:
        conf = "medium"
    base = rel.rsplit("/", 1)[-1].lower()
    if name.startswith("supabase-demo-") and base in _TEST_ENV_NAMES:
        return ("supabase-local-demo-jwt", "info", "note", sp.DESCRIPTIONS["supabase-local-demo-jwt"], "medium")
    if kind == "secret" and _marked_fake(text, hit):
        if test_path:
            return (name, "info", "note", message + " (a comment marks it as a fake test value)", "medium")
        return (name, "low", kind, message + "; a nearby comment says it is a fake or throwaway value, confirm "
                "that before rotating", "low")
    return (name, severity, kind, message, conf)


def _hits(text: str, rel: str) -> List["sp.SecretHit"]:
    hits = sp.find_secrets_in_text(text) + sp.find_context_secrets(text, rel)
    hits.sort(key=lambda h: h.start)
    return hits


def scan_text(text: str, rel: str, source: str = "source") -> Tuple[List[wc.Finding], List[Tuple[str, int]]]:
    """Scan one text blob. Returns (findings, public_keys).

    source is a label stored in finding.extra["source"] ("source", "build",
    "bundle", "git-history", ...). Messages are the plain description; callers
    add context. public_keys is a list of (name, line) for keys that are public
    by design and therefore not reported.

    A value that a comment on its line (or just above) calls fake, dummy or
    throwaway drops to info in test paths and to low elsewhere.
    """
    findings = []
    for hit in _hits(text, rel):
        rule, severity, kind, message, conf = _classify(text, rel, hit)
        findings.append(wc.Finding(
            skill=SKILL, klass=KLASS if kind == "secret" else "key to review",
            severity=severity, file=rel, line=hit.line, rule=rule, message=message,
            evidence=_evidence(text, hit), fix_ref=sp.ROTATION_REF.get(rule, "rotation.md"),
            confidence=conf, needs_confirmation=kind != "secret",
            extra={"source": source}))
    return findings, sp.find_public_keys(text)


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------

def _git_exe() -> Optional[str]:
    return shutil.which("git")


def _git(root: Path, args: Sequence[str], stdin: Optional[str] = None, timeout: int = 120
         ) -> Optional[subprocess.CompletedProcess]:
    exe = _git_exe()
    if not exe:
        return None
    try:
        return subprocess.run([exe, "-C", str(root), "-c", "core.quotepath=off"] + list(args),
                              input=stdin, capture_output=True, encoding="utf-8", errors="replace",
                              timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _in_git_repo(root: Path) -> bool:
    r = _git(root, ["rev-parse", "--is-inside-work-tree"])
    return bool(r and r.returncode == 0 and r.stdout.strip() == "true")


def git_file_status(root: Path, rels: Sequence[str]) -> Tuple[Optional[Set[str]], Optional[Set[str]]]:
    """(tracked, ignored) sets for rels relative to root, or (None, None) when
    root is not inside a git work tree or git is missing."""
    if not rels or not _in_git_repo(root):
        return None, None
    tracked: Set[str] = set()
    r = _git(root, ["ls-files", "-z"])
    if r is None or r.returncode != 0:
        return None, None
    tracked.update(p for p in r.stdout.split("\0") if p)
    ignored: Set[str] = set()
    r = _git(root, ["check-ignore", "-z", "--stdin"], stdin="\0".join(rels) + "\0")
    if r is not None and r.returncode in (0, 1):
        ignored.update(p for p in r.stdout.split("\0") if p)
    return tracked, ignored


def _gitignore_covers(root: Path, rel: str) -> bool:
    """Rough .gitignore check for folders that are not git repos yet.

    Reads the .gitignore at root and in every folder between root and the
    file; patterns in a nested .gitignore are relative to its own folder."""
    parts = rel.split("/")
    name = parts[-1]
    covered = False
    for depth in range(len(parts)):
        text = wc.read_text(root.joinpath(*parts[:depth]) / ".gitignore")
        if not text:
            continue
        sub = "/".join(parts[depth:])
        for raw in text.split("\n"):
            pat = raw.strip()
            if not pat or pat.startswith("#"):
                continue
            neg = pat.startswith("!")
            pat = pat.lstrip("!").lstrip("/").rstrip("/")
            if not pat:
                continue
            hit = fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(sub, pat) or fnmatch.fnmatch(sub, pat + "/*")
            if hit:
                covered = not neg
    return covered


# ---------------------------------------------------------------------------
# Source scan
# ---------------------------------------------------------------------------

# Binary containers that hold private keys (Android and Java keystores, PKCS#12).
_KEY_CONTAINER_EXTS = (".keystore", ".jks", ".p12", ".pfx", ".bks")


def iter_key_containers(target: Path) -> Iterator[str]:
    """Relative paths of keystore and PKCS#12 files under target. The text walk
    skips them as binary. Android debug keystores (debug.keystore, published
    password "android") are left out."""
    def wanted(name: str) -> bool:
        low = name.lower()
        return low.endswith(_KEY_CONTAINER_EXTS) and "debug" not in low

    if target.is_file():
        if wanted(target.name):
            yield target.name
        return
    for dirpath, dirnames, filenames in os.walk(str(target)):
        rel_dir = wc.rel_posix(dirpath, target)
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in sorted(dirnames):
            sub = (rel_dir + "/" + d) if rel_dir else d
            if d in wc.SKIP_DIRS or wc.is_build_path(sub + "/x"):
                continue
            if os.path.exists(os.path.join(dirpath, d, "pyvenv.cfg")) or wc.is_ward_skill_dir(os.path.join(dirpath, d)):
                continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            if wanted(name):
                yield (rel_dir + "/" + name) if rel_dir else name


def _container_finding(rel: str) -> wc.Finding:
    low = rel.lower()
    android = low.endswith((".keystore", ".jks"))
    msg = ("Signing keystore or private key container (%s) in the project; with its password anyone can sign or "
           "decrypt as you" % rel.rsplit("/", 1)[-1])
    if android:
        msg += ". If it is an Android release or upload key, reset the upload key through Play App Signing"
    test_path = bool(_LOW_CONFIDENCE_PATH.search(rel))
    return wc.Finding(skill=SKILL, klass=KLASS, severity="low" if test_path else "high", file=rel, line=0,
                      rule="private-key-file", message=msg, evidence="", fix_ref="rotation.md#private-keys",
                      confidence="medium" if test_path else "high", extra={"source": "source"})


def scan_source(target: Path) -> Tuple[List[wc.Finding], Counter, int]:
    """Scan the working tree (no build output). Returns (findings, public_counts, files_scanned).

    Secrets in files git ignores (and does not track) become one info note per
    file: a local .env that never gets committed is where secrets belong. In a
    folder that is not a git repo, the .gitignore files decide (any file, not
    only env files). Keystore and PKCS#12 files are reported by name. An env
    file that git tracks (or does not ignore) gets an info note even when it
    holds no secret yet, since the next key written to it gets committed.
    """
    base = target.parent if target.is_file() else target
    public: Counter = Counter()
    per_file: Dict[str, Tuple[str, List[wc.Finding]]] = {}
    env_files: List[str] = []
    count = 0
    for tf in wc.iter_text_files(target, skip_examples=False):
        count += 1
        if wc.is_env_file(tf.rel) and not wc.is_example_file(tf.rel):
            env_files.append(tf.rel)
        found, pub = scan_text(tf.text, tf.rel, "source")
        for name, _line in pub:
            public[name] += 1
        if found:
            per_file[tf.rel] = (tf.text, found)
    for rel in iter_key_containers(target):
        count += 1
        per_file[rel] = ("", [_container_finding(rel)])

    tracked, ignored = git_file_status(base, sorted(set(per_file) | set(env_files)))
    git_mode = tracked is not None
    out: List[wc.Finding] = []
    for rel in sorted(env_files):
        has_secret = any(f.severity != "info" for f in per_file.get(rel, ("", []))[1])
        if has_secret or rel.rsplit("/", 1)[-1].lower() in _TEST_ENV_NAMES or _LOW_CONFIDENCE_PATH.search(rel):
            # Test and CI env files are meant to be committed with throwaway values.
            continue
        if git_mode:
            if rel in tracked:
                state = "tracked"
                where = "is committed to git"
            elif rel in ignored:
                continue
            else:
                state = "untracked"
                where = "is not git-ignored, so the next commit would include it"
        else:
            if _gitignore_covers(base, rel):
                continue
            state = "no-gitignore"
            where = "is not covered by any .gitignore"
        fix = "add it to .gitignore" + (" and run git rm --cached %s" % rel if state == "tracked" else "")
        out.append(wc.Finding(
            skill=SKILL, klass="env file in git", severity="info", file=rel, line=0, rule="env-file-tracked",
            message="%s %s. It holds no secret now, but a key added later (STRIPE_SECRET_KEY, OPENAI_API_KEY) "
                    "would be committed with it: %s, or keep only public values here and put server secrets in "
                    ".env.local or the host's secret store" % (rel, where, fix),
            evidence="", fix_ref="secrets.md#fail-closed-on-missing-env", confidence="high",
            extra={"source": "source", "git": state}))
    for rel in sorted(per_file):
        _text, found = per_file[rel]
        if wc.is_example_file(rel):
            # The published Supabase self-hosting template ships demo keys on purpose.
            found = [f for f in found if not f.rule.startswith(("supabase-demo-", "supabase-local-demo-"))]
        secrets = [f for f in found if f.severity != "info"]
        notes = [f for f in found if f.severity == "info"]
        if git_mode:
            is_tracked = rel in tracked
            is_ignored = (rel in ignored) and not is_tracked
        else:
            is_tracked = False
            is_ignored = _gitignore_covers(base, rel)
        if is_ignored and secrets:
            kinds = sorted({f.rule for f in secrets})
            out.append(wc.Finding(
                skill=SKILL, klass="local secret file", severity="info", file=rel, line=secrets[0].line,
                rule="secret-in-ignored-file",
                message="%d secret%s in a git-ignored file (not committed). Keep it out of deploy uploads "
                        "and Docker images." % (len(secrets), "" if len(secrets) == 1 else "s"),
                evidence=", ".join(kinds), fix_ref="rotation.md", confidence="high",
                extra={"source": "source", "git": "ignored"}))
            out.extend(notes)
            continue
        for f in secrets:
            if wc.is_example_file(rel):
                f.message += " in an env template. Templates are committed, so a real value here is public"
                f.confidence = "medium"
            elif git_mode and is_tracked:
                f.message += " in a file tracked by git"
                f.extra["git"] = "tracked"
            elif git_mode:
                f.message += " in a file git does not ignore yet (the next commit would include it)"
                f.extra["git"] = "untracked"
            elif wc.is_env_file(rel):
                f.message += " in an env file that no .gitignore covers"
        out.extend(secrets)
        out.extend(notes)
    return out, public, count


# ---------------------------------------------------------------------------
# Build output scan
# ---------------------------------------------------------------------------

_NEXT_PRUNE = frozenset({"cache", "standalone", "types", "trace"})


def build_kind(rel: str) -> Optional[str]:
    """'served' for output that browsers download, 'build' for other build
    folders (dist/, build/, out/), None for anything else.

    Next.js: .next/static/** and the prerendered .next/server/app/**/*.{html,rsc,body,meta}
    and .next/server/pages/**/*.{html,json} are served; server chunks are not.
    """
    parts = rel.split("/")
    ext = os.path.splitext(parts[-1])[1].lower()
    if ".next" in parts[:-1]:
        sub = parts[parts.index(".next") + 1:]
        if sub[:1] == ["static"]:
            return "served"
        if sub[:2] == ["server", "app"] and ext in (".html", ".rsc", ".body", ".meta"):
            return "served"
        if sub[:2] == ["server", "pages"] and ext in (".html", ".json"):
            return "served"
        return None
    dirs = parts[:-1]
    for i, p in enumerate(dirs):
        nxt = dirs[i + 1:i + 3]
        if p == "storybook-static":
            return "served"
        if p == ".output" and nxt[:1] == ["public"]:
            return "served"
        if p == ".svelte-kit" and nxt == ["output", "client"]:
            return "served"
        if p == "build" and i > 0 and dirs[i - 1] == "public":
            return "served"
    for p in dirs:
        if p in ("dist", "build", "out"):
            return "build"
    return None


def iter_build_files(target: Path) -> Iterator[Tuple[Path, str, str]]:
    """Yield (path, rel, kind) for build output files under target."""
    if target.is_file():
        return
    for dirpath, dirnames, filenames in os.walk(str(target)):
        rel_dir = wc.rel_posix(dirpath, target)
        rel_dir = "" if rel_dir == "." else rel_dir
        keep = []
        for d in sorted(dirnames):
            if d in wc.SKIP_DIRS:
                continue
            if rel_dir.endswith(".next") or rel_dir == ".next":
                if d in _NEXT_PRUNE:
                    continue
            keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            rel = (rel_dir + "/" + name) if rel_dir else name
            kind = build_kind(rel)
            if not kind:
                continue
            if os.path.splitext(name)[1].lower() in wc.BINARY_EXTS:
                continue
            yield Path(dirpath) / name, rel, kind


def scan_build_output(target: Path) -> Tuple[List[wc.Finding], Counter, int]:
    """Scan build output folders. Returns (findings, public_counts, files_scanned)."""
    out: List[wc.Finding] = []
    public: Counter = Counter()
    count = 0
    for path, rel, kind in iter_build_files(target):
        text = wc.read_text(path, max_bytes=BUILD_MAX_BYTES)
        if text is None:
            continue
        count += 1
        found, pub = scan_text(text, rel, "build")
        for name, _line in pub:
            public[name] += 1
        for f in found:
            if f.severity == "info":
                out.append(f)
                continue
            if rel.endswith(".map"):
                f.message += " in a source map in the build output"
            elif kind == "served":
                f.message += " in build output that is served to browsers"
            else:
                f.message += " in build output (check whether this folder is deployed or served)"
            f.extra["build"] = kind
            out.append(f)
    return out, public, count


# ---------------------------------------------------------------------------
# Git history scan
# ---------------------------------------------------------------------------

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _diff_path(raw: str) -> str:
    p = raw.rstrip("\t\r\n")
    if len(p) >= 2 and p.startswith('"') and p.endswith('"'):
        p = p[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if p.startswith(("a/", "b/")):
        p = p[2:]
    return p


def scan_git_history(target: Path) -> Tuple[List[wc.Finding], List[str]]:
    """Stream `git log --all -p` and report secrets that were ever added.

    Each distinct value is reported once, at the oldest commit that added it.
    Returns (findings, warnings). Missing git or a non-repo is a warning, not
    an error.
    """
    base = target.parent if target.is_file() else target
    exe = _git_exe()
    if not exe:
        return [], ["git was not found on PATH, so --git-history was skipped"]
    if not _in_git_repo(base):
        return [], ["%s is not inside a git repository, so --git-history was skipped" % base.as_posix()]
    prefix = ""
    r = _git(base, ["rev-parse", "--show-prefix"])
    if r is not None and r.returncode == 0:
        prefix = r.stdout.strip()
    cmd = [exe, "-C", str(base), "-c", "core.quotepath=off", "log", "--all", "-p", "--no-color",
           "--no-ext-diff", "--no-textconv", "-U0", "--format=commit %H", "--", "."]
    found: Dict[Tuple[str, str], wc.Finding] = {}
    counts: Counter = Counter()
    warnings: List[str] = []
    r = _git(base, ["rev-parse", "--is-shallow-repository"])
    if r is not None and r.returncode == 0 and r.stdout.strip() == "true":
        n = _git(base, ["rev-list", "--count", "--all"])
        reach = n.stdout.strip() if n is not None and n.returncode == 0 and n.stdout.strip() else "?"
        warnings.append("this clone is shallow (%s commit%s reachable), so secrets deleted in older commits were "
                        "not checked; run git fetch --unshallow and scan again" % (reach, "" if reach == "1" else "s"))

    state = {"commit": "", "file": "", "line": 0, "added": []}

    def flush() -> None:
        added = state["added"]
        if not added or not state["file"]:
            state["added"] = []
            return
        text = "\n".join(t for _n, t in added)
        rel = state["file"]
        if prefix and rel.startswith(prefix):
            rel = rel[len(prefix):]
        for hit in _hits(text, rel):
            rule, severity, kind, message, conf = _classify(text, rel, hit)
            if kind != "secret":
                continue
            idx = max(0, min(len(added) - 1, hit.line - 1))
            key = (rule, hit.value)
            counts[key] += 1
            found[key] = wc.Finding(
                skill=SKILL, klass=KLASS, severity=severity, file=rel, line=added[idx][0],
                rule=rule,
                message=message + " in git history. Deleting it later does not remove it; rotate it",
                evidence=_evidence(text, hit), fix_ref=sp.ROTATION_REF.get(rule, "rotation.md"),
                confidence=conf, extra={"source": "git-history", "commit": state["commit"]})
        state["added"] = []

    err = tempfile.TemporaryFile()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=err, encoding="utf-8", errors="replace")
    except OSError as exc:
        err.close()
        return [], ["could not run git log: %s" % exc]
    try:
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            if line.startswith("commit ") and len(line) >= 47:
                flush()
                state["commit"] = line[7:].strip()
                state["file"] = ""
                continue
            if line.startswith("diff --git "):
                flush()
                state["file"] = ""
                continue
            if line.startswith("--- "):
                if not state["file"] and line[4:].strip() != "/dev/null":
                    state["file"] = _diff_path(line[4:])
                continue
            if line.startswith("+++ "):
                if line[4:].strip() != "/dev/null":
                    state["file"] = _diff_path(line[4:])
                continue
            m = _HUNK.match(line)
            if m:
                state["line"] = int(m.group(1))
                continue
            if line.startswith("+"):
                state["added"].append((state["line"], line[1:]))
                state["line"] += 1
        flush()
        proc.wait()
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        err.seek(0)
        err_text = err.read().decode("utf-8", "replace").strip()
        err.close()
    if proc.returncode not in (0, None):
        warnings.append("git log exited with %s: %s" % (proc.returncode, err_text[:300]))
    out = []
    for key, f in found.items():
        if counts[key] > 1:
            f.extra["occurrences"] = counts[key]
        out.append(f)
    return out, warnings


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def run(target: Path, git_history: bool = False, build_output: bool = False
        ) -> Tuple[List[wc.Finding], List[str], Dict[str, object]]:
    """Run the requested scans. Returns (findings, warnings, meta)."""
    findings, public, n_src = scan_source(target)
    warnings: List[str] = []
    scanned = ["source"]
    n_build = 0
    if build_output:
        bf, bpub, n_build = scan_build_output(target)
        findings.extend(bf)
        public.update(bpub)
        scanned.append("build output")
        if n_build == 0:
            warnings.append("no build output found (dist/, build/, out/, .next/static); build the app first")
    if git_history:
        hf, hw = scan_git_history(target)
        findings.extend(hf)
        warnings.extend(hw)
        scanned.append("git history")
    meta: Dict[str, object] = {
        "scanned": scanned,
        "files_scanned": n_src + n_build,
        "public_keys_not_reported": dict(sorted(public.items())),
    }
    return wc.sort_findings(findings), warnings, meta


def main(argv: Optional[Sequence[str]] = None) -> int:
    wc.setup_io()
    ap = argparse.ArgumentParser(
        prog="find_secrets.py",
        description="Find leaked secrets in source files, build output and git history. "
                    "Values are always masked. Exit 0 = nothing found, 1 = secrets found, 2 = error.")
    ap.add_argument("target", nargs="?", default=".", help="project folder or file (default: .)")
    wc.add_common_args(ap)
    ap.add_argument("--git-history", action="store_true",
                    help="also scan every commit on every branch (git log --all -p)")
    ap.add_argument("--build-output", action="store_true",
                    help="also scan dist/, build/, out/, .next/static and prerendered .next/server pages")
    args = ap.parse_args(argv)
    target = wc.norm(args.target)
    if not target.exists():
        sys.stderr.write("error: %s does not exist\n" % target.as_posix())
        return wc.EXIT_ERROR
    try:
        findings, warnings, meta = run(target, git_history=args.git_history, build_output=args.build_output)
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return wc.EXIT_ERROR
    return wc.emit(findings, as_json=args.json, out_file=args.output, max_findings=args.max_findings,
                   target=target.as_posix(), script=SCRIPT, meta=meta, warnings=warnings)


if __name__ == "__main__":
    sys.exit(main())
