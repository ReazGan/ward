"""Supply chain rules (threats-logic 5): install hardening per package
manager, known-bad versions, URL and git dependency specs, risky lifecycle
scripts, worm artifacts in node_modules, and dependencies that were never
installed from the lockfile (the offline slopsquat signal).

This scan is offline. It cannot ask a registry whether a package exists or
how old it is; rules that depend on that say so in their message.

Each rule is a _wardcore.Rule; see its docstring for the fields.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import _wardcore as wc
from _wardcore import Hit, Rule

SKILL = "supply-chain"

# ---------------------------------------------------------------------------
# Data: releases known to be malicious. Only entries confirmed by a public
# advisory go here, with the source. Versions None = every version.
# LAST-VERIFIED: 2026-10-06
# ---------------------------------------------------------------------------

KNOWN_BAD: List[Dict[str, Any]] = [
    {
        "ecosystem": "npm", "name": "axios", "versions": ("1.14.1", "0.30.4"),
        "advice": "pin 1.14.0 or 0.30.3, delete node_modules/plain-crypto-js, reinstall from a clean tree and "
                  "rotate every token the machine or CI held",
        "source": "CISA alert 2026-04-20",
    },
    {
        "ecosystem": "npm", "name": "plain-crypto-js", "versions": None,
        "advice": "this package is the RAT dropper the compromised axios releases pulled in (4.2.1); delete it, "
                  "pin a clean axios and rotate every token the machine or CI held",
        "source": "CISA alert 2026-04-20",
    },
    {
        "ecosystem": "pypi", "name": "litellm", "versions": ("1.82.7", "1.82.8"),
        "advice": "1.82.7 runs a payload on import and 1.82.8 ships a .pth file that runs at interpreter "
                  "start; install a release outside these two, rebuild the virtualenv and rotate the keys it saw",
        "source": "Zscaler 2026-03-26",
    },
]

_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb")
_LOCK_MANAGER = {"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "yarn",
                 "pnpm-lock.yaml": "pnpm", "bun.lock": "bun", "bun.lockb": "bun"}
_PY_LOCKS = ("uv.lock", "poetry.lock", "pdm.lock")
_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def _dir(rel: str) -> str:
    return rel.rsplit("/", 1)[0] + "/" if "/" in rel else ""


def _ancestors(d: str) -> List[str]:
    """d and every parent folder up to the root, as 'a/b/', 'a/', ''."""
    out = [d]
    while d:
        d = d[:-1].rsplit("/", 1)[0] + "/" if "/" in d[:-1] else ""
        out.append(d)
    return out


def _line_of_text(text: str, needle: str, default: int = 1) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else default


def _pkg_json(ctx: wc.ScanContext, rel: str) -> Dict[str, Any]:
    data = ctx.json(rel)
    return data if isinstance(data, dict) else {}


def _norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_hit(entry: Dict[str, Any], version: Optional[str]) -> bool:
    versions = entry["versions"]
    if versions is None:
        return True
    v = (version or "").strip().lstrip("=v")
    return v in versions


# ---------------------------------------------------------------------------
# 1. Install hardening per package manager
# ---------------------------------------------------------------------------

def _read_up(ctx: wc.ScanContext, d: str, name: str) -> str:
    """Concatenated text of name in d and every parent folder."""
    return "\n".join(ctx.read(a + name) for a in _ancestors(d))


def _has_deps(data: Dict[str, Any]) -> bool:
    return any(isinstance(data.get(s), dict) and data.get(s) for s in ("dependencies", "devDependencies"))


def _pm_version(ctx: wc.ScanContext, d: str, manager: str) -> Optional[Tuple[int, ...]]:
    for a in _ancestors(d):
        field = _pkg_json(ctx, a + "package.json").get("packageManager")
        if isinstance(field, str) and field.startswith(manager + "@"):
            return wc.parse_version(field.split("@", 1)[1])
    return None


def _npm_items(ctx: wc.ScanContext, d: str) -> List[str]:
    rc = _read_up(ctx, d, ".npmrc")
    missing = []
    if not re.search(r"(?m)^\s*ignore-scripts\s*=\s*true\b", rc):
        missing.append("ignore-scripts=true")
    if not re.search(r"(?m)^\s*min-release-age\s*=\s*[1-9]", rc):
        missing.append("min-release-age=7 (days; only npm 11.10+ enforces it, so check npm -v: Node 22 ships "
                       "npm 10, which accepts the line and ignores it)")
    return ["add %s to .npmrc" % " and ".join(missing)] if missing else []


def _pnpm_items(ctx: wc.ScanContext, d: str) -> Tuple[List[str], List[str]]:
    ws = _read_up(ctx, d, "pnpm-workspace.yaml")
    rc = _read_up(ctx, d, ".npmrc")
    pkg = _pkg_json(ctx, d + "package.json").get("pnpm")
    pkg = pkg if isinstance(pkg, dict) else {}
    major = _pm_version(ctx, d, "pnpm")
    risky = []
    if (re.search(r"(?m)^\s*dangerouslyAllowAllBuilds\s*:\s*true\b", ws)
            or re.search(r"(?m)^\s*dangerously-allow-all-builds\s*=\s*true\b", rc)
            or pkg.get("dangerouslyAllowAllBuilds") is True):
        risky.append("dangerouslyAllowAllBuilds is on, so every dependency build script runs; list the few "
                     "that need it under allowBuilds instead (pnpm 10.26+; onlyBuiltDependencies on older pnpm 10)")
    missing = []
    if major is not None and major[0] < 10:
        missing.append("pnpm %s runs dependency build scripts on install (pnpm 10+ blocks them unless "
                       "allowlisted); upgrade or set ignore-scripts=true" % ".".join(str(x) for x in major))
    age = (re.search(r"(?m)^\s*minimumReleaseAge\s*:\s*[1-9]", ws) or re.search(r"(?m)^\s*minimum-release-age\s*=\s*[1-9]", rc)
           or pkg.get("minimumReleaseAge"))
    if not age and not (major is not None and major[0] >= 11):
        missing.append("set minimumReleaseAge: 10080 (minutes) in pnpm-workspace.yaml")
    return missing, risky


def _yarn_items(ctx: wc.ScanContext, d: str) -> List[str]:
    lock = ctx.read(d + "yarn.lock")[:4000]
    berry = bool(ctx.exists(d + ".yarnrc.yml") or "__metadata:" in lock)
    if berry:
        rc = _read_up(ctx, d, ".yarnrc.yml")
        missing = []
        if not re.search(r"(?m)^\s*enableScripts\s*:\s*false\b", rc):
            missing.append("enableScripts: false")
        if not re.search(r"""(?m)^\s*npmMinimalAgeGate\s*:\s*["']?[1-9]""", rc):
            missing.append("npmMinimalAgeGate: 7d")
        return ["add %s to .yarnrc.yml (allow the few packages that must build with dependenciesMeta.<pkg>.built)"
                % " and ".join(missing)] if missing else []
    rc = _read_up(ctx, d, ".yarnrc")
    if re.search(r"(?m)^\s*ignore-scripts\s+true\b", rc):
        return []
    return ["add ignore-scripts true to .yarnrc; Yarn 1 has no release-age gate, Yarn 4 adds npmMinimalAgeGate"]


def _bun_items(ctx: wc.ScanContext, d: str) -> List[str]:
    cfg = _read_up(ctx, d, "bunfig.toml")
    if re.search(r"(?m)^\s*minimumReleaseAge\s*=\s*[1-9]", cfg):
        return []
    return ["set minimumReleaseAge = 604800 (seconds) under [install] in bunfig.toml"]


def _uv_items(ctx: wc.ScanContext, d: str) -> List[str]:
    text = ctx.read(d + "pyproject.toml") + "\n" + _read_up(ctx, d, "uv.toml")
    # A date or a duration string turns the gate on; exclude-newer = false turns it off.
    if re.search(r"""(?m)^\s*exclude-newer\s*=\s*(?:["'][^"'\s][^"']*["']|\d{4}-\d{2}-\d{2})""", text):
        return []
    return ['set exclude-newer = "7 days" under [tool.uv] in pyproject.toml (uv 0.9.17+)']


_CONFIG_FILE = {"npm": ".npmrc", "pnpm": "pnpm-workspace.yaml", "yarn": ".yarnrc.yml", "bun": "bunfig.toml",
                "uv": "pyproject.toml"}

# Sub-projects that exist only for tests, docs or examples, or are templates
# copied at install time. Their install settings do not protect the app.
_SIDE_DIRS = frozenset({
    "__tests__", "test", "tests", "e2e", "doc", "docs", "example", "examples", "fixtures", "__fixtures__",
    "install", "stubs", "stub", "templates", "template", "skeleton", "playwright", "cypress", "demo", "demos",
})


def _side_project(d: str) -> bool:
    return any(p.lower() in _SIDE_DIRS for p in d.rstrip("/").split("/") if p)


def _dir_locks(ctx: wc.ScanContext, d: str) -> List[str]:
    """JS lockfile names present in folder d. bun.lockb is dropped when the
    text bun.lock sits next to it (Bun 1.2+ writes the text one)."""
    locks = [lock for lock in _NPM_LOCKS if ctx.exists(d + lock)]
    if "bun.lock" in locks and "bun.lockb" in locks:
        locks.remove("bun.lockb")
    return locks


def _ws_globs_match(rel_dir: str, patterns: Iterable[Any]) -> bool:
    """True when rel_dir matches a workspaces glob list (later "!" globs exclude)."""
    hit = False
    for p in patterns:
        if not isinstance(p, str):
            continue
        neg = p.startswith("!")
        p = p.lstrip("!").strip()
        while p.startswith("./"):
            p = p[2:]
        p = p.rstrip("/")
        if p and wc.glob_match(rel_dir + "/x", p + "/x"):
            hit = not neg
    return hit


def _pnpm_ws_globs(text: str) -> List[str]:
    m = re.search(r"(?m)^packages:[ \t]*\r?\n((?:[ \t]+[^\n]*\n?|[ \t]*\r?\n)*)", text)
    out: List[str] = []
    if m:
        for line in m.group(1).split("\n"):
            s = line.strip()
            if s.startswith("-"):
                out.append(s[1:].split(" #", 1)[0].strip().strip("'\""))
    return out


def _workspace_member(ctx: wc.ScanContext, a: str, d: str) -> bool:
    """True when the project in folder a installs folder d as part of itself:
    its package.json workspaces or pnpm-workspace.yaml packages match d, or one
    of its dependencies points at d with file:, link: or portal:."""
    rel = d[len(a):].rstrip("/")
    if not rel:
        return True
    data = _pkg_json(ctx, a + "package.json")
    ws = data.get("workspaces")
    if isinstance(ws, dict):
        ws = ws.get("packages")
    if isinstance(ws, list) and _ws_globs_match(rel, ws):
        return True
    if _ws_globs_match(rel, _pnpm_ws_globs(ctx.read(a + "pnpm-workspace.yaml"))):
        return True
    for section in _DEP_SECTIONS:
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for spec in block.values():
            if isinstance(spec, str) and re.match(r"(?:file|link|portal):", spec.strip()):
                target = spec.strip().split(":", 1)[1].strip()
                while target.startswith("./"):
                    target = target[2:]
                if target.rstrip("/") == rel:
                    return True
    return False


def _pnpm_importers(ctx: wc.ScanContext, lock_rel: str) -> Set[str]:
    def build() -> Set[str]:
        text = ctx.read(lock_rel)
        m = re.search(r"(?m)^importers:[ \t]*$", text)
        out: Set[str] = set()
        if not m:
            return out
        for line in text[m.end():].split("\n")[1:]:
            if line.strip() and not line.startswith(" "):
                break
            km = re.match(r"""^  (['"]?)([^'"\s:][^'":]*)\1:\s*$""", line.rstrip("\r"))
            if km:
                out.add(km.group(2))
        return out
    return ctx.memo(("ward-supply", "pnpm-importers", lock_rel), build)


def _lock_covers(ctx: wc.ScanContext, a: str, lock_rel: str, d: str) -> bool:
    """True when the lockfile lock_rel in folder a installs the package in folder d."""
    rel = d[len(a):].rstrip("/")
    if not rel or _workspace_member(ctx, a, d):
        return True
    name = lock_rel.rsplit("/", 1)[-1]
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        data = ctx.json(lock_rel)
        pk = data.get("packages") if isinstance(data, dict) else None
        return isinstance(pk, dict) and rel in pk
    text = ctx.read(lock_rel)
    if not text:
        return False
    if name == "pnpm-lock.yaml":
        return rel in _pnpm_importers(ctx, lock_rel)
    if name == "bun.lock":
        head = re.split(r'\n\s*"packages"\s*:', text, maxsplit=1)[0]
        return re.search(r'"%s"\s*:\s*\{' % re.escape(rel), head) is not None
    if name == "yarn.lock":
        return ('@workspace:%s"' % rel) in text or ("@workspace:%s:" % rel) in text
    return False


def _owner(ctx: wc.ScanContext, d: str) -> Optional[str]:
    """The ancestor folder whose project installs folder d (a workspace member
    or a file: dependency), or None when d is a standalone project. The nearest
    ancestor with a lockfile decides: if its lockfile does not include d, d is
    standalone."""
    for a in _ancestors(d)[1:]:
        locks = _dir_locks(ctx, a)
        if locks:
            return a if any(_lock_covers(ctx, a, a + lock, d) for lock in locks) else None
        if ctx.exists(a + "package.json") and _workspace_member(ctx, a, d):
            return a
    return None


def _pick_manager(ctx: wc.ScanContext, d: str, locks: Sequence[str]) -> Tuple[Optional[str], List[str]]:
    """(manager, unused lockfiles) for a folder with lockfiles. With lockfiles
    of several managers, packageManager in package.json decides, then
    bunfig.toml, pnpm-workspace.yaml or .yarnrc.yml; manager is None when
    nothing does."""
    managers: List[str] = []
    for lock in locks:
        if _LOCK_MANAGER[lock] not in managers:
            managers.append(_LOCK_MANAGER[lock])
    if len(managers) == 1:
        return managers[0], []
    chosen: Optional[str] = None
    for a in _ancestors(d):
        field = _pkg_json(ctx, a + "package.json").get("packageManager")
        if isinstance(field, str) and "@" in field:
            name = field.split("@", 1)[0]
            chosen = name if name in managers else None
            break
    if chosen is None and "bun" in managers and _read_up(ctx, d, "bunfig.toml").strip():
        chosen = "bun"
    if chosen is None and "pnpm" in managers and ctx.exists(d + "pnpm-workspace.yaml"):
        chosen = "pnpm"
    if chosen is None and "yarn" in managers and ctx.exists(d + ".yarnrc.yml"):
        chosen = "yarn"
    if chosen is None:
        return None, []
    return chosen, [lock for lock in locks if _LOCK_MANAGER[lock] != chosen]


def _show_dir(d: str) -> str:
    return d or "./"


_CI_INSTALL = {"npm": "npm ci", "pnpm": "pnpm install --frozen-lockfile",
               "yarn": "yarn install --immutable (Yarn 1: --frozen-lockfile)", "bun": "bun install --frozen-lockfile"}


def _declared_manager(ctx: wc.ScanContext, d: str) -> str:
    """The manager named by packageManager in package.json (d or a parent), else npm."""
    for a in _ancestors(d):
        field = _pkg_json(ctx, a + "package.json").get("packageManager")
        if isinstance(field, str) and "@" in field:
            name = field.split("@", 1)[0]
            return name if name in _CI_INSTALL else "npm"
    return "npm"


def _manager_items(ctx: wc.ScanContext, d: str, manager: str) -> Tuple[List[str], List[str]]:
    if manager == "npm":
        return _npm_items(ctx, d), []
    if manager == "pnpm":
        return _pnpm_items(ctx, d)
    if manager == "yarn":
        return _yarn_items(ctx, d), []
    if manager == "bun":
        return _bun_items(ctx, d), []
    return _uv_items(ctx, d), []


def _config_target(ctx: wc.ScanContext, d: str, manager: str, fallback: str) -> str:
    """The config file to anchor a finding on when it exists (in d or a parent
    folder), else fallback (the lockfile), so a finding never points at a file
    that is not there."""
    cfg = _CONFIG_FILE[manager]
    if manager == "yarn" and not (ctx.exists(d + ".yarnrc.yml") or "__metadata:" in ctx.read(d + "yarn.lock")[:4000]):
        cfg = ".yarnrc"
    for a in _ancestors(d):
        if ctx.exists(a + cfg):
            return a + cfg
    return fallback


def check_install_hardening(_rel: str, _text: str, ctx: wc.ScanContext) -> List[Hit]:
    hits: List[Hit] = []
    pkgs = sorted(ctx.glob("package.json"), key=lambda r: (r.count("/"), r))[:60]
    no_lock: List[str] = []
    advice: Dict[Tuple[str, Tuple[str, ...]], List[Tuple[str, str]]] = {}
    for rel in pkgs:
        d = _dir(rel)
        if d and _side_project(d):
            continue
        locks = _dir_locks(ctx, d)
        if not locks:
            if _owner(ctx, d) is None:
                data = _pkg_json(ctx, rel)
                if _has_deps(data) or data.get("workspaces") or ctx.exists(d + "pnpm-workspace.yaml"):
                    no_lock.append(rel)
            continue
        manager, unused = _pick_manager(ctx, d, locks)
        if manager is None:
            hits.append(Hit(1, "", "several lockfiles (%s) sit in %s, so it is unclear which package manager "
                            "installs this project: keep the lockfile of the one you use and delete the others"
                            % (", ".join(locks), _show_dir(d)), "info", rel))
        elif unused:
            kept = ", ".join(lock for lock in locks if lock not in unused)
            hits.append(Hit(1, "", "%s looks unused: %s installs this project (%s). Delete it so nobody installs "
                            "from a stale lockfile" % (" and ".join(unused), manager, kept), "info", d + unused[0]))
        for m in ([manager] if manager else [_LOCK_MANAGER[lock] for lock in locks]):
            lock_file = d + next(lock for lock in locks if _LOCK_MANAGER[lock] == m)
            items, risky = _manager_items(ctx, d, m)
            target = _config_target(ctx, d, m, lock_file)
            for r in risky:
                n = _line_of_text(ctx.read(target), "angerously", 1)
                hits.append(Hit(n, "", "%s: %s" % (m, r), "medium", target))
            if items:
                advice.setdefault((m, tuple(items)), []).append((d, target))
    for rel in sorted(ctx.glob("uv.lock"), key=lambda r: (r.count("/"), r))[:20]:
        d = _dir(rel)
        if d and _side_project(d):
            continue
        items, _risky = _manager_items(ctx, d, "uv")
        if items:
            advice.setdefault(("uv", tuple(items)), []).append((d, _config_target(ctx, d, "uv", rel)))
    if no_lock:
        others = ", ".join(no_lock[1:6]) + (" and %d more" % (len(no_lock) - 6) if len(no_lock) > 6 else "")
        d0 = _dir(no_lock[0])
        manager = _declared_manager(ctx, d0)
        items, _risky = _manager_items(ctx, d0, manager)
        hits.insert(0, Hit(1, "", "no lockfile next to this package.json%s, so every install resolves fresh "
                           "versions; commit a lockfile and install with %s%s"
                           % (" (also: %s)" % others if others else "", _CI_INSTALL[manager],
                              "; also %s" % items[0] if items else ""),
                           "low", no_lock[0]))
    used = {(h.file, h.line) for h in hits}
    for (manager, items), where in advice.items():
        dirs = [_show_dir(d) for d, _t in where]
        extra = " (projects: %s)" % ", ".join(dirs[:8]) if len(dirs) > 1 else ""
        # One finding per (file, line) survives the engine's dedupe; step aside
        # to line 0 (the whole file) when a note already sits on line 1.
        n = 0 if (where[0][1], 1) in used else 1
        used.add((where[0][1], n))
        hits.append(Hit(n, "", "%s installs are not hardened against fresh malicious releases: %s%s"
                        % (manager, "; ".join(items), extra), "info", where[0][1]))
    return hits


# ---------------------------------------------------------------------------
# 2. Known-bad versions in lockfiles, manifests and installed packages
# ---------------------------------------------------------------------------

def _npm_bad_entries() -> List[Dict[str, Any]]:
    return [e for e in KNOWN_BAD if e["ecosystem"] == "npm"]


def _py_bad_entries() -> List[Dict[str, Any]]:
    return [e for e in KNOWN_BAD if e["ecosystem"] == "pypi"]


def _found(entry: Dict[str, Any], version: str) -> str:
    return ("%s@%s is a known malicious release (%s): %s"
            % (entry["name"], version or "?", entry["source"], entry["advice"]))


def _scan_npm_lock(rel: str, text: str, ctx: wc.ScanContext) -> List[Tuple[int, Dict[str, Any], str]]:
    out: List[Tuple[int, Dict[str, Any], str]] = []
    name = rel.rsplit("/", 1)[-1]
    for e in _npm_bad_entries():
        n = e["name"]
        esc = re.escape(n)
        if n not in text:
            continue
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            data = ctx.json(rel)
            if not isinstance(data, dict):
                continue
            pk = data.get("packages")
            if isinstance(pk, dict):
                for key, ent in pk.items():
                    if key.endswith("node_modules/" + n) and isinstance(ent, dict):
                        v = str(ent.get("version") or "")
                        if _version_hit(e, v):
                            out.append((_line_of_text(text, '"%s"' % key), e, v))
            stack = [data.get("dependencies")]
            while stack:
                deps = stack.pop()
                if not isinstance(deps, dict):
                    continue
                for k, ent in deps.items():
                    if not isinstance(ent, dict):
                        continue
                    if k == n and _version_hit(e, str(ent.get("version") or "")):
                        out.append((_line_of_text(text, '"%s": {' % k), e, str(ent.get("version") or "")))
                    stack.append(ent.get("dependencies"))
        elif name == "yarn.lock":
            for m in re.finditer(r'(?m)^"?%s@[^\n]*:\s*\n(?:[ \t]+[^\n]*\n){0,6}?[ \t]+version:?\s+"?([^"\s]+)' % esc, text):
                if _version_hit(e, m.group(1)):
                    out.append((text.count("\n", 0, m.start()) + 1, e, m.group(1)))
        elif name == "pnpm-lock.yaml":
            for m in re.finditer(r"""(?m)^[ \t]+['"]?/?%s[@/](\d[^'"():\s]*)""" % esc, text):
                if _version_hit(e, m.group(1)):
                    out.append((text.count("\n", 0, m.start(1)) + 1, e, m.group(1)))
        elif name == "bun.lock":
            for m in re.finditer(r'"%s@(\d[^"]*)"' % esc, text):
                if _version_hit(e, m.group(1)):
                    out.append((text.count("\n", 0, m.start()) + 1, e, m.group(1)))
    return out


def _scan_package_json(rel: str, text: str, ctx: wc.ScanContext) -> List[Tuple[int, Dict[str, Any], str, str]]:
    out: List[Tuple[int, Dict[str, Any], str, str]] = []
    data = _pkg_json(ctx, rel)
    d = _dir(rel)
    for e in _npm_bad_entries():
        n = e["name"]
        for section in _DEP_SECTIONS:
            block = data.get(section)
            if isinstance(block, dict) and isinstance(block.get(n), str):
                spec = block[n].strip()
                exact = re.fullmatch(r"=?v?(\d+\.\d+\.\d+)", spec)
                if e["versions"] is None or (exact and _version_hit(e, exact.group(1))):
                    out.append((_line_of_text(text, '"%s"' % n), e, exact.group(1) if exact else spec, rel))
        installed = _pkg_json(ctx, d + "node_modules/%s/package.json" % n)
        if installed:
            v = str(installed.get("version") or "")
            if _version_hit(e, v):
                out.append((1, e, v, d + "node_modules/%s/package.json" % n))
    return out


_PY_REQ_LINE = r"(?im)^\s*%s\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,]*)"


def _scan_python(rel: str, text: str, ctx: wc.ScanContext) -> List[Tuple[int, Dict[str, Any], str]]:
    out: List[Tuple[int, Dict[str, Any], str]] = []
    name = rel.rsplit("/", 1)[-1]
    for e in _py_bad_entries():
        n = e["name"]
        esc = re.escape(n).replace(r"\-", "[-_.]").replace("-", "[-_.]")
        if not re.search(esc, text, re.I):
            continue
        if name in _PY_LOCKS:
            rx = re.compile(r'(?im)^name\s*=\s*"%s"\s*\r?\nversion\s*=\s*"([^"]+)"' % esc)
        elif name == "Pipfile.lock":
            rx = re.compile(r'(?i)"%s"\s*:\s*\{[^{}]*?"version"\s*:\s*"==([^"]+)"' % esc)
        elif name in ("pyproject.toml", "Pipfile"):
            rx = re.compile(r"""(?im)(?:^|['"])\s*%s\s*(?:\[[^\]]*\])?\s*(?:===?\s*|=\s*['"]==?)([0-9][\w.]*)""" % esc)
        else:
            rx = re.compile(_PY_REQ_LINE % esc)
        for m in rx.finditer(text):
            if _version_hit(e, m.group(1)):
                out.append((text.count("\n", 0, m.start(1)) + 1, e, m.group(1)))
    return out


def _venv_hits(ctx: wc.ScanContext) -> List[Hit]:
    hits: List[Hit] = []
    root = Path(ctx.root)
    for e in _py_bad_entries():
        for venv in (".venv", "venv", "env"):
            base = root / venv
            if not (base / "pyvenv.cfg").exists():
                continue
            for sp in list(base.glob("lib/python*/site-packages")) + [base / "Lib" / "site-packages"]:
                if not sp.is_dir():
                    continue
                for v in e["versions"] or ():
                    for cand in (sp / ("%s-%s.dist-info" % (e["name"], v)),):
                        if cand.exists():
                            hits.append(Hit(0, "", _found(e, v), None, wc.rel_posix(cand, root)))
    return hits


def check_known_bad_version(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    name = rel.rsplit("/", 1)[-1]
    hits: List[Hit] = []
    seen: Set[Tuple[str, str, str]] = set()

    def add(line: int, e: Dict[str, Any], v: str, file: Optional[str] = None) -> None:
        key = (file or rel, e["name"], v)
        if key in seen:
            return
        seen.add(key)
        hits.append(Hit(line, "%s %s" % (e["name"], v), _found(e, v), None, file))

    if name in _DENO_FILES or wc.match_any(rel, _DENO_CODE):
        # Deno code (Supabase Edge Functions) imports npm packages by specifier, npm:pkg@1.2.3 or
        # esm.sh/pkg@1.2.3; scan_app collects them in ctx.deno_deps. Only an exact version is a hit.
        deno = getattr(ctx, "deno_deps", None) or {}
        for e in _npm_bad_entries():
            for ver, f, line in deno.get(e["name"], ()):
                exact = re.fullmatch(r"=?v?(\d+\.\d+\.\d+)", ver or "")
                if f == rel and (e["versions"] is None or (exact and _version_hit(e, exact.group(1)))):
                    add(line, e, exact.group(1) if exact else ver)
        return hits
    if name in _LOCK_MANAGER:
        for line, e, v in _scan_npm_lock(rel, text, ctx):
            add(line, e, v)
    elif name == "package.json":
        for line, e, v, f in _scan_package_json(rel, text, ctx):
            add(line, e, v, None if f == rel else f)
    else:
        for line, e, v in _scan_python(rel, text, ctx):
            add(line, e, v)
        if _dir(rel) == "" and name in ("pyproject.toml", "requirements.txt", "uv.lock", "poetry.lock"):
            first = [r for r in ("pyproject.toml", "requirements.txt", "uv.lock", "poetry.lock") if ctx.exists(r)]
            if first and first[0] == name:
                hits.extend(_venv_hits(ctx))
    return hits


# ---------------------------------------------------------------------------
# 3. URL and git dependency specs
# ---------------------------------------------------------------------------

_GIT_SPEC = re.compile(r"(?i)^(?:git(?:\+[a-z]+)?://|git@|github:|gitlab:|bitbucket:|gist:)")
_GH_SHORTHAND = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+(?:#\S*)?$")
_SHA_PIN = re.compile(r"#[0-9a-f]{40}$")
_LOCAL_HOST = r"(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$)"


def classify_spec(spec: str) -> Optional[Tuple[str, str]]:
    """(severity, reason) for a package.json dependency spec that bypasses the
    registry, or None for normal and local specs."""
    s = (spec or "").strip()
    if not s or s.startswith(("file:", "link:", "workspace:", "portal:", "npm:", "catalog:", "patch:", "exec:")):
        return None
    if re.match(r"(?i)^(?:git\+)?http://", s):
        if re.match(r"(?i)^(?:git\+)?http://" + _LOCAL_HOST, s):
            return None
        return ("high", "installs code over plain http, so anyone on the network path can swap it")
    if _GIT_SPEC.match(s) or _GH_SHORTHAND.match(s):
        if _SHA_PIN.search(s):
            return None
        return ("medium", "installs from git without pinning a commit, so the code can change under the same spec")
    if re.match(r"(?i)^https://", s):
        if re.search(r"(?i)\.git(?:#|$)", s):
            return None if _SHA_PIN.search(s) else (
                "medium", "installs from git without pinning a commit, so the code can change under the same spec")
        return ("medium", "installs a tarball from a URL outside the registry (the remote dynamic dependency "
                          "trick used by PhantomRaven)")
    return None


_LOCK_HTTP_RX = re.compile(r"""(?:"resolved"\s*:\s*"|\bresolved\s+"|\btarball:\s*['"]?|\bresolution:\s*"[^"@]+@)http://(?!""" + _LOCAL_HOST + ")")
_PY_URL_RX = re.compile(r"(?i)(?:^|['\"\s@])((?:git\+)?(?:https?|ssh|git)://[^\s'\";]+)")
_PY_INDEX_HTTP_RX = re.compile(r"(?i)^\s*(?:--(?:extra-)?index-url|-i)\s+http://(?!" + _LOCAL_HOST + ")")


def _py_url_issue(url: str) -> Optional[Tuple[str, str]]:
    u = url.strip()
    if re.match(r"(?i)^(?:git\+)?http://", u) and not re.match(r"(?i)^(?:git\+)?http://" + _LOCAL_HOST, u):
        return ("high", "installs code over plain http")
    if u.lower().startswith("git+") or u.lower().startswith(("ssh://", "git://")):
        if re.search(r"@[0-9a-f]{40}(?:#|$)", u):
            return None
        return ("medium", "installs from git without pinning a commit")
    if re.match(r"(?i)^https://", u):
        return ("medium", "installs an archive from a URL outside the package index")
    return None


def check_url_dependency(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    name = rel.rsplit("/", 1)[-1]
    hits: List[Hit] = []
    if name == "package.json":
        data = _pkg_json(ctx, rel)
        for section in _DEP_SECTIONS:
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for dep, spec in block.items():
                if not isinstance(spec, str):
                    continue
                res = classify_spec(spec)
                if res:
                    n = _line_of_text(text, '"%s"' % dep)
                    hits.append(Hit(n, '"%s": "%s"' % (dep, spec), "%s %s" % (dep, res[1]), res[0]))
        return hits
    if name in _LOCK_MANAGER:
        for i, line in enumerate(ctx.lines(rel), 1):
            if "http://" in line and _LOCK_HTTP_RX.search(line):
                hits.append(Hit(i, line, "a locked dependency is downloaded over plain http", "high"))
        return hits
    for i, line in enumerate(ctx.lines(rel), 1):
        s = line.split(" #", 1)[0].strip()
        if not s or s.startswith("#"):
            continue
        if _PY_INDEX_HTTP_RX.search(s):
            hits.append(Hit(i, line, "the package index is reached over plain http", "high"))
            continue
        if s.startswith("-") and not s.startswith(("-e ", "--editable")):
            continue
        if name.endswith(".toml") and re.search(r"""\brev\s*=\s*['"][0-9a-f]{40}['"]""", s):
            continue
        m = _PY_URL_RX.search(s)
        if m:
            if name.endswith(".toml") and not re.search(r"(?i)\bgit\s*=|@\s*(?:git\+)?(?:https?|ssh|git)://", s):
                continue
            res = _py_url_issue(m.group(1))
            if res:
                hits.append(Hit(i, line, "dependency %s" % res[1], res[0]))
    return hits


# ---------------------------------------------------------------------------
# 4/5. Lifecycle scripts and worm artifacts
# ---------------------------------------------------------------------------

# Commands only, so a file name like scripts/check-curl.js does not count.
_CMD_START = r"(?:^|(?<=[\s;&|(`\"']))"
_FETCH_TELL = re.compile(
    _CMD_START + r"(?:curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|Invoke-Expression|iex)(?=\s|$)"
    r"|" + _CMD_START + r"certutil(?:\.exe)?\s[^\n]*-urlcache"
    r"|(?<!\|)\|(?!\|)\s*(?:ba|z|da)?sh\b|(?<!\|)\|(?!\|)\s*(?:node|python3?|perl)\b"
    r"|\bbase64\s+(?:-d|--decode)\b", re.I)
_WORM_FILES = ("setup_bun.js", "bun_environment.js")
_WORM_FILE_TELL = re.compile(r"\b(?:setup_bun|bun_environment)\.js\b")
_SETUP_MJS = re.compile(r"\bnode\s+(?:\./)?setup\.mjs\b")
_NODE_EVAL = re.compile(r"\bnode\s+(?:-e|--eval|-p|--print)\b")
_EVAL_BAD = re.compile(
    r"child_process|\bexecSync\b|\bspawn(?:Sync)?\b|require\(\s*\\?['\"](?:https?|net|dgram)\\?['\"]\s*\)"
    r"|\bhttps?\.(?:get|request)\b|\bfetch\s*\(|Buffer\.from\([^)]*base64|\batob\s*\(|\beval\s*\(|new\s+Function\s*\(")
_PROJECT_HOOKS = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare")
_DEP_HOOKS = ("preinstall", "install", "postinstall")


def script_tell(cmd: str, hook: str) -> Optional[Tuple[str, str]]:
    """(severity, reason) when an install-time script shows a known tell."""
    if _WORM_FILE_TELL.search(cmd):
        return ("critical", "runs a file name used by the Shai-Hulud 2.0 worm (setup_bun.js / bun_environment.js)")
    if _FETCH_TELL.search(cmd):
        return ("high", "downloads code or pipes it into a shell at install time")
    if hook == "preinstall" and _SETUP_MJS.search(cmd):
        return ("high", "preinstall runs node setup.mjs, the shape the 2026 ChainDrop worm used")
    if _NODE_EVAL.search(cmd) and _EVAL_BAD.search(cmd):
        return ("high", "runs inline node code that spawns processes, makes requests or decodes a payload")
    return None


def check_lifecycle_script(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    scripts = _pkg_json(ctx, rel).get("scripts")
    if not isinstance(scripts, dict):
        return []
    hits: List[Hit] = []
    for hook in _PROJECT_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str):
            continue
        res = script_tell(cmd, hook)
        if res:
            n = _line_of_text(text, '"%s"' % hook)
            hits.append(Hit(n, '"%s": %s' % (hook, json.dumps(cmd)[:160]), "%s script %s" % (hook, res[1]), res[0]))
    return hits


_MAX_PACKAGES = 12000


def _package_dirs(nm: Path) -> Iterable[Path]:
    """Package folders under one node_modules: top level, scoped, and pnpm's .pnpm store."""
    count = 0
    try:
        entries = sorted(os.scandir(str(nm)), key=lambda e: e.name)
    except OSError:
        return
    for ent in entries:
        if count >= _MAX_PACKAGES:
            return
        name = ent.name
        if name == ".pnpm":
            try:
                store = sorted(os.scandir(ent.path), key=lambda e: e.name)
            except OSError:
                continue
            for s in store:
                if not s.is_dir() or s.name in ("node_modules", "lock.yaml"):
                    continue
                pkg = s.name[1:].split("@", 1)[0].replace("+", "/") if s.name.startswith("@") else s.name.split("@", 1)[0]
                if s.name.startswith("@"):
                    pkg = "@" + pkg
                p = Path(s.path) / "node_modules" / pkg
                if p.is_dir():
                    count += 1
                    yield p
            continue
        if name.startswith(".") or not ent.is_dir():
            continue
        if name.startswith("@"):
            try:
                for sub in sorted(os.scandir(ent.path), key=lambda e: e.name):
                    if sub.is_dir():
                        count += 1
                        yield Path(sub.path)
            except OSError:
                continue
        else:
            count += 1
            yield Path(ent.path)


def check_installed_worm(_rel: str, _text: str, ctx: wc.ScanContext) -> List[Hit]:
    root = Path(ctx.root)
    hits: List[Hit] = []
    dirs = [""] + sorted({_dir(r) for r in ctx.glob("package.json") if _dir(r)})[:30]
    seen: Set[str] = set()
    for d in dirs:
        nm = root / d / "node_modules" if d else root / "node_modules"
        if not nm.is_dir():
            continue
        for pdir in _package_dirs(nm):
            try:
                real = str(pdir.resolve())
            except OSError:
                real = str(pdir)
            if real in seen:
                continue
            seen.add(real)
            rel_pkg = wc.rel_posix(pdir / "package.json", root)
            for f in _WORM_FILES:
                if (pdir / f).is_file():
                    hits.append(Hit(0, f, "installed package ships %s, a Shai-Hulud 2.0 worm file; treat the "
                                    "machine and every token on it as compromised" % f, "critical",
                                    wc.rel_posix(pdir / f, root)))
            text = wc.read_text(pdir / "package.json", 512 * 1024)
            if not text or '"scripts"' not in text:
                continue
            try:
                data = json.loads(text)
            except ValueError:
                continue
            scripts = data.get("scripts") if isinstance(data, dict) else None
            if not isinstance(scripts, dict):
                continue
            for hook in _DEP_HOOKS:
                cmd = scripts.get(hook)
                if not isinstance(cmd, str):
                    continue
                res = script_tell(cmd, hook)
                if res:
                    hits.append(Hit(_line_of_text(text, '"%s"' % hook), '"%s": %s' % (hook, json.dumps(cmd)[:160]),
                                    "installed dependency %s: %s script %s" % (data.get("name") or pdir.name, hook, res[1]),
                                    res[0], rel_pkg))
    return hits


# ---------------------------------------------------------------------------
# 6. Declared but never installed from the lockfile (slopsquat signal)
# ---------------------------------------------------------------------------

def _lock_names(ctx: wc.ScanContext, lock_rel: str) -> Optional[Set[str]]:
    """Package names a JS lockfile mentions, or None when it cannot be read."""
    def build() -> Optional[Set[str]]:
        name = lock_rel.rsplit("/", 1)[-1]
        text = ctx.read(lock_rel)
        if not text:
            return None
        out: Set[str] = set()
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            data = ctx.json(lock_rel)
            if not isinstance(data, dict):
                return None
            for key in (data.get("packages") or {}):
                if "node_modules/" in key:
                    out.add(key.rsplit("node_modules/", 1)[1])
            stack = [data.get("dependencies")]
            while stack:
                deps = stack.pop()
                if isinstance(deps, dict):
                    for k, ent in deps.items():
                        out.add(k)
                        if isinstance(ent, dict):
                            stack.append(ent.get("dependencies"))
            for imp in (data.get("packages") or {}).values():
                if isinstance(imp, dict):
                    for sec in _DEP_SECTIONS + ("peerDependencies",):
                        if isinstance(imp.get(sec), dict):
                            out.update(imp[sec].keys())
        elif name == "yarn.lock":
            for line in text.split("\n"):
                if line[:1] in (" ", "\t", "#", ""):
                    continue
                for spec in line.rstrip(":").split(","):
                    m = re.match(r'\s*"?(@?[^@\s"]+)@', spec)
                    if m:
                        out.add(m.group(1))
        elif name == "pnpm-lock.yaml":
            for m in re.finditer(r"""(?m)^\s+['"]?/?(@?[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?)(?=@|/\d|['"]?:)""", text):
                out.add(m.group(1))
        elif name == "bun.lock":
            for m in re.finditer(r'"(@?[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?)"\s*:|"(@?[A-Za-z0-9][\w.-]*(?:/[\w.-]+)?)@', text):
                out.add(m.group(1) or m.group(2))
        else:
            return None
        return out
    return ctx.memo(("ward-supply", "lock-names", lock_rel), build)


def _installing_locks(ctx: wc.ScanContext, d: str) -> List[str]:
    """Lockfiles that install the package in folder d: its own, else those of
    the ancestor project it is a workspace member (or file: dependency) of.
    Empty for a standalone package without a lockfile."""
    own = _dir_locks(ctx, d)
    if own:
        return [d + lock for lock in own]
    owner = _owner(ctx, d)
    if owner is None:
        return []
    return [owner + lock for lock in _dir_locks(ctx, owner)]


def _workspace_names(ctx: wc.ScanContext) -> Set[str]:
    def build() -> Set[str]:
        out: Set[str] = set()
        for rel in ctx.glob("package.json"):
            n = _pkg_json(ctx, rel).get("name")
            if isinstance(n, str):
                out.add(n)
        return out
    return ctx.memo(("ward-supply", "workspace-names"), build)


def _py_lock_names(ctx: wc.ScanContext, lock_rel: str) -> Set[str]:
    return ctx.memo(("ward-supply", "py-lock", lock_rel),
                    lambda: {_norm_py(m) for m in re.findall(r'(?m)^name\s*=\s*"([^"]+)"', ctx.read(lock_rel))})


def _toml_array_strings(text: str, i: int) -> List[Tuple[str, int]]:
    """(value, offset) of each top-level string element of the TOML array whose
    [ is at text[i]. Inline tables ({include-group = "dev"}), nested arrays and
    comments are skipped."""
    out: List[Tuple[str, int]] = []
    depth = 0
    j = i + 1
    n = len(text)
    while j < n:
        c = text[j]
        if c == "#":
            nl = text.find("\n", j)
            j = n if nl == -1 else nl
            continue
        if c in "\"'":
            triple = text[j:j + 3] == c * 3
            q = c * 3 if triple else c
            k = j + len(q)
            while k < n and not text.startswith(q, k):
                k += 2 if (text[k] == "\\" and c == '"') else 1
            if depth == 0:
                out.append((text[j + len(q):k], j + len(q)))
            j = k + len(q)
            continue
        if c in "[{":
            depth += 1
        elif c in "]}":
            if depth == 0:
                break
            depth -= 1
        j += 1
    return out


def _py_declared(rel: str, text: str) -> List[Tuple[str, int]]:
    out: List[Tuple[str, int]] = []
    if rel.endswith(".txt"):
        for i, line in enumerate(text.split("\n"), 1):
            s = line.split("#", 1)[0].strip()
            if not s or s.startswith("-") or "://" in s:
                continue
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", s)
            if m:
                out.append((m.group(1), i))
        return out
    for sec in re.finditer(r"(?ms)^\[([^\]\n]+)\]\s*$(.*?)(?=^\[|\Z)", text):
        title = sec.group(1).strip()
        if title in ("project", "tool.uv"):
            key_rx = r"(?:dependencies|dev-dependencies)"
        elif title in ("project.optional-dependencies", "dependency-groups"):
            key_rx = r"[\w-]+"
        else:
            continue
        body, base = sec.group(2), sec.start(2)
        for block in re.finditer(r"(?m)^[ \t]*%s\s*=\s*\[" % key_rx, body):
            for req, off in _toml_array_strings(body, block.end() - 1):
                spec = req.split(";", 1)[0]
                if "://" in spec:
                    continue
                m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~@(]|$)", spec)
                if m:
                    out.append((m.group(1), text.count("\n", 0, base + off) + 1))
    sec = re.search(r"(?ms)^\[tool\.poetry\.(?:dev-)?dependencies\]\s*$(.*?)(?=^\[|\Z)", text)
    if sec:
        for m in re.finditer(r"(?m)^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", sec.group(1)):
            if m.group(1).lower() != "python":
                out.append((m.group(1), text.count("\n", 0, sec.start(1) + m.start()) + 1))
    return out


_UNLOCKED_MSG = ("%s is declared in %s but missing from %s, so it was never installed from the lockfile. If a "
                 "coding agent added it, confirm on the registry that the package exists, is the project you meant "
                 "and is not brand new before installing; this scan is offline and cannot check the registry")


def check_dep_not_in_lockfile(rel: str, text: str, ctx: wc.ScanContext) -> List[Hit]:
    name = rel.rsplit("/", 1)[-1]
    d = _dir(rel)
    hits: List[Hit] = []
    if name == "package.json":
        locks = _installing_locks(ctx, d)
        if not locks:
            return []
        present: Set[str] = set()
        for lk in locks:
            got = _lock_names(ctx, lk)
            if got is None:
                # bun.lockb or an unreadable lockfile: a dependency may be in it.
                return []
            present |= got
        lock = " and ".join(locks)
        internal = _workspace_names(ctx)
        data = _pkg_json(ctx, rel)
        for section in ("dependencies", "devDependencies"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for dep, spec in block.items():
                if not isinstance(spec, str) or dep in present or dep in internal:
                    continue
                s = spec.strip()
                if s.startswith(("file:", "link:", "workspace:", "portal:", "npm:", "catalog:", "patch:", "exec:")):
                    continue
                if classify_spec(s) or "://" in s:
                    continue
                if ctx.exists(d + "node_modules/" + dep + "/package.json"):
                    continue
                n = _line_of_text(text, '"%s"' % dep)
                hits.append(Hit(n, '"%s": "%s"' % (dep, spec), _UNLOCKED_MSG % (dep, rel.rsplit("/", 1)[-1], lock)))
        return hits
    lock = None
    for cand in _PY_LOCKS:
        if ctx.exists(d + cand):
            lock = d + cand
            break
    if lock is None:
        return []
    present = _py_lock_names(ctx, lock)
    if not present:
        return []
    for dep, n in _py_declared(rel, text):
        if _norm_py(dep) in present:
            continue
        hits.append(Hit(n, _dep_line(ctx, rel, n), _UNLOCKED_MSG % (dep, rel.rsplit("/", 1)[-1], lock)))
    return hits


def _dep_line(ctx: wc.ScanContext, rel: str, n: int) -> str:
    ls = ctx.lines(rel)
    return ls[n - 1] if 0 < n <= len(ls) else ""


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

_LOCK_GLOBS = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"]
# Deno manifests and Supabase Edge Function code, whose npm: / esm.sh imports land in ctx.deno_deps
_DENO_FILES = ("deno.json", "deno.jsonc", "import_map.json")
_DENO_CODE = ["supabase/functions/**/*.{ts,tsx,js,mjs,jsx}", "**/supabase/functions/**/*.{ts,tsx,js,mjs,jsx}"]
_PY_MANIFESTS = ["requirements*.txt", "**/requirements/*.txt", "pyproject.toml", "Pipfile"]

RULES: List[Rule] = [
    Rule(
        id="supply-known-bad-version",
        skill=SKILL,
        klass="known malicious release installed or locked",
        severity="critical",
        stacks=["*"],
        file_globs=_LOCK_GLOBS + ["package.json"] + _PY_MANIFESTS + ["uv.lock", "poetry.lock", "pdm.lock",
                                                                     "Pipfile.lock"] + list(_DENO_FILES) + _DENO_CODE,
        pattern="check_known_bad_version",
        message="a lockfile, manifest or installed package pins a release known to be malicious",
        why=("Compromised maintainer accounts and self-spreading worms publish malicious versions of popular "
             "packages; an install during the exposure window locks them in, and AI-built apps rarely review "
             "lockfile changes."),
        fp_trap=("Only exact versions from public advisories are listed (see KNOWN_BAD in _rules_supply.py). A "
                 "version range in package.json is not a finding by itself; the lockfile shows what was installed. "
                 "Deno imports (npm:pkg@1.2.3, esm.sh/pkg@1.2.3) in deno.json or Supabase Edge Functions are checked "
                 "the same way: only an exact version counts."),
        fix_ref="supply-chain.md#known-bad-versions",
        confidence="high",
        needs_confirmation=False,
    ),
    Rule(
        id="supply-installed-worm-artifact",
        skill=SKILL,
        klass="worm file or download-and-run install script in node_modules",
        severity="critical",
        stacks=["node"],
        file_globs=[],
        pattern="check_installed_worm",
        once=True,
        message="an installed package ships a known worm file or an install script that downloads and runs code",
        why=("Dependencies run preinstall and postinstall scripts with the developer's full rights. The 2025-2026 "
             "npm worms (Shai-Hulud, ChainDrop) used exactly these hooks to steal tokens."),
        fp_trap=("A postinstall that runs a local build or a node script shipped in the package (node install.js, "
                 "node -e \"try{require('./postinstall')}catch(e){}\") is normal and is not reported. Read the "
                 "reported script before deleting anything."),
        fix_ref="supply-chain.md#after-a-compromise",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="supply-risky-lifecycle-script",
        skill=SKILL,
        klass="install script downloads or runs remote code",
        severity="high",
        stacks=["node"],
        file_globs=["package.json"],
        pattern="check_lifecycle_script",
        message="a preinstall, install, postinstall or prepare script downloads code or runs a known worm tell",
        why=("Install hooks run on every npm install, including in CI with deploy tokens. Agents paste setup "
             "one-liners (curl ... | sh) into postinstall to automate a step."),
        fp_trap=("prisma generate, patch-package, husky, a local build or node scripts/setup.js are normal hooks "
                 "and are not reported. node -e is only reported when it spawns processes, fetches or decodes data."),
        fix_ref="supply-chain.md#lifecycle-script-tells",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="supply-url-dependency",
        skill=SKILL,
        klass="dependency installed from a URL or git",
        severity="medium",
        stacks=["*"],
        file_globs=["package.json"] + _LOCK_GLOBS + _PY_MANIFESTS,
        pattern="check_url_dependency",
        message="a dependency is installed from a URL, plain http or an unpinned git ref instead of the registry",
        why=("URL specs skip the registry's integrity and malware checks; PhantomRaven packages declared http "
             "tarball dependencies so the payload never appeared on npm. Agents add git or tarball specs to pull "
             "a fork or a fix that is not published yet."),
        fp_trap=("file:, link:, workspace: and npm: aliases are local or registry specs and are not reported. A git "
                 "dependency pinned to a full 40-character commit hash is reproducible and is not reported. "
                 "Private registries over https in lockfiles are not reported."),
        fix_ref="supply-chain.md#url-and-git-dependencies",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="supply-unlocked-dependency",
        skill=SKILL,
        klass="dependency never installed from the lockfile",
        severity="low",
        stacks=["*"],
        file_globs=["package.json", "requirements*.txt", "pyproject.toml"],
        pattern="check_dep_not_in_lockfile",
        message="a declared dependency is missing from the lockfile; confirm it exists on the registry before installing",
        why=("Models invent plausible package names (about one in five suggestions in the USENIX 2025 study) and "
             "attackers register them. A name the agent added that never made it into the lockfile is exactly "
             "the package nobody has verified yet."),
        fp_trap=("An offline scan cannot tell a hallucinated name from a real package added since the last install. "
                 "Workspace packages and anything already in node_modules are skipped. A sub-project is only "
                 "compared with a parent lockfile when it is a workspace member (or a file: dependency) of that "
                 "project, and with several lockfiles in one folder a name counts as locked when any of them has it. "
                 "Check the registry page: age, downloads, repository link and a name that is not a near-copy of a "
                 "popular package."),
        fix_ref="supply-chain.md#check-a-package-before-installing",
        confidence="low",
        needs_confirmation=True,
    ),
    Rule(
        id="supply-no-install-hardening",
        skill=SKILL,
        klass="install hardening missing",
        severity="info",
        stacks=["*"],
        file_globs=[],
        pattern="check_install_hardening",
        once=True,
        message=("the package manager runs dependency install scripts or accepts releases published minutes ago "
                 "(hardening advice is info; a missing lockfile is low, dangerouslyAllowAllBuilds medium)"),
        why=("Most 2025-2026 supply chain attacks were live for under a week. A release-age cooldown and disabled "
             "dependency scripts would have blocked them. pnpm 11 is the only manager that turns both on by default "
             "(dependency build scripts blocked unless allowed, a one-day minimumReleaseAge); npm, Yarn, Bun and uv "
             "need the settings added, and agents never add them."),
        fp_trap=("Settings in a user-level ~/.npmrc or set only in CI are not visible to this scan; if they exist "
                 "there, this note is already handled. pnpm 10+ blocks dependency build scripts unless allowed, and "
                 "Bun runs them only for its built-in allowlist of popular packages, so for them only the release "
                 "age is reported. ignore-scripts=true also skips the project's own postinstall (prisma generate and "
                 "the like): read the trade-offs before adding it. Test, docs, example and template sub-projects "
                 "are skipped; the advice is one note per package manager, and a lockfile left over from another "
                 "manager is reported as unused instead of getting its own advice."),
        fix_ref="supply-chain.md#install-hardening",
        confidence="high",
        needs_confirmation=True,
    ),
]
