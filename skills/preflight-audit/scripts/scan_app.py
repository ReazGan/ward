"""Static security scan of a whole app: data access, secrets, payments and
abuse, injection, deployment settings and supply chain.

Usage:
  python3 scan_app.py [--json] [--output FILE] [--stack LIST] [--only SEVERITY]
                      [--max-findings N] [--per-rule N] [--ignore FILE | --no-ignore]
                      [--jobs N] [--explain IDS] [--list-rules] [TARGET]

The scanner reports candidates. Each finding names a rule id; print that
rule's false-positive trap and fix with --explain RULE_ID (the same text as
its entry in references/rules.md) and confirm against the code before
reporting or fixing. At most --per-rule findings of one rule are listed
(summary.by_rule counts all). Reviewed false positives go in .ward-ignore
(RULE@PATH[:LINE]  # reason); they are listed under "ignored" and do not
change the exit code.

Exit codes: 0 no findings, 1 findings, 2 usage or runtime error.

Importable API:
  load_rules(modules=RULE_MODULES) -> (rules, warnings)
  detect_stacks(ctx)               fills ctx.stacks, deps and package managers
  run_scan(target, stacks=None, min_severity=None, rule_ids=None, rules=None,
           ignore_file=None, jobs=None) -> ScanResult
  vendored_files(ctx), load_ignore(path), apply_ignore(findings, entries), explain(ids)
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import _wardcore as wc  # noqa: E402

try:
    import _secret_patterns as _sp  # noqa: E402
except Exception:  # pragma: no cover - the pattern module ships beside this file
    _sp = None

SCRIPT = "scan_app"
DEFAULT_PER_RULE = 5

# Order matters: it is the order of references/rules.md.
RULE_MODULES = (
    "_rules_dataauth",
    "_rules_secrets",
    "_rules_logic",
    "_rules_injection",
    "_rules_deploy",
    "_rules_supply",
)

# Stack names rule authors can use in Rule.stacks.
KNOWN_STACKS = (
    "nextjs-app", "nextjs-pages", "nextjs", "react-vite", "vite-spa", "cra", "tanstack-start", "supabase",
    "firebase", "express", "node", "fastapi", "flask", "django", "python", "laravel", "php", "expo",
    "react-native", "stripe", "llm", "prisma",
)

_LLM_NPM = frozenset({
    "openai", "@anthropic-ai/sdk", "@google/generative-ai", "@google/genai", "ai", "langchain",
    "groq-sdk", "cohere-ai", "@mistralai/mistralai", "replicate", "ollama", "together-ai",
    "@huggingface/inference", "llamaindex", "@openrouter/ai-sdk-provider",
})
_LLM_PY = frozenset({
    "openai", "anthropic", "google-generativeai", "google-genai", "litellm", "llama-index",
    "cohere", "mistralai", "groq", "together", "replicate", "ollama", "huggingface-hub",
})
_LLM_COMPOSER = frozenset({
    "laravel/ai", "openai-php/client", "openai-php/laravel", "prism-php/prism", "echolabsdev/prism",
    "anthropic-ai/sdk", "mozex/anthropic-php", "mozex/anthropic-laravel", "google-gemini-php/client",
    "google-gemini-php/laravel", "theodo-group/llphant", "orhanerday/open-ai", "lucianotonet/groq-php",
})
_LLM_COMPOSER_PREFIX = ("openai-php/", "prism-php/", "google-gemini-php/")
# Calls straight to a model API, without an SDK (common in Deno Edge Functions).
_LLM_HOSTS = re.compile(
    r"https://(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|openrouter\.ai/api"
    r"|api\.groq\.com|api\.mistral\.ai|api\.together\.xyz|api\.deepseek\.com|api\.x\.ai|api\.perplexity\.ai"
    r"|api\.cohere\.(?:ai|com)|ai\.gateway\.lovable\.dev)\b")
# Severity notes for rules whose checks report some hits at another severity than
# the rule default, shown next to the severity in rules.md and --explain. A
# severity_note set on the Rule itself wins over this table.
SEVERITY_NOTES: Dict[str, str] = {
    "xss-react-dangerous-html": ("medium when the HTML comes from a prop or parameter the scanner cannot follow; "
                                 "low when a lint suppression above the line gives a reason, or in a React Email template"),
}
_SSR_NPM = wc.SSR_PACKAGES
_SPA_UI = wc.SPA_UI_PACKAGES
# Folders whose loose .py files are tooling, not a Python app.
_PY_TOOLING_DIRS = frozenset({
    ".github", ".circleci", ".gitlab", ".buildkite", ".husky", "scripts", "script", "tools", "tooling",
    "docs", "doc", "bin", "ci", "hack", "devtools", "benchmarks", "examples",
})
_PY_MANIFESTS = ("requirements*.txt", "**/requirements/*.txt", "setup.py", "setup.cfg", "pyproject.toml",
                 "Pipfile", "manage.py")
_DENO_IMPORT = re.compile(
    r"""["'](?:npm:(?P<npm>@?[\w.-]+(?:/[\w.-]+)?)(?:@(?P<npmv>[^/"'\s]+))?"""
    r"""|https://(?:esm\.sh|cdn\.skypack\.dev|cdn\.jsdelivr\.net/npm)/(?:v\d+/)?(?P<cdn>@?[\w.-]+(?:/[\w.-]+)?)"""
    r"""@(?P<cdnv>[^/"'?\s]+))""")
_DENO_CODE_GLOBS = ("supabase/functions/**/*.{ts,tsx,js,mjs,jsx}", "**/supabase/functions/**/*.{ts,tsx,js,mjs,jsx}")
_DENO_MANIFESTS = ("deno.json", "deno.jsonc", "import_map.json")


class ScanResult:
    """Outcome of run_scan(): findings (sorted), ctx, warnings, rules_run, rules_loaded."""

    def __init__(self, findings: List[wc.Finding], ctx: wc.ScanContext, warnings: List[Any],
                 rules_run: List[str], rules_loaded: int) -> None:
        self.findings = findings
        self.ctx = ctx
        self.warnings = warnings
        self.rules_run = rules_run
        self.rules_loaded = rules_loaded
        self.ignored: List[wc.Finding] = []
        self.vendored = 0

    @property
    def rule_ids(self) -> List[str]:
        """Rule ids of the findings, in order (handy in tests)."""
        return [f.rule for f in self.findings]


# ---------------------------------------------------------------------------
# Loading rules
# ---------------------------------------------------------------------------

def _resolve(rule: wc.Rule) -> Tuple[str, Any]:
    """Return ("regex", compiled) or ("check", callable) for a rule."""
    if rule.check is not None:
        if not callable(rule.check):
            raise ValueError("check is not callable")
        return "check", rule.check
    pat = rule.pattern
    if callable(pat) and not hasattr(pat, "search"):
        return "check", pat
    if isinstance(pat, str) and re.fullmatch(r"check_\w+", pat):
        mod = sys.modules.get(rule.module) if rule.module else None
        fn = getattr(mod, pat, None) if mod is not None else None
        if not callable(fn):
            raise ValueError("pattern names %s but module %s has no such function" % (pat, rule.module or "?"))
        return "check", fn
    if hasattr(pat, "search"):
        return "regex", pat
    return "regex", re.compile(pat, re.M if rule.multiline else 0)


def load_rules(modules: Sequence[str] = RULE_MODULES) -> Tuple[List[wc.Rule], List[str]]:
    """Import the rule modules and return (valid rules, warnings).

    A module that fails to import, a rule that fails validation, a regex that
    does not compile and a duplicate id each produce a warning; the rest load.
    """
    rules: List[wc.Rule] = []
    warnings: List[str] = []
    seen: Dict[str, str] = {}
    for name in modules:
        try:
            mod = importlib.import_module(name)
        except Exception as exc:
            warnings.append("could not load %s: %s: %s" % (name, type(exc).__name__, exc))
            continue
        items = getattr(mod, "RULES", None)
        if not isinstance(items, (list, tuple)):
            warnings.append("%s has no RULES list" % name)
            continue
        for r in items:
            errs = wc.validate_rule(r)
            if errs:
                rid = getattr(r, "id", "?")
                warnings.append("rule %s in %s skipped: %s" % (rid, name, "; ".join(errs)))
                continue
            if r.id in seen:
                warnings.append("duplicate rule id %s in %s (already in %s); second one skipped"
                                % (r.id, name, seen[r.id]))
                continue
            r.module = name
            if not r.severity_note and r.id in SEVERITY_NOTES:
                r.severity_note = SEVERITY_NOTES[r.id]
            try:
                _resolve(r)
            except Exception as exc:
                warnings.append("rule %s in %s skipped: %s: %s" % (r.id, name, type(exc).__name__, exc))
                continue
            unknown = sorted({s for entry in r.stacks for s in entry.split("+")
                              if s and s != "*" and s not in KNOWN_STACKS})
            if unknown:
                warnings.append("rule %s in %s uses unknown stack name(s): %s" % (r.id, name, ", ".join(unknown)))
            seen[r.id] = name
            rules.append(r)
    return rules, warnings


# ---------------------------------------------------------------------------
# Stack detection
# ---------------------------------------------------------------------------

def _depth(rel: str) -> int:
    return rel.count("/")


def _py_names(text: str, toml: bool) -> Set[str]:
    """Package names from requirements-style lines, TOML keys and quoted
    requirement strings. Over-inclusive on purpose: only used for membership."""
    names: Set[str] = set()
    quoted = re.compile(r"[\"']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~;@ ][^\"']*)?[\"']")
    for raw in text.split("\n"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if toml:
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*=", line)
        elif not line.startswith(("-", "[")):
            m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        else:
            m = None
        if m:
            names.add(m.group(1))
        names.update(quoted.findall(line))
    return {n.lower().replace("_", "-") for n in names}


def _pkg_prefix(d: str) -> str:
    return d + "/" if d else ""


def _deno_deps(ctx: wc.ScanContext) -> Dict[str, List[Tuple[str, str, int]]]:
    """npm packages imported by Deno code: deno.json(c) / import_map.json "imports"
    and npm: / esm.sh / skypack / jsdelivr specifiers in supabase/functions."""
    found: Dict[str, List[Tuple[str, str, int]]] = {}
    files = ctx.glob(*_DENO_MANIFESTS) + ctx.glob(*_DENO_CODE_GLOBS)
    seen: Set[str] = set()
    for rel in files:
        if rel in seen:
            continue
        seen.add(rel)
        text = ctx.read(rel)
        if not text or ("npm:" not in text and "https://" not in text):
            continue
        for m in _DENO_IMPORT.finditer(text):
            name = m.group("npm") or m.group("cdn") or ""
            ver = m.group("npmv") or m.group("cdnv") or ""
            if not name:
                continue
            if not name.startswith("@"):
                name = name.split("/", 1)[0]
            if name.endswith(".ts") or name.endswith(".js"):
                continue
            found.setdefault(name, []).append((ver, rel, ctx.line_of(rel, m.start())))
    return found


def _py_tooling(rel: str) -> bool:
    return any(part in _PY_TOOLING_DIRS for part in rel.split("/")[:-1])


def detect_stacks(ctx: wc.ScanContext) -> None:
    """Fill ctx.stacks, ctx.deps / prod_deps / dev_deps / deno_deps, ctx.py_deps,
    ctx.composer_deps / composer_prod and ctx.package_managers from manifests,
    config files and lockfiles. Framework stacks are decided per package.json
    folder, so a docs site or a tooling package does not change the app's stacks."""
    stacks: Set[str] = set()

    # npm manifests, root first
    pkgs = sorted(ctx.glob("package.json"), key=lambda r: (_depth(r), r))
    root_pkg: Dict[str, Any] = {}
    pkg_deps: Dict[str, Dict[str, str]] = {}
    for rel in pkgs:
        data = ctx.json(rel)
        if not isinstance(data, dict):
            continue
        if rel == "package.json":
            root_pkg = data
        own: Dict[str, str] = {}
        for section, target in (("dependencies", ctx.prod_deps), ("devDependencies", ctx.dev_deps),
                                ("peerDependencies", None), ("optionalDependencies", None)):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for k, v in block.items():
                ver = v if isinstance(v, str) else str(v)
                ctx.deps.setdefault(k, ver)
                own.setdefault(k, ver)
                if target is not None:
                    target.setdefault(k, ver)
        pkg_deps[rel[:-len("package.json")].rstrip("/")] = own
    if pkgs:
        stacks.add("node")

    # Deno (Supabase Edge Functions): npm packages imported by specifier
    ctx.deno_deps = _deno_deps(ctx)
    for name, locs in ctx.deno_deps.items():
        ctx.deps.setdefault(name, locs[0][0] or "*")
    deps = ctx.deps

    # Python manifests (a docs/ or .github/ requirements file is tooling, not the app)
    for rel in ctx.glob("requirements*.txt", "**/requirements/*.txt", "setup.py", "setup.cfg"):
        if not _py_tooling(rel):
            ctx.py_deps |= _py_names(ctx.read(rel), toml=False)
    for rel in ctx.glob("pyproject.toml", "Pipfile"):
        if not _py_tooling(rel):
            ctx.py_deps |= _py_names(ctx.read(rel), toml=True)

    # Composer
    for rel in sorted(ctx.glob("composer.json"), key=lambda r: (_depth(r), r)):
        data = ctx.json(rel)
        if not isinstance(data, dict):
            continue
        for section in ("require", "require-dev"):
            block = data.get(section)
            if isinstance(block, dict):
                for k, v in block.items():
                    ctx.composer_deps.setdefault(k, str(v))
                    if section == "require":
                        ctx.composer_prod.setdefault(k, str(v))
        stacks.add("php")

    py = ctx.py_deps
    comp = ctx.composer_deps

    # Next.js: app/ and pages/ only count under a folder that is a Next.js app
    if "next" in deps:
        stacks.add("nextjs")
        next_dirs = {d for d, own in pkg_deps.items() if "next" in own}
        for rel in ctx.glob("next.config.{js,mjs,cjs,ts,mts}"):
            next_dirs.add(rel.rsplit("/", 1)[0] if "/" in rel else "")
        if not next_dirs:
            next_dirs = {""}
        has_app = has_pages = False
        for d in next_dirs:
            p = _pkg_prefix(d)
            for base in (p, p + "src/"):
                if not has_app and ctx.glob(base + "app/**/page.{js,jsx,ts,tsx,mdx}",
                                            base + "app/**/layout.{js,jsx,ts,tsx}"):
                    has_app = True
                if not has_pages and ctx.glob(base + "pages/**/*.{js,jsx,ts,tsx}"):
                    has_pages = True
        if has_app:
            stacks.add("nextjs-app")
        if has_pages:
            stacks.add("nextjs-pages")
        if not has_app and not has_pages:
            v = wc.parse_version(ctx.next_version)
            stacks.add("nextjs-app" if (v is None or v[0] >= 13) else "nextjs-pages")

    # SPAs and TanStack Start, decided per package.json folder
    root_deps = pkg_deps.get("", {})
    for d, own in pkg_deps.items():
        ssr = any(k in own for k in _SSR_NPM)
        vite = "vite" in own or "vite" in root_deps  # workspaces often hoist vite to the root
        if vite and not ssr and any(k in own for k in _SPA_UI):
            stacks.add("vite-spa")
            if "react" in own or "react-dom" in own:
                stacks.add("react-vite")
        if "react-scripts" in own:
            stacks.add("cra")
        if any(k in own for k in wc.TANSTACK_START_PACKAGES):
            stacks.add("tanstack-start")

    # Mobile
    app_json = ctx.json("app.json")
    if "expo" in deps or (isinstance(app_json, dict) and "expo" in app_json):
        stacks.add("expo")
    if "react-native" in deps:
        stacks.add("react-native")

    # Backends as a service
    if (any(k.startswith("@supabase/") for k in deps) or "supabase" in py
            or ctx.exists("supabase/config.toml") or ctx.glob("supabase/migrations/*.sql")):
        stacks.add("supabase")
    fb_npm = ("firebase", "firebase-admin", "firebase-functions", "@react-native-firebase/app",
              "@angular/fire", "reactfire")
    fb_files = ("firebase.json", ".firebaserc", "firestore.rules", "database.rules.json", "storage.rules")
    if any(k in deps for k in fb_npm) or "firebase-admin" in py or any(ctx.exists(f) for f in fb_files):
        stacks.add("firebase")

    # Servers
    if "express" in deps:
        stacks.add("express")
    if "django" in py or ctx.exists("manage.py"):
        stacks.add("django")
    if "flask" in py:
        stacks.add("flask")
    if "fastapi" in py:
        stacks.add("fastapi")
    # Loose .py files: tooling folders (.github/, scripts/, docs/, ...) do not
    # make a project a Python app.
    py_files = [f for f in ctx.glob("*.py") if not _py_tooling(f)]
    framework = False
    if py_files and not stacks & {"django", "flask", "fastapi"}:
        for rel in py_files[:300]:
            text = ctx.read(rel)
            if re.search(r"^\s*(?:from\s+flask\s+import|import\s+flask\b)", text, re.M):
                stacks.add("flask")
                framework = True
            if re.search(r"^\s*(?:from\s+fastapi\s+import|import\s+fastapi\b)", text, re.M):
                stacks.add("fastapi")
                framework = True
            if re.search(r"^\s*(?:from\s+django[.\s]|import\s+django\b)", text, re.M):
                stacks.add("django")
                framework = True
    has_manifest = bool([f for f in ctx.glob(*_PY_MANIFESTS) if not _py_tooling(f)])
    if has_manifest or framework or stacks & {"django", "flask", "fastapi"} or len(py_files) >= 3:
        stacks.add("python")
    if "laravel/framework" in comp or ctx.exists("artisan"):
        stacks.add("laravel")
    if "laravel" in stacks or ctx.glob("*.php"):
        stacks.add("php")

    # Integrations
    if ("stripe" in deps or "@stripe/stripe-js" in deps or "@stripe/react-stripe-js" in deps
            or "stripe" in py or "stripe/stripe-php" in comp or "laravel/cashier" in comp):
        stacks.add("stripe")
    if (any(k in deps for k in _LLM_NPM) or any(k.startswith(("@ai-sdk/", "@langchain/")) for k in deps)
            or any(k in py for k in _LLM_PY) or any(k.startswith("langchain") for k in py)
            or any(k in comp for k in _LLM_COMPOSER) or any(k.startswith(_LLM_COMPOSER_PREFIX) for k in comp)):
        stacks.add("llm")
    elif _calls_llm_api(ctx):
        stacks.add("llm")
    if "prisma" in deps or "@prisma/client" in deps or ctx.glob("schema.prisma"):
        stacks.add("prisma")

    ctx.stacks |= stacks

    # Package managers
    managers: List[str] = []

    def add(m: str) -> None:
        if m not in managers:
            managers.append(m)

    pm_field = root_pkg.get("packageManager") if isinstance(root_pkg, dict) else None
    if isinstance(pm_field, str) and "@" in pm_field:
        add(pm_field.split("@", 1)[0])
    js_locks = (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"), ("package-lock.json", "npm"),
                ("npm-shrinkwrap.json", "npm"), ("bun.lock", "bun"), ("bun.lockb", "bun"))
    for name, m in js_locks:
        if ctx.exists(name) or ctx.glob(name):
            add(m)
    py_locks = (("uv.lock", "uv"), ("poetry.lock", "poetry"), ("Pipfile.lock", "pipenv"), ("pdm.lock", "pdm"))
    py_lock_found = False
    for name, m in py_locks:
        if ctx.exists(name) or ctx.glob(name):
            add(m)
            py_lock_found = True
    if not py_lock_found and ctx.glob("requirements*.txt"):
        add("pip")
    if ctx.exists("composer.lock") or ctx.glob("composer.lock"):
        add("composer")
    ctx.package_managers = managers


def _calls_llm_api(ctx: wc.ScanContext) -> bool:
    """True when server or function code calls a model API host directly."""
    for rel in ctx.glob("*.{js,jsx,ts,tsx,mjs,cjs,mts,cts,py,php}"):
        if any(p in ("test", "tests", "__tests__", "e2e") for p in rel.split("/")[:-1]) or wc.is_build_path(rel):
            continue
        text = ctx.read(rel)
        if ("api." in text or "googleapis" in text or "openrouter" in text or "gateway" in text) \
                and _LLM_HOSTS.search(text):
            return True
    return False


def parse_stack_arg(value: Optional[str], detected: Iterable[str]) -> Tuple[Set[str], bool]:
    """--stack parsing. "a,b" replaces detection, "+a" adds to it, "all" runs every rule.
    When any item starts with "+", the whole list adds to detection
    ("+stripe,llm" = "+stripe,+llm"), so a missing "+" cannot silently drop
    the detected stacks. Returns (stacks, force_all)."""
    current = set(detected)
    if not value:
        return current, False
    items = [x.strip().lower() for x in re.split(r"[,\s]+", value) if x.strip()]
    force_all = any(x in ("all", "*") for x in items)
    names = [x for x in items if x not in ("all", "*")]
    additive = any(x.startswith("+") for x in names)
    clean = [x.lstrip("+") for x in names if x.lstrip("+")]
    if additive or not clean:
        return current | set(clean), force_all
    return set(clean), force_all


# ---------------------------------------------------------------------------
# Running rules
# ---------------------------------------------------------------------------

def _redact(text: str) -> str:
    if _sp is not None:
        text = _sp.redact(text)
    return wc.redact(text)


def _as_hit(item: Any) -> wc.Hit:
    if isinstance(item, wc.Hit):
        return item
    if isinstance(item, (tuple, list)) and 1 <= len(item) <= 5:
        return wc.Hit(*item) if len(item) >= 2 else wc.Hit(item[0], "")
    if isinstance(item, int):
        return wc.Hit(item, "")
    raise TypeError("check returned %r; expected (line, evidence) or Hit" % (item,))


def _starts_in_comment(ctx: wc.ScanContext, rel: str, offset: int, match_text: str) -> bool:
    """True when the first non-blank character of a match sits in a comment
    (a // or # tail, or anywhere inside a /* ... */ block)."""
    skip = len(match_text) - len(match_text.lstrip())
    return ctx.in_comment(rel, offset + skip)


def _regex_hits(rule: wc.Rule, rx: "re.Pattern[str]", rel: str, text: str, ctx: wc.ScanContext,
                unless_line: Optional["re.Pattern[str]"]) -> List[wc.Hit]:
    out: List[wc.Hit] = []
    lines = ctx.lines(rel)
    if rule.multiline:
        last_line = -1
        for m in rx.finditer(text):
            n = ctx.line_of(rel, m.start())
            if n == last_line:
                continue
            line = lines[n - 1] if 0 < n <= len(lines) else ""
            if rule.skip_comments and (wc.is_comment_line(line, rel)
                                       or _starts_in_comment(ctx, rel, m.start(), m.group(0))):
                continue
            if unless_line is not None and unless_line.search(line):
                continue
            col = m.start() - (text.rfind("\n", 0, m.start()) + 1)
            out.append(wc.Hit(n, wc.clip(line, col, col + len(m.group(0)))))
            last_line = n
            if len(out) > rule.max_per_file + 50:
                break
        return out
    for i, line in enumerate(lines, 1):
        m = rx.search(line)
        if not m:
            continue
        if rule.skip_comments:
            if wc.is_comment_line(line, rel):
                continue
            base = ctx.line_offset(rel, i)
            # A later match on the same line may be outside the comment.
            mm: Optional["re.Match[str]"] = m
            while mm is not None and _starts_in_comment(ctx, rel, base + mm.start(), mm.group(0)):
                mm = rx.search(line, mm.end()) if mm.end() > mm.start() else None
            if mm is None:
                continue
            m = mm
        if unless_line is not None and unless_line.search(line):
            continue
        out.append(wc.Hit(i, wc.clip(line, m.start(), m.end())))
        if len(out) > rule.max_per_file + 50:
            break
    return out


def _run_rule(rule: wc.Rule, ctx: wc.ScanContext, warnings: List[Any]) -> List[wc.Finding]:
    try:
        kind, fn = _resolve(rule)
        unless_file = re.compile(rule.unless_file, re.M) if rule.unless_file else None
        unless_line = re.compile(rule.unless_line) if rule.unless_line else None
    except Exception as exc:
        warnings.append("rule %s skipped: %s: %s" % (rule.id, type(exc).__name__, exc))
        return []

    def make(h: wc.Hit, rel: str) -> wc.Finding:
        sev = h.severity if h.severity in wc.SEVERITY_RANK else rule.severity
        ev = "" if h.evidence is None else str(h.evidence)
        ev = ev.replace("\n", " ")
        if len(ev) > 220:
            ev = wc.clip(ev, 0, None, 200)
        ev = _redact(ev.strip())
        return wc.Finding(skill=rule.skill, klass=rule.klass, severity=sev, file=h.file or rel,
                          line=h.line or 0, rule=rule.id, message=h.message or rule.message,
                          evidence=ev, fix_ref=rule.fix_ref, confidence=rule.confidence,
                          needs_confirmation=rule.needs_confirmation)

    found: List[wc.Finding] = []
    if rule.once:
        try:
            items = fn("", "", ctx) or []
            found.extend(make(_as_hit(it), "") for it in items)
        except Exception as exc:
            warnings.append("rule %s failed: %s: %s" % (rule.id, type(exc).__name__, exc))
        return found

    key = ("files-for-globs", tuple(rule.file_globs), tuple(rule.exclude_globs))
    files = ctx.memo(key, lambda: [f for f in ctx.files if rule.wants_file(f)])
    if rule.client_only:
        files = [f for f in files if ctx.is_client_file(f)]
    anchors = tuple(a for a in (rule.anchors or ()) if a)
    errors = 0
    for rel in files:
        try:
            if not rule.include_minified and ctx.is_minified(rel):
                continue
            text = ctx.read(rel)
            if not text:
                continue
            if anchors and not any(a in text for a in anchors):
                continue
            if unless_file is not None and unless_file.search(text):
                continue
            if kind == "regex":
                hits = _regex_hits(rule, fn, rel, text, ctx, unless_line)
            else:
                hits = [_as_hit(it) for it in (fn(rel, text, ctx) or [])]
                if unless_line is not None:
                    keep = []
                    for h in hits:
                        target = h.file or rel
                        ln = ctx.lines(target)[h.line - 1] if h.line and 0 < h.line <= len(ctx.lines(target)) else ""
                        if not (ln and unless_line.search(ln)):
                            keep.append(h)
                    hits = keep
            batch = [make(h, rel) for h in hits]
        except Exception as exc:
            errors += 1
            if errors <= 3:
                warnings.append("rule %s failed on %s: %s: %s" % (rule.id, rel, type(exc).__name__, exc))
            continue
        cap = max(1, rule.max_per_file)
        if len(batch) > cap:
            extra = len(batch) - cap
            stopped_early = kind == "regex" and len(batch) > cap + 50
            batch = batch[:cap]
            batch[-1].message += " (and %s more in this file)" % ("%d+" % extra if stopped_early else extra)
        found.extend(batch)
    if errors > 3:
        warnings.append("rule %s failed on %d more files" % (rule.id, errors - 3))
    return found


# ---------------------------------------------------------------------------
# Vendored code that does not sit in a folder named vendor/
# ---------------------------------------------------------------------------

_LIB_FOLDERS = frozenset({"lib", "libs", "vendor", "vendors", "third_party", "third-party", "thirdparty",
                          "external", "externals", "3rdparty"})
# Folders served as-is by the web server. Names like web/ or www/ also hold app
# source (apps/web/lib/...), so only these count.
_SERVED_FOLDERS = frozenset({"public", "static", "wwwroot", "webroot", "htdocs", "public_html"})
_BANNER = re.compile(r"\A\s*/\*!|@license\b|@preserve\b")


def _norm_dir(base: str, sub: str) -> Optional[str]:
    """base + sub as a clean relative folder ('' = root), or None if it escapes."""
    parts: List[str] = [p for p in base.split("/") if p]
    for p in sub.replace("\\", "/").split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(p)
    return "/".join(parts)


def _composer_vendored(ctx: wc.ScanContext) -> Set[str]:
    """Folder prefixes ('x/y/') of third-party PHP code: a composer config.vendor-dir
    other than vendor/, and autoload entries under lib/, libs/, third_party/ ...
    whose namespace is not the project's own."""
    out: Set[str] = set()
    for rel in ctx.glob("composer.json"):
        data = ctx.json(rel)
        if not isinstance(data, dict):
            continue
        base = rel[:-len("composer.json")].rstrip("/")
        config = data.get("config") if isinstance(data.get("config"), dict) else {}
        vd = config.get("vendor-dir") if isinstance(config, dict) else None
        if isinstance(vd, str) and vd.strip():
            vdir = _norm_dir(base, vd.strip())
            if vdir is not None and vdir == base:
                # Packages are installed next to the project's own code: <dir>/<vendor>/<name>.
                names: Set[str] = set()
                for section in ("require", "require-dev"):
                    block = data.get(section)
                    if isinstance(block, dict):
                        names.update(k for k in block if "/" in k)
                inst = ctx.json(_norm_dir(vdir, "composer/installed.json") or "")
                pk = inst.get("packages") if isinstance(inst, dict) else inst
                if isinstance(pk, list):
                    names.update(p.get("name") for p in pk if isinstance(p, dict) and isinstance(p.get("name"), str))
                for n in names:
                    d = _norm_dir(vdir, n)
                    if d:
                        out.add(d + "/")
                d = _norm_dir(vdir, "composer")
                if d:
                    out.add(d + "/")
            elif vdir:
                out.add(vdir + "/")
        autoload = data.get("autoload") if isinstance(data.get("autoload"), dict) else {}
        mapped: List[Tuple[str, str]] = []
        for kind in ("psr-4", "psr-0"):
            block = autoload.get(kind)
            if not isinstance(block, dict):
                continue
            for ns, paths in block.items():
                for p in ([paths] if isinstance(paths, str) else paths if isinstance(paths, list) else []):
                    if isinstance(p, str):
                        mapped.append((str(ns).strip("\\").split("\\")[0].split("_")[0], p))
        own = {ns for ns, p in mapped if (_norm_dir("", p) or "").split("/")[0] not in _LIB_FOLDERS}
        if not own:
            continue
        lib_dirs: Set[str] = set()
        for ns, p in mapped:
            parts = (_norm_dir("", p) or "").split("/")
            if len(parts) >= 2 and parts[0] in _LIB_FOLDERS and ns not in own:
                lib_dirs.add(parts[0] + "/" + parts[1])
        for p in autoload.get("files") or []:
            parts = (_norm_dir("", p) if isinstance(p, str) else "") or ""
            parts_l = parts.split("/")
            if len(parts_l) >= 3 and parts_l[0] in _LIB_FOLDERS:
                lib_dirs.add(parts_l[0] + "/" + parts_l[1])
        for d in lib_dirs:
            full = _norm_dir(base, d)
            if full:
                out.add(full + "/")
    return out


def vendored_files(ctx: wc.ScanContext) -> Set[str]:
    """Files of third-party code outside a vendor/ folder: Composer packages
    installed elsewhere (see _composer_vendored), anything under public/**/lib/,
    and plain .js/.css files in served folders that start with a library
    banner (/*!, @license, @preserve)."""
    prefixes = _composer_vendored(ctx)
    out: Set[str] = set()
    for f in ctx.files:
        if prefixes and any(f.startswith(p) for p in prefixes):
            out.add(f)
            continue
        dirs = f.split("/")[:-1]
        served = [i for i, d in enumerate(dirs) if d in _SERVED_FOLDERS]
        if not served:
            continue
        if any(d in ("lib", "libs") for d in dirs[served[0] + 1:]):
            out.add(f)
            continue
        if f.endswith((".js", ".css", ".mjs")) and not f.endswith((".min.js", ".min.css")):
            if _BANNER.search(ctx.read(f)[:1500]):
                out.add(f)
    return out


# ---------------------------------------------------------------------------
# Recorded false positives (.ward-ignore)
# ---------------------------------------------------------------------------

IGNORE_FILE = ".ward-ignore"
_IGNORE_LINE = re.compile(r"^(?P<rule>[A-Za-z0-9*?\[\]-]+)@(?P<path>[^\s#]+?)(?::(?P<line>\d+))?(?:\s+#\s*(?P<reason>.*)|\s*)$")


def load_ignore(path: Union[str, Path]) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse an ignore file. One entry per line: RULE@PATH[:LINE]  # reason.
    RULE and PATH may use * globs; PATH (project) means a project-level finding.
    Returns (entries, warnings)."""
    entries: List[Dict[str, Any]] = []
    warnings: List[str] = []
    text = wc.read_text(path) or ""
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _IGNORE_LINE.match(line)
        if not m:
            warnings.append("%s:%d: cannot read %r (expected RULE@PATH[:LINE]  # reason)"
                            % (Path(path).name, n, line[:80]))
            continue
        p = m.group("path").replace("\\", "/")
        while p.startswith("./"):
            p = p[2:]
        entries.append({"rule": m.group("rule"), "path": p,
                        "line": int(m.group("line")) if m.group("line") else None,
                        "reason": (m.group("reason") or "").strip(), "text": line, "used": 0})
    return entries, warnings


def _ignore_matches(e: Dict[str, Any], f: wc.Finding) -> bool:
    rule = e["rule"]
    if rule != f.rule and not (any(c in rule for c in "*?[") and wc.glob_match(f.rule, rule)):
        return False
    path = e["path"]
    file = f.file or "(project)"
    if path != file and not (any(c in path for c in "*?[") and wc.glob_match(file, path)):
        return False
    return e["line"] is None or e["line"] == f.line


def apply_ignore(findings: Sequence[wc.Finding], entries: Sequence[Dict[str, Any]]
                 ) -> Tuple[List[wc.Finding], List[wc.Finding]]:
    """Split findings into (kept, ignored) by the entries of an ignore file."""
    kept: List[wc.Finding] = []
    ignored: List[wc.Finding] = []
    for f in findings:
        hit = next((e for e in entries if _ignore_matches(e, f)), None)
        if hit is None:
            kept.append(f)
            continue
        hit["used"] += 1
        if hit["reason"]:
            f.extra["ignore_reason"] = hit["reason"]
        ignored.append(f)
    return kept, ignored


# ---------------------------------------------------------------------------
# Worker processes for large projects
# ---------------------------------------------------------------------------

# Each rule reads every file it wants on its own, so a big monorepo takes tens
# of seconds in one process. Rules are independent (cross-file indexes live in
# ctx.memo and are rebuilt per process), so they can run in parallel. Smaller
# projects stay in one process: starting workers costs more than it saves.
PARALLEL_MIN_FILES = 800
MAX_JOBS = 8
_WORKER: Dict[str, Any] = {}


def auto_jobs(n_files: int, n_rules: int) -> int:
    """Worker processes to use when --jobs is not given."""
    if n_files < PARALLEL_MIN_FILES or n_rules < 2:
        return 1
    try:
        cpus = len(os.sched_getaffinity(0))  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        cpus = os.cpu_count() or 1
    return max(1, min(MAX_JOBS, cpus, n_rules))


def _worker_init(root: str, files: List[str], stacks: List[str], max_bytes: int) -> None:
    """Build this worker's own ScanContext and rule table (runs once per process)."""
    ctx = wc.ScanContext(root, files=files, max_bytes=max_bytes)
    try:
        detect_stacks(ctx)
    except Exception:
        pass
    ctx.stacks = set(stacks)
    ctx.warnings = []
    loaded, _warnings = load_rules()
    _WORKER["ctx"] = ctx
    _WORKER["rules"] = {r.id: r for r in loaded}


def _worker_run(rule_id: str) -> Tuple[List[wc.Finding], List[Any], List[Any]]:
    """Run one rule in a worker: (findings, rule warnings, ctx warnings it added)."""
    ctx = _WORKER["ctx"]
    rule = _WORKER["rules"][rule_id]
    warnings: List[Any] = []
    before = len(ctx.warnings)
    found = _run_rule(rule, ctx, warnings)
    return found, warnings, list(ctx.warnings[before:])


def _run_parallel(selected: Sequence[wc.Rule], ctx: wc.ScanContext, jobs: int
                  ) -> Dict[str, Tuple[List[wc.Finding], List[Any], List[Any]]]:
    """Run rules in worker processes. Returns {rule id: result} for the rules
    that finished; the caller runs any missing rule in this process, so a
    platform without working process pools only loses time."""
    out: Dict[str, Tuple[List[wc.Finding], List[Any], List[Any]]] = {}
    try:
        from concurrent.futures import ProcessPoolExecutor
        with ProcessPoolExecutor(max_workers=jobs, initializer=_worker_init,
                                 initargs=(str(ctx.root), list(ctx.files), sorted(ctx.stacks),
                                           ctx.max_bytes)) as pool:
            futures = [(r.id, pool.submit(_worker_run, r.id)) for r in selected]
            for rid, fut in futures:
                try:
                    out[rid] = fut.result()
                except Exception:
                    continue
    except Exception:
        pass
    return out


def run_scan(target: Union[str, Path], stacks: Optional[Union[str, Iterable[str]]] = None,
             min_severity: Optional[str] = None, rule_ids: Optional[Iterable[str]] = None,
             rules: Optional[Sequence[wc.Rule]] = None, max_bytes: int = wc.DEFAULT_MAX_BYTES,
             ignore_file: Optional[Union[str, Path]] = None, jobs: Optional[int] = None) -> ScanResult:
    """Scan target and return a ScanResult.

    stacks: an override like the --stack flag ("django", "+supabase", "all") or a
    list of names. rule_ids: only run these rules. rules: use these Rule
    objects instead of loading the modules (tests). min_severity: drop findings
    below it. ignore_file: an ignore file (see load_ignore); matching findings
    move to result.ignored. jobs: worker processes (None = auto_jobs(), 1 = run
    in this process). Results are the same either way; rules passed in rules=
    always run in this process.
    """
    root = wc.norm(target)
    files = None
    if root.is_file():
        files = [root.name]
        root = root.parent
    ctx = wc.ScanContext(root, files=files, max_bytes=max_bytes)
    warnings: List[Any] = []
    vendored: Set[str] = set()
    if files is None:
        try:
            vendored = vendored_files(ctx)
            if vendored:
                ctx.set_files([f for f in ctx.files if f not in vendored])
        except Exception as exc:
            warnings.append("vendored code detection failed: %s: %s" % (type(exc).__name__, exc))
    try:
        detect_stacks(ctx)
    except Exception as exc:
        warnings.append("stack detection failed: %s: %s" % (type(exc).__name__, exc))

    if stacks is not None and not isinstance(stacks, str):
        stacks = ",".join(stacks)
    detected = set(ctx.stacks)
    ctx.stacks, force_all = parse_stack_arg(stacks, ctx.stacks)
    if stacks:
        named = {x.strip().lstrip("+").lower() for x in re.split(r"[,\s]+", stacks) if x.strip()}
        unknown = sorted(named - set(KNOWN_STACKS) - {"all", "*", ""})
        if unknown:
            warnings.append("unknown stack name(s) in --stack: %s (known: %s)"
                            % (", ".join(unknown), ", ".join(KNOWN_STACKS)))
        dropped = sorted(detected - ctx.stacks)
        if dropped and not force_all:
            warnings.append("--stack replaced the detected stacks; rules for %s will not run. "
                            "Prefix names with '+' to add to detection instead" % ", ".join(dropped))

    if rules is None:
        loaded, load_warnings = load_rules()
        warnings.extend(load_warnings)
    else:
        loaded = []
        for r in rules:
            errs = wc.validate_rule(r)
            if errs:
                warnings.append("rule %s skipped: %s" % (getattr(r, "id", "?"), "; ".join(errs)))
                continue
            loaded.append(r)
    if rule_ids is not None:
        wanted = set(rule_ids)
        loaded = [r for r in loaded if r.id in wanted]

    selected = [r for r in loaded if r.applies_to(ctx.stacks, force_all)]
    if jobs is None:
        jobs = auto_jobs(len(ctx.files), len(selected)) if rules is None and files is None else 1
    parallel: Dict[str, Tuple[List[wc.Finding], List[Any], List[Any]]] = {}
    if jobs > 1 and rules is None and len(selected) > 1:
        parallel = _run_parallel(selected, ctx, min(int(jobs), MAX_JOBS * 4, len(selected)))
    findings: List[wc.Finding] = []
    for rule in selected:
        done = parallel.get(rule.id)
        if done is None:
            findings.extend(_run_rule(rule, ctx, warnings))
            continue
        found, rule_warnings, ctx_warnings = done
        findings.extend(found)
        warnings.extend(rule_warnings)
        ctx.warnings.extend(ctx_warnings)

    seen: Set[Tuple[str, str, int]] = set()
    unique = []
    for f in findings:
        key = (f.rule, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    if min_severity:
        limit = wc.SEVERITY_RANK.get(min_severity.lower(), len(wc.SEVERITIES))
        unique = [f for f in unique if wc.SEVERITY_RANK[f.severity] <= limit]
    ignored: List[wc.Finding] = []
    if ignore_file is not None:
        entries, ign_warnings = load_ignore(ignore_file)
        warnings.extend(ign_warnings)
        unique, ignored = apply_ignore(unique, entries)
        for e in entries:
            if not e["used"]:
                warnings.append("%s: entry matched no finding (fixed or moved?): %s"
                                % (Path(ignore_file).name, e["text"]))
    warnings.extend(ctx.warnings)
    result = ScanResult(wc.sort_findings(unique), ctx, warnings, [r.id for r in selected], len(loaded))
    result.ignored = wc.sort_findings(ignored)
    result.vendored = len(vendored)
    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _list_rules(as_json: bool) -> int:
    rules, warnings = load_rules()
    order = {m: i for i, m in enumerate(RULE_MODULES)}
    rules = sorted(rules, key=lambda r: (order.get(r.module, 99), r.id))
    if as_json:
        sys.stdout.write(json.dumps([r.to_dict() for r in rules], indent=2, ensure_ascii=False) + "\n")
    else:
        for r in rules:
            sys.stdout.write(r.id + "\n")
    for w in warnings:
        sys.stderr.write("warning: %s\n" % w)
    return wc.EXIT_OK


def explain(ids: Sequence[str]) -> Tuple[str, List[str]]:
    """The reference text of the given rule ids (the same content as their
    references/rules.md entries) and the ids that do not exist."""
    rules, _warnings = load_rules()
    by_id = {r.id: r for r in rules}
    parts: List[str] = []
    missing: List[str] = []
    for rid in ids:
        r = by_id.get(rid)
        if r is None:
            missing.append(rid)
            continue
        sev = r.severity + (" (%s)" % r.severity_note if r.severity_note else "")
        confirm = "confirm before reporting" if r.needs_confirmation else "direct"
        fix = ("references/" + r.fix_ref) if r.fix_ref and ".md" in r.fix_ref.split("#", 1)[0] else (r.fix_ref or "-")
        parts.append("\n".join([
            "### %s" % r.id,
            "%s | confidence %s | %s | stacks: %s" % (sev, r.confidence, confirm, ", ".join(r.stacks)),
            "- What: %s" % " ".join(r.message.split()),
            "- Why agents produce it: %s" % (" ".join(r.why.split()) or "-"),
            "- False-positive trap: %s" % (" ".join(r.fp_trap.split()) or "-"),
            "- Fix: %s" % fix,
        ]))
    return "\n\n".join(parts) + ("\n" if parts else ""), missing


def main(argv: Optional[Sequence[str]] = None) -> int:
    wc.setup_io()
    ap = argparse.ArgumentParser(
        prog="scan_app.py",
        description="Scan an app for security holes coding agents often leave: open databases, "
                    "secrets reaching the client, unverified payments, injection, debug settings and "
                    "risky dependencies. Findings are candidates: confirm each one with --explain "
                    "RULE_ID (or references/rules.md). Exit 0 = clean, 1 = findings, 2 = error.",
        epilog="Stacks: " + ", ".join(KNOWN_STACKS))
    ap.add_argument("target", nargs="?", default=".", help="project folder (default: .)")
    wc.add_common_args(ap)
    ap.add_argument("--stack", metavar="LIST",
                    help="override detected stacks: 'django,flask' replaces, '+supabase' adds "
                         "(any '+' makes the whole list add), 'all' runs every rule")
    ap.add_argument("--only", metavar="SEVERITY", type=str.lower, choices=wc.SEVERITIES,
                    help="report only this severity and worse (critical, high, medium, low, info)")
    ap.add_argument("--per-rule", type=int, default=DEFAULT_PER_RULE, metavar="N",
                    help="show at most N findings of one rule (default %d, 0 = no limit); "
                         "summary.by_rule counts all of them" % DEFAULT_PER_RULE)
    ap.add_argument("--ignore", metavar="FILE",
                    help="file of reviewed false positives, one 'RULE@PATH[:LINE]  # reason' per line "
                         "(default: %s in the project, when present)" % IGNORE_FILE)
    ap.add_argument("--no-ignore", action="store_true", help="do not read any ignore file")
    ap.add_argument("--jobs", type=int, metavar="N",
                    help="worker processes (default: up to %d on projects with %d+ files; 1 = one process)"
                         % (MAX_JOBS, PARALLEL_MIN_FILES))
    ap.add_argument("--explain", metavar="IDS",
                    help="print the reference entry (false-positive trap and fix) of these rule ids and exit")
    ap.add_argument("--list-rules", action="store_true", help="print every rule id and exit")
    args = ap.parse_args(argv)

    if args.list_rules:
        return _list_rules(args.json)
    if args.explain:
        ids = [x.strip() for x in re.split(r"[,\s]+", args.explain) if x.strip()]
        text, missing = explain(ids)
        sys.stdout.write(text)
        if missing:
            sys.stderr.write("error: unknown rule id(s): %s (see --list-rules)\n" % ", ".join(missing))
            return wc.EXIT_ERROR
        return wc.EXIT_OK

    target = wc.norm(args.target)
    if not target.exists():
        sys.stderr.write("error: %s does not exist\n" % target.as_posix())
        return wc.EXIT_ERROR
    ignore_file: Optional[Path] = None
    if args.ignore and not args.no_ignore:
        ignore_file = wc.norm(args.ignore)
        if not ignore_file.is_file():
            sys.stderr.write("error: ignore file %s does not exist\n" % ignore_file.as_posix())
            return wc.EXIT_ERROR
    elif not args.no_ignore:
        default = (target if target.is_dir() else target.parent) / IGNORE_FILE
        if default.is_file():
            ignore_file = default
    try:
        result = run_scan(target, stacks=args.stack, min_severity=args.only, ignore_file=ignore_file,
                          jobs=args.jobs if args.jobs and args.jobs > 0 else None)
    except KeyboardInterrupt:
        sys.stderr.write("interrupted\n")
        return wc.EXIT_ERROR
    except Exception as exc:
        sys.stderr.write("error: scan failed: %s: %s\n" % (type(exc).__name__, exc))
        return wc.EXIT_ERROR
    ctx = result.ctx
    meta: Dict[str, Any] = {
        "stacks": sorted(ctx.stacks),
        "package_managers": ctx.package_managers,
        "next_version": ctx.next_version,
        "files_scanned": len(ctx.files),
        "vendored_files_skipped": result.vendored or None,
        "rules_run": len(result.rules_run),
        "rules_loaded": result.rules_loaded,
    }
    if ignore_file is not None:
        meta["ignore_file"] = ignore_file.as_posix()
    if meta["vendored_files_skipped"] is None:
        del meta["vendored_files_skipped"]
    return wc.emit(result.findings, as_json=args.json, out_file=args.output, max_findings=args.max_findings,
                   target=ctx.root.as_posix(), script=SCRIPT, meta=meta, warnings=result.warnings,
                   per_rule=args.per_rule or None, compact=True, ignored=result.ignored)


if __name__ == "__main__":
    sys.exit(main())
