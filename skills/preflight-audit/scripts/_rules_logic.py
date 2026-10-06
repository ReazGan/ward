"""Request logic rules: Stripe and other payment gateways' webhooks and
client-sent prices, fulfillment and idempotency, metered or LLM routes without
auth or limits, OTP and email send throttling, CSRF, open redirects
(threats-logic 1-2, 9-10).

Most of these need more than a single regex, so they are check functions that
look at the surrounding function. They report candidates. Each rule's fp_trap
says what to rule out before calling it a bug.
"""

from __future__ import annotations

import posixpath
import re
from functools import lru_cache
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from _wardcore import Hit, Rule, match_any

SKILL = "logic"

JS_GLOB = "*.{js,jsx,ts,tsx,mjs,cjs,mts,cts}"
CODE_GLOBS = [JS_GLOB, "*.py", "*.php"]

# Files that are not production request handlers.
NOT_PROD = [
    "**/test/**", "**/tests/**", "**/__tests__/**", "**/__mocks__/**", "**/mocks/**", "**/mock/**",
    "**/fixtures/**", "**/e2e/**", "**/cypress/**", "**/playwright/**", "**/examples/**",
    "**/example/**", "**/samples/**", "*.test.*", "*.spec.*", "test_*.py", "*_test.py",
    "conftest.py", "*.stories.*", "*.d.ts",
]

REF = "payments-and-abuse.md"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _lang(path: str) -> str:
    if path.endswith(".py"):
        return "py"
    if path.endswith(".php"):
        return "php"
    return "js"


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _code_lines(ctx: Any, path: str) -> List[str]:
    """File lines with comments blanked, /* */ blocks included (line numbers stay the same)."""
    return ctx.code_lines(path)


def _code(ctx: Any, path: str) -> str:
    return ctx.memo(("logic-code-text", path), lambda: "\n".join(_code_lines(ctx, path)))


def _line_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _prod_code_files(ctx: Any) -> List[str]:
    return ctx.memo("logic-prod-code", lambda: [
        f for f in ctx.files if match_any(f, CODE_GLOBS) and not match_any(f, NOT_PROD)])


def _project_any(ctx: Any, key: str, rx: "re.Pattern[str]", globs: Optional[Sequence[str]] = None) -> bool:
    """True when rx matches the code of any production file (optionally limited by globs)."""
    def scan() -> bool:
        for f in _prod_code_files(ctx):
            if globs and not match_any(f, globs):
                continue
            if rx.search(_code(ctx, f)):
                return True
        return False
    return ctx.memo(("logic-any", key), scan)


_CLOSE = {"(": ")", "[": "]", "{": "}"}


def _balanced_end(text: str, i: int, limit: int = 6000) -> int:
    """text[i] is an opening bracket. Index just past its partner (or a capped end)."""
    stack: List[str] = []
    j, end = i, min(len(text), i + limit)
    quote = ""
    while j < end:
        c = text[j]
        if quote:
            if c == "\\":
                j += 2
                continue
            if c == quote or (c == "\n" and quote != "`"):
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c in _CLOSE:
            stack.append(_CLOSE[c])
        elif c in ")]}":
            if stack and c == stack[-1]:
                stack.pop()
                if not stack:
                    return j + 1
            else:
                return j + 1
        j += 1
    return end


def _split_args(s: str) -> List[str]:
    """Split a call's argument text on top-level commas."""
    out, depth, cur, quote = [], 0, [], ""
    i = 0
    while i < len(s):
        c = s[i]
        if quote:
            cur.append(c)
            if c == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def _call_args(text: str, open_idx: int) -> Tuple[str, int]:
    """Argument text of the call whose "(" is at open_idx, and the end offset."""
    end = _balanced_end(text, open_idx)
    inner = text[open_idx + 1:end - 1] if end - 1 > open_idx else ""
    return inner, end


_FUNC_START = {
    "js": re.compile(r"\bfunction\b|=>\s*\{|=>\s*$|^\s*(?:(?:public|private|protected|static|async)\s+)*"
                     r"(?!(?:if|for|while|switch|catch|with|else|return)\b)[A-Za-z_$][\w$]*\s*\([^)]*\)\s*"
                     r"(?::[^={]+)?\{\s*$"),
    "py": re.compile(r"^\s*(?:async\s+)?def\s+\w+"),
    "php": re.compile(r"\bfunction\b|\bfn\s*\("),
}


def _find_func(lines: Sequence[str], idx: int, lang: str, ind: int, allow_same: bool, back: int = 150) -> int:
    rx = _FUNC_START[lang]
    for j in range(idx, max(-1, idx - back), -1):
        ln = lines[j]
        if not ln.strip():
            continue
        if rx.search(ln) and (_indent(ln) < ind or (allow_same and j == idx)):
            return j
    return -1


def _func_start(lines: Sequence[str], idx: int, lang: str, depth: int = 3) -> int:
    """Start of the enclosing function of lines[idx], widened to up to `depth`
    nested functions so closures see the variables of their parents."""
    if not lines:
        return 0
    idx = min(idx, len(lines) - 1)
    start = _find_func(lines, idx, lang, _indent(lines[idx]), True)
    if start < 0:
        return max(0, idx - 80)
    for _ in range(depth - 1):
        if start == 0 or _indent(lines[start]) == 0:
            break
        outer = _find_func(lines, start - 1, lang, _indent(lines[start]), False)
        if outer < 0:
            break
        start = outer
    return start


# ---------------------------------------------------------------------------
# Local JS/TS imports: which project file an imported name comes from, and the
# body of a named function in that file. Used to follow a route one or two
# hops into the project's own helpers (an LLM wrapper, an auth helper).
# ---------------------------------------------------------------------------

_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
_IMPORT_RX = re.compile(r"""^[ \t]*import\s+(?!type\s)([^'";]*?)\s+from\s+['"]([^'"\n]+)['"]""", re.M)
_REQUIRE_RX = re.compile(r"""\b(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*require\s*\(\s*['"]([^'"\n]+)['"]\s*\)""")


def _file_index(ctx: Any) -> Dict[str, List[str]]:
    """basename -> project files with that name."""
    def build() -> Dict[str, List[str]]:
        idx: Dict[str, List[str]] = {}
        for f in ctx.files:
            idx.setdefault(f.rsplit("/", 1)[-1], []).append(f)
        return idx
    return ctx.memo("logic-file-index", build)


def _spec_variants(base: str) -> List[str]:
    stem = re.sub(r"\.(?:js|jsx|mjs|cjs)$", "", base)
    out = [base] if base.endswith(_JS_EXTS) else []
    out += [stem + e for e in _JS_EXTS] + [stem + "/index" + e for e in _JS_EXTS]
    return out


def _resolve_spec(ctx: Any, path: str, spec: str) -> Optional[str]:
    """Project file an import specifier points at: relative paths and the
    common @/ and ~/ aliases. None for packages and unknown targets."""
    idx = _file_index(ctx)
    if spec.startswith("."):
        base = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
        for v in _spec_variants(base):
            if v.rsplit("/", 1)[-1] in idx and v in idx[v.rsplit("/", 1)[-1]]:
                return v
        return None
    if not spec.startswith(("@/", "~/")):
        return None
    rest = spec[2:].strip("/")
    best, score = None, -1
    here = path.split("/")[:-1]
    for v in _spec_variants(rest):
        for f in idx.get(v.rsplit("/", 1)[-1], []):
            if f != v and not f.endswith("/" + v):
                continue
            common = 0
            for a, b in zip(here, f.split("/")):
                if a != b:
                    break
                common += 1
            if common > score:
                best, score = f, common
        if best:
            break
    return best


def _import_bindings(clause: str) -> List[Tuple[str, str]]:
    """(local name, exported name) pairs of an import clause; "*" for a
    namespace import and "default" for a default import."""
    out: List[Tuple[str, str]] = []
    m = re.search(r"\{([^}]*)\}", clause)
    if m:
        for part in m.group(1).split(","):
            part = re.sub(r"^\s*type\s+", "", part).strip()
            mm = re.match(r"([\w$]+)(?:\s*(?:as|:)\s*([\w$]+))?$", part)
            if mm:
                out.append((mm.group(2) or mm.group(1), mm.group(1)))
        clause = clause[:m.start()] + clause[m.end():]
    m = re.search(r"\*\s*as\s+([\w$]+)", clause)
    if m:
        out.append((m.group(1), "*"))
        clause = clause[:m.start()] + clause[m.end():]
    m = re.match(r"\s*([\w$]+)", clause)
    if m and m.group(1) != "type":
        out.append((m.group(1), "default"))
    return out


def _local_imports(ctx: Any, path: str) -> List[Tuple[str, str, str]]:
    """(local name, exported name, resolved file) for imports of project files."""
    def build() -> List[Tuple[str, str, str]]:
        code = _code(ctx, path)
        out: List[Tuple[str, str, str]] = []
        found = [(m.group(1), m.group(2)) for m in _IMPORT_RX.finditer(code)]
        found += [(m.group(1) if m.group(1).startswith("{") else "* as " + m.group(1), m.group(2))
                  for m in _REQUIRE_RX.finditer(code)]
        for clause, spec in found:
            target = _resolve_spec(ctx, path, spec)
            if not target or target == path:
                continue
            for local, exported in _import_bindings(clause):
                out.append((local, exported, target))
        return out
    return ctx.memo(("logic-imports", path), build)


_JS_DECL = re.compile(
    r"(?:^|[^\w$.])(?P<exp>export\s+)?(?P<def>default\s+)?(?:async\s+)?function\s*\*?\s*(?P<n1>[\w$]*)\s*(?:<[^(]*?>)?\s*\("
    r"|(?:^|[^\w$.])(?P<exp2>export\s+)?(?:const|let|var)\s+(?P<n2>[\w$]+)\s*(?::[^=\n]+)?=\s*(?:async\s+)?"
    r"(?:function\b[^(]*)?(?:<[^(]*?>)?\(", re.M)


def _body_after_params(code: str, p: int) -> str:
    """Body text of a function whose parameter list ends just before p."""
    n = len(code)
    j = p
    while j < n and code[j] in " \t\r\n":
        j += 1
    if j < n and code[j] == ":":
        j += 1
        depth = 0
        start = j
        while j < n:
            c = code[j]
            if c in "<([":
                depth += 1
            elif c in ">)]" and depth > 0:
                depth -= 1
            elif depth == 0 and code.startswith("=>", j):
                break
            elif depth == 0 and c == "{":
                if code[start:j].strip():
                    break
                j = _balanced_end(code, j)
                continue
            elif depth == 0 and c in ";":
                return ""
            j += 1
    while j < n and code[j] in " \t\r\n":
        j += 1
    if code.startswith("=>", j):
        j += 2
        while j < n and code[j] in " \t\r\n":
            j += 1
        if j < n and code[j] in "({":
            return code[j:_balanced_end(code, j, 60000)]
        end = code.find("\n\n", j)
        return code[j:min(n if end < 0 else end, j + 1500)]
    if j < n and code[j] == "{":
        return code[j:_balanced_end(code, j, 60000)]
    return ""


def _func_bodies(ctx: Any, path: str) -> Dict[str, str]:
    """Named function bodies of a JS/TS file (declarations, arrow and function
    expressions assigned to a const). The default export is under "default"."""
    def build() -> Dict[str, str]:
        code = _code(ctx, path)
        out: Dict[str, str] = {}
        for m in _JS_DECL.finditer(code):
            names = [m.group("n1") or m.group("n2") or ""]
            if m.group("def"):
                names.append("default")
            names = [n for n in names if n and n not in out]
            if not names:
                continue
            _, end = _call_args(code, m.end() - 1)
            body = _body_after_params(code, end)
            for n in names:
                out[n] = body
        dm = re.search(r"^\s*export\s+default\s+([\w$]+)\s*;?\s*$", code, re.M)
        if dm and dm.group(1) in out and "default" not in out:
            out["default"] = out[dm.group(1)]
        # Top-level consts that are not functions (a next-safe-action client
        # built with .use(...), a wrapped handler): the text up to the next
        # top-level declaration.
        tops = list(_TOP_DECL.finditer(code))
        for i, m in enumerate(tops):
            name = m.group(1)
            if name and name not in out:
                end = tops[i + 1].start() if i + 1 < len(tops) else len(code)
                out[name] = code[m.start():min(end, m.start() + 20000)]
        return out
    return ctx.memo(("logic-bodies", path), build)


_TOP_DECL = re.compile(r"^(?:export\s+)?(?:(?:const|let|var)\s+([\w$]+)|(?:async\s+)?function\b|class\b|type\b"
                       r"|interface\b|import\b|export\s+default\b)", re.M)


_CALL_SITE = re.compile(r"(?<![\w$.])([\w$]+)\s*(?:<[^()<>]*>)?\s*\(")
_NS_CALL_SITE = re.compile(r"(?<![\w$.])([\w$]+)\s*\.\s*([\w$]+)\s*(?:<[^()<>]*>)?\s*\(")
_CHAIN_SITE = re.compile(r"(?<![\w$.])([\w$]+)\s*\.\s*(?:metadata|schema|inputSchema|outputSchema|bindArgsSchemas"
                         r"|action|stateAction|use|input|query|mutation|handler|middleware)\s*\(")


def _call_sites(text: str) -> Dict[str, "re.Match[str]"]:
    """First call (or builder chain) of each bare name in text."""
    first: Dict[str, "re.Match[str]"] = {}
    for rx in (_CALL_SITE, _CHAIN_SITE):
        for m in rx.finditer(text):
            if m.group(1) not in first or m.start() < first[m.group(1)].start():
                first[m.group(1)] = m
    return first


def _called_imports(ctx: Any, path: str, text: str) -> List[Tuple["re.Match[str]", str, str]]:
    """Calls in text of functions imported from project files, and imported
    builders used as the base of a chain (authActionClient.schema(...).action(...)):
    (call match, exported name, resolved file)."""
    imports = _local_imports(ctx, path)
    if not imports:
        return []
    first = _call_sites(text)
    ns: Dict[str, List["re.Match[str]"]] = {}
    if any(e == "*" for _, e, _ in imports):
        for m in _NS_CALL_SITE.finditer(text):
            ns.setdefault(m.group(1), []).append(m)
    out = []
    for local, exported, target in imports:
        if exported == "*":
            out.extend((m, m.group(2), target) for m in ns.get(local, []))
        elif local in first:
            out.append((first[local], exported, target))
    out.sort(key=lambda t: t[0].start())
    return out


def _helper_matches(ctx: Any, path: str, name: str, test: Any, key: str, hops: int,
                    seen: Optional[Set[Tuple[str, str]]] = None) -> bool:
    """True when function `name` of file `path`, or a function it calls (same
    file, or up to `hops` more imported files), satisfies test(body, path).
    key names the test for the per-scan cache."""
    cache = ctx.memo("logic-helper-cache", dict)
    ck = (path, name, key, hops)
    if ck in cache:
        return cache[ck]
    seen = set() if seen is None else seen
    if (path, name) in seen:
        return False
    seen.add((path, name))
    bodies = _func_bodies(ctx, path)
    body = bodies.get(name)
    res = False
    if body:
        if test(body, path):
            res = True
        else:
            called = _call_sites(body)
            for other in called:
                if other != name and other in bodies and (path, other) not in seen:
                    if _helper_matches(ctx, path, other, test, key, hops, seen):
                        res = True
                        break
            if not res and hops > 0:
                for _, exported, target in _called_imports(ctx, path, body):
                    if _helper_matches(ctx, target, exported, test, key, hops - 1, seen):
                        res = True
                        break
    cache[ck] = res
    return res


# ---------------------------------------------------------------------------
# Light taint tracking: which names in a function come from the request
# ---------------------------------------------------------------------------

_SRC = {
    "js": re.compile(
        r"\b(?:req|request|ctx\.request)\s*\??\.\s*(?:body|query|params)\b"
        r"|\b(?:req|request)\s*\.\s*(?:json|formData)\s*\("
        r"|\bformData\s*\??\.\s*get(?:All)?\s*\("
        r"|\bc\.req\.(?:json|query|param|parseBody|formData)\s*\("
        r"|\b(?:readBody|getQuery|readValidatedBody)\s*\("
        r"|\b(?:router|route)\.query\b"
        r"|JSON\.parse\s*\(\s*(?:event|req|request)\.body"),
    "py": re.compile(
        r"\brequest\.(?:json|form|args|values|data|POST|GET|query_params|get_json\s*\()"
        r"|\bjson\.loads\s*\(\s*request\.(?:body|data)"),
    "php": re.compile(
        r"\$request\s*->\s*(?:input|get|query|post|all|validated|only|json|string|integer|float)\s*\("
        r"|\$request\s*->\s*(?!user\b|session\b|header\b|headers\b|ip\b|route\b|method\b|path\b|url\b"
        r"|fullUrl\b|file\b|files\b|hasFile\b|has\b|filled\b|wantsJson\b|expectsJson\b|isMethod\b"
        r"|validate\b|merge\b|cookie\b|cookies\b|server\b|bearerToken\b|attributes\b|query\b|request\b)"
        r"[a-z_]\w*\b(?!\s*\()"
        r"|\$_(?:POST|GET|REQUEST)\b|\brequest\s*\(\s*['\"]|php://input"),
}

_WRAPPERS = frozenset({
    "Number", "parseInt", "parseFloat", "String", "BigInt", "Decimal", "Boolean", "int", "float",
    "str", "round", "abs", "intval", "floatval", "strval", "Math.round", "Math.floor", "Math.ceil",
    "Math.trunc", "Math.abs", "decodeURIComponent", "decodeURI", "unquote", "urldecode",
    "rawurldecode", "trim", "URL",
})
_ACCESSORS = frozenset({
    "get", "getAll", "input", "query", "post", "param", "json", "get_json", "string", "integer",
    "float", "all", "validated", "only", "toFixed", "toString", "trim", "valueOf", "toNumber",
    "toLowerCase", "strip", "lower", "pop",
})

_CALL_RX = re.compile(r"((?:new\s+)?[$A-Za-z_][\w$]*(?:\s*(?:\?\.|\.|->|::)\s*[$A-Za-z_][\w$]*)*)\s*\(([^()]*)\)")
_GROUP_RX = re.compile(r"(?<![\w$\])])\(([^()]*)\)")
_SUB_RX = re.compile(r"((?:[$A-Za-z_][\w$]*(?:\s*(?:\?\.|\.|->|::)\s*[$A-Za-z_][\w$]*)*)|__SRC__|__T__)\s*\[([^\[\]]*)\]")
_MEMBER_SPLIT = re.compile(r"\s*(?:\?\.|\.|->|::)\s*")


@lru_cache(maxsize=2048)
def _name_rx(name: str, lang: str) -> "re.Pattern[str]":
    if lang == "php":
        return re.compile(r"(?<![\w$])" + re.escape(name) + r"(?![\w])")
    return re.compile(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])")


def _expand_interp(s: str, lang: str) -> str:
    if lang == "py":
        s = re.sub(r"""\bf(['"])(.*?)\1""", lambda m: " ".join(re.findall(r"\{([^{}]*)\}", m.group(2))) or "''", s)
    if lang == "php":
        s = re.sub(r'"([^"\\\n]*(?:\\.[^"\\\n]*)*)"', lambda m: " ".join(re.findall(r"\$\w+", m.group(1))) or "''", s)
    return s


def _strip_strings(s: str) -> str:
    return re.sub(r"'(?:[^'\\\n]|\\.)*'|\"(?:[^\"\\\n]|\\.)*\"", "''", s)


def _has_taint(expr: str, names: Set[str], lang: str, src: "re.Pattern[str]") -> bool:
    if "__SRC__" in expr or "__T__" in expr:
        return True
    plain = _strip_strings(_expand_interp(expr, lang))
    if src.search(plain):
        return True
    return any(_name_rx(n, lang).search(plain) for n in names)


def _reduce(expr: str, names: Set[str], lang: str, src: "re.Pattern[str]") -> str:
    e = _expand_interp(expr, lang)

    def call_repl(m: "re.Match[str]") -> str:
        full, name, inner = m.group(0), m.group(1), m.group(2)
        sm = src.search(full)
        if sm and sm.start() <= len(name):
            return "__SRC__"
        bare = name[4:].strip() if name.startswith("new ") else name
        parts = _MEMBER_SPLIT.split(bare)
        dotted = ".".join(parts)
        if dotted in _WRAPPERS or (len(parts) == 1 and parts[0] in _WRAPPERS):
            return " (" + inner + ") "
        if len(parts) > 1 and parts[-1] in _ACCESSORS and _has_taint(".".join(parts[:-1]), names, lang, src):
            return "__T__"
        return "__CALL__"

    def sub_repl(m: "re.Match[str]") -> str:
        full, base = m.group(0), m.group(1)
        sm = src.search(full)
        if sm and sm.start() <= len(base):
            return "__SRC__"
        if base in ("__SRC__", "__T__") or _has_taint(base, names, lang, src):
            return "__T__"
        return "__IDX__"

    for _ in range(16):
        new = _CALL_RX.sub(call_repl, e)
        new = _GROUP_RX.sub(lambda m: " " + m.group(1) + " ", new)
        new = _SUB_RX.sub(sub_repl, new)
        if new == e:
            break
        e = new
    return e


def _ternary_branches(expr: str, lang: str) -> Optional[List[str]]:
    """The two value branches of a top-level conditional expression, or None."""
    if lang == "py":
        m = re.match(r"(.*?)\s+if\s+.+?\s+else\s+(.*)$", expr.strip(), re.S)
        return [m.group(1), m.group(2)] if m else None
    depth, quote, q = 0, "", -1
    for i, c in enumerate(expr):
        if quote:
            if c == quote:
                quote = ""
            continue
        if c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c == "?" and expr[i + 1:i + 2] not in (".", "?") and expr[i - 1:i] != "?":
            if q < 0:
                q = i
        elif depth == 0 and c == ":" and q >= 0 and expr[i + 1:i + 2] != ":" and expr[i - 1:i] != ":":
            return [expr[q + 1:i], expr[i + 1:]]
    return None


def _direct(expr: str, names: Set[str], lang: str, src: "re.Pattern[str]") -> bool:
    """True when expr is request data, maybe converted or defaulted, not looked up or computed."""
    if not expr or not expr.strip():
        return False
    branches = _ternary_branches(expr, lang)
    if branches:
        return any(_direct(b, names, lang, src) for b in branches)
    return _has_taint(_reduce(expr, names, lang, src), names, lang, src)


_JS_DESTRUCT = re.compile(r"\b(?:const|let|var)\s*([{\[])([^{}\[\]]*)[}\]]\s*(?::\s*[^=;]+?)?\s*=(?![=>])\s*([^;\n]+)")
_JS_ASSIGN = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?::\s*[\w$.<>\[\]| ]+?)?\s*(?<![=!<>+\-*/%&|^?])=(?![=>])\s*([^;\n]+)")
_PY_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*(?::\s*[^=\n]+)?=(?!=)\s*(.+)$", re.M)
_PHP_ASSIGN = re.compile(r"(\$\w+)\s*(?<![=!<>.+\-*/])=(?![=>])\s*([^;]+)")
_JS_FOROF = re.compile(r"\bfor\s*\(\s*(?:const|let|var)\s+(?:\{([^}]*)\}|([\w$]+))\s+of\s+([^)]+)\)")
_JS_MAPCB = re.compile(r"([\w$.?\[\]'\"]+?)\s*\??\.\s*(?:map|forEach|flatMap|filter)\s*\(\s*(?:async\s*)?"
                       r"(?:\(\s*(?:\{([^}]*)\}|([\w$]+))\s*(?:,[^)]*)?\)|([\w$]+))\s*=>")
_PY_FOR = re.compile(r"\bfor\s+([A-Za-z_]\w*)\s+in\s+([^:\]\n]+)")
_PHP_FOREACH = re.compile(r"\bforeach\s*\(\s*(.+?)\s+as\s+(?:\$\w+\s*=>\s*)?(\$\w+)")


def _destruct_names(body: str) -> List[str]:
    out = []
    for piece in body.split(","):
        p = piece.strip().lstrip(".")
        if not p:
            continue
        if ":" in p:
            p = p.split(":", 1)[1]
        p = p.split("=", 1)[0].strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", p):
            out.append(p)
    return out


def _assignments(region: str, lang: str) -> List[Tuple[List[str], str]]:
    out: List[Tuple[List[str], str]] = []
    if lang == "js":
        for m in _JS_DESTRUCT.finditer(region):
            out.append((_destruct_names(m.group(2)), m.group(3)))
        for m in _JS_ASSIGN.finditer(region):
            out.append(([m.group(1)], m.group(2)))
    elif lang == "py":
        for m in _PY_ASSIGN.finditer(region):
            out.append(([n.strip() for n in m.group(1).split(",")], m.group(2)))
    else:
        for m in _PHP_ASSIGN.finditer(region):
            out.append(([m.group(1)], m.group(2)))
    return out


def _loops(region: str, lang: str) -> List[Tuple[List[str], str]]:
    out: List[Tuple[List[str], str]] = []
    if lang == "js":
        for m in _JS_FOROF.finditer(region):
            names = _destruct_names(m.group(1)) if m.group(1) else [m.group(2)]
            out.append((names, m.group(3)))
        for m in _JS_MAPCB.finditer(region):
            if m.group(2):
                names = _destruct_names(m.group(2))
            else:
                names = [m.group(3) or m.group(4)]
            out.append((names, m.group(1)))
    elif lang == "py":
        for m in _PY_FOR.finditer(region):
            out.append(([m.group(1)], m.group(2)))
    else:
        for m in _PHP_FOREACH.finditer(region):
            out.append(([m.group(2)], m.group(1)))
    return out


def _tainted(region: str, lang: str, src: "re.Pattern[str]", seed: Iterable[str] = ()) -> Set[str]:
    names: Set[str] = set(seed)
    assigns = _assignments(region, lang)
    loops = _loops(region, lang)
    for _ in range(4):
        before = len(names)
        for lhs, rhs in assigns:
            if lhs and not set(lhs) <= names and _direct(rhs, names, lang, src):
                names.update(lhs)
        for lhs, it in loops:
            if lhs and not set(lhs) <= names and _direct(it, names, lang, src):
                names.update(lhs)
        if len(names) == before:
            break
    return names


_PY_ROUTE_DECO = re.compile(r"^\s*@[\w.]+\.(?:post|put|patch|get|api_route|route|delete)\s*\(")
_PY_PARAMS_SKIP = re.compile(r"Depends|Request\b|Session\b|BackgroundTasks|Header\s*\(|Cookie\s*\(|Security|"
                             r"HTTPAuthorizationCredentials|\bUser\b|AsyncSession|Response\b")
_USE_SERVER = re.compile(r"""\A(?:\s|//[^\n]*(?:\n|\Z)|/\*(?:[^*]|\*(?!/))*\*/)*["']use server["']""")


def _seed_names(lines: Sequence[str], start: int, lang: str, text: str) -> Set[str]:
    """Names that are client input because of where they are declared: FastAPI
    route parameters and exported Server Action parameters."""
    seed: Set[str] = set()
    if lang == "py" and 0 <= start < len(lines):
        deco = any(_PY_ROUTE_DECO.match(lines[k]) for k in range(max(0, start - 4), start))
        if deco:
            sig = " ".join(lines[start:start + 8])
            m = re.search(r"def\s+\w+\s*\((.*?)\)\s*(?:->[^:]+)?:", sig)
            if m:
                for p in _split_args(m.group(1)):
                    if not p or _PY_PARAMS_SKIP.search(p):
                        continue
                    name = re.split(r"[:=]", p, maxsplit=1)[0].strip().lstrip("*")
                    if name and name not in ("self", "request", "db", "session", "current_user", "user"):
                        seed.add(name)
    if lang == "js" and _USE_SERVER.match(text) and 0 <= start < len(lines):
        sig = " ".join(lines[start:start + 4])
        m = re.search(r"export\s+(?:default\s+)?async\s+function\s*\w*\s*\(([^)]*)\)", sig)
        if m:
            for p in _split_args(m.group(1)):
                p = re.sub(r":.*$", "", p).strip()
                if p.startswith("{"):
                    seed.update(_destruct_names(p.strip("{} ")))
                elif re.fullmatch(r"[A-Za-z_$][\w$]*", p) and p not in ("prevState", "state"):
                    seed.add(p)
    return seed


# ---------------------------------------------------------------------------
# Stripe webhooks
# ---------------------------------------------------------------------------

_STRIPE_WORD = re.compile(r"(?i)stripe")
_VERIFY = re.compile(r"(?i)\bconstruct_?event(?:_?async)?\s*\(|\bverify_?header\s*\(|\bVerifyWebhookSignature\b"
                     r"|\bWebhookSignature\s*(?:\.|::)\s*verify")
_VERIFY_CALL = re.compile(r"(?i)\bconstruct_?event(?:_?async)?\s*\(")
_SIG_HEADER = re.compile(r"(?i)stripe[-_]signature")
_HMAC = re.compile(r"(?i)createHmac|hmac\.new|hash_hmac|timingSafeEqual|compare_digest|crypto\.subtle\.(?:verify|sign)")
_EVT = r"(?:checkout\.session|payment_intent|invoice|customer\.subscription|charge|setup_intent|subscription_schedule)\.[a-z_]+(?:\.[a-z_]+)*"
_DISPATCH = re.compile(r"""(?:\bcase\s+|[=!]==?\s*|\bin\s*[\[(]\s*)['"]""" + _EVT + r"""['"]"""
                       r"""|['"]""" + _EVT + r"""['"]\s*(?:[=!]==?|:(?!:)|=>)""")
_MANAGED_WEBHOOK = re.compile(r"Laravel\\+Cashier|CashierController|WebhookReceived|WebhookHandled|djstripe|dj_stripe"
                              r"|stripe-sync-engine|@supabase/stripe-sync")
# Events fetched back from the Stripe API are trusted (a valid alternative to signatures).
_API_EVENTS = re.compile(r"\bevents\s*(?:\.|->)\s*(?:list|retrieve)\s*\(|\bEvent\s*(?:\.|::)\s*(?:list|retrieve)\s*\(")


def _file_verifies(code: str) -> bool:
    return bool(_VERIFY.search(code) or (_SIG_HEADER.search(code) and _HMAC.search(code)))


def _project_verifies(ctx: Any) -> bool:
    def scan() -> bool:
        return any(_file_verifies(_code(ctx, f)) for f in _prod_code_files(ctx))
    return ctx.memo("logic-project-verifies", scan)


def _is_webhook_handler(code: str) -> bool:
    return bool(_STRIPE_WORD.search(code) and (_VERIFY.search(code) or _DISPATCH.search(code)))


_PAID_WRITE = re.compile(
    r"""(?i)\b(?:payment_?status|paymentStatus|order_?status|orderStatus|status|is_?paid|isPaid|paid)['"]?\s*"""
    r"""(?::(?!:)|=>|=(?![=>]))\s*(?:['"](?:paid|completed?|success|successful|succeeded|captured|settled)['"]"""
    r"""|true\b)""")
_CALLBACK_PATH = re.compile(r"(?i)ipn|callback|notify|notification|webhook|hook|verify|confirm|capture|success"
                            r"|return|complete")
_GW_SIGNATURE = re.compile(
    r"(?i)createHmac|hmac\.new|hash_hmac|crypto\.subtle\.(?:verify|sign|importKey)|timingSafeEqual|compare_digest"
    r"|hash_equals|verify\w*Signature|validate\w*Signature|validatePaymentVerification|verif-hash"
    r"|x-paystack-signature|x-razorpay-signature|paypal-transmission-sig|verify_sign|verify_key|webhook_?secret"
    r"|signing_?secret|\bverify_?webhook")
_GW_SDK_FETCH = re.compile(r"(?i)\.\s*(?:payments?|orders?|transactions?|transaction)\s*\.\s*(?:fetch|get|verify|retrieve"
                           r"|capture|show)\s*\(")
_AMOUNT_CMP = re.compile(r"(?i)\b\w*(?:amount|total|price)\w*\b[^\n;=!]{0,80}[!=]==?(?!>)"
                         r"|[!=]==?\s*[^\n;]{0,80}\b\w*(?:amount|total|price)\w*\b")


def _gateway_callback_hits(path: str, code: str, ctx: Any) -> List[Hit]:
    """Non-Stripe payment callbacks (IPN, return or verify endpoints) that mark an
    order paid without checking the gateway's signature, or that ask the
    gateway to validate but never compare the paid amount with the order."""
    lang = _lang(path)
    if not (_GATEWAY_WORD.search(code) or _GATEWAY_WORD.search(path)) or not _CALLBACK_PATH.search(path):
        return []
    if lang != "php" and (ctx.is_client_file(path) or not _is_server_route(path, code, ctx, lang)):
        return []
    if _GW_SIGNATURE.search(code):
        return []
    hits: List[Hit] = []
    pm = _PAID_WRITE.search(code)
    if pm:
        n = _line_at(code, pm.start())
        ev = ctx.lines(path)[n - 1].strip()
        if not (_url_calls(code, _GATEWAY_HOST_RX) or _GW_SDK_FETCH.search(code)):
            hits.append(Hit(n, ev, "Payment callback marks the order paid without verifying the gateway's signature "
                                   "or asking the gateway; anyone can post a fake success", "high"))
        elif not _AMOUNT_CMP.search(code):
            hits.append(Hit(n, ev, "Payment callback asks the gateway to validate the payment but never compares the "
                                   "paid amount and order id with the stored order; a cheap payment can settle an "
                                   "expensive order", "medium"))
    sw = _posted_status_write(path, code, ctx)
    if sw is not None and all(h.line != sw + 1 for h in hits):
        hits.append(Hit(sw + 1, ctx.lines(path)[sw].strip(),
                        "Payment callback writes the order's status straight from the posted data with no signature "
                        "check; anyone can mark any order failed or cancelled", "medium"))
    return hits


_STATUS_KV = re.compile(r"""(?<![\w$])['"]?(?:payment_?status|paymentStatus|order_?status|orderStatus|status)['"]?"""
                        r"""\s*(?::(?!:)|=>|=(?![=>]))\s*(?P<val>[^,\n}\]);]+)""")


def _posted_status_write(path: str, code: str, ctx: Any) -> Optional[int]:
    """Line index of an order or payment status written from request data
    (payment_status: ipn.status.toLowerCase()) inside a database write."""
    lang = _lang(path)
    lines = _code_lines(ctx, path)
    src = _SRC[lang]
    for wm in _WRITE_OP.finditer(code):
        # Updates of an existing order only: an insert that logs the posted
        # status (an ipn_logs row) changes nothing.
        if not wm.group(0).rstrip().endswith("(") or not re.search(r"(?i)update|upsert", wm.group(0)):
            continue
        args, _ = _call_args(code, wm.end() - 1)
        base = wm.end()
        for km in _STATUS_KV.finditer(args):
            off = base + km.start("val")
            i = _line_at(code, off) - 1
            ln = lines[i]
            col = off - (code.rfind("\n", 0, off) + 1)
            # Callback files hold one handler: take the whole file above the
            # write as its scope (nested callbacks confuse the function finder).
            start = _func_start(lines, i, lang)
            names = _tainted("\n".join(lines[:i + 1]), lang, src, _seed_names(lines, start, lang, code))
            if _direct(_value_at(ln, col), names, lang, src):
                return i
    return None


def _value_at(line: str, i: int) -> str:
    """The expression starting at line[i], up to the next top-level , ; or closing bracket."""
    depth, quote, j = 0, "", i
    while j < len(line):
        c = line[j]
        if quote:
            if c == "\\":
                j += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif c in ",;" and depth == 0:
            break
        j += 1
    return line[i:j].strip()


def check_webhook_unverified(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path)
    m = _DISPATCH.search(code)
    if not m or not _STRIPE_WORD.search(code):
        return _gateway_callback_hits(path, code, ctx)
    if _file_verifies(code) or _MANAGED_WEBHOOK.search(code) or _API_EVENTS.search(code):
        return []
    lang = _lang(path)
    if lang == "php" and "laravel/cashier" in ctx.composer_deps:
        return []
    if lang == "py" and "dj-stripe" in ctx.py_deps:
        return []
    if _project_verifies(ctx):
        return []
    n = _line_at(code, m.start())
    return [Hit(n, ctx.lines(path)[n - 1].strip())]


_EVT_VAR = r"(?:\$?\b(?:event|evt|stripe_?event|stripeEvent|webhook_?event|webhookEvent))"
_FALLBACK = re.compile(
    r"(?i)" + _EVT_VAR + r"\s*(?::\s*[\w.<>\[\]| ]+?)?\s*=(?![=>])\s*(?:await\s+)?"
    r"(?![^;\n]*\b(?:events|Event)\s*(?:\.|::)\s*retrieve)[^;\n]*?"
    r"(?:\b(?:req|request|ctx\.request)\.(?:body|data|json|get_json|payload)\b|\bJSON\.parse\s*\("
    r"|\bjson\.loads\s*\(|\bjson_decode\s*\(|\bconstruct_?from\s*\(|\bparse_?body\s*\()")
_SECRETISH = r"(?:secret|whsec|signing_?key)"
_SECRETISH_RX = re.compile(_SECRETISH, re.I)
_TERNARY = re.compile(_SECRETISH + r"[\w.$\]'\")]*\s*\?\s*[^:\n]*?\bconstruct_?event(?:_?async)?\s*\([^\n]*:\s*[^\n]*"
                      r"(?:\.body\b|JSON\.parse|json\.loads|json_decode)", re.I)
_IF = re.compile(r"(?i)^\s*(?:\}\s*)?(?:else\s*)?(?:el)?if\b(?P<cond>.*)$")
_ELSE = re.compile(r"(?i)^\s*(?:\}\s*)?else\b(?!\s*if)")
_CATCH = re.compile(r"^\s*(?:\}\s*)?(?:catch\b|except\b)")
_FAILS = re.compile(r"(?i)\b(?:return|throw|raise|abort|exit|die)\b|\.status\s*\(\s*[45]\d\d|sendStatus\s*\(\s*[45]"
                    r"|status(?:_code)?\s*=\s*[45]\d\d|http_response_code\s*\(\s*[45]|\bnext\s*\(\s*\w+\s*\)")


def _polarity(cond: str) -> int:
    """+1 when the condition is true while the secret is set, -1 when true while it is missing."""
    c = cond.lower()
    if re.search(r"!\s*empty\s*\(", c):
        return 1
    if re.search(r"\bempty\s*\(", c) or re.search(r"!\s*isset\s*\(", c):
        return -1
    if re.search(r"\bisset\s*\(", c) or re.search(r"\bis\s+not\s+none\b", c):
        return 1
    if re.search(r"\bis\s+none\b", c):
        return -1
    if re.search(r"\bnot\s+[\w.\[\]'\"()]*" + _SECRETISH, c):
        return -1
    if re.search(r"!\s*\(?\s*[\w.$\[\]'\"()>-]*?" + _SECRETISH, c):
        return -1
    if re.search(_SECRETISH + r"[\w.$\]'\"()]*\s*(?:===?|==)\s*(?:null|undefined|none|''|\"\"|false)", c):
        return -1
    return 1


def _cond_of(line: str) -> Optional[str]:
    m = _IF.match(line)
    if not m:
        return None
    cond = m.group("cond")
    cond = cond.split("{", 1)[0] if "{" in cond else cond
    cond = cond.rstrip().rstrip(":")
    return cond if _SECRETISH_RX.search(cond) else None


def _block_after(lines: Sequence[str], c: int, lang: str, limit: int = 12) -> List[str]:
    """Body lines of the block opened on lines[c] (catch, except, else)."""
    head = lines[c]
    ind = _indent(head)
    if lang == "py":
        out = []
        for ln in lines[c + 1:c + 1 + limit]:
            if ln.strip() and _indent(ln) <= ind:
                break
            out.append(ln)
        return out
    tail = head.split("{", 1)[1] if "{" in head else ""
    if tail and "}" in tail:
        return [tail]
    out = [tail] if tail.strip() else []
    for ln in lines[c + 1:c + 1 + limit]:
        s = ln.strip()
        if s.startswith("}") and _indent(ln) <= ind:
            break
        out.append(ln)
    return out


_ENV_READ = (r"(?:process\.env(?:\.[\w$]+|\[\s*['\"]\w+['\"]\s*\])|Deno\.env\.get\s*\(\s*['\"]\w+['\"]\s*\)"
             r"|import\.meta\.env\.[\w$]+|(?:os\.environ\.get|os\.getenv|getenv|env)\s*\(\s*['\"]\w+['\"]\s*\))")
_EMPTY_FALLBACK = re.compile(
    r"(" + _ENV_READ + r"\s*(?:\|\||\?\?|\?:|\bor\b)\s*(?:''|\"\"|``)"
    r"|(?:os\.environ\.get|os\.getenv|\benv)\s*\(\s*['\"]\w+['\"]\s*,\s*(?:''|\"\")\s*\))")
_HMAC_KEY_USE = {
    "js": re.compile(r"createHmac\s*\(\s*['\"`][\w-]+['\"`]\s*,\s*(?P<k>[^,)]+)"
                     r"|importKey\s*\(\s*['\"`]raw['\"`]\s*,\s*(?P<k2>[^,]+),"),
    "py": re.compile(r"hmac\.new\s*\(\s*(?:key\s*=\s*)?(?P<k>[^,)]+)"),
    "php": re.compile(r"hash_hmac\s*\(\s*['\"][\w-]+['\"]\s*,\s*[^,]+,\s*(?P<k>[^,)]+)"),
}


def _fails_when_empty(code: str, name: str, lang: str) -> bool:
    """The code stops (throw, return, 500) when the key is empty: if (!KEY) throw ..."""
    e = re.escape(name)
    for m in re.finditer(r"\bif\s*\(?\s*(?:!\s*|not\s+|empty\s*\(\s*)" + e + r"\b(?!\s*[.\[(])"
                         r"|\bif\s*\(?\s*" + e + r"\s*(?:===?|==)\s*(?:''|\"\"|null|undefined|None)", code):
        if _FAILS.search(code[m.end():m.end() + 250]):
            return True
    return False


def _hmac_empty_key_hits(path: str, code: str, ctx: Any) -> List[Hit]:
    """A payment signature checked with an HMAC whose key falls back to ''."""
    lang = _lang(path)
    if not (_GATEWAY_WORD.search(code) or re.search(r"(?i)webhook|payment|signature", path)):
        return []
    use_rx = _HMAC_KEY_USE[lang]
    uses = [(m, m.group("k") or m.groupdict().get("k2") or "") for m in use_rx.finditer(code)]
    if not uses:
        return []
    seed: Set[str] = set()
    first_assign: Dict[str, int] = {}
    for a in _assignments(code, lang):
        names, rhs = a
        if _EMPTY_FALLBACK.search(rhs):
            for nm in names:
                seed.add(nm)
                first_assign.setdefault(nm, code.find(rhs))
    derived = _tainted(code, lang, _NEVER, seed) if seed else set()
    for m, key in uses:
        inline = _EMPTY_FALLBACK.search(key)
        hit_names = [nm for nm in derived if _name_rx(nm, lang).search(key)]
        if not inline and not hit_names:
            continue
        related = [nm for nm in seed if nm in hit_names] or sorted(seed)
        if any(_fails_when_empty(code, nm, lang) for nm in related):
            continue
        off = m.start()
        roots = [nm for nm in hit_names if nm in first_assign]
        if roots and first_assign[roots[0]] >= 0:
            off = first_assign[roots[0]]
        n = _line_at(code, off)
        return [Hit(n, ctx.lines(path)[n - 1].strip(),
                    "The HMAC key for the payment or webhook signature falls back to an empty string when the env "
                    "var is unset, so anyone can compute a valid signature", "high")]
    return []


def check_webhook_verify_optional(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path)
    if not _VERIFY.search(code) or not _STRIPE_WORD.search(code):
        return _hmac_empty_key_hits(path, code, ctx)
    lines = _code_lines(ctx, path)
    lang = _lang(path)
    hits: List[Hit] = []
    seen: Set[int] = set()
    n = len(lines)
    for v in range(n):
        line = lines[v]
        if not _VERIFY.search(line):
            continue
        # One-line ternary: secret ? verify(...) : JSON.parse(body)
        t = _TERNARY.search(line)
        if t:
            if v not in seen:
                seen.add(v)
                hits.append(Hit(v + 1, line.strip(), "Stripe signature is only checked when the webhook secret is set; "
                                                    "otherwise the parsed body is trusted"))
            continue
        lo, hi = max(0, v - 25), min(n, v + 15)
        fb = [i for i in range(lo, hi) if i != v and _FALLBACK.search(lines[i]) and not _VERIFY.search(lines[i])]
        if not fb:
            continue
        found = False
        for g in range(v - 1, max(-1, v - 9), -1):
            cond = _cond_of(lines[g])
            if cond is None:
                continue
            if _polarity(cond) > 0:
                # Safe when an else branch fails closed without trusting the body.
                safe_else = False
                for e in range(v + 1, min(n, v + 16)):
                    if _ELSE.match(lines[e]) and _indent(lines[e]) <= _indent(lines[g]):
                        body = _block_after(lines, e, lang)
                        body_idx = set(range(e, e + len(body) + 1))
                        if _FAILS.search("\n".join(body)) and not (body_idx & set(fb)):
                            safe_else = True
                        break
                if not safe_else and g not in seen:
                    seen.add(g)
                    hits.append(Hit(g + 1, lines[g].strip(),
                                    "Stripe signature is only checked when the webhook secret is set; "
                                    "otherwise the unverified body is trusted"))
                    found = True
            elif any(g < i < v for i in fb) and g not in seen:
                seen.add(g)
                hits.append(Hit(g + 1, lines[g].strip(),
                                "When the webhook secret is missing the handler trusts the unverified body"))
                found = True
            break
        if found:
            continue
        if not any(i < v for i in fb):
            continue
        for c in range(v + 1, min(n, v + 9)):
            if _CATCH.match(lines[c]):
                body = _block_after(lines, c, lang)
                if not _FAILS.search("\n".join(body)) and c not in seen:
                    seen.add(c)
                    hits.append(Hit(c + 1, lines[c].strip(),
                                    "A failed signature check is caught and ignored, so the unverified body is used"))
                break
    return hits


_JSON_MOUNT = re.compile(r"\b(?:app|server|router)\.use\s*\(\s*(?:express|bodyParser)\.json\s*\(([^)]*)\)")
_ROUTE_LINE = re.compile(r"\.(?:post|all|use)\s*\(\s*['\"`]")
_RAW_PARSER = re.compile(r"\b(?:express|bodyParser)\.(?:raw|text)\s*\(|\braw\s*\(\s*\{")


def check_webhook_parsed_body(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path)
    if not _VERIFY_CALL.search(code) or not _STRIPE_WORD.search(code):
        return []
    lines = _code_lines(ctx, path)
    lang = _lang(path)
    hits: List[Hit] = []
    for m in _VERIFY_CALL.finditer(code):
        v = _line_at(code, m.start()) - 1
        args, _ = _call_args(code, m.end() - 1)
        parts = _split_args(args)
        if not parts:
            continue
        first = parts[0].strip()
        ev = lines[v].strip()
        if re.match(r"(?:JSON\.stringify|json\.dumps|json_encode)\s*\(", first):
            hits.append(Hit(v + 1, ev, "The webhook verifies a re-serialized JSON body; Stripe signs the raw bytes, "
                                       "so this check fails or gets removed"))
            continue
        if re.fullmatch(r"\$?[A-Za-z_][\w$]*", first):
            name = first
            pat = re.compile(r"(?<![\w$.])" + re.escape(name) + r"\s*(?::[^=\n]+)?=(?![=>])\s*(?:await\s+)?[^;\n]*?"
                             r"(?:\b(?:req|request|c\.req)\s*\.\s*json\b|\bget_json\s*\(|\bJSON\.parse\s*\("
                             r"|\bjson\.loads\s*\(|\bjson_decode\s*\()")
            for k in range(v, max(-1, v - 30), -1):
                if pat.search(lines[k]):
                    hits.append(Hit(k + 1, lines[k].strip(), "The webhook body is parsed as JSON before the "
                                                             "signature check; verify the raw body instead"))
                    break
            continue
        if lang == "js" and re.fullmatch(r"(?:req|request)\.body", first):
            if re.search(r"(?:^|/)pages/api/", path) and not re.search(r"bodyParser\s*:\s*false", code):
                hits.append(Hit(v + 1, ev, "Pages Router API route parses the body before the Stripe check; "
                                           "set config.api.bodyParser = false and read the raw body"))
                continue
            r = None
            for k in range(v, max(-1, v - 40), -1):
                if _ROUTE_LINE.search(lines[k]):
                    r = k
                    break
            if r is None:
                continue
            if any(_RAW_PARSER.search(lines[k]) for k in range(r, min(v + 1, r + 4))):
                continue
            for k in range(0, r):
                jm = _JSON_MOUNT.search(lines[k])
                if not jm or "verify" in jm.group(1):
                    continue
                near = "\n".join(lines[max(0, k - 4):k + 1])
                if re.search(r"originalUrl|req\.(?:path|url)\b", near):
                    continue
                hits.append(Hit(v + 1, ev, "express.json() is mounted before this webhook route, so req.body is "
                                           "already parsed and the Stripe check cannot pass"))
                break
    return hits


# ---------------------------------------------------------------------------
# Client-sent amounts
# ---------------------------------------------------------------------------

_STRIPE_CREATE = re.compile(
    r"(?:\b(?:paymentIntents|payment_intents|checkout\s*(?:\.|->)\s*sessions|invoiceItems|invoice_items"
    r"|paymentLinks|payment_links|prices)\s*(?:\.|->)\s*(?:create|update)"
    r"|\b(?:PaymentIntent|checkout\.Session|InvoiceItem|PaymentLink|Price)\s*(?:\.|::)\s*(?:create|modify)"
    r"|\bCheckout\\+Session\s*::\s*create)\s*\(")
_CASHIER_CHARGE = re.compile(r"->\s*(?:charge|checkoutCharge|pay)\s*\(")
_MONEY_KV = re.compile(r"""(?<![\w$])['"]?(amount|unit_amount|unit_amount_decimal)['"]?\s*(?::(?!:)|=>|=(?![=>]))\s*(?P<val>[^,\n}]+)""")
_UNIT_KV = re.compile(r"""(?<![\w$])['"]?(unit_amount|unit_amount_decimal)['"]?\s*(?::(?!:)|=>|=(?![=>]))\s*(?P<val>[^,\n}]+)""")
_MONEY_SHORT = re.compile(r"[{,]\s*(amount|unit_amount)\s*(?=[,}\n])")
_VARIABLE_PRICE = re.compile(r"(?i)donat|\btips?\b|tip_?amount|pay[-_ ]?what|contribution|top[-_ ]?up|deposit")


_TS_WORDS = frozenset({"as", "number", "string", "any", "unknown", "bigint", "null", "undefined", "true", "false",
                       "None", "or", "and", "not", "await", "int", "float", "__SRC__", "__T__"})
_CHAIN = r"(?:\s*(?:\?\.|\.|->)\s*[$\w]+|\s*\[[^\]]*\])*"


def _client_money(val: str, names: Set[str], lang: str, src: "re.Pattern[str]") -> bool:
    """True when a money value is request data, maybe converted or scaled by a
    constant. A value that also uses a server-side figure (product.price * qty)
    or any lookup or call is treated as priced on the server."""
    red = _reduce(val, names, lang, src)
    if not _has_taint(red, names, lang, src):
        return False
    if "__CALL__" in red or "__IDX__" in red:
        return False
    rest = _strip_strings(red)
    rest = re.sub(r"(?:__SRC__|__T__)" + _CHAIN, " ", rest)
    rest = re.sub(r"(?:" + src.pattern + r")" + _CHAIN, " ", rest)
    for n in names:
        rest = re.sub(_name_rx(n, lang).pattern + _CHAIN, " ", rest)
    idents = [w for w in re.findall(r"\$?[A-Za-z_][\w$]*", rest) if w not in _TS_WORDS]
    return not idents


def _object_lines(lines: Sequence[str], start: int, end: int, name: str) -> Optional[Tuple[int, int]]:
    """Line range of `name = {...}` defined in lines[start:end]."""
    rx = re.compile(r"(?<![\w$.])" + re.escape(name) + r"\s*(?::[^=\n]+)?=\s*[\[{]")
    for k in range(end - 1, start - 1, -1):
        if rx.search(lines[k]):
            depth = 0
            for j in range(k, min(len(lines), k + 60)):
                depth += lines[j].count("{") + lines[j].count("[") - lines[j].count("}") - lines[j].count("]")
                if depth <= 0 and j > k:
                    return k, j
            return k, min(len(lines) - 1, k + 60)
    return None


def check_client_amount(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path)
    hits: List[Hit] = []
    if _STRIPE_WORD.search(code):
        hits += _stripe_client_amount(path, code, ctx)
    if _GATEWAY_WORD.search(code):
        hits += _gateway_client_amount(path, code, ctx)
    if _ORDER_INSERT.search(code):
        hits += _client_order_total(path, code, ctx)
    return hits


def _stripe_client_amount(path: str, code: str, ctx: Any) -> List[Hit]:
    lang = _lang(path)
    lines = _code_lines(ctx, path)
    src = _SRC[lang]
    hits: List[Hit] = []
    calls = [(m, False) for m in _STRIPE_CREATE.finditer(code)]
    if lang == "php":
        calls += [(m, True) for m in _CASHIER_CHARGE.finditer(code)]
    for m, cashier in calls:
        c = _line_at(code, m.start()) - 1
        args, end = _call_args(code, m.end() - 1)
        e = _line_at(code, end) - 1
        start = _func_start(lines, c, lang)
        region_lines = lines[start:e + 1]
        region = "\n".join(region_lines)
        if _VARIABLE_PRICE.search(region) or _VARIABLE_PRICE.search(path):
            continue
        names = _tainted(region, lang, src, _seed_names(lines, start, lang, code))
        if cashier:
            parts = _split_args(args)
            if parts and _client_money(parts[0], names, lang, src):
                hits.append(Hit(c + 1, lines[c].strip()))
            continue
        block = (c, e)
        stripped = args.strip()
        if re.fullmatch(r"\$?[A-Za-z_][\w$]*", stripped):
            rng = _object_lines(lines, start, c, stripped)
            if rng:
                block = rng
        found = None
        for k in range(block[0], block[1] + 1):
            ln = lines[k]
            for km in _MONEY_KV.finditer(ln):
                if _client_money(km.group("val"), names, lang, src):
                    found = k
                    break
            if found is None:
                for km in _MONEY_SHORT.finditer(ln):
                    if km.group(1) in names:
                        found = k
                        break
            if found is not None:
                break
        if found is None:
            for k in range(start, c):
                for km in _UNIT_KV.finditer(lines[k]):
                    if _client_money(km.group("val"), names, lang, src):
                        found = k
                        break
                if found is not None:
                    break
        if found is not None and not _amount_checked(region, lines[found], names, lang):
            hits.append(Hit(found + 1, lines[found].strip()))
    return hits


# Other payment gateways: their REST APIs called with fetch or axios, and their SDKs.
_GATEWAY_WORD = re.compile(
    r"(?i)razorpay|sslcommerz|paystack|flutterwave|mercado_?pago|paypal|lemon_?squeezy|paddle|iyzi(?:co|pay)|mollie"
    r"|shopier|cashfree|xendit|midtrans|paytr|squareup|bkash|payu|yookassa|instamojo|paymob")
_GATEWAY_HOST_RX = re.compile(
    r"['\"`]https?://[\w.-]*?(?:razorpay\.com|sslcommerz\.com|paystack\.co|flutterwave\.com|mercadopago\.com"
    r"|paypal\.com|lemonsqueezy\.com|paddle\.com|iyzipay\.com|mollie\.com|shopier\.com|cashfree\.com|xendit\.co"
    r"|midtrans\.com|paytr\.com|squareup(?:sandbox)?\.com|bka\.sh|payu\.in|yookassa\.ru|instamojo\.com"
    r"|paymob\.com)\b")
_GATEWAY_SDK_CALL = re.compile(
    r"(?i)\b(?:\w*(?:razorpay|rzp)\w*|instance)\s*\.\s*orders?\s*\.\s*create\s*\("
    r"|\b\w*paystack\w*\s*\.\s*transactions?\s*\.\s*initiali[sz]e\s*\("
    r"|\b\w*mollie\w*\s*\.\s*payments\s*\.\s*create\s*\(|\bpreference\w*\s*\.\s*create\s*\("
    r"|\biyzipay\w*\s*\.\s*(?:payment|checkoutFormInitialize)\s*\.\s*create\s*\("
    r"|\bsnap\s*\.\s*createTransaction\s*\(|\bcreateCheckout\s*\(|\.requestBody\s*\(")
_GW_MONEY_KV = re.compile(
    r"""(?<![\w$])['"]?(amount|total_amount|totalAmount|unit_amount|unit_price|unitPrice|price|value|custom_price"""
    r"""|customPrice|amount_in_cents|amountInCents|amount_cents|paidPrice|paid_price|gross_amount"""
    r"""|transaction_amount)['"]?\s*(?::(?!:)|=>|=(?![=>]))\s*(?P<val>[^,\n}\]]+)""")
_GW_MONEY_APPEND = re.compile(
    r"""\.(?:append|set)\s*\(\s*['"](amount|total_amount|unit_amount|price|value|amount_in_cents)['"]\s*,"""
    r"""\s*(?P<val>[^\n]+?)\)\s*;?\s*$""", re.M)


def _gateway_calls(code: str) -> List[Tuple[int, int]]:
    """(start, end) offsets of payment-gateway calls in a file: REST calls to a
    gateway host and SDK create calls."""
    out = []
    for m in _url_calls(code, _GATEWAY_HOST_RX):
        _, end = _call_args(code, code.index("(", m.start()))
        out.append((m.start(), end))
    for m in _GATEWAY_SDK_CALL.finditer(code):
        if m.group(0).startswith(".requestBody") and "OrdersCreateRequest" not in code:
            continue
        _, end = _call_args(code, m.end() - 1)
        out.append((m.start(), end))
    return sorted(out)


def _gateway_client_amount(path: str, code: str, ctx: Any) -> List[Hit]:
    lang = _lang(path)
    if lang != "php" and ctx.is_client_file(path):
        return []
    lines = _code_lines(ctx, path)
    src = _SRC[lang]
    hits: List[Hit] = []
    done: Set[int] = set()
    for s, e in _gateway_calls(code):
        c = _line_at(code, s) - 1
        last = _line_at(code, e) - 1
        start = _func_start(lines, c, lang)
        if start in done:
            continue
        region = "\n".join(lines[start:last + 1])
        if _VARIABLE_PRICE.search(region) or _VARIABLE_PRICE.search(path):
            continue
        names = _tainted(region, lang, src, _seed_names(lines, start, lang, code))
        found = None
        for k in range(start, last + 1):
            ln = lines[k]
            for km in list(_GW_MONEY_KV.finditer(ln)) + list(_GW_MONEY_APPEND.finditer(ln)):
                if km.group(1) == "value" and "currency_code" not in "\n".join(lines[max(0, k - 2):k + 1]):
                    continue
                if _client_money(km.group("val"), names, lang, src):
                    found = k
                    break
            if found is not None:
                break
        if found is not None and not _amount_checked(region, lines[found], names, lang):
            done.add(start)
            hits.append(Hit(found + 1, lines[found].strip(),
                            "Amount sent to the payment gateway comes from the request; anyone can pay any price"))
    return hits


# A browser that writes an order row with its own total (Supabase client code).
_ORDER_INSERT = re.compile(r"""\.from\s*\(\s*['"`](\w*(?:orders?|purchases?|bookings?)\w*)['"`]\s*\)\s*"""
                           r"""\.\s*(?:insert|upsert)\s*\(""")
_ORDER_MONEY_KV = re.compile(
    r"""(?<![\w$])['"]?(total|total_price|totalPrice|total_amount|totalAmount|amount|subtotal|sub_total"""
    r"""|grand_total|grandTotal|price|unit_price|unitPrice|discount_amount|discountAmount)['"]?\s*:\s*"""
    r"""(?P<val>[^,\n}]+)""")
_CART_WORD = re.compile(r"(?i)cart|checkout")
_LITERAL_VAL = re.compile(r"""^\s*(?:-?\d[\d_.]*|null|undefined|true|false|'[^']*'|"[^"]*")\s*$""")


def _client_order_total(path: str, code: str, ctx: Any) -> List[Hit]:
    if _lang(path) != "js" or not ctx.is_client_file(path) or not (_CART_WORD.search(code) or _CART_WORD.search(path)):
        return []
    lines = _code_lines(ctx, path)
    hits: List[Hit] = []
    for m in _ORDER_INSERT.finditer(code):
        args, end = _call_args(code, m.end() - 1)
        c = _line_at(code, m.start()) - 1
        block = (_line_at(code, m.end()) - 1, _line_at(code, end) - 1)
        stripped = args.strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", stripped):
            rng = _object_lines(lines, _func_start(lines, c, "js"), c, stripped)
            if rng:
                block = rng
        for k in range(block[0], block[1] + 1):
            km = _ORDER_MONEY_KV.search(lines[k])
            if km and not _LITERAL_VAL.match(km.group("val")):
                hits.append(Hit(k + 1, lines[k].strip(),
                                "The browser sets the order total when it inserts the order row, so a user can "
                                "change it; compute the total from product prices in an RPC, trigger or Edge Function",
                                "medium"))
                break
    return hits


def _amount_checked(region: str, line: str, names: Set[str], lang: str) -> bool:
    """True when a tainted name used on line is compared for equality with a non-literal."""
    lit = r"(?:\d|['\"]|null\b|undefined\b|None\b)"
    for n in names:
        if not _name_rx(n, lang).search(line):
            continue
        e = re.escape(n)
        if re.search(r"(?<![\w$.])" + e + r"\s*(?:!==?|===?)\s*(?!" + lit + r")[\w$]", region) or \
                re.search(r"[\w$\])]\s*(?:!==?|===?)\s*" + e + r"(?![\w$])", region):
            return True
    return False


# ---------------------------------------------------------------------------
# Fulfillment on the success page, and idempotency
# ---------------------------------------------------------------------------

_SUCCESS_PATH = re.compile(r"(?i)(?:^|/)[^/]*(?:success|thank[-_]?you|thanks|payment[-_]?(?:complete|confirmed?|done)"
                           r"|order[-_]?(?:complete|confirmed?)|checkout[-_]?(?:complete|return|done))[^/]*(?:/|$)")
_SESSION_FROM_URL = re.compile(
    r"""(?:searchParams|query|args|GET|params)\s*(?:\??\.\s*get\s*\(\s*|\[\s*|\??\.\s*)['"]?session_?id\b"""
    r"""|\$request\s*->\s*(?:query|get|input)\s*\(\s*['"]session_id|\$_GET\s*\[\s*['"]session_id""")
_RETRIEVE = re.compile(r"(?i)\bsessions?\s*(?:\.|->|::)\s*retrieve\s*\(|\bSession\s*(?:\.|::)\s*retrieve\s*\(")
_PAID_CHECK = re.compile(r"payment_status|paymentStatus|\bstatus\s*[!=]==?\s*['\"](?:complete|paid)['\"]"
                         r"|['\"](?:complete|paid)['\"]\s*[!=]==?\s*[\w.]*status")
_WRITE_OP = re.compile(
    r"\.(?:update|upsert|insert|updateOne|updateMany|findOneAndUpdate|findByIdAndUpdate|setDoc|updateDoc)\s*\("
    r"|\b(?:updateDoc|setDoc)\s*\(|->\s*(?:update|save|increment|forceFill)\s*\(|::\s*(?:create|update)\s*\("
    r"|\.objects\.\w+\([^)]*\)\.update\s*\(|\.objects\.(?:create|update_or_create)\s*\(|\.save\s*\(\s*\)"
    r"|\bUPDATE\s+\w+\s+SET\b|\bINSERT\s+INTO\b|\.rpc\s*\(", re.I)
_ENTITLE = re.compile(
    r"""(?i)(?:^|[\s{,(\[.>])['"]?(?:is_?pro|is_?premium|is_?paid|is_?vip|is_?subscribed|has_?paid|has_?access"""
    r"""|premium|plan|tier|subscription_?(?:status|tier|plan)?|subscribed|credits?|credit_?balance|balance"""
    r"""|role|entitlements?|access_?level|vip|paid)['"]?\s*(?:=>|:(?!:)|\+=|=(?![=>]))"""
    r"""|\bstatus['"]?\s*(?:=>|:(?!:)|=(?![=>]))\s*['"](?:paid|active|complete|completed|succeeded)['"]""")


def check_fulfill_on_redirect(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path)
    if not (_SUCCESS_PATH.search(path) or _SESSION_FROM_URL.search(code)):
        return []
    if "webhook" in path.lower() or _file_verifies(code) or _DISPATCH.search(code):
        return []
    if _RETRIEVE.search(code) and _PAID_CHECK.search(code):
        return []
    lines = _code_lines(ctx, path)
    for i, ln in enumerate(lines):
        if not _WRITE_OP.search(ln):
            continue
        near = "\n".join(lines[max(0, i - 1):i + 5])
        if _ENTITLE.search(near):
            return [Hit(i + 1, ln.strip())]
    return []


_INC_K = r"(?:credits?|credit_?balance|balance|tokens|coins|points|quota|generations|minutes)"
_INCREMENT = re.compile(
    r"(?i)\b" + _INC_K + r"['\"]?\s*\+=|\b" + _INC_K + r"\s*:\s*\{\s*increment\b"
    r"|\bincrement\s*\(\s*['\"]" + _INC_K + r"|\b" + _INC_K + r"['\"]?\s*(?::|=)\s*[\w.\[\]'\"$>-]*" + _INC_K + r"['\"\]]?\s*\+"
    r"|\bF\(\s*['\"]" + _INC_K + r"['\"]\s*\)\s*\+|\$inc\s*:\s*\{\s*['\"]?" + _INC_K +
    r"|\.rpc\s*\(\s*['\"]\w*(?:increment|add)\w*['\"]|\bSET\s+" + _INC_K + r"\s*=\s*" + _INC_K + r"\s*\+"
    r"|FieldValue\.increment\s*\(|\b" + _INC_K + r"\s*:\s*increment\s*\(")
_DEDUPE = re.compile(
    r"(?i)\bevent\.id\b|\bevent\[\s*['\"]id['\"]\s*\]|\$event->id\b|\$event\[\s*['\"]id['\"]\s*\]|\bevent_?id\b"
    r"|processed_?events|webhook_?events|stripe_?events|\bon\s+conflict\b|onConflict|\bupsert\b|\bsetnx\b"
    r"|\bnx\s*:\s*true|['\"]NX['\"]|idempot|already\s+(?:processed|handled|fulfilled)|get_or_create"
    r"|firstOrCreate|updateOrCreate|insertOrIgnore|insert\s+ignore|ignoreDuplicates|skipDuplicates"
    r"|\bP2002\b|IntegrityError|UniqueViolation|duplicate\s+key|23505|stripe_?session_?id|stripeSessionId"
    r"|checkout_?session_?id|checkoutSessionId|payment_?intent_?id|paymentIntentId|invoice_?id|invoiceId"
    r"|charge_?id|chargeId")
_DB_UNIQUE = re.compile(r"(?is)unique[^;\n]{0,80}(?:event_?id|session_?id|payment_?intent)"
                        r"|(?:event_?id|session_?id|payment_?intent_?id)[^;\n]{0,80}(?:unique|@unique|@@unique)")


def check_webhook_no_idempotency(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path)
    if not _is_webhook_handler(code):
        return []
    m = _INCREMENT.search(code)
    if not m or _DEDUPE.search(code):
        return []
    if _project_any(ctx, "db-unique", _DB_UNIQUE, None) or ctx.memo("logic-sql-unique", lambda: any(
            _DB_UNIQUE.search(ctx.read(f)) for f in ctx.files if match_any(f, ["*.sql", "*.prisma"]))):
        return []
    n = _line_at(code, m.start())
    return [Hit(n, ctx.lines(path)[n - 1].strip())]


# ---------------------------------------------------------------------------
# Metered routes: LLM calls and message sends
# ---------------------------------------------------------------------------

_ROUTE_SIG_JS = re.compile(
    r"\b(?:app|router|server|api|fastify|routes?|r|hono)\s*\.\s*(?:post|get|put|patch|delete|all|route)\s*\(\s*['\"`/]"
    r"|^\s*export\s+(?:async\s+)?function\s+(?:POST|GET|PUT|PATCH|DELETE|handler|action|loader)\b"
    r"|^\s*export\s+const\s+(?:POST|GET|PUT|PATCH|handler|action|loader)\s*="
    r"|^\s*export\s+default\s+(?:async\s+)?function\s*\w*\s*\(\s*(?:req|request)\b"
    r"|\bmodule\.exports\s*=\s*(?:async\s*)?(?:function\s*\w*\s*)?\(\s*(?:req|request)\b"
    r"|\bDeno\.serve\s*\(|^\s*serve\s*\(\s*(?:async\b|[\w$]+\s*\))|\bexports\.handler\s*=|\bon(?:Request|Call)\s*\(", re.M)
_ROUTE_SIG_PY = re.compile(r"^\s*@[\w.]+\.(?:route|post|get|put|patch|api_route)\s*\(|@api_view|"
                           r"^\s*def\s+\w+\s*\(\s*request\b|^\s*class\s+\w+\(\s*[\w.]*(?:APIView|View|ViewSet)\b", re.M)


_SERVER_FN = re.compile(r"\bcreateServerFn\s*\(")


def _is_server_route(path: str, code: str, ctx: Any, lang: str) -> bool:
    if lang == "php":
        return True
    if lang == "js" and _SERVER_FN.search(code):
        return True
    if ctx.is_client_file(path):
        return False
    if lang == "py":
        return bool(_ROUTE_SIG_PY.search(code))
    joined = "/" + path
    name = path.rsplit("/", 1)[-1]
    if "/pages/api/" in joined or "+api." in name:
        return True
    if re.search(r"/supabase/functions/(?!_)[^/]+/index\.(?:ts|js|mjs)$", joined):
        return True
    if re.match(r"route\.(?:js|ts|mjs|jsx|tsx)$", name) and "/app/" in joined:
        return True
    if _USE_SERVER.match(code):
        return True
    return bool(_ROUTE_SIG_JS.search(code))


_LLM_HOSTS = (r"(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|openrouter\.ai"
              r"|api\.groq\.com|api\.mistral\.ai|api\.deepseek\.com|api\.x\.ai|api\.together\.xyz|api\.replicate\.com"
              r"|ai\.gateway\.lovable\.dev)")
_LLM_IMPORT = re.compile(
    r"""(?:from\s+|import\s+|require\s*\(\s*)['"](?:openai|@anthropic-ai/sdk|@google/genai|@google/generative-ai|ai"""
    r"""|@ai-sdk/[\w-]+|groq-sdk|@mistralai/mistralai|cohere-ai|replicate|together-ai|@fal-ai/[\w-]+"""
    r"""|@huggingface/inference|langchain|@langchain/[\w-]+|npm:openai[^'"]*|npm:@anthropic-ai/sdk[^'"]*"""
    r"""|https://esm\.sh/openai[^'"]*)['"]"""
    r"""|^\s*(?:from|import)\s+(?:openai|anthropic|google\.generativeai|google\.genai|google\s+import\s+genai"""
    r"""|litellm|groq|mistralai|cohere|replicate|langchain\w*|together)\b"""
    r"""|https://""" + _LLM_HOSTS + r"""|\bLOVABLE_API_KEY\b""", re.M)
_LLM_CALL = re.compile(
    r"\b(?:chat\.completions\.create|completions\.create|responses\.create|messages\.(?:create|stream)"
    r"|generateContent(?:Stream)?|generate_content|generateText|streamText|generateObject|streamObject"
    r"|images\.generate|embeddings\.create|ChatCompletion\.create|litellm\.a?completion|replicate\.run"
    r"|fal\.(?:run|subscribe)|a?invoke)\s*\("
    r"|\bfetch\s*\(\s*['\"`]https://" + _LLM_HOSTS)
_LLM_HOST_RX = re.compile(r"['\"`]https://" + _LLM_HOSTS)
_HTTP_CALL = r"(?:\bfetch|\baxios(?:\s*\.\s*(?:post|get|put|request))?|\bky(?:\s*\.\s*post)?|\$fetch|\bgot(?:\s*\.\s*post)?)\s*\(\s*"


_URL_ARG_NAME = re.compile(r"(?:`\$\{)?([\w$]+)")


def _url_consts(code: str, host_rx: "re.Pattern[str]") -> Set[str]:
    """Names of consts whose string value starts with a URL on one of the hosts."""
    out = set()
    for m in re.finditer(r"\b(?:const|let|var)\s+([\w$]+)\s*(?::[^=\n]+)?=\s*(['\"`])", code):
        if host_rx.match(code, m.end() - 1):
            out.add(m.group(1))
    return out


def _call_url_text(code: str, call: "re.Match[str]") -> str:
    """The URL text a fetch-style call uses: its literal, or the string value of
    the const it names (twilioUrl = `https://.../VerificationCheck`)."""
    p = call.end()
    if p < len(code) and code[p] in "'\"`":
        end = code.find(code[p], p + 1)
        return code[p:end + 1 if end > 0 else p + 300]
    mm = _URL_ARG_NAME.match(code, p)
    if not mm:
        return ""
    dm = None
    for dm in re.finditer(r"\b(?:const|let|var)\s+" + re.escape(mm.group(1)) + r"\s*(?::[^=\n]+)?=\s*(['\"`])",
                          code[:p]):
        pass
    if dm is None:
        return ""
    q = dm.group(1)
    s = dm.end()
    end = code.find(q, s)
    return code[s - 1:end + 1 if end > 0 else s + 300]


def _url_calls(code: str, host_rx: "re.Pattern[str]") -> List["re.Match[str]"]:
    """fetch, axios, ky or got calls whose URL is on one of the hosts: a literal,
    a const holding such a URL, or a template that starts with that const."""
    consts = _url_consts(code, host_rx)
    out = []
    for m in re.finditer(_HTTP_CALL, code):
        if host_rx.match(code, m.end()):
            out.append(m)
            continue
        mm = _URL_ARG_NAME.match(code, m.end())
        if mm and mm.group(1) in consts:
            out.append(m)
    return out


def _llm_call_in(code: str) -> Optional["re.Match[str]"]:
    """First paid LLM call in a file that imports an LLM SDK or names an LLM host."""
    if not _LLM_IMPORT.search(code):
        return None
    m = _LLM_CALL.search(code)
    calls = _url_calls(code, _LLM_HOST_RX)
    if calls and (m is None or calls[0].start() < m.start()):
        return calls[0]
    return m


_LLM_SDK_CALL = re.compile(_LLM_CALL.pattern.replace("|a?invoke)", ")"))


def _shared_client_llm_call(ctx: Any, path: str, code: str) -> Optional["re.Match[str]"]:
    """An SDK call on a client the file imports from a project module that sets
    up the LLM SDK (openai.chat.completions.create with openai from lib/openai)."""
    if _lang(path) != "js":
        return None
    m = _LLM_SDK_CALL.search(code)
    if not m:
        return None
    for _, _, target in _local_imports(ctx, path):
        if _LLM_IMPORT.search(_code(ctx, target)):
            return m
    return None


def _body_calls_llm(ctx: Any, body: str, path: str) -> bool:
    code = _code(ctx, path)
    if not ctx.memo(("logic-llm-module", path), lambda: bool(_LLM_IMPORT.search(code))):
        return False
    if _LLM_CALL.search(body) or _LLM_HOST_RX.search(body):
        return True
    consts = ctx.memo(("logic-llm-consts", path), lambda: _url_consts(code, _LLM_HOST_RX))
    return any(_name_rx(c, "js").search(body) for c in consts)


def _project_has_llm(ctx: Any) -> bool:
    return _project_any(ctx, "llm-any", _LLM_IMPORT, [JS_GLOB])


def _imported_llm_call(ctx: Any, path: str, code: str) -> Optional["re.Match[str]"]:
    """A call to a project helper (up to two imports away) that calls a paid LLM."""
    if _lang(path) != "js" or not _project_has_llm(ctx):
        return None
    for m, exported, target in _called_imports(ctx, path, code):
        if _helper_matches(ctx, target, exported, lambda b, p: _body_calls_llm(ctx, b, p), "llm", 1):
            return m
    return None


_BYOK = re.compile(r"(?i)api_?key\s*[:=]\s*(?:req|request|body|data|payload)\b|api_?key\s*[:=][^\n,]*headers")

# Auth wrappers and helpers that projects name themselves: withWorkspace(...),
# next-safe-action clients built on an auth middleware, tRPC auth procedures,
# TanStack Start server functions with an auth middleware, and helpers that
# load the signed-in user or throw.
_AUTH_WORDS = (r"\bwith(?:Auth|Session|User|Admin|Workspace|Org\w*|Team|Project|Partner\w*|Account|Tenant)\s*\("
               r"|[Aa]uth\w*ActionClient\b|\b(?:admin|authenticated|authed|private|protected)Procedure\b"
               r"|\bget(?:Server)?(?:Profile|CurrentUser|SessionUser|AuthUser|AuthedUser)\s*\("
               r"|\.middleware\s*\(\s*\[\s*\w*(?:[Aa]uth|[Ss]ession|[Uu]ser|[Pp]rotect|[Ll]ogin)\w*")
_AUTH_TELL = re.compile(
    r"\bauth\s*\(\s*\)|getServerSession|\bgetSession\s*\(|\.auth\.getUser\s*\(|\bgetUser\s*\(|\bgetClaims\s*\("
    r"|\bcurrentUser\s*\(|\brequire(?:Auth|User|Session|Login)\w*|\bwithAuth\b|\bisAuthenticated\b|\bensureAuth\w*"
    r"|\bauthenticate\w*\s*\(|\bverify(?:Token|IdToken|Jwt|JWT|Session)\b|\bjwt\.verify\b|\bjwtVerify\b"
    r"|\bgetToken\s*\(|auth\.protect\s*\(|\breq\.(?:user|auth)\b|\brequest\.(?:user|auth)\b|\bcontext\.auth\b"
    r"|\bsession\??\.user\b|\blocals\??\.user\b|login_required|permission_classes|IsAuthenticated"
    r"|Depends\s*\(\s*\w*(?:auth|user|current|token|verify|session)\w*|\bSecurity\s*\(|HTTPBearer"
    r"|headers\s*(?:\.get\s*\(\s*|\[\s*)['\"](?:authorization|x-api-key)['\"]|\bheaders\.(?:authorization|cookie)\b"
    r"|HTTP_AUTHORIZATION|bearerToken\s*\(|\b401\b|unauthori[sz]ed|Unauthori[sz]ed|\b403\b|[Ff]orbidden"
    r"|Auth::(?:check|user|id)|->middleware\s*\(\s*\[?\s*['\"]auth|auth:sanctum|\$_SESSION\s*\["
    r"|\b(?:isLoggedIn|ensureLoggedIn|checkAuth|verifyUser|authorize|authGuard|authMiddleware|requiresAuth"
    r"|protectedProcedure|bearerAuth|basicAuth|jwtAuth|jwt_required|get_jwt_identity|current_user)\b"
    r"|\bjwt\s*\(\s*\{|\bcreateHmac\b|\btimingSafeEqual\b|\bcompare_digest\b|\bverify\w*Signature\b"
    r"|" + _AUTH_WORDS)
_STRONG_AUTH = re.compile(
    r"\bauth\s*\(\s*\)|getServerSession|\.auth\.getUser\s*\(|\bgetUser\s*\(|\bgetClaims\s*\(|\bcurrentUser\s*\("
    r"|\brequire(?:Auth|User|Session|Login)\w*|\bwithAuth\b|\bensureAuth\w*|\bisAuthenticated\s*\("
    r"|\breq\.user\b|\brequest\.user\b|\breq\.session\??\.user|login_required|Depends\s*\(\s*get_current"
    r"|->middleware\s*\(\s*\[?\s*['\"]auth|auth:sanctum|\bverifyIdToken\b|\bjwt\.verify\b|\bjwtVerify\b"
    r"|\bcontext\.auth\b|\brequest\.auth\b|Auth::(?:check|user|id)|\$_SESSION\s*\[\s*['\"](?:user|uid|user_id|logged|auth)"
    r"|\b(?:isLoggedIn|ensureLoggedIn|checkAuth|authGuard|authMiddleware|requiresAuth|protectedProcedure"
    r"|bearerAuth|jwt_required|current_user)\b|" + _AUTH_WORDS)
_LIMIT_TELL = re.compile(r"(?i)rate.?limit|limiter|throttl|slowapi|\b429\b|too many requests|\bquota\b|\bcredits?\b"
                         r"|\busage\w*(?:exceeded|limit)|\bthrowif\w*exceeded"
                         r"|enforceAppCheck|appCheck|consumeAppCheckToken|RateLimiter::|arcjet|botid|\.incr\s*\(")
_CAPTCHA = re.compile(r"(?i)recaptcha|hcaptcha|turnstile|captcha|siteverify|botid|arcjet|appCheck|App Check")

_MW_FILES = ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js",
             "proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js")
_MW_AUTH = re.compile(r"clerkMiddleware|authMiddleware|withAuth|NextAuth|\bauth\s*\(|getToken|getUser|getClaims"
                      r"|updateSession|jwtVerify|verify\w*\(")
_MW_BLOCK = re.compile(r"protect\s*\(|redirect\s*\(|\b401\b|Unauthori[sz]ed|rewrite\s*\(|withAuth")
_GLOBAL_JS = re.compile(
    r"\b(?:app|server)\.use\s*\(\s*(?:['\"`][^'\"`]*['\"`]\s*,\s*)?(?:\w+\.)*(?:rateLimit|\w*[Ll]imiter|slowDown"
    r"|requireAuth|authenticate\w*|isAuthenticated|ensureAuth\w*|verifyToken|authMiddleware|requireUser|protect"
    r"|checkJwt|jwtCheck|expressjwt|clerkMiddleware|ClerkExpressRequireAuth|passport\.authenticate)\b")
_GLOBAL_PY = re.compile(r"FastAPI\s*\([^)]*dependencies|include_router\s*\([^)]*dependencies|add_middleware\s*\(\s*\w*"
                        r"(?:RateLimit|Limiter|SlowAPI)|app\.state\.limiter|Limiter\s*\([^)]*default_limits"
                        r"|DEFAULT_THROTTLE_CLASSES|DEFAULT_PERMISSION_CLASSES")
_LARAVEL_ROUTE_LIMIT = re.compile(r"throttle|RateLimiter::|auth:sanctum|->middleware\s*\(\s*\[?\s*['\"]auth")


def _next_middleware_protects(ctx: Any) -> bool:
    def scan() -> bool:
        for rel in _MW_FILES:
            t = ctx.read(rel)
            if not t or not _MW_AUTH.search(t) or not _MW_BLOCK.search(t):
                continue
            m = re.search(r"matcher\s*:", t)
            if not m:
                return True
            mt = t[m.end():m.end() + 600]
            mt = re.split(r"\n\s*\}|\}\s*;", mt, maxsplit=1)[0]
            neg = re.findall(r"\(\?!([^)]*)\)", mt)
            if any("api" in g for g in neg):
                continue
            rest = re.sub(r"\(\?!([^)]*)\)", "", mt)
            if "api" in rest or neg or ".*" in rest or ":path*" in rest:
                return True
        return False
    return ctx.memo("logic-next-mw", scan)


def _globally_protected(ctx: Any, path: str, lang: str) -> bool:
    if lang == "js":
        if ctx.has_stack("nextjs", "nextjs-app", "nextjs-pages") and _next_middleware_protects(ctx):
            joined = "/" + path
            if "/app/" in joined or "/pages/" in joined or _USE_SERVER.match(_code(ctx, path)):
                return True
        return _project_any(ctx, "global-js", _GLOBAL_JS, [JS_GLOB])
    if lang == "py":
        return _project_any(ctx, "global-py", _GLOBAL_PY, ["*.py"])
    if lang == "php" and path.startswith("app/Http/Controllers/"):
        return _project_any(ctx, "laravel-routes", _LARAVEL_ROUTE_LIMIT,
                            ["routes/*.php", "bootstrap/*.php", "app/Providers/*.php", "app/Http/Kernel.php"])
    return False


_FAILS_CLOSED = re.compile(r"\bthrow\b|\b40[13]\b|Unauthori[sz]ed|\bredirect\s*\(|\bnotFound\s*\(|\babort\s*\(")


def _imported_auth(ctx: Any, path: str, code: str) -> bool:
    """True when the route calls a project helper that checks the session and
    fails closed (getServerProfile() calling supabase.auth.getUser() and throwing)."""
    if _lang(path) != "js":
        return False
    for _, exported, target in _called_imports(ctx, path, code):
        if _helper_matches(ctx, target, exported, _auth_body, "auth", 0):
            return True
    return False


def _auth_body(body: str, path: str) -> bool:
    return bool(_AUTH_TELL.search(body) and _FAILS_CLOSED.search(body))


def check_llm_route_open(path: str, text: str, ctx: Any) -> List[Hit]:
    lang = _lang(path)
    if lang == "php":
        return []
    code = _code(ctx, path)
    if not _is_server_route(path, code, ctx, lang):
        return []
    m = _llm_call_in(code) or _shared_client_llm_call(ctx, path, code)
    msg = None
    if m is None:
        m = _imported_llm_call(ctx, path, code)
        if m is None:
            return []
        msg = ("Server route calls a project helper that calls a paid LLM API, with no auth check and no rate "
               "limit in sight")
    if _AUTH_TELL.search(code) or _LIMIT_TELL.search(code) or _BYOK.search(code):
        return []
    if _globally_protected(ctx, path, lang) or _imported_auth(ctx, path, code):
        return []
    n = _line_at(code, m.start())
    return [Hit(n, ctx.lines(path)[n - 1].strip(), msg)]


_SMS_GATE = re.compile(r"(?i)twilio|vonage|nexmo|messagebird|plivo|sinch|telnyx|textbelt|\bsns\b|SNSClient|\bsms\b")
_SMS_CALL = re.compile(r"\b(?:messages|verifications)\s*\.\s*create\s*\(|\bsns\s*\.\s*publish\s*\(|\bnew\s+PublishCommand\s*\("
                       r"|\bsms\s*\.\s*send\s*\(|\bsend_?[Ss]ms\s*\(|\bsendSMS\s*\(")
_EMAIL_CALL = re.compile(r"\b(?:emails\s*\.\s*send|sendMail|send_mail|sendEmail|send_email|sgMail\s*\.\s*send"
                         r"|mail\s*\.\s*send|mailer\s*\.\s*send|transporter\s*\.\s*sendMail)\s*\("
                         r"|\bnew\s+SendEmailCommand\s*\(|\bMail\s*::\s*to\s*\(|\bmail\s*\(")
_DEST_KV = re.compile(r"""(?<![\w$])['"]?(?:to|To|ToAddresses|PhoneNumber|phone_?number|phoneNumber|recipient|recipients"""
                      r"""|recipient_list)['"]?\s*(?::(?!:)|=>|=(?![=>]))\s*(?P<val>[^,\n}]+)""")
_DEST_SHORT = re.compile(r"(?:(?<!\$)\{|,)\s*(to|phone|phoneNumber|email)\s*(?=[,}\n])")
_DEST_APPEND = re.compile(r"""\.(?:append|set)\s*\(\s*['"](?:To|to|PhoneNumber|phone|recipient)['"]\s*,\s*(?P<val>[^)\n]+)\)""")
# Provider REST endpoints called with plain fetch (Deno, Workers, Edge Functions).
_SMS_HOST_RX = re.compile(r"['\"`]https://(?:api\.twilio\.com|verify\.twilio\.com|rest\.nexmo\.com|api\.nexmo\.com"
                          r"|api\.vonage\.com|api\.plivo\.com|api\.telnyx\.com|textbelt\.com|rest\.messagebird\.com"
                          r"|sms\.api\.sinch\.com|[\w-]+\.api\.infobip\.com)")
_EMAIL_HOST_RX = re.compile(r"['\"`]https://(?:api\.resend\.com|api\.sendgrid\.com|api\.postmarkapp\.com"
                            r"|api(?:\.eu)?\.mailgun\.net|api\.brevo\.com|api\.sendinblue\.com|send\.api\.mailtrap\.io"
                            r"|api\.mailersend\.com)")
# A user picked by an id: getUserById(x), .eq('id', x), where: { id: x }, findById(x), objects.get(id=x).
_ID_LOOKUP = re.compile(
    r"\bget(?:User|Profile|Customer|Account)ById\s*\(\s*(?P<a>[^),]+)"
    r"|\.eq\s*\(\s*['\"](?:id|user_id|userId|uid|profile_id|customer_id)['\"]\s*,\s*(?P<b>[^)]+)\)"
    r"|\bfindById\s*\(\s*(?P<c>[^),]+)|\bwhere\s*:\s*\{\s*id\s*:\s*(?P<d>[^,}]+)"
    r"|\.objects\s*\.\s*(?:get|filter)\s*\(\s*(?:id|pk|user_id)\s*=\s*(?P<e>[^,)]+)"
    r"|::(?:find|findOrFail)\s*\(\s*(?P<f>\$[^,)]+)")
_ASSIGN_BEFORE = {
    "js": re.compile(r"\b(?:const|let|var)\s*(\{[^{}]*\}|[\w$]+)\s*(?::[^=;\n]+)?=(?![=>])"),
    "py": re.compile(r"(?:^|\n)[ \t]*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*=(?!=)"),
    "php": re.compile(r"(\$\w+)\s*=(?![=>])"),
}
_NEVER = re.compile(r"(?!x)x")


def _rest_send_calls(code: str) -> List[Tuple["re.Match[str]", str]]:
    out = [(m, "sms") for m in _url_calls(code, _SMS_HOST_RX)]
    out += [(m, "email") for m in _url_calls(code, _EMAIL_HOST_RX)]
    # Checking a code the visitor typed (Twilio VerificationCheck) sends nothing.
    return [(m, k) for m, k in out if "VerificationCheck" not in _call_url_text(code, m)]


def _id_lookup_names(region: str, lang: str, names: Set[str]) -> Set[str]:
    """Names assigned from a user lookup keyed by request data."""
    out: Set[str] = set()
    rx = _ASSIGN_BEFORE[lang]
    for m in _ID_LOOKUP.finditer(region):
        arg = next(g for g in m.groups() if g is not None)
        if not _direct(arg, names, lang, _SRC[lang]):
            continue
        before = region[max(0, m.start() - 400):m.start()]
        found = list(rx.finditer(before))
        if not found:
            continue
        am = found[-1]
        tail = before[am.end():]
        if ";" in tail or (lang == "py" and "\n" in tail):
            continue
        lhs = am.group(1)
        if lhs.startswith("{"):
            out.update(_destruct_names(lhs.strip("{} ")))
        else:
            out.update(n.strip() for n in lhs.split(","))
    return out


def _destinations(call: "re.Match[str]", args: str) -> List[str]:
    name = call.group(0)
    if re.match(r"Mail\s*::\s*to|mail\s*\(", name):
        parts = _split_args(args)
        return parts[:1]
    if "send_mail" in name:
        parts = _split_args(args)
        vals = [m.group("val") for m in _DEST_KV.finditer(args)]
        return vals + (parts[3:4] if len(parts) >= 4 else [])
    vals = [m.group("val") for m in _DEST_KV.finditer(args)]
    vals += [m.group(1) for m in _DEST_SHORT.finditer(args)]
    return vals


_BODY_KEY = re.compile(r"""(?<![\w$])['"]?(?:html|text|content|htmlContent|textContent|HtmlBody|TextBody)['"]?\s*:\s*""")


def _template_has_taint(expr: str, names: Set[str], src: "re.Pattern[str]") -> bool:
    """True when a JS template literal interpolates request data without a call
    around it (`${name}` yes, `${escapeHtml(name)}` no)."""
    expr = expr.strip()
    if not expr.startswith("`"):
        return False
    i = expr.find("${")
    while i >= 0:
        end = _balanced_end(expr, i + 1, 20000)
        if _direct(expr[i + 2:end - 1], names, "js", src):
            return True
        i = expr.find("${", end)
    return False


def _body_has_request_text(code: str, call_end: int, args: str, names: Set[str]) -> bool:
    """The html or text of an email send carries request data unescaped."""
    src = _SRC["js"]
    for km in _BODY_KEY.finditer(args):
        val = _value_at(args, km.end())
        if _template_has_taint(val, names, src):
            return True
        if re.fullmatch(r"[A-Za-z_$][\w$]*", val):
            decl = None
            for decl in re.finditer(r"\b(?:const|let|var)\s+" + re.escape(val) + r"\s*(?::[^=\n]+)?=\s*",
                                    code[:call_end]):
                pass
            if decl and _template_has_taint(_value_at(code, decl.end()), names, src):
                return True
    return False


def check_send_no_throttle(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path)
    lang = _lang(path)
    sms_file = bool(_SMS_GATE.search(code))
    calls = []
    if sms_file:
        calls += [(m, "sms") for m in _SMS_CALL.finditer(code)]
    calls += [(m, "email") for m in _EMAIL_CALL.finditer(code)]
    rest = _rest_send_calls(code) if lang == "js" else []
    calls += rest
    if not calls or not _is_server_route(path, code, ctx, lang):
        return []
    if _STRONG_AUTH.search(code) or _LIMIT_TELL.search(code) or _CAPTCHA.search(code):
        return []
    if _globally_protected(ctx, path, lang) or _imported_auth(ctx, path, code):
        return []
    weak_auth = bool(_AUTH_TELL.search(code))
    lines = _code_lines(ctx, path)
    src = _SRC[lang]
    hits: List[Hit] = []
    rest_ids = {id(m) for m, _ in rest}
    for m, kind in sorted(calls, key=lambda t: t[0].start()):
        if id(m) in rest_ids:
            args, _ = _call_args(code, code.index("(", m.start()))
        else:
            args, _ = _call_args(code, m.end() - 1)
        if re.search(r"\bmodel\s*[:=]", args):
            continue
        c = _line_at(code, m.start()) - 1
        start = _func_start(lines, c, lang)
        region = "\n".join(lines[start:c + 1])
        names = _tainted(region, lang, src, _seed_names(lines, start, lang, code))
        dests = _destinations(m, args)
        if id(m) in rest_ids:
            dests += [d.group("val") for d in _DEST_KV.finditer(region)]
            dests += [d.group("val") for d in _DEST_APPEND.finditer(region)]
        relay = kind == "email" and lang == "js" and _body_has_request_text(code, m.start(), args, names)
        extra = ("; its HTML or text also carries request data unescaped, so anyone can send phishing in your "
                 "name" if relay else "")
        if any(_direct(d, names, lang, src) for d in dests):
            if kind == "sms":
                hits.append(Hit(c + 1, lines[c].strip(), "Sends an SMS or OTP to a number from the request with no "
                                                         "rate limit or CAPTCHA (SMS pumping)", "high"))
            else:
                hits.append(Hit(c + 1, lines[c].strip(), "Sends email to an address from the request with no rate "
                                                         "limit or CAPTCHA (email bombing, quota burn)" + extra,
                                "medium"))
            break
        if weak_auth:
            continue
        looked_up = _id_lookup_names(region, lang, names)
        if looked_up:
            derived = _tainted(region, lang, _NEVER, looked_up)
            if any(_direct(d, derived, lang, _NEVER) for d in dests):
                hits.append(Hit(c + 1, lines[c].strip(), "Sends a message to a user picked by an id from the request, "
                                                         "with no auth check: anyone can make the app message any "
                                                         "user" + extra, "medium"))
                break
    return hits


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

_WEBHOOKISH = re.compile(r"(?i)web_?hook|hook|stripe|paddle|cashier|pay|ipn|callback|notify|lemon|mollie|razorpay"
                         r"|iyzico|shopier|gateway|coinbase|twilio|github|slack|telegram|discord|sns|inbound|saml"
                         r"|\bacs\b|sso|oauth|openid|apple")
_CSRF_EXEMPT = re.compile(r"^\s*@(?:csrf_exempt|csrf\.exempt)\b")
_CSRF_USES_SESSION = re.compile(r"\brequest\.(?:user|session)\b|\bcurrent_user\b|\bsession\s*\[|login_required"
                                r"|permission_required|is_authenticated")
_HEADER_AUTH = re.compile(r"(?i)HTTP_AUTHORIZATION|headers\.get\(\s*['\"]authorization|\bBearer\b|request\.auth\b"
                          r"|TokenAuthentication|JWTAuthentication|authentication_classes")


def _laravel_except_hits(code: str, open_idx: int, lines: Sequence[str]) -> List[Hit]:
    """Entries of a CSRF except list starting at the "[" at open_idx."""
    hits = []
    end = _balanced_end(code, open_idx)
    for sm in re.finditer(r"['\"]([^'\"\n]+)['\"]", code[open_idx:end]):
        v = sm.group(1).strip()
        n = _line_at(code, open_idx + sm.start())
        ev = lines[n - 1].strip()
        if v in ("*", "/*"):
            hits.append(Hit(n, ev, "CSRF verification is switched off for every route", "high"))
        elif not _WEBHOOKISH.search(v) and not v.startswith(("api/", "/api/")):
            hits.append(Hit(n, ev, "Route excluded from CSRF verification is not a webhook"))
    return hits


def _in_test_config_class(lines: Sequence[str], i: int) -> bool:
    ind = _indent(lines[i])
    if ind == 0:
        return False
    for k in range(i - 1, max(-1, i - 60), -1):
        m = re.match(r"(\s*)class\s+(\w+)", lines[k])
        if m and len(m.group(1)) < ind:
            return bool(re.search(r"(?i)test|dev|local|debug", m.group(2)))
    return False


def check_csrf_disabled(path: str, text: str, ctx: Any) -> List[Hit]:
    lines = _code_lines(ctx, path)
    code = _code(ctx, path)
    lang = _lang(path)
    hits: List[Hit] = []
    if lang == "py":
        for i, ln in enumerate(lines):
            if _CSRF_EXEMPT.match(ln):
                j = next((k for k in range(i + 1, min(len(lines), i + 6)) if re.match(r"\s*(?:async\s+)?def\s", lines[k])), None)
                if j is None:
                    continue
                head = "\n".join(lines[i:j + 1])
                if _WEBHOOKISH.search(head) or "api_view" in head:
                    continue
                ind = _indent(lines[j])
                body = []
                for ln2 in lines[j + 1:j + 80]:
                    if ln2.strip() and _indent(ln2) <= ind:
                        break
                    body.append(ln2)
                body_text = head + "\n" + "\n".join(body)
                if not _CSRF_USES_SESSION.search(body_text) or _HEADER_AUTH.search(body_text):
                    continue
                hits.append(Hit(i + 1, ln.strip(), "CSRF check is turned off on a view that acts as the logged-in user"))
            if re.match(r"\s*(?:app\.config\[\s*['\"])?WTF_CSRF_ENABLED['\"]?\s*\]?\s*=\s*False\b", ln) \
                    and not _in_test_config_class(lines, i):
                hits.append(Hit(i + 1, ln.strip(), "Flask-WTF CSRF protection is disabled"))
        m = re.search(r"^MIDDLEWARE\s*=\s*[\[(]", code, re.M)
        if m and ctx.has_stack("django"):
            end = _balanced_end(code, code.index(m.group(0)[-1], m.start()))
            block = code[m.start():end]
            if "SessionMiddleware" in block and "CsrfViewMiddleware" not in block:
                hits.append(Hit(_line_at(code, m.start()), lines[_line_at(code, m.start()) - 1].strip(),
                                "CsrfViewMiddleware is missing from MIDDLEWARE while sessions are on"))
    elif lang == "php":
        for m in re.finditer(r"protected\s+\$except\s*=\s*(\[)|validateCsrfTokens\s*\(\s*except\s*:\s*(\[)", code):
            if m.group(1) and "Csrf" not in code:
                continue
            hits.extend(_laravel_except_hits(code, m.start(1) if m.group(1) else m.start(2), lines))
        for i, ln in enumerate(lines):
            if re.search(r"\bremove\s*[:(]", ln) and re.search(r"(?:VerifyCsrfToken|ValidateCsrfToken)", ln):
                hits.append(Hit(i + 1, ln.strip(), "The CSRF middleware is removed from the web group"))
    return hits


_CSRF_DEFENSE = re.compile(r"(?i)csrf|xsrf|lusca|sec-fetch-site|headers\.origin|get\(\s*['\"]origin['\"]"
                           r"|headers\[\s*['\"]origin['\"]\s*\]|sameSite\s*:\s*(?:['\"](?:strict|lax)['\"]|true)")
_STATE_ROUTE = re.compile(r"\b(?:app|router)\.(?:post|put|patch|delete)\s*\(\s*['\"`]([^'\"`]*)")
_SESSION_GUARD = re.compile(r",\s*(?:[\w$]+\s*\.\s*)?(?:isLoggedIn|isLoggedin|ensureLoggedIn|ensureAuthenticated|"
                            r"isAuthenticated)\b")


def check_csrf_session_no_token(path: str, text: str, ctx: Any) -> List[Hit]:
    if not ("express-session" in ctx.deps or "cookie-session" in ctx.deps):
        return []
    # a csrf package only counts once code calls it: NodeGoat lists csurf but leaves app.use(csrf()) commented out
    if _project_any(ctx, "csrf-defense", _CSRF_DEFENSE, [JS_GLOB]):
        return []
    if ctx.is_client_file(path):
        return []
    lines = _code_lines(ctx, path)
    hits: List[Hit] = []
    for i, ln in enumerate(lines):
        m = _STATE_ROUTE.search(ln)
        if not m or _WEBHOOKISH.search(m.group(1)):
            continue
        window = "\n".join(lines[i:i + 20])
        # a session-login guard named on the route line (app.post('/x', isLoggedIn, handler)) counts too
        if (re.search(r"\breq\.(?:session|user)\b|req\.isAuthenticated\s*\(", window) or _SESSION_GUARD.search(ln)) and \
                not re.search(r"(?i)headers\.authorization|get\(\s*['\"]authorization", window):
            hits.append(Hit(i + 1, ln.strip()))
    return hits


# ---------------------------------------------------------------------------
# Open redirects
# ---------------------------------------------------------------------------

_RP_BASE = (r"next|redirect(?:_?to|_?url|_?uri)?|redirectTo|redirectUrl|redirectUri|return(?:_?to|_?url|_?path)?"
            r"|returnTo|returnUrl|returnPath|callback_?url|callbackUrl|continue|goto|dest(?:ination)?"
            r"|target_?url|targetUrl|forward")
# url, to and back are too generic for a bare .get('...'): they only count when
# read from a request container (req.query.to, searchParams.get('to'), $_GET['to']).
_RP = r"(?:" + _RP_BASE + r"|url|to|back)"
_RP_NOURL = r"(?:" + _RP_BASE + r")"
_RP_SRC = re.compile(
    r"""(?<![\w$])(?:searchParams|query|args|GET|POST|query_params|params|values|form)\s*\??\.\s*get\s*\(\s*['"]""" + _RP + r"""['"]"""
    r"""|\.get\s*\(\s*['"]""" + _RP_NOURL + r"""['"]"""
    r"""|(?<![\w$])(?:searchParams|query|args|GET|params)\s*(?:\??\.\s*|\[\s*['"])""" + _RP + r"""\b"""
    r"""|\breq\s*\.\s*(?:query|body)\s*(?:\??\.\s*|\[\s*['"])""" + _RP + r"""\b"""
    r"""|\$request\s*->\s*(?:query|input|get|post)\s*\(\s*['"]""" + _RP + r"""['"]"""
    r"""|\$_(?:GET|POST|REQUEST)\s*\[\s*['"]""" + _RP + r"""['"]|\brequest\s*\(\s*['"]""" + _RP + r"""['"]""")
_SINK = re.compile(
    r"\b(?:res|response|reply|ctx)\s*\.\s*redirect\s*\(|\bNextResponse\s*\.\s*redirect\s*\(|\bResponse\s*\.\s*redirect\s*\("
    r"|\bredirect\s*\(\s*\)\s*->\s*(?:to|away)\s*\(|\bRedirect\s*::\s*(?:to|away)\s*\(|\bheader\s*\(\s*['\"](?i:location)\s*:"
    r"|(?<![\w.$>])redirect\s*\(|\brouter\s*\.\s*(?:push|replace)\s*\(|(?<![\w.$])navigate\s*\("
    r"|\blocation\s*\.\s*(?:assign|replace)\s*\(|\b(?:HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse)\s*\(")
_ASSIGN_SINK = re.compile(r"\b(?:window|document)\.location(?:\.href)?\s*=(?!=)\s*([^;\n]+)|\blocation\.href\s*=(?!=)\s*([^;\n]+)")
_LOC_HEADER = re.compile(r"\bLocation['\"]?\s*:\s*([^,}\n]+)")

_STRONG_GUARD = {
    "js": re.compile(r"""\.origin\s*[!=]==?|[!=]==?\s*[\w.]*\.origin\b"""
                     r"""|\.host(?:name)?\s*[!=]==?|[!=]==?\s*[\w.]*\.host(?:name)?\b"""
                     r"""|\b\w*(?:[Ss]afe|[Vv]alid|[Aa]llowed|[Rr]elative|[Ll]ocal|[Ii]nternal|[Ss]ame[Oo]rigin)\w*"""
                     r"""(?:Redirect|Url|URL|Next|Path|Return|Target|Dest)\w*\s*\(|\bsafe(?:Next|Redirect|Url|Path)\s*\("""
                     r"""|\b(?:ALLOWED|allowed|ALLOW|allow|SAFE|safe|whitelist|allowlist)\w*\s*\.\s*(?:includes|has|indexOf)\s*\("""),
    "py": re.compile(r"""url_has_allowed_host_and_scheme|is_safe_url"""
                     r"""|\b_?(?:is_safe|is_valid|is_allowed|is_relative|is_local|safe)_\w*\s*\("""
                     r"""|\b_?\w*(?:allow|safe|valid|permit)\w*_(?:redirect|url|next|path|target|dest)\w*\s*\("""
                     r"""|\bin\s+[A-Z_]{4,}\b"""),
    "php": re.compile(r"""preg_match\s*\(|in_array\s*\(|->intended\s*\(|\b\w*(?:[Ss]afe|[Vv]alid|[Aa]llowed)\w*\s*\("""),
}
# Checks that stop //host but not, on their own, /\host or a tab or newline
# inside the value (browsers read both as another host). They count as a full
# guard only next to a backslash check.
_SLASH2_GUARD = {
    "js": re.compile(r"""startsWith\s*\(\s*['"`]//|\^\\?/(?:\(\?!|\[\^)|(?:\[\s*1\s*\]|charAt\s*\(\s*1\s*\))\s*[!=]==?\s*['"`]/"""),
    "py": re.compile(r"""startswith\s*\(\s*\(?\s*['"]//|\.netloc\b|\[\s*1\s*\]\s*(?:[!=]=|(?:not\s+)?in)\s*['"(]"""),
    "php": re.compile(r"""parse_url\s*\(|str_starts_with\s*\([^,]+,\s*['"]//|Str::startsWith\s*\([^,]+,\s*['"]//"""
                      r"""|substr\s*\([^;]*?,\s*0\s*,\s*2\s*\)\s*[!=]==?\s*['"]//"""),
}
_BACKSLASH_CHECK = re.compile(r"\\\\|\\x5[cC]|%5[cC]")
_IF_COND = re.compile(r"^\s*(?:\}\s*)?(?:else\s+)?(?:el)?if\b(.*)$")
_VALIDATOR_NAME = r"[\w.$>-]*(?:[Aa]llow|[Ss]afe|[Vv]alid|[Pp]ermit|[Tt]rust|[Ll]ocal|[Rr]elative|[Ii]nternal|[Ss]ame)\w*"
_SUBSTR_HELPER = re.compile(
    r"\w*(?:[Rr]edirect|[Uu]rl|URL|[Nn]ext|[Rr]eturn)\w*(?:[Aa]llow|[Ss]afe|[Vv]alid|[Tt]rust|[Ww]hitelist)\w*"
    r"|\w*(?:[Aa]llow|[Ss]afe|[Vv]alid|[Tt]rust|[Ww]hitelist)\w*(?:[Rr]edirect|[Uu]rl|URL|[Nn]ext|[Rr]eturn)\w*")
_PARSES_URL = re.compile(r"new\s+URL\s*\(|URL\.parse|url\.parse|urlparse|urlsplit|parse_url|\.origin\b|\.host(?:name)?\b|netloc")
_WEAK_GUARD = re.compile(r"""\.starts[Ww]ith\s*\(\s*['"`]/['"`]\s*\)|str_starts_with\s*\([^,]+,\s*['"]/['"]\s*\)"""
                         r"""|\[\s*0\s*\]\s*[!=]==?\s*['"]/['"]|charAt\s*\(\s*0\s*\)\s*[!=]==?\s*['"]/['"]|\^\\?/""")
_NOT_IDENT = frozenset({"new", "URL", "String", "f", "decodeURIComponent", "decodeURI", "await", "return", "unquote",
                        "Location", "urldecode", "trim", "str"})


def _prefix_kind(prefix: str, header_sink: bool) -> str:
    """none (param is the whole target), path (a fixed path comes first), host
    (an origin or variable comes first) or query (the param is a query value)."""
    lits: List[str] = []
    code: List[str] = []
    i, n = 0, len(prefix)
    while i < n:
        c = prefix[i]
        if c in "'\"`":
            fstr = c != "`" and i > 0 and prefix[i - 1] == "f"
            j = i + 1
            buf = []
            while j < n and prefix[j] != c:
                if c == "`" and prefix.startswith("${", j):
                    k = prefix.find("}", j)
                    k = n if k == -1 else k
                    code.append(prefix[j + 2:k])
                    j = k + 1
                    continue
                if fstr and prefix[j] == "{":
                    k = prefix.find("}", j)
                    k = n if k == -1 else k
                    code.append(prefix[j + 1:k])
                    j = k + 1
                    continue
                buf.append(prefix[j])
                j += 1
            lits.append("".join(buf))
            i = j + 1
        else:
            code.append(c)
            i += 1
    lit = "".join(lits)
    if header_sink:
        lit = re.sub(r"(?i)\s*location\s*:\s*", "", lit, count=1)
    code_text = "".join(code)
    if re.search(r"[?&=#]", lit) or re.search(r"encodeURIComponent|urlencode|quote\s*\(|URLSearchParams", prefix):
        return "query"
    idents = [w for w in re.findall(r"\$?[A-Za-z_][\w$]*", code_text) if w not in _NOT_IDENT]
    lit = lit.strip()
    if idents:
        return "host"
    if lit in ("", "/"):
        return "none"
    if lit.startswith("/"):
        return "path"
    return "host"


def _sink_args(code: str, m: "re.Match[str]") -> Tuple[str, bool]:
    s = m.group(0)
    if re.match(r"header\s*\(", s):
        args, _ = _call_args(code, m.start() + s.index("("))
        return args, True
    if s.rstrip().endswith("("):
        args, _ = _call_args(code, m.end() - 1)
        return args, False
    return "", False


def _chain_start(expr: str, i: int) -> int:
    """Walk back from i to the start of the member chain (req.query.next -> req)."""
    while i > 0:
        if expr[i - 1] in "$_." or expr[i - 1].isalnum():
            i -= 1
        elif expr[i - 2:i] in ("->", "?."):
            i -= 2
        else:
            break
    return i


def _first_taint_index(expr: str, names: Set[str], lang: str) -> int:
    best = -1
    for rx in [_RP_SRC] + [_name_rx(nm, lang) for nm in names]:
        mm = rx.search(expr)
        if mm:
            st = _chain_start(expr, mm.start())
            if best < 0 or st < best:
                best = st
    return best


def _split_top(expr: str, ops: Sequence[str]) -> List[str]:
    """Split expr on top-level operators (outside brackets and strings)."""
    out, depth, quote, last, i = [], 0, "", 0, 0
    n = len(expr)
    while i < n:
        c = expr[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            op = next((o for o in ops if expr.startswith(o, i)), None)
            if op:
                out.append(expr[last:i])
                i += len(op)
                last = i
                continue
        i += 1
    out.append(expr[last:])
    return [p for p in (x.strip() for x in out) if p]


def _alternatives(expr: str, lang: str) -> List[str]:
    """The values a redirect target can take: the branches of a conditional and
    the operands of ||, ??, ?: and or."""
    ops = {"js": ("||", "??"), "py": (" or ",), "php": ("||", "??", "?:", " or ")}[lang]
    if lang != "php" or "?:" not in expr:
        br = _ternary_branches(expr, lang)
        if br:
            return [a for b in br for a in _alternatives(b, lang)]
    parts = _split_top(expr, ops)
    if len(parts) > 1:
        return [a for p in parts for a in _alternatives(p, lang)]
    return [expr.strip()]


def _guarded_by_call(region: str, names: Set[str]) -> bool:
    """An if condition passes the value to a function: first term of any call,
    or any conjunct when the function name reads like a validator."""
    for nm in names:
        e = re.escape(nm)
        if re.search(r"\bif\s*\(?\s*!?\s*(?:not\s+)?[\w.$>-]+\s*\(\s*" + e + r"\s*\)", region):
            return True
        for ln in region.split("\n"):
            m = _IF_COND.match(ln)
            if m and re.search(r"(?<![\w$])" + _VALIDATOR_NAME + r"\s*\(\s*" + e + r"\s*[,)]", m.group(1)):
                return True
    return False


def _substring_allowlist_hits(path: str, ctx: Any, lang: str) -> List[Hit]:
    """Redirect allowlist helpers that accept any URL containing an allowed value."""
    code = _code(ctx, path)
    if not _SUBSTR_HELPER.search(code):
        return []
    lines = _code_lines(ctx, path)
    funcs: List[Tuple[str, str, int]] = []
    if lang == "js":
        for m in re.finditer(r"(?:\bfunction\s+|\b(?:const|let|var)\s+)(" + _SUBSTR_HELPER.pattern + r")\s*"
                             r"(?:=\s*(?:async\s+)?(?:function\s*)?)?\(\s*([\w$]+)", code):
            body = _func_bodies(ctx, path).get(m.group(1), "")
            if body:
                funcs.append((m.group(2), body, code.find(body, m.end())))
    elif lang == "py":
        for i, ln in enumerate(lines):
            m = re.match(r"(\s*)def\s+(" + _SUBSTR_HELPER.pattern + r")\s*\(\s*(?:self\s*,\s*)?(\w+)", ln)
            if not m:
                continue
            body = []
            for ln2 in lines[i + 1:i + 60]:
                if ln2.strip() and _indent(ln2) <= len(m.group(1)):
                    break
                body.append(ln2)
            text = "\n".join(body)
            funcs.append((m.group(3), text, code.find(text) if text else -1))
    hits = []
    for param, body, off in funcs:
        if off < 0 or _PARSES_URL.search(body):
            continue
        e = re.escape(param)
        m = re.search(r"(?<![\w$.])" + e + r"\s*\.\s*(?:includes|indexOf|search|match)\s*\(", body) or \
            re.search(r"\bin\s+" + e + r"\b(?!\s*\()|(?<![\w$.])" + e + r"\s*\.\s*find\s*\(", body)
        if m:
            n = _line_at(code, off + m.start())
            hits.append(Hit(n, ctx.lines(path)[n - 1].strip(),
                            "Redirect allowlist matches by substring, so any URL that merely contains an allowed "
                            "value passes; parse the URL and compare its origin or host"))
    return hits


def check_open_redirect(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path)
    lang = _lang(path)
    hits: List[Hit] = [] if lang == "php" else _substring_allowlist_hits(path, ctx, lang)
    if not _RP_SRC.search(code):
        return hits
    lines = _code_lines(ctx, path)
    seen: Set[int] = {h.line - 1 for h in hits}
    sinks: List[Tuple[int, str, bool]] = []
    for m in _SINK.finditer(code):
        args, header = _sink_args(code, m)
        sinks.append((m.start(), args, header))
    if lang == "js":
        for m in _ASSIGN_SINK.finditer(code):
            sinks.append((m.start(), m.group(1) or m.group(2), False))
        for m in _LOC_HEADER.finditer(code):
            sinks.append((m.start(), m.group(1), False))
    for off, args, header in sinks:
        k = _line_at(code, off) - 1
        if k in seen or not args:
            continue
        start = _func_start(lines, k, lang)
        region = "\n".join(lines[start:k + 1])
        names = _tainted(region, lang, _RP_SRC)
        parts = _split_args(args) if not header else [args]
        target = next((p for p in parts if _direct(p, names, lang, _RP_SRC)), None)
        if target is None:
            continue
        if _STRONG_GUARD[lang].search(region) or _guarded_by_call(region, names):
            continue
        partial = bool(_SLASH2_GUARD[lang].search(region))
        if partial and _BACKSLASH_CHECK.search(region):
            continue
        kinds = set()
        for alt in _alternatives(target, lang):
            if not _direct(alt, names, lang, _RP_SRC):
                continue
            idx = _first_taint_index(alt, names, lang)
            kinds.add(_prefix_kind(alt[:idx] if idx > 0 else "", header))
        kinds -= {"query", "path"}
        if not kinds:
            continue
        kind = "none" if "none" in kinds else "host"
        weak = bool(_WEAK_GUARD.search(region))
        if kind == "host" and (weak or partial):
            continue
        seen.add(k)
        if partial:
            msg = ("Redirect target from a request parameter is checked for // but not for a backslash or a tab "
                   "or newline (/\\host), which browsers also read as another host")
        elif weak:
            msg = ("Redirect target from a request parameter is only checked with startsWith('/'), "
                   "which still lets //other-host through")
        elif kind == "host":
            msg = ("Request parameter is appended to the origin without checking it starts with a single /; "
                   "values like .evil.example or @evil.example leave the site")
        else:
            msg = None
        hits.append(Hit(k + 1, ctx.lines(path)[k].strip(), msg))
    return hits


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULES: List[Rule] = [
    Rule(
        id="pay-webhook-unverified",
        skill=SKILL,
        klass="payment webhook signature not verified",
        severity="critical",
        stacks=["*"],
        file_globs=CODE_GLOBS,
        exclude_globs=NOT_PROD,
        check=check_webhook_unverified,
        message="Stripe webhook handler acts on events but nothing in the project verifies the Stripe signature",
        why=("Agents wire the webhook route straight to the event switch, or copy the branch of Stripe's sample "
             "that deserializes the body when no secret is set. Anyone who knows the URL can then post a fake "
             "checkout.session.completed and get credited. With other gateways the same happens in the IPN or "
             "return handler that trusts the posted status."),
        fp_trap=("Verification can live in a helper in another file (the scanner already skips this when any "
                 "production file calls constructEvent or verify_header), in Laravel Cashier's controller or "
                 "dj-stripe, or in an API gateway. Confirm the route that receives Stripe's POST actually checks "
                 "the Stripe-Signature header before reporting. Other gateways (SSLCommerz, Razorpay, Paystack and "
                 "the like): a callback that marks an order paid is reported when it neither checks a signature nor "
                 "asks the gateway, and at medium when it asks the gateway but never compares the returned amount "
                 "and order id with the stored order. A status copied from the posted data into an order update "
                 "(the FAILED or CANCELLED branch) is reported at medium when no signature is checked. Safe: the "
                 "order is looked up from the gateway's own response, or the amount and id are compared somewhere "
                 "the scanner did not see."),
        fix_ref=REF + "#webhook-signature",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="pay-webhook-verify-optional",
        skill=SKILL,
        klass="payment webhook verification can be skipped",
        severity="critical",
        stacks=["*"],
        file_globs=CODE_GLOBS,
        exclude_globs=NOT_PROD,
        check=check_webhook_verify_optional,
        message="Stripe signature check only runs when the webhook secret is set, or its failure is ignored",
        why=("Stripe's quickstart wraps constructEvent in if (endpointSecret) and falls back to the parsed body. "
             "Agents copy it and never set STRIPE_WEBHOOK_SECRET in production, so forged events are accepted. "
             "Several 2026 CVEs are this exact guard."),
        fp_trap=("Safe: if (!secret) return a 500 before verifying, or an else branch that fails closed. Also safe: "
                 "a try/catch whose catch returns 400. The rule only fires when the handler also assigns the event "
                 "from the raw or parsed body, so check that this fallback really reaches the fulfillment code. "
                 "It also reports an HMAC signature check (Razorpay, Paystack, a webhook) whose key is "
                 "env || '' with no empty-key check; a startup check elsewhere that refuses to boot without the "
                 "variable makes that safe."),
        fix_ref=REF + "#webhook-signature",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="pay-webhook-parsed-body",
        skill=SKILL,
        klass="webhook body parsed before verification",
        severity="medium",
        stacks=["*"],
        file_globs=CODE_GLOBS,
        exclude_globs=NOT_PROD,
        check=check_webhook_parsed_body,
        message="Stripe webhook verifies a parsed or re-serialized body instead of the raw request bytes",
        why=("Stripe signs the exact raw body. Agents call await req.json(), mount express.json() first, or "
             "pass JSON.stringify(req.body). Verification then always fails, and the next agent edit tends to "
             "remove the check to make webhooks work."),
        fp_trap=("Safe: App Router await req.text(), express.raw() on the webhook route (or express.json() mounted "
                 "after it, or with a verify callback that keeps rawBody), Pages Router with bodyParser: false, "
                 "Flask request.data, FastAPI await request.body(), Django request.body."),
        fix_ref=REF + "#raw-body",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="pay-client-amount",
        skill=SKILL,
        klass="client-controlled price",
        severity="high",
        stacks=["*"],
        file_globs=CODE_GLOBS,
        exclude_globs=NOT_PROD,
        check=check_client_amount,
        message="Payment amount for a Stripe PaymentIntent, Checkout line item or charge comes from the request",
        why=("The shortest path from a cart to Stripe, Razorpay, SSLCommerz or any other gateway is to pass the "
             "cart's amount or item prices to the create call, or to let the browser insert the order row with "
             "its own total. An attacker edits the request and pays one cent for a real product."),
        fp_trap=("Safe: the client sends a plan or product id and the server looks the price up in its own "
                 "catalog or DB (PRICES[plan], product.price), or computes the total from ids "
                 "(calculateOrderAmount(items)). Quantity from the client is fine with server prices. Donations, "
                 "tips and top-ups are meant to be variable; the scanner skips files that say so, check others "
                 "for a server-side min and max. A browser order insert (medium) is safe when a trigger or RPC "
                 "recomputes the total from product prices before anything is charged or shipped."),
        fix_ref=REF + "#server-side-prices",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="pay-fulfill-on-redirect",
        skill=SKILL,
        klass="fulfillment on the success page",
        severity="high",
        stacks=["*"],
        file_globs=CODE_GLOBS,
        exclude_globs=NOT_PROD,
        check=check_fulfill_on_redirect,
        message="Checkout success page grants a plan, credits or access without confirming the payment with Stripe",
        why=("Agents put the 'give the user Pro' write where the browser lands after checkout. Anyone can open "
             "the success URL without paying, and customers whose browser never returns are never served."),
        fp_trap=("Safe: the page only shows status, or calls a shared fulfill function that retrieves the Checkout "
                 "Session and checks payment_status (the scanner skips files that do both). The webhook should "
                 "still be the main path."),
        fix_ref=REF + "#fulfill-from-the-webhook",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="pay-webhook-no-idempotency",
        skill=SKILL,
        klass="webhook not idempotent",
        severity="medium",
        stacks=["*"],
        file_globs=CODE_GLOBS,
        exclude_globs=NOT_PROD,
        check=check_webhook_no_idempotency,
        message="Stripe webhook adds credits or balance with no check that the event was already processed",
        why=("Stripe delivers events at least once and may retry or send them out of order. A handler that does "
             "credits += N on every delivery double-credits users."),
        fp_trap=("Idempotency can live elsewhere: a unique constraint on the event or session id in a migration, "
                 "an upsert, or a queue that dedupes. The scanner skips files that mention event.id, ON CONFLICT, "
                 "upsert or a stored session id, and projects with such a unique index in SQL or Prisma."),
        fix_ref=REF + "#idempotent-fulfillment",
        confidence="low",
        needs_confirmation=True,
    ),
    Rule(
        id="abuse-llm-route-open",
        skill=SKILL,
        klass="denial of wallet",
        severity="high",
        stacks=["*"],
        file_globs=[JS_GLOB, "*.py"],
        exclude_globs=NOT_PROD,
        check=check_llm_route_open,
        message="Server route calls a paid LLM API with no auth check and no rate limit in sight",
        why=("Agents build /api/chat as a thin proxy because the demo works without login or limits. Anyone who "
             "finds the endpoint can run up the provider bill or resell access."),
        fp_trap=("Auth or limits may be global: Next.js middleware or proxy whose matcher covers the route, an "
                 "app.use() limiter or auth in the Express entry file, FastAPI router dependencies, an API gateway. "
                 "They may also sit in a wrapper or helper: withWorkspace(...), an auth action client, a project "
                 "helper that loads the user and throws. The scanner skips the common forms and follows the "
                 "route's own imports one level for auth and two levels for the LLM call; confirm the route "
                 "really answers a logged-out request. Local-only models are not metered."),
        fix_ref=REF + "#metered-and-llm-routes",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="abuse-send-no-throttle",
        skill=SKILL,
        klass="SMS or email pumping",
        severity="high",
        stacks=["*"],
        file_globs=CODE_GLOBS,
        exclude_globs=NOT_PROD,
        check=check_send_no_throttle,
        message="Endpoint sends an SMS, OTP or email to a destination from the request with no rate limit or CAPTCHA",
        why=("Agents wire 'send code' or 'verify email' straight to Twilio or the mailer. Fraudsters use the "
             "form to send messages to premium number ranges (SMS pumping) or to flood inboxes and burn quota."),
        fp_trap=("Sends behind login, sends to an address loaded from your own DB by the email the visitor typed "
                 "(password reset for a known user), and sends to a fixed admin address are lower risk and not "
                 "flagged. A send to a user looked up by an id from the request is flagged at medium when the route "
                 "has no auth check at all; a shared-secret header from a DB webhook makes it safe. The message says "
                 "when the email body also carries request text without escaping. Limits can also "
                 "be global middleware or the provider's fraud guard (Twilio Verify Fraud Guard, Supabase Auth's "
                 "built-in limits); check those before reporting."),
        fix_ref=REF + "#otp-sms-and-email-sends",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="csrf-csurf-deprecated",
        skill=SKILL,
        klass="deprecated CSRF package",
        severity="low",
        stacks=["node"],
        file_globs=["package.json"],
        pattern=r'^\s*"csurf"\s*:',
        message="csurf is deprecated (since 2022-09) and no longer maintained",
        why=("Older tutorials and agent training data still add csurf for Express CSRF. It is archived, had a "
             "double-submit weakness, and leaves apps on an unmaintained dependency."),
        fp_trap=("The app may be token-authenticated (Authorization header, no cookies) and not need CSRF at all; "
                 "then remove csurf instead of replacing it."),
        fix_ref=REF + "#csrf",
        confidence="high",
        needs_confirmation=False,
    ),
    Rule(
        id="csrf-protection-disabled",
        skill=SKILL,
        klass="framework CSRF disabled",
        severity="medium",
        stacks=["django", "flask", "laravel", "python", "php"],
        file_globs=["*.py", "*.php"],
        exclude_globs=NOT_PROD + ["**/settings/dev*.py", "**/settings/local*.py", "**/settings/test*.py",
                                  "test_settings.py", "settings_test.py"],
        check=check_csrf_disabled,
        message="Framework CSRF protection is switched off for a route or the whole app",
        why=("When a form or fetch call fails with a CSRF error, the quickest agent fix is @csrf_exempt, an "
             "except entry, or removing the middleware. Cookie-authenticated actions then accept cross-site posts."),
        fp_trap=("Webhook endpoints (Stripe, PayPal, GitHub) are correctly exempt, and views authenticated by a "
                 "header token instead of cookies are not CSRF-prone. The scanner skips webhook-like names and "
                 "views that never touch request.user or the session; confirm the rest."),
        fix_ref=REF + "#csrf",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="csrf-session-no-token",
        skill=SKILL,
        klass="CSRF on cookie sessions",
        severity="medium",
        stacks=["express"],
        file_globs=[JS_GLOB],
        exclude_globs=NOT_PROD,
        check=check_csrf_session_no_token,
        message="State-changing Express route uses the cookie session, and the project has no CSRF defense",
        why=("Agents add express-session or cookie-session for login and forget CSRF because same-origin fetch "
             "works in development. A page on another site can then post as the logged-in user."),
        fp_trap=("A SameSite=Lax or Strict session cookie, an Origin or Sec-Fetch-Site check, or a CSRF library "
                 "called anywhere in the project makes the scanner skip; so does Authorization-header auth. A "
                 "library that is only listed in package.json, or whose call is commented out, does not count. SameSite "
                 "alone is defense in depth, not a full fix."),
        fix_ref=REF + "#csrf",
        confidence="low",
        needs_confirmation=True,
        max_per_file=3,
    ),
    Rule(
        id="redirect-open",
        skill=SKILL,
        klass="open redirect",
        severity="medium",
        stacks=["*"],
        file_globs=CODE_GLOBS,
        exclude_globs=NOT_PROD,
        check=check_open_redirect,
        message="Redirect target comes from a next, returnTo or redirect parameter without a same-site check",
        why=("'Send the user back where they came from' is implemented by echoing the parameter. Attackers use "
             "your login link to land victims on a phishing page or to leak OAuth codes."),
        fp_trap=("Safe: a constant target, an exact-match allowlist, url_has_allowed_host_and_scheme, a parsed "
                 "origin compared with your own, or a check that the value starts with one /, is not // or /\\, and "
                 "holds no backslash or control character. A // check or a urlsplit netloc check alone is reported: "
                 "browsers read /\\host and a tab or newline after the first / as another host. Prefixing the origin "
                 "(`${origin}${next}`) is safe only together with the startsWith('/') check. new URL(next, base) "
                 "alone is not safe, and an allowlist matched with includes() accepts any URL that contains it."),
        fix_ref=REF + "#open-redirects",
        confidence="medium",
        needs_confirmation=True,
    ),
]
