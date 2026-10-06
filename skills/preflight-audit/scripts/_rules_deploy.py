"""Deployment rules: debug modes, dev servers in production, serving the
project root, CORS with credentials, cookie flags, security headers, source
maps, and secrets or PII in logs (threats-exposure classes 4-6, 8-10).

Each rule is a _wardcore.Rule. Checks that need more than one regex use the
small code scanner below. It blanks comments and string contents (keeping
positions), so brackets and identifiers can be matched without tripping on
text inside strings. Values such as cookie names are then read from the
original text at the same offsets.
"""

from __future__ import annotations

import bisect
import json
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Tuple

from _wardcore import Hit, Rule, is_env_file, is_example_file, match_any, parse_version, version_lt

# ---------------------------------------------------------------------------
# File groups
# ---------------------------------------------------------------------------

_JS = ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.mts", "*.cts"]
_PY = ["*.py"]
_JS_EXTS = tuple(g[1:] for g in _JS)

# Never shipped or never run in production.
_TESTS = [
    "**/test/**", "**/tests/**", "**/__tests__/**", "**/__mocks__/**", "**/spec/**", "**/e2e/**",
    "**/cypress/**", "**/playwright/**", "**/fixtures/**", "**/examples/**", "**/example/**",
    "**/docs/**", "*.test.*", "*.spec.*", "*.stories.*", "test_*.py", "*_test.py", "conftest.py",
]

# Settings modules that only a developer machine or the test runner loads.
_DEV_SETTINGS = [
    "**/settings/dev*.py", "**/settings/local*.py", "**/settings/test*.py", "**/settings/ci.py",
    "dev_settings.py", "local_settings.py", "test_settings.py", "settings_dev.py",
    "settings_local.py", "settings_test.py", "**/tests/**", "**/test/**", "conftest.py",
]

_DOCKER = ["Dockerfile", "Dockerfile.*", "*.Dockerfile", "*.dockerfile", "Containerfile"]
_DEPLOY = _DOCKER + [
    "Procfile", "docker-compose*.yml", "docker-compose*.yaml", "compose*.yml", "compose*.yaml",
    "ecosystem.config.js", "ecosystem.config.cjs", "ecosystem.config.mjs", "ecosystem.json",
    "pm2.config.js", "fly.toml", "render.yaml", "railway.json", "railway.toml", "nixpacks.toml",
    "app.yaml",
]
_PROD_ENV_FILES = [".env.*", "*.env"]

_DEV_TOKEN = re.compile(r"(?:^|[._-])(?:dev|develop|development|local|test|tests|testing|ci|debug|"
                        r"override|sample|example)(?:[._-]|$)", re.I)
_PROD_TOKEN = re.compile(r"(?:^|[._-])(?:prod|production|live|release|deploy|staging|stage)(?:[._-]|$)", re.I)


def _name(rel: str) -> str:
    return rel.rsplit("/", 1)[-1]


def _is_dev_named(rel: str) -> bool:
    if "/.devcontainer/" in "/" + rel:
        return True
    return bool(_DEV_TOKEN.search(_name(rel)))


def _is_prod_named(rel: str) -> bool:
    return bool(_PROD_TOKEN.search(_name(rel)))


def _is_compose(rel: str) -> bool:
    return bool(re.match(r"(?:docker-)?compose[\w.-]*\.ya?ml$", _name(rel)))


def _is_docker(rel: str) -> bool:
    n = _name(rel)
    return n in ("Dockerfile", "Containerfile") or n.startswith("Dockerfile.") or n.lower().endswith(".dockerfile")


def _line_text(ctx: Any, rel: str, line: int) -> str:
    ls = ctx.lines(rel)
    if 0 < line <= len(ls):
        return ls[line - 1].strip()
    return ""


# ---------------------------------------------------------------------------
# Code scanner: blank comments and string contents, match brackets lazily
# ---------------------------------------------------------------------------

_REGEX_PREV = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_WORDS = frozenset({"return", "typeof", "case", "in", "of", "yield", "await", "void", "delete",
                          "instanceof", "new", "throw", "else", "do"})
_JS_SPECIAL = re.compile(r"[/'\"`{}]")
_PY_SPECIAL = re.compile(r"[#'\"]")
_PHP_SPECIAL = re.compile(r"[/#'\"]")
_NOT_NL = re.compile(r"[^\n]")
_BRACKET = re.compile(r"[()\[\]{}]")
_ARG_TOKEN = re.compile(r"[,()\[\]{}]")


class _Lexer(object):
    """Collects the spans to blank; view() builds the blanked copy in one pass."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.n = len(text)
        self.spans: List[Tuple[int, int]] = []
        self.c_starts: List[int] = []
        self.c_ends: List[int] = []

    def blank(self, a: int, b: int) -> None:
        a = max(0, a)
        b = min(b, self.n)
        if b > a:
            self.spans.append((a, b))

    def comment(self, a: int, b: int) -> None:
        self.blank(a, b)
        self.c_starts.append(a)
        self.c_ends.append(b)

    def view(self) -> str:
        text = self.text
        out: List[str] = []
        last = 0
        for a, b in sorted(self.spans):
            a = max(a, last)
            if b <= a:
                continue
            out.append(text[last:a])
            out.append(_NOT_NL.sub(" ", text[a:b]))
            last = b
        out.append(text[last:])
        return "".join(out)


def _end_quote(text: str, i: int, n: int, q: str) -> int:
    """Index of the closing quote for a string opening at i, or of the newline
    / end of text when it is not closed on the line."""
    j = i + 1
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == q or ch == "\n":
            return j
        j += 1
    return n


def _regex_allowed(lx: _Lexer, i: int) -> bool:
    """Can a / at i start a regex literal? Looks at the previous code token."""
    text = lx.text
    k = i - 1
    lo = max(0, i - 400)
    while k >= lo:
        if text[k] in " \t\r\n":
            k -= 1
            continue
        idx = bisect.bisect_right(lx.c_starts, k) - 1
        if idx >= 0 and k < lx.c_ends[idx]:
            k = lx.c_starts[idx] - 1
            continue
        break
    if k < lo:
        return True
    ch = text[k]
    if ch in _REGEX_PREV:
        return True
    if ch.isalnum() or ch in "_$":
        j = k
        while j >= 0 and (text[j].isalnum() or text[j] in "_$"):
            j -= 1
        return text[j + 1:k + 1] in _REGEX_WORDS
    return False


def _skip_regex(text: str, i: int, n: int) -> int:
    """End (exclusive) of a regex literal starting at i, or -1 if it is not one."""
    j = i + 1
    in_class = False
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "\n":
            return -1
        if in_class:
            if ch == "]":
                in_class = False
        elif ch == "[":
            in_class = True
        elif ch == "/":
            j += 1
            while j < n and text[j].isalpha():
                j += 1
            return j
        j += 1
    return -1


def _lex_js(lx: _Lexer, i: int, in_expr: bool) -> int:
    text, n = lx.text, lx.n
    depth = 0
    while True:
        m = _JS_SPECIAL.search(text, i)
        if not m:
            return n
        i = m.start()
        c = text[i]
        if c == "/":
            nxt = text[i + 1] if i + 1 < n else ""
            if nxt == "/":
                j = text.find("\n", i)
                j = n if j < 0 else j
                lx.comment(i, j)
                i = j
                continue
            if nxt == "*":
                j = text.find("*/", i + 2)
                j = n if j < 0 else j + 2
                lx.comment(i, j)
                i = j
                continue
            if _regex_allowed(lx, i):
                j = _skip_regex(text, i, n)
                if j > 0:
                    lx.blank(i + 1, text.rfind("/", i + 1, j))
                    i = j
                    continue
            i += 1
            continue
        if c in "'\"":
            j = _end_quote(text, i, n, c)
            lx.blank(i + 1, j)
            i = j + 1
            continue
        if c == "`":
            i = _lex_template(lx, i + 1)
            continue
        if in_expr:
            if c == "{":
                depth += 1
            elif depth == 0:
                return i
            else:
                depth -= 1
        i += 1


def _lex_template(lx: _Lexer, i: int) -> int:
    text, n = lx.text, lx.n
    start = i
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == "`":
            lx.blank(start, i)
            return i + 1
        if ch == "$" and i + 1 < n and text[i + 1] == "{":
            lx.blank(start, i + 2)
            j = _lex_js(lx, i + 2, True)
            lx.blank(j, j + 1)
            i = j + 1
            start = i
            continue
        i += 1
    lx.blank(start, n)
    return n


def _blank_fstring(lx: _Lexer, a: int, b: int) -> None:
    """Blank an f-string body but keep the {expressions}."""
    text = lx.text
    k = a
    depth = 0
    run = a
    while k < b:
        ch = text[k]
        if depth == 0:
            if ch == "{" and k + 1 < b and text[k + 1] == "{":
                k += 2
                continue
            if ch == "{":
                lx.blank(run, k + 1)
                depth = 1
        else:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    run = k
        k += 1
    if depth == 0:
        lx.blank(run, b)


def _lex_py(lx: _Lexer) -> None:
    text, n = lx.text, lx.n
    i = 0
    while True:
        m = _PY_SPECIAL.search(text, i)
        if not m:
            return
        i = m.start()
        c = text[i]
        if c == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            lx.comment(i, j)
            i = j
            continue
        k = i
        pre = ""
        while k > 0 and text[k - 1] in "rRbBfFuU" and len(pre) < 2:
            pre = text[k - 1] + pre
            k -= 1
        if k > 0 and (text[k - 1].isalnum() or text[k - 1] == "_"):
            pre = ""
        q = c * 3 if text.startswith(c * 3, i) else c
        j = i + len(q)
        body = j
        if len(q) == 3:
            while True:
                j = text.find(q, j)
                if j < 0:
                    j = n
                    break
                bs = 0
                while j - 1 - bs >= body and text[j - 1 - bs] == "\\":
                    bs += 1
                if bs % 2 == 0:
                    break
                j += 1
        else:
            j = _end_quote(text, i, n, c)
        if "f" in pre.lower():
            _blank_fstring(lx, body, j)
        else:
            lx.blank(body, j)
        i = j + (len(q) if text.startswith(q, j) else 1)


def _lex_php(lx: _Lexer) -> None:
    text, n = lx.text, lx.n
    i = 0
    while True:
        m = _PHP_SPECIAL.search(text, i)
        if not m:
            return
        i = m.start()
        c = text[i]
        if c == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            lx.comment(i, j)
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            lx.comment(i, j)
            i = j
            continue
        if c == "/":
            i += 1
            continue
        j = _end_quote(text, i, n, c)
        lx.blank(i + 1, j)
        i = j + 1


def _lex(text: str, lang: str) -> _Lexer:
    lx = _Lexer(text)
    if lang == "py":
        _lex_py(lx)
    elif lang == "php":
        _lex_php(lx)
    else:
        _lex_js(lx, 0, False)
    return lx


def _code_view(text: str, lang: str) -> str:
    """Same-length copy of text with comments and string contents blanked.

    lang is "js", "py" or "php". JS template ${...} and Python f-string
    {...} expressions are kept, since they are code.
    """
    return _lex(text, lang).view()


def _blank_spans(text: str, spans: Sequence[Tuple[int, int]]) -> str:
    out: List[str] = []
    last = 0
    for a, b in spans:
        a = max(a, last)
        if b <= a:
            continue
        out.append(text[last:a])
        out.append(_NOT_NL.sub(" ", text[a:b]))
        last = b
    out.append(text[last:])
    return "".join(out)


class _Code(object):
    """Blanked view of one file plus a cache of matched brackets.

    nocomment is a second same-length copy with only the comments blanked
    (strings kept), built on first use.
    """

    __slots__ = ("view", "closes", "_text", "_comments", "_nc")

    def __init__(self, view: str, text: str = "", comments: Sequence[Tuple[int, int]] = ()) -> None:
        self.view = view
        self.closes: Dict[int, Optional[int]] = {}
        self._text = text
        self._comments = list(comments)
        self._nc: Optional[str] = None

    @property
    def nocomment(self) -> str:
        if self._nc is None:
            self._nc = _blank_spans(self._text, self._comments)
        return self._nc


def _lang(rel: str) -> str:
    n = rel.lower()
    if n.endswith(".py"):
        return "py"
    if n.endswith(".php"):
        return "php"
    return "js"


def _make_code(rel: str, text: str) -> _Code:
    lx = _lex(text, _lang(rel))
    return _Code(lx.view(), text, sorted(zip(lx.c_starts, lx.c_ends)))


def _code(ctx: Any, rel: str, text: str) -> _Code:
    return ctx.memo(("deploy-code", rel), lambda: _make_code(rel, text))


def _strip_hash_comments(text: str) -> str:
    """Drop whole-line # comments (nginx, Apache, Caddy, TOML, _headers files)."""
    return re.sub(r"(?m)^[ \t]*#.*$", "", text)


_MAX_SPAN = 30000  # calls and objects longer than this are not worth matching


def _close_of(code: _Code, o: int) -> Optional[int]:
    """Index of the bracket closing the one at o (any bracket kind counts),
    or None when it does not close within _MAX_SPAN characters."""
    if o in code.closes:
        return code.closes[o]
    found = None
    if 0 <= o < len(code.view) and code.view[o] in "([{":
        depth = 0
        for m in _BRACKET.finditer(code.view, o, o + _MAX_SPAN):
            if m.group(0) in "([{":
                depth += 1
            else:
                depth -= 1
                if depth == 0:
                    found = m.start()
                    break
    code.closes[o] = found
    return found


def _call_end(code: _Code, open_idx: int) -> Optional[int]:
    return _close_of(code, open_idx)


def _enclosing(code: _Code, pos: int, ch: str = "{") -> Optional[Tuple[int, int]]:
    """Innermost bracket pair of kind ch that contains pos."""
    lo = max(0, pos - 20000)
    marks = [(m.start(), m.group(0)) for m in _BRACKET.finditer(code.view, lo, pos)]
    depth = 0
    for idx, c in reversed(marks):
        if c in ")]}":
            depth += 1
        elif depth:
            depth -= 1
        elif c == ch:
            close = _close_of(code, idx)
            if close is not None and close > pos:
                return idx, close
    return None


def _split_args(code: _Code, a: int, b: int) -> List[Tuple[int, int]]:
    """Top-level argument spans inside the brackets a..b (a and b excluded)."""
    view = code.view
    out: List[Tuple[int, int]] = []
    start = a + 1
    depth = 0
    for m in _ARG_TOKEN.finditer(view, a + 1, b):
        ch = m.group(0)
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0:
            out.append((start, m.start()))
            start = m.start() + 1
    if view[start:b].strip():
        out.append((start, b))
    return out


def _strip_span(text: str, a: int, b: int) -> Tuple[int, int]:
    while a < b and text[a].isspace():
        a += 1
    while b > a and text[b - 1].isspace():
        b -= 1
    return a, b


def _string_value(text: str, a: int, b: int) -> Optional[str]:
    """The literal value when text[a:b] is one plain string, else None."""
    a, b = _strip_span(text, a, b)
    s = text[a:b]
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"`" and "${" not in s:
        return s[1:-1]
    return None


def _prop(code: _Code, text: str, a: int, b: int, key: str) -> Optional[str]:
    """Raw value text of `key: value` (JS) directly inside the object a..b, or None."""
    rx = re.compile(r"(?<![\w$.])" + key + r"\s*:\s*")
    for m in rx.finditer(code.view, a, b):
        inner = _enclosing(code, m.start(), "{")
        if inner is None or inner[0] != a:
            continue
        v = re.match(r"\s*([^,}\n]*)", text[m.end():b])
        return v.group(1).strip() if v else ""
    return None


def _kwarg(code: _Code, text: str, a: int, b: int, key: str) -> Optional[str]:
    """Raw value of a Python keyword argument key=value at the top level of a..b."""
    for s, e in _split_args(code, a, b):
        m = re.match(r"\s*" + key + r"\s*=(?!=)\s*", code.view[s:e])
        if m:
            return text[s + m.end():e].strip()
    return None


def _in_main_guard(lines: Sequence[str], lineno: int) -> bool:
    """True when the Python line is (indirectly) inside `if __name__ == "__main__":`."""
    if not (0 < lineno <= len(lines)):
        return False
    cur = lines[lineno - 1]
    indent = len(cur) - len(cur.lstrip())
    if indent == 0:
        return False
    func = None
    for k in range(lineno - 2, -1, -1):
        ln = lines[k]
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        ind = len(ln) - len(ln.lstrip())
        if ind < indent:
            if re.match(r"""if\s+(?:__name__\s*==\s*['"]__main__['"]|['"]__main__['"]\s*==\s*__name__)\s*:""", s):
                return True
            if ind == 0:
                m = re.match(r"def\s+(\w+)\s*\(", s)
                func = m.group(1) if m else None
                break
            indent = ind
    if func:
        guard = False
        for ln in lines:
            s = ln.strip()
            if re.match(r"""if\s+__name__\s*==\s*['"]__main__['"]\s*:""", s):
                guard = True
                continue
            if guard and re.match(r"%s\s*\(" % re.escape(func), s) and ln[:1] in (" ", "\t"):
                return True
    return False


# ---------------------------------------------------------------------------
# Deploy commands (Dockerfile, Procfile, compose, pm2, PaaS configs)
# ---------------------------------------------------------------------------

def _docker_instructions(text: str) -> List[Tuple[int, str, str]]:
    """(line, INSTRUCTION, args) with backslash continuations joined."""
    out: List[Tuple[int, str, str]] = []
    buf = ""
    start = 0
    for i, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        s = line.strip()
        if not buf and (not s or s.startswith("#")):
            continue
        if buf and s.startswith("#"):
            continue
        if not buf:
            start = i
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        parts = buf.strip().split(None, 1)
        if parts:
            out.append((start, parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        buf = ""
    return out


def _final_stage(instrs: List[Tuple[int, str, str]]) -> List[Tuple[int, str, str]]:
    last = 0
    for i, (_ln, ins, _a) in enumerate(instrs):
        if ins == "FROM":
            last = i
    return instrs[last:]


def _flat_cmd(value: str) -> str:
    v = value.strip()
    if v.startswith("["):
        try:
            items = json.loads(v)
            if isinstance(items, list):
                return " ".join(str(x) for x in items)
        except ValueError:
            return re.sub(r"[\[\]\"',]", " ", v)
    return v.strip("\"'")


def _start_commands(ctx: Any, rel: str, text: str) -> List[Tuple[int, str]]:
    """Production start commands found in one deploy file: (line, command)."""
    name = _name(rel)
    out: List[Tuple[int, str]] = []
    if _is_docker(rel):
        stage = _final_stage(_docker_instructions(text))
        entry = ""
        for ln, ins, args in stage:
            if ins == "ENTRYPOINT":
                entry = _flat_cmd(args)
                out.append((ln, entry))
        for ln, ins, args in stage:
            if ins == "CMD":
                cmd = _flat_cmd(args)
                out.append((ln, (entry + " " + cmd).strip() if entry else cmd))
        return out
    lines = ctx.lines(rel)
    if name == "Procfile":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*(?:web|app)\s*:\s*(.+)$", ln)
            if m:
                out.append((i, m.group(1).strip()))
        return out
    if _is_compose(rel):
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*(?:command|entrypoint)\s*:\s*(.*)$", ln)
            if not m:
                continue
            val = m.group(1).strip()
            if val in ("", ">", "|", ">-", "|-") and i < len(lines):
                val = lines[i].strip()
            out.append((i, _flat_cmd(val)))
        return out
    if name.startswith(("ecosystem.", "pm2.")):
        for m in re.finditer(r"""\bscript\s*:\s*(['"`])(.+?)\1""", text):
            args = ""
            tail = text[m.end():m.end() + 400]
            nxt = re.search(r"\bscript\s*:", tail)
            if nxt:
                tail = tail[:nxt.start()]
            am = re.search(r"""\bargs\s*:\s*(['"`])(.+?)\1""", tail)
            if am:
                args = am.group(2)
            out.append((ctx.line_of(rel, m.start()), (m.group(2) + " " + args).strip()))
        return out
    if name == "render.yaml":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*startCommand\s*:\s*(.+)$", ln)
            if m:
                out.append((i, _flat_cmd(m.group(1))))
        return out
    if name == "railway.json":
        for m in re.finditer(r'"startCommand"\s*:\s*"([^"]+)"', text):
            out.append((ctx.line_of(rel, m.start()), m.group(1)))
        return out
    if name == "app.yaml":
        for i, ln in enumerate(lines, 1):
            m = re.match(r"entrypoint\s*:\s*(.+)$", ln)
            if m:
                out.append((i, _flat_cmd(m.group(1))))
        return out
    if name in ("fly.toml", "railway.toml", "nixpacks.toml"):
        for i, ln in enumerate(lines, 1):
            m = re.match(r"\s*(?:app|web|cmd|command|startCommand|start)\s*=\s*(.+)$", ln)
            if m:
                out.append((i, _flat_cmd(m.group(1))))
        return out
    return out


def _deploy_files(ctx: Any) -> List[str]:
    """Deploy configs that describe production (dev-named ones and plain compose files left out)."""
    def build() -> List[str]:
        out = []
        for f in ctx.files:
            if not _is_deploy_file(f) or _is_dev_named(f):
                continue
            if any(p in f.split("/")[:-1] for p in ("test", "tests", "examples", "example", "docs")):
                continue
            if _is_compose(f) and not _is_prod_named(f):
                continue
            out.append(f)
        return out
    return ctx.memo("deploy-files", build)


def _is_deploy_file(rel: str) -> bool:
    return match_any(rel, _DEPLOY)


def _scripts_near(ctx: Any, rel: str) -> Dict[str, str]:
    folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
    for cand in ((folder + "/package.json") if folder else "package.json", "package.json"):
        data = ctx.json(cand)
        if isinstance(data, dict) and isinstance(data.get("scripts"), dict):
            return {str(k): str(v) for k, v in data["scripts"].items()}
    return {}


_DEV_SERVERS = [
    (re.compile(r"(?<![\w.-])next\s+dev\b"), "the Next.js dev server (next dev)", "medium", "next"),
    (re.compile(r"(?<![\w.-])nuxi?\s+dev\b"), "the Nuxt dev server", "medium", "nuxt"),
    (re.compile(r"\bmanage\.py\s+runserver\b"), "Django's runserver", "medium", "django"),
    (re.compile(r"\bartisan\s+serve\b"), "php artisan serve", "medium", "laravel"),
    (re.compile(r"(?<![\w.-])expo\s+start\b"), "the Expo dev server", "medium", "expo"),
    (re.compile(r"(?<![\w.-])(?:webpack-dev-server|webpack\s+serve)\b"), "webpack-dev-server", "medium", "webpack"),
    (re.compile(r"(?<![\w.-])ng\s+serve\b"), "the Angular dev server (ng serve)", "medium", "angular"),
    (re.compile(r"(?<![\w.-])react-scripts\s+start\b"), "the Create React App dev server", "medium", "cra"),
    (re.compile(r"(?<![\w.-])(?:astro\s+dev|remix\s+dev|gatsby\s+develop)\b"), "a framework dev server", "medium", "other"),
    (re.compile(r"(?<![\w.-])uvicorn\b[^;&|]*\s--reload\b"), "uvicorn with --reload", "low", "uvicorn"),
]
# Dev servers that are the generated default for "npm start" in their templates.
_DEFAULT_START = frozenset({"expo", "webpack", "angular", "cra", "other"})
_NPM_RUN = re.compile(r"(?<![\w.-])(?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s+)?([\w:.-]+)")


def _classify_cmd(cmd: str, scripts: Dict[str, str], depth: int = 0,
                  package_start: bool = False) -> Optional[Tuple[str, str]]:
    """(label, severity) when the command starts a dev server, else None."""
    for seg in re.split(r"&&|\|\||;|\|", cmd):
        seg = seg.strip()
        if not seg:
            continue
        for rx, label, sev, kind in _DEV_SERVERS:
            if rx.search(seg):
                if package_start and kind in _DEFAULT_START:
                    break  # template default for npm start, leave it alone
                return label, sev
        else:
            # no fixed pattern matched: Vite, flask run, or an npm script to resolve
            m = re.search(r"(?<![\w.-])vite(?![\w.-])(.*)$", seg)
            if m and not re.search(r"\b(?:build|preview|optimize)\b", m.group(1)):
                if re.search(r"--host\b", m.group(1)):
                    return ("the Vite dev server with --host (it has had a long series of file-read bypasses, "
                            "CVE-2025-30208 to CVE-2026-53571; upgrading does not make it safe to expose)"), "medium"
                return "the Vite dev server", "medium"
            toks = seg.split()
            if "flask" in toks and "run" in toks and "--debug" not in toks:
                return "the Flask dev server (flask run)", "medium"
            nm = _NPM_RUN.search(seg)
            if nm and depth < 2:
                script = nm.group(1)
                body = scripts.get(script)
                if body is not None and script not in ("build", "install", "test"):
                    r = _classify_cmd(body, scripts, depth + 1)
                    if r:
                        return "%s via the %r script" % (r[0], script), r[1]
                elif script == "dev" and body is None:
                    return "the dev script", "medium"
    return None


# ---------------------------------------------------------------------------
# Git helper (only for "is this .env committed")
# ---------------------------------------------------------------------------

def _git_tracked(ctx: Any) -> Optional[set]:
    def run() -> Optional[set]:
        exe = shutil.which("git")
        if not exe:
            return None
        try:
            r = subprocess.run([exe, "-C", str(ctx.root), "ls-files", "-z"], capture_output=True,
                               encoding="utf-8", errors="replace", timeout=20)
        except (OSError, subprocess.SubprocessError):
            return None
        if r.returncode != 0:
            return None
        return set(p for p in r.stdout.split("\0") if p)
    return ctx.memo("deploy-git-tracked", run)


# ---------------------------------------------------------------------------
# Debug modes
# ---------------------------------------------------------------------------

_APP_DEBUG_ON = re.compile(r"""(?im)^[ \t]*APP_DEBUG[ \t]*=[ \t]*["']?(?:true|1|on|yes)["']?[ \t]*(?:#.*)?$""")
_APP_ENV = re.compile(r"""(?im)^[ \t]*APP_ENV[ \t]*=[ \t]*["']?([\w-]+)""")
_PROD_ENVS = ("production", "prod", "staging", "stage", "live")


def check_laravel_debug(path: str, text: str, ctx: Any) -> List[Hit]:
    if path == "config/app.php" or path.endswith("/config/app.php"):
        code = _code(ctx, path, text)
        for m in re.finditer(r"""(['"])debug\1\s*=>\s*""", text):
            if code.view[m.start()] not in "'\"":
                continue
            rest = text[m.end():m.end() + 120]
            line = ctx.line_of(path, m.start())
            if re.match(r"true\b", rest, re.I):
                return [Hit(line, _line_text(ctx, path, line),
                            "config/app.php hardcodes 'debug' => true, so every environment shows full error pages")]
            if re.match(r"""(?:\(bool\)\s*)?env\(\s*['"]APP_DEBUG['"]\s*,\s*true\s*\)""", rest, re.I):
                return [Hit(line, _line_text(ctx, path, line),
                            "config/app.php defaults 'debug' to true when APP_DEBUG is unset on the server", "medium")]
        return []
    if not is_env_file(path) or is_example_file(path):
        return []
    m = _APP_DEBUG_ON.search(text)
    if not m:
        return []
    line = ctx.line_of(path, m.start())
    env_m = _APP_ENV.search(text)
    env = env_m.group(1).lower() if env_m else ""
    ev = _line_text(ctx, path, line)
    if _is_prod_named(path) or env in _PROD_ENVS:
        return [Hit(line, ev, "APP_DEBUG=true in a production env file (APP_ENV=%s); Laravel shows full error "
                              "pages with config values" % (env or "unset"))]
    if _name(path) == ".env":
        tracked = _git_tracked(ctx)
        if tracked is not None and path in tracked:
            return [Hit(line, ev, "APP_DEBUG=true in a .env that is committed to git; a git based deploy ships "
                                  "it with debug on", "medium")]
    return []


# --- Django settings modules -------------------------------------------------

_DJANGO_DEBUG_ON = re.compile(
    r"^DEBUG\s*=\s*(?:True\b|.*(?:environ\.get|getenv)\([^)]*,\s*['\"]?(?:True|1)\b|.*default\s*=\s*True\b)", re.M)
_DJANGO_SETTINGS_GLOBS = ["settings.py", "*settings*.py", "**/settings/*.py"]
_DSM = re.compile(r"""DJANGO_SETTINGS_MODULE['"]?\s*[=:,]?\s*['"]?([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+)"""
                  r"""|--settings[= ]['"]?([A-Za-z_][\w]*(?:\.[A-Za-z_]\w*)+)""")
_STAR_IMPORT = re.compile(r"^[ \t]*from[ \t]+(\.*)([\w.]*)[ \t]+import[ \t]+\*", re.M)
_PROD_STEM = re.compile(r"(?:^|_)(?:prod|production|live)(?:_|$)", re.I)


def _py_module_file(ctx: Any, module: str, base_pkg: str = "") -> Optional[str]:
    """Repo file for a dotted module name (x.y -> x/y.py or x/y/__init__.py), also under a src/ style prefix."""
    files = _py_files(ctx)
    fileset = ctx.memo("deploy-py-fileset", lambda: set(files))
    stem = module.replace(".", "/")
    if base_pkg:
        stem = base_pkg + "/" + stem if stem else base_pkg
    for cand in (stem + ".py", stem + "/__init__.py"):
        if cand in fileset:
            return cand
    if base_pkg:
        return None
    for cand in (stem + ".py", stem + "/__init__.py"):
        for f in files:
            if f.endswith("/" + cand):
                return f
    return None


def _py_files(ctx: Any) -> List[str]:
    return ctx.memo("deploy-py-files", lambda: sorted(f for f in ctx.files if f.endswith(".py")))


def _star_imports(ctx: Any, rel: str) -> List[Tuple[int, str]]:
    """(line, file) for each `from X import *` in a Python module that resolves to a repo file."""
    def build() -> List[Tuple[int, str]]:
        text = ctx.read(rel)
        out: List[Tuple[int, str]] = []
        if "import" not in text:
            return out
        pkg = rel.rsplit("/", 1)[0] if "/" in rel else ""
        for m in _STAR_IMPORT.finditer(text):
            dots, mod = m.group(1), m.group(2)
            if dots:
                base = pkg
                for _ in range(len(dots) - 1):
                    base = base.rsplit("/", 1)[0] if "/" in base else ""
                target = _py_module_file(ctx, mod, base) if (mod or base) else None
            else:
                target = _py_module_file(ctx, mod)
            if target and target != rel:
                out.append((ctx.line_of(rel, m.start()), target))
        return out
    return ctx.memo(("deploy-star-imports", rel), build)


def _star_closure(ctx: Any, rel: str) -> set:
    """rel plus every module it pulls in through star imports (transitively)."""
    def build() -> set:
        seen = {rel}
        todo = [rel]
        while todo and len(seen) < 200:
            cur = todo.pop()
            for _ln, t in _star_imports(ctx, cur):
                if t not in seen:
                    seen.add(t)
                    todo.append(t)
        return seen
    return ctx.memo(("deploy-star-closure", rel), build)


def _django_settings_refs(ctx: Any) -> List[Tuple[str, str, str]]:
    """(kind, source file, module file) for every DJANGO_SETTINGS_MODULE / --settings value.

    kind is "prod" (production deploy config or env file), "default"
    (setdefault in manage.py, wsgi.py, asgi.py) or "other".
    """
    def build() -> List[Tuple[str, str, str]]:
        prod_files = set(_deploy_files(ctx))
        out: List[Tuple[str, str, str]] = []
        for f in ctx.files:
            n = _name(f)
            if match_any(f, _TESTS):
                continue
            if f in prod_files:
                kind = "prod"
            elif is_env_file(f) and not is_example_file(f) and _is_prod_named(f):
                kind = "prod"
            elif n in ("manage.py", "wsgi.py", "asgi.py"):
                kind = "default"
            elif _is_deploy_file(f) or n.endswith((".ini", ".cfg", ".toml", ".yml", ".yaml")) or n == "heroku.yml":
                kind = "other"
            else:
                continue
            text = ctx.read(f)
            if "DJANGO_SETTINGS_MODULE" not in text and "--settings" not in text:
                continue
            for m in _DSM.finditer(text):
                mod = m.group(1) or m.group(2)
                target = _py_module_file(ctx, mod)
                if target:
                    out.append((kind, f, target))
        return out
    return ctx.memo("deploy-django-refs", build)


def _is_django_settings(ctx: Any, rel: str) -> bool:
    if match_any(rel, _DJANGO_SETTINGS_GLOBS):
        return True
    named = ctx.memo("deploy-django-named", lambda: set(
        f for _k, _src, t in _django_settings_refs(ctx) for f in _star_closure(ctx, t)))
    return rel in named and not _DEV_TOKEN.search(_name(rel))


def _sets_off(ctx: Any, rel: str, kind: str) -> bool:
    """True when the module's own last top-level assignment turns the setting off,
    after its last star import (so nothing it imports can turn it back on).
    kind "debug" looks at DEBUG; "cors" at the all-origins or credentials switch."""
    text = ctx.read(rel)
    last_import = max([ln for ln, _t in _star_imports(ctx, rel)] or [0])
    if kind == "debug":
        ms = list(re.finditer(r"^DEBUG[ \t]*=", text, re.M))
        return bool(ms) and ctx.line_of(rel, ms[-1].start()) > last_import \
            and not _DJANGO_DEBUG_ON.match(text, ms[-1].start())
    for name in ("CORS_ALLOW_ALL_ORIGINS", "CORS_ORIGIN_ALLOW_ALL", "CORS_ALLOW_CREDENTIALS"):
        ms = list(re.finditer(r"^%s[ \t]*=[ \t]*(.+)$" % name, text, re.M))
        if ms and ctx.line_of(rel, ms[-1].start()) > last_import and not re.match(r"\s*True\b", ms[-1].group(1)):
            return True
    return False


def _django_override(ctx: Any, rel: str, kind: str) -> Optional[Tuple[str, str]]:
    """How production settings treat a module that turns DEBUG or open CORS on.

    None: report as usual. ("skip", ""): every production settings module named
    by the deploy config imports this one and turns the setting off. ("low", why):
    a production-named module overrides it but nothing in the repo shows the
    server uses that module, or the named production module never loads it.
    """
    refs = _django_settings_refs(ctx)
    targets = sorted(set((src, t) for k, src, t in refs if k == "prod"))
    if targets:
        loaded = False
        for _src, t in targets:
            if t == rel:
                return None
            if rel not in _star_closure(ctx, t):
                continue
            loaded = True
            if not _sets_off(ctx, t, kind):
                return None
        if loaded:
            return "skip", ""
        src, t = targets[0]
        return "low", "the production settings module (%s, from %s) does not import this file" % (t, src)
    for f in _py_files(ctx):
        stem = _name(f)[:-3]
        if f == rel or not _PROD_STEM.search(stem) or match_any(f, _TESTS):
            continue
        if rel in _star_closure(ctx, f) and _sets_off(ctx, f, kind):
            defaults = sorted(set(t for k, _s, t in refs if k == "default"))
            hint = (" (manage.py/wsgi.py default to %s)" % ", ".join(defaults)) if defaults else ""
            return "low", ("%s imports this file and turns it off; it only matters if the server does not set "
                           "DJANGO_SETTINGS_MODULE to that module%s" % (f, hint))
    return None


def check_django_debug(path: str, text: str, ctx: Any) -> List[Hit]:
    if "DEBUG" not in text or not _is_django_settings(ctx, path):
        return []
    m = _DJANGO_DEBUG_ON.search(text)
    if not m:
        return []
    line = ctx.line_of(path, m.start())
    ev = _line_text(ctx, path, line)
    ov = _django_override(ctx, path, "debug")
    if ov is None:
        return [Hit(line, ev, "Django DEBUG is on (or defaults to on) in a settings module that production may load")]
    if ov[0] == "skip":
        return []
    return [Hit(line, ev, "Django DEBUG is on (or defaults to on) here, but " + ov[1], "low")]


_FLASK_IMPORT = re.compile(r"^\s*(?:from\s+(?:flask|flask_socketio|werkzeug)\b|import\s+(?:flask|werkzeug)\b)", re.M)
_WSGI_SERVERS = re.compile(r"\b(?:gunicorn|uwsgi|waitress-serve|waitress|uvicorn|hypercorn|daphne|mod_wsgi|granian)\b")


def _python_served_by_wsgi(ctx: Any) -> bool:
    """True when the deploy config (or, without one, the dependencies) shows a real WSGI/ASGI server."""
    def build() -> bool:
        cmds = []
        for f in _deploy_files(ctx):
            cmds.extend(c for _ln, c in _start_commands(ctx, f, ctx.read(f)))
        if cmds:
            return any(_WSGI_SERVERS.search(c) for c in cmds)
        return bool(ctx.py_deps & {"gunicorn", "uwsgi", "waitress", "uvicorn", "hypercorn", "daphne", "granian"})
    return ctx.memo("deploy-py-wsgi", build)


def check_flask_debug(path: str, text: str, ctx: Any) -> List[Hit]:
    hits: List[Hit] = []
    if path.endswith(".py"):
        imports_flask = bool(_FLASK_IMPORT.search(text))
        if not imports_flask and not re.search(r"\b(?:app|application|flask_app|socketio)\s*\.\s*run\s*\(", text):
            return []
        code = _code(ctx, path, text)
        lines = ctx.lines(path)
        for m in re.finditer(r"(?<![\w.])(\w+)\.run\s*\(", code.view):
            # without a flask import (app factory in run.py) only trust the usual app names
            if not imports_flask and m.group(1) not in ("app", "application", "flask_app", "socketio"):
                continue
            o = m.end() - 1
            c = _call_end(code, o)
            if c is None:
                continue
            dbg = _kwarg(code, text, o, c, "debug")
            if dbg is None or not re.match(r"True\b", dbg):
                continue
            line = ctx.line_of(path, m.start())
            host = _kwarg(code, text, o, c, "host") or ""
            public = "0.0.0.0" in host
            ev = _line_text(ctx, path, line)
            if not _in_main_guard(lines, line):
                hits.append(Hit(line, ev, "app.run(debug=True) runs whenever this module loads; the Werkzeug "
                                          "debugger lets anyone who reaches it run code on the server"))
            elif not _python_served_by_wsgi(ctx):
                runs_file = any(re.search(r"\bpython[\d.]*\s+(?:-u\s+)?(?:\S*/)?%s\b" % re.escape(_name(path)), c)
                                for f in _deploy_files(ctx) for _ln, c in _start_commands(ctx, f, ctx.read(f)))
                if runs_file:
                    msg = ("the production start command runs this file, so app.run(debug=True) serves the app "
                           "with the Werkzeug debugger on")
                else:
                    msg = ("app.run(debug=True) under __main__ and no gunicorn/uvicorn start command found; if the "
                           "server runs this file, the Werkzeug debugger is exposed")
                hits.append(Hit(line, ev, msg, "high" if (public or runs_file) else "medium"))
        for m in re.finditer(r"\bDebuggedApplication\s*\(|\buse_debugger\s*=\s*True\b", code.view):
            line = ctx.line_of(path, m.start())
            if _in_main_guard(lines, line) and _python_served_by_wsgi(ctx):
                continue
            hits.append(Hit(line, _line_text(ctx, path, line),
                            "Werkzeug interactive debugger enabled in app code; it allows running code on the server"))
        return hits
    # deploy configs and production env files
    if is_env_file(path) and not _is_prod_named(path):
        return []
    if _is_compose(path) and not _is_prod_named(path):
        return []
    if _is_dev_named(path):
        return []
    rx = re.compile(r"""\b(?:FLASK_DEBUG\s*[=:]\s*["']?(?:1|true|yes|on)\b|FLASK_ENV\s*[=:]\s*["']?development\b"""
                    r"""|WERKZEUG_DEBUG_PIN\s*[=:]\s*["']?off\b|flask\b[^\n]*\s--debug\b)""", re.I)
    for i, ln in enumerate(ctx.lines(path), 1):
        if ln.lstrip().startswith("#"):
            continue
        if rx.search(ln):
            hits.append(Hit(i, ln.strip(), "Flask debug mode switched on in a production config; the Werkzeug "
                                           "debugger lets anyone who reaches it run code on the server"))
    return hits


# ---------------------------------------------------------------------------
# Dev server as the production start command
# ---------------------------------------------------------------------------

def check_dev_server(path: str, text: str, ctx: Any) -> List[Hit]:
    name = _name(path)
    hits: List[Hit] = []
    if name == "package.json":
        data = ctx.json(path)
        if not isinstance(data, dict) or not isinstance(data.get("scripts"), dict):
            return []
        scripts = {str(k): str(v) for k, v in data["scripts"].items()}
        start = scripts.get("start")
        if not start:
            return []
        r = _classify_cmd(start, scripts, package_start=True)
        if r:
            m = re.search(r'"start"\s*:', text)
            line = ctx.line_of(path, m.start()) if m else 1
            hits.append(Hit(line, _line_text(ctx, path, line),
                            "\"npm start\" runs %s; hosts that run npm start serve the dev server to the public" % r[0],
                            r[1]))
        return hits
    if name == "eas.json":
        data = ctx.json(path)
        build = data.get("build") if isinstance(data, dict) else None
        if not isinstance(build, dict):
            return []
        for prof, cfg in build.items():
            if not isinstance(cfg, dict) or cfg.get("developmentClient") is not True:
                continue
            if not (re.search(r"prod|release|store", str(prof), re.I) or cfg.get("distribution") == "store"):
                continue
            m = re.search(r'"%s"\s*:\s*\{' % re.escape(str(prof)), text)
            pos = m.end() if m else 0
            d = re.compile(r'"developmentClient"\s*:\s*true').search(text, pos)
            line = ctx.line_of(path, d.start()) if d else 1
            hits.append(Hit(line, _line_text(ctx, path, line),
                            "EAS build profile %r ships a development client to the store" % prof))
        return hits
    if path not in _deploy_files(ctx):
        return []
    scripts = _scripts_near(ctx, path)
    start_flagged = bool(scripts.get("start")) and _classify_cmd(scripts["start"], scripts, package_start=True) is not None
    for line, cmd in _start_commands(ctx, path, text):
        r = _classify_cmd(cmd, scripts)
        if r and start_flagged and "'start' script" in r[0]:
            continue  # package.json "start" is reported; that is where the fix goes
        if r:
            hits.append(Hit(line, _line_text(ctx, path, line),
                            "Production start command runs %s; dev servers are not built for public traffic and "
                            "expose debug features" % r[0], r[1]))
    return hits


# ---------------------------------------------------------------------------
# NODE_ENV and error handlers
# ---------------------------------------------------------------------------

# The opening of a parameter list whose first name looks like an error.
_ERR_HEAD = re.compile(r"\(\s*(?:err|error|e|ex|exc|exception|_err|_error|_e|_)\s*[:,]")
_ERR_PARAMS = (re.compile(r"(?:req|request|_[\w$]*|_)$"), re.compile(r"(?:res|response|_[\w$]*|_)$"),
               re.compile(r"(?:next|nxt|_[\w$]*|_)$"))
_NODE_ENV_PROD = re.compile(r"""NODE_ENV["']?\s*[=:\s]\s*["']?production|key:\s*NODE_ENV\s*\n\s*value:\s*["']?production""")


def _has_error_handler(ctx: Any, rel: str, text: str) -> bool:
    """True when the file defines a 4-parameter Express error handler (err, req, res, next).

    Parameters may carry TypeScript types (unions, generics), be spread over
    lines, and end with a trailing comma.
    """
    if not _ERR_HEAD.search(text):
        return False
    code = _code(ctx, rel, text)
    for m in _ERR_HEAD.finditer(code.view):
        c = _close_of(code, m.start())
        if c is None:
            continue
        args = _split_args(code, m.start(), c)
        if len(args) != 4:
            continue
        names = []
        for a, b in args[1:]:
            nm = re.match(r"\s*([\w$]+)\s*\??\s*(?::|=|$)", code.view[a:b])
            names.append(nm.group(1) if nm else "")
        if all(rx.match(n) for rx, n in zip(_ERR_PARAMS, names)):
            return True
    return False


def check_node_env(path: str, text: str, ctx: Any) -> List[Hit]:
    if "express" not in ctx.deps:
        return []
    deploy = list(_deploy_files(ctx))
    if not deploy:
        return []
    js = [f for f in ctx.files if f.endswith((".js", ".ts", ".mjs", ".cjs", ".mts", ".cts"))
          and not match_any(f, _TESTS)]
    server = None
    for f in js:
        t = ctx.read(f)
        if not t:
            continue
        if _has_error_handler(ctx, f, t):
            return []
        if server is None and re.search(r"\bexpress\s*\(\s*\)", t) and re.search(r"\.listen\s*\(", t):
            server = f
    if server is None:
        return []
    others = list(deploy) + ["package.json"] + [f for f in ctx.files if is_env_file(f) and not is_example_file(f)]
    for f in others:
        if _NODE_ENV_PROD.search(ctx.read(f)):
            return []
    target = deploy[0]
    cmds = _start_commands(ctx, target, ctx.read(target))
    line = cmds[0][0] if cmds else 1
    return [Hit(line, _line_text(ctx, target, line),
                "Express app (%s) is deployed without NODE_ENV=production and has no error handler of its own, so "
                "Express's default handler sends stack traces to clients" % server, None, target)]


_RESP_CALL_JS = re.compile(
    r"(?<![\w$.])(?:res|response|reply)\s*(?:\.\s*status\s*\([^()]*\)\s*)?\.\s*(?:json|send|end|write|jsonp)\s*\("
    r"|(?<![\w$])(?:NextResponse|Response)\s*\.\s*json\s*\(|\bnew\s+(?:Response|NextResponse)\s*\("
    r"|(?<![\w$.])c\s*\.\s*(?:json|text)\s*\(")
_ENV_GUARD = re.compile(r"NODE_ENV|isDev\b|isDevelopment|isProd\b|isProduction|development|process\.env\.DEBUG|app\.get\(\s*['\"]env")
_PY_RESPONSE = re.compile(r"^\s*return\b|\b(?:jsonify|JSONResponse|HTTPException|Response|make_response|HttpResponse|"
                          r"JsonResponse|abort)\s*\(|\bdetail\s*=")


def _import_names(code: _Code, pkgs: str) -> List[str]:
    """Local names bound to a package by import or require (comments ignored); pkgs is a regex."""
    rx = re.compile(r"""(?:\bimport\s+(?:\*\s+as\s+)?([\w$]+)(?:\s*,\s*\{[^}]*\})?\s+from\s*|"""
                    r"""\bimport\s+([\w$]+)\s*=\s*require\s*\(\s*|"""
                    r"""\b(?:const|let|var)\s+([\w$]+)\s*=\s*require\s*\(\s*)['"](?:%s)['"]""" % pkgs)
    return sorted(set(m.group(1) or m.group(2) or m.group(3) for m in rx.finditer(code.nocomment)))


def _guarded_line(ctx: Any, path: str, code: _Code, text: str, pos: int) -> bool:
    """True when pos sits under a development-only condition: an enclosing if block,
    an `if (...)` or `cond &&` on the same line, or a brace-less `if (...)` on the line above."""
    if _in_dev_branch(code, text, pos):
        return True
    line = ctx.line_of(path, pos)
    lines = ctx.lines(path)
    start = text.rfind("\n", 0, pos) + 1
    before = text[start:pos]
    if re.search(r"\bif\s*\(|&&|\?", before) and _DEV_COND.search(before):
        return True
    k = line - 2
    while k >= 0 and not lines[k].strip():
        k -= 1
    if k >= 0:
        m = re.match(r"\s*(?:else\s+)?if\s*\((.*)\)\s*$", lines[k])
        if m and _DEV_COND.search(m.group(1)):
            return True
    return False


def _errorhandler_hits(ctx: Any, path: str, text: str) -> List[Hit]:
    """app.use(errorhandler()) from the errorhandler package outside a development-only guard."""
    code = _code(ctx, path, text)
    out: List[Hit] = []
    for name in _import_names(code, "errorhandler"):
        for m in re.finditer(r"(?<![\w$.])%s\s*\(" % re.escape(name), code.view):
            span = _enclosing(code, m.start(), "(")
            if not span or not re.search(r"\.\s*use\s*$", code.view[max(0, span[0] - 40):span[0]]):
                continue
            if _guarded_line(ctx, path, code, text, m.start()):
                continue
            line = ctx.line_of(path, m.start())
            out.append(Hit(line, _line_text(ctx, path, line),
                           "errorhandler() is mounted without a development-only guard; it sends the full stack "
                           "trace of every error to the client"))
    return out


def check_error_stack(path: str, text: str, ctx: Any) -> List[Hit]:
    hits: List[Hit] = []
    if path.endswith(".py"):
        if "traceback" not in text:
            return []
        code = _code(ctx, path, text)
        lines = ctx.lines(path)
        for m in re.finditer(r"\btraceback\.format_(?:exc|exception|tb)\s*\(", code.view):
            line = ctx.line_of(path, m.start())
            ln = lines[line - 1] if line <= len(lines) else ""
            prev = "\n".join(lines[max(0, line - 4):line - 1])
            if re.search(r"\bif\b[^\n]*(?:debug|DEBUG)", prev):
                continue
            leak = bool(_PY_RESPONSE.search(ln))
            if not leak:
                v = re.match(r"\s*(\w+)\s*=", ln)
                if v:
                    after = "\n".join(lines[line:line + 6])
                    leak = bool(re.search(r"(?:return\b|jsonify\(|JSONResponse\(|detail\s*=|Response\()[^\n]*\b%s\b"
                                          % re.escape(v.group(1)), after))
            if leak:
                hits.append(Hit(line, ln.strip(), "Response includes a Python traceback; clients see file paths, "
                                                  "code and sometimes secrets"))
        return hits
    if "errorhandler" in text:
        hits.extend(_errorhandler_hits(ctx, path, text))
    if ".stack" not in text:
        return hits
    code = _code(ctx, path, text)
    for m in _RESP_CALL_JS.finditer(code.view):
        o = m.end() - 1
        c = _call_end(code, o)
        if c is None:
            continue
        args = code.view[o:c]
        if not re.search(r"[\w$\])]\s*\.\s*stack\b", args):
            continue
        if _ENV_GUARD.search(text[o:c]):
            continue
        line = ctx.line_of(path, m.start())
        before = "\n".join(ctx.lines(path)[max(0, line - 4):line - 1])
        if re.search(r"\bif\s*\([^\n]*(?:NODE_ENV|isDev|development|isProd)", before):
            continue
        hits.append(Hit(line, _line_text(ctx, path, line),
                        "Error response sends err.stack to the client (file paths, code, sometimes secrets)"))
    return hits


# ---------------------------------------------------------------------------
# Serving the project root
# ---------------------------------------------------------------------------

_JS_STATIC = re.compile(r"(?<![\w$.])(?:express\s*\.\s*static|serveStatic|serve_static)\s*\(")


def _js_static_dir(arg: str) -> Optional[str]:
    """'cwd', 'here', 'parent' or None for the directory an express.static argument names."""
    a = re.sub(r"\s+", "", arg)
    if a in ("'.'", '"."', "'./'", '"./"', "''", '""', "`.`", "`./`", "process.cwd()",
             "path.resolve()", "path.resolve('.')", 'path.resolve(".")', "path.join(process.cwd())",
             "path.resolve(process.cwd())"):
        return "cwd"
    m = re.match(r"^(?:path\.(?:join|resolve)\()?(__dirname|process\.cwd\(\))(?:,(['\"`])(\.{1,2})/?\2)?\)?$", a)
    if m and (a.startswith("path.") or a in ("__dirname", "process.cwd()")):
        if m.group(1) == "process.cwd()":
            return "cwd" if m.group(3) in (None, ".") else "parent-cwd"
        if m.group(3) == "..":
            return "parent"
        return "here"
    return None


def check_static_root(path: str, text: str, ctx: Any) -> List[Hit]:
    name = _name(path)
    hits: List[Hit] = []
    depth = path.count("/")
    if name == "firebase.json":
        data = ctx.json(path)
        hosting = data.get("hosting") if isinstance(data, dict) else None
        items = hosting if isinstance(hosting, list) else [hosting] if isinstance(hosting, dict) else []
        for h in items:
            if not isinstance(h, dict) or str(h.get("public", "x")).strip() not in (".", "./", ""):
                continue
            ignore = h.get("ignore") or []
            dot_ok = any(str(x).strip() in ("**/.*", ".*", "**/.**") for x in ignore) if isinstance(ignore, list) else False
            m = re.search(r'"public"\s*:\s*"\.?/?"', text)
            line = ctx.line_of(path, m.start()) if m else 1
            hits.append(Hit(line, _line_text(ctx, path, line),
                            "Firebase Hosting deploys the whole project folder (\"public\": \".\"), including source "
                            "and any key files" + ("" if dot_ok else " and dotfiles such as .env"),
                            "medium" if dot_ok else "high"))
        return hits
    if _is_docker(path) or name == "Procfile":
        if _is_dev_named(path):
            return []
        if _is_docker(path):
            for ln, ins, args in _docker_instructions(text):
                if ins in ("COPY", "ADD"):
                    a = re.sub(r"--\S+\s+", "", args).split()
                    if len(a) == 2 and a[0] in (".", "./") and re.match(
                            r"/(?:usr/share/nginx/html|var/www/html|usr/local/apache2/htdocs|srv/http|var/www)/?$", a[1]):
                        di = ctx.read(".dockerignore") if ctx.exists(".dockerignore") else ""
                        covered = bool(re.search(r"(?m)^\s*\**/?\.env", di)) and bool(re.search(r"(?m)^\s*\**/?\.git\b", di))
                        # PHP images run the copied code, so a plain PHP site is only a problem when
                        # .env and .git come along. Laravel must serve public/ instead.
                        php_root = a[1].startswith("/var/www") and "nginx" not in text
                        if php_root and covered:
                            if ctx.has_stack("laravel"):
                                hits.append(Hit(ln, _line_text(ctx, path, ln),
                                                "Laravel project copied into the web root; the document root must "
                                                "be public/, or config, storage logs and composer files are served",
                                                "medium"))
                            continue
                        hits.append(Hit(ln, _line_text(ctx, path, ln),
                                        "Dockerfile copies the whole build context into the web root, so the web "
                                        "server serves the repo" + ("" if covered else " (including .env and .git, "
                                                                    "which .dockerignore does not exclude)"),
                                        "medium" if covered else "high"))
        for line, cmd in _start_commands(ctx, path, text):
            if (re.search(r"\bpython3?\s+-m\s+http\.server\b", cmd) and not re.search(r"\s(?:-d|--directory)\b", cmd)) \
                    or re.search(r"(?<![\w.-])(?:npx\s+)?(?:serve|http-server)\s+\.(?:/)?(?:\s|$)", cmd):
                hits.append(Hit(line, _line_text(ctx, path, line),
                                "Start command serves the current folder as static files; .env, .git and source "
                                "become downloadable", "medium"))
        return hits
    if path.endswith(".py"):
        if "static" not in text.lower() and "send_from_directory" not in text:
            return []
        code = _code(ctx, path, text)
        root_vals = r"""(?:(['"])\.?/?\1|os\.getcwd\(\)|BASE_DIR|basedir|ROOT_DIR|app\.root_path|os\.path\.dirname\(\s*(?:os\.path\.abspath\(\s*)?__file__\s*\)?\s*\))"""
        for m in re.finditer(r"\bstatic_folder\s*=\s*" + root_vals + r"\s*[,)]", text):
            if code.view[m.start()] == " ":
                continue
            line = ctx.line_of(path, m.start())
            hits.append(Hit(line, _line_text(ctx, path, line),
                            "Flask static_folder points at the project folder, so app source, .env and .git are served"))
        for m in re.finditer(r"\bStaticFiles\s*\(\s*directory\s*=\s*" + root_vals + r"\s*[,)]", text):
            if code.view[m.start()] == " ":
                continue
            line = ctx.line_of(path, m.start())
            hits.append(Hit(line, _line_text(ctx, path, line),
                            "StaticFiles serves the project folder, so app source, .env and .git are served"))
        for m in re.finditer(r"\bsend_from_directory\s*\(", code.view):
            o = m.end() - 1
            c = _call_end(code, o)
            if c is None:
                continue
            args = _split_args(code, o, c)
            if len(args) < 2:
                continue
            first = re.sub(r"\s+", "", text[args[0][0]:args[0][1]])
            if not re.match(r"^(?:(['\"])\.?/?\1|os\.getcwd\(\)|app\.root_path|BASE_DIR|basedir|ROOT_DIR)$", first):
                continue
            if _string_value(text, args[1][0], args[1][1]) is not None:
                continue
            line = ctx.line_of(path, m.start())
            hits.append(Hit(line, _line_text(ctx, path, line),
                            "send_from_directory serves any requested file from the project folder (.env, source, "
                            "database files)"))
        return hits
    # JS / TS
    if "static" not in text.lower():
        return []
    code = _code(ctx, path, text)
    for m in _JS_STATIC.finditer(code.view):
        o = m.end() - 1
        c = _call_end(code, o)
        if c is None:
            continue
        args = _split_args(code, o, c)
        if not args:
            continue
        kind = _js_static_dir(text[args[0][0]:args[0][1]])
        if kind is None:
            continue
        opts = text[args[1][0]:args[1][1]] if len(args) > 1 else ""
        dot_allow = bool(re.search(r"""dotfiles\s*:\s*['"]allow['"]""", opts))
        is_root = kind in ("cwd", "parent-cwd") or (kind == "here" and depth == 0) or (kind == "parent" and depth <= 1)
        line = ctx.line_of(path, m.start())
        ev = _line_text(ctx, path, line)
        if is_root:
            v = parse_version(ctx.installed_version("express")) if "express" in ctx.deps else None
            old = v is not None and v[0] < 5
            msg = "express.static serves the project root: package.json, server code and database files are public"
            if dot_allow:
                msg += ", and dotfiles: 'allow' also serves .env and .git"
            elif old:
                msg += "; Express 4 also serves .git/config and .git/HEAD (only a dot in the last path part is hidden)"
            hits.append(Hit(line, ev, msg, "critical" if dot_allow else "high"))
        else:
            folder = path.rsplit("/", 1)[0] if kind == "here" else "the parent folder of " + path.rsplit("/", 1)[0]
            hits.append(Hit(line, ev, "express.static serves %s, which holds server code, not a public assets folder"
                                      % (folder + "/" if kind == "here" else folder), "medium"))
    return hits


# ---------------------------------------------------------------------------
# Directory listing
# ---------------------------------------------------------------------------

_SENSITIVE_DIR = re.compile(r"(?i)(?:^|[/_.\s(-])(?:logs?|keys?|secrets?|backups?|bak|dumps?|encrypt\w*|private|creds?|"
                            r"credentials|certs?|ssh|\.?git|\.?env|uploads?|ftp)(?:$|[/_.\s)-])")


def _listing_hit(ctx: Any, path: str, line: int, where: str, what: str) -> Hit:
    sens = bool(_SENSITIVE_DIR.search(where or ""))
    msg = "%s lists the contents of %s, so anyone can browse and download every file in it" % (what, where or "a folder")
    if sens:
        msg += "; the name suggests logs, keys, backups or uploads"
    return Hit(line, _line_text(ctx, path, line), msg, "high" if sens else "medium")


def check_directory_listing(path: str, text: str, ctx: Any) -> List[Hit]:
    name = _name(path)
    hits: List[Hit] = []
    if name.endswith(_JS_EXTS):
        if "serve-index" not in text:
            return []
        code = _code(ctx, path, text)
        for ident in _import_names(code, r"serve-index"):
            for m in re.finditer(r"(?<![\w$.])%s\s*\(" % re.escape(ident), code.view):
                o = m.end() - 1
                c = _call_end(code, o)
                if c is None or _guarded_line(ctx, path, code, text, m.start()):
                    continue
                args = _split_args(code, o, c)
                served = _string_value(text, *args[0]) if args else None
                mount = None
                span = _enclosing(code, m.start(), "(")
                if span and re.search(r"\.\s*use\s*$", code.view[max(0, span[0] - 40):span[0]]):
                    uargs = _split_args(code, span[0], span[1])
                    if uargs:
                        mount = _string_value(text, *uargs[0])
                where = " ".join(x for x in (mount, served and "(folder %s)" % served) if x) or None
                hits.append(_listing_hit(ctx, path, ctx.line_of(path, m.start()), where or "", "serve-index"))
        return hits
    lines = ctx.lines(path)
    if name == "Caddyfile" or name.endswith(".caddy"):
        for i, ln in enumerate(lines, 1):
            s = ln.split("#", 1)[0]
            if re.search(r"\bfile_server\b[^{\n]*\bbrowse\b|^\s*browse\s*(?:\{|$)", s):
                hits.append(_listing_hit(ctx, path, i, "", "Caddy file_server browse"))
        return hits
    location = ""
    directory = ""
    for i, ln in enumerate(lines, 1):
        s = ln.split("#", 1)[0]
        if not s.strip():
            continue
        lm = re.match(r"\s*location\s+(?:[=~^*]+\s*)?(\S+)\s*\{", s)
        if lm:
            location = lm.group(1)
        dm = re.match(r"""\s*<(?:Directory|Location)(?:Match)?\s+["']?([^"'>]+)""", s, re.I)
        if dm:
            directory = dm.group(1).strip()
        if re.match(r"\s*autoindex\s+on\s*;", s):
            hits.append(_listing_hit(ctx, path, i, location, "nginx autoindex on"))
            continue
        om = re.match(r"\s*Options\s+(.+)$", s, re.I)
        if om:
            on = False
            for tok in om.group(1).lower().split():
                if tok in ("indexes", "+indexes", "all"):
                    on = True
                elif tok in ("-indexes", "none"):
                    on = False
            if on:
                hits.append(_listing_hit(ctx, path, i, directory or ("the folder of " + path), "Apache Options Indexes"))
    return hits


_PUBLIC_DIRS = ("public", "static", "public_html", "www", "htdocs")
_SKIP_WALK = frozenset({"node_modules", ".git", ".next", "vendor", "__pycache__"})


def _classify_public_file(name: str) -> Optional[Tuple[str, str]]:
    low = name.lower()
    if low == ".env" or (low.startswith(".env.") and not any(x in low for x in ("example", "sample", "template"))):
        return "critical", "an env file"
    if low.endswith((".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")) or low in ("id_rsa", "id_ed25519", "id_ecdsa"):
        return "critical", "a private key"
    if low.endswith((".sql", ".sqlite", ".sqlite3", ".db", ".dump", ".bak", ".backup", ".mdb")) or low.endswith(".sql.gz"):
        return "high", "a database or backup file"
    if low == ".htpasswd" or low == ".npmrc":
        return "medium", "a credentials file"
    if low.endswith(".log"):
        return "medium", "a log file"
    return None


def check_public_files(path: str, text: str, ctx: Any) -> List[Hit]:
    root = str(ctx.root)
    bases: List[str] = []
    for d in _PUBLIC_DIRS:
        bases.append(d)
    try:
        for top in sorted(os.listdir(root)):
            if top in _SKIP_WALK or top.startswith(".") or not os.path.isdir(os.path.join(root, top)):
                continue
            for d in _PUBLIC_DIRS:
                bases.append(top + "/" + d)
            for sub in sorted(os.listdir(os.path.join(root, top)))[:200]:
                if sub in _SKIP_WALK or sub.startswith("."):
                    continue
                if os.path.isdir(os.path.join(root, top, sub)):
                    for d in _PUBLIC_DIRS:
                        bases.append(top + "/" + sub + "/" + d)
    except OSError:
        pass
    hits: List[Hit] = []
    seen = 0
    for base in bases:
        full = os.path.join(root, base)
        if not os.path.isdir(full):
            continue
        if os.path.isdir(os.path.join(full, ".git")):
            hits.append(Hit(0, base + "/.git/", "%s/.git is inside a served folder; the whole repo history can be "
                                                "downloaded" % base, "critical", base + "/.git"))
        for dirpath, dirnames, filenames in os.walk(full):
            dirnames[:] = [d for d in sorted(dirnames) if d not in _SKIP_WALK]
            for fn in sorted(filenames):
                seen += 1
                if seen > 20000:
                    return hits
                cls = _classify_public_file(fn)
                if not cls:
                    continue
                rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/")
                hits.append(Hit(0, rel, "%s is %s inside a folder the web server or framework serves as-is"
                                        % (rel, cls[1]), cls[0], rel))
    return hits


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

def _obj_has_true(code: _Code, obj: Tuple[int, int], key: str) -> bool:
    for m in re.finditer(r"(?<![\w$.])" + key + r"\s*:\s*true\b", code.view[obj[0]:obj[1]]):
        inner = _enclosing(code, obj[0] + m.start(), "{")
        if inner and inner[0] == obj[0]:
            return True
    return False


_ORIGIN_ALWAYS = re.compile(
    r"(?<![\w$.])origin\s*:\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?\(\s*[\w$]+\s*(?::\s*[\w|<> ]+)?\s*,\s*([\w$]+)"
    r"\s*(?::\s*[\w|<>() =>,]+)?\)\s*(?:=>\s*)?\{?\s*(?:return\s+)?\1\s*\(\s*null\s*,\s*true\s*\)")


def check_cors_node(path: str, text: str, ctx: Any) -> List[Hit]:
    low = text.lower()
    if "cors" not in low and "access-control-allow-origin" not in low:
        return []
    code = _code(ctx, path, text)
    hits: List[Hit] = []

    def add(pos: int, msg: str, sev: Optional[str] = None) -> None:
        line = ctx.line_of(path, pos)
        hits.append(Hit(line, _line_text(ctx, path, line), msg, sev))

    for m in re.finditer(r"(?<![\w$.])origin\s*:\s*true\b", code.view):
        obj = _enclosing(code, m.start(), "{")
        if obj and _obj_has_true(code, obj, "credentials"):
            add(m.start(), "CORS reflects any Origin (origin: true) with credentials: true, so any site can read "
                           "logged-in users' responses")
    for m in _ORIGIN_ALWAYS.finditer(code.view):
        obj = _enclosing(code, m.start(), "{")
        if obj and _obj_has_true(code, obj, "credentials"):
            add(m.start(), "CORS origin callback allows every Origin while credentials: true, so any site can read "
                           "logged-in users' responses")
    for m in re.finditer(r"(?<![\w$.])origin\s*:\s*(?=/)", code.view):
        start = m.end()
        end = _skip_regex(text, start, len(text))
        if end < 0:
            continue
        body = text[start + 1:text.rfind("/", start + 1, end)]
        if body.endswith("$"):
            continue
        obj = _enclosing(code, m.start(), "{")
        if obj and _obj_has_true(code, obj, "credentials"):
            add(m.start(), "CORS origin regex is not anchored with $, so a lookalike domain such as "
                           "yourapp.com.attacker.example passes, with credentials: true", "medium")
    creds = re.search(r"""(?i)access-control-allow-credentials['"]\s*[,:]\s*(?:['"]true['"]|true\b)""", text)
    if creds:
        def allow_check(var: Optional[str]) -> bool:
            names = r"(?:%sorigin|requestOrigin|reqOrigin|(?:req|request)\s*\.\s*headers\s*\.\s*origin)" % (
                re.escape(var) + "|" if var else "")
            rx = re.compile(r"(?:includes|has|indexOf|test|match|some|find)\s*\(\s*%s\b|(?<![\w$.])%s\s*===|"
                            r"===\s*%s\b" % (names, names, names))
            return bool(rx.search(code.view))

        for m in re.finditer(r"(?i)access-control-allow-origin", text):
            if m.start() == 0 or code.view[m.start() - 1] not in "'\"`":
                continue
            tail = text[m.end():m.end() + 160]
            src = re.match(r"""\s*['"`]\s*[,:]\s*(?:(?:req|request|event|ctx)\s*\.\s*(?:headers\s*\.\s*origin|"""
                           r"""headers\s*\[\s*['"]origin['"]\s*\]|headers\s*\.\s*get\(\s*['"]origin['"]\s*\)|"""
                           r"""get\(\s*['"]origin['"]\s*\)|header\(\s*['"]origin['"]\s*\))|([\w$]+)\s*[),}])""", tail, re.I)
            if not src:
                continue
            var = src.group(1)
            if var:
                assigned = re.search(r"\b%s\s*=\s*(?:req|request|event|ctx)\s*\.\s*(?:headers\s*\.\s*origin|headers\s*\[|"
                                     r"headers\s*\.\s*get\(|get\(|header\()" % re.escape(var), text)
                if not assigned:
                    continue
            if allow_check(var):
                continue
            add(m.start(), "Access-Control-Allow-Origin is set to the request's Origin together with "
                           "Allow-Credentials: true, so any site can read logged-in users' responses")
    return hits


def check_cors_python(path: str, text: str, ctx: Any) -> List[Hit]:
    if "cors" not in text.lower():
        return []
    code = _code(ctx, path, text)
    hits: List[Hit] = []

    def add(pos: int, msg: str) -> None:
        line = ctx.line_of(path, pos)
        hits.append(Hit(line, _line_text(ctx, path, line), msg))

    star_vars = set(m.group(1) for m in re.finditer(
        r"""(?m)^\s*(\w+)\s*(?::\s*[\w\[\], ]+)?=\s*[\[(]\s*['"]\*['"]\s*,?\s*[\])]""", text))
    for m in re.finditer(r"\bCORSMiddleware\b", code.view):
        span = _enclosing(code, m.start(), "(")
        if not span:
            continue
        o, c = span
        creds = _kwarg(code, text, o, c, "allow_credentials")
        if not creds or not creds.startswith("True"):
            continue
        origins = (_kwarg(code, text, o, c, "allow_origins") or "").strip()
        regex = (_kwarg(code, text, o, c, "allow_origin_regex") or "").strip()
        star = bool(re.match(r"""^[\[(]\s*['"]\*['"]\s*,?\s*[\])]$""", origins)) or origins in star_vars
        loose = bool(re.match(r"""^r?['"](?:\.\*|\.\+|https?://\.\*|https?://\.\+|\^?\.\*\$?)['"]$""", regex))
        if star or loose:
            add(m.start(), "CORSMiddleware allows every origin with allow_credentials=True; Starlette then reflects "
                           "the request Origin, so any site can read logged-in users' responses")
    if re.search(r"(?m)^[ \t]*CORS_ALLOW_CREDENTIALS[ \t]*=[ \t]*True\b", code.view):
        msg = "django-cors-headers allows all origins with CORS_ALLOW_CREDENTIALS = True; it then reflects the request Origin"
        for m in re.finditer(r"(?m)^[ \t]*(CORS_(?:ORIGIN_ALLOW_ALL|ALLOW_ALL_ORIGINS))[ \t]*=[ \t]*True\b", code.view):
            ov = _django_override(ctx, path, "cors")
            if ov is None:
                add(m.start(1), msg)
            elif ov[0] != "skip":
                line = ctx.line_of(path, m.start(1))
                hits.append(Hit(line, _line_text(ctx, path, line), msg + ", but " + ov[1], "low"))
    if "CORS_ORIGINS" not in text:
        for m in re.finditer(r"(?<![\w.])(?:CORS|cross_origin)\s*\(", code.view):
            o = m.end() - 1
            c = _call_end(code, o)
            if c is None:
                continue
            creds = _kwarg(code, text, o, c, "supports_credentials")
            if not creds or not creds.startswith("True"):
                continue
            origins = _kwarg(code, text, o, c, "origins")
            resources = _kwarg(code, text, o, c, "resources")
            if origins is not None:
                bad = bool(re.match(r"""^(?:['"]\*['"]|[\[(]\s*['"]\*['"]\s*[\])])$""", origins.strip()))
            elif resources is not None:
                inner = re.search(r"""['"]origins['"]\s*:\s*(.+?)(?:,\s*['"]\w+['"]\s*:|\})""", resources)
                bad = inner is None or bool(re.match(r"""^\s*(?:['"]\*['"]|\[\s*['"]\*['"]\s*\])""", inner.group(1)))
            else:
                bad = True
            if bad:
                add(m.start(), "Flask-CORS with supports_credentials=True and no origin allowlist reflects every "
                               "Origin, so any site can read logged-in users' responses")
    return hits


def check_cors_laravel(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path, text)
    creds = None
    for m in re.finditer(r"""(['"])supports_credentials\1\s*=>\s*true\b""", text, re.I):
        if code.view[m.start()] in "'\"":
            creds = m
    if not creds:
        return []
    for m in re.finditer(r"""(['"])allowed_origins\1\s*=>\s*\[\s*(['"])\*\2\s*,?\s*\]""", text):
        if code.view[m.start()] not in "'\"":
            continue
        line = ctx.line_of(path, m.start())
        return [Hit(line, _line_text(ctx, path, line),
                    "config/cors.php allows every origin with supports_credentials => true; check that your CORS "
                    "package does not echo the request Origin")]
    return []


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

_AUTH_WORDS = frozenset({"session", "sess", "sid", "token", "jwt", "auth", "access", "refresh", "remember",
                         "login", "identity", "credential", "credentials", "bearer"})


def _auth_name(name: str) -> bool:
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    toks = set(t for t in re.split(r"[^a-z0-9]+", words.lower()) if t)
    if toks & {"csrf", "xsrf"}:
        return False
    return bool(toks & _AUTH_WORDS)


_JS_COOKIE_CALLS = [
    (re.compile(r"(?<![\w$.])(?:res|response|reply|ctx)\s*\.\s*cookie\s*\("), 0, 2),
    (re.compile(r"(?<![\w$])(?:cookies\s*\(\s*\)\s*\)?|[\w$]*[cC]ookies|cookieStore|cookieJar)\s*\.\s*set\s*\("), 0, 2),
    (re.compile(r"(?<![\w$.])(?:cookie\s*\.\s*)?serialize\s*\("), 0, 2),
    (re.compile(r"(?<![\w$.])setCookie\s*\("), 1, 3),
]
_DEV_COND = re.compile(r"""development|isDev\b|isDevelopment|isLocal|localhost|!==?\s*['"]production['"]|"""
                       r"""['"]production['"]\s*!==?|!\s*(?:isProd|isProduction)\b""")


_PROD_COND = re.compile(r"""^\s*(?:[\w$.\[\]'"()]+\s*===?\s*['"]production['"]|['"]production['"]\s*===?\s*[\w$.\[\]'"()]+"""
                        r"""|isProd|isProduction|IS_PROD|IS_PRODUCTION)\s*$""")


def _in_dev_branch(code: _Code, text: str, pos: int) -> bool:
    """True when pos sits inside `if (<development check>) { ... }`, or in the else
    block of `if (<production check>) { ... }`, up to four blocks out."""
    p = pos
    for _ in range(4):
        blk = _enclosing(code, p, "{")
        if not blk:
            return False
        before = code.view[max(0, blk[0] - 200):blk[0]]
        m = re.search(r"\bif\s*\(([^\n]*)\)\s*$", before)
        if m:
            cond = text[blk[0] - len(before) + m.start(1):blk[0] - len(before) + m.end(1)]
            if _DEV_COND.search(cond):
                return True
        elif re.search(r"\}\s*else\s*$", before):
            # find the opening brace of the if block that this else follows
            close = blk[0] - len(before) + before.rfind("}")
            opened: Optional[int] = None
            depth = 0
            k = close
            while k > max(0, close - 20000):
                ch = code.view[k]
                if ch == "}":
                    depth += 1
                elif ch == "{":
                    depth -= 1
                    if depth == 0:
                        opened = k
                        break
                k -= 1
            if opened is not None:
                pre = code.view[max(0, opened - 200):opened]
                mi = re.search(r"\bif\s*\(([^\n]*)\)\s*$", pre)
                if mi:
                    cond = text[opened - len(pre) + mi.start(1):opened - len(pre) + mi.end(1)]
                    if _PROD_COND.match(cond):
                        return True
        p = blk[0]
    return False


def _resolve_obj(code: _Code, text: str, ident: str) -> Optional[Tuple[int, int]]:
    m = re.search(r"(?:const|let|var)\s+%s\s*(?::\s*[\w<>\[\]., ]+)?=\s*\{" % re.escape(ident), code.view)
    if not m:
        return None
    o = m.end() - 1
    c = _close_of(code, o)
    return (o, c) if c is not None else None


def check_cookie_node(path: str, text: str, ctx: Any) -> List[Hit]:
    if "cookie" not in text.lower():
        return []
    code = _code(ctx, path, text)
    hits: List[Hit] = []
    done = set()

    def add(pos: int, msg: str, sev: Optional[str] = None) -> None:
        line = ctx.line_of(path, pos)
        if (line, msg) in done:
            return
        done.add((line, msg))
        hits.append(Hit(line, _line_text(ctx, path, line), msg, sev))

    def check_obj(obj: Tuple[int, int], session: bool, label: str) -> None:
        o, c = obj
        sec = _prop(code, text, o, c, "secure")
        http = _prop(code, text, o, c, "httpOnly")
        same = _prop(code, text, o, c, "sameSite")
        if sec is not None and re.match(r"false\b", sec) and not _in_dev_branch(code, text, o):
            pos = o + code.view[o:c].find("secure")
            add(pos, "%s sets secure: false, so the cookie also travels over plain HTTP" % label, "medium")
        if session and http is not None and re.match(r"false\b", http):
            pos = o + code.view[o:c].find("httpOnly")
            add(pos, "%s sets httpOnly: false, so any XSS can read the session cookie" % label, "medium")
        if same is not None and re.match(r"""['"`]none['"`]""", same, re.I):
            pos = o + code.view[o:c].find("sameSite")
            add(pos, "%s uses sameSite: 'none', so the cookie is sent on cross-site requests (CSRF and credentialed "
                     "CORS risk)" % label, "low")

    # cookie option objects: express-session, cookie-session, iron-session, socket.io
    for m in re.finditer(r"(?<![\w$.])(?:cookie|cookieOptions|cookieOpts)\s*[:=]\s*\{", code.view):
        o = m.end() - 1
        c = _close_of(code, o)
        if c is not None:
            check_obj((o, c), True, "Cookie options")
    # cookie writes
    for rx, name_i, opt_i in _JS_COOKIE_CALLS:
        for m in rx.finditer(code.view):
            head = text[m.start():m.end()]
            if head.lstrip().startswith(("Cookies.", "Cookie.")):
                continue
            if "serialize" in head and not head.lstrip().startswith("cookie") and not re.search(
                    r"""(?:from\s+['"]cookie['"]|require\(\s*['"]cookie['"]\s*\))""", text):
                continue
            o = m.end() - 1
            c = _call_end(code, o)
            if c is None:
                continue
            args = _split_args(code, o, c)
            if not args:
                continue
            obj_form = False
            a0 = _strip_span(text, *args[0])[0]
            if code.view[a0:a0 + 1] == "{":
                # cookies().set({ name, value, ... })
                c0 = _close_of(code, a0)
                if c0 is None:
                    continue
                nm = _prop(code, text, a0, c0, "name")
                cname = _string_value(nm, 0, len(nm)) if nm else None
                obj = (a0, c0)
                obj_form = True
            else:
                if len(args) <= name_i:
                    continue
                cname = _string_value(text, *args[name_i])
                if cname is None:
                    cname = text[args[name_i][0]:args[name_i][1]].strip()
                obj = None
                if len(args) > opt_i:
                    a, b = _strip_span(text, *args[opt_i])
                    if code.view[a:a + 1] == "{" and _close_of(code, a):
                        obj = (a, _close_of(code, a))
                    elif re.match(r"^[\w$]+$", text[a:b]):
                        obj = _resolve_obj(code, text, text[a:b])
                        if obj is None:
                            continue
                    else:
                        continue
            session = _auth_name(cname or "")
            label = "Cookie %r" % cname if cname and len(cname) < 40 else "Cookie"
            # Clearing a cookie (logout) carries no value worth protecting.
            if not obj_form and len(args) > name_i + 1 and _string_value(text, *args[name_i + 1]) == "":
                continue
            if obj is not None:
                if "..." in code.view[obj[0]:obj[1]]:
                    continue
                if obj_form and re.match(r"""\s*['"`]{2}\s*$""", _prop(code, text, obj[0], obj[1], "value") or "x"):
                    continue
                if re.match(r"0\b|new\s+Date\(\s*0\s*\)", _prop(code, text, obj[0], obj[1], "maxAge")
                            or _prop(code, text, obj[0], obj[1], "expires") or "x"):
                    continue
                check_obj(obj, session, label)
                if session and _prop(code, text, obj[0], obj[1], "httpOnly") is None:
                    add(m.start(), "%s carries a session or token without httpOnly (the default here is off), so "
                                   "any XSS can read it" % label, "medium")
            elif session and not obj_form:
                add(m.start(), "%s carries a session or token without httpOnly, secure or sameSite (the default "
                               "here is off), so any XSS can read it" % label, "medium")
    # raw Set-Cookie header strings
    for m in re.finditer(r"""(?i)set-cookie['"]\s*,\s*([`'"])([^`'"\n]*)""", text):
        if m.start() == 0 or code.view[m.start() - 1] not in "'\"`":
            continue
        val = m.group(2)
        cm = re.match(r"\s*([\w.-]+)\s*=", val)
        if cm and _auth_name(cm.group(1)) and "httponly" not in val.lower():
            add(m.start(), "Set-Cookie header for %r has no HttpOnly flag, so any XSS can read it" % cm.group(1),
                "medium")
    if hits and ctx.is_client_file(path):
        return []  # browser or app code: no server logs or cookies here
    return hits


def check_cookie_python(path: str, text: str, ctx: Any) -> List[Hit]:
    if "cookie" not in text.lower():
        return []
    code = _code(ctx, path, text)
    hits: List[Hit] = []

    def add(pos: int, msg: str, sev: Optional[str] = None) -> None:
        line = ctx.line_of(path, pos)
        hits.append(Hit(line, _line_text(ctx, path, line), msg, sev))

    for m in re.finditer(r"\.\s*set_cookie\s*\(", code.view):
        o = m.end() - 1
        c = _call_end(code, o)
        if c is None:
            continue
        args = _split_args(code, o, c)
        if not args or "**" in code.view[o:c]:
            continue
        key = _kwarg(code, text, o, c, "key")
        if key is not None:
            cname = _string_value(key, 0, len(key)) or key
        else:
            first = text[args[0][0]:args[0][1]]
            if "=" in code.view[args[0][0]:args[0][1]]:
                continue
            cname = _string_value(text, *args[0]) or first.strip()
        session = _auth_name(cname)
        label = "Cookie %r" % cname if len(cname) < 40 else "Cookie"
        value = _kwarg(code, text, o, c, "value")
        if value is None and len(args) > 1 and "=" not in code.view[args[1][0]:args[1][1]]:
            value = text[args[1][0]:args[1][1]].strip()
        max_age = _kwarg(code, text, o, c, "max_age") or _kwarg(code, text, o, c, "expires") or ""
        if (value is not None and re.match(r"""^(?:['"]{2}|None)$""", value)) or re.match(r"0\b", max_age):
            continue  # clearing the cookie
        http = _kwarg(code, text, o, c, "httponly")
        sec = _kwarg(code, text, o, c, "secure")
        same = _kwarg(code, text, o, c, "samesite")
        if session and (http is None or http.startswith("False")):
            add(m.start(), "%s carries a session or token without httponly=True (set_cookie defaults to off), so any "
                           "XSS can read it" % label, "medium")
        if sec is not None and sec.startswith("False"):
            add(m.start(), "%s sets secure=False, so it also travels over plain HTTP" % label, "medium")
        if same is not None and re.match(r"""['"]?none['"]?$""", same.strip(), re.I) and session:
            add(m.start(), "%s uses samesite='none', so it is sent on cross-site requests" % label, "low")
    for m in re.finditer(r"""\bSESSION_COOKIE_HTTPONLY['"]?\]?\s*=\s*False\b""", text):
        in_code = code.view[m.start()] != " "
        in_key = m.start() > 0 and code.view[m.start() - 1] in "'\""
        if not (in_code or in_key):
            continue
        add(m.start(), "SESSION_COOKIE_HTTPONLY is turned off, so any XSS can read the session cookie", "medium")
    return hits


def check_laravel_session(path: str, text: str, ctx: Any) -> List[Hit]:
    hits: List[Hit] = []
    code = _code(ctx, path, text)
    checks = [
        (r"""(['"])http_only\1\s*=>\s*false\b""", "config/session.php turns http_only off, so any XSS can read the "
                                                   "session cookie", "medium"),
        (r"""(['"])secure\1\s*=>\s*false\b""", "config/session.php hardcodes 'secure' => false, so the session "
                                                "cookie travels over plain HTTP", "medium"),
        (r"""(['"])same_site\1\s*=>\s*(['"])none\2""", "config/session.php uses same_site none, so the session "
                                                       "cookie is sent on cross-site requests", "low"),
    ]
    for rx, msg, sev in checks:
        for m in re.finditer(rx, text, re.I):
            if code.view[m.start()] not in "'\"":
                continue
            line = ctx.line_of(path, m.start())
            hits.append(Hit(line, _line_text(ctx, path, line), msg, sev))
    return hits


_PHP_FALSE = re.compile(r"(?i)^\s*(?:false|0|null|['\"](?:0|off|false)?['\"])\s*$")


def _php_array_value(text: str, a: int, b: int, key: str) -> Optional[str]:
    m = re.search(r"""(['"])%s\1\s*=>\s*([^,\]\)\n]+)""" % key, text[a:b], re.I)
    return m.group(2).strip() if m else None


def check_cookie_php(path: str, text: str, ctx: Any) -> List[Hit]:
    low = text.lower()
    if "cookie" not in low:
        return []
    if not path.lower().endswith(".php"):
        return _php_ini_cookie_hits(path, ctx)
    code = _code(ctx, path, text)
    hits: List[Hit] = []

    def add(pos: int, msg: str, sev: Optional[str] = None) -> None:
        line = ctx.line_of(path, pos)
        hits.append(Hit(line, _line_text(ctx, path, line), msg, sev))

    for m in re.finditer(r"(?<![\w$>:])(setcookie|setrawcookie)\s*\(", code.view, re.I):
        o = m.end() - 1
        c = _call_end(code, o)
        if c is None:
            continue
        args = _split_args(code, o, c)
        if len(args) < 2 or re.match(r"\s*\w+\s*:", code.view[args[0][0]:args[0][1]]):
            continue  # name only (clears the cookie) or PHP 8 named arguments
        cname = _string_value(text, *args[0])
        if cname is None:
            cname = text[args[0][0]:args[0][1]].strip().lstrip("$")
        if not _auth_name(cname):
            continue
        value = text[args[1][0]:args[1][1]].strip()
        if re.match(r"""^(?:''|""|null|false)$""", value, re.I):
            continue  # clearing the cookie
        label = "%s for %r" % (m.group(1), cname) if len(cname) < 40 else m.group(1)
        httponly = secure = None
        if len(args) >= 3:
            a, b = _strip_span(text, *args[2])
            third = text[a:b]
            if re.match(r"time\s*\(\s*\)\s*-", third):
                continue  # expiry in the past: clearing the cookie
            opts = None
            if third.startswith("[") or re.match(r"array\s*\(", third, re.I):
                opts = (a, b)
            elif re.match(r"^\$\w+$", third):
                # a bare variable is an expiry time or an options array; read it only when it is
                # clearly an expiry, otherwise the flags cannot be known here
                assigned = re.search(r"%s\s*=(?!=)\s*([^;]*)" % re.escape(third), text)
                if not assigned or not re.match(r"(?:time\s*\(|strtotime\s*\(|\d|mktime\s*\()", assigned.group(1)):
                    continue
            if opts is not None:
                httponly = _php_array_value(text, opts[0], opts[1], "httponly")
                secure = _php_array_value(text, opts[0], opts[1], "secure")
            else:
                if len(args) >= 7:
                    httponly = text[args[6][0]:args[6][1]].strip()
                if len(args) >= 6:
                    secure = text[args[5][0]:args[5][1]].strip()
        if httponly is not None and not _PHP_FALSE.match(httponly):
            continue  # true, or a variable we cannot read
        extra = "" if (secure is not None and not _PHP_FALSE.match(secure)) else " and without Secure"
        add(m.start(), "%s sets a session or token cookie without HttpOnly%s (setcookie defaults both to off), so "
                       "any XSS can read it" % (label, extra))
    for m in re.finditer(r"""(?i)\bini_set\s*\(\s*['"]session\.cookie_(httponly|secure)['"]\s*,\s*([^)]+)\)""", text):
        if code.view[m.start()] == " ":
            continue
        if _PHP_FALSE.match(m.group(2)):
            add(m.start(), "ini_set turns session.cookie_%s off for the PHP session cookie" % m.group(1).lower())
    for m in re.finditer(r"(?<![\w$>:])session_set_cookie_params\s*\(", code.view, re.I):
        o = m.end() - 1
        c = _call_end(code, o)
        if c is None:
            continue
        args = _split_args(code, o, c)
        if not args:
            continue
        a, b = _strip_span(text, *args[0])
        if text[a:a + 1] == "[" or re.match(r"array\s*\(", text[a:b], re.I):
            val = _php_array_value(text, a, b, "httponly")
        else:
            val = text[args[4][0]:args[4][1]].strip() if len(args) >= 5 else None
        if val is not None and _PHP_FALSE.match(val):
            add(m.start(), "session_set_cookie_params turns httponly off for the PHP session cookie")
    return hits


def _php_ini_cookie_hits(path: str, ctx: Any) -> List[Hit]:
    """php.ini, .user.ini and .htaccess (php_flag) lines that turn a session cookie flag off."""
    hits: List[Hit] = []
    for i, ln in enumerate(ctx.lines(path), 1):
        m = re.match(r"""\s*(?:php_(?:admin_)?(?:flag|value)\s+)?session\.cookie_(httponly|secure)\s*=?\s*["']?(0|off|false)["']?\s*$""",
                     ln, re.I)
        if m:
            hits.append(Hit(i, ln.strip(), "session.cookie_%s is turned off for the PHP session cookie"
                            % m.group(1).lower()))
    return hits


# ---------------------------------------------------------------------------
# Security headers (project level, low)
# ---------------------------------------------------------------------------

_HEADER_NAMES = re.compile(r"(?i)content-security-policy|x-frame-options|strict-transport-security|x-content-type-options")
# A header name used as a value in code: a quoted key, not a word in a comment.
_QUOTED_HEADER = re.compile(r"""(?i)['"`](?:content-security-policy(?:-report-only)?|x-frame-options|"""
                            r"""strict-transport-security|x-content-type-options)['"`]""")


def _headers_elsewhere(ctx: Any) -> bool:
    def build() -> bool:
        for f in ("vercel.json", "netlify.toml", "firebase.json", "_headers", "public/_headers", "static/_headers"):
            t = ctx.read(f) if ctx.exists(f) else ""
            if t and _HEADER_NAMES.search(t if f.endswith(".json") else _strip_hash_comments(t)):
                return True
        for f in ctx.files:
            n = _name(f)
            if (n.endswith(".conf") or n in ("Caddyfile", "nginx.conf", ".htaccess")) \
                    and _HEADER_NAMES.search(_strip_hash_comments(ctx.read(f))):
                return True
        return False
    return ctx.memo("deploy-headers-elsewhere", build)


def _sets_header_in_code(ctx: Any, rel: str) -> bool:
    t = ctx.read(rel)
    if not t or not _HEADER_NAMES.search(t):
        return False
    return bool(_QUOTED_HEADER.search(_code(ctx, rel, t).nocomment))


def check_nextjs_headers(path: str, text: str, ctx: Any) -> List[Hit]:
    if "next" not in ctx.deps:
        return []
    if any(d in ctx.deps for d in ("@next-safe/middleware", "next-safe", "@nosecone/next", "nosecone",
                                   "next-secure-headers", "helmet")):
        return []
    configs = sorted((f for f in ctx.files if re.match(r"next\.config\.(?:js|mjs|cjs|ts|mts)$", _name(f))),
                     key=lambda f: (f.count("/"), f))
    for f in configs:
        t = ctx.read(f)
        if re.search(r"\bheaders\s*(?:\(|:)", _code(ctx, f, t).view) or _sets_header_in_code(ctx, f):
            return []
    for f in ctx.files:
        if re.match(r"(?:src/)?(?:middleware|proxy)\.(?:js|ts|mjs)$", f) and _sets_header_in_code(ctx, f):
            return []
    if _headers_elsewhere(ctx):
        return []
    if configs:
        f = configs[0]
        m = re.search(r"(?m)^.*(?:nextConfig|module\.exports|export\s+default).*$", ctx.read(f))
        line = ctx.line_of(f, m.start()) if m else 1
        return [Hit(line, _line_text(ctx, f, line),
                    "No security headers (CSP, HSTS, nosniff, frame-ancestors) are set in next.config headers(), "
                    "proxy/middleware or the host config", None, f)]
    # Point at the manifest that declares next (it may sit in a subfolder).
    manifests = sorted((f for f in ctx.files if _name(f) == "package.json"), key=lambda f: (f.count("/"), f))
    pkg, m = None, None
    for f in manifests:
        m = re.search(r'"next"\s*:', ctx.read(f) or "")
        if m:
            pkg = f
            break
    if pkg is None:
        return []
    line = ctx.line_of(pkg, m.start())
    return [Hit(line, _line_text(ctx, pkg, line),
                "No security headers (CSP, HSTS, nosniff, frame-ancestors) are set anywhere in this Next.js app",
                None, pkg)]


def check_express_helmet(path: str, text: str, ctx: Any) -> List[Hit]:
    if "express" not in ctx.prod_deps and "express" not in ctx.deps:
        return []
    hits: List[Hit] = []
    app_file = None
    app_pos = 0
    for f in ctx.files:
        if not f.endswith(_JS_EXTS) or f.endswith((".jsx", ".tsx")) or match_any(f, _TESTS):
            continue
        t = ctx.read(f)
        if not t or "express" not in t or ctx.is_client_file(f):
            continue
        if "helmet" in t:
            code = _code(ctx, f, t)
            for m in re.finditer(r"(?<![\w$.])helmet\s*\(\s*\{", code.view):
                o = m.end() - 1
                c = _close_of(code, o)
                if c is not None and re.search(r"(?<![\w$.])contentSecurityPolicy\s*:\s*false\b", code.view[o:c]):
                    line = ctx.line_of(f, m.start())
                    hits.append(Hit(line, _line_text(ctx, f, line),
                                    "helmet is used with contentSecurityPolicy: false, so pages get no CSP",
                                    None, f))
        if app_file is None:
            m = re.search(r"(?<![\w$.])express\s*\(\s*\)", _code(ctx, f, t).nocomment)
            if m:
                app_file, app_pos = f, m.start()
    if app_file is None or _helmet_called(ctx):
        return hits
    rx = re.compile(r"""(?i)(?:setHeader|header|set)\s*\(\s*['"](?:x-content-type-options|content-security-policy|"""
                    r"""strict-transport-security|x-frame-options)""")
    for f in ctx.files:
        if f.endswith(_JS_EXTS) and rx.search(ctx.read(f)) and rx.search(_code(ctx, f, ctx.read(f)).nocomment):
            return hits
    if _headers_elsewhere(ctx):
        return hits
    line = ctx.line_of(app_file, app_pos)
    if "helmet" in ctx.deps:
        msg = ("helmet is in package.json but never called (app.use(helmet()) is missing or commented out), so the "
               "Express app sets no security headers")
    else:
        msg = "Express app sets no security headers (no helmet, no CSP, HSTS or nosniff)"
    hits.append(Hit(line, _line_text(ctx, app_file, line), msg, None, app_file))
    return hits


def _helmet_called(ctx: Any) -> bool:
    """True when server code calls helmet (helmet(), helmet.hsts(), or the name it was imported as)."""
    def build() -> bool:
        for f in ctx.files:
            if not f.endswith(_JS_EXTS) or match_any(f, _TESTS) or ctx.is_client_file(f):
                continue
            t = ctx.read(f)
            if not t or "helmet" not in t:
                continue
            code = _code(ctx, f, t)
            names = set(_import_names(code, r"helmet|koa-helmet")) | {"helmet"}
            for n in names:
                if re.search(r"(?<![\w$.])%s\s*(?:\.\s*[\w$]+\s*)?\(" % re.escape(n), code.view):
                    return True
        return False
    return ctx.memo("deploy-helmet-called", build)


# ---------------------------------------------------------------------------
# Source maps
# ---------------------------------------------------------------------------

_MAP_DELETE = re.compile(r"filesToDeleteAfterUpload|deleteSourcemapsAfterUpload\s*:\s*true|deleteFilesAfterUpload")
_OSI_ID = re.compile(r"(?i)^(?:MIT(?:-0)?|ISC|0BSD|BSD-[234]-Clause(?:-[\w-]+)?|Apache-2\.0|MPL-2\.0|EPL-2\.0|"
                     r"(?:L|A)?GPL-[23]\.0(?:-only|-or-later|\+)?|LGPL-2\.1(?:-only|-or-later|\+)?|Unlicense|Zlib|"
                     r"Artistic-2\.0|BSL-1\.0|CC0-1\.0|EUPL-1\.2|BlueOak-1\.0\.0)$")
_LICENSE_TEXT = [
    ("MIT", "Permission is hereby granted, free of charge"),
    ("BSD", "Redistribution and use in source and binary forms"),
    ("Apache-2.0", "Apache License"),
    ("AGPL", "GNU AFFERO GENERAL PUBLIC LICENSE"),
    ("LGPL", "GNU LESSER GENERAL PUBLIC LICENSE"),
    ("GPL", "GNU GENERAL PUBLIC LICENSE"),
    ("MPL-2.0", "Mozilla Public License"),
    ("ISC", "Permission to use, copy, modify, and/or distribute this software for any"),
    ("Unlicense", "This is free and unencumbered software released into the public domain"),
]


_LICENSE_FILES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE", "LICENCE.md", "COPYING", "COPYING.md")


def _open_source_license(ctx: Any, rel: str) -> Optional[str]:
    """The open-source license of the project that owns this config, or None.

    Needs a LICENSE/COPYING file (nearest folder up to the root) with an
    open-source license text. A package.json "license" field alone does not
    count, because npm init writes "ISC" into every new package, and
    "private": true only blocks npm publishing, so it says nothing either way.
    The SPDX id from the nearest package.json is shown when it is one.
    """
    folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
    spdx = None
    while True:
        data = ctx.json((folder + "/package.json") if folder else "package.json")
        if spdx is None and isinstance(data, dict) and isinstance(data.get("license"), str) \
                and _OSI_ID.match(data["license"].strip()):
            spdx = data["license"].strip()
        for f in _LICENSE_FILES:
            p = (folder + "/" + f) if folder else f
            if ctx.exists(p):
                head = ctx.read(p)[:6000].lower()
                for lid, marker in _LICENSE_TEXT:
                    if marker.lower() in head:
                        return spdx or lid
                return None  # a license file that is not an open-source license
        if not folder:
            return None
        folder = folder.rsplit("/", 1)[0] if "/" in folder else ""


def check_source_maps(path: str, text: str, ctx: Any) -> List[Hit]:
    hits = _source_map_hits(path, text, ctx)
    lic = _open_source_license(ctx, path) if hits else None
    if not lic:
        return hits
    note = ("; the project declares an open-source license (%s), so the maps mostly reveal code that is already "
            "public (confirm the deployed build matches the public repo)" % lic)
    return [h._replace(message=(h.message or "") + note, severity="low") for h in hits]


def _source_map_hits(path: str, text: str, ctx: Any) -> List[Hit]:
    name = _name(path)
    hits: List[Hit] = []
    code = _code(ctx, path, text) if name != "package.json" else None

    def add(pos: int, msg: str, sev: Optional[str] = None) -> None:
        line = ctx.line_of(path, pos)
        hits.append(Hit(line, _line_text(ctx, path, line), msg, sev))

    if name.startswith("next.config."):
        if _MAP_DELETE.search(text):
            return []
        for m in re.finditer(r"(?<![\w$.])productionBrowserSourceMaps\s*:\s*true\b", code.view):
            add(m.start(), "productionBrowserSourceMaps: true publishes the full original source of every page "
                           "to the browser")
        return hits
    if name.startswith("vite.config."):
        if _MAP_DELETE.search(text):
            return []
        for m in re.finditer(r"(?<![\w$.])sourcemap\s*:\s*", code.view):
            obj = _enclosing(code, m.start(), "{")
            if not obj:
                continue
            key = re.search(r"([\w$]+)\s*:\s*$", code.view[max(0, obj[0] - 60):obj[0]])
            if not key or key.group(1) not in ("build", "output"):
                continue
            val = text[m.end():m.end() + 20]
            if re.match(r"true\b|['\"]inline['\"]", val):
                add(m.start(), "Vite build.sourcemap is on, so .map files with the original source ship next to "
                               "the bundle")
            elif re.match(r"['\"]hidden['\"]", val):
                add(m.start(), "Vite build.sourcemap is 'hidden': the .map files are still written to dist and get "
                               "deployed unless something deletes them", "low")
        return hits
    if name.startswith("webpack"):
        prod = _is_prod_named(path) or re.search(r"""\bmode\s*:\s*['"]production['"]""", text)
        if not prod:
            return []
        for m in re.finditer(r"""(?<![\w$.])devtool\s*:\s*(['"])((?:inline-|eval-|cheap-|module-)*(?:source-map|eval))\1""", text):
            if code.view[m.start()] == " ":
                continue
            add(m.start(), "webpack production build uses devtool %r, which publishes the original source"
                % m.group(2))
        return hits
    if name == "package.json" and path == "package.json":
        if "react-scripts" not in ctx.deps:
            return []
        data = ctx.json(path)
        scripts = data.get("scripts") if isinstance(data, dict) else None
        build = str(scripts.get("build", "")) if isinstance(scripts, dict) else ""
        if "GENERATE_SOURCEMAP=false" in build.replace(" ", ""):
            return []
        for f in (".env", ".env.production", ".env.production.local"):
            if re.search(r"(?m)^\s*GENERATE_SOURCEMAP\s*=\s*false\b", ctx.read(f) if ctx.exists(f) else ""):
                return []
        m = re.search(r'"build"\s*:', text) or re.search(r'"react-scripts"\s*:', text)
        add(m.start() if m else 0, "Create React App writes production source maps unless GENERATE_SOURCEMAP=false "
                                   "is set", "low")
    return hits


# ---------------------------------------------------------------------------
# Secrets and PII in logs
# ---------------------------------------------------------------------------

_JS_LOG = re.compile(r"(?<![\w$.])(?:console\s*\.\s*(?:log|info|debug|warn|error|trace|dir)|"
                     r"(?:logger|log|winston|pino|fastify\.log|req\.log|app\.log)\s*\.\s*"
                     r"(?:log|info|debug|warn|error|trace|fatal|verbose|silly|http))\s*\(")
_JS_LOG_HINT = re.compile(r"(?:console|log|logger|winston|pino)\s*\.\s*\w+\s*\(")
_AUTH_PATH = re.compile(r"(?i)log-?in|sign-?in|sign-?up|register|auth|passw|reset|otp|verify|session|account")

# Identifier chains in log arguments (strings already blanked), and the endings
# of names that hold a secret value.
_IDENT_CHAIN = re.compile(r"(?<![\w$.])((?:[A-Za-z_$][\w$]*\s*(?:\?\.|\.)\s*)*[A-Za-z_$][\w$]*)")
_SECRET_END = ("password", "passwd", "secret", "token", "apikey", "privatekey", "jwt", "authorization",
               "credentials", "secretkey")
_NOT_SECRET = frozenset({"csrftoken", "xsrftoken", "pagetoken", "nextpagetoken", "continuationtoken",
                         "cursortoken", "maxtoken", "notoken", "hastoken", "hassecret", "haspassword",
                         # public by design: echoed back to the caller, or a shareable code
                         "validationtoken", "checkouttoken", "coupontoken", "promotoken"})
# First word of a name that holds a flag, a message or a derived value, not the secret itself.
_NOT_SECRET_FIRST = frozenset({"is", "has", "missing", "no", "should", "needs", "need", "requires", "require",
                               "show", "enable", "enabled", "use", "can", "did", "was", "hash", "hashed", "masked",
                               "redacted", "encrypted", "truncated", "obfuscated"})
# Objects whose fields are message text or public codes, not credentials.
_NOT_SECRET_OWNER = re.compile(r"(?i)^(?:i18n|intl|locale|lang|copy|strings?|texts?|labels?|messages?|msgs?|errors?|"
                               r"coupon|promo|promotion|discount|[\w$]*(?:messages|errors|strings|labels|texts))$")
# Calls that hash, mask or shorten a value before it is logged.
_SAFE_WRAP = re.compile(r"(?i)hash|fingerprint|mask|redact|digest|^sha\d*$|hmac|truncate|preview|obfuscat|censor|"
                        r"anonymi[sz]e|scrub|sanitize")
_PRESENCE_AFTER = re.compile(r"\s*(?:(?:\?\.|\.)\s*(?:length|slice|substring|substr|startsWith|endsWith|includes|"
                             r"test)\b|\?(?!\.)|!==?|===?|==|!=|:|\(|\[|&&|is\b|in\b|and\b)")
_PRESENCE_BEFORE = ("!!", "!", "typeof", "Boolean(", "len(", "bool(", "type(", "not", "isinstance(", "keys(",
                    " if", "(if")


def _name_words(name: str) -> List[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w for w in re.split(r"[^a-z0-9]+", spaced.lower()) if w]


def _secret_name(chain: str) -> Optional[str]:
    parts = [p.strip() for p in re.split(r"\??\.", chain)]
    last = parts[-1]
    key = last.replace("_", "").lower()
    if key in _NOT_SECRET or key.startswith(("csrf", "xsrf")):
        return None
    words = _name_words(last)
    if words and words[0] in _NOT_SECRET_FIRST and len(words) > 1:
        return None
    if len(parts) > 1 and _NOT_SECRET_OWNER.match(parts[-2]):
        return None
    for end in _SECRET_END:
        if key.endswith(end):
            return last
    return None


def _wrapped_safely(args_view: str, pos: int) -> bool:
    """True when the value at pos is an argument of a hashing or masking call, or the
    search argument of .replace()/.replaceAll() (a redaction)."""
    depth = 0
    k = pos - 1
    first_arg = True
    while k >= 0:
        ch = args_view[k]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth:
                depth -= 1
            elif ch == "(":
                m = re.search(r"([\w$]+)\s*$", args_view[:k])
                callee = m.group(1) if m else ""
                if callee and _SAFE_WRAP.search(callee):
                    return True
                if first_arg and callee in ("replace", "replaceAll"):
                    return True
                first_arg = False
            else:
                first_arg = False
        elif ch == "," and depth == 0:
            first_arg = False
        k -= 1
    return False


def _ident_hits(args_view: str) -> Optional[str]:
    """Name of the first secret-looking value passed to a log call, or None."""
    for m in _IDENT_CHAIN.finditer(args_view):
        name = _secret_name(m.group(1))
        if not name:
            continue
        if _PRESENCE_AFTER.match(args_view, m.end()):
            continue
        if args_view[:m.start()].rstrip().endswith(_PRESENCE_BEFORE):
            continue
        if _wrapped_safely(args_view, m.start()):
            continue
        return name
    return None


def _auth_context(ctx: Any, path: str, line: int) -> bool:
    if _AUTH_PATH.search(path):
        return True
    win = "\n".join(ctx.lines(path)[max(0, line - 25):line])
    return bool(re.search(r"""['"`]/[\w/{}:.-]*(?:log-?in|sign-?in|sign-?up|register|auth|passw|reset|otp)""", win, re.I))


_LOCAL_DIRS = frozenset({"scripts", "script", "bin", "cli", "tools", "seed", "seeds", "seeders", "seeding"})
_LOCAL_NAME = re.compile(r"(?i)(?:^|[._-])(?:seed|seeds|seeder|seeding|emulator)(?:[._-]|$)")


def _local_script(path: str, text: str) -> bool:
    """A CLI, seed or emulator script run by hand: its output goes to a terminal, not to server logs."""
    parts = path.split("/")
    if not (_LOCAL_NAME.search(parts[-1]) or any(p in _LOCAL_DIRS for p in parts[:-1])):
        return False
    return not re.search(r"\.listen\s*\(|createServer\s*\(|export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b",
                         text)


def _literal_assigned(text: str, name: str) -> bool:
    """True when `const name = 'literal'` (a plain, non-empty string) appears in the file."""
    return bool(re.search(r"(?<![\w$.])(?:const|let|var)\s+%s\s*(?::\s*string\s*)?=\s*(['\"`])(?:(?!\1|\$\{)[^\n])+\1\s*[;,\n)]"
                          % re.escape(name), text))


def _failed_response_body(code: _Code, text: str, pos: int, name: str) -> bool:
    """True for `const name = await resp.json()` logged inside `if (!resp.ok)`: the
    value is the error body of a failed call, not the token the name promises."""
    m = re.search(r"(?<![\w$.])(?:const|let|var)\s+%s\s*=\s*(?:await\s+)?([\w$]+)\s*\.\s*(?:json|text)\s*\(\s*\)"
                  % re.escape(name), code.view)
    if not m:
        return False
    resp = re.escape(m.group(1))
    p = pos
    for _ in range(4):
        blk = _enclosing(code, p, "{")
        if not blk:
            return False
        before = text[max(0, blk[0] - 200):blk[0]]
        cond = re.search(r"\bif\s*\(([^\n]*)\)\s*$", before)
        if cond and re.search(r"!\s*%s\s*\.\s*ok\b|%s\s*\.\s*ok\s*===?\s*false|%s\s*\.\s*status\s*(?:>=?\s*[3-5]\d\d|!==?\s*20\d)"
                              % (resp, resp, resp), cond.group(1)):
            return True
        p = blk[0]
    return False


def check_log_node(path: str, text: str, ctx: Any) -> List[Hit]:
    if not _JS_LOG_HINT.search(text):
        return []
    code = _code(ctx, path, text)
    hits: List[Hit] = []
    redact = "redact" in text
    local = _local_script(path, text)
    for m in _JS_LOG.finditer(code.view):
        if redact and "console" not in m.group(0):
            continue
        o = m.end() - 1
        c = _call_end(code, o)
        if c is None:
            continue
        if _guarded_line(ctx, path, code, text, m.start()):
            continue  # if (process.env.NODE_ENV === 'development') console.log(...), with or without braces
        args = code.view[o + 1:c]
        raw = text[o + 1:c]
        line = ctx.line_of(path, m.start())
        ev = _line_text(ctx, path, line)
        if re.search(r"(?<![\w$.])process\s*\.\s*env\b(?!\s*(?:\.|\[|\?\.))", args):
            hits.append(Hit(line, ev, "Logs the whole process.env, so every secret ends up in the logs",
                            "medium" if local else "high"))
            continue
        auth_hdr = re.search(
            r"(?i)(?<![\w$.])(?:req|request)\s*\.\s*(?:headers\s*(?:\.\s*(?:authorization|cookie)\b|\[\s*['\"]"
            r"(?:authorization|cookie)['\"]\s*\]|\.\s*get\s*\(\s*['\"](?:authorization|cookie)['\"]\s*\))|"
            r"(?:get|header)\s*\(\s*['\"](?:authorization|cookie)['\"]\s*\))", raw)
        if auth_hdr and not _PRESENCE_AFTER.match(raw, auth_hdr.end()) \
                and not raw[:auth_hdr.start()].rstrip().endswith(_PRESENCE_BEFORE):
            hits.append(Hit(line, ev, "Logs the Authorization or Cookie header, so session tokens end up in the logs",
                            "high"))
            continue
        all_hdr = re.search(r"(?<![\w$.])(?:req|request)\s*\.\s*headers\b(?!\s*(?:\.|\[))", args)
        if all_hdr and not args[:all_hdr.start()].rstrip().endswith(_PRESENCE_BEFORE):
            hits.append(Hit(line, ev, "Logs all request headers, including Authorization and Cookie", "medium"))
            continue
        if re.search(r"(?<![\w$.])(?:req|request)\s*\.\s*body\s*\.\s*(?:password|passwd|token|secret)\b", args):
            hits.append(Hit(line, ev, "Logs a password or token from the request body", "high"))
            continue
        if re.search(r"(?<![\w$.])(?:req|request)\s*\.\s*body\b(?!\s*(?:\.|\[))", args) and _auth_context(ctx, path, line):
            hits.append(Hit(line, ev, "Logs the whole request body on an auth route, so passwords end up in the logs",
                            "medium"))
            continue
        name = _ident_hits(args)
        if not name or _failed_response_body(code, text, o, name):
            continue
        if _literal_assigned(text, name):
            msg = ("Logs %s, which is a string literal in this file: the value is committed to the repo. If it is a "
                   "real credential, rotate it (rotation.md), load it from env and stop printing it" % name)
        elif local:
            msg = ("Logs the %s value from a local script; it lands in terminal scrollback and CI logs, so print a "
                   "masked form instead" % name)
        else:
            msg = "Logs the %s value; logs are kept long and read by many people and services" % name
        hits.append(Hit(line, ev, msg, "low" if local else "medium"))
    if hits and ctx.is_client_file(path):
        return []  # browser or app code: no server logs or cookies here
    return hits


_PY_LOG = re.compile(r"(?<![\w.])(?:print|pprint|(?:logger|logging|log|_logger|LOGGER|app\.logger|current_app\.logger)"
                     r"\s*\.\s*(?:debug|info|warning|warn|error|exception|critical|log))\s*\(")


def check_log_python(path: str, text: str, ctx: Any) -> List[Hit]:
    code = _code(ctx, path, text)
    hits: List[Hit] = []
    for m in _PY_LOG.finditer(code.view):
        o = m.end() - 1
        c = _call_end(code, o)
        if c is None:
            continue
        args = code.view[o + 1:c]
        raw = text[o + 1:c]
        line = ctx.line_of(path, m.start())
        ev = _line_text(ctx, path, line)
        if re.search(r"(?<![\w.])os\s*\.\s*environ\b(?!\s*(?:\.\s*(?:get|setdefault|pop)\b|\[))", args):
            hits.append(Hit(line, ev, "Logs the whole os.environ, so every secret ends up in the logs", "high"))
            continue
        if re.search(r"(?i)\brequest\s*\.\s*(?:headers|META)\s*(?:\.\s*get\s*\(|\[)\s*['\"](?:authorization|cookie|"
                     r"x-api-key|HTTP_AUTHORIZATION|HTTP_COOKIE)['\"]", raw) \
                or re.search(r"\brequest\s*\.\s*cookies\b(?!\s*(?:\.|\[))", args) \
                or re.search(r"(?i)\brequest\s*\.\s*cookies\s*(?:\.\s*get\s*\(|\[)\s*['\"][\w.-]*(?:session|token|"
                             r"auth|jwt|sid)", raw):
            hits.append(Hit(line, ev, "Logs the Authorization header or cookies, so session tokens end up in the logs",
                            "high"))
            continue
        if re.search(r"\brequest\s*\.\s*headers\b(?!\s*(?:\.|\[))", args):
            hits.append(Hit(line, ev, "Logs all request headers, including Authorization and Cookie", "medium"))
            continue
        if re.search(r"(?i)\brequest\s*\.\s*(?:form|json|POST|data|get_json\(\s*\))\s*(?:\.\s*get\s*\(|\[)\s*['\"]"
                     r"(?:password|passwd|token|secret)['\"]", raw):
            hits.append(Hit(line, ev, "Logs a password or token from the request", "high"))
            continue
        if re.search(r"\brequest\s*\.\s*(?:form|json|POST|data|body|get_json\s*\(\s*\))(?!\s*(?:\.|\[))", args) \
                and _auth_context(ctx, path, line):
            hits.append(Hit(line, ev, "Logs the whole request body on an auth route, so passwords end up in the logs",
                            "medium"))
            continue
        name = _ident_hits(args)
        if name:
            hits.append(Hit(line, ev, "Logs the %s value; logs are kept long and read by many people and services"
                            % name, "medium"))
    return hits


_PHP_LOG = re.compile(r"(?:\bLog::(?:\w+)|\bLog::channel\([^)]*\)\s*->\s*\w+|(?<![>:$\w])logger\(\s*\)\s*->\s*\w+|"
                      r"(?<![>:$\w])(?:logger|info|error_log))\s*\(")


def check_log_laravel(path: str, text: str, ctx: Any) -> List[Hit]:
    if "$request" not in text and "$_" not in text and "config(" not in text:
        return []
    code = _code(ctx, path, text)
    hits: List[Hit] = []
    for m in _PHP_LOG.finditer(code.view):
        o = m.end() - 1
        c = _call_end(code, o)
        if c is None:
            continue
        raw = text[o + 1:c]
        args = code.view[o + 1:c]
        line = ctx.line_of(path, m.start())
        ev = _line_text(ctx, path, line)
        if re.search(r"(?<![\w>])config\(\s*\)|\$_ENV\b|getenv\(\s*\)", args):
            hits.append(Hit(line, ev, "Logs the whole config or environment, so every secret ends up in the logs",
                            "high"))
        elif re.search(r"""(?i)\$request\s*->\s*(?:password\b|bearerToken\(|cookie\(|header\(\s*['"](?:authorization|"""
                       r"""cookie)|input\(\s*['"](?:password|token)|get\(\s*['"](?:password|token))""", raw):
            hits.append(Hit(line, ev, "Logs a password, bearer token or cookie from the request", "high"))
        elif re.search(r"\$request\s*->\s*(?:all|input|post|json)\(\s*\)|\$request\s*->\s*headers\b|\$_(?:POST|REQUEST|COOKIE)\b",
                       args):
            hits.append(Hit(line, ev, "Logs the whole request input, so passwords and tokens end up in the logs",
                            "medium"))
    return hits


# ---------------------------------------------------------------------------
# Laravel Ignition
# ---------------------------------------------------------------------------

def check_laravel_ignition(path: str, text: str, ctx: Any) -> List[Hit]:
    comp = ctx.json("composer.json")
    if not isinstance(comp, dict):
        return []
    req = comp.get("require") if isinstance(comp.get("require"), dict) else {}
    dev = comp.get("require-dev") if isinstance(comp.get("require-dev"), dict) else {}
    lock = ctx.json("composer.lock")
    locked: Dict[str, str] = {}
    if isinstance(lock, dict):
        for sec in ("packages", "packages-dev"):
            for p in lock.get(sec) or []:
                if isinstance(p, dict) and p.get("name"):
                    locked[str(p["name"])] = str(p.get("version", ""))
    ctext = ctx.read("composer.json")
    hits: List[Hit] = []
    for name in ("facade/ignition", "spatie/laravel-ignition"):
        if name not in req and name not in dev:
            continue
        m = re.search(r'"%s"\s*:' % re.escape(name), ctext)
        line = ctx.line_of("composer.json", m.start()) if m else 1
        ev = _line_text(ctx, "composer.json", line)
        ver = locked.get(name)
        if ver is None:
            spec = str(req.get(name) or dev.get(name) or "")
            ver = spec if re.match(r"^v?\d+(?:\.\d+){1,2}$", spec.strip()) else None
        if name == "facade/ignition" and ver and version_lt(ver, "2.5.2"):
            hits.append(Hit(line, ev, "facade/ignition %s is affected by CVE-2021-3129 (remote code execution when "
                                      "debug mode is on); upgrade to 2.5.2 or later" % ver, "critical",
                            "composer.json"))
        elif name in req:
            hits.append(Hit(line, ev, "%s (the debug error page) is in production dependencies; move it to "
                                      "require-dev and deploy with composer install --no-dev" % name, None,
                            "composer.json"))
    return hits


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

RULES: List[Rule] = [
    Rule(
        id="deploy-django-debug",
        skill="deploy",
        klass="debug mode in production",
        severity="high",
        stacks=["django"],
        file_globs=_PY,
        exclude_globs=_DEV_SETTINGS + _TESTS,
        pattern="check_django_debug",
        message="Django DEBUG is on (or defaults to on) in a settings module that production may load",
        why=("startproject ships DEBUG = True and agents deploy the generated settings as they are; "
             "the debug page then shows tracebacks, settings and request data to anyone."),
        fp_trap=("DEBUG = True in a dev-only settings module (settings/dev.py, local.py) that production "
                 "never imports is fine. The rule reads DJANGO_SETTINGS_MODULE from the Dockerfile, Procfile, "
                 "compose and env files, manage.py and wsgi.py: when the production module imports this one and "
                 "sets DEBUG off it stays quiet, and when only a production.py that nobody names overrides it "
                 "the finding drops to low. DEBUG read from an env var that defaults to off is fine."),
        fix_ref="stack-python.md#django-debug",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-flask-debug",
        skill="deploy",
        klass="debug mode in production",
        severity="high",
        stacks=["flask"],
        file_globs=_PY + _DEPLOY + _PROD_ENV_FILES,
        exclude_globs=_TESTS,
        pattern="check_flask_debug",
        message="Flask debug mode or the Werkzeug debugger is enabled where production may run it",
        why=("Flask tutorials end with app.run(debug=True) and agents deploy that file with python app.py, or "
             "set FLASK_DEBUG=1 in the Dockerfile to see errors. The Werkzeug debugger runs code on request."),
        fp_trap=("app.run(debug=True) under if __name__ == '__main__' is fine when production starts the app with "
                 "gunicorn, uwsgi or waitress (the rule checks Procfile, Dockerfile and dependencies). FLASK_DEBUG "
                 "in .flaskenv or a local .env is the normal dev setup and is not flagged."),
        fix_ref="stack-python.md#flask-debug",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-laravel-debug",
        skill="deploy",
        klass="debug mode in production",
        severity="high",
        stacks=["laravel"],
        file_globs=[".env", ".env.*", "*.env", "config/app.php"],
        pattern="check_laravel_debug",
        message="Laravel APP_DEBUG is on in a production env file, a committed .env, or config/app.php",
        why=("Laravel's .env.example ships APP_DEBUG=true and agents copy it to the server, or upload the whole "
             "project with its local .env to shared hosting."),
        fp_trap=("APP_DEBUG=true in a local, untracked .env with APP_ENV=local is the normal dev setup and is not "
                 "flagged. .env.example is not scanned. Confirm which env file the server actually loads."),
        fix_ref="stack-laravel.md#debug-mode",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-laravel-ignition",
        skill="deploy",
        klass="debug tooling in production",
        severity="low",
        stacks=["laravel"],
        file_globs=[],
        once=True,
        pattern="check_laravel_ignition",
        message="Ignition (Laravel's debug error page) is installed for production or is a vulnerable version",
        why=("Agents add packages with composer require without --dev, and older Laravel 8 apps still pin "
             "facade/ignition below the CVE-2021-3129 fix."),
        fp_trap=("spatie/laravel-ignition in require-dev is the Laravel default and is fine when production runs "
                 "composer install --no-dev. The CVE only bites with APP_DEBUG on, but upgrade anyway."),
        fix_ref="stack-laravel.md#ignition",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-dev-server-in-prod",
        skill="deploy",
        klass="dev server in production",
        severity="medium",
        stacks=["*"],
        file_globs=_DEPLOY + ["package.json", "eas.json"],
        exclude_globs=["**/node_modules/**"] + _TESTS,
        pattern="check_dev_server",
        message="The production start command runs a development server",
        why=("Asked to deploy to a VPS or PaaS, agents reuse the command that worked locally: npm run dev under "
             "PM2, next dev in a Dockerfile, manage.py runserver or php artisan serve in a Procfile."),
        fp_trap=("Dev-named files (Dockerfile.dev, docker-compose.override.yml, Procfile.dev, .devcontainer) and "
                 "plain docker-compose.yml files used for local work are skipped. In package.json only start "
                 "scripts that are not the template default are flagged (react-scripts start, ng serve and "
                 "expo start are left alone)."),
        fix_ref="stack-express-node.md#dev-server-in-production",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-express-node-env",
        skill="deploy",
        klass="stack traces in production",
        severity="low",
        stacks=["express"],
        file_globs=[],
        once=True,
        pattern="check_node_env",
        message="Express app is deployed without NODE_ENV=production and has no error handler of its own",
        why=("Agents write a Dockerfile or PM2 config that runs node server.js and never set NODE_ENV; Express's "
             "default error handler then returns err.stack in every 500 response."),
        fp_trap=("Many hosts set NODE_ENV=production for you (Heroku's Node buildpack does), and the value may "
                 "live in the host dashboard. Only flagged when a deploy config exists in the repo, none of them "
                 "sets NODE_ENV=production, and the app has no 4-argument error handler (typed, multi-line and "
                 "trailing-comma parameter lists count)."),
        fix_ref="stack-express-node.md#production-mode",
        confidence="low",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-error-stack-leak",
        skill="deploy",
        klass="stack traces in responses",
        severity="medium",
        stacks=["node", "python"],
        file_globs=_JS + _PY,
        exclude_globs=_TESTS,
        pattern="check_error_stack",
        message="An error response sends the stack trace (err.stack, a Python traceback, or the errorhandler middleware) to the client",
        why=("Agents return the full error to make debugging easier and the debug branch ships: "
             "res.status(500).json({ error: err.stack }), return {'error': traceback.format_exc()}, or "
             "app.use(errorhandler()) copied from an Express example."),
        fp_trap=("A stack included only when NODE_ENV is development (or under if app.debug) is fine; the rule "
                 "skips responses whose arguments or enclosing if mention the environment, and errorhandler() "
                 "mounted inside such a check. Logging the stack server-side is fine."),
        fix_ref="stack-express-node.md#error-handler",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-static-project-root",
        skill="deploy",
        klass="sensitive files served",
        severity="high",
        stacks=["*"],
        file_globs=_JS + _PY + ["firebase.json", "Procfile"] + _DOCKER,
        exclude_globs=_TESTS,
        pattern="check_static_root",
        message="Static file serving points at the project folder, so .env, .git, source or database files are downloadable",
        why=("The shortest way to serve a frontend from one server file is express.static(__dirname) or "
             "static_folder='.', and the shortest Firebase or nginx deploy copies the whole folder."),
        fp_trap=("express.static(path.join(__dirname, 'public')) or a dedicated dist/ folder is fine. Express 5 "
                 "hides dotfiles by default, Express 4 still serves .git/config. send_from_directory('.', "
                 "'index.html') with a fixed file name is fine. Firebase skips dotfiles when ignore lists '**/.*'."),
        fix_ref="stack-express-node.md#static-files",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-sensitive-file-public",
        skill="deploy",
        klass="sensitive files served",
        severity="high",
        stacks=["*"],
        file_globs=[],
        once=True,
        pattern="check_public_files",
        message="An env file, key, database dump, backup or log sits inside a folder that is served as-is",
        why=("Agents drop seed dumps, SQLite files and exported backups into public/ or static/ so the app can "
             "fetch them, and copy .env next to the built files."),
        fp_trap=("public/.htaccess, .well-known/, .gitkeep and robots.txt are not flagged. A file in public/ is "
                 "only live if the deploy includes it; check the deployed URL with live-exposure-check."),
        fix_ref="stack-nextjs.md#files-in-public",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-directory-listing",
        skill="deploy",
        klass="directory listing",
        severity="medium",
        stacks=["*"],
        file_globs=_JS + ["*.conf", "nginx.conf", ".htaccess", "Caddyfile", "*.caddy"],
        exclude_globs=_TESTS + ["**/node_modules/**"],
        pattern="check_directory_listing",
        message="Directory listing is on (serve-index, nginx autoindex, Apache Options Indexes or Caddy browse)",
        why=("Asked to let users or admins browse files, agents mount serve-index on a folder or switch on "
             "autoindex, and the folder later fills with logs, backups, keys or uploads."),
        fp_trap=("A listing of a folder that holds only public downloads is a design choice; confirm what the "
                 "folder contains on the server. Severity is high when the path looks like logs, keys, backups, "
                 "uploads or ftp. Listings mounted inside an if (development) check are skipped, and "
                 "Options -Indexes is the safe form."),
        fix_ref="stack-express-node.md#directory-listing",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-cors-credentials-node",
        skill="deploy",
        klass="CORS misconfiguration",
        severity="high",
        stacks=["node"],
        file_globs=_JS,
        exclude_globs=_TESTS,
        pattern="check_cors_node",
        message="CORS reflects any Origin while allowing credentials",
        why=("A CORS error is the most common blocker when the frontend and API live on different domains; the "
             "fastest generated fix is cors({ origin: true, credentials: true })."),
        fp_trap=("Access-Control-Allow-Origin: * without credentials is fine for a public or bearer-token API "
                 "(a browser will not let a page read a credentialed response whose Access-Control-Allow-Origin "
                 "is *). origin: '*' with credentials: true is broken, not exploitable for reading. An exact "
                 "allowlist (Set or array lookup) with credentials is fine. If the API uses Authorization headers "
                 "only, severity drops to medium."),
        fix_ref="stack-express-node.md#cors-with-credentials",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-cors-credentials-python",
        skill="deploy",
        klass="CORS misconfiguration",
        severity="high",
        stacks=["python"],
        file_globs=_PY,
        exclude_globs=_TESTS + _DEV_SETTINGS,
        pattern="check_cors_python",
        message="CORS allows every origin with credentials (FastAPI, django-cors-headers or Flask-CORS reflect the Origin)",
        why=("FastAPI tutorials show allow_origins=['*'] and agents add allow_credentials=True to make cookie "
             "login work; Starlette then echoes any Origin."),
        fp_trap=("allow_origins=['*'] without allow_credentials=True is fine for a public API. An explicit list "
                 "of your own origins with credentials is fine. CORS_ALLOW_ALL_ORIGINS in a dev-only settings "
                 "module is not flagged; in a base module that the production settings import and switch off "
                 "it is skipped, or reported low when no deploy config names that production module."),
        fix_ref="stack-python.md#cors",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-cors-credentials-laravel",
        skill="deploy",
        klass="CORS misconfiguration",
        severity="high",
        stacks=["laravel"],
        file_globs=["config/cors.php"],
        pattern="check_cors_laravel",
        message="config/cors.php allows every origin with supports_credentials => true",
        why=("Agents open CORS fully to unblock a separate SPA frontend and switch on credentials for Sanctum "
             "cookie auth."),
        fp_trap=("allowed_origins ['*'] with supports_credentials false is fine for token APIs. An explicit "
                 "FRONTEND_URL list with credentials is the correct Sanctum setup."),
        fix_ref="stack-laravel.md#cors",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-cookie-flags-node",
        skill="deploy",
        klass="weak cookie flags",
        severity="medium",
        stacks=["node"],
        file_globs=_JS,
        exclude_globs=_TESTS,
        pattern="check_cookie_node",
        message="A session or auth cookie is set without httpOnly, with secure: false, or with sameSite: 'none'",
        why=("secure: false is added to make cookies work on http://localhost and ships; sameSite: 'none' is "
             "added to fix cross-domain login; res.cookie and Next.js cookies().set default httpOnly to off."),
        fp_trap=("secure: process.env.NODE_ENV === 'production' is fine. Non-auth cookies (theme, locale) and "
                 "CSRF/XSRF cookies that JavaScript must read are not flagged. express-session and iron-session "
                 "default to httpOnly, so only an explicit httpOnly: false is flagged there. secure: false inside "
                 "an if (development) branch is skipped."),
        fix_ref="stack-express-node.md#cookie-flags",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-cookie-flags-python",
        skill="deploy",
        klass="weak cookie flags",
        severity="medium",
        stacks=["python"],
        file_globs=_PY,
        exclude_globs=_TESTS + _DEV_SETTINGS,
        pattern="check_cookie_python",
        message="A session or token cookie is set without httponly=True, or with secure=False",
        why=("FastAPI, Flask and Django set_cookie all default httponly to False, and generated login code calls "
             "response.set_cookie('access_token', token) with no flags."),
        fp_trap=("Cookies that are not session or token cookies are not flagged. httponly passed from settings "
                 "(httponly=settings.X) counts as set. Django's own session cookie is HttpOnly by default."),
        fix_ref="stack-python.md#cookies",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-laravel-session-cookie",
        skill="deploy",
        klass="weak cookie flags",
        severity="medium",
        stacks=["laravel"],
        file_globs=["config/session.php"],
        pattern="check_laravel_session",
        message="config/session.php weakens the session cookie (http_only false, secure false, or same_site none)",
        why="Agents loosen session cookie settings to get a cross-domain SPA login working over plain HTTP.",
        fp_trap=("The default 'secure' => env('SESSION_SECURE_COOKIE') is fine; set SESSION_SECURE_COOKIE=true "
                 "in the production env. same_site none is sometimes needed for embedded apps."),
        fix_ref="stack-laravel.md#session-cookies",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-cookie-flags-php",
        skill="deploy",
        klass="weak cookie flags",
        severity="medium",
        stacks=["php"],
        file_globs=["*.php", "php.ini", "*.ini", ".user.ini", ".htaccess"],
        exclude_globs=_TESTS + ["**/vendor/**"],
        pattern="check_cookie_php",
        message="Plain PHP sets a session or token cookie without HttpOnly, or turns the session cookie flags off",
        why=("setcookie('session', $id) is the shortest form in every PHP tutorial, and both HttpOnly and Secure "
             "default to off; ini_set('session.cookie_httponly', 0) is added to let JavaScript read the cookie."),
        fp_trap=("Theme, locale and CSRF cookies are not flagged. A setcookie with httponly passed as a variable, or "
                 "an options array built elsewhere, cannot be read and is skipped. Clearing a cookie (empty value "
                 "or an expiry in the past) is skipped. Laravel's own session cookie is covered by "
                 "deploy-laravel-session-cookie."),
        fix_ref="stack-laravel.md#plain-php-cookies",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-nextjs-no-security-headers",
        skill="deploy",
        klass="missing security headers",
        severity="low",
        stacks=["nextjs"],
        file_globs=[],
        once=True,
        pattern="check_nextjs_headers",
        message="The Next.js app sets no security headers (CSP, HSTS, nosniff, frame-ancestors)",
        why="Headers are not needed for the app to work, so agents never add a headers() block.",
        fp_trap=("Headers may be set by the CDN, reverse proxy or host dashboard; the rule checks next.config "
                 "headers(), proxy.ts/middleware.ts, vercel.json, netlify.toml, _headers and nginx configs in the "
                 "repo (header names in comments do not count). Confirm on the live URL with live-exposure-check "
                 "before reporting."),
        fix_ref="stack-nextjs.md#security-headers",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-express-no-helmet",
        skill="deploy",
        klass="missing security headers",
        severity="low",
        stacks=["express"],
        file_globs=[],
        once=True,
        pattern="check_express_helmet",
        message="The Express app sets no security headers (helmet missing or never called), or turns helmet's CSP off",
        why=("Headers are not needed for the app to work, so agents skip helmet, install it and never call it, "
             "or disable its CSP when an inline script breaks."),
        fp_trap=("A reverse proxy (nginx, Caddy, the host) may add the headers; the rule checks configs in the "
                 "repo only. helmet counts only when server code calls it (a commented-out app.use(helmet()) does "
                 "not). A pure JSON API needs fewer headers than an app that serves HTML."),
        fix_ref="stack-express-node.md#helmet",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-source-maps",
        skill="deploy",
        klass="source maps in production",
        severity="medium",
        stacks=["node"],
        file_globs=["next.config.*", "vite.config.*", "webpack*.js", "webpack*.ts", "webpack*.cjs", "webpack*.mjs",
                    "package.json"],
        exclude_globs=["**/node_modules/**"],
        pattern="check_source_maps",
        message="The production build publishes source maps (the original source code)",
        why=("productionBrowserSourceMaps or build.sourcemap: true is copied in to debug a production error and "
             "never removed; Create React App emits maps unless told not to."),
        fp_trap=("Maps uploaded to an error tracker and deleted before deploy (filesToDeleteAfterUpload, "
                 "deleteSourcemapsAfterUpload) are fine and skip the rule. Open-source frontends lose little: with "
                 "an open-source LICENSE file the finding drops to low (a package.json license alone does not "
                 "count, npm init writes ISC everywhere). Vercel Protected Source Maps gate .map files on that host."),
        fix_ref="stack-nextjs.md#source-maps",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-log-secrets-node",
        skill="deploy",
        klass="secrets or PII in logs",
        severity="medium",
        stacks=["node"],
        file_globs=_JS,
        exclude_globs=_TESTS,
        pattern="check_log_node",
        message="Server code logs secrets, tokens, auth headers or request bodies with passwords",
        why=("Debug statements such as console.log(req.body) on the login route, console.log(req.headers) or "
             "console.log(process.env) are added while fixing a bug and never removed."),
        fp_trap=("Logging the presence of a value (!!token, token ? 'set' : 'missing', token.length) or a hashed, "
                 "fingerprinted or redacted form (hash(token), s.replaceAll(token, '[redacted]')) is fine, and so "
                 "are message-catalog keys (messages.missingCredentials) and logs inside an if (development) "
                 "block (with or without braces). Local scripts, CLIs, seeds and emulators (scripts/, bin/, cli/, "
                 "seed/) are reported low. Structured loggers with redact configured are skipped. Browser and app "
                 "code is not checked."),
        fix_ref="stack-express-node.md#logging",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-log-secrets-python",
        skill="deploy",
        klass="secrets or PII in logs",
        severity="medium",
        stacks=["python"],
        file_globs=_PY,
        exclude_globs=_TESTS,
        pattern="check_log_python",
        message="Python code prints or logs os.environ, auth headers, tokens or request bodies with passwords",
        why="print(os.environ) and logger.info(request.json) are added while debugging config or login and stay in.",
        fp_trap=("os.environ.get('X') of one non-secret setting is fine. Logging len(token) or whether a value is "
                 "set is fine. Words inside log strings are ignored, f-string expressions are checked."),
        fix_ref="stack-python.md#logging",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="deploy-log-secrets-laravel",
        skill="deploy",
        klass="secrets or PII in logs",
        severity="medium",
        stacks=["php"],
        file_globs=["*.php"],
        exclude_globs=_TESTS + ["**/vendor/**"],
        pattern="check_log_laravel",
        message="PHP code logs the whole request, a password or token, or the whole config",
        why="Log::info($request->all()) is the quickest way to see what a form posts and it stays in the login controller.",
        fp_trap=("Log::info($request->except(['password', 'token'])) or logging selected fields is fine. "
                 "Logging a user id or route is fine."),
        fix_ref="stack-laravel.md#logging",
        confidence="medium",
        needs_confirmation=True,
    ),
]
