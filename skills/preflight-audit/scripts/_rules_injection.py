"""Injection rules: SQL, NoSQL, OS command, XSS sinks, file uploads, file
paths from the request, and SSRF (threats-logic 3, 4, 6, 7 and the Python
parts of threats-data / threats-exposure).

Most rules here are checks rather than single regexes. A check finds a sink
call in the code (comments and string contents are masked out first), reads
the call's arguments with a small tokenizer that understands JS template
literals, Python f-strings and PHP interpolated strings, and reports only
when a value that is not a constant reaches the sink. A light, same-file
trace follows a variable back to where it was assigned, so

    const sql = `SELECT * FROM users WHERE id = ${id}`; db.query(sql)

is reported while

    const col = SORTABLE.includes(sort) ? sort : 'created_at'

is not. The trace does not follow imports or calls into other functions, so
every rule is a candidate the agent confirms.
"""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from _wardcore import Hit, Rule, clip, parse_version, redact

SKILL = "injection"

# Value levels, from harmless to request input.
SAFE = 0      # constant, sanitized, numeric, config, or picked from an allowlist
UNKNOWN = 1   # a name we cannot follow (a parameter) or an unknown call
DYNAMIC = 2   # data that is not ours: a row field, a response, a loop item
TAINTED = 3   # straight from the request: body, query, params, form, URL

_CODE, _STR, _NONCODE = 0, 1, 2

# Fix references. A bare name that is not in this skill's references/ folder lives in
# skills/secure-by-default/references/.
_SBY = "uploads-and-fetch.md"
_PY_REF = "stack-python.md"
_LARAVEL_REF = "stack-laravel.md"
_NEXT_REF = "stack-nextjs.md"


# ---------------------------------------------------------------------------
# Tokenizers: mark every character as code, string or comment, and record
# string tokens with their interpolation islands.
# ---------------------------------------------------------------------------

class _Tok(object):
    """A string-like literal. start/end: offsets (end exclusive). bs/be: the
    body without quotes. islands: (a, b, pre, post) code spans inside it, with
    the length of the delimiters around them ("${" and "}" -> 2 and 1)."""
    __slots__ = ("start", "end", "quote", "prefix", "islands", "bs", "be")

    def __init__(self, start: int, quote: str, prefix: str = "") -> None:
        self.start = start
        self.end = start
        self.quote = quote
        self.prefix = prefix
        self.islands: List[Tuple[int, int, int, int]] = []
        self.bs = start
        self.be = start


class _Src(object):
    __slots__ = ("text", "lang", "kinds", "toks", "tok_at", "code", "memo")

    def __init__(self, text: str, lang: str) -> None:
        self.text = text
        self.lang = lang
        self.kinds = bytearray(len(text))
        self.toks: List[_Tok] = []
        self.tok_at: Dict[int, _Tok] = {}
        self.code = ""
        self.memo: Dict[Any, Any] = {}

    def finish(self) -> "_Src":
        self.tok_at = {t.start: t for t in self.toks}
        text, kinds = self.text, self.kinds
        self.code = "".join(c if k == _CODE or c == "\n" else " " for c, k in zip(text, kinds))
        return self


def _fill(kinds: bytearray, a: int, b: int, v: int) -> None:
    if b > a:
        kinds[a:b] = bytes([v]) * (b - a)


def _scan_quote(text: str, i: int, n: int, q: str, multiline: bool = False) -> int:
    j = i + 1
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == q:
            return j + 1
        if ch == "\n" and not multiline:
            return j
        j += 1
    return n


_JS_RX_PREV = frozenset("(,=:[!&|?{};+-*%<>~^")
_JS_RX_WORDS = frozenset(["return", "typeof", "case", "do", "else", "in", "of", "void", "yield",
                          "await", "delete", "throw", "new", "instanceof"])


def _scan_regex(text: str, i: int, n: int) -> int:
    j = i + 1
    cls = False
    while j < n:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if ch == "\n":
            return -1
        if cls:
            if ch == "]":
                cls = False
        elif ch == "[":
            cls = True
        elif ch == "/":
            j += 1
            while j < n and text[j].isalpha():
                j += 1
            return j
        j += 1
    return -1


def _tok_js(src: _Src, start: int, end: int) -> None:
    text, kinds = src.text, src.kinds
    n = end
    i = start
    stack: List[list] = []
    last = ""
    word = ""
    while i < n:
        c = text[i]
        if stack and stack[-1][0] == "tpl":
            tok = stack[-1][1]
            if c == "\\":
                _fill(kinds, i, min(i + 2, n), _STR)
                i += 2
                continue
            if c == "`":
                kinds[i] = _STR
                i += 1
                tok.end = i
                tok.be = i - 1
                stack.pop()
                last, word = "`", ""
                continue
            if c == "$" and i + 1 < n and text[i + 1] == "{":
                kinds[i] = _STR
                kinds[i + 1] = _STR
                i += 2
                stack.append(["interp", tok, i, 0])
                last, word = "{", ""
                continue
            kinds[i] = _STR
            i += 1
            continue
        if c in " \t\r\n":
            i += 1
            continue
        nx = text[i + 1] if i + 1 < n else ""
        if c == "/" and nx == "/":
            j = text.find("\n", i, n)
            j = n if j < 0 else j
            _fill(kinds, i, j, _NONCODE)
            i = j
            continue
        if c == "/" and nx == "*":
            j = text.find("*/", i + 2, n)
            j = n if j < 0 else j + 2
            _fill(kinds, i, j, _NONCODE)
            i = j
            continue
        if c == "'" or c == '"':
            j = _scan_quote(text, i, n, c)
            tok = _Tok(i, c)
            tok.end = j
            tok.bs = i + 1
            tok.be = j - 1 if j > i + 1 and text[j - 1] == c else j
            src.toks.append(tok)
            _fill(kinds, i, j, _STR)
            i = j
            last, word = c, ""
            continue
        if c == "`":
            tok = _Tok(i, "`")
            tok.end = n
            tok.bs = i + 1
            tok.be = n
            src.toks.append(tok)
            kinds[i] = _STR
            stack.append(["tpl", tok])
            i += 1
            continue
        if (c == "/" and nx != ">" and (i == 0 or text[i - 1] != "<")
                and (last == "" or last in _JS_RX_PREV or word in _JS_RX_WORDS)):
            j = _scan_regex(text, i, n)
            if j > 0:
                tok = _Tok(i, "/")
                tok.end = j
                tok.bs = i + 1
                tok.be = j
                src.toks.append(tok)
                _fill(kinds, i, j, _STR)
                i = j
                last, word = "/", ""
                continue
        if stack and stack[-1][0] == "interp":
            fr = stack[-1]
            if c == "{":
                fr[3] += 1
            elif c == "}":
                if fr[3] == 0:
                    fr[1].islands.append((fr[2], i, 2, 1))
                    kinds[i] = _STR
                    stack.pop()
                    i += 1
                    continue
                fr[3] -= 1
        if c.isalnum() or c == "_" or c == "$":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_" or text[j] == "$"):
                j += 1
            word = text[i:j]
            last = "a"
            i = j
            continue
        last, word = c, ""
        i += 1


_PY_PREFIXES = frozenset(["r", "b", "u", "f", "rb", "br", "fr", "rf"])


def _tok_py(src: _Src) -> None:
    text, kinds = src.text, src.kinds
    n = len(text)
    i = 0
    while i < n:
        c = text[i]
        if c == "#":
            j = text.find("\n", i)
            j = n if j < 0 else j
            _fill(kinds, i, j, _NONCODE)
            i = j
            continue
        prefix = ""
        if c.isalpha() or c == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            w = text[i:j]
            if j < n and text[j] in "'\"" and w.lower() in _PY_PREFIXES:
                prefix = w
            else:
                i = j
                continue
        if c in "'\"" or prefix:
            q0 = i + len(prefix)
            q = text[q0]
            qq = q * 3 if text.startswith(q * 3, q0) else q
            tok = _Tok(i, qq, prefix)
            _scan_py_string(src, tok, q0 + len(qq), qq, "f" in prefix.lower())
            src.toks.append(tok)
            i = tok.end
            continue
        i += 1


def _scan_py_string(src: _Src, tok: _Tok, j: int, qq: str, is_f: bool) -> None:
    text, kinds = src.text, src.kinds
    n = len(text)
    single = len(qq) == 1
    tok.bs = j
    inner: List[Tuple[int, int]] = []
    closed = False
    while j < n:
        if text.startswith(qq, j):
            tok.be = j
            j += len(qq)
            closed = True
            break
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if single and ch == "\n":
            break
        if is_f and ch == "{":
            if j + 1 < n and text[j + 1] == "{":
                j += 2
                continue
            k = j + 1
            depth = 0
            while k < n:
                ck = text[k]
                if ck in "([{":
                    depth += 1
                elif ck in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif ck in "'\"":
                    if text.startswith(qq, k):
                        break
                    e2 = _scan_quote(text, k, n, ck)
                    inner.append((k, e2))
                    k = e2
                    continue
                elif ck == "\n" and single:
                    break
                k += 1
            tok.islands.append((j + 1, k, 1, 1))
            j = k + 1 if k < n and text[k] == "}" else k
            continue
        if is_f and ch == "}" and j + 1 < n and text[j + 1] == "}":
            j += 2
            continue
        j += 1
    if not closed:
        tok.be = min(j, n)
    tok.end = min(j, n)
    _fill(kinds, tok.start, tok.end, _STR)
    for a, b, _p, _q in tok.islands:
        _fill(kinds, a, b, _CODE)
    for a, b in inner:
        _fill(kinds, a, b, _STR)
        t2 = _Tok(a, text[a])
        t2.end = b
        t2.bs = a + 1
        t2.be = b - 1 if b > a + 1 else b
        src.toks.append(t2)


_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1[ \t]*\r?\n")


def _php_islands(src: _Src, tok: _Tok, j: int, stop: int, q: Optional[str]) -> int:
    """Scan a double-quoted / heredoc / backtick body from j. Returns the index
    after the closing quote (or stop)."""
    text = src.text
    while j < stop:
        ch = text[j]
        if ch == "\\":
            j += 2
            continue
        if q is not None and ch == q:
            tok.be = j
            return j + 1
        if ch == "$" and j + 1 < stop and (text[j + 1].isalpha() or text[j + 1] == "_"):
            k = j + 1
            while k < stop and (text[k].isalnum() or text[k] == "_"):
                k += 1
            if text.startswith("->", k) and k + 2 < stop and (text[k + 2].isalpha() or text[k + 2] == "_"):
                k += 2
                while k < stop and (text[k].isalnum() or text[k] == "_"):
                    k += 1
            elif k < stop and text[k] == "[":
                e2 = text.find("]", k, min(stop, k + 80))
                if e2 > 0:
                    k = e2 + 1
            tok.islands.append((j, k, 0, 0))
            j = k
            continue
        if ch == "{" and j + 1 < stop and text[j + 1] == "$":
            k = j + 1
            depth = 0
            while k < stop:
                if text[k] == "{":
                    depth += 1
                elif text[k] == "}":
                    if depth == 0:
                        break
                    depth -= 1
                k += 1
            tok.islands.append((j + 1, k, 1, 1))
            j = k + 1
            continue
        if ch == "$" and j + 1 < stop and text[j + 1] == "{":
            k = text.find("}", j, stop)
            k = stop if k < 0 else k
            tok.islands.append((j + 2, k, 2, 1))
            j = k + 1
            continue
        j += 1
    tok.be = stop
    return stop


def _tok_php(src: _Src) -> None:
    text, kinds = src.text, src.kinds
    n = len(text)
    i = 0
    incode = False
    while i < n:
        if not incode:
            j = text.find("<?", i)
            if j < 0:
                _fill(kinds, i, n, _NONCODE)
                break
            if text.startswith("<?php", j):
                k = j + 5
            elif text.startswith("<?=", j):
                k = j + 3
            else:
                k = j + 2
            _fill(kinds, i, k, _NONCODE)
            i = k
            incode = True
            continue
        c = text[i]
        if c == "?" and text.startswith("?>", i):
            _fill(kinds, i, i + 2, _NONCODE)
            i += 2
            incode = False
            continue
        if (c == "#" and not text.startswith("#[", i)) or text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            k = text.find("?>", i, j)
            if k >= 0:
                j = k
            _fill(kinds, i, j, _NONCODE)
            i = j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            _fill(kinds, i, j, _NONCODE)
            i = j
            continue
        if c == "'":
            j = _scan_quote(text, i, n, "'", multiline=True)
            tok = _Tok(i, "'")
            tok.end = j
            tok.bs = i + 1
            tok.be = j - 1 if j > i + 1 else j
            src.toks.append(tok)
            _fill(kinds, i, j, _STR)
            i = j
            continue
        if c == '"' or c == "`":
            tok = _Tok(i, c)
            tok.bs = i + 1
            j = _php_islands(src, tok, i + 1, n, c)
            tok.end = j
            src.toks.append(tok)
            _fill(kinds, i, j, _STR)
            for a, b, _p, _q in tok.islands:
                _fill(kinds, a, b, _CODE)
            i = j
            continue
        if c == "<" and text.startswith("<<<", i):
            m = _HEREDOC.match(text, i)
            if m:
                ident = m.group(2)
                body = m.end()
                em = re.compile(r"(?m)^[ \t]*" + re.escape(ident) + r"\b").search(text, body)
                stop = em.start() if em else n
                endi = em.end() if em else n
                tok = _Tok(i, "<<<")
                tok.bs = body
                if m.group(1) != "'":
                    _php_islands(src, tok, body, stop, None)
                tok.be = stop
                tok.end = endi
                src.toks.append(tok)
                _fill(kinds, i, endi, _STR)
                for a, b, _p, _q in tok.islands:
                    _fill(kinds, a, b, _CODE)
                i = endi
                continue
        i += 1


_SCRIPT_BLOCK = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.S | re.I)


def _build_src(text: str, lang: str) -> _Src:
    """lang: js, py, php, or js-embedded (only <script> blocks of an HTML,
    Vue or Svelte file are code)."""
    if lang == "py":
        src = _Src(text, "py")
        _tok_py(src)
    elif lang == "php":
        src = _Src(text, "php")
        _tok_php(src)
    elif lang == "js-embedded":
        src = _Src(text, "js")
        _fill(src.kinds, 0, len(text), _NONCODE)
        for m in _SCRIPT_BLOCK.finditer(text):
            attrs = m.group(1).lower()
            if "src=" in attrs or ("type=" in attrs and not re.search(r"type\s*=\s*['\"]?(?:text/javascript|module|application/javascript|text/babel)", attrs)):
                continue
            _fill(src.kinds, m.start(2), m.end(2), _CODE)
            _tok_js(src, m.start(2), m.end(2))
    else:
        src = _Src(text, "js")
        _tok_js(src, 0, len(text))
    return src.finish()


def _src(ctx: Any, rel: str, lang: Optional[str] = None) -> _Src:
    if lang is None:
        lang = _lang_of(rel)
    return ctx.memo(("ward-inj-src", rel, lang), lambda: _build_src(ctx.read(rel), lang))


_JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts")


def _lang_of(rel: str) -> str:
    low = rel.lower()
    if low.endswith(".py"):
        return "py"
    if low.endswith(".php"):
        return "php"
    if low.endswith(_JS_EXTS):
        return "js"
    return "js-embedded"


# ---------------------------------------------------------------------------
# Span helpers
# ---------------------------------------------------------------------------

def _strip(src: _Src, s: int, e: int) -> Tuple[int, int]:
    text, kinds = src.text, src.kinds
    while s < e and (text[s].isspace() or kinds[s] == _NONCODE):
        s += 1
    while e > s and (text[e - 1].isspace() or kinds[e - 1] == _NONCODE):
        e -= 1
    return s, e


def _match_fwd(src: _Src, i: int, limit: int = 20000) -> int:
    """Index of the bracket that closes the one at i, or -1."""
    text, kinds = src.text, src.kinds
    n = min(len(text), i + limit)
    depth = 0
    j = i
    while j < n:
        if kinds[j] == _CODE:
            c = text[j]
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
                if depth == 0:
                    return j
        j += 1
    return -1


def _match_back(src: _Src, j: int, limit: int = 20000) -> int:
    """Index of the bracket that opens the one at j, or -1."""
    text, kinds = src.text, src.kinds
    lo = max(0, j - limit)
    depth = 0
    i = j
    while i >= lo:
        if kinds[i] == _CODE:
            c = text[i]
            if c in ")]}":
                depth += 1
            elif c in "([{":
                depth -= 1
                if depth == 0:
                    return i
        i -= 1
    return -1


def _call_args(src: _Src, open_i: int, limit: int = 12000) -> Tuple[List[Tuple[int, int]], int]:
    """Top-level argument spans of the call whose "(" is at open_i."""
    text, kinds = src.text, src.kinds
    n = min(len(text), open_i + limit)
    depth = 0
    i = open_i + 1
    start = i
    args: List[Tuple[int, int]] = []
    while i < n:
        if kinds[i] != _CODE:
            i += 1
            continue
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                s, e = _strip(src, start, i)
                if e > s:
                    args.append((s, e))
                return args, i
            depth -= 1
        elif c == "," and depth == 0:
            args.append(_strip(src, start, i))
            start = i + 1
        i += 1
    return args, -1


def _next_sig(src: _Src, i: int, limit: int) -> int:
    text, kinds = src.text, src.kinds
    while i < limit and (text[i].isspace() or kinds[i] == _NONCODE):
        i += 1
    return i


def _expr_end(src: _Src, s: int, stops: str = ";", limit: int = 8000) -> int:
    """End of the expression that starts at s (exclusive)."""
    text, kinds, lang = src.text, src.kinds, src.lang
    n = min(len(text), s + limit)
    depth = 0
    prev = -1
    i = s
    while i < n:
        k = kinds[i]
        c = text[i]
        if k != _CODE:
            if k == _STR:
                prev = i
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0:
            if c in stops:
                return i
            if c == "\n" and lang != "php":
                if lang == "py":
                    j = i - 1
                    while j >= s and text[j] in " \t\r":
                        j -= 1
                    if j < s or text[j] != "\\":
                        return i
                else:
                    pc = text[prev] if prev >= 0 else ""
                    nxt = _next_sig(src, i, n)
                    nc = text[nxt] if nxt < n else ""
                    cont = (prev >= 0 and kinds[prev] == _CODE and pc in "+-*/%=&|^!?:<>,.([{")
                    if not cont and nc and kinds[nxt] == _CODE and nc in "+-*/%&|^?:.,=":
                        cont = not text.startswith(("++", "--"), nxt)
                    if not cont:
                        return i
        if not c.isspace():
            prev = i
        i += 1
    return i


def _split(src: _Src, s: int, e: int, test: Callable[[_Src, int, int, int], int]) -> List[Tuple[int, int]]:
    text, kinds = src.text, src.kinds
    spans: List[Tuple[int, int]] = []
    depth = 0
    start = s
    i = s
    while i < e:
        if kinds[i] != _CODE:
            i += 1
            continue
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            k = test(src, i, s, e)
            if k:
                spans.append((start, i))
                i += k
                start = i
                continue
        i += 1
    spans.append((start, e))
    return spans


def _prev_sig(src: _Src, i: int, s: int) -> int:
    text, kinds = src.text, src.kinds
    j = i - 1
    while j >= s and (text[j].isspace() or kinds[j] == _NONCODE):
        j -= 1
    return j


def _t_plus(src: _Src, i: int, s: int, e: int) -> int:
    text = src.text
    if text[i] != "+":
        return 0
    nx = text[i + 1] if i + 1 < e else ""
    if nx in ("+", "=") or (i > s and text[i - 1] == "+"):
        return 0
    p = _prev_sig(src, i, s)
    if p < s:
        return 0
    if src.kinds[p] != _CODE:
        return 1
    pc = text[p]
    if pc.isalnum() or pc in "_$)]}'\"`":
        return 1
    return 0


def _t_dot_php(src: _Src, i: int, s: int, e: int) -> int:
    text = src.text
    if text[i] != ".":
        return 0
    nx = text[i + 1] if i + 1 < e else ""
    pv = text[i - 1] if i > s else ""
    if nx in ("=", ".") or pv == ".":
        return 0
    if pv.isdigit() and nx.isdigit():
        return 0
    return 1


def _t_slash_py(src: _Src, i: int, s: int, e: int) -> int:
    text = src.text
    if text[i] != "/":
        return 0
    nx = text[i + 1] if i + 1 < e else ""
    if nx in ("/", "=") or (i > s and text[i - 1] == "/"):
        return 0
    return 1


def _t_logic(src: _Src, i: int, s: int, e: int) -> int:
    text, lang = src.text, src.lang
    two = text[i:i + 2]
    if two in ("||", "??", "&&"):
        if text[i + 2:i + 3] == "=":
            return 0
        return 2
    if lang == "php" and two == "?:":
        return 2
    if lang in ("py", "php"):
        for w in ("or", "and"):
            if text.startswith(w, i) and i > s and text[i - 1].isspace():
                after = text[i + len(w):i + len(w) + 1]
                if after.isspace():
                    return len(w)
    return 0


def _ternary(src: _Src, s: int, e: int) -> Optional[Tuple[Tuple[int, int], Tuple[int, int], Tuple[int, int]]]:
    """(cond, a, b) spans of a top-level ternary, or None."""
    text, kinds, lang = src.text, src.kinds, src.lang
    if lang == "py":
        code = src.code
        depth = 0
        pos_if = -1
        i = s
        while i < e:
            if kinds[i] == _CODE:
                c = text[i]
                if c in "([{":
                    depth += 1
                elif c in ")]}":
                    depth -= 1
                elif depth == 0 and c in "ie" and (i == s or not (code[i - 1].isalnum() or code[i - 1] == "_")):
                    if pos_if < 0 and code.startswith("if", i) and i + 2 < e and not (code[i + 2].isalnum() or code[i + 2] == "_"):
                        pos_if = i
                    elif pos_if >= 0 and code.startswith("else", i) and i + 4 < e and not (code[i + 4].isalnum() or code[i + 4] == "_"):
                        return (pos_if + 2, i), (s, pos_if), (i + 4, e)
            i += 1
        return None
    depth = 0
    q = -1
    nest = 0
    i = s
    while i < e:
        if kinds[i] != _CODE:
            i += 1
            continue
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0:
            if c == "?":
                nx = text[i + 1] if i + 1 < e else ""
                pv = text[i - 1] if i > s else ""
                if nx == "?" or pv == "?" or (lang == "php" and nx in ":-") or (nx == "." and not text[i + 2:i + 3].isdigit()):
                    i += 1
                    continue
                if q < 0:
                    q = i
                else:
                    nest += 1
            elif c == ":" and q >= 0:
                if text[i + 1:i + 2] == ":" or (i > s and text[i - 1] == ":"):
                    i += 1
                    continue
                if nest:
                    nest -= 1
                else:
                    return (s, q), (q + 1, i), (i + 1, e)
        i += 1
    return None


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------

class _V(object):
    """What we know about an expression. parts: dynamic pieces as tuples
    (level, text, literal_before, from_path_segment)."""
    __slots__ = ("level", "lit", "parts", "built", "md", "call", "is_lit", "toks")

    def __init__(self, level: int = SAFE, lit: str = "", parts: Optional[list] = None, built: bool = False,
                 md: bool = False, call: bool = False, is_lit: bool = False) -> None:
        self.level = level
        self.lit = lit
        self.parts = parts if parts is not None else []
        self.built = built
        self.md = md
        self.call = call
        self.is_lit = is_lit
        self.toks: List[int] = []


def _value(level: int, text: str, md: bool = False, call: bool = False, seg: bool = False) -> _V:
    return _V(level, parts=[(level, text, "", seg, call)], md=md, call=call)


def _lit(content: str) -> _V:
    return _V(SAFE, lit=content, is_lit=True)


def _seq(vs: Sequence[_V]) -> _V:
    out = _V()
    lit = ""
    has_lit = False
    has_dyn = False
    for v in vs:
        out.toks.extend(v.toks)
        out.md = out.md or v.md
        if v.is_lit:
            lit += v.lit
            has_lit = True
            continue
        if v.built:
            for p in v.parts:
                out.parts.append((p[0], p[1], lit + p[2]) + tuple(p[3:]))
            lit += v.lit
            has_lit = True
            has_dyn = True
            continue
        for p in v.parts:
            out.parts.append((p[0], p[1], lit) + tuple(p[3:]))
        has_dyn = True
    out.lit = lit
    out.built = has_lit and has_dyn or any(v.built for v in vs)
    out.level = max([p[0] for p in out.parts], default=SAFE)
    out.is_lit = bool(vs) and all(v.is_lit for v in vs)
    out.call = (not out.built) and any(v.call for v in vs)
    return out


def _alt(vs: Sequence[_V]) -> _V:
    out = _V()
    if not vs:
        return out
    out.level = max(v.level for v in vs)
    out.lit = " ".join(v.lit for v in vs if v.lit)
    for v in vs:
        out.parts.extend(v.parts)
        out.toks.extend(v.toks)
    out.built = any(v.built for v in vs)
    out.md = any(v.md for v in vs)
    out.is_lit = all(v.is_lit for v in vs)
    dyn = [v for v in vs if not v.is_lit and v.level > SAFE]
    out.call = bool(dyn) and all(v.call for v in dyn)
    return out


class _Mode(object):
    """How to judge a value for one kind of sink."""
    __slots__ = ("lang", "kind", "sources", "safe", "route_params", "key")

    def __init__(self, lang: str, kind: str, sources: "re.Pattern[str]", safe: "re.Pattern[str]",
                 route_params: bool = True) -> None:
        self.lang = lang
        self.kind = kind
        self.sources = sources
        self.safe = safe
        self.route_params = route_params
        self.key = (lang, kind, sources.pattern, safe.pattern, route_params)


_JS_SOURCES = re.compile(
    r"\breq\s*\.\s*(?:body|query|params|headers|cookies|files?)\b"
    r"|\brequest\s*\.\s*(?:body|query|params|nextUrl)\b"
    r"|\b(?:req|request)\s*\.\s*(?:json|formData|text)\s*\("
    r"|\bsearchParams\b|\bformData\s*\.\s*get(?:All)?\s*\("
    r"|\bctx\s*\.\s*(?:request|query|params)\b|\bc\s*\.\s*req\s*\.\s*\w+"
    r"|\bevent\s*\.\s*(?:body|queryStringParameters|pathParameters)\b"
    r"|\blocation\s*\.\s*(?:search|hash|href)\b|\bdocument\s*\.\s*(?:URL|referrer|cookie)\b"
    r"|\bURLSearchParams\b|\buseSearchParams\b")
_PY_SOURCES = re.compile(
    r"\brequest\s*\.\s*(?:args|form|values|json|data|files|cookies|GET|POST|FILES|COOKIES|body|query_params|path_params|get_data|get_json)\b"
    r"|\bawait\s+request\s*\.\s*(?:json|form|body)\s*\(")
_PHP_SOURCES = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b"
    r"|\$request\s*->\s*(?!user\b|ip\b|method\b|isMethod\b|wantsJson\b|expectsJson\b|ajax\b|secure\b|session\b|routeIs\b|is\b|has\b|filled\b|missing\b|hasFile\b|isJson\b)\w+"
    r"|\brequest\s*\(\s*\)\s*->\s*(?!user\b|ip\b|method\b|is\b|has\b)\w+|\brequest\s*\(\s*['\"]"
    r"|\b(?:Request|Input)\s*::\s*(?:input|get|query|post|all|json)\b|\bold\s*\(")

# URL, path and header accessors. They count as request input for SQL, shell, HTML, code and path sinks,
# but not for the SSRF host check, where the request's own URL names this server.
_JS_SOURCES_X = re.compile(
    _JS_SOURCES.pattern +
    r"|\breq\s*\.\s*(?:url|originalUrl|path)\b|\brequest\s*\.\s*(?:url|headers\s*\.\s*get\s*\()"
    r"|\bheaders\s*\(\s*\)\s*\.\s*get\s*\(")
_PY_SOURCES_X = re.compile(
    _PY_SOURCES.pattern +
    r"|\brequest\s*\.\s*(?:url|path|full_path|base_url|url_root|headers|referrer|user_agent|environ|META|path_info|"
    r"get_full_path)\b")
_PHP_SOURCES_X = _PHP_SOURCES
# $_SERVER keys that the client controls; the key is a string, so it is matched on the raw text
_PHP_SERVER_SRC = re.compile(r"\$_SERVER\s*\[\s*['\"](?:REQUEST_URI|PHP_SELF|QUERY_STRING|PATH_INFO|HTTP_(?!HOST\b)\w+)['\"]\s*\]")

_JS_NOSQL_SOURCES = re.compile(
    r"\breq\s*\.\s*(?:body|query)\b|\b(?:req|request)\s*\.\s*json\s*\(|\bctx\s*\.\s*request\s*\.\s*body\b|\bevent\s*\.\s*body\b")
_JS_NOSQL_SOURCES_X5 = re.compile(
    r"\breq\s*\.\s*body\b|\b(?:req|request)\s*\.\s*json\s*\(|\bctx\s*\.\s*request\s*\.\s*body\b|\bevent\s*\.\s*body\b")
_PY_NOSQL_SOURCES = re.compile(
    r"\brequest\s*\.\s*(?:json|get_json)\b|\bawait\s+request\s*\.\s*json\s*\(|\bjson\s*\.\s*loads\s*\(\s*request\s*\.\s*(?:data|body|get_data)")

_SAFE_ANY = (r"require|import|Number|parseInt|parseFloat|BigInt|isNaN|int|float|bool|len|abs|round|ceil|floor|"
             r"intval|floatval|boolval|count|sizeof|toFixed|toPrecision|toISOString|toLocaleString|toLocaleDateString|"
             r"getTime|now|uuid\w*|randomUUID|nanoid|uniqid|random_bytes|bin2hex|token_hex|token_urlsafe|cuid|ulid|"
             r"md5|sha1|sha256|hash|hashName|crc32|isoformat|strftime|date")


def _safe_rx(extra: str) -> "re.Pattern[str]":
    return re.compile(r"(?:" + _SAFE_ANY + (r"|" + extra if extra else "") + r")")


_SAFE_SQL = _safe_rx(r"escape\w*|sqlEscape|quote\w*|pgFormat|escape_string|real_escape_string|mysqli_real_escape_string|"
                     r"esc_sql|addslashes|Identifier|Literal|Placeholder|prepare|placeholders?")
_SAFE_HTML = _safe_rx(r"sanitize\w*|purify\w*|escape\w*|esc|esc_html|esc_attr|esc_url|encodeHTML|encodeHtml|htmlEscape|"
                      r"htmlspecialchars|htmlentities|strip_tags|striptags|stripTags|e|clean|clean_html|bleach\w*|"
                      r"filterXSS|xss|insane|conditional_escape|format_html|render_to_string|wp_kses\w*|linebreaks|urlize")
_SAFE_HTML_JSON = _safe_rx(r"sanitize\w*|purify\w*|escape\w*|esc|encodeHTML|encodeHtml|htmlEscape|filterXSS|xss|insane|"
                           r"stringify|renderToStaticMarkup|renderToString")
_SAFE_CMD = _safe_rx(r"quote|shellQuote|shellescape|shellEscape|escapeShellArg|escapeshellarg|escapeshellcmd|shq|escape|"
                     r"basename|secure_filename")
_SAFE_PATH = _safe_rx(r"basename|secure_filename|get_valid_filename|safe_join|sanitize\w*|slugify|slug|extname|splitext")
_SAFE_URL = _safe_rx(r"")
_SAFE_NOSQL = _safe_rx(r"String|str|toString|ObjectId|isValidObjectId|escapeRegex|escapeRegExp|escape_regex|sanitize\w*|"
                       r"parse|safeParse|validate|validateSync|cast|trim|toLowerCase|toUpperCase|lower|upper|strip|"
                       r"normalizeEmail|isEmail")

_NUMERIC_NAME = re.compile(
    r"(?:length|size|count|total|index|idx|id|width|height|top|left|right|bottom|x|y|z|page|pages|year|month|day|"
    r"hours?|minutes?|seconds?|ms|duration|price|amount|qty|quantity|percent|pct|progress|score|rank|level|"
    r"version|age|num\w*|innerHTML|outerHTML)|\w*(?:Count|Total|Index|Size|Width|Height|Id|Ms|Px|Num|Price|Amount|Percent)")
# table, schema and prefix names (also with a word before or after them: schemaTable, users_table, tablePrefix)
# and generated placeholder lists. Names like editable or sortable do not match.
_SQL_SAFE_NAME = re.compile(r"(?i:table|tbl|table_?name|tablename|prefix|db_?prefix|schema|placeholders?|qmarks|"
                            r"marks|in_?clause|bind_?marks|param_?marks|sql_?placeholders)"
                            r"|[a-z][a-zA-Z0-9]*(?:Table|Tbl|Schema|Prefix)(?:Name)?|[A-Za-z][A-Za-z0-9]*_(?i:table|tbl|schema|prefix)(?:_?name)?"
                            r"|(?i:table|schema)(?:[A-Z][A-Za-z0-9]*|_[a-z][a-z0-9_]*)")
_ALL_CAPS = re.compile(r"\$?[A-Z][A-Z0-9_]+")
# Paths the upload middleware generated, not the client: multer's file.path, PHP's tmp_name.
_SERVER_UPLOAD_PATH = re.compile(r"(?:\breq\s*\.\s*files?\b[\w$.\[\]'\"\s]*\.\s*(?:path|destination|filename)|"
                                 r"\[\s*['\"]tmp_name['\"]\s*\])\s*$")
_NUMBER = re.compile(r"\s*-?(?:\d[\d_]*(?:\.\d*)?(?:[eE][+-]?\d+)?|0[xXbBoO][\da-fA-F_]+)n?\s*"
                     r"|\s*(?:true|false|null|undefined|None|True|False|NULL|NaN|Infinity)\s*")
_CONFIG = re.compile(
    r"\s*(?:process\s*\.\s*env\b|import\s*\.\s*meta\s*\.\s*env\b|Deno\s*\.\s*env\b|os\s*\.\s*(?:environ|getenv)\b|"
    r"settings\s*\.|(?:current_)?app\s*\.\s*config\b|config\s*\(|env\s*\(|getenv\s*\(|\$_ENV\b|__dirname\b|"
    r"__filename\b|process\s*\.\s*cwd\s*\(|os\s*\.\s*tmpdir\s*\(|BASE_DIR\b|MEDIA_ROOT\b|base_path\s*\(|"
    r"storage_path\s*\(|public_path\s*\(|app_path\s*\(|__DIR__\b)")
_ALLOW_COND = re.compile(
    r"\.\s*(?:includes|has|indexOf|hasOwnProperty|test|match)\s*\(|\bin_array\s*\(|\barray_key_exists\s*\(|"
    r"\bisset\s*\(|\bin\s+[\w\[\(\{'\"]|\bObject\s*\.\s*hasOwn\b|\bpreg_match\s*\(|"
    r"[=!]==?\s*['\"][^'\"]|['\"][^'\"]*['\"]\s*[=!]==?")
_SANITIZING_RX = re.compile(r"^/\[\^[\w\\\-. ]+\][+*]?/[gimsuy]*$|^r?['\"]\[\^[\w\\\-. ]+\][+*]?['\"]$")

_IDENT = {
    "js": re.compile(r"[A-Za-z_$][\w$]*"),
    "py": re.compile(r"[A-Za-z_]\w*"),
    "php": re.compile(r"\$[A-Za-z_]\w*"),
}
_MEMBER = {
    "js": re.compile(r"([A-Za-z_$][\w$]*)((?:\s*\??\.\s*[A-Za-z_$][\w$]*|\s*(?:\?\.)?\s*\[[^\[\]]*\])+)"),
    "py": re.compile(r"([A-Za-z_]\w*)((?:\s*\.\s*[A-Za-z_]\w*|\s*\[[^\[\]]*\])+)"),
    "php": re.compile(r"(\$[A-Za-z_]\w*|[A-Za-z_\\][\w\\]*)((?:\s*(?:->|\?->|::)\s*\$?[A-Za-z_]\w*|\s*\[[^\[\]]*\])+)"),
}
_LAST_NAME = re.compile(r"(?:\.|->|::)\s*\$?([A-Za-z_$][\w$]*)\s*$")


def _short(s: str, width: int = 60) -> str:
    s = " ".join((s or "").split())
    if len(s) > width:
        s = s[:width - 3] + "..."
    return redact(s)


def _callee_parts(callee: str) -> Tuple[str, str]:
    """(receiver, name) of a callee like "a.b.c", "$x->m", "C::m" or "f"."""
    c = callee.strip()
    if c.startswith("new "):
        c = c[4:].strip()
    m = re.search(r"(?:\?\.|\.|->|::)\s*\$?([A-Za-z_$][\w$]*)\s*$", c)
    if m:
        return c[:m.start()].strip(), m.group(1)
    m = re.fullmatch(r"\$?([A-Za-z_$][\w$]*)", c)
    if m:
        return "", m.group(1)
    return c, ""


_MD_NAMES = re.compile(r"(?:marked(?:\s*\.\s*(?:parse|parseInline|marked))?|snarkdown|micromark|markdownToHtml|"
                       r"markdownToHTML|mdToHtml|md2html|markdown\s*\.\s*markdown|markdown2\s*\.\s*markdown|"
                       r"mistune\s*\.\s*\w+|commonmark\s*\.\s*\w+|markdown|\w+\s*\.\s*makeHtml)")
_MDIT_INST = re.compile(r"(?:const|let|var)\s+([\w$]+)\s*=\s*(?:new\s+)?(?:MarkdownIt|markdownit|markdownIt|"
                        r"require\(\s*['\"]markdown-it['\"]\s*\))\s*\(")


def _md_call(src: _Src, callee: str) -> bool:
    c = " ".join(callee.split())
    if c.startswith("new "):
        return False
    if _MD_NAMES.fullmatch(c):
        return True
    if src.lang == "php" and re.search(r"(?i)parsedown|commonmark|markdown", c) and re.search(r"->\s*(?:text|line|convert\w*)$", c):
        return True
    m = re.fullmatch(r"([\w$]+)\s*\.\s*render(?:Inline)?", c)
    if m and src.lang == "js":
        unsafe = src.memo.get("mdit")
        if unsafe is None:
            unsafe = set()
            for mm in _MDIT_INST.finditer(src.code):
                args, close = _call_args(src, mm.end() - 1)
                opts = src.text[mm.end():close] if close > 0 else ""
                if re.search(r"\bhtml\s*:\s*true\b", opts):
                    unsafe.add(mm.group(1))
            src.memo["mdit"] = unsafe
        return m.group(1) in unsafe
    return False


# Renderers that escape the text they are given: syntax highlighters, mermaid (default securityLevel
# 'strict' sanitizes labels), KaTeX.
_HTML_SAFE_CALLEE = re.compile(r"(?:[\w$]+\s*\.\s*)*(?:codeToHtml|codeToHast)|(?:hljs|highlightjs|hljs\s*\.\s*default)\s*\.\s*"
                               r"(?:highlight|highlightAuto)|Prism\s*\.\s*highlight|katex\s*\.\s*renderToString|"
                               r"(?:mermaid|mermaidAPI)\s*\.\s*render")


_MERMAID_LOOSE = re.compile(r"securityLevel['\"]?\s*:\s*['\"](?:loose|antiscript)")


def _html_safe_call(src: _Src, callee: str) -> Optional[bool]:
    """True for a renderer that escapes its input, None for mermaid with a loose securityLevel (HTML in labels
    passes through, but the diagram source is usually the developer's), False otherwise."""
    c = " ".join(callee.split())
    if not _HTML_SAFE_CALLEE.fullmatch(c):
        return False
    if "mermaid" in c and _MERMAID_LOOSE.search(src.text):
        return None
    return True


def _marked_sanitized(src: _Src) -> bool:
    """True when this file configures marked with a sanitizing postprocess hook (marked.use / new Marked)."""
    res = src.memo.get("marked-sanitized")
    if res is None:
        res = False
        for mt in re.finditer(r"\bmarked\s*\.\s*(?:use|setOptions)\s*\(|\bnew\s+Marked\s*\(", src.code):
            args, close = _call_args(src, mt.end() - 1)
            body = src.code[mt.end():close] if close > 0 else ""
            if re.search(r"\bpostprocess\b", body) and re.search(r"(?i)\bsanitize\w*\s*\(|\bpurify\w*\s*\(|DOMPurify|filterXSS|\bxss\s*\(",
                                                                 body):
                res = True
                break
        src.memo["marked-sanitized"] = res
    return res


# ---------------------------------------------------------------------------
# Same-file trace of a name back to where it got its value
# ---------------------------------------------------------------------------

def _names_in_pattern(pat: str) -> Dict[str, Optional[str]]:
    """Names bound by a JS destructuring pattern body "a, b: c, d = 1, ...e"
    mapped to the source key."""
    out: Dict[str, Optional[str]] = {}
    depth = 0
    cur = ""
    items = []
    for ch in pat:
        if ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth -= 1
        if ch == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += ch
    items.append(cur)
    for it in items:
        it = it.strip()
        if not it or "{" in it or "[" in it:
            continue
        it = it.split("=", 1)[0].strip()
        if it.startswith("..."):
            out[it[3:].strip()] = None
            continue
        if ":" in it:
            k, v = it.split(":", 1)
            out[v.strip()] = k.strip()
        else:
            out[it] = it
    return out


_JS_FUNC_HEADERS = [
    re.compile(r"\bfunction\b\s*\*?\s*[\w$]*\s*\("),
    re.compile(r"(?<![\w$.])(?!if\b|for\b|while\b|switch\b|catch\b|with\b|function\b|return\b)[\w$]+\s*\((?=[^()]*\)\s*(?::\s*[^{;=]{1,80})?\{)"),
]
_JS_ARROW = re.compile(r"\(([^()]*)\)\s*(?::\s*[^=;{}()]{1,80})?=>")


def _js_param_names(text: str) -> List[str]:
    names = re.findall(r"[A-Za-z_$][\w$]*", re.sub(r":\s*[^,{}=]+", "", text))
    return names


def _trace(src: _Src, name: str, pos: int) -> Optional[tuple]:
    key = ("trace", name, pos)
    if key in src.memo:
        return src.memo[key]
    if src.lang == "py":
        res = _trace_py(src, name, pos)
    elif src.lang == "php":
        res = _trace_php(src, name, pos)
    else:
        res = _trace_js(src, name, pos)
    src.memo[key] = res
    return res


def _back_operand(src: _Src, i: int) -> int:
    """Start of the member chain (a.b(c).d, $x->y, A::b) that ends just before index i."""
    text, kinds = src.text, src.kinds
    j = i - 1
    while j >= 0 and text[j] in " \t":
        j -= 1
    while j >= 0:
        c = text[j]
        if kinds[j] != _CODE:
            break
        if c in ")]":
            k = _match_back(src, j)
            if k < 0:
                break
            j = k - 1
            continue
        if c.isalnum() or c in "_$":
            j -= 1
            continue
        step = 0
        if c == ".":
            step = 1
        elif c == ">" and j > 0 and text[j - 1] == "-":
            step = 2
        elif c == ":" and j > 0 and text[j - 1] == ":":
            step = 2
        if step:
            j -= step
            if j >= 0 and text[j] == "?":
                j -= 1
            while j >= 0 and text[j] in " \t\r\n":
                j -= 1
            continue
        break
    k = j + 1
    while k < i and text[k] in " \t\r\n":
        k += 1
    return k


def _then_receiver(src: _Src, at: int) -> Optional[Tuple[int, int]]:
    """(start, end) of p in p.then((x) => ...) when the callback starts at at, else None."""
    code = src.code
    mt = re.search(r"\.\s*then\s*\(\s*(?:async\s*)?$", code[max(0, at - 80):at])
    if not mt:
        return None
    dot = max(0, at - 80) + mt.start()
    rs = _back_operand(src, dot)
    return (rs, dot) if rs < dot else None


def _server_fn_data(src: _Src, at: int, params: str, name: str) -> bool:
    """True for data in createServerFn(...).handler(async ({ data }) => ...): the client sends it."""
    if name != "data" or "{" not in params or "createServerFn" not in src.code:
        return False
    return re.search(r"\.\s*handler\s*\(\s*(?:async\s*)?$", src.code[max(0, at - 80):at]) is not None


def _trace_js(src: _Src, name: str, pos: int) -> Optional[tuple]:
    code = src.code
    lo = max(0, pos - 20000)
    region = code[lo:pos]
    n = re.escape(name)
    best: List[Any] = [None]

    def take(at: int, kind: str, data: Any) -> None:
        if best[0] is None or at > best[0][0]:
            best[0] = (at, kind, data)

    for mt in re.finditer(r"(?<![\w$.])" + n + r"\s*(?::\s*[^=;,(){}]{1,120})?=(?![=>])", region):
        at = lo + mt.start()
        before = region[max(0, mt.start() - 16):mt.start()]
        decl = re.search(r"\b(?:const|let|var)\s+$", before)
        if not decl:
            p = _prev_sig(src, at, max(0, at - 200))
            pc = code[p] if p >= 0 else ""
            if pc and pc in "(,":
                # a default value in a parameter list or a destructuring pattern
                take(at, "param", None)
                continue
            if pc == "{":
                k = _match_fwd(src, p)
                if k > at and re.match(r"\s*(?:=(?!=)|\))", code[k + 1:k + 40]):
                    continue
        rhs = lo + mt.end()
        take(at, "assign", (rhs, _expr_end(src, rhs, ";,")))
    for mt in re.finditer(r"\b(?:const|let|var)\s*\{", region):
        ob = lo + mt.end() - 1
        cb = _match_fwd(src, ob)
        if cb < 0 or cb >= pos:
            continue
        names = _names_in_pattern(src.text[ob + 1:cb])
        if name not in names:
            continue
        rest = re.match(r"\s*(?::[^=;]{1,120})?=(?![=>])", code[cb + 1:cb + 200])
        if not rest:
            continue
        rhs = cb + 1 + rest.end()
        take(lo + mt.start(), "destr", ((rhs, _expr_end(src, rhs, ";,")), names[name]))
    for mt in re.finditer(r"\b(?:const|let|var)\s*\[", region):
        ob = lo + mt.end() - 1
        cb = _match_fwd(src, ob)
        if cb < 0 or cb >= pos:
            continue
        items = [x.strip().split("=", 1)[0].strip() for x in src.text[ob + 1:cb].split(",")]
        if name not in items:
            continue
        rest = re.match(r"\s*(?::[^=;]{1,120})?=(?![=>])", code[cb + 1:cb + 200])
        if not rest:
            continue
        rhs = cb + 1 + rest.end()
        rend = _expr_end(src, rhs, ";,")
        sm = re.match(r"\s*(?:React\s*\.\s*)?useState\b", code[rhs:rend])
        op = -1
        if sm:
            j = rhs + sm.end()
            gdepth = 0
            while j < min(rend, rhs + 600):
                ch = code[j]
                if ch in "<{":
                    gdepth += 1
                elif ch in ">}":
                    gdepth -= 1
                elif ch == "(" and gdepth <= 0:
                    op = j
                    break
                j += 1
        if op >= 0 and items.index(name) == 0:
            setter = items[1] if len(items) > 1 and re.fullmatch(r"[A-Za-z_$][\w$]*", items[1]) else ""
            take(lo + mt.start(), "state", (op, setter))
        else:
            take(lo + mt.start(), "destr", ((rhs, rend), None))
    for mt in re.finditer(r"\bimport\s+([\w$\s,{}*]*?)\s*from\b", region):
        body = mt.group(1)
        found = re.findall(r"(?:\bas\s+)?([A-Za-z_$][\w$]*)", re.sub(r"\b[\w$]+\s+as\s+", "", body))
        if name in found:
            take(lo + mt.start(), "import", None)
    for mt in re.finditer(r"\bfor\s*\(\s*(?:const|let|var)\s+(?:" + n + r"\b|\{[^}]*\b" + n + r"\b[^}]*\}|\[[^\]]*\b" + n + r"\b[^\]]*\])\s+(?:of|in)\s+", region):
        cs = lo + mt.end()
        take(lo + mt.start(), "loop", (cs, _expr_end(src, cs, "")))
    loop_spans = []
    for mt in re.finditer(r"\.\s*(?:map|forEach|filter|flatMap|find|findLast|some|every|sort)\s*\(\s*(?:async\s*)?(?:function\s*[\w$]*\s*)?(?:\(\s*)?(?:" + n + r"\b|\{[^}]*\b" + n + r"\b[^}]*\})", region):
        dot = lo + mt.start()
        rs = _back_operand(src, dot)
        loop_spans.append((lo + mt.start(), lo + mt.end()))
        take(lo + mt.start(), "loop", (rs, dot))
    for rx in _JS_FUNC_HEADERS:
        for mt in rx.finditer(region):
            op = lo + mt.end() - 1
            cp = _match_fwd(src, op)
            if cp < 0 or cp >= pos:
                continue
            if name in _js_param_names(code[op + 1:cp]):
                # a TypeScript parameter typed as a union of string literals is an allowlist
                lit = re.search(r"(?<![\w$])" + n + r"\s*\??\s*:\s*['\"][^'\"\n]*['\"](?:\s*\|\s*['\"][^'\"\n]*['\"])*\s*(?:[,=)]|$)",
                                src.text[op + 1:cp])
                take(lo + mt.start(), "param", {"literal": bool(lit), "open": op})
    for mt in _JS_ARROW.finditer(region):
        if name in _js_param_names(mt.group(1)):
            if any(a <= lo + mt.start() < b for a, b in loop_spans):
                continue  # the callback of items.map((x) => ...): the loop above already took it
            lit = re.search(r"(?<![\w$])" + n + r"\s*\??\s*:\s*['\"][^'\"\n]*['\"](?:\s*\|\s*['\"][^'\"\n]*['\"])*\s*(?:[,=)]|$)",
                            src.text[lo + mt.start(1):lo + mt.end(1)])
            take(lo + mt.start(), "param", {"literal": bool(lit), "then": _then_receiver(src, lo + mt.start()),
                                            "server_fn": _server_fn_data(src, lo + mt.start(), mt.group(1), name)})
    for mt in re.finditer(r"(?<![\w$.])" + n + r"\s*=>", region):
        if any(a <= lo + mt.start() < b for a, b in loop_spans):
            continue
        take(lo + mt.start(), "param", {"then": _then_receiver(src, lo + mt.start())})
    for mt in re.finditer(r"\bcatch\s*\(\s*" + n + r"\b", region):
        take(lo + mt.start(), "param", None)
    if best[0] is None:
        return None
    at, kind, data = best[0]
    appends = []
    for mt in re.finditer(r"(?<![\w$.])" + n + r"\s*\+=", code[at:pos]):
        rs = at + mt.end()
        appends.append((rs, _expr_end(src, rs, ";,")))
    return at, kind, data, appends


_PY_DEF = re.compile(r"(?m)^([ \t]*)(?:async[ \t]+)?def[ \t]+\w+[ \t]*\(")
_PY_ROUTE_DECO = re.compile(r"@\s*[\w.]*\b(?:route|get|post|put|patch|delete|head|options|websocket|api_route|api_view|action)\s*\(")


def _py_params(src: _Src, open_i: int) -> List[Tuple[str, str, str]]:
    args, close = _call_args(src, open_i)
    out = []
    for s, e in args:
        a = src.text[s:e]
        m = re.match(r"\s*\*{0,2}([A-Za-z_]\w*)\s*(?::\s*([^=]*))?(?:=\s*(.*))?$", a, re.S)
        if m:
            out.append((m.group(1), (m.group(2) or "").strip(), (m.group(3) or "").strip()))
    return out


def _py_decorators(src: _Src, def_at: int) -> str:
    # raw text: the route path inside the decorator is a string
    lines = src.text[max(0, def_at - 1500):def_at].split("\n")
    if lines and not lines[-1].strip():
        lines = lines[:-1]
    keep: List[str] = []
    depth = 0
    for ln in reversed(lines):
        st = ln.strip()
        depth += ln.count(")") - ln.count("(")
        if st.startswith("@") or depth > 0 or st.endswith(",") or st.startswith(")"):
            keep.append(ln)
            continue
        break
    return "\n".join(reversed(keep))


def _trace_py(src: _Src, name: str, pos: int) -> Optional[tuple]:
    code = src.code
    lo = max(0, pos - 20000)
    region = code[lo:pos]
    n = re.escape(name)
    best: List[Any] = [None]

    def take(at: int, kind: str, data: Any) -> None:
        if best[0] is None or at > best[0][0]:
            best[0] = (at, kind, data)

    for mt in re.finditer(r"(?m)^[ \t]*" + n + r"[ \t]*(?::[^=\n]{1,120})?=(?!=)", region):
        rhs = lo + mt.end()
        take(lo + mt.start(), "assign", (rhs, _expr_end(src, rhs, ";")))
    for mt in re.finditer(r"(?m)^[ \t]*(?:async[ \t]+)?for[ \t]+\(?[\w, \t]*\b" + n + r"\b[\w, \t]*\)?[ \t]+in[ \t]+", region):
        cs = lo + mt.end()
        take(lo + mt.start(), "loop", (cs, _expr_end(src, cs, ":")))
    for mt in re.finditer(r"\bfor\s+(?:\w+\s*,\s*)*" + n + r"(?:\s*,\s*\w+)*\s+in\s+", region):
        line_start = region.rfind("\n", 0, mt.start()) + 1
        if re.fullmatch(r"[ \t]*(?:async[ \t]+)?", region[line_start:mt.start()]):
            continue  # a for statement, handled above
        cs = lo + mt.end()
        ce = _expr_end(src, cs, "")
        mm = re.search(r"\s(?:if|for)\s", code[cs:ce])
        take(lo + mt.start(), "loop", (cs, cs + mm.start() if mm else ce))
    for mt in re.finditer(r"\bwith\s+([^\n:]+?)\s+as\s+" + n + r"\b", region):
        take(lo + mt.start(), "assign", (lo + mt.start(1), lo + mt.end(1)))
    for mt in re.finditer(r"(?m)^[ \t]*(?:from[ \t]+[\w.]+[ \t]+import[ \t]+|import[ \t]+)[^\n]*\b" + n + r"\b", region):
        take(lo + mt.start(), "import", None)
    for mt in _PY_DEF.finditer(region):
        op = lo + mt.end() - 1
        params = _py_params(src, op)
        names = [p[0] for p in params]
        if name not in names:
            continue
        info = {"route": False, "seg": False}
        pname, annot, default = params[names.index(name)]
        deco = _py_decorators(src, lo + mt.start())
        route = _PY_ROUTE_DECO.search(deco)
        if "Depends(" in default or "Depends(" in annot:
            route = None
        elif route:
            pm = re.search(r"\(\s*[rRbBuUfF]?['\"]([^'\"]*)['\"]", deco[route.end() - 1:])
            path = pm.group(1) if pm else ""
            if re.search(r"\{" + n + r"\}|<(?:(?!path)\w+:)?" + n + r">", path):
                info["seg"] = True
        elif names and names[0] == "request" and name != "request":
            info["seg"] = True
            route = True
        if re.search(r"\b(?:Query|Form|Body|Path|Header|Cookie)\s*\(", default + " " + annot):
            route = route or True
        info["route"] = bool(route)
        info["annot"] = annot
        # a click / typer command argument comes from the operator's own command line
        info["cli"] = bool(re.search(r"@\s*click\s*\.\s*(?:argument|option)\b|@\s*[\w.]*\bcli\s*\.\s*command\b", deco)
                           or re.search(r"\btyper\s*\.\s*(?:Argument|Option)\s*\(", default + " " + annot)
                           or (re.search(r"@\s*[\w.]+\s*\.\s*command\s*\(", deco)
                               and re.search(r"(?m)^\s*(?:import\s+(?:click|typer)\b|from\s+(?:click|typer|flask\.cli)\s+import)", code)))
        take(lo + mt.start(), "param", info)
    if best[0] is None:
        return None
    at, kind, data = best[0]
    appends = []
    for mt in re.finditer(r"(?m)^[ \t]*" + n + r"[ \t]*\+=", code[at:pos]):
        rs = at + mt.end()
        appends.append((rs, _expr_end(src, rs, ";")))
    return at, kind, data, appends


def _in_php_params(src: _Src, at: int) -> bool:
    """True when at sits inside the parameter list of a PHP function or fn header."""
    text, kinds, code = src.text, src.kinds, src.code
    depth = 0
    j = at - 1
    lo = max(0, at - 800)
    while j >= lo:
        if kinds[j] == _CODE:
            c = text[j]
            if c == ")":
                depth += 1
            elif c == "(":
                if depth == 0:
                    return re.search(r"\b(?:function\s*&?\s*\w*|fn)\s*$", code[max(0, j - 80):j]) is not None
                depth -= 1
            elif c in ";{}" and depth == 0:
                return False
        j -= 1
    return False


def _trace_php(src: _Src, name: str, pos: int) -> Optional[tuple]:
    code = src.code
    lo = max(0, pos - 20000)
    region = code[lo:pos]
    bare = name.lstrip("$")
    n = re.escape(bare)
    best: List[Any] = [None]

    def take(at: int, kind: str, data: Any) -> None:
        if best[0] is None or at > best[0][0]:
            best[0] = (at, kind, data)

    for mt in re.finditer(r"\$" + n + r"\b\s*=(?![=>])", region):
        if _in_php_params(src, lo + mt.start()):
            continue  # a default value in a parameter list; the parameter itself is taken below
        rhs = lo + mt.end()
        take(lo + mt.start(), "assign", (rhs, _expr_end(src, rhs, ";")))
    # [$values, $sql] = f(...) and list($a, $b) = f(...): each name carries what the right side carries
    for mt in re.finditer(r"(?:\blist\s*\(|\[)[^\[\]();]*\$" + n + r"\b[^\[\]();]*[\])]\s*=(?![=>])", region):
        rhs = lo + mt.end()
        take(lo + mt.start(), "assign", (rhs, _expr_end(src, rhs, ";")))
    for mt in re.finditer(r"\bforeach\s*\(", region):
        op = lo + mt.end() - 1
        cp = _match_fwd(src, op)
        if cp < 0 or cp >= pos:
            continue
        inner = code[op + 1:cp]
        mm = re.search(r"\s+as\s+(?:&?\$\w+\s*=>\s*)?&?\$" + n + r"\s*$", inner)
        if mm:
            take(lo + mt.start(), "loop", (op + 1, op + 1 + mm.start()))
    for mt in re.finditer(r"\b(?:function\s*&?\s*\w*|fn)\s*\(", region):
        op = lo + mt.end() - 1
        cp = _match_fwd(src, op)
        if cp < 0 or cp >= pos:
            continue
        if re.search(r"\$" + n + r"\b", code[op:cp]):
            pre = code[max(0, lo + mt.start() - 300):lo + mt.start()]
            route = bool(re.search(r"Route\s*::\s*\w+\s*\([^;]*$", pre))
            typed = re.search(r"(?<![\w\\])\??(?:int|float|bool)\s+&?\s*\$" + n + r"\b", code[op:cp]) is not None
            take(lo + mt.start(), "param", {"route": route, "seg": True, "literal": typed})
    if best[0] is None:
        return None
    at, kind, data = best[0]
    appends = []
    for mt in re.finditer(r"\$" + n + r"\b\s*\.=", code[at:pos]):
        rs = at + mt.end()
        appends.append((rs, _expr_end(src, rs, ";")))
    return at, kind, data, appends


def _guarded(src: _Src, name: str, a: int, b: int, mode: _Mode) -> bool:
    """True when the code between a and b checks name against an allowlist."""
    region = src.text[a:b]
    if src.lang == "php":
        n = re.escape(name.lstrip("$"))
        rx = (r"in_array\s*\(\s*\$" + n + r"\b|array_key_exists\s*\(\s*\$" + n + r"\b|isset\s*\(\s*\$\w+\s*\[\s*\$" + n +
              r"\s*\]|\bmatch\s*\(\s*\$" + n + r"\s*\)|\bswitch\s*\(\s*\$" + n + r"\s*\)|preg_match\s*\([^,;]+,\s*\$" + n +
              r"\b|\$" + n + r"\s*!==?\s*['\"][^'\"]|Rule\s*::\s*in\s*\(|['\"]in:"
              r"|ctype_(?:digit|alnum|xdigit|alpha)\s*\(\s*\$" + n + r"\b|is_numeric\s*\(\s*\$" + n + r"\b"
              r"|filter_var\s*\(\s*\$" + n + r"\b[^;]*FILTER_VALIDATE_(?:INT|FLOAT|IP|BOOL|BOOLEAN)\b")
    elif src.lang == "py":
        n = re.escape(name)
        rx = (r"\b" + n + r"\s+(?:not\s+)?in\s+(?!request\b|data\b|body\b|payload\b)[\w\[\(\{'\"]|re\s*\.\s*(?:match|fullmatch)\s*\([^)]*\b" + n +
              r"\b|\bmatch\s+" + n + r"\s*:|\b" + n + r"\s*!=\s*['\"][^'\"]")
    else:
        n = re.escape(name)
        rx = (r"\.\s*(?:includes|has|indexOf)\s*\(\s*" + n + r"\s*\)|\b" + n + r"\s+in\s+[\w$]|\bswitch\s*\(\s*" + n +
              r"\s*\)|\.\s*test\s*\(\s*" + n + r"\s*\)|\b" + n + r"\s*!==?\s*['\"][^'\"]|\.\s*(?:parse|safeParse)\s*\(\s*" + n + r"\b")
    if mode.kind == "nosql":
        nn = re.escape(name.lstrip("$"))
        rx += (r"|typeof\s+" + nn + r"\s*[!=]==?\s*['\"]|\b(?:String|str)\s*\(\s*" + nn + r"\s*\)|\bisinstance\s*\(\s*" + nn + r"\s*,\s*str\b"
               r"|\bisEmail\s*\(\s*" + nn + r"\b")
    return re.search(rx, region) is not None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _classify(src: _Src, s: int, e: int, m: _Mode, depth: int = 0, seen: frozenset = frozenset()) -> _V:
    s, e = _strip(src, s, e)
    if s >= e:
        return _V()
    key = ("cls", s, e, m.key)
    if key in src.memo:
        return src.memo[key]
    v = _classify_inner(src, s, e, m, depth, seen)
    src.memo[key] = v
    return v


def _classify_inner(src: _Src, s: int, e: int, m: _Mode, depth: int, seen: frozenset) -> _V:
    text, code, lang = src.text, src.code, src.lang
    if depth > 7:
        tok = src.tok_at.get(s)
        if tok is not None and tok.end >= e and not tok.islands:
            return _lit(text[tok.bs:tok.be])  # a plain literal stays a literal however deep the trace went
        if _NUMBER.fullmatch(code[s:e]):
            return _V(SAFE, parts=[(SAFE, text[s:e], "", False)])
        return _value(UNKNOWN, text[s:e])
    # prefixes and suffixes that do not change the value
    pm = re.match(r"\s*(await|yield|typeof|void|clone)\s+", code[s:e])
    if pm and pm.end() < e - s:
        if pm.group(1) in ("typeof", "void"):
            return _V(SAFE, parts=[(SAFE, text[s:e], "", False)])
        return _classify(src, s + pm.end(), e, m, depth, seen)
    if lang == "js":
        am = re.search(r"\s+(?:as|satisfies)\s+[\w$.<>\[\]|&\s'\"]+$", code[s:e])
        if am and am.start() > 0 and src.kinds[s + am.start()] == _CODE:
            return _classify(src, s, s + am.start(), m, depth, seen)
        if text[e - 1] == "!" and e - s > 1 and src.kinds[e - 1] == _CODE:
            return _classify(src, s, e - 1, m, depth, seen)
    if lang == "php":
        cm = re.match(r"\(\s*(int|integer|float|double|bool|boolean|string|array)\s*\)", code[s:e])
        if cm:
            if cm.group(1) in ("string", "array"):
                return _classify(src, s + cm.end(), e, m, depth, seen)
            return _V(SAFE, parts=[(SAFE, text[s:e], "", False)])
        if text[s] == "@":
            return _classify(src, s + 1, e, m, depth, seen)
    if lang == "py":
        # a keyword argument (table=TABLE) or a star argument: judge the value
        km = re.match(r"\s*(?:\*{1,2}|[A-Za-z_]\w*\s*=(?!=))", code[s:e])
        if km and km.end() < e - s:
            return _classify(src, s + km.end(), e, m, depth, seen)
    # parenthesized
    if text[s] == "(" and src.kinds[s] == _CODE and _match_fwd(src, s) == e - 1:
        inner = _classify_list(src, s + 1, e - 1, m, depth, seen) if lang == "py" else None
        if inner is not None:
            return inner
        return _classify(src, s + 1, e - 1, m, depth + 1, seen)
    t = _ternary(src, s, e)
    if t is not None:
        cond, a, b = t
        ccode = code[cond[0]:cond[1]]
        picked = _ALLOW_COND.search(ccode)
        if picked and m.kind != "nosql" and re.search(r"\btypeof\b|\bisinstance\b|\bis_string\b", ccode) \
                and not re.search(r"\.\s*(?:includes|has|indexOf)\s*\(|\bin_array\s*\(|\bin\s+[\w\[\(\{]", ccode):
            picked = None
        if picked:
            return _V(SAFE, parts=[(SAFE, text[s:e], "", False)])
        return _alt([_classify(src, a[0], a[1], m, depth + 1, seen), _classify(src, b[0], b[1], m, depth + 1, seen)])
    parts = _split(src, s, e, _t_logic)
    if len(parts) > 1:
        return _alt([_classify(src, a, b, m, depth + 1, seen) for a, b in parts])
    ops = _split(src, s, e, _t_dot_php if lang == "php" else _t_plus)
    if len(ops) == 1 and lang == "py" and m.kind == "path":
        ops = _split(src, s, e, _t_slash_py)
    if len(ops) > 1:
        return _seq([_classify(src, a, b, m, depth + 1, seen) for a, b in ops])
    return _operand(src, s, e, m, depth, seen)


def _classify_list(src: _Src, s: int, e: int, m: _Mode, depth: int, seen: frozenset) -> Optional[_V]:
    """A Python tuple "(a, b)" or "(a,)": the alternatives of its items, or None when it has no comma."""
    raw = _split(src, s, e, lambda sr, i, a, b: 1 if sr.text[i] == "," else 0)
    if len(raw) < 2:
        return None
    items = [x for x in raw if _strip(src, x[0], x[1])[1] > _strip(src, x[0], x[1])[0]]
    if not items:
        return _V()
    out = _alt([_classify(src, a, b, m, depth + 1, seen) for a, b in items])
    out.built = False
    return out


def _tok_value(src: _Src, tok: _Tok, m: _Mode, depth: int, seen: frozenset) -> _V:
    text = src.text
    if tok.quote == "/":
        return _lit("")
    if not tok.islands:
        v = _lit(text[tok.bs:tok.be])
        v.toks.append(tok.start)
        return v
    vs: List[_V] = []
    cur = tok.bs
    for a, b, pre, post in tok.islands:
        vs.append(_lit(text[cur:max(cur, a - pre)]))
        ie = b
        if src.lang == "py":
            ie = _py_island_end(src, a, b)
        vs.append(_classify(src, a, ie, m, depth + 1, seen))
        cur = b + post
    vs.append(_lit(text[cur:tok.be] if cur < tok.be else ""))
    v = _seq(vs)
    v.built = True
    v.is_lit = False
    v.toks.append(tok.start)
    return v


def _py_island_end(src: _Src, a: int, b: int) -> int:
    """Cut an f-string field before its !r conversion, :format spec or = debug marker."""
    text = src.text
    depth = 0
    i = a
    while i < b:
        c = text[i]
        if src.kinds[i] == _CODE:
            if c in "([{":
                depth += 1
            elif c in ")]}":
                depth -= 1
            elif depth == 0:
                if c == ":" and text[i + 1:i + 2] != "=":
                    return i
                if c == "!" and text[i + 1:i + 2] in ("r", "s", "a") and (i + 2 >= b or text[i + 2] == ":"):
                    return i
                if c == "=" and i + 1 >= b and text[i - 1:i] not in ("=", "!", "<", ">"):
                    return i
        i += 1
    return b


def _operand(src: _Src, s: int, e: int, m: _Mode, depth: int, seen: frozenset) -> _V:
    text, code, lang = src.text, src.code, src.lang
    expr = text[s:e]
    ecode = code[s:e]
    tok = src.tok_at.get(s)
    if tok is not None:
        base = _tok_value(src, tok, m, depth, seen)
        if tok.end >= e:
            return base
        rest = code[tok.end:e]
        if lang == "py":
            # "a" "b" written next to each other is one string
            chain = [base]
            j = _next_sig(src, tok.end, e)
            t2 = src.tok_at.get(j)
            while t2 is not None and t2.quote != "/":
                chain.append(_tok_value(src, t2, m, depth, seen))
                j = _next_sig(src, t2.end, e)
                t2 = src.tok_at.get(j)
            if len(chain) > 1:
                joined = _seq(chain)
                joined.built = any(c.built for c in chain)
                if j >= e:
                    return joined
                base = joined
                rest = code[j:e]
                tok_end = j
            else:
                tok_end = tok.end
            pm = re.match(r"\s*%", rest)
            if pm:
                rv = _classify(src, tok_end + pm.end(), e, m, depth + 1, seen)
                out = _seq([base, rv])
                out.built = True
                return out
        else:
            tok_end = tok.end
        mm = re.match(r"\s*\.\s*([A-Za-z_]\w*)\s*\(", rest)
        if mm and mm.group(1) in ("format", "join", "concat", "format_map"):
            op = tok_end + mm.end() - 1
            args, _close = _call_args(src, op)
            avs = [_classify(src, a, b, m, depth + 1, seen) for a, b in args]
            out = _seq([base] + avs)
            out.built = any(not x.is_lit for x in avs) or base.built
            return out
        return base
    if _NUMBER.fullmatch(ecode):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if _CONFIG.match(ecode):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    # array / object / dict literal
    if text[s] in "[{" and src.kinds[s] == _CODE and _match_fwd(src, s) == e - 1:
        return _literal_container(src, s, e, m, depth, seen)
    if lang == "php" and re.match(r"array\s*\(", ecode) and _match_fwd(src, s + ecode.index("(")) == e - 1:
        return _literal_container(src, s + ecode.index("("), e, m, depth, seen)
    # arrow function: judge what it returns
    if lang == "js":
        am = re.match(r"\s*(?:async\s*)?(?:\([^()]*\)|[\w$]+)\s*(?::\s*[^=;{}()]{1,80})?=>", ecode)
        if am:
            return _arrow_body(src, s + am.end(), e, m, depth, seen)
    # arithmetic: in PHP every + - * / % gives a number, in JS every operator but +
    if lang in ("js", "php") and _top_arith(src, s, e):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if lang == "php" and re.match(r"match\s*\(", ecode):
        arms = _php_match_arms(src, s, e)
        if arms:
            return _alt([_classify(src, a, b, m, depth + 1, seen) for a, b in arms])
    # call
    if text[e - 1] == ")" and src.kinds[e - 1] == _CODE:
        p = _match_back(src, e - 1)
        if p > s:
            return _call_value(src, s, p, e, m, depth, seen)
    # a member of a call result: hljs.highlight(code, opts).value
    if lang == "js" and m.kind == "html":
        cm = re.search(r"\)\s*\??\.\s*[A-Za-z_$][\w$]*\s*$", ecode)
        if cm and src.kinds[s + cm.start()] == _CODE:
            p = _match_back(src, s + cm.start())
            if p > s:
                cv = _call_value(src, s, p, s + cm.start() + 1, m, depth, seen)
                if cv.level == SAFE:
                    return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if m.kind == "path" and _SERVER_UPLOAD_PATH.search(expr):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])  # a temp path the server picked
    if lang == "php" and m.kind != "url" and _PHP_SERVER_SRC.fullmatch(expr.strip()):
        return _value(TAINTED, expr)
    if m.sources.search(ecode):
        if lang == "php" and _php_source_validated(src, s, expr):
            return _V(SAFE, parts=[(SAFE, expr, "", False)])
        return _value(TAINTED, expr)
    word = ecode.strip()
    if _IDENT[lang].fullmatch(word):
        return _ident_value(src, word, s, e, m, depth, seen)
    if lang == "php" and re.fullmatch(r"\\?[A-Za-z_][\w\\]*", word):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])  # a bare word in PHP is a constant
    mem = _MEMBER[lang].fullmatch(word)
    if mem:
        return _member_value(src, mem.group(1), mem.group(2), s, e, m, depth, seen)
    if lang == "js" and word.startswith("new "):
        return _value(UNKNOWN, expr, call=True)
    return _value(UNKNOWN, expr)


def _top_arith(src: _Src, s: int, e: int) -> bool:
    """True when the expression has a top-level arithmetic operator that always yields a number."""
    text, kinds, lang = src.text, src.kinds, src.lang
    ops = "+-*/%" if lang == "php" else "-*/%"
    depth = 0
    i = s
    while i < e:
        if kinds[i] != _CODE:
            i += 1
            continue
        c = text[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif depth == 0 and c in ops:
            nx = text[i + 1] if i + 1 < e else ""
            pv = text[i - 1] if i > s else ""
            if nx in ("=", ">") or (c in "+-" and (nx == c or pv == c)) or (c == "/" and pv == "<"):
                i += 2
                continue
            if i > s and _prev_sig(src, i, s) >= s:
                return True
        i += 1
    return False


def _php_match_arms(src: _Src, s: int, e: int) -> List[Tuple[int, int]]:
    """Value spans of the arms of a PHP match (...) { a => x, default => y } expression."""
    code = src.code
    op = code.find("(", s, e)
    cp = _match_fwd(src, op) if op >= 0 else -1
    if cp < 0:
        return []
    ob = _next_sig(src, cp + 1, e)
    if ob >= e or code[ob] != "{" or _match_fwd(src, ob) != e - 1:
        return []
    out = []
    for a, b in _split(src, ob + 1, e - 1, lambda sr, i, x, y: 1 if sr.text[i] == "," else 0):
        arrow = code.find("=>", a, b)
        if arrow >= 0:
            out.append((arrow + 2, b))
    return out


def _loose_rx(expr: str) -> str:
    """A regex for expr that ignores whitespace and the kind of quote."""
    out = []
    for c in expr:
        if c.isspace():
            continue
        out.append("['\"]" if c in "'\"" else re.escape(c))
    return r"\s*".join(out)


# strict PHP checks that leave only digits, hex or word characters (or a number or an IP address)
_PHP_STRICT_CHECK = (r"preg_match\s*\(\s*(['\"])/\^(?:\\d|\\w|\[[\w\\-]{1,30}\])(?:[+*]|\{\d+(?:,\d*)?\})\$/[a-zA-Z]*\1\s*,\s*{x}\s*\)"
                     r"|ctype_(?:digit|alnum|xdigit|alpha)\s*\(\s*{x}\s*\)|is_numeric\s*\(\s*{x}\s*\)"
                     r"|filter_var\s*\(\s*{x}\s*,\s*FILTER_VALIDATE_(?:INT|FLOAT|IP|BOOL|BOOLEAN)\b")


def _php_source_validated(src: _Src, s: int, expr: str) -> bool:
    """True when a superglobal read such as $_GET['id'] was checked with a strict pattern earlier in the file."""
    if not expr.lstrip().startswith("$_"):
        return False
    rx = _PHP_STRICT_CHECK.replace("{x}", _loose_rx(expr))
    return re.search(rx, src.text[max(0, s - 3000):s]) is not None


def _literal_container(src: _Src, s: int, e: int, m: _Mode, depth: int, seen: frozenset) -> _V:
    text = src.text
    items = _split(src, s + 1, e - 1, lambda sr, i, a, b: 1 if sr.text[i] == "," else 0)
    vs = []
    for a, b in items:
        a, b = _strip(src, a, b)
        if b <= a:
            continue
        seg = src.code[a:b]
        if seg.startswith("..."):
            vs.append(_classify(src, a + 3, b, m, depth + 1, seen))
            continue
        sep = _split(src, a, b, lambda sr, i, x, y: (2 if sr.text.startswith("=>", i) else 0) if sr.lang == "php"
                     else (1 if sr.text[i] == ":" and not sr.text.startswith("::", i) else 0))
        if len(sep) > 1:
            vs.append(_classify(src, sep[-1][0], sep[-1][1], m, depth + 1, seen))
        else:
            vs.append(_classify(src, a, b, m, depth + 1, seen))
    out = _alt(vs) if vs else _V()
    if not vs:
        out.parts = [(SAFE, text[s:e], "", False)]
    out.is_lit = False
    out.call = False
    if out.level == SAFE:
        out.parts = [(SAFE, text[s:e], "", False)]
    return out


def _arrow_body(src: _Src, s: int, e: int, m: _Mode, depth: int, seen: frozenset) -> _V:
    s, e = _strip(src, s, e)
    if s < e and src.text[s] == "{" and src.kinds[s] == _CODE:
        close = _match_fwd(src, s)
        body = src.code[s:close if close > 0 else e]
        rm = list(re.finditer(r"\breturn\b", body))
        if not rm:
            return _V()
        rs = s + rm[-1].end()
        return _classify(src, rs, _expr_end(src, rs, ";"), m, depth + 1, seen)
    return _classify(src, s, e, m, depth + 1, seen)


# Calls that pass their input through: which part carries the value.
# "recv" = the object the method is called on, "args" = every argument,
# an int = that argument only.
_PASS_RECV = frozenset(["toString", "trim", "trimStart", "trimEnd", "strip", "lstrip", "rstrip", "toLowerCase",
                        "toUpperCase", "lower", "upper", "slice", "substring", "substr", "as_posix", "expanduser",
                        "normalize", "concat", "replace", "replaceAll", "format", "join", "decode", "encode"])
_PASS_ARGS = frozenset(["String", "str", "strval", "Path", "PurePath", "fspath", "abspath", "realpath", "decodeURIComponent",
                        "decodeURI", "unescape", "urldecode", "rawurldecode", "stripslashes", "URL", "encodeURI",
                        "encodeURIComponent", "quote_plus", "urlencode", "rawurlencode", "urljoin", "sprintf", "implode",
                        "unquote", "join", "resolve", "normalize", "format", "trim", "strtolower", "strtoupper"])
_PASS_SUBJECT = {"sub": 2, "preg_replace": 2, "str_replace": 2, "str_ireplace": 2}
_PATH_RECV = re.compile(r"(?:path|os\s*\.\s*path|posixpath|ntpath|urllib\s*\.\s*parse|parse|urlparse|_|lodash|re|\w+\s*\.\s*path)")


def _call_value(src: _Src, s: int, p: int, e: int, m: _Mode, depth: int, seen: frozenset) -> _V:
    text, code = src.text, src.code
    expr = text[s:e]
    callee = code[s:p].strip()
    recv, name = _callee_parts(callee)
    if not name:
        return _value(UNKNOWN, expr, call=True)
    if m.safe.fullmatch(name):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if src.lang == "php" and name == "prepare" and recv.endswith("wpdb"):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if m.kind == "html" and src.lang == "js":
        hs = _html_safe_call(src, callee)
        if hs:
            return _V(SAFE, parts=[(SAFE, expr, "", False)])
        if hs is None:
            return _value(UNKNOWN, expr)  # mermaid with securityLevel 'loose': as safe as the diagram source
    if m.kind == "html" and _md_call(src, callee):
        if src.lang == "js" and callee.lstrip().startswith("marked") and _marked_sanitized(src):
            return _V(SAFE, parts=[(SAFE, expr, "", False)])
        return _value(DYNAMIC, expr, md=True)
    args, _close = _call_args(src, p)
    if src.lang == "js" and recv == "Object" and name in ("entries", "keys", "values") and args:
        # Object.entries(THEMES): as constant as the object it reads
        return _classify(src, args[0][0], args[0][1], m, depth + 1, seen)
    if (name in ("parse", "safeParse", "parseAsync", "safeParseAsync") and m.kind != "nosql" and args and recv
            and not re.fullmatch(r"Date|Number|Math|path|url|querystring|qs|BigInt", recv)):
        # schema.parse(req.body): the shape is checked, the strings in it are still the client's
        if re.search(r"\b(?:number|int|boolean|bigint|date|uuid|cuid2?|ulid|enum|nativeEnum|literal)\s*\(\s*[^()]*\)"
                     r"(?:\s*\.\s*(?:int|min|max|positive|nonnegative|finite|gte|lte|gt|lt|optional|nullable|default|"
                     r"step|multipleOf)\s*\([^()]*\))*\s*$", recv):
            return _V(SAFE, parts=[(SAFE, expr, "", False)])
        av = _classify(src, args[0][0], args[0][1], m, depth + 1, seen)
        if av.level == TAINTED:
            return _value(TAINTED, expr)
    if name in ("replace", "replaceAll", "sub", "preg_replace") and args and m.kind in ("sql", "cmd", "path", "url", "html"):
        if _SANITIZING_RX.match(text[args[0][0]:args[0][1]].strip()):
            return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if name in ("map", "flatMap") and args and recv:
        return _classify(src, args[0][0], args[0][1], m, depth + 1, seen)
    spans: List[Tuple[int, int]] = []
    if name in _PASS_SUBJECT:
        k = _PASS_SUBJECT[name]
        if k < len(args):
            spans.append(args[k])
    elif recv and name in _PASS_RECV and not _PATH_RECV.fullmatch(recv) and not (src.lang == "py" and name == "join"):
        rm = re.search(r"(?:\?\.|\.|->|::)\s*\$?" + re.escape(name) + r"\s*$", code[s:p].rstrip())
        if rm:
            spans.append((s, s + rm.start()))
        if name in ("concat", "join", "format") and src.lang != "js" or name == "concat":
            spans.extend(args)
        if name in ("replace", "replaceAll") and len(args) > 1:
            spans.append(args[1])
    elif name in _PASS_ARGS:
        spans.extend(args)
    if spans:
        return _alt([_classify(src, a, b, m, depth + 1, seen) for a, b in spans])
    if m.sources.search(code[s:p + 1]):
        # a read straight off the request: searchParams.get(), req.json(), $request->input()
        return _value(TAINTED, expr)
    if m.sources.search(code[s:e]):
        # request data passed into some other function; what comes back is unknown
        return _value(TAINTED, expr, call=True)
    if src.lang == "js" and not recv and depth < 5 and _local_fn_safe(src, name, s, m, depth, seen):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    return _value(UNKNOWN, expr, call=True)


def _local_fn_safe(src: _Src, name: str, pos: int, m: _Mode, depth: int, seen: frozenset) -> bool:
    """True when name is a function defined in this file whose every return value is constant or escaped
    (a helper that wraps a syntax highlighter, for example)."""
    key = ("fn-safe", name, m.key)
    if key in src.memo:
        return src.memo[key]
    src.memo[key] = False  # recursion guard
    code = src.code
    body = None
    dm = re.search(r"\bfunction\s*\*?\s*" + re.escape(name) + r"\s*\(", code)
    if dm:
        cp = _match_fwd(src, dm.end() - 1)
        ob = _next_sig(src, cp + 1, len(code)) if cp > 0 else -1
        if ob > 0 and code[ob:ob + 1] == ":":
            ob = code.find("{", ob)
        if ob > 0 and code[ob:ob + 1] == "{":
            body = (ob, _match_fwd(src, ob))
    else:
        am = re.search(r"\b(?:const|let|var)\s+" + re.escape(name) + r"\s*(?::[^=;]{1,120})?=\s*(?:async\s*)?"
                       r"(?:\([^()]*\)|[\w$]+)\s*(?::\s*[^=;{}()]{1,80})?=>\s*", code)
        if am:
            st = am.end()
            if code[st:st + 1] == "{":
                body = (st, _match_fwd(src, st))
            else:
                v = _classify(src, st, _expr_end(src, st, ";,"), m, depth + 1, seen)
                src.memo[key] = v.level == SAFE
                return src.memo[key]
    if not body or body[1] < 0:
        return False
    rets = list(re.finditer(r"\breturn\b", code[body[0]:body[1]]))
    if not rets:
        return False
    ok = True
    for rm in rets:
        rs = body[0] + rm.end()
        re_ = _expr_end(src, rs, ";")
        if _strip(src, rs, re_)[0] >= re_:
            continue
        if _classify(src, rs, re_, m, depth + 1, seen).level != SAFE:
            ok = False
            break
    src.memo[key] = ok
    return ok


def _ident_value(src: _Src, name: str, s: int, e: int, m: _Mode, depth: int, seen: frozenset) -> _V:
    text = src.text
    bare = name.lstrip("$")
    if _ALL_CAPS.fullmatch(name):
        return _V(SAFE, parts=[(SAFE, name, "", False)])
    if name in ("__dirname", "__filename", "undefined", "null"):
        return _V(SAFE, parts=[(SAFE, name, "", False)])
    if m.kind == "sql" and _SQL_SAFE_NAME.fullmatch(bare):
        # a table name or a placeholder list; still report it when it comes straight from the request
        if (name, s) not in seen:
            v = _ident_value_traced(src, name, s, e, m, depth, seen)
            if v.level == TAINTED:
                return v
        return _V(SAFE, parts=[(SAFE, name, "", False)])
    if (name, s) in seen:
        return _value(UNKNOWN, name)
    return _ident_value_traced(src, name, s, e, m, depth, seen)


_PY_SAFE_ANNOT = re.compile(r"\s*(?:Optional\s*\[\s*)?(?:int|float|bool|Literal\s*\[[^\]]*\]|(?:datetime\s*\.\s*)?(?:datetime|date|time|"
                            r"timedelta)|(?:uuid\s*\.\s*)?UUID|Decimal|PositiveInt|NonNegativeInt)\s*\]?\s*(?:\|\s*None\s*)?")


def _ident_value_traced(src: _Src, name: str, s: int, e: int, m: _Mode, depth: int, seen: frozenset) -> _V:
    tr = _trace(src, name, s)
    if tr is None:
        return _value(UNKNOWN, name)
    at, kind, data, appends = tr
    if kind == "import":
        return _V(SAFE, parts=[(SAFE, name, "", False)])
    if _guarded(src, name, at, s, m):
        return _V(SAFE, parts=[(SAFE, name, "", False)])
    seen2 = seen | {(name, s)}
    if kind == "assign" and data[0] <= s < data[1] and depth < 7:
        # x = x.replace(...): the x on the right is the value from before this line
        return _ident_value(src, name, at, at + len(name), m, depth + 1, seen2)
    if kind == "param":
        info = data or {}
        if info.get("literal") or info.get("cli"):
            return _V(SAFE, parts=[(SAFE, name, "", False)])
        if src.lang == "py" and info.get("annot") and _PY_SAFE_ANNOT.fullmatch(info["annot"]):
            return _V(SAFE, parts=[(SAFE, name, "", False)])
        if info.get("server_fn"):
            return _value(TAINTED, name)
        if info.get("then") and depth < 7:
            rv = _classify(src, info["then"][0], info["then"][1], m, depth + 1, seen2)
            if rv.level == SAFE:
                return _V(SAFE, parts=[(SAFE, name, "", False)])
            if rv.level == TAINTED:
                return _value(TAINTED, name)
        if src.lang in ("py", "php") and info.get("route") and m.route_params:
            return _value(TAINTED, name, seg=bool(info.get("seg")))
        if src.lang == "js" and info.get("open") is not None and _literal_callers(src, at, info["open"], name):
            return _V(SAFE, parts=[(SAFE, name, "", False)])
        return _value(UNKNOWN, name)
    if kind == "state":
        rv = _state_value(src, data[0], data[1], m, depth, seen2)
        if rv.level == SAFE:
            return _V(SAFE, parts=[(SAFE, name, "", False)])
        if rv.level in (TAINTED, DYNAMIC):
            return _value(rv.level, name)  # set from the request, or from fetched data
        return _value(UNKNOWN, name)
    if kind == "assign":
        a, b = data
        base = _classify(src, a, b, m, depth + 1, seen2)
    elif kind == "destr":
        (a, b), _k = data
        rv = _classify(src, a, b, m, depth + 1, seen2)
        if rv.level in (SAFE, TAINTED):
            lvl = rv.level
        elif rv.level == DYNAMIC or rv.call:
            lvl = DYNAMIC
        else:
            lvl = UNKNOWN
        seg = all(p[3] for p in rv.parts if p[0] == TAINTED) if lvl == TAINTED else False
        base = _value(lvl, name, seg=seg) if lvl != SAFE else _V(SAFE, parts=[(SAFE, name, "", False)])
    elif kind == "loop":
        a, b = data
        cv = _classify(src, a, b, m, depth + 1, seen2)
        if cv.level == SAFE:
            base = _V(SAFE, parts=[(SAFE, name, "", False)])
        elif cv.level == TAINTED:
            base = _value(TAINTED, name)
        else:
            base = _value(DYNAMIC, name)
    else:
        base = _value(UNKNOWN, name)
    if appends:
        vs = [base] + [_classify(src, a, b, m, depth + 1, seen2) for a, b in appends]
        out = _seq(vs)
        return out
    return base


def _state_value(src: _Src, open_i: int, setter: str, m: _Mode, depth: int, seen: frozenset) -> _V:
    """What a React useState variable can hold: its initial value and everything passed to its setter."""
    code = src.code
    vs: List[_V] = []
    args, _c = _call_args(src, open_i)
    if args:
        vs.append(_classify(src, args[0][0], args[0][1], m, depth + 1, seen))
    if setter:
        rx = re.escape(setter)
        for mt in re.finditer(r"(?<![\w$.])" + rx + r"\b", code):
            k = _next_sig(src, mt.end(), len(code))
            before = code[max(0, mt.start() - 40):mt.start()]
            if k < len(code) and code[k] == "(":
                sargs, _c2 = _call_args(src, k)
                if sargs:
                    vs.append(_classify(src, sargs[0][0], sargs[0][1], m, depth + 1, seen))
                continue
            if re.search(r"[\[,]\s*$", before) and re.match(r"\s*\]\s*=", code[mt.end():mt.end() + 40]):
                continue  # the useState destructuring itself
            tm = re.search(r"\.\s*then\s*\(\s*$", before)
            if tm and k < len(code) and code[k] == ")":
                dot = max(0, mt.start() - 40) + tm.start()
                rs = _back_operand(src, dot)
                vs.append(_classify(src, rs, dot, m, depth + 1, seen))
                continue
            vs.append(_value(UNKNOWN, setter))  # passed somewhere else: unknown values
    return _alt(vs) if vs else _V()


def _literal_callers(src: _Src, at: int, open_i: int, name: str) -> bool:
    """True when name is a parameter of a function declared in this file that is not exported or passed
    around, and every call in the file passes a string or number literal in that position."""
    code = src.code
    hm = re.match(r"(?:(?:async\s+)?function\s*\*?\s*)?([\w$]+)\s*\(", code[at:open_i + 1])
    if not hm or not (code[at:at + hm.start(1)].strip() or re.search(r"\bfunction\s*\*?\s*$", code[max(0, at - 30):at])):
        return False
    fname = hm.group(1)
    close = _match_fwd(src, open_i)
    if close < 0:
        return False
    params = [x for x in _split(src, open_i + 1, close, lambda sr, i, a, b: 1 if sr.text[i] == "," else 0)]
    idx = -1
    for k, (a, b) in enumerate(params):
        if name in _js_param_names(code[a:b]):
            idx = k
            break
    if idx < 0:
        return False
    if re.search(r"\bexport\b[^;\n]*\b" + re.escape(fname) + r"\b|exports\s*\.\s*" + re.escape(fname) + r"\b", code):
        return False
    calls = 0
    for mt in re.finditer(r"(?<![\w$.])" + re.escape(fname) + r"\b", code):
        if mt.start() == at + hm.start(1):
            continue
        k = _next_sig(src, mt.end(), len(code))
        if k >= len(code) or code[k] != "(":
            return False  # referenced without a call: exported or passed as a callback
        args, _c = _call_args(src, k)
        if idx >= len(args):
            return False
        a, b = args[idx]
        tok = src.tok_at.get(a)
        if not ((tok is not None and tok.end >= b and not tok.islands and tok.quote != "/") or _NUMBER.fullmatch(code[a:b])):
            return False
        calls += 1
    return calls > 0


def _member_value(src: _Src, root: str, tail: str, s: int, e: int, m: _Mode, depth: int, seen: frozenset) -> _V:
    expr = src.text[s:e]
    lm = _LAST_NAME.search(tail)
    last = lm.group(1) if lm else ""
    if not last:
        km = re.search(r"\[\s*['\"]?([\w$]+)['\"]?\s*\]\s*$", src.text[s:e])
        last = km.group(1) if km else ""
    if _ALL_CAPS.fullmatch(root) or (last and _ALL_CAPS.fullmatch(last)):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if m.kind in ("html", "url", "path", "cmd") and last and _NUMERIC_NAME.fullmatch(last):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if m.kind == "sql" and last and _SQL_SAFE_NAME.fullmatch(last):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if root in ("this", "$this", "self", "cls", "super", "window", "globalThis", "document", "props"):
        if root == "document" and m.kind == "html":
            return _value(UNKNOWN, expr)
        return _value(DYNAMIC if root in ("this", "$this", "self", "props") else UNKNOWN, expr)
    if root in ("Math", "Date", "JSON", "Object", "Number", "path", "os", "process", "console"):
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    rv = _ident_value(src, root, s, s + len(root), m, depth + 1, seen)
    if rv.level == SAFE:
        return _V(SAFE, parts=[(SAFE, expr, "", False)])
    if rv.level == TAINTED:
        seg = all(p[3] for p in rv.parts if p[0] == TAINTED)
        return _value(TAINTED, expr, seg=seg)
    return _value(DYNAMIC, expr)


# ---------------------------------------------------------------------------
# Shared rule plumbing
# ---------------------------------------------------------------------------

def _hit(ctx: Any, rel: str, off: int, message: Optional[str] = None, severity: Optional[str] = None) -> Hit:
    line = ctx.line_of(rel, off)
    lines = ctx.lines(rel)
    ln = lines[line - 1] if 0 < line <= len(lines) else ""
    text = ctx.read(rel)
    col = off - (text.rfind("\n", 0, off) + 1)
    return Hit(line, clip(ln, col, col + 40), message, severity)


# Third-party browser libraries that get committed next to app code (static/js/jquery.sparkline.js).
_VENDOR_FILE = re.compile(r"(?i)^(?:jquery|bootstrap|popper|moment|lodash|underscore|d3|chart|highcharts|select2|datatables|"
                          r"raphael|modernizr|backbone|knockout|handlebars|mustache|leaflet|tinymce|ckeditor|codemirror|"
                          r"sparkline|flot|morris|summernote|dropzone|fullcalendar|sweetalert2?)(?:[.-][\w.-]*)?\.js$")


_PHP_LIB_DIR = re.compile(r"(?:^|/)(?:lib|libs|library|libraries|vendor|vendors|third[_-]?party|external|extlib|contrib)/", re.I)


def _vendored(text: str, path: str = "") -> bool:
    """A third-party library copied into the repo: a license banner, or a well-known library file name.
    PHP app code (WordPress plugins, for example) often carries an @license docblock too, so for PHP the
    banner counts only inside a library folder such as lib/ or vendor/."""
    head = text[:2000]
    if path.lower().endswith(".php"):
        return ("@license" in head or "* @version" in head or "@copyright" in head) and _PHP_LIB_DIR.search(path) is not None
    if "@license" in head or head.lstrip().startswith("/*!") or "* @version" in head:
        return True
    if path and _VENDOR_FILE.match(path.rsplit("/", 1)[-1]):
        return True
    # a release banner: a version number plus a copyright and a license line (an app's own GPL header has no x.y.z)
    top = head[:800]
    return (re.search(r"\bv?\d+\.\d+\.\d+\b", top) is not None and re.search(r"(?i)\(c\)|copyright", top) is not None
            and re.search(r"(?i)\blicen[sc]e[ds]?\b", top) is not None)


def _is_call_part(p: tuple) -> bool:
    return len(p) > 4 and bool(p[4])


def _worst(v: _V, threshold: int, skip_unknown_calls: bool = False) -> Optional[tuple]:
    """The most dangerous part at or above threshold. With skip_unknown_calls,
    a part that is only an unknown helper call (level UNKNOWN) does not count."""
    best = None
    for p in v.parts:
        if p[0] < threshold:
            continue
        if skip_unknown_calls and p[0] == UNKNOWN and _is_call_part(p):
            continue
        if best is None or p[0] > best[0]:
            best = p
    return best


_JS_REQ_FILE = re.compile(r"\b(?:req|request)\s*[,)]|\bNextRequest\b|\bexport\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)\b|"
                          r"['\"]use server['\"]|\b(?:app|router|server|fastify)\s*\.\s*(?:get|post|put|patch|delete|all|route)\s*\(|"
                          r"\bc\s*\.\s*req\b|\bctx\s*\.\s*request\b|\bevent\s*\.\s*body\b")
_PY_REQ_FILE = re.compile(r"@\s*[\w.]+\s*\.\s*(?:route|get|post|put|patch|delete|api_route)\s*\(|\brequest\s*\.\s*(?:args|form|json|GET|POST|data|files|FILES)\b|"
                          r"\bdef\s+\w+\s*\(\s*request\b|\bAPIRouter\b|\bFastAPI\s*\(|\bFlask\s*\(")
_PHP_REQ_FILE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|\$request\s*->|Request\s+\$request|\brequest\s*\(")


def _req_file(src: _Src) -> bool:
    rx = {"py": _PY_REQ_FILE, "php": _PHP_REQ_FILE}.get(src.lang, _JS_REQ_FILE)
    return rx.search(src.code) is not None


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------

_SQL_STRONG = re.compile(r"(?is)\bselect\b.{0,600}?\bfrom\b|\binsert\s+into\b|\bupdate\s+[\w`\"\[\].$?{}]+\s+set\b|"
                         r"\bdelete\s+from\b|\b(?:create|drop|alter|truncate)\s+table\b|\bmerge\s+into\b|\breplace\s+into\b")
_SQL_WEAK = re.compile(r"(?is)\bwhere\b.{0,300}?(?:=|<|>|\blike\b|\bin\b|\bis\b)|\border\s+by\b|\bgroup\s+by\b|\bvalues\s*\(|"
                       r"\blimit\s+\S|\bjoin\b.{0,200}?\bon\b")
_SQL_IDENT_CTX = re.compile(r"(?is)\b(?:order|group)\s+by\s+(?:[\w.\"`\[\]]+\s*(?:asc|desc)?\s*,\s*)*[\"`\[]?$|"
                            r"\b(?:order|group)\s+by\s+[\w.\"`\[\]]+\s+$")
_SQL_PLACEHOLDER = re.compile(r"\$\d+|\?|(?<![:\w]):[A-Za-z_]\w*|%s|%\([A-Za-z_]\w*\)s|@[A-Za-z_]\w*")

_M_SQL = {
    "js": _Mode("js", "sql", _JS_SOURCES_X, _SAFE_SQL),
    "py": _Mode("py", "sql", _PY_SOURCES_X, _SAFE_SQL),
    "php": _Mode("php", "sql", _PHP_SOURCES_X, _SAFE_SQL),
}


_NUMERIC_SQL_CTX = re.compile(r"(?i)\b(?:limit|offset|top|skip)\s*\(?\s*$|\bfetch\s+(?:first|next)\s+$")


def _typed_number(src: Optional[_Src], expr: str) -> bool:
    """True when the last name in expr is declared as a number in this TypeScript file (limit?: number)."""
    if src is None or src.lang != "js":
        return False
    m = re.search(r"([A-Za-z_$][\w$]*)\s*$", expr)
    if not m:
        return False
    return re.search(r"(?<![\w$])" + re.escape(m.group(1)) + r"\s*\??\s*:\s*(?:number|bigint)\b", src.text) is not None


def _sql_judge(v: _V, params: bool, implied: bool, strong_only: bool, src: Optional[_Src] = None) -> Optional[tuple]:
    """(level, expr, ident_context) of the worst unsafe part, or None."""
    if not v.built:
        if implied and v.level == TAINTED and not v.call:
            return (TAINTED, v.parts[0][1] if v.parts else "", False)
        return None
    if not implied:
        if not _SQL_STRONG.search(v.lit) and (strong_only or not _SQL_WEAK.search(v.lit)):
            return None
    worst = None
    for p in v.parts:
        lv, t, before = p[0], p[1], p[2]
        if lv == UNKNOWN and _is_call_part(p):
            continue  # an unknown helper call (formatDate(d), buildWhere(f)) is not judged
        if lv < TAINTED and _NUMERIC_SQL_CTX.search(before[-40:]) and _typed_number(src, t):
            continue  # LIMIT ${limit} where limit is typed number
        ident = _SQL_IDENT_CTX.search(before[-80:]) is not None
        thr = UNKNOWN if (not params or ident) else TAINTED
        if lv >= thr and (worst is None or lv > worst[0]):
            worst = (lv, t, ident)
    return worst


def _sql_message(prefix: str, w: tuple) -> Tuple[str, str]:
    lv, expr, ident = w
    ex = _short(expr)
    if ident:
        msg = "%s: ORDER BY / column name comes from %s with no allowlist" % (prefix, ex)
    elif lv == TAINTED:
        msg = "%s: SQL built from request input (%s); bind it as a parameter" % (prefix, ex)
    else:
        msg = "%s: SQL string built with %s; use a bound parameter unless it is a fixed constant" % (prefix, ex)
    return msg, ("critical" if lv == TAINTED else "high")


_PRISMA_SINK = re.compile(r"\$(?:queryRawUnsafe|executeRawUnsafe)\b\s*(?:<[^<>()]{0,200}>)?\s*\(|\bPrisma\s*\.\s*raw\s*\(")


def check_sqli_prisma_unsafe(path: str, text: str, ctx: Any) -> List[Hit]:
    if "RawUnsafe" not in text and "Prisma.raw" not in text:
        return []
    src = _src(ctx, path, "js")
    out = []
    for mt in _PRISMA_SINK.finditer(src.code):
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        lit_args = len(args) > 1
        v = _classify(src, args[0][0], args[0][1], _M_SQL["js"])
        w = _sql_judge(v, params=lit_args, implied=True, strong_only=False, src=src)
        if not w:
            continue
        name = "Prisma.raw" if "Prisma" in mt.group(0) else mt.group(0).split("(")[0].strip().split("<")[0].strip()
        msg, sev = _sql_message(name, w)
        out.append(_hit(ctx, path, mt.start(), msg, sev))
    return out


def _js_params_arg(src: _Src, span: Tuple[int, int]) -> bool:
    """True when the second argument of a query call looks like bound values, not a callback."""
    a, b = _strip(src, span[0], span[1])
    seg = src.code[a:b]
    if re.match(r"\s*(?:async\s*)?(?:function\b|\([^()]*\)\s*=>|[\w$]+\s*=>)", seg):
        return False
    if seg.startswith("["):
        return re.fullmatch(r"\[\s*\]", seg.strip()) is None
    if seg.startswith("{"):
        return re.search(r"\b(?:replacements|bind|values|params)\s*:", seg) is not None
    return re.fullmatch(r"[\w$.]+", seg.strip()) is not None


_JS_SQL_SINK = re.compile(
    r"\.\s*(query|execute|executeQuery|raw|unsafe|literal|run|all|get|each|exec|prepare|"
    r"whereRaw|orWhereRaw|andWhereRaw|havingRaw|orHavingRaw|orderByRaw|groupByRaw|joinRaw|selectRaw|fromRaw)\s*(?:<[^<>()]{0,200}>)?\s*\("
    r"|(?<![\w$.])(query|execute)\s*(?:<[^<>()]{0,200}>)?\s*\("
    # project wrappers: runQuery(sql), dbQuery(sql), executeSql(sql), db.execSQL(sql), runStatement(sql)
    r"|(?<![\w$])((?:[a-z][\w$]*)?(?:Query|Sql|SQL|Statement))\s*(?:<[^<>()]{0,200}>)?\s*\(")
_JS_IMPLIED = frozenset(["unsafe", "literal", "whereRaw", "orWhereRaw", "andWhereRaw", "havingRaw", "orHavingRaw",
                         "orderByRaw", "groupByRaw", "joinRaw", "selectRaw", "fromRaw"])
_JS_STRONG_ONLY = frozenset(["run", "all", "get", "each", "exec", "prepare"])
_ORDER_FRAG = re.compile(r"(?is)\b(?:order|group)\s+by\s+(?:[\w.\"`\[\]]+\s*(?:asc|desc)?\s*,\s*)*[\"`\[]?$")
# a whole statement at the start of a string: SELECT ... FROM, INSERT INTO, UPDATE x SET, DELETE FROM
# (the column list is names joined by commas, so prose such as "Select a file from your disk" does not match)
_SQL_STMT_START = re.compile(r"(?is)^\s*(?:select\s+(?:distinct\s+)?(?:\*|[\w\"`.()*]+(?:\s+as\s+[\w\"`]+)?)"
                             r"(?:\s*,\s*[\w\"`.()*]+(?:\s+as\s+[\w\"`]+)?)*\s+from\s|insert\s+(?:or\s+\w+\s+)?into\s|"
                             r"update\s+[\w`\"\[\].]+\s+set\s|delete\s+from\s+[\w`\"\[\].]+(?:\s+where\b|\s*;|\s*$))")


def _sql_fragments(ctx: Any, path: str, src: _Src, mode: _Mode, skip: set) -> List[Hit]:
    """Strings built outside a sink call: ORDER BY / GROUP BY fed from the request, and whole statements
    (SELECT ... FROM, INSERT INTO ...) that take request input, whatever function they are later passed to."""
    out = []
    lines: set = set()

    def add(off: int, msg: str, sev: str) -> None:
        ln = ctx.line_of(path, off)
        if ln not in lines:
            lines.add(ln)
            out.append(_hit(ctx, path, off, msg, sev))

    for tok in src.toks:
        if tok.start in skip or tok.quote == "/":
            continue
        body = src.text[tok.bs:tok.be]
        stmt = _SQL_STMT_START.match(body) is not None
        if stmt and tok.quote == "`":
            p = _prev_sig(src, tok.start, max(0, tok.start - 60))
            wm = re.search(r"[\w$]+$", src.code[max(0, p - 40):p + 1]) if p >= 0 else None
            if wm and wm.group(0) not in _JS_RX_WORDS and wm.group(0) not in ("return", "in", "of", "case"):
                continue  # a tagged template (sql`...`, Prisma.sql`...`) binds its values
        if tok.islands:
            for a, b, pre, post in tok.islands:
                before = src.text[tok.bs:max(tok.bs, a - pre)]
                ie = _py_island_end(src, a, b) if src.lang == "py" else b
                if _ORDER_FRAG.search(before[-80:]):
                    v = _classify(src, a, ie, mode)
                    if v.level == TAINTED:
                        add(a, "ORDER BY / GROUP BY column comes from request input (%s) with no allowlist"
                            % _short(src.text[a:ie]), "high")
                elif stmt:
                    v = _classify(src, a, ie, mode)
                    if v.level == TAINTED and not v.call:
                        add(tok.start, "SQL statement built from request input (%s); whatever runs it, bind the value as "
                                       "a parameter" % _short(src.text[a:ie]), "critical")
                        break
            continue
        rest = src.code[tok.end:tok.end + 200]
        pm = re.match(r"\s*\.(?![.=])" if src.lang == "php" else r"\s*\+(?![+=])", rest)
        if not pm:
            continue
        if _ORDER_FRAG.search(body[-80:]):
            os_ = tok.end + pm.end()
            oe = _expr_end(src, os_, ";,")
            ops = _split(src, os_, oe, _t_dot_php if src.lang == "php" else _t_plus)
            a, b = ops[0]
            v = _classify(src, a, b, mode)
            if v.level == TAINTED:
                add(a, "ORDER BY / GROUP BY column comes from request input (%s) with no allowlist"
                    % _short(src.text[a:b]), "high")
        elif stmt:
            oe = _expr_end(src, tok.start, ";,")
            v = _classify(src, tok.start, oe, mode)
            for p in v.parts:
                if p[0] == TAINTED and not _is_call_part(p):
                    add(tok.start, "SQL statement built from request input (%s); whatever runs it, bind the value as a "
                                   "parameter" % _short(p[1]), "critical")
                    break
    return out


def _sql_object_arg(src: _Src, span: Tuple[int, int]) -> Optional[Tuple[Tuple[int, int], bool]]:
    """For pool.query({ name, text, values }): the span of the text / sql / query property and whether values
    are bound. None when the argument is not an object literal."""
    a, b = _strip(src, span[0], span[1])
    if b <= a or src.text[a] != "{" or _match_fwd(src, a) != b - 1:
        return None
    text_span = None
    bound = False
    for x, y in _split(src, a + 1, b - 1, lambda sr, i, p, q: 1 if sr.text[i] == "," else 0):
        x, y = _strip(src, x, y)
        km = re.match(r"['\"]?(\w+)['\"]?\s*(:)?", src.text[x:y])
        if not km:
            continue
        key = km.group(1)
        if key in ("text", "sql", "query"):
            text_span = (x + km.end(), y) if km.group(2) else (x, y)
        elif key in ("values", "params", "bind", "replacements", "parameters"):
            bound = True
    if text_span is None:
        return ((b, b), bound)
    return (text_span, bound)


def _postgrest_trusted(expr: str) -> bool:
    """The signed-in user's own id (user.id, session.user.id, auth.user.id): issued by the auth server."""
    return re.search(r"(?:^|[.\s(])(?:user|currentUser|authUser|me)\s*\??\.\s*(?:id|sub|email)\s*$|"
                     r"(?:getUser|getClaims|getSession)\s*\(", expr) is not None


_WEBHOOK_VERIFIED = re.compile(r"\bcreateHmac\s*\(|\bhmac\s*\(|\btimingSafeEqual\s*\(|\bconstructEvent(?:Async)?\s*\(|"
                               r"\bvalidateWebhookSignature\s*\(|\bverifyWebhookSignature\s*\(|\bvalidateSignature\s*\(|"
                               r"\bcrypto\s*\.\s*subtle\s*\.\s*verify\s*\(|\bWebhook\s*\(\s*[^)]*\)\s*\.\s*verify\s*\(")


def check_sqli_js_string(path: str, text: str, ctx: Any) -> List[Hit]:
    if _vendored(text, path):
        return []
    low = text.lower()
    if not any(k in low for k in ("select", "insert", "update", "delete", "order by", "group by", "raw", "literal", "unsafe",
                                  ".or(")):
        return []
    src = _src(ctx, path)
    mode = _M_SQL["js"]
    out = []
    seen_toks: set = set()
    for mt in _JS_SQL_SINK.finditer(src.code):
        meth = mt.group(1) or mt.group(2) or mt.group(3)
        if mt.group(3) and re.search(r"\b(?:function|def|class)\s+$|\bnew\s+$", src.code[max(0, mt.start() - 12):mt.start()]):
            continue
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        first = args[0]
        bound = False
        obj = _sql_object_arg(src, first)
        if obj is not None:
            if obj[0][0] >= obj[0][1]:
                continue  # an options object with no SQL text in it
            first, bound = obj
        v = _classify(src, first[0], first[1], mode)
        seen_toks.update(v.toks)
        params = bound or (len(args) > 1 and (bool(_SQL_PLACEHOLDER.search(v.lit)) or _js_params_arg(src, args[1])))
        strong = meth in _JS_STRONG_ONLY or bool(mt.group(3))
        w = _sql_judge(v, params=params, implied=meth in _JS_IMPLIED, strong_only=strong, src=src)
        if not w:
            continue
        msg, sev = _sql_message(meth + "()", w)
        out.append(_hit(ctx, path, mt.start(), msg, sev))
    out.extend(_sql_fragments(ctx, path, src, mode, seen_toks))
    if ".or(" in text or ".or (" in text:
        # supabase-js / PostgREST: .or() takes raw filter syntax and escapes nothing
        client = ctx.is_client_file(path)
        verified = _WEBHOOK_VERIFIED.search(src.code) is not None
        for mt in re.finditer(r"\.\s*or\s*\(", src.code):
            args, _c = _call_args(src, mt.end() - 1)
            if not args:
                continue
            v = _classify(src, args[0][0], args[0][1], mode)
            if not v.built or not _POSTGREST_SYNTAX.search(v.lit):
                continue
            parts = [p for p in v.parts if p[0] >= UNKNOWN and not (p[0] == UNKNOWN and _is_call_part(p))
                     and not _postgrest_trusted(p[1]) and not verified]
            if not parts:
                continue
            w = max(parts, key=lambda p: p[0])
            msg = (".or() builds a PostgREST filter string from %s; commas and dots in the value add filters. "
                   "Use .eq() / .ilike() or allowlist the value" % _short(w[1]))
            sev = "high" if w[0] == TAINTED else "medium"
            if client:
                sev = "low"
                msg += ("; in browser code this only changes the caller's own query under RLS, and becomes real if "
                        "the code moves to a service-role function")
            out.append(_hit(ctx, path, mt.start(), msg, sev))
    return out


_POSTGREST_SYNTAX = re.compile(r"\w+\.(?:eq|neq|gt|gte|lt|lte|like|ilike|is|in|cs|cd|ov|fts|plfts|phfts|wfts|match|imatch)\.")


_PY_SQL_SINK = re.compile(
    r"\.\s*(execute|executemany|executescript|raw|mogrify|exec_driver_sql|extra)\s*\("
    r"|(?<![\w.])(RawSQL|text|read_sql|read_sql_query)\s*\("
    r"|\b(?:sa|sqlalchemy|pd|pandas)\s*\.\s*(text|read_sql|read_sql_query)\s*\(")
_PY_IMPLIED = frozenset(["RawSQL", "text", "extra", "executescript", "exec_driver_sql"])


def check_sqli_python_string(path: str, text: str, ctx: Any) -> List[Hit]:
    low = text.lower()
    if not any(k in low for k in ("select", "insert", "update", "delete", "order by", "rawsql", ".extra(", "where")):
        return []
    src = _src(ctx, path, "py")
    mode = _M_SQL["py"]
    sa_text = re.search(r"from\s+sqlalchemy(?:\.\w+)*\s+import\s+[^\n]*\btext\b", src.code) is not None
    out = []
    seen_toks: set = set()
    for mt in _PY_SQL_SINK.finditer(src.code):
        meth = mt.group(1) or mt.group(2) or mt.group(3)
        if mt.group(2) == "text" and not sa_text:
            continue
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        if meth == "extra":
            w = None
            for a, b in args:
                eq = re.match(r"\s*(\w+)\s*=", src.code[a:b])
                if eq and eq.group(1) == "params":
                    continue
                vs = _classify(src, a + (eq.end() if eq else 0), b, mode)
                seen_toks.update(vs.toks)
                cand = _sql_judge(vs, params=False, implied=True, strong_only=False)
                if cand and (w is None or cand[0] > w[0]):
                    w = cand
            quoted = any(re.search(r"'%s'|\"%s\"", src.text[t.bs:t.be]) for t in src.toks if mt.end() <= t.start < (_c if _c > 0 else mt.end()))
            if not w and quoted:
                out.append(_hit(ctx, path, mt.start(), ".extra(): placeholder is quoted ('%s'), which Django documents as unsafe; "
                                                       "drop the quotes and pass params=[...]", "high"))
                continue
            if w:
                msg, sev = _sql_message(".extra()", w)
                out.append(_hit(ctx, path, mt.start(), msg, sev))
            continue
        first = args[0]
        fcode = src.code[first[0]:first[1]]
        if meth in ("execute", "executemany") and re.match(r"\s*(?:sa\s*\.\s*|sqlalchemy\s*\.\s*)?text\s*\(", fcode):
            continue
        v = _classify(src, first[0], first[1], mode)
        seen_toks.update(v.toks)
        # a second positional argument (or params=) to execute()/raw()/RawSQL() is the parameter list,
        # unless it is empty: RawSQL(f"...", []) binds nothing
        empty = re.compile(r"\s*(?:\[\s*\]|\(\s*\)|\{\s*\}|None|(?:tuple|list|dict)\(\s*\))\s*$")
        positional = [x for x in args[1:] if not re.match(r"\s*\w+\s*=(?!=)", src.code[x[0]:x[1]])
                      and not empty.match(src.code[x[0]:x[1]])]
        params = bool(positional) or any(re.match(r"\s*params\s*=(?!\s*(?:\[\s*\]|\(\s*\)|None)\s*$)", src.code[x[0]:x[1]])
                                         for x in args[1:])
        w = _sql_judge(v, params=params, implied=meth in _PY_IMPLIED, strong_only=False)
        if not w:
            continue
        msg, sev = _sql_message(meth + "()", w)
        out.append(_hit(ctx, path, mt.start(), msg, sev))
    out.extend(_sql_fragments(ctx, path, src, mode, seen_toks))
    return out


_PHP_SQL_SINK = re.compile(
    r"\bDB\s*::\s*(raw|select|selectOne|scalar|statement|unprepared|insert|update|delete|affectingStatement)\s*\("
    r"|(?:->|::)\s*(whereRaw|orWhereRaw|havingRaw|orHavingRaw|orderByRaw|groupByRaw|selectRaw|fromRaw|joinRaw)\s*\("
    r"|->\s*(query|exec|prepare|multi_query|real_query|get_results|get_row|get_var|get_col)\s*\("
    r"|(?<![\w>:$])(mysqli_query|mysqli_multi_query|mysqli_real_query|mysqli_prepare|pg_query|pg_prepare|pg_send_query)\s*\(")
_PHP_IMPLIED = frozenset(["raw", "unprepared", "whereRaw", "orWhereRaw", "havingRaw", "orHavingRaw", "orderByRaw",
                          "groupByRaw", "selectRaw", "fromRaw", "joinRaw", "select", "selectOne", "scalar", "statement",
                          "insert", "update", "delete", "affectingStatement"])


def check_sqli_php_string(path: str, text: str, ctx: Any) -> List[Hit]:
    if _vendored(text, path):
        return []
    low = text.lower()
    if not any(k in low for k in ("select", "insert", "update", "delete", "raw(", "order by")):
        return []
    src = _src(ctx, path, "php")
    mode = _M_SQL["php"]
    out = []
    seen_toks: set = set()
    for mt in _PHP_SQL_SINK.finditer(src.code):
        meth = mt.group(1) or mt.group(2) or mt.group(3) or mt.group(4)
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        idx = 0
        if meth in ("mysqli_query", "mysqli_multi_query", "mysqli_real_query", "mysqli_prepare", "pg_send_query"):
            idx = 1
        elif meth == "pg_query":
            idx = 1 if len(args) > 1 else 0
        elif meth == "pg_prepare":
            idx = 2
        if idx >= len(args):
            continue
        a, b = args[idx]
        v = _classify(src, a, b, mode)
        seen_toks.update(v.toks)
        if mt.group(1) or mt.group(2):
            params = len(args) > idx + 1
        elif meth in ("prepare", "mysqli_prepare", "pg_prepare"):
            params = True
        else:
            params = False
        params = params and bool(_SQL_PLACEHOLDER.search(v.lit))
        implied = meth in _PHP_IMPLIED and bool(mt.group(1) or mt.group(2))
        w = _sql_judge(v, params=params, implied=implied, strong_only=False)
        if not w:
            continue
        label = ("DB::" + meth) if mt.group(1) else meth
        msg, sev = _sql_message(label + "()", w)
        out.append(_hit(ctx, path, mt.start(), msg, sev))
    out.extend(_sql_fragments(ctx, path, src, mode, seen_toks))
    return out


_PHP_ORDER = re.compile(r"(?:->|::)\s*(orderBy|orderByDesc|groupBy|latest|oldest|reorder)\s*\(")


def check_sqli_laravel_column(path: str, text: str, ctx: Any) -> List[Hit]:
    if not re.search(r"(?:->|::)\s*(?:orderBy|orderByDesc|groupBy|latest|oldest|reorder)\s*\(", text):
        return []
    src = _src(ctx, path, "php")
    if re.search(r"Rule\s*::\s*in\s*\(|['\"]in:|\|in:", src.text):
        return []
    mode = _M_SQL["php"]
    out = []
    for mt in _PHP_ORDER.finditer(src.code):
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        v = _classify(src, args[0][0], args[0][1], mode)
        if v.level == TAINTED and not v.built:
            out.append(_hit(ctx, path, mt.start(), "%s() column comes from request input (%s); "
                            "PDO cannot bind column names, allowlist them" % (mt.group(1), _short(v.parts[0][1] if v.parts else "")),
                            None))
    return out


# ---------------------------------------------------------------------------
# NoSQL operator injection
# ---------------------------------------------------------------------------

_MONGO_METHODS = (r"find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|findOneAndRemove|updateOne|"
                  r"updateMany|deleteOne|deleteMany|replaceOne|countDocuments|count|remove|exists|update|delete")
# names that key-value stores, file helpers and ORMs also use: only a Mongo-looking receiver counts
_MONGO_GENERIC = frozenset(["count", "remove", "exists", "update", "delete"])
_MONGO_RECV = re.compile(r"(?:^|\.)\s*(?:[A-Z]\w*|\w*(?:Model|Collection|collection|Coll|coll))\s*$|"
                         r"\bcollection\s*\([^()]*\)\s*$|^\s*(?:this\s*\.\s*)?(?:model|coll|collection)\s*$")
_JS_NOSQL_SINK = re.compile(r"\.\s*(" + _MONGO_METHODS + r")\s*\(")
_PY_NOSQL_SINK = re.compile(r"\.\s*(find|find_one|find_one_and_update|find_one_and_delete|find_one_and_replace|update_one|"
                            r"update_many|delete_one|delete_many|replace_one|count_documents)\s*\(")
_SANITIZE_FILTER = re.compile(r"sanitizeFilter['\"]?\s*[:,]\s*true")
_MONGO_SANITIZE_USE = re.compile(r"\.\s*use\s*\(\s*(?:mongoSanitize|expressMongoSanitize|ExpressMongoSanitize|sanitize|"
                                 r"require\s*\(\s*['\"]express-mongo-sanitize['\"]\s*\))\s*\(")
# sanitizeFilter could be bypassed through $nor before these releases (CVE-2026-42334)
_MONGOOSE_FIXED = {6: (6, 13, 9), 7: (7, 8, 9), 8: (8, 22, 1), 9: (9, 1, 6)}


def _mongoose_patched(v: Optional[Tuple[int, ...]]) -> bool:
    if not v:
        return False
    if v[0] >= 10:
        return True
    fixed = _MONGOOSE_FIXED.get(v[0])
    return fixed is not None and tuple(v) + (0,) * (3 - len(v)) >= fixed


def _mongo_protection(ctx: Any) -> str:
    """'skip' when the project sanitizes every filter (sanitizeFilter on a patched Mongoose, or
    express-mongo-sanitize mounted on Express 4), 'old' when sanitizeFilter is set on an older Mongoose,
    '' otherwise."""
    def compute() -> str:
        texts = [ctx.read(f) for f in ctx.files if f.endswith(_JS_EXTS) and "anitiz" in ctx.read(f)]
        sf = any(_SANITIZE_FILTER.search(t) for t in texts)
        if sf and _mongoose_patched(parse_version(ctx.installed_version("mongoose"))):
            return "skip"
        ev = parse_version(ctx.installed_version("express")) if "express" in ctx.deps else None
        if (ev is None or ev[0] < 5) and any(_MONGO_SANITIZE_USE.search(t) for t in texts) \
                and ("express-mongo-sanitize" in ctx.deps or any("express-mongo-sanitize" in t for t in texts)):
            return "skip"
        return "old" if sf else ""
    return ctx.memo("ward-inj-mongo-protection", compute)


def _nosql_filter(src: _Src, s: int, e: int, mode: _Mode, depth: int = 0) -> Optional[tuple]:
    """(level, expr) when a request object can reach a filter value, or None."""
    s, e = _strip(src, s, e)
    if s >= e or depth > 3:
        return None
    text = src.text
    if re.match(r"\s*(?:async\s*)?(?:\([^()]*\)|[\w$]+)\s*=>|\s*(?:async\s+)?function\b|\s*lambda\b", src.code[s:e]):
        return None
    if text[s] == "{" and _match_fwd(src, s) == e - 1:
        items = _split(src, s + 1, e - 1, lambda sr, i, a, b: 1 if sr.text[i] == "," else 0)
        if depth == 0 and src.lang == "js" and re.search(r"(?:^|[{,])\s*where\s*:", src.code[s:e]):
            return None  # Sequelize / TypeORM / Prisma options ({ where: ... }), not a Mongo filter
        for a, b in items:
            a, b = _strip(src, a, b)
            if b <= a:
                continue
            sep = _split(src, a, b, lambda sr, i, x, y: 1 if sr.text[i] == ":" else 0)
            if len(sep) > 1:
                kt = src.text[sep[0][0]:sep[0][1]].strip().strip("'\"")
                va, vb = _strip(src, sep[-1][0], sep[-1][1])
            else:
                kt = src.text[a:b].strip()
                va, vb = a, b
            if kt.startswith("..."):
                kt = ""
                va += 3
            if kt == "$where":
                v = _classify(src, va, vb, _M_SQL["js"] if src.lang == "js" else _M_SQL["py"])
                if v.built and v.level >= UNKNOWN:
                    return (TAINTED if v.level == TAINTED else v.level, src.text[va:vb], "$where")
                continue
            if kt.startswith("$") and kt not in ("$or", "$and", "$nor"):
                continue
            if vb > va and text[va] in "{[" and _match_fwd(src, va) == vb - 1:
                if text[va] == "[":
                    for x, y in _split(src, va + 1, vb - 1, lambda sr, i, a2, b2: 1 if sr.text[i] == "," else 0):
                        r = _nosql_filter(src, x, y, mode, depth + 1)
                        if r:
                            return r
                    continue
                inner = src.code[va:vb]
                if re.search(r"['\"]?\$(?:eq|in|nin)['\"]?\s*:", inner):
                    continue
                r = _nosql_filter(src, va, vb, mode, depth + 1)
                if r:
                    return r
                continue
            v = _classify(src, va, vb, mode)
            if v.level == TAINTED and not v.built and not v.call:
                return (TAINTED, src.text[va:vb], kt)
        return None
    v = _classify(src, s, e, mode)
    if v.level == TAINTED and not v.built and not v.call:
        return (TAINTED, src.text[s:e], "")
    return None


_WHERE_KEY = re.compile(r"(?:(['\"])\$where\1|(?<![\w$])\$where)\s*:")


def _where_anywhere(src: _Src, spans: List[Tuple[int, int]], ctx: Any, path: str) -> List[Hit]:
    """A $where clause built from a variable anywhere in the file, also in a helper that returns the filter."""
    out = []
    mode = _M_SQL["js"] if src.lang == "js" else _M_SQL["py"]
    for mt in _WHERE_KEY.finditer(src.text):
        if src.kinds[mt.start()] == _NONCODE:
            continue
        va = _next_sig(src, mt.end(), len(src.text))
        vb = _expr_end(src, va, ",;")
        if vb <= va:
            continue
        v = _classify(src, va, vb, mode)
        if not v.built:
            continue
        w = _worst(v, UNKNOWN, skip_unknown_calls=True)
        if not w:
            continue
        if any(x <= mt.start() < y for x, y in spans):
            continue  # already reported at the find() / update() call
        spans.append((mt.start(), vb))
        tainted = w[0] == TAINTED
        out.append(_hit(ctx, path, mt.start(), "$where runs JavaScript built from %s%s; use query operators instead"
                        % (_short(w[1]), " (request input)" if tainted else ""), "critical" if tainted else "high"))
    return out


def check_nosqli_request_filter(path: str, text: str, ctx: Any) -> List[Hit]:
    lang = _lang_of(path)
    old_note = ""
    if lang == "py":
        mongo = any(d in ctx.py_deps for d in ("pymongo", "motor", "mongoengine", "flask-pymongo", "beanie", "odmantic")) \
            or re.search(r"\bpymongo\b|\bmotor\b|MongoClient", text)
        if not mongo:
            return []
        src = _src(ctx, path, "py")
        mode = _Mode("py", "nosql", _PY_NOSQL_SOURCES, _SAFE_NOSQL, route_params=False)
        sink = _PY_NOSQL_SINK
    else:
        if _vendored(text, path):
            return []
        mongo = any(d in ctx.deps for d in ("mongoose", "mongodb", "monk", "mongoist", "@typegoose/typegoose", "marsdb")) \
            or re.search(r"\bmongoose\b|\bmongodb\b|\.collection\s*\(", text)
        if not mongo:
            return []
        prot = _mongo_protection(ctx)
        if prot == "skip":
            return []
        if prot == "old":
            old_note = ("; sanitizeFilter is set, but Mongoose before 6.13.9, 7.8.9, 8.22.1 and 9.1.6 lets operators "
                        "through inside $nor")
        src = _src(ctx, path)
        ev = parse_version(ctx.installed_version("express")) if "express" in ctx.deps else None
        srcs = _JS_NOSQL_SOURCES_X5 if ev and ev[0] >= 5 else _JS_NOSQL_SOURCES
        mode = _Mode("js", "nosql", srcs, _SAFE_NOSQL, route_params=False)
        sink = _JS_NOSQL_SINK
    out = []
    spans: List[Tuple[int, int]] = []
    for mt in sink.finditer(src.code):
        meth = mt.group(1)
        if meth in _MONGO_GENERIC:
            recv = src.code[_back_operand(src, mt.start()):mt.start()]
            if not _MONGO_RECV.search(recv):
                continue
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        a, b = args[0]
        r = _nosql_filter(src, a, b, mode)
        if not r:
            continue
        lv, expr, key = r
        sev = None
        if key == "$where":
            msg = "%s(): $where runs JavaScript built from %s" % (meth, _short(expr))
            sev = "critical" if lv == TAINTED else "high"
        elif key:
            msg = ("%s(): filter field '%s' takes %s straight from the request; an object with an operator key "
                   "in place of a string changes what the filter matches" % (meth, _short(key, 30), _short(expr)))
        else:
            msg = "%s(): the whole request object (%s) is used as the query filter" % (meth, _short(expr))
        if old_note and key != "$where":
            msg += old_note
            sev = "medium"
        spans.append((a, b))
        out.append(_hit(ctx, path, mt.start(), msg, sev))
    if "$where" in text:
        out.extend(_where_anywhere(src, spans, ctx, path))
    return out


# ---------------------------------------------------------------------------
# OS command injection
# ---------------------------------------------------------------------------

_M_CMD = {
    "js": _Mode("js", "cmd", _JS_SOURCES_X, _SAFE_CMD),
    "py": _Mode("py", "cmd", _PY_SOURCES_X, _SAFE_CMD),
    "php": _Mode("php", "cmd", _PHP_SOURCES_X, _SAFE_CMD),
}
_CP_MOD = r"['\"](?:node:)?child_process['\"]"


def _cmd_judge(v: _V) -> Optional[tuple]:
    if v.built:
        return _worst(v, UNKNOWN, skip_unknown_calls=True)
    if v.level == TAINTED and not v.call:
        return v.parts[0] if v.parts else (TAINTED, "", "", False)
    return None


def _cmd_hit(ctx: Any, path: str, src: _Src, off: int, label: str, w: tuple) -> Hit:
    lv = w[0]
    if lv == TAINTED:
        sev = "critical"
        msg = "%s runs a shell command built from request input (%s)" % (label, _short(w[1]))
    else:
        sev = "high" if _req_file(src) else "medium"
        msg = "%s runs a shell command built with %s; confirm it can never hold user input, or pass an argument list" % (
            label, _short(w[1]))
    return _hit(ctx, path, off, msg, sev)


def check_cmdi_node(path: str, text: str, ctx: Any) -> List[Hit]:
    if "child_process" not in text or _vendored(text, path):
        return []
    src = _src(ctx, path)
    code = src.code
    cp_text = src.text
    shell_fns: Dict[str, str] = {}
    other_fns: Dict[str, str] = {}
    ns: List[str] = []
    for mt in re.finditer(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*" + _CP_MOD + r"\s*\)", cp_text):
        for k, v in _names_in_pattern(mt.group(1)).items():
            (shell_fns if v in ("exec", "execSync") else other_fns)[k] = v or k
    for mt in re.finditer(r"import\s*\{([^}]*)\}\s*from\s*" + _CP_MOD, cp_text):
        for part in mt.group(1).split(","):
            bits = part.strip().split(" as ")
            if not bits[0].strip():
                continue
            orig = bits[0].strip()
            alias = bits[-1].strip()
            (shell_fns if orig in ("exec", "execSync") else other_fns)[alias] = orig
    for mt in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*" + _CP_MOD + r"\s*\)(?!\s*\.)", cp_text):
        ns.append(mt.group(1))
    for mt in re.finditer(r"import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s*" + _CP_MOD + r"|import\s+([\w$]+)\s*=\s*require\(\s*" + _CP_MOD,
                          cp_text):
        ns.append(mt.group(1) or mt.group(2))
    # const exec = require('child_process').exec
    for mt in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*" + _CP_MOD + r"\s*\)\s*\.\s*"
                          r"(exec|execSync|spawn|spawnSync|execFile|execFileSync)\b", cp_text):
        (shell_fns if mt.group(2) in ("exec", "execSync") else other_fns)[mt.group(1)] = mt.group(2)
    # const exec = cp.exec, const { exec } = cp
    if ns:
        nsr = "|".join(re.escape(x) for x in ns)
        for mt in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*(?:" + nsr + r")\s*\.\s*"
                              r"(exec|execSync|spawn|spawnSync|execFile|execFileSync)\b(?!\s*\()", code):
            (shell_fns if mt.group(2) in ("exec", "execSync") else other_fns)[mt.group(1)] = mt.group(2)
        for mt in re.finditer(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:" + nsr + r")\s*[;\n]", code):
            for k, v in _names_in_pattern(mt.group(1)).items():
                (shell_fns if v in ("exec", "execSync") else other_fns)[k] = v or k
    for mt in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*(?:util\s*\.\s*)?promisify\(\s*(?:([\w$]+)\s*\.\s*)?([\w$]+)\s*\)", code):
        base = mt.group(3)
        if (mt.group(2) in ns and base in ("exec", "execSync")) or base in shell_fns:
            shell_fns[mt.group(1)] = "exec"
        elif (mt.group(2) in ns) or base in other_fns:
            other_fns[mt.group(1)] = other_fns.get(base, base)
    names = list(shell_fns) + list(other_fns)
    pats = []
    if names:
        pats.append(r"(?<![\w$.])(" + "|".join(re.escape(x) for x in names) + r")\s*\(")
    if ns:
        pats.append(r"\b(?:" + "|".join(re.escape(x) for x in ns) + r")\s*\.\s*(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(")
    # require('child_process').exec(...) inline; the module name is blanked in the code view
    pats.append(r"\brequire\s*\(\s*\)\s*\.\s*(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(")
    out = []
    mode = _M_CMD["js"]
    for mt in re.finditer("|".join(pats), code):
        fn = next((g for g in mt.groups() if g), "")
        if mt.group(0).startswith("require") and "child_process" not in src.text[mt.start():mt.end()]:
            continue
        real = shell_fns.get(fn) or other_fns.get(fn) or fn
        before = code[max(0, mt.start() - 12):mt.start()]
        if re.search(r"\bfunction\s+$", before):
            continue
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        if real in ("exec", "execSync"):
            v = _classify(src, args[0][0], args[0][1], mode)
            w = _cmd_judge(v)
            if w:
                out.append(_cmd_hit(ctx, path, src, mt.start(), real + "()", w))
            continue
        if real not in ("spawn", "spawnSync", "execFile", "execFileSync"):
            continue
        shell = any(re.search(r"\bshell\s*:\s*(?:true|['\"][^'\"]+['\"])", src.text[a:b]) for a, b in args[1:])
        if not shell:
            continue
        cands = [args[0]]
        if len(args) > 1 and src.text[args[1][0]] == "[":
            inner = _split(src, args[1][0] + 1, args[1][1] - 1, lambda sr, i, x, y: 1 if sr.text[i] == "," else 0)
            cands.extend(inner)
        w = None
        for a, b in cands:
            v = _classify(src, a, b, mode)
            c = _cmd_judge(v)
            if c and (w is None or c[0] > w[0]):
                w = c
        if w:
            out.append(_cmd_hit(ctx, path, src, mt.start(), real + "() with shell: true", w))
    return out


_PY_CMD_ALWAYS = frozenset(["system", "popen", "getoutput", "getstatusoutput", "create_subprocess_shell"])


def check_cmdi_python(path: str, text: str, ctx: Any) -> List[Hit]:
    if not re.search(r"\bos\b|\bsubprocess\b|create_subprocess_shell|\bcommands\b", text):
        return []
    src = _src(ctx, path, "py")
    code = src.code
    sub_ns = {"subprocess"}
    os_ns = {"os"}
    bare: Dict[str, str] = {}
    for mt in re.finditer(r"(?m)^[ \t]*import[ \t]+subprocess[ \t]+as[ \t]+(\w+)", code):
        sub_ns.add(mt.group(1))
    for mt in re.finditer(r"(?m)^[ \t]*import[ \t]+os[ \t]+as[ \t]+(\w+)", code):
        os_ns.add(mt.group(1))
    for mt in re.finditer(r"(?m)^[ \t]*from[ \t]+(subprocess|os)[ \t]+import[ \t]+\(?([^\n)]*)", code):
        for part in mt.group(2).split(","):
            bits = part.strip().split(" as ")
            if bits[0].strip():
                bare[bits[-1].strip()] = bits[0].strip()
    pats = [r"\b(?:" + "|".join(sorted(os_ns)) + r")\s*\.\s*(system|popen)\s*\(",
            r"\b(?:" + "|".join(sorted(sub_ns)) + r")\s*\.\s*(run|call|check_call|check_output|Popen|getoutput|getstatusoutput)\s*\(",
            r"\b(create_subprocess_shell)\s*\("]
    if bare:
        pats.append(r"(?<![\w.])(" + "|".join(re.escape(x) for x in bare) + r")\s*\(")
    out = []
    mode = _M_CMD["py"]
    for mt in re.finditer("|".join(pats), code):
        fn = next((g for g in mt.groups() if g), "")
        real = bare.get(fn, fn)
        if real not in ("system", "popen", "run", "call", "check_call", "check_output", "Popen", "getoutput",
                        "getstatusoutput", "create_subprocess_shell"):
            continue
        if re.search(r"\bdef\s+$", code[max(0, mt.start() - 8):mt.start()]):
            continue
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        if real not in _PY_CMD_ALWAYS:
            if not any(re.match(r"\s*shell\s*=\s*True\b", code[a:b]) for a, b in args[1:]):
                continue
        v = _classify(src, args[0][0], args[0][1], mode)
        w = _cmd_judge(v)
        if w:
            label = ("os." if real in ("system", "popen") else "subprocess.") + real + "()"
            if real not in _PY_CMD_ALWAYS:
                label += " with shell=True"
            out.append(_cmd_hit(ctx, path, src, mt.start(), label, w))
    return out


_PHP_CMD_SINK = re.compile(r"(?<![\w>:$\\])(shell_exec|exec|system|passthru|popen|proc_open|pcntl_exec)\s*\(")


def check_cmdi_php(path: str, text: str, ctx: Any) -> List[Hit]:
    if _vendored(text, path):
        return []
    if not re.search(r"shell_exec|exec\s*\(|system\s*\(|passthru|popen|proc_open|`", text):
        return []
    src = _src(ctx, path, "php")
    code = src.code
    mode = _M_CMD["php"]
    out = []
    for mt in _PHP_CMD_SINK.finditer(code):
        if re.search(r"\bfunction\s+&?\s*$", code[max(0, mt.start() - 12):mt.start()]):
            continue
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        v = _classify(src, args[0][0], args[0][1], mode)
        w = _cmd_judge(v)
        if w:
            out.append(_cmd_hit(ctx, path, src, mt.start(), mt.group(1) + "()", w))
    for tok in src.toks:
        if tok.quote != "`" or not tok.islands:
            continue
        v = _tok_value(src, tok, mode, 0, frozenset())
        w = _worst(v, UNKNOWN)
        if w:
            out.append(_cmd_hit(ctx, path, src, tok.start, "backtick shell", w))
    return out


# ---------------------------------------------------------------------------
# XSS sinks
# ---------------------------------------------------------------------------

_M_HTML = {
    "js": _Mode("js", "html", _JS_SOURCES_X, _SAFE_HTML),
    "py": _Mode("py", "html", _PY_SOURCES_X, _SAFE_HTML),
    "php": _Mode("php", "html", _PHP_SOURCES_X, _SAFE_HTML),
}
_M_HTML_REACT = _Mode("js", "html", _JS_SOURCES_X, _SAFE_HTML_JSON)


def _html_raw_judge(v: _V, allow_unknown_names: bool) -> Optional[str]:
    """Reason text when a raw-HTML value is unsafe, else None."""
    if v.md:
        return "md"
    if v.built:
        w = _worst(v, UNKNOWN if allow_unknown_names else DYNAMIC, skip_unknown_calls=True)
        return "built" if w else None
    if v.call:
        return None
    if v.level >= DYNAMIC:
        return "value"
    if v.level == UNKNOWN and allow_unknown_names:
        return "value"
    return None


def _html_msg(sink: str, v: _V, expr: str, reason: str) -> Tuple[str, str]:
    if reason == "md":
        return ("%s gets markdown rendered to HTML with no sanitizer (%s); marked and similar renderers pass raw HTML through"
                % (sink, _short(expr)), "high")
    sev = "high"
    if v.level == TAINTED:
        return ("%s renders request or URL input as HTML (%s)" % (sink, _short(expr)), sev)
    return ("%s renders %s as raw HTML with no sanitizer; confirm it can never hold user or model text" % (sink, _short(expr)), sev)


def check_xss_react_html(path: str, text: str, ctx: Any) -> List[Hit]:
    if "__html" not in text or _vendored(text, path):
        return []
    src = _src(ctx, path)
    out = []
    for mt in re.finditer(r"\b__html\s*:|\{\s*__html\s*\}", src.code):
        if mt.group(0).startswith("{"):
            a = mt.start() + mt.group(0).index("__html")
            b = a + len("__html")
        else:
            a = mt.end()
            b = _expr_end(src, a, ",;")
        a, b = _strip(src, a, b)
        if b <= a:
            continue
        if re.match(r"Object\s*\.\s*entries\s*\(\s*[A-Z][A-Z0-9_]*\s*\)", src.code[a:b]) and "--color-" in src.text[a:b]:
            continue  # shadcn/ui ChartStyle: CSS variables from the THEMES constant and the developer's chart config
        v = _classify(src, a, b, _M_HTML_REACT)
        reason = _html_raw_judge(v, allow_unknown_names=True)
        if not reason:
            continue
        msg, sev = _html_msg("dangerouslySetInnerHTML", v, src.text[a:b], reason)
        if reason != "md" and v.level == UNKNOWN:
            sev = "medium"  # a prop or parameter we cannot follow: often a wrapper fed sanitized HTML
            if "mermaid" in src.code and _MERMAID_LOOSE.search(src.text):
                msg += (" (mermaid securityLevel 'loose' lets HTML in diagram labels through; keep 'strict' unless every "
                        "diagram is written by the developer)")
        if v.level != TAINTED and _LINT_DANGER_OK.search(src.text[max(0, mt.start() - 400):mt.start()]):
            sev = "low"
            msg += " (a lint suppression above gives a reason; check that it holds)"
        elif _REACT_EMAIL.search(src.text):
            sev = "medium" if v.level == TAINTED else "low"
            msg += (" (React Email template: mail clients do not run scripts, but injected markup can still fake "
                    "links and content in a mail sent from your domain; escape anything a user wrote)")
        out.append(_hit(ctx, path, mt.start(), msg, sev))
    return out


# a React Email template (rendered to an email body, never into the app's own pages)
_REACT_EMAIL = re.compile(r"""\bfrom\s*['"](?:@react-email/[\w-]+|react-email|jsx-email)['"]""")


# a biome / eslint suppression of the dangerouslySetInnerHTML lint that carries a written reason
_LINT_DANGER_OK = re.compile(r"(?:biome-ignore\s+lint/security/noDangerouslySetInnerHtml(?:WithChildren)?\s*:|"
                             r"eslint-disable(?:-next-line|-line)?\s+react/no-danger\s+--)\s*[^\n]{10,}\n[^\n]*\n?[^\n]*$")


_VUE_HTML = re.compile(r"(?<![\w:-])(?:v-html|v-bind:innerHTML|:innerHTML|:inner-html)\s*=\s*(\"([^\"]*)\"|'([^']*)')")
_SVELTE_HTML = re.compile(r"\{@html\s")


def _template_expr_judge(ctx: Any, rel: str, expr: str, script_code: str) -> Optional[str]:
    mini = _build_src(expr, "js")
    v = _classify(mini, 0, len(expr), _M_HTML["js"])
    if v.level == SAFE and not v.md:
        return None
    if v.md:
        return "md"
    # an assignment to the exact member path: description.content = DOMPurify.sanitize(...)
    for path_m in re.finditer(r"(?<![\w$.])[A-Za-z_$][\w$]*(?:\s*\??\.\s*[A-Za-z_$][\w$]*)+", mini.code):
        parts = [x.strip() for x in re.split(r"\??\.", path_m.group(0))]
        rx = r"(?<![\w$.])" + r"\s*\??\.\s*".join(re.escape(x) for x in parts) + r"\s*=(?![=>])([^;\n]*)"
        for d in re.finditer(rx, script_code):
            if re.search(r"sanitize|purify|DOMPurify|escape", d.group(1), re.I):
                return None
    names = set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)", mini.code))
    names -= {"this", "true", "false", "null", "undefined"}
    for nm in names:
        defs = re.finditer(r"(?<![\w$.])" + re.escape(nm) + r"\s*(?:=|:|\()", script_code)
        for d in defs:
            chunk = script_code[d.start():d.start() + 400]
            if re.search(r"sanitize|purify|DOMPurify|escape", chunk, re.I):
                return None
            if re.search(r"\bmarked\b|\.render\(|makeHtml|markdown", chunk):
                return "md"
    if v.call and v.level <= UNKNOWN:
        return None
    return "value"


_SERVER_PURIFIERS = ("ezyang/htmlpurifier", "mews/purifier", "stevebauman/purify")


def _server_purifies(ctx: Any) -> bool:
    """True when the backend has an HTML purifier, so rich text from its API is often cleaned before it ships."""
    return any(p in ctx.composer_deps for p in _SERVER_PURIFIERS) or "bleach" in ctx.py_deps or "nh3" in ctx.py_deps


# Server-side template engines: raw output tags
_ENGINE_RAW = [
    (re.compile(r"<%-(?!\s*(?:include|partial|body|defineContent|block|script|style|layout)\b)\s*([^%]*?)\s*-?%>"),
     (".ejs",), "EJS <%- %>"),
    (re.compile(r"\{\{\{(?!\s*(?:>|body\s*\}|yield\s*\}))\s*([^}]*?)\s*\}\}\}|\{\{&\s*([^}]*?)\s*\}\}"),
     (".hbs", ".handlebars", ".mustache", ".html"), "Handlebars {{{ }}}"),
    (re.compile(r"(?m)^[ \t]*(?:[\w.#-]+(?:\([^)\n]*\))?)?!=[ \t]*(\S[^\n]*)$|!\{([^}\n]+)\}"), (".pug", ".jade"), "Pug != / !{}"),
    (re.compile(r"\{\{-?\s*((?:[^{}]|\{[^{}]*\})*?)\|\s*(?:safe|raw)\s*(?:\|[^}]*)?-?\}\}"), (".njk", ".twig"), "|safe / |raw"),
]
_ENGINE_AUTOESC_OFF = re.compile(r"\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}")
_ENGINE_TAINT = re.compile(r"\b(?:req|request|query|params|body|searchTerm|search|q)\b")


def _engine_hits(path: str, text: str, ctx: Any) -> List[Hit]:
    low = path.lower()
    out = []
    for rx, exts, label in _ENGINE_RAW:
        if not low.endswith(exts):
            continue
        if low.endswith(".html") and not re.search(r"\{\{\{", text):
            continue
        for mt in rx.finditer(text):
            expr = next((g for g in mt.groups() if g), "").strip()
            if not expr or re.fullmatch(r"(['\"])[^'\"]*\1", expr):
                continue
            if re.search(r"(?i)sanitiz|purif|escape|JSON\.stringify|\bclean\b", expr):
                continue
            tainted = _ENGINE_TAINT.search(expr) is not None
            out.append(_hit(ctx, path, mt.start(), "%s prints %s without escaping; use the escaping tag unless the value "
                                                   "is sanitized or fixed HTML" % (label, _short(expr)),
                            "high" if tainted else "medium"))
    if low.endswith((".njk", ".twig", ".html")):
        for mt in _ENGINE_AUTOESC_OFF.finditer(text):
            if low.endswith(".html") and not re.search(r"\{%-?\s*endautoescape", text):
                continue
            out.append(_hit(ctx, path, mt.start(), "template turns autoescape off for a block; every value inside is printed "
                                                   "raw", "medium"))
    return out


def check_xss_framework_html(path: str, text: str, ctx: Any) -> List[Hit]:
    low = path.lower()
    out = []
    if low.endswith((".ejs", ".hbs", ".handlebars", ".mustache", ".pug", ".jade", ".njk", ".twig")):
        return _engine_hits(path, text, ctx)
    if low.endswith((".vue", ".svelte", ".html", ".htm")):
        if low.endswith(".html") and "{{{" in text:
            out.extend(_engine_hits(path, text, ctx))
        if "v-html" not in text and "innerHTML" not in text and "inner-html" not in text and "{@html" not in text:
            return out
        script = " ".join(m.group(2) for m in _SCRIPT_BLOCK.finditer(text))
        purifier = _server_purifies(ctx)
        for mt in _VUE_HTML.finditer(text):
            expr = mt.group(2) if mt.group(2) is not None else (mt.group(3) or "")
            if not expr.strip():
                continue
            reason = _template_expr_judge(ctx, path, expr, script)
            if reason:
                msg, sev = _html_msg("v-html", _V(UNKNOWN), expr, reason)
                if purifier and reason != "md":
                    sev = "medium"
                    msg += " (the backend has an HTML purifier; check whether this field passes through it)"
                out.append(_hit(ctx, path, mt.start(), msg, sev))
        for mt in _SVELTE_HTML.finditer(text):
            depth = 0
            j = mt.start()
            while j < len(text):
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            expr = text[mt.end():j]
            if not expr.strip():
                continue
            reason = _template_expr_judge(ctx, path, expr, script)
            if reason:
                msg, sev = _html_msg("{@html}", _V(UNKNOWN), expr, reason)
                out.append(_hit(ctx, path, mt.start(), msg, sev))
        return out
    if low.endswith(_JS_EXTS) and "autoescape" in text:
        src = _src(ctx, path)
        for mt in re.finditer(r"\bautoescape\s*:\s*false\b", src.code):
            out.append(_hit(ctx, path, mt.start(), "template engine configured with autoescape: false (swig.setDefaults, "
                                                   "nunjucks.configure); every {{ }} prints raw HTML", None))
    if "bypassSecurityTrust" not in text:
        return out
    src = _src(ctx, path)
    for mt in re.finditer(r"\bbypassSecurityTrust(?:Html|Script|ResourceUrl)\s*\(", src.code):
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        v = _classify(src, args[0][0], args[0][1], _M_HTML["js"])
        reason = _html_raw_judge(v, allow_unknown_names=True)
        if reason:
            msg, sev = _html_msg(mt.group(0).rstrip("( "), v, src.text[args[0][0]:args[0][1]], reason)
            out.append(_hit(ctx, path, mt.start(), msg, sev))
    return out


_ESCAPE_USE = re.compile(r"(?<![\w$.])(?:esc|escape\w*|htmlEscape|encodeHTML|encodeHtml|sanitize\w*|purify\w*)\s*\(|"
                         r"\bDOMPurify\s*\.|\.\s*(?:escape|sanitize)\s*\(")
_HTMLISH_NAME = re.compile(r"(?i)(?:html|markup|svg|template|tpl|icons?)\s*$")
_DOM_SINK = re.compile(r"\.\s*(innerHTML|outerHTML)\s*(\+?=)(?!=)|\.\s*(insertAdjacentHTML)\s*\(|\bdocument\s*\.\s*(write|writeln)\s*\(|"
                       r"\.\s*(html)\s*\((?!\s*\))")


def check_xss_dom_html(path: str, text: str, ctx: Any) -> List[Hit]:
    if not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write|\.html\s*\(", text) or _vendored(text, path):
        return []
    lang = _lang_of(path)
    if lang not in ("js", "js-embedded"):
        return []
    src = _src(ctx, path, lang)
    mode = _M_HTML["js"]
    out = []
    escapes: Optional[bool] = None
    for mt in _DOM_SINK.finditer(src.code):
        if mt.group(1):
            a = mt.end()
            b = _expr_end(src, a, ";")
            sink = "." + mt.group(1)
        else:
            args, _c = _call_args(src, mt.end() - 1)
            if mt.group(5):
                # jQuery: $(...).html(value) parses value as HTML
                recv = src.code[_back_operand(src, mt.start()):mt.start()].strip()
                if not args or not re.match(r"(?:\$|jQuery)\s*\(|\$[\w$]*$", recv):
                    continue
                a, b = args[0]
                sink = "jQuery .html()"
            elif mt.group(3):
                if len(args) < 2:
                    continue
                a, b = args[1]
                sink = "insertAdjacentHTML()"
            else:
                if not args:
                    continue
                a, b = args[0]
                sink = "document." + mt.group(4) + "()"
        a, b = _strip(src, a, b)
        if b <= a:
            continue
        v = _classify(src, a, b, mode)
        reason = _html_raw_judge(v, allow_unknown_names=False)
        if not reason:
            continue
        if reason != "md" and v.level != TAINTED:
            if escapes is None:
                escapes = _ESCAPE_USE.search(src.code) is not None
            if escapes:
                # this file escapes text on purpose; what it leaves raw is numbers and fragments it built
                continue
            dyn = [p for p in v.parts if p[0] >= DYNAMIC and not _HTMLISH_NAME.search(p[1])]
            if not dyn:
                continue
        msg, sev = _html_msg(sink, v, src.text[a:b], reason)
        if reason != "md" and v.level != TAINTED:
            sev = "medium"
            if _ajax_response_field(src, src.code[a:b].strip(), a):
                sev = "low"
                msg += (" (a field of this app's own JSON response: fine when the server built it with an escaping "
                        "template, check the endpoint)")
        out.append(_hit(ctx, path, mt.start(), msg, sev))
    return out


def _ajax_response_field(src: _Src, expr: str, pos: int) -> bool:
    """True for data.events where data is the parameter of a same-origin $.ajax / $.getJSON / fetch callback."""
    m = re.fullmatch(r"([A-Za-z_$][\w$]*)(?:\s*\.\s*[\w$.]+)?", expr)
    if not m:
        return False
    tr = _trace(src, m.group(1), pos)
    if tr and tr[1] == "loop":
        # for (const el of data.details) / data.details.forEach(el => ...): judge the list it walks
        rs, rend = tr[2]
        inner = src.code[rs:rend].strip()
        return inner != expr and re.fullmatch(r"[A-Za-z_$][\w$]*\s*\.\s*[\w$.]+", inner) is not None \
            and _ajax_response_field(src, inner, rs)
    if tr and tr[1] == "param":
        # for (var i = 0, el; (el = data.details[i]); i++): an item of a list in the response
        im = re.match(re.escape(m.group(1)) + r"\s*=\s*([A-Za-z_$][\w$]*\s*\.\s*[\w$.]+)\s*\[[^\]]*\]\s*\)",
                      src.code[tr[0]:tr[0] + 120])
        if im and im.group(1) != expr:
            return _ajax_response_field(src, im.group(1), tr[0])
    if not tr or tr[1] != "param" or "." not in expr:
        return False
    at = tr[0]
    before = src.code[max(0, at - 160):at]
    call = re.search(r"(?:\$|jQuery)\s*\.\s*(?:ajax|getJSON|get|post)\s*\(\s*(['\"`]?)|\bsuccess\s*:\s*(?:function\b\s*)?$|"
                     r"\.\s*(?:done|then)\s*\(\s*(?:function\b\s*)?$", before)
    if not call:
        return False
    # an absolute URL to another host is not this app's own endpoint
    seg = src.text[max(0, at - 400):at]
    return re.search(r"(?:\$|jQuery)\s*\.\s*(?:ajax|getJSON|get|post)\s*\(\s*(?:\{[^}]*\burl\s*:\s*)?['\"`]https?://", seg) is None


def check_xss_rehype_raw(path: str, text: str, ctx: Any) -> List[Hit]:
    if "rehype-raw" not in text:
        return []
    src = _src(ctx, path)
    code = src.code
    im = re.search(r"import\s+([\w$]+)\s+from\s*['\"]rehype-raw['\"]|(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['\"]rehype-raw['\"]\s*\)", src.text)
    if not im:
        return []
    raw = im.group(1) or im.group(2)
    sm = re.search(r"import\s+([\w$]+)(?:\s*,\s*\{[^}]*\})?\s+from\s*['\"](?:rehype-sanitize|rehype-dompurify)['\"]|(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['\"](?:rehype-sanitize|rehype-dompurify)['\"]\s*\)", src.text)
    uses = [u for u in re.finditer(r"(?<![\w$.])" + re.escape(raw) + r"\b", code) if u.start() >= im.end()]
    if not uses:
        return []
    if sm:
        san = sm.group(1) or sm.group(2)
        for u in uses:
            ob = code.rfind("[", 0, u.start())
            if ob < 0:
                continue
            cb = _match_fwd(src, ob)
            if cb < u.start():
                continue
            arr = code[ob:cb]
            si = re.search(r"(?<![\w$.])" + re.escape(san) + r"\b", arr)
            ri = re.search(r"(?<![\w$.])" + re.escape(raw) + r"\b", arr)
            if si and ri and si.start() < ri.start():
                return [_hit(ctx, path, u.start(), "rehype-sanitize runs before rehype-raw, so the raw HTML that rehype-raw "
                                                    "parses is never sanitized; put the sanitizer after it", None)]
        return []
    return [_hit(ctx, path, uses[0].start(), "markdown renders raw HTML (rehype-raw) with no rehype-sanitize after it", None)]


_BLADE_RAW = re.compile(r"\{!!(.*?)!!\}", re.S)
_BLADE_SAFE = re.compile(
    r"\s*(?:(?:csrf_field|method_field|e|clean|purify|__|trans|trans_choice|route|url|asset|secure_asset|mix|"
    r"vite|config|svg|strip_tags|htmlspecialchars|htmlentities|view|esc_html|wp_kses\w*)\s*\("
    r"|nl2br\s*\(\s*e\s*\(|(?:Purifier|Js|Vite|Form|Html|QrCode|\w+Form)\s*::|\$__env\b|\$slot\b|\$attributes\b|\$errors\b"
    r"|(['\"])[^'\"]*\1\s*$)")
_BLADE_SANITIZED = re.compile(r"(?i)\bpurif|sanitiz|\bclean\s*\(|htmlspecialchars|\be\s*\(|\bescape\w*\s*\(|\besc_\w+\s*\(")
# league/commonmark (and Str::markdown) configured to escape or strip raw HTML and drop javascript: links
_SAFE_MARKDOWN_CFG = re.compile(r"html_input['\"]?\s*=>\s*['\"](?:escape|strip)['\"]")
_UNSAFE_LINKS_OFF = re.compile(r"allow_unsafe_links['\"]?\s*=>\s*false")


def _php_definitions(ctx: Any) -> Dict[str, str]:
    """name -> body text of the functions and the names of the classes defined in the project's own PHP code."""
    def build() -> Dict[str, str]:
        out: Dict[str, str] = {}
        for f in ctx.files:
            if not f.endswith(".php") or f.endswith(".blade.php") or re.search(r"(?:^|/)(?:vendor|node_modules|tests?)/", f):
                continue
            t = ctx.read(f)
            for mt in re.finditer(r"\bfunction\s+&?\s*([A-Za-z_]\w*)\s*\(", t):
                out.setdefault(mt.group(1), t[mt.start():mt.start() + 1500])
            for mt in re.finditer(r"(?m)^\s*(?:final\s+|abstract\s+)?class\s+([A-Za-z_]\w*)", t):
                out.setdefault("class:" + mt.group(1), "")
        return out
    return ctx.memo("ward-inj-php-defs", build)


def _blade_helper(ctx: Any, expr: str) -> Optional[Tuple[str, str]]:
    """(callee, body) when the expression calls a function or a class defined in this project, else None."""
    m = re.match(r"\s*\\?((?:[A-Za-z_]\w*\\)*[A-Za-z_]\w*)\s*(::\s*[A-Za-z_]\w*)?\s*\(", expr)
    if not m:
        return None
    defs = _php_definitions(ctx)
    name = m.group(1).rsplit("\\", 1)[-1]
    if m.group(2):
        if ("class:" + name) in defs:
            meth = m.group(2).lstrip(":").strip()
            return name + "::" + meth, defs.get(meth, "")
        return None
    if name in defs:
        return name, defs[name]
    return None


def _in_script(text: str, pos: int) -> bool:
    open_i = text.rfind("<script", 0, pos)
    return open_i >= 0 and text.rfind("</script", open_i, pos) < 0


def check_xss_blade_raw(path: str, text: str, ctx: Any) -> List[Hit]:
    if "{!!" not in text:
        return []
    comments = [(m.start(), m.end()) for m in re.finditer(r"\{\{--.*?--\}\}", text, re.S)]
    out = []
    reported = ctx.memo("ward-inj-blade-helpers", lambda: set())
    for mt in _BLADE_RAW.finditer(text):
        if any(a <= mt.start() < b for a, b in comments):
            continue
        expr = mt.group(1).strip()
        if not expr or _BLADE_SAFE.match(expr):
            continue
        if _BLADE_SANITIZED.search(expr):
            continue
        bare = re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", "''", expr)  # string contents removed
        if re.fullmatch(r"[^?'\"]+\?\s*(['\"])[^'\"]*\1\s*:\s*(['\"])[^'\"]*\2\s*", expr):
            continue  # $flag ? '<b>x</b>' : 'y' prints one of two fixed strings
        if re.match(r"\s*json_encode\s*\(", expr):
            if "JSON_HEX_TAG" in expr or _in_script(text, mt.start()) or not _HTML_TAG.search(text):
                continue  # json_encode escapes / by default, so </script> cannot close a script block; a JS view is no HTML
            out.append(_hit(ctx, path, mt.start(), "Blade {!! json_encode(...) !!} outside a <script> block: json_encode leaves "
                                                   "\" ' < > & as they are, so in an HTML attribute a quote breaks out. Use "
                                                   "@json() or {{ Js::from() }}", "medium"))
            continue
        tainted = re.search(r"\bold\s*\(|\brequest\s*\(|\$request\b|\$_(?:GET|POST|REQUEST)", expr)
        md = re.search(r"(?i)markdown|parsedown", bare)
        if md and _SAFE_MARKDOWN_CFG.search(expr) and _UNSAFE_LINKS_OFF.search(expr):
            continue  # Str::markdown($x, ['html_input' => 'strip', 'allow_unsafe_links' => false])
        helper = None if tainted else _blade_helper(ctx, expr)
        if helper is not None:
            callee, body = helper
            if _SAFE_MARKDOWN_CFG.search(body) and _UNSAFE_LINKS_OFF.search(body):
                continue  # a markdown helper whose converter escapes raw HTML and unsafe links
            if callee in reported:
                continue
            reported.add(callee)
            escapes = re.search(r"->\s*render\s*\(|\bview\s*\(|htmlspecialchars|htmlentities|\be\s*\(|sprintf\s*\(\s*['\"]<", body)
            out.append(_hit(ctx, path, mt.start(), "Blade {!! !!} prints the HTML that the project helper %s() builds; "
                                                   "check once that it escapes every value it inserts (later uses of the "
                                                   "same helper are not listed)" % callee, "low" if escapes else "medium"))
            continue
        if tainted:
            msg = "Blade {!! !!} prints request input unescaped (%s)" % _short(expr)
        elif md:
            msg = "Blade {!! !!} prints rendered markdown with no sanitizer (%s)" % _short(expr)
        else:
            msg = "Blade {!! !!} prints %s unescaped; use {{ }} unless the HTML is sanitized or fixed" % _short(expr)
        out.append(_hit(ctx, path, mt.start(), msg, None))
    return out


_JINJA_SAFE = re.compile(r"\{\{-?((?:[^{}]|\{[^{}]*\})*?)\|\s*safe(?:seq)?\s*(?:\|[^}]*)?-?\}\}")
_JINJA_AUTOESC = re.compile(r"\{%-?\s*autoescape\s+(?:false|off)\s*-?%\}")
_PY_MARK = re.compile(r"\b(mark_safe|Markup|SafeString)\s*\(")
# templates whose name says they render plain text (an email's text part, an SMS, a push title): |safe there
# only avoids HTML entities in output that is never parsed as HTML
_TEXT_TEMPLATE = re.compile(r"(?i)(?:^|[-_.])(?:text|txt|subject|title|topic|name|desc|description|message|sms)(?:[-_.]|$)|^sms")
_JINJA_CONST = re.compile(r"\{%-?\s*(?:cycle\s+(?:(['\"])[^'\"]*\1\s+)+as\s+(\w+)|with\s+(\w+)\s*=\s*(['\"])[^'\"]*\4|"
                          r"set\s+(\w+)\s*=\s*(['\"])[^'\"]*\6)")


def check_xss_python_templates(path: str, text: str, ctx: Any) -> List[Hit]:
    out = []
    if path.lower().endswith(".py"):
        if not re.search(r"mark_safe|Markup|SafeString|autoescape", text):
            return []
        src = _src(ctx, path, "py")
        for mt in _PY_MARK.finditer(src.code):
            if re.search(r"\b(?:def|class|import)\s+$|\bimport\s+[\w, ]*$", src.code[max(0, mt.start() - 30):mt.start()]):
                continue
            args, _c = _call_args(src, mt.end() - 1)
            if not args:
                continue
            v = _classify(src, args[0][0], args[0][1], _M_HTML["py"])
            reason = _html_raw_judge(v, allow_unknown_names=True)
            if reason:
                msg, sev = _html_msg(mt.group(1) + "()", v, src.text[args[0][0]:args[0][1]], reason)
                out.append(_hit(ctx, path, mt.start(), msg, sev))
        for mt in re.finditer(r"\b(?:jinja2\s*\.\s*)?Environment\s*\(", src.code):
            args, _c = _call_args(src, mt.end() - 1)
            if any(re.match(r"\s*autoescape\s*=\s*False\b", src.code[a:b]) for a, b in args):
                out.append(_hit(ctx, path, mt.start(), "jinja2 Environment(autoescape=False): every {{ }} in its templates "
                                                       "prints raw HTML; use autoescape=select_autoescape()", "medium"))
        return out
    if "safe" not in text and "autoescape" not in text:
        return []
    name = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    if _TEXT_TEMPLATE.search(name) and not _HTML_TAG.search(re.sub(r"\{[{%#].*?[}%#]\}", "", text, flags=re.S)):
        return []
    consts = set()
    for mt in _JINJA_CONST.finditer(text):
        consts.add(mt.group(2) or mt.group(3) or mt.group(5))
    for mt in _JINJA_SAFE.finditer(text):
        expr = mt.group(1).strip()
        if not expr or re.search(r"tojson|json_script|sanitiz|bleach|\bclean\b|escape|striptags|csrf", expr):
            continue
        if re.fullmatch(r"\s*(['\"])[^'\"]*\1\s*", expr) or expr in consts:
            continue
        md = re.search(r"\|\s*markdown|markdown\s*\(", expr)
        sev = None
        if md:
            msg = "template renders markdown output with |safe and no sanitizer (%s)" % _short(expr)
        else:
            msg = "template marks %s as |safe, which turns off escaping; confirm it never holds user or model text" % _short(expr)
            if re.search(r"(?i)(?:svg|icon|qr_?code|sparkline)\w*\s*$", expr):
                sev = "low"  # markup the server generated (an SVG icon or QR code)
            elif re.search(r"(?i)(?:^|/)e?mails?/", path):
                sev = "low"  # an email body: mail clients run no scripts, but injected markup can still fake content
                msg += " (email template: no script runs in a mail client, but escape user text to stop faked links)"
        out.append(_hit(ctx, path, mt.start(), msg, sev))
    for mt in _JINJA_AUTOESC.finditer(text):
        out.append(_hit(ctx, path, mt.start(), "template turns autoescape off for a block; every value inside is printed raw",
                        "medium"))
    return out


_HTML_TAG = re.compile(r"<[A-Za-z][\w-]*(?:\s|>|/>)|</[A-Za-z]")
_JS_RESP = re.compile(r"\bres\s*(?:\.\s*(?:status|type|set|header|append|cookie)\s*\([^()]*\)\s*)*\.\s*(send|write|end)\s*\(|\bnew\s+(Response)\s*\(|\bc\s*\.\s*(html)\s*\(")
_JS_BARE_STRING_INPUT = re.compile(r"\s*req\s*\.\s*(?:query|params)\s*(?:\.\s*[\w$]+|\[[^\]]+\])\s*")
_PY_BARE_STRING_INPUT = re.compile(r"\s*request\s*\.\s*(?:args|form|values)\b.*", re.S)
_PY_ROUTE_FN = re.compile(r"@\s*[\w.]*\b(?:route|get|post|put|patch|delete)\s*\(")


def _reflect_judge(v: _V, bare: bool) -> Optional[tuple]:
    """The request part that ends up raw in an HTML response, or None."""
    if v.built:
        if not _HTML_TAG.search(v.lit):
            return None
        for p in v.parts:
            if p[0] == TAINTED and not _is_call_part(p):
                return p
        return None
    if bare and v.level == TAINTED and not v.call and v.parts:
        return v.parts[0]
    return None


def _reflect_msg(sink: str, w: tuple) -> str:
    return ("%s sends request input (%s) back inside HTML without escaping; escape it or render a template "
            "with autoescape" % (sink, _short(w[1])))


def _py_function_body(src: _Src, def_start: int) -> Tuple[int, int]:
    """(start, end) of the body of the def that starts at def_start."""
    code = src.code
    m = re.match(r"([ \t]*)", code[def_start:])
    indent = len(m.group(1)) if m else 0
    op = code.find("(", def_start)
    _args, cp = _call_args(src, op) if op >= 0 else ([], -1)
    colon = code.find(":", cp if cp > 0 else def_start)
    start = colon + 1 if colon >= 0 else def_start
    for lm in re.finditer(r"(?m)^([ \t]*)\S", code[start:]):
        line_at = start + lm.start()
        if line_at <= start:
            continue
        if len(lm.group(1)) <= indent and code[start:line_at].strip():
            return start, line_at
    return start, len(code)


def check_xss_reflected(path: str, text: str, ctx: Any) -> List[Hit]:
    lang = _lang_of(path)
    out = []
    if lang == "js":
        if _vendored(text, path) or ctx.is_client_file(path):
            return []
        if not re.search(r"\bres\s*[.)]|new\s+Response|\bc\s*\.\s*html", text):
            return []
        src = _src(ctx, path)
        html_ct = "text/html" in src.text
        for mt in _JS_RESP.finditer(src.code):
            kind = mt.group(1) or mt.group(2) or mt.group(3)
            if kind in ("write", "end", "Response") and not html_ct:
                continue
            args, _c = _call_args(src, mt.end() - 1)
            if not args:
                continue
            a, b = args[0]
            v = _classify(src, a, b, _M_HTML["js"])
            bare = kind in ("send", "html") and _JS_BARE_STRING_INPUT.fullmatch(src.code[a:b]) is not None
            w = _reflect_judge(v, bare)
            if w:
                label = "res.%s()" % kind if kind in ("send", "write", "end") else ("new Response()" if kind == "Response" else "c.html()")
                out.append(_hit(ctx, path, mt.start(), _reflect_msg(label, w), None))
        return out
    if lang == "py":
        if not re.search(r"\breturn\b|HttpResponse|HTMLResponse|make_response", text):
            return []
        src = _src(ctx, path, "py")
        mode = _M_HTML["py"]
        flask = re.search(r"(?m)^\s*(?:from\s+flask\s+import|import\s+flask\b)", src.code) is not None
        for mt in re.finditer(r"\b(HttpResponse|HTMLResponse|make_response)\s*\(", src.code):
            args, _c = _call_args(src, mt.end() - 1)
            if not args:
                continue
            a, b = args[0]
            km = re.match(r"\s*content\s*=", src.code[a:b])
            if km:
                a += km.end()
            v = _classify(src, a, b, mode)
            w = _reflect_judge(v, _PY_BARE_STRING_INPUT.fullmatch(src.code[a:b]) is not None)
            if w:
                out.append(_hit(ctx, path, mt.start(), _reflect_msg(mt.group(1) + "()", w), None))
        if flask:
            for dm in _PY_DEF.finditer(src.code):
                deco = _py_decorators(src, dm.start())
                if not _PY_ROUTE_FN.search(deco):
                    continue
                bs, be = _py_function_body(src, dm.start())
                for rm in re.finditer(r"\breturn\b", src.code[bs:be]):
                    a = bs + rm.end()
                    b = _expr_end(src, a, ";")
                    a, b = _strip(src, a, b)
                    if b <= a or re.match(r"(?:render_template|redirect|jsonify|send_file|send_from_directory|abort|"
                                          r"make_response|Response|url_for)\b", src.code[a:b]):
                        continue
                    first = _split(src, a, b, lambda sr, i, x, y: 1 if sr.text[i] == "," else 0)[0]
                    v = _classify(src, first[0], first[1], mode)
                    w = _reflect_judge(v, _PY_BARE_STRING_INPUT.fullmatch(src.code[first[0]:first[1]]) is not None)
                    if w:
                        out.append(_hit(ctx, path, bs + rm.start(), _reflect_msg("Flask route return", w), None))
        return out
    if lang == "php" and not path.lower().endswith(".blade.php"):
        if not re.search(r"\becho\b|\bprint\b|<\?=|\$\w+\s*\.?=\s*['\"][^'\"\n]*<[A-Za-z/]", text):
            return []
        src = _src(ctx, path, "php")
        if re.search(r"Content-Type:\s*application/json", src.text, re.I):
            return []
        mode = _M_HTML["php"]
        spans = []
        for mt in re.finditer(r"(?<![\w$>:])(echo|print)\b", src.code):
            a = mt.end()
            b = _expr_end(src, a, ";")
            spans.append((mt.start(), a, b, mt.group(1)))
        for mt in re.finditer(r"<\?=", src.text):
            a = mt.end()
            stop = src.text.find("?>", a)
            b = _expr_end(src, a, ";")
            if 0 <= stop < b:
                b = stop
            spans.append((mt.start(), a, b, "<?="))
        for at, a, b, label in spans:
            for x, y in _split(src, a, b, lambda sr, i, s0, e0: 1 if sr.text[i] == "," else 0):
                v = _classify(src, x, y, mode)
                w = None
                if v.built:
                    w = next((p for p in v.parts if p[0] == TAINTED and not _is_call_part(p)), None)
                elif v.level == TAINTED and not v.call and v.parts:
                    w = v.parts[0]
                if w:
                    out.append(_hit(ctx, path, at, "%s prints request input (%s) without htmlspecialchars()" % (label, _short(w[1])), None))
                    break
        # HTML built into a variable that is printed later, often by another file: $html .= '<pre>' . $_GET['x']
        lines = {h.line for h in out}
        for mt in re.finditer(r"\$\w+\s*\.?=(?![=>])", src.code):
            a = mt.end()
            b = _expr_end(src, a, ";")
            v = _classify(src, a, b, mode)
            if not v.built or not _HTML_TAG.search(v.lit):
                continue
            w = next((p for p in v.parts if p[0] == TAINTED and not _is_call_part(p)), None)
            if w and ctx.line_of(path, mt.start()) not in lines:
                lines.add(ctx.line_of(path, mt.start()))
                out.append(_hit(ctx, path, mt.start(), "HTML is built from request input (%s) without htmlspecialchars(); "
                                                       "it is printed later" % _short(w[1]), "medium"))
        return out
    return out


_JS_EVAL = re.compile(r"(?<![\w$.])(eval)\s*\(|\bnew\s+(Function)\s*\(|(?<![\w$.])(Function)\s*\(|"
                      r"\bvm\s*\.\s*(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|\bnew\s+vm\s*\.\s*(Script)\s*\(")
_PY_EVAL = re.compile(r"(?<![\w.])(eval|exec|compile)\s*\(|(?<![\w.])(render_template_string)\s*\(|"
                      r"\b(?:jinja2\s*\.\s*)?(Template)\s*\(|\.\s*(from_string)\s*\(")
_PHP_EVAL = re.compile(r"(?<![\w>:$\\])(eval|assert|create_function)\s*\(")


def check_code_eval(path: str, text: str, ctx: Any) -> List[Hit]:
    lang = _lang_of(path)
    if lang == "js":
        if _vendored(text, path):
            return []
        evals = re.search(r"\beval\b|Function\s*\(|\bvm\s*\.", text) is not None
        if not evals and not re.search(r"node-serialize|js-yaml", text):
            return []
        src = _src(ctx, path)
        rx, mode = _JS_EVAL, _M_CMD["js"]
    elif lang == "py":
        evals = re.search(r"\beval\b|\bexec\b|compile|render_template_string|Template|from_string", text) is not None
        if not evals and not re.search(r"pickle|\bdill\b|marshal|jsonpickle|\byaml\b", text):
            return []
        src = _src(ctx, path, "py")
        rx, mode = _PY_EVAL, _M_CMD["py"]
    elif lang == "php":
        evals = re.search(r"\beval\b|\bassert\b|create_function", text) is not None
        if not evals and "unserialize" not in text:
            return []
        src = _src(ctx, path, "php")
        rx, mode = _PHP_EVAL, _M_CMD["php"]
    else:
        return []
    out = []
    for mt in rx.finditer(src.code) if evals else ():
        fn = next((g for g in mt.groups() if g), "")
        if re.search(r"\b(?:def|function)\s+$", src.code[max(0, mt.start() - 10):mt.start()]):
            continue
        if lang == "py" and fn == "Template" and not re.search(r"\bjinja2\b|from\s+jinja2\s+import", src.code):
            continue
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        cands = args if fn in ("Function",) else args[:1]
        w = None
        for a, b in cands:
            v = _classify(src, a, b, mode)
            if v.built:
                w = next((p for p in v.parts if p[0] == TAINTED and not _is_call_part(p)), None)
            elif v.level == TAINTED and not v.call and v.parts:
                w = v.parts[0]
            if w:
                break
        if not w:
            continue
        if fn in ("render_template_string", "Template", "from_string"):
            msg = ("%s() compiles a template built from request input (%s); Jinja expressions in it run on the server. "
                   "Pass the value as a variable to a fixed template" % (fn, _short(w[1])))
        else:
            msg = "%s() runs code built from request input (%s)" % (fn, _short(w[1]))
        out.append(_hit(ctx, path, mt.start(), msg, None))
    out.extend(_deserialize_hits(ctx, path, src, mode))
    return out


_PY_DESER = re.compile(r"\b(pickle|cPickle|_pickle|dill|cloudpickle|marshal)\s*\.\s*(loads?)\s*\(|\b(jsonpickle)\s*\.\s*(decode)\s*\(|"
                       r"\b(yaml)\s*\.\s*(load|load_all|unsafe_load|unsafe_load_all|full_load|full_load_all)\s*\(")


_DECODERS = re.compile(r"\w*b(?:16|32|64|85)decode|unhexlify|a2b_\w+|fromhex|decode|decompress|read|getvalue|toString|from|"
                       r"base64_decode|gzuncompress|gzinflate|hex2bin|urldecode|rawurldecode|file_get_contents")
_DECODER_MODULES = frozenset(["base64", "codecs", "Buffer", "zlib", "gzip", "binascii", "bytes", "bz2", "lzma"])


def _deser_taint(src: _Src, span: Tuple[int, int], mode: _Mode, hops: int = 0) -> Optional[tuple]:
    """The request part of a value that is deserialized. Decoders around it (b64decode, read, toString) and
    assignments are followed, since decoding keeps the bytes the client's."""
    v = _classify(src, span[0], span[1], mode)
    for p in v.parts:
        if p[0] == TAINTED:
            return p
    if hops > 4:
        return None
    a, b = _strip(src, span[0], span[1])
    if b <= a:
        return None
    e = src.code[a:b].strip()
    if _IDENT[src.lang].fullmatch(e):
        tr = _trace(src, e, a)
        if tr and tr[1] in ("assign", "loop"):
            return _deser_taint(src, tr[2], mode, hops + 1)
        return None
    if src.text[b - 1] == ")" and src.kinds[b - 1] == _CODE:
        p = _match_back(src, b - 1)
        if p <= a:
            return None
        recv, name = _callee_parts(src.code[a:p])
        if not name or not _DECODERS.fullmatch(name):
            return None
        rm = re.search(r"(?:\?\.|\.|->|::)\s*" + re.escape(name) + r"\s*$", src.code[a:p].rstrip())
        if recv and rm and recv.split(".")[-1].strip() not in _DECODER_MODULES:
            return _deser_taint(src, (a, a + rm.start()), mode, hops + 1)
        args, _c = _call_args(src, p)
        if args:
            return _deser_taint(src, args[0], mode, hops + 1)
    return None


def _py_pin(ctx: Any, name: str) -> Optional[str]:
    """The version of a Python package that requirements files, pyproject.toml, Pipfile or a lock file name
    (==, ~=, >= or a locked version), or None."""
    def find() -> Optional[str]:
        n = re.escape(name)
        spec = re.compile(r"(?<![\w.-])" + n + r"\s*(?:\[[^\]\n]*\])?\s*(?:===?|~=|>=)\s*v?([0-9][\w.]*)|"
                          r"^\s*" + n + r"\s*=\s*['\"](?:===?|~=|>=)?\s*([0-9][\w.]*)", re.I | re.M)
        locked = re.compile(r"(?i)name\s*=\s*\"" + n + r"\"\s*\r?\n\s*version\s*=\s*\"([0-9][^\"]*)\"|"
                            r"\"" + n + r"\"\s*:\s*\{[^{}]*\"version\"\s*:\s*\"==([0-9][^\"]*)\"")
        for f in ctx.files:
            base = f.rsplit("/", 1)[-1].lower()
            if base in ("poetry.lock", "uv.lock", "pipfile.lock", "pdm.lock"):
                rx = locked
            elif (base.endswith((".txt", ".in")) and "requirement" in base) or base in ("pyproject.toml", "pipfile", "setup.py",
                                                                                         "setup.cfg"):
                rx = spec
            else:
                continue
            m = rx.search(ctx.read(f))
            if m:
                return next(g for g in m.groups() if g)
        return None
    return ctx.memo(("ward-inj-py-pin", name.lower()), find)


def _deser_sev(w: Optional[tuple], sure: bool, req: bool) -> str:
    """Severity of an unsafe deserializer call: request data reaches it (w), the call is unsafe on this
    version for certain (sure), and the file handles requests (req)."""
    if w:
        return "critical" if sure else "high"
    return "high" if sure and req else "medium"


# a read of a file the developer named: yaml.load(fs.readFileSync('./swagger.yml')), yaml.load(open("config.yml"))
_FIXED_FILE_READ = re.compile(r"^\s*(?:await\s+)?(?:[\w$.]+\s*\.\s*)?(?:readFileSync|readFile|open)\s*\(\s*(['\"`])[^'\"`$]+\1\s*[,)]")


def _fixed_file_arg(src: _Src, span: Tuple[int, int], hops: int = 0) -> bool:
    """True when the value is read from a file the developer named, also through fh = open('x.yml'), fh.read()
    or with open('x.yml') as fh."""
    a, b = _strip(src, span[0], span[1])
    if b <= a:
        return False
    if _FIXED_FILE_READ.match(src.text[a:b]):
        return True
    if hops > 2:
        return False
    e = src.code[a:b].strip()
    rm = re.fullmatch(r"([A-Za-z_$][\w$]*)\s*\.\s*read\w*\s*\(\s*\)", e)
    name = rm.group(1) if rm else (e if _IDENT[src.lang].fullmatch(e) else "")
    if not name:
        return False
    tr = _trace(src, name, a)
    return bool(tr and tr[1] == "assign" and _fixed_file_arg(src, tr[2], hops + 1))


def _deserialize_hits(ctx: Any, path: str, src: _Src, mode: _Mode) -> List[Hit]:
    """Deserializers that build objects (and so run code) from the bytes they are given."""
    out = []
    code = src.code
    req = _req_file(src)
    if src.lang == "py":
        for mt in _PY_DESER.finditer(code):
            lib = mt.group(1) or mt.group(3) or mt.group(5)
            fn = mt.group(2) or mt.group(4) or mt.group(6)
            args, _c = _call_args(src, mt.end() - 1)
            if not args:
                continue
            label = "%s.%s()" % (lib, fn)
            w = _deser_taint(src, args[0], mode)
            if lib == "yaml":
                if not re.search(r"(?m)^\s*(?:import\s+yaml\b|from\s+yaml\s+import)", code):
                    continue  # ruamel's YAML() and other parsers are not PyYAML
                if not w and _fixed_file_arg(src, args[0]):
                    continue  # a file the developer named, not data from outside
                pv = parse_version(_py_pin(ctx, "pyyaml"))
                old = pv is not None and pv + (0,) * (2 - len(pv)) < (5, 4)
                loader = " ".join(code[a:b] for a, b in args[1:]).strip()
                last = re.sub(r"^\s*Loader\s*=\s*", "", loader).split(".")[-1].strip() if loader else ""
                data = " (request or upload data: %s)" % _short(w[1]) if w else ""
                if fn.startswith("full_load") or last in ("FullLoader", "CFullLoader"):
                    if old:  # FullLoader built objects until PyYAML 5.4 (CVE-2020-14343)
                        out.append(_hit(ctx, path, mt.start(), "%s with FullLoader can build Python objects on PyYAML before "
                                                               "5.4%s; use yaml.safe_load()" % (label, data),
                                        _deser_sev(w, True, req)))
                    continue
                if fn.startswith("unsafe") or last in ("Loader", "UnsafeLoader", "CLoader", "CUnsafeLoader"):
                    sev = _deser_sev(w, True, req)
                elif loader:
                    continue  # SafeLoader, CSafeLoader or a custom loader
                elif pv is not None and not old:
                    continue  # PyYAML 5.4+ defaults to FullLoader, and 6.0 refuses a call without Loader=
                else:
                    sev = _deser_sev(w, old, req)
                    if not old:
                        data += " (PyYAML is not pinned here; this applies before 5.4, and 6.0 refuses the call)"
                msg = "%s without SafeLoader can build any Python object from the document%s; use yaml.safe_load()" % (label, data)
                out.append(_hit(ctx, path, mt.start(), msg, sev))
                continue
            if not w:
                continue  # a pickle of the app's own data (a cache, a model file) is not reported
            out.append(_hit(ctx, path, mt.start(), "%s deserializes request data (%s); a crafted payload runs code on the "
                                                   "server. Accept JSON and validate it" % (label, _short(w[1])), "critical"))
        return out
    if src.lang == "js":
        names = []
        for mt in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['\"]node-serialize['\"]\s*\)|"
                              r"import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s*['\"]node-serialize['\"]", src.text):
            names.append(mt.group(1) or mt.group(2))
        for nm in names:
            for mt in re.finditer(r"(?<![\w$.])" + re.escape(nm) + r"\s*\.\s*unserialize\s*\(", code):
                args, _c = _call_args(src, mt.end() - 1)
                if not args:
                    continue
                w = _deser_taint(src, args[0], mode)
                out.append(_hit(ctx, path, mt.start(), "node-serialize unserialize() runs functions embedded in its input "
                                                       "(%s); never use it on data from outside. Use JSON.parse()"
                                                       % _short(w[1] if w else src.text[args[0][0]:args[0][1]]),
                                "critical" if w else "high"))
        jv = parse_version(ctx.installed_version("js-yaml")) if "js-yaml" in ctx.deps else None
        if jv and jv[0] < 4:
            for mt in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['\"]js-yaml['\"]\s*\)|"
                                  r"import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s*['\"]js-yaml['\"]", src.text):
                nm = mt.group(1) or mt.group(2)
                for lm in re.finditer(r"(?<![\w$.])" + re.escape(nm) + r"\s*\.\s*(load|loadAll)\s*\(", code):
                    args, _c = _call_args(src, lm.end() - 1)
                    if not args or any(re.search(r"SAFE_SCHEMA|JSON_SCHEMA|CORE_SCHEMA", code[a:b]) for a, b in args[1:]):
                        continue
                    w = _deser_taint(src, args[0], mode)
                    if not w and _fixed_file_arg(src, args[0]):
                        continue  # a file the developer named, not data from outside
                    out.append(_hit(ctx, path, lm.start(), "js-yaml %s() before version 4 parses !!js/function tags into "
                                                           "code%s; use safeLoad() or upgrade to js-yaml 4"
                                                           % (lm.group(1), " (request data: %s)" % _short(w[1]) if w else ""),
                                    _deser_sev(w, True, req)))
        return out
    for mt in re.finditer(r"(?<![\w>:$\\])unserialize\s*\(", code):
        args, _c = _call_args(src, mt.end() - 1)
        if not args:
            continue
        w = _deser_taint(src, args[0], mode)
        if not w:
            continue
        no_classes = any(re.search(r"allowed_classes['\"]\s*=>\s*false", src.text[a:b]) for a, b in args[1:])
        if no_classes:
            out.append(_hit(ctx, path, mt.start(), "unserialize() of request data (%s) with allowed_classes => false; the "
                                                   "PHP manual still says never to unserialize untrusted input. Use "
                                                   "json_decode()" % _short(w[1]), "medium"))
            continue
        out.append(_hit(ctx, path, mt.start(), "unserialize() of request data (%s) can create any class and run its "
                                               "magic methods; use json_decode()" % _short(w[1]), "critical"))
    return out


# ---------------------------------------------------------------------------
# File uploads and file paths
# ---------------------------------------------------------------------------

_M_PATH = {
    "js": _Mode("js", "path", _JS_SOURCES_X, _SAFE_PATH),
    "py": _Mode("py", "path", _PY_SOURCES_X, _SAFE_PATH),
    "php": _Mode("php", "path", _PHP_SOURCES_X, _SAFE_PATH),
}

_PATH_SINK_NAMES = {
    "js": frozenset(["join", "resolve", "writeFile", "writeFileSync", "createWriteStream", "rename", "renameSync",
                     "copyFile", "copyFileSync", "mv", "cb", "callback", "done", "appendFile", "appendFileSync",
                     "outputFile", "move", "open", "openSync", "write"]),
    "py": frozenset(["join", "open", "save", "Path", "copy", "copyfile", "move", "rename", "write_bytes", "write_text",
                     "makedirs"]),
    "php": frozenset(["move_uploaded_file", "move", "storeAs", "storePubliclyAs", "putFileAs", "file_put_contents",
                      "fopen", "copy", "rename"]),
}
_UPLOAD_NAME_SAFE = re.compile(r"(?i)(?:basename|secure_filename|get_valid_filename|sanitize\w*|slugify|slug|extname|"
                               r"splitext|pathinfo|parse|uuid\w*|randomUUID|nanoid|hash\w*|md5|sha1|crc32|"
                               r"preg_replace|replace|replaceAll|sub|filenamify|clean\w*|Str\s*::\s*(?:slug|random|uuid))")


def _enclosing_calls(src: _Src, idx: int, levels: int = 3) -> List[Tuple[str, str, int]]:
    """(callee_name, receiver, open_index) of the calls that contain idx, inner first."""
    text, kinds = src.text, src.kinds
    out = []
    j = idx - 1
    depth = 0
    lo = max(0, idx - 4000)
    while j >= lo and len(out) < levels:
        if kinds[j] == _CODE:
            c = text[j]
            if c in ")]}":
                depth += 1
            elif c in "([{":
                if depth == 0:
                    if c == "(":
                        cs = _back_operand(src, j)
                        callee = src.code[cs:j].strip()
                        recv, name = _callee_parts(callee)
                        out.append((name, recv, j))
                    elif c == "{":
                        if re.search(r"\bfunction\b[^{]*$|=>\s*$|\)\s*$", src.code[max(0, j - 200):j]):
                            break
                    j -= 1
                    continue
                depth -= 1
            elif c == ";" and depth == 0:
                break
        j -= 1
    return out


def _stmt_assign_target(src: _Src, idx: int) -> Optional[Tuple[str, int]]:
    code = src.code
    lo = max(0, idx - 600)
    seg = code[lo:idx]
    cut = max(seg.rfind(";"), seg.rfind("\n\n"), seg.rfind("{"), seg.rfind("}"))
    line = seg[cut + 1:] if cut >= 0 else seg
    if src.lang == "php":
        m = re.search(r"\$(\w+)\s*\.?=(?![=>])[^=]*$", line)
        return ("$" + m.group(1), idx) if m else None
    if src.lang == "py":
        m = re.search(r"(?m)^[ \t]*(\w+)[ \t]*(?::[^=\n]+)?=(?!=)[^\n]*$", line)
        return (m.group(1), idx) if m else None
    m = re.search(r"(?:\b(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)\s*(?::[^=]{1,80})?\s*\+?=(?![=>])[^;]*$", line)
    return (m.group(1), idx) if m else None


def _client_name_occurrences(src: _Src) -> List[Tuple[int, int, str]]:
    """(start, end, kind) of expressions holding the client-supplied upload file name."""
    code, lang = src.code, src.lang
    out = []
    if lang == "js":
        for mt in re.finditer(r"\.\s*(?:originalname|originalFilename)\b", code):
            s = _back_operand(src, mt.start())
            out.append((s, mt.end(), "client"))
        for mt in re.finditer(r"\breq\s*\.\s*files?\b[\w$.\[\]\s'\"]*?\.\s*name\b", code):
            out.append((mt.start(), mt.end(), "client"))
        for mt in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*name\b", code):
            nm = mt.group(1)
            tr = _trace(src, nm, mt.start())
            if not tr:
                continue
            at, kind, data, _ap = tr
            rhs = ""
            if kind == "assign":
                rhs = src.text[data[0]:data[1]]
            hdr = code[at:at + 200]
            if re.search(r"formData\b.*\.\s*get\s*\(|\.get\s*\(\s*['\"](?:file|image|avatar|upload|photo|attachment)", rhs) \
                    or re.search(r"\bas\s+File\b|:\s*File\b", hdr) or re.search(r"\breq\s*\.\s*files?\b", rhs):
                out.append((mt.start(), mt.end(), "client"))
    elif lang == "py":
        for mt in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)((?:\s*\[[^\]]*\]|\s*\.\s*get\s*\([^)]*\))*)\s*\.\s*(filename|name)\b", code):
            nm = mt.group(1)
            chain = code[mt.start():mt.end()]
            if nm == "request" and re.search(r"request\s*\.\s*(?:files|FILES)", chain):
                out.append((mt.start(), mt.end(), "client"))
                continue
            tr = _trace(src, nm, mt.start())
            if not tr:
                continue
            at, kind, data, _ap = tr
            if kind == "assign":
                rhs = code[data[0]:data[1]]
                if re.search(r"\brequest\s*\.\s*(?:files|FILES)\b", rhs):
                    out.append((mt.start(), mt.end(), "client"))
            elif kind == "loop":
                rhs = code[data[0]:data[1]]
                if re.search(r"\brequest\s*\.\s*(?:files|FILES)\b|getlist\s*\(", rhs):
                    out.append((mt.start(), mt.end(), "client"))
            elif kind == "param" and data and re.search(r"UploadFile|FileStorage|UploadedFile", data.get("annot", "")):
                out.append((mt.start(), mt.end(), "client"))
    else:
        # the array keys are strings, so match on the raw text and keep code positions only
        for mt in re.finditer(r"\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]name['\"]\s*\]", src.text):
            if src.kinds[mt.start()] == _CODE:
                out.append((mt.start(), mt.end(), "client"))
        for mt in re.finditer(r"(\$\w+)\s*\[\s*['\"]name['\"]\s*\]", src.text):
            if mt.group(1) == "$_FILES" or src.kinds[mt.start()] != _CODE:
                continue
            tr = _trace(src, mt.group(1), mt.start())
            if tr and tr[1] in ("assign", "loop") and re.search(r"\$_FILES\b", code[tr[2][0]:tr[2][1]]):
                out.append((mt.start(), mt.end(), "client"))
        for mt in re.finditer(r"->\s*getClientOriginalName\s*\(\s*\)", code):
            s = _back_operand(src, mt.start())
            out.append((s, mt.end(), "laravel"))
    return out


_JS_ANY_RECV_SINKS = frozenset(["writeFile", "writeFileSync", "createWriteStream", "rename", "renameSync", "copyFile",
                                "copyFileSync", "appendFile", "appendFileSync", "outputFile", "outputFileSync", "mv"])
_JS_PATH_FNS = frozenset(["join", "resolve"])
_JS_FS_FNS = frozenset(["open", "openSync", "write", "move", "moveSync", "copy", "copySync"])
_JS_CB_FNS = frozenset(["cb", "callback", "done"])
_JS_MODS = r"['\"](?:node:)?(path|fs|fs/promises|fs-extra|graceful-fs)(?:/posix|/win32)?['\"]"


def _js_module_names(src: _Src) -> Tuple[set, set, set, set]:
    """(path namespaces, bare path functions, fs namespaces, bare fs functions) this JS file imports."""
    res = src.memo.get("mod-names")
    if res is None:
        text = src.text
        pns, pbare = {"path"}, set()
        fns, fbare = {"fs", "fsp", "fse", "fsExtra", "promises"}, set()
        for mt in re.finditer(r"(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*" + _JS_MODS + r"\s*\)|"
                              r"import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s*" + _JS_MODS, text):
            nm, mod = (mt.group(1), mt.group(2)) if mt.group(1) else (mt.group(3), mt.group(4))
            (pns if mod == "path" else fns).add(nm)
        for mt in re.finditer(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*" + _JS_MODS + r"\s*\)|"
                              r"import\s*\{([^}]*)\}\s*from\s*" + _JS_MODS, text):
            body, mod = (mt.group(1), mt.group(2)) if mt.group(1) is not None else (mt.group(3), mt.group(4))
            for part in body.split(","):
                bits = re.split(r"\s+as\s+|\s*:\s*", part.strip())
                if bits and bits[-1].strip():
                    (pbare if mod == "path" else fbare).add(bits[-1].strip())
        res = (pns, pbare, fns, fbare)
        src.memo["mod-names"] = res
    return res


def _upload_sink(src: _Src, name: str, recv: str, op: int) -> bool:
    """True when the call name(...) on recv writes or builds a server path."""
    if src.lang != "js":
        return name in _PATH_SINK_NAMES[src.lang]
    if name in _JS_ANY_RECV_SINKS:
        return True
    pns, pbare, fns, fbare = _js_module_names(src)
    r = re.sub(r"\s+", "", recv or "")
    root = r.split(".")[0]
    if name in _JS_PATH_FNS:
        return root in pns if r else name in pbare
    if name in _JS_FS_FNS:
        return (root in fns or r.endswith(".promises")) if r else name in fbare
    if name in _JS_CB_FNS and not r:
        # multer's diskStorage({ filename: (req, file, cb) => cb(null, name) })
        return re.search(r"\bfilename\s*(?::\s*(?:async\s*)?(?:function\b[^{]*\{|\([^()]*\)\s*=>)|\([^()]*\)\s*\{)",
                         src.code[max(0, op - 600):op]) is not None
    return False


# an extension allowlist in a PHP upload handler: pathinfo(..., PATHINFO_EXTENSION), the part after the last
# dot, or a literal extension such as 'jpg'
_PHP_EXT_CHECK = re.compile(r"PATHINFO_EXTENSION|getClientOriginalExtension|guessExtension|strrpos\s*\([^;]*['\"]\.['\"]|"
                            r"explode\s*\(\s*['\"]\.['\"]|['\"]\.?(?:jpe?g|png|gif|webp|bmp|pdf|txt|csv|docx?|xlsx?|mp[34])['\"]")
_RANDOM_DIR = re.compile(r"Ulid\s*::\s*generate|Str\s*::\s*(?:uuid|ulid|orderedUuid|random)|Uuid\s*::|uniqid\s*\(|random_bytes\s*\(|"
                         r"hashName\s*\(")


def _php_ext_kept(src: _Src, s: int, e: int) -> Optional[str]:
    """For basename($_FILES[..]['name']): the call that stores the upload under that name, when the file has no
    extension allowlist (basename() stops ../ but keeps .php)."""
    if _PHP_EXT_CHECK.search(src.text):
        return None
    tgt = _stmt_assign_target(src, s)
    if not tgt:
        return None
    fwd = src.code[e:e + 3000]
    for fm in re.finditer(r"(?<![\w$])" + re.escape(tgt[0]) + r"\b", fwd):
        for name, recv, op in _enclosing_calls(src, e + fm.start()):
            if name in ("move_uploaded_file", "copy", "rename", "move", "file_put_contents"):
                args, _c = _call_args(src, op)
                if name in ("move_uploaded_file", "copy", "rename") and args and args[0][0] <= e + fm.start() < args[0][1]:
                    continue  # the source path, not the target
                return name
    return None


def check_upload_client_filename(path: str, text: str, ctx: Any) -> List[Hit]:
    if not re.search(r"originalname|originalFilename|\.filename\b|\.name\b|\$_FILES|getClientOriginalName", text):
        return []
    lang = _lang_of(path)
    if lang == "js" and (_vendored(text, path) or ctx.is_client_file(path) or re.match(r"\s*['\"]use client['\"]", text)):
        return []  # the browser cannot write a server path
    src = _src(ctx, path)
    lang = src.lang
    if lang not in ("js", "py", "php"):
        return []
    out = []
    done_lines: set = set()
    for s, e, kind in _client_name_occurrences(src):
        tail = src.code[e:e + 60]
        if re.match(r"\s*\.\s*(?:split\s*\(\s*['\"]\.['\"]\s*\)\s*\.\s*pop|replace\s*\(\s*/\[\^|rsplit\s*\(|endswith|lower\s*\(\s*\)\s*\.\s*endswith)", tail):
            continue
        calls = _enclosing_calls(src, s)
        if calls and _UPLOAD_NAME_SAFE.fullmatch(calls[0][0] or "") and not _upload_sink(src, *calls[0]):
            if lang == "php" and calls[0][0] == "basename":
                mover = _php_ext_kept(src, s, e)
                line = ctx.line_of(path, s)
                if mover and line not in done_lines:
                    done_lines.add(line)
                    out.append(_hit(ctx, path, s, "upload keeps the client's file extension (basename() of %s) and %s() "
                                                  "stores it; a .php file in a web-served folder runs as code. Allow only "
                                                  "known extensions or generate the name" % (_short(src.text[s:e], 40), mover),
                                    None))
            continue
        if lang == "py" and re.search(r"Path\s*\([^()]*$", src.code[max(0, s - 80):s]) and re.match(r"\s*\)\s*\.\s*name\b", tail):
            continue
        sink = None
        sink_op = -1
        for name, recv, _op in calls:
            if _upload_sink(src, name, recv, _op):
                if lang == "py" and name == "save" and re.search(r"(?:default_storage|storage|fs|FileSystemStorage\s*\([^)]*\))\s*$", recv):
                    sink = None
                    break
                if lang == "php" and name == "move_uploaded_file":
                    args, _c = _call_args(src, _op)
                    if args and args[0][0] <= s < args[0][1]:
                        continue
                sink = name
                sink_op = _op
                break
            if _UPLOAD_NAME_SAFE.fullmatch(name or ""):
                break
        if sink is None and lang == "py" and re.search(r"/\s*$", src.code[max(0, s - 10):s]):
            sink = "/"
        if sink is None:
            tgt = _stmt_assign_target(src, s)
            if tgt:
                var = tgt[0]
                fwd = src.code[e:e + 3000]
                for fm in re.finditer(r"(?<![\w$.])" + re.escape(var) + r"\b", fwd):
                    cs = _enclosing_calls(src, e + fm.start())
                    hits = [c for c in cs if _upload_sink(src, *c)]
                    if hits and not (_UPLOAD_NAME_SAFE.fullmatch(cs[0][0] or "") and not _upload_sink(src, *cs[0])):
                        if lang == "py" and any(c[0] == "save" and re.search(r"storage|fs$", c[1]) for c in hits):
                            continue
                        sink, sink_op = hits[0][0], hits[0][2]
                        break
                    if lang == "py" and re.search(r"/\s*$", src.code[max(0, e + fm.start() - 10):e + fm.start()]):
                        sink = "/"
                        break
        if sink is None:
            continue
        line = ctx.line_of(path, s)
        if line in done_lines:
            continue
        expr = _short(src.text[s:e], 50)
        if kind == "laravel" and sink == "move":
            # Symfony's UploadedFile::move() keeps only the base name of the target, so ../ cannot escape
            args, _c = _call_args(src, sink_op) if sink_op >= 0 else ([], -1)
            dir_text = src.text[args[0][0]:args[0][1]] if args else ""
            if re.fullmatch(r"\s*\$\w+\s*", dir_text):
                tr = _trace(src, dir_text.strip(), args[0][0])
                if tr and tr[1] == "assign":
                    dir_text = src.text[tr[2][0]:tr[2][1]]
            if _RANDOM_DIR.search(dir_text) and not re.search(r"public_path|public/", dir_text):
                continue  # a fresh random folder outside the web root: nothing to overwrite, nothing served
            msg = ("upload is moved under the client's file name (%s); move() keeps only the base name, so ../ does not "
                   "escape, but the file can overwrite another upload and keeps the client's extension. Use hashName() "
                   "or a random name" % expr)
            sev = "medium"
        elif kind == "laravel" and sink in ("storeAs", "storePubliclyAs", "putFileAs"):
            msg = ("upload is stored under the client's file name (%s); it can overwrite other files and keeps the client's "
                   "extension. Use hashName() or a random name" % expr)
            sev = "medium"
        else:
            msg = ("upload is written to disk under the client's file name (%s); a name with ../ escapes the upload folder. "
                   "Generate a random name or take basename()" % expr)
            sev = None
        done_lines.add(line)
        out.append(_hit(ctx, path, s, msg, sev))
    return out


_JS_SNIFF = re.compile(r"\bfile-type\b|fileTypeFrom\w+|\bmagic-bytes|\bmmmagic\b|\bsharp\s*\(|\bjimp\b|image-size|probe-image-size|"
                       r"readChunk|magicNumber|magic_number|\bfiletype\b|isSvg|\bimage-type\b")
_PY_SNIFF = re.compile(r"\bimghdr\b|\bfiletype\b|\bpuremagic\b|\bmagic\s*\.|\bfrom\s+PIL\b|\bimport\s+PIL\b|\bImage\s*\.\s*open\b|"
                       r"\bfleep\b|\bverify\s*\(\s*\)")
_PHP_SNIFF = re.compile(r"\bfinfo\b|mime_content_type|getimagesize|exif_imagetype|->\s*getMimeType\s*\(|->\s*guessExtension\s*\(|"
                        r"(?:['\"]|\|)(?:image(?=['\"|:])|mimes:|mimetypes:)|File\s*::\s*(?:types|image)\b|imagecreatefrom")
_CMP_CTX = re.compile(r"^\s*(?:[=!]==?|\.\s*(?:startsWith|endsWith|includes|match|test|indexOf|startswith|endswith|split)\s*\(|\s+(?:not\s+)?in\b|\)\s*\)?\s*[=!]==?)")


def check_upload_client_mime(path: str, text: str, ctx: Any) -> List[Hit]:
    lang = _lang_of(path)
    if lang == "js":
        if "mimetype" not in text and ".type" not in text:
            return []
        if _JS_SNIFF.search(text) or ctx.is_client_file(path) or _vendored(text, path):
            return []
    elif lang == "py":
        if "content_type" not in text and "mimetype" not in text:
            return []
        if _PY_SNIFF.search(text):
            return []
    elif lang == "php":
        if "type" not in text and "getClientMimeType" not in text:
            return []
        if _PHP_SNIFF.search(text):
            return []
    else:
        return []
    src = _src(ctx, path, lang)
    code = src.code
    occ = []
    if lang == "js":
        for mt in re.finditer(r"\.\s*mimetype\b", code):
            occ.append((_back_operand(src, mt.start()), mt.end()))
        for mt in re.finditer(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*type\b", code):
            tr = _trace(src, mt.group(1), mt.start())
            if tr and tr[1] == "assign" and re.search(r"formData\b|\.get\s*\(\s*['\"](?:file|image|avatar|upload|photo)",
                                                      src.text[tr[2][0]:tr[2][1]]):
                occ.append((mt.start(), mt.end()))
    elif lang == "py":
        for mt in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)((?:\s*\[[^\]]*\])*)\s*\.\s*(content_type|mimetype)\b", code):
            nm = mt.group(1)
            if nm == "request":
                continue
            tr = _trace(src, nm, mt.start())
            ok = False
            if tr:
                at, kind, data, _ap = tr
                if kind in ("assign", "loop") and re.search(r"\brequest\s*\.\s*(?:files|FILES)\b|getlist", code[data[0]:data[1]]):
                    ok = True
                if kind == "param" and data and re.search(r"UploadFile|FileStorage|UploadedFile", data.get("annot", "")):
                    ok = True
            if re.search(r"request\s*\.\s*(?:files|FILES)", code[mt.start():mt.end()]):
                ok = True
            if ok:
                occ.append((mt.start(), mt.end()))
    else:
        for mt in re.finditer(r"\$_FILES\s*\[[^\]]+\]\s*\[\s*['\"]type['\"]\s*\]|->\s*getClientMimeType\s*\(\s*\)", src.text):
            if src.kinds[mt.start()] == _CODE:
                occ.append((mt.start(), mt.end()))
        for mt in re.finditer(r"(\$\w+)\s*\[\s*['\"]type['\"]\s*\]", src.text):
            if mt.group(1) == "$_FILES" or src.kinds[mt.start()] != _CODE:
                continue
            tr = _trace(src, mt.group(1), mt.start())
            if tr and tr[1] in ("assign", "loop") and re.search(r"\$_FILES\b", code[tr[2][0]:tr[2][1]]):
                occ.append((mt.start(), mt.end()))
    # one assignment hop: $type = $_FILES['f']['type']; if ($type == 'image/png') ...
    for s, e in list(occ):
        tgt = _stmt_assign_target(src, s)
        if not tgt or not re.search(r"(?<![=!<>])=\s*$", code[max(0, s - 40):s]) or not re.match(r"[ \t]*(?:;|\r?\n|$)", code[e:e + 20]):
            continue
        for vm in re.finditer(r"(?<![\w$.])" + re.escape(tgt[0]) + r"(?![\w$])", code[e:e + 3000]):
            occ.append((e + vm.start(), e + vm.end()))
    out = []
    for s, e in sorted(occ):
        after = code[e:e + 80]
        before = code[max(0, s - 120):s]
        compared = _CMP_CTX.match(after) or re.search(r"(?:includes|indexOf|in_array|has)\s*\(\s*$|[=!]==?\s*$|\bin\s*$", before)
        if not compared:
            continue
        out.append(_hit(ctx, path, s, "upload type is checked only against the client-sent Content-Type; check the file's "
                                      "bytes (magic number) or re-encode it", None))
        break
    return out


def check_upload_no_size_limit(path: str, text: str, ctx: Any) -> List[Hit]:
    lang = _lang_of(path)
    if lang == "js":
        if "multer" not in text and "express-fileupload" not in text:
            return []
        src = _src(ctx, path)
        code = src.code
        out = []
        checks = []
        if re.search(r"require\(\s*['\"]multer['\"]\s*\)|from\s+['\"]multer['\"]", src.text):
            checks.append((re.compile(r"(?<![\w$.])multer\s*\("), "multer"))
        fm = re.search(r"(?:const|let|var|import)\s+([\w$]+)\s*(?:=\s*require\(\s*|from\s*)['\"]express-fileupload['\"]", src.text)
        if fm:
            checks.append((re.compile(r"(?<![\w$.])" + re.escape(fm.group(1)) + r"\s*\("), "express-fileupload"))
        for rx, label in checks:
            for mt in rx.finditer(code):
                args, _c = _call_args(src, mt.end() - 1)
                opts = None
                if args:
                    a, b = args[0]
                    if src.text[a] == "{":
                        opts = src.text[a:b]
                    elif _IDENT["js"].fullmatch(src.code[a:b].strip()):
                        tr = _trace(src, src.code[a:b].strip(), a)
                        if tr and tr[1] == "assign" and src.text[tr[2][0]:tr[2][0] + 1] == "{":
                            opts = src.text[tr[2][0]:tr[2][1]]
                        else:
                            continue
                    else:
                        continue
                if opts is not None and re.search(r"\bfileSize\s*:", opts):
                    continue
                if opts is not None and re.search(r"\blimits\s*:\s*[\w$]+\s*[,}]", opts):
                    continue
                out.append(_hit(ctx, path, mt.start(), "%s() has no limits.fileSize, so uploads of any size are accepted "
                                                       "(the default is unlimited)" % label, None))
        return out
    if lang == "py":
        if "request.files" not in text or not re.search(r"\bflask\b", text):
            return []
        state = ctx.memo("ward-inj-flask-maxlen", lambda: {
            "has": any("MAX_CONTENT_LENGTH" in ctx.read(f) or "max_content_length" in ctx.read(f)
                       for f in ctx.files if f.endswith((".py", ".cfg", ".toml", ".ini", ".env", ".json", ".yaml", ".yml"))),
            "done": False})
        if state["has"] or state["done"]:
            return []
        src = _src(ctx, path, "py")
        mt = re.search(r"\brequest\s*\.\s*files\b", src.code)
        if not mt:
            return []
        state["done"] = True
        return [_hit(ctx, path, mt.start(), "Flask app reads uploads but MAX_CONTENT_LENGTH is not set anywhere, so request "
                                            "size is unlimited", None)]
    return []


_JS_FS_NS = re.compile(r"(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*['\"](?:node:)?fs(?:/promises)?['\"]\s*\)(?:\s*\.\s*promises)?|"
                       r"import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s*['\"](?:node:)?fs(?:/promises)?['\"]")
_JS_FS_BARE = re.compile(r"(?:const|let|var)\s*\{([^}]*)\}\s*=\s*require\(\s*['\"](?:node:)?fs(?:/promises)?['\"]\s*\)|"
                         r"import\s*\{([^}]*)\}\s*from\s*['\"](?:node:)?fs(?:/promises)?['\"]")
_FS_FUNCS = (r"readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|appendFileSync|"
             r"unlink|unlinkSync|rm|rmSync|readdir|readdirSync|open|openSync|copyFile|copyFileSync|rename|renameSync|"
             r"mkdir|mkdirSync")
# Archive libraries: the names of the entries inside an uploaded zip or tar are the uploader's (zip slip).
_JS_ARCHIVE_LIB = re.compile(r"['\"](?:unzipper|yauzl|adm-zip|tar-stream|tar|jszip|decompress|extract-zip|node-stream-zip|"
                             r"unzip-stream|unzip)['\"]")
_JS_ARCHIVE_SRC = re.compile(r"\b(?:entry|header|zipEntry|fileEntry|ent)\s*\.\s*(?:path|fileName|entryName|name)\b")
_ZIP_SLIP_GUARD = re.compile(r"\.\s*startsWith\s*\(|path\s*\.\s*relative\s*\(|isPathInside|is-path-inside|path-is-inside")
_PY_ZIP_SLIP_GUARD = re.compile(r"\.\s*(?:startswith|is_relative_to|relative_to)\s*\(|\bcommonpath\s*\(")
_JS_PATH_GUARD = re.compile(r"\.\s*startsWith\s*\(|path\s*\.\s*relative\s*\(|\.\s*includes\s*\(\s*['\"]\.\.['\"]|isPathInside|"
                            r"is-path-inside|path-is-inside|\.\s*indexOf\s*\(\s*['\"]\.\.['\"]|sanitize-filename|"
                            r"\.\s*test\s*\(|\.\s*match\s*\(")
_PY_PATH_GUARD = re.compile(r"secure_filename|basename|safe_join|send_from_directory|is_relative_to|commonpath|relative_to\s*\(|"
                            r"startswith\s*\(|re\s*\.\s*(?:fullmatch|match)\s*\(")
_PHP_PATH_GUARD = re.compile(r"\bbasename\s*\(|\brealpath\s*\(|str_starts_with\s*\(|\bstrpos\s*\(|preg_match\s*\(|in_array\s*\(")


def _tar_extract_hits(ctx: Any, path: str, src: _Src) -> List[Hit]:
    """tarfile extractall() / shutil.unpack_archive() without filter= in a request handler: member names
    such as ../../app.py or absolute paths are written where they point (Python 3.14 defaults to 'data')."""
    code = src.code
    if not re.search(r"(?m)^\s*(?:import\s+[\w., ]*\b(?:tarfile|shutil)\b|from\s+tarfile\s+import)", code) or not _req_file(src):
        return []
    out = []
    for mt in re.finditer(r"\.\s*(extractall|extract)\s*\(|\bshutil\s*\.\s*(unpack_archive)\s*\(", code):
        if mt.group(1) and "tarfile" not in code:
            continue  # zipfile's extract() and extractall() drop ../ and absolute paths themselves
        args, _c = _call_args(src, mt.end() - 1)
        if any(re.match(r"\s*(?:filter|members)\s*=", code[a:b]) for a, b in args):
            continue
        fn = mt.group(1) or mt.group(2)
        out.append(_hit(ctx, path, mt.start(), "%s() without filter='data' writes archive members wherever their names "
                                               "point (../, absolute paths, links); pass filter='data' (Python 3.12+) or "
                                               "check each member" % fn, None))
    return out


_URLISH = re.compile(r"(?i)url|uri|link|href|endpoint|feed|webhook|src\b|image|avatar|http")


def _path_judge(v: _V) -> Optional[tuple]:
    if v.level != TAINTED or (v.call and not v.built):
        return None
    for p in v.parts:
        if p[0] == TAINTED and not p[3]:
            return p
    return None


def check_path_traversal(path: str, text: str, ctx: Any) -> List[Hit]:
    lang = _lang_of(path)
    arch_mode: Optional[_Mode] = None
    if lang == "js":
        if _vendored(text, path) or not re.search(r"\bfs\b|sendFile|download|readFile|createReadStream", text):
            return []
        src = _src(ctx, path)
        code = src.code
        ns = {"fs"}
        bare: List[str] = []
        for mt in _JS_FS_NS.finditer(src.text):
            ns.add(mt.group(1) or mt.group(2))
        for mt in _JS_FS_BARE.finditer(src.text):
            body = mt.group(1) or mt.group(2) or ""
            for part in body.split(","):
                bits = re.split(r"\s+as\s+|\s*:\s*", part.strip())
                if bits and re.fullmatch(_FS_FUNCS, bits[0].strip()):
                    bare.append(bits[-1].strip())
        pats = [r"\bres\s*\.\s*(sendFile|download)\s*\(",
                r"\b(?:" + "|".join(re.escape(x) for x in sorted(ns)) + r")\s*(?:\.\s*promises\s*)?\.\s*(" + _FS_FUNCS + r")\s*\("]
        if bare:
            pats.append(r"(?<![\w$.])(" + "|".join(re.escape(x) for x in bare) + r")\s*\(")
        sink_rx = re.compile("|".join(pats))
        guard = _JS_PATH_GUARD
        if _JS_ARCHIVE_LIB.search(src.text):
            arch_mode = _Mode("js", "path", re.compile(_JS_ARCHIVE_SRC.pattern), _SAFE_PATH)
    elif lang == "py":
        if not re.search(r"\bopen\s*\(|send_file|FileResponse|os\s*\.\s*remove|unlink|shutil|extractall", text):
            return []
        src = _src(ctx, path, "py")
        code = src.code
        sink_rx = re.compile(r"(?<![\w.])(open|send_file|FileResponse)\s*\(|\b(?:aiofiles|io)\s*\.\s*(open)\s*\(|"
                             r"\bos\s*\.\s*(remove|unlink|rmdir|listdir)\s*\(|\bshutil\s*\.\s*(rmtree|copy|copyfile|move)\s*\(")
        guard = _PY_PATH_GUARD
        # for info in zf.infolist(): open(os.path.join(dest, info.filename), "wb"): the member name is the uploader's
        members = sorted(set(re.findall(r"\bfor\s+(\w+)\s+in\s+[\w.]+\s*\.\s*(?:infolist|namelist|getmembers|getnames)\s*\(\s*\)",
                                        code)))
        if members and re.search(r"(?m)^\s*(?:import\s+[\w., ]*\b(?:zipfile|tarfile)\b|from\s+(?:zipfile|tarfile)\s+import)", code):
            arch_mode = _Mode("py", "path", re.compile(r"\b(?:" + "|".join(members) + r")\b(?:\s*\.\s*(?:filename|name))?"),
                              _SAFE_PATH)
    elif lang == "php":
        src = _src(ctx, path, "php")
        code = src.code
        sink_rx = re.compile(r"(?<![\w>:$])(include|include_once|require|require_once)\b|"
                             r"(?<![\w>:$])(file_get_contents|readfile|fopen|file|unlink|file_put_contents|copy|rename|fpassthru|"
                             r"show_source|highlight_file)\s*\(|"
                             r"(?:\bresponse\s*\(\s*\)\s*->|\bResponse\s*::)\s*(download|file)\s*\(")
        guard = _PHP_PATH_GUARD
    else:
        return []
    mode = _M_PATH[lang]
    out = []
    if lang == "py":
        out.extend(_tar_extract_hits(ctx, path, src))
    for mt in sink_rx.finditer(code):
        fn = next((g for g in mt.groups() if g), "")
        if lang == "php" and fn in ("include", "include_once", "require", "require_once"):
            k = _next_sig(src, mt.end(), len(code))
            if k < len(code) and code[k] == "(":
                args, _c = _call_args(src, k)
                if not args:
                    continue
                a, b = args[0]
                b = _expr_end(src, a, ";")
            else:
                a = k
                b = _expr_end(src, a, ";")
        else:
            args, _c = _call_args(src, mt.end() - 1)
            if not args:
                continue
            a, b = args[0]
            if lang == "js" and fn in ("sendFile", "download") and any(re.search(r"\broot\s*:", code[x:y]) for x, y in args[1:]):
                continue
        v = _classify(src, a, b, mode)
        w = _path_judge(v)
        if not w and arch_mode is not None:
            w = _path_judge(_classify(src, a, b, arch_mode))
            zguard = _PY_ZIP_SLIP_GUARD if lang == "py" else _ZIP_SLIP_GUARD
            if w and not zguard.search(code[max(0, mt.start() - 1500):mt.start()]):
                out.append(_hit(ctx, path, mt.start(), "%s() writes an archive entry to a path built from the entry name "
                                                       "(%s); ../ in the name writes outside the folder (zip slip). Resolve "
                                                       "the path and check it starts with the destination folder + path.sep"
                                                       % (fn, _short(w[1])), None))
            continue
        if not w:
            continue
        if lang == "php" and fn in ("file_get_contents", "fopen", "file") and _URLISH.search(w[1]):
            continue
        win = code[max(0, mt.start() - 1500):mt.start()]
        if guard.search(win):
            continue
        crit = lang == "php" and fn.startswith(("include", "require"))
        label = fn + ("" if crit else "()")
        msg = "%s opens a file path built from request input (%s) with no basename() or stay-inside-the-folder check" % (
            label, _short(w[1]))
        out.append(_hit(ctx, path, mt.start(), msg, "critical" if crit else None))
    return out


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

_M_URL = {
    "js": _Mode("js", "url", _JS_SOURCES, _SAFE_URL),
    "py": _Mode("py", "url", _PY_SOURCES, _SAFE_URL),
    "php": _Mode("php", "url", _PHP_SOURCES, _SAFE_URL),
}
# Guards are matched on the code view (comments and strings blanked), as shapes, so a comment that says
# "add an allowlist later" or a flag named abused_ssrf_bug does not count.
# A host allowlist or an exact host comparison: enough on its own.
_SSRF_ALLOW = re.compile(
    r"(?i)\b\w*(?:allow|white|trusted|permitted|safe)\w*(?:list|hosts?|domains?|origins?|urls?|sites?)\w*\s*"
    r"\??\.\s*(?:includes|has|indexOf|some|find|test|contains|match)\s*\("
    r"|\bin\s+[\w.]*(?:allow|white|trusted|permitted)\w*"
    r"|\bin_array\s*\([^;]*\$\w*(?:allow|white|trusted|permitted)\w*"
    r"|\.\s*(?:hostname|host|netloc|origin)\s*(?:===|!==|==|!=|\bin\b|\bnot\s+in\b)"
    r"|(?:===|!==|==|!=)\s*[\w$.]*\.\s*(?:hostname|host|netloc|origin)\b"
    r"|\.\s*(?:hostname|host|netloc)\s*\??\.\s*(?:endsWith|endswith)\s*\("
    r"|\.\s*(?:includes|has|indexOf)\s*\(\s*(?:[\w$]+\s*\.\s*)?(?:hostname|host|origin|netloc)\b"
    r"|\$\w*host\w*\s*(?:===|!==|==|!=)|in_array\s*\(\s*(?:\$\w*host\w*|parse_url\s*\()")
# An SSRF-filtering HTTP agent or library (checked on the raw text: the module name is a string).
_SSRF_LIB = re.compile(r"['\"](?:request-filtering-agent|ssrf-req-filter|ssrf-agent|ssrfcheck|ssrf-protect)['\"]|"
                       r"^\s*(?:import\s+advocate\b|from\s+advocate\s+import)", re.M)
# A private-address check. It is a real guard only when the file also resolves the name.
_SSRF_PRIVATE = re.compile(
    r"(?i)\bis_?private\w*\s*\(|\bis_?(?:local|internal|loopback)\w*(?:ip|host|address|url)\w*\s*\(|\bssrf\w*\s*\("
    r"|\.\s*is_(?:private|global|loopback|link_local|reserved)\b|\bipaddr\s*\.\s*(?:parse|process|isValid)\s*\("
    r"|\bipaddress\s*\.\s*ip_(?:address|network)\s*\(|FILTER_FLAG_NO_PRIV_RANGE|\bisPrivate\w*\b")
_SSRF_DNS = re.compile(r"\bdns\s*\.\s*(?:promises\s*\.\s*)?(?:lookup|resolve\w*)\s*\(|['\"](?:node:)?dns(?:/promises)?['\"]|"
                       r"\bgetaddrinfo\s*\(|\bgethostbyname\w*\s*\(|\bdns_get_record\s*\(|\bresolver\s*\.\s*resolve\s*\(")
# Redirects turned on explicitly: a check made before the request does not cover the hops that follow.
_SSRF_FOLLOW = re.compile(r"\bredirect\s*:\s*['\"]follow['\"]|\b(?:follow_redirects|allow_redirects)\s*=\s*True\b|"
                          r"\bfollowRedirects?\s*:\s*true\b|\bmaxRedirects\s*:\s*[1-9]|CURLOPT_FOLLOWLOCATION\s*,\s*(?:true|1)\b")
_FIXED_HOST = re.compile(r"\s*(?:(?:https?|wss?|ftp):)?//[^/?#'\"`\s$]+[/?#:]|\s*/(?!/)|\s*\.{1,2}/|\s*[\w-]+\.[\w.-]+/")


def _ssrf_guard(src: _Src) -> str:
    """'full' when the file allowlists hosts or checks resolved addresses, 'redirects' when it checks resolved
    addresses but turns redirect following on, 'string' when it only checks the host name as text, '' when there
    is no guard."""
    res = src.memo.get("ssrf-guard")
    if res is None:
        code = src.code
        if _SSRF_ALLOW.search(code) or _SSRF_LIB.search(src.text):
            res = "full"
        elif _SSRF_PRIVATE.search(code):
            if _SSRF_DNS.search(src.text):
                res = "redirects" if _SSRF_FOLLOW.search(src.text) else "full"
            else:
                res = "string"
        else:
            res = ""
        src.memo["ssrf-guard"] = res
    return res


_STR_CONST = {
    "js": r"(?:export\s+)?(?:const|let|var)\s+{n}\s*(?::[^=;\n]{{1,80}})?=\s*(['\"`])([^'\"`$\n]*)\1",
    "py": r"(?m)^{n}\s*(?::[^=\n]{{1,80}})?=\s*[rRuU]?(['\"])([^'\"\n]*)\1",
    "php": r"(?:const\s+{n}\s*=|define\s*\(\s*['\"]{n}['\"]\s*,)\s*(['\"])([^'\"\n]*)\1",
}


def _const_string(ctx: Any, src: _Src, name: str) -> Optional[List[str]]:
    """The string values an ALL_CAPS constant is given in this file, or, when it is imported, in the project's
    other files of the same language. None when no definition is found."""
    rx = _STR_CONST[src.lang].format(n=re.escape(name.lstrip("$")))
    vals = [m.group(2) for m in re.finditer(rx, src.text)]
    if vals:
        return vals
    exts = {"js": _JS_EXTS, "py": (".py",), "php": (".php",)}[src.lang]
    index = ctx.memo(("ward-inj-str-consts", src.lang), lambda: [f for f in ctx.files if f.endswith(exts)])
    out: List[str] = []
    for f in index:
        t = ctx.read(f)
        if name.lstrip("$") not in t:
            continue
        out.extend(m.group(2) for m in re.finditer(rx, t))
        if len(out) > 5:
            break
    return out or None


def _host_tainted(v: _V) -> Optional[tuple]:
    if v.built:
        if not v.parts:
            return None
        first = v.parts[0]
        before = first[2]
        if before.strip() and _FIXED_HOST.match(before):
            return None
        for p in v.parts:
            if p[2] != before:
                break
            if p[0] == TAINTED:
                return p
        return None
    if v.level == TAINTED and not v.call:
        return v.parts[0] if v.parts else (TAINTED, "", "", False)
    return None


def _ssrf_url_arg(src: _Src, args: List[Tuple[int, int]], idx: int) -> Optional[Tuple[int, int]]:
    if idx >= len(args):
        return None
    a, b = _strip(src, args[idx][0], args[idx][1])
    if b <= a:
        return None
    if src.text[a] == "{" and _match_fwd(src, a) == b - 1:
        mm = re.search(r"(?<![\w$])(?:url|baseURL|uri|href)\s*:", src.code[a:b])
        if mm:
            vs = a + mm.end()
            return vs, _expr_end(src, vs, ",")
        mm = re.search(r"(?<![\w$])(url|uri)\s*[,}]", src.code[a:b])
        if mm:
            return a + mm.start(1), a + mm.end(1)
        return None
    return a, b


def check_ssrf_request_url(path: str, text: str, ctx: Any) -> List[Hit]:
    lang = _lang_of(path)
    if lang == "js":
        if ctx.is_client_file(path) or _vendored(text, path):
            return []
        if not re.search(r"fetch|axios|got|needle|superagent|undici|https?\s*\.\s*(?:get|request)|\bky\b", text):
            return []
        src = _src(ctx, path)
        sinks = [(re.compile(r"(?<![\w$.])(fetch|axios|got|needle|ky|ofetch|superagent)\s*\("), 0),
                 (re.compile(r"(?<![\w.])\$fetch\s*\("), 0),
                 (re.compile(r"\b(axios|got|needle|ky|superagent|http|https|undici)\s*\.\s*(get|post|put|patch|delete|head|request|stream)\s*\("), 0)]
    elif lang == "py":
        if not re.search(r"requests|httpx|urlopen|aiohttp|urllib", text):
            return []
        src = _src(ctx, path, "py")
        sinks = [(re.compile(r"\b(?:requests|httpx)\s*\.\s*(get|post|put|patch|delete|head|stream)\s*\("), 0),
                 (re.compile(r"\b(?:requests|httpx)\s*\.\s*(request)\s*\("), 1),
                 (re.compile(r"(?<![\w])(?:urllib\s*\.\s*request\s*\.\s*)?(urlopen|Request)\s*\("), 0)]
        clients = set()
        for mt in re.finditer(r"(?m)^[ \t]*(\w+)[ \t]*=[ \t]*(?:requests\s*\.\s*Session|httpx\s*\.\s*(?:Async)?Client|aiohttp\s*\.\s*ClientSession)\s*\(", src.code):
            clients.add(mt.group(1))
        for mt in re.finditer(r"\bwith\s+(?:requests\s*\.\s*Session|httpx\s*\.\s*(?:Async)?Client|aiohttp\s*\.\s*ClientSession)\s*\([^)]*\)\s+as\s+(\w+)", src.code):
            clients.add(mt.group(1))
        if clients:
            names = "|".join(re.escape(c) for c in sorted(clients))
            sinks.append((re.compile(r"\b(?:" + names + r")\s*\.\s*(get|post|put|patch|delete|head|stream)\s*\("), 0))
            sinks.append((re.compile(r"\b(?:" + names + r")\s*\.\s*(request)\s*\("), 1))
    elif lang == "php":
        if not re.search(r"file_get_contents|curl_|Http\s*::|->request\s*\(|get_headers", text):
            return []
        src = _src(ctx, path, "php")
        sinks = [(re.compile(r"(?<![\w>:$])(file_get_contents|curl_init|get_headers)\s*\("), 0),
                 (re.compile(r"(?<![\w>:$])(curl_setopt)\s*\(\s*\$\w+\s*,\s*CURLOPT_URL\s*,"), -1),
                 (re.compile(r"\bHttp\s*::\s*(get|post|put|patch|delete|head)\s*\("), 0),
                 (re.compile(r"->\s*(request)\s*\(\s*['\"]\w+['\"]\s*,"), 1)]
    else:
        return []
    guard = _ssrf_guard(src)
    if guard == "full":
        return []
    mode = _M_URL[lang]
    out = []
    done: set = set()
    for rx, idx in sinks:
        for mt in rx.finditer(src.code):
            if mt.start() in done:
                continue
            op = src.code.rfind("(", mt.start(), mt.end())
            args, _c = _call_args(src, op)
            if idx == -1:
                args = [(mt.end(), _expr_end(src, mt.end(), ","))]
                idx2 = 0
            else:
                idx2 = idx
            span = _ssrf_url_arg(src, args, idx2)
            if span is None:
                continue
            a, b = span
            v = _classify(src, a, b, mode)
            w = _host_tainted(v)
            if not w:
                continue
            if lang == "php" and mt.group(1) == "file_get_contents" and not _URLISH.search(w[1]) and not re.search(r"https?:", v.lit):
                continue
            sev = None
            note = ""
            first = v.parts[0] if v.built and v.parts else None
            if first is not None and first is not w and first[0] == SAFE and not first[2]:
                # a base URL constant or setting comes first: `${BASE_URL}${input}`
                base = first[1].strip()
                vals = _const_string(ctx, src, base) if _ALL_CAPS.fullmatch(base) else None
                if vals and all(_FIXED_HOST.match(x) and x.strip() for x in vals):
                    continue  # a fixed host; the request fills only the path or query
                sev = "medium"
                note = "; the base URL %s was not resolved, check that it ends in a fixed host and /" % _short(base, 40)
            if guard == "string":
                sev = "medium"
                note += ("; the file checks the host name as text, which a DNS name that points at 127.0.0.1 or "
                         "169.254.169.254, or a redirect, gets past. Resolve it and check the address at connect time")
            elif guard == "redirects":
                sev = "medium"
                note += ("; the file checks the resolved address but follows redirects, so a public URL that redirects to "
                         "an internal one gets past. Turn redirects off or check every hop")
            done.add(mt.start())
            fn = next((g for g in mt.groups() if g), "fetch")
            msg = ("server-side %s() fetches a URL taken from the request (%s) with no host allowlist or private-IP "
                   "check" % (fn, _short(w[1])))
            if guard in ("string", "redirects"):
                msg = "server-side %s() fetches a URL taken from the request (%s)" % (fn, _short(w[1]))
            out.append(_hit(ctx, path, mt.start(), msg + note, sev))
    return out


def check_ssrf_next_image(path: str, text: str, ctx: Any) -> List[Hit]:
    if "remotePatterns" not in text and "dangerouslyAllowLocalIP" not in text:
        return []
    src = _src(ctx, path, "js")
    code = src.code
    if re.search(r"\bunoptimized\s*:\s*true\b", code) or re.search(r"\bloader(?:File)?\s*:", code):
        return []
    out = []
    for mt in re.finditer(r"\bdangerouslyAllowLocalIP\s*:\s*true\b", code):
        out.append(_hit(ctx, path, mt.start(), "images.dangerouslyAllowLocalIP: true lets the image optimizer fetch private "
                                               "and loopback addresses (Next.js 16+); remove it unless the app runs on a "
                                               "private network you trust", None))
    for mt in re.finditer(r"\bremotePatterns\s*:\s*\[", code):
        ob = mt.end() - 1
        cb = _match_fwd(src, ob)
        if cb < 0:
            continue
        for hm in re.finditer(r"\bhostname\s*:", code[ob:cb]):
            vs = _next_sig(src, ob + hm.end(), cb)
            tok = src.tok_at.get(vs)
            if tok is not None and src.text[tok.bs:tok.be].strip() in ("**", "*"):
                out.append(_hit(ctx, path, vs, "next/image remotePatterns allows any host (hostname '%s'), so the image "
                                               "optimizer fetches any URL a visitor asks for" % src.text[tok.bs:tok.be].strip(), None))
    return out


# ---------------------------------------------------------------------------
# Rule table
# ---------------------------------------------------------------------------

_JS = ["*.js", "*.jsx", "*.ts", "*.tsx", "*.mjs", "*.cjs", "*.mts", "*.cts"]
_PY = ["*.py"]
_PHP = ["*.php"]
_TESTS = ["**/test/**", "**/tests/**", "**/__tests__/**", "**/__mocks__/**", "**/spec/**", "**/e2e/**", "**/cypress/**",
          "**/playwright/**", "**/fixtures/**", "**/testdata/**", "*.test.*", "*.spec.*", "*.stories.*", "*.story.*",
          "test_*.py", "*_test.py", "conftest.py", "*.d.ts"]
_TOOLING = ["scripts/**", "tools/**", "bin/**", ".github/**", "*.config.js", "*.config.cjs", "*.config.mjs", "*.config.ts",
            "gulpfile.*", "Gruntfile.*", "webpack.*.js", "rollup.*.js"]
_LIBS = ["**/vendor/**", "**/vendors/**", "**/third_party/**", "**/third-party/**", "**/libs/**", "**/*.min.*", "**/*.bundle.*"]
_MIGRATIONS = ["**/migrations/**", "**/migration/**", "**/seeds/**", "**/seeders/**", "**/seed/**"]


RULES: List[Rule] = [
    Rule(
        id="sqli-prisma-raw-unsafe",
        skill=SKILL,
        klass="SQL injection",
        severity="critical",
        stacks=["node", "prisma"],
        file_globs=_JS,
        exclude_globs=_TESTS + _MIGRATIONS + _LIBS,
        pattern="check_sqli_prisma_unsafe",
        message="$queryRawUnsafe / $executeRawUnsafe gets a string built with interpolation",
        why=("The tagged $queryRaw template parameterizes, but agents switch to the Unsafe variant to build a dynamic "
             "query (search, sort, filters) and interpolate values into the string."),
        fp_trap=("prisma.$queryRaw`... ${x}` (tagged template) and Prisma.sql are safe: do not flag them. "
                 "$queryRawUnsafe('... WHERE id = $1', id) with placeholders and separate arguments is safe. "
                 "An interpolated constant (an ALL_CAPS table name) is not flagged."),
        fix_ref=_SBY + "#sql-queries",
        confidence="high",
        needs_confirmation=True,
    ),
    Rule(
        id="sqli-js-string-query",
        skill=SKILL,
        klass="SQL injection",
        severity="critical",
        stacks=["node"],
        file_globs=_JS,
        exclude_globs=_TESTS + _MIGRATIONS + _LIBS,
        pattern="check_sqli_js_string",
        message="SQL string built with interpolation or + is passed to query(), knex.raw(), sequelize.literal() or similar",
        why=("Template literals make it easy to drop a variable into SQL; agents do it for dynamic WHERE, IN lists and "
             "ORDER BY, where the parameterized form takes more code."),
        fp_trap=("Parameterized calls (pool.query('... $1', [id]), knex.whereRaw('x = ?', [x]), a { text, values } config "
                 "object) are safe. Tagged templates (sql`...`, Prisma.sql) are safe. When the call passes parameters, only "
                 "request input or an ORDER BY value is flagged, so placeholder-built WHERE clauses stay quiet. A sort "
                 "column picked through an allowlist (ALLOWED.includes(x) ? x : 'id'), a loop over a constant list, and "
                 "LIMIT with a number-typed value are not flagged. supabase .or() with the signed-in user's own id is not "
                 "flagged; in browser code it is low, since it runs under the caller's own RLS."),
        fix_ref=_SBY + "#sql-queries",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="sqli-python-string-query",
        skill=SKILL,
        klass="SQL injection",
        severity="critical",
        stacks=["python", "django", "flask", "fastapi"],
        file_globs=_PY,
        exclude_globs=_TESTS + _MIGRATIONS + _LIBS,
        pattern="check_sqli_python_string",
        message="SQL built with an f-string, % or .format() reaches cursor.execute(), .raw(), RawSQL(), .extra() or text()",
        why=("f-strings are the shortest way to build a query, so agents use them in cursor.execute(), Django .raw() and "
             "SQLAlchemy text() instead of passing parameters."),
        fp_trap=("cursor.execute('... %s', (x,)) passes x as a parameter: the comma, not the % operator, is the safe "
                 "form. .raw('... %s', [x]), RawSQL(sql, [x]), text(':x') with bound params and the ORM "
                 "(.filter(name=x)) are safe. psycopg sql.SQL(...).format(sql.Identifier(x)) is safe."),
        fix_ref=_PY_REF + "#sql-injection",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="sqli-php-string-query",
        skill=SKILL,
        klass="SQL injection",
        severity="critical",
        stacks=["php", "laravel"],
        file_globs=_PHP,
        exclude_globs=_TESTS + _MIGRATIONS + _LIBS + ["*.blade.php"],
        pattern="check_sqli_php_string",
        message="SQL with an interpolated or concatenated variable reaches DB::raw(), a *Raw() method, PDO or mysqli",
        why=("Laravel's raw helpers and plain PDO accept any string; agents interpolate \"$id\" or concatenate request "
             "values because it works in the demo."),
        fp_trap=("whereRaw('x = ?', [$x]), DB::select($sql, [$x]) and PDO prepare() with ? or :name placeholders are "
                 "safe. Interpolating a table property ({$this->table}, $this->schemaTable), (int) casts, arithmetic, "
                 "in_array() / match() picks and values checked with ctype_digit(), is_numeric(), filter_var() or an "
                 "anchored digits-only preg_match() are not flagged. $wpdb->prepare() is safe. Vendored libraries (libs/, "
                 "vendor/, or a license banner inside lib/) are skipped."),
        fix_ref=_SBY + "#sql-queries",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="sqli-laravel-request-column",
        skill=SKILL,
        klass="SQL injection (column name)",
        severity="high",
        stacks=["laravel", "php"],
        file_globs=_PHP,
        exclude_globs=_TESTS + ["*.blade.php"],
        pattern="check_sqli_laravel_column",
        message="orderBy() / groupBy() takes its column name from request input",
        why=("Sortable tables are wired straight to ?sort=; Laravel binds values but cannot bind column names, and its "
             "docs say never to let user input pick them."),
        fp_trap=("A column checked with in_array() against a fixed list, a match() or a validation rule 'in:a,b' / "
                 "Rule::in() is safe. The sort direction is validated by Laravel itself."),
        fix_ref=_LARAVEL_REF + "#raw-queries",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="nosqli-request-filter",
        skill=SKILL,
        klass="NoSQL operator injection",
        severity="high",
        stacks=["node", "python"],
        file_globs=_JS + _PY,
        exclude_globs=_TESTS + _LIBS,
        pattern="check_nosqli_request_filter",
        message="a MongoDB filter takes a value (or the whole object) straight from the request body or query string",
        why=("Agents write User.findOne({ email: req.body.email, password: req.body.password }); a JSON body can send "
             "an object with a query operator instead of a string, and the filter then matches any user."),
        fp_trap=("Values cast to a string (String(x)), wrapped as { $eq: x }, checked with typeof x === 'string', or "
                 "parsed by a schema (zod, Joi, Pydantic) are safe. req.params values are always strings. exists(), "
                 "remove(), count() and update() count only on a Mongo-looking receiver (a Model, a collection), and "
                 "Sequelize-style { where: ... } options are not Mongo filters. Projects that set sanitizeFilter: true on a "
                 "patched Mongoose (6.13.9, 7.8.9, 8.22.1, 9.1.6 or newer) are skipped; on older releases findings drop to "
                 "medium. express-mongo-sanitize counts only when app.use() mounts it on Express 4; it does not protect "
                 "req.query on Express 5."),
        fix_ref=_SBY + "#nosql-filters",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="cmdi-node-shell",
        skill=SKILL,
        klass="OS command injection",
        severity="critical",
        stacks=["node"],
        file_globs=_JS,
        exclude_globs=_TESTS + _TOOLING + _LIBS,
        pattern="check_cmdi_node",
        message="exec() / execSync() (or spawn with shell: true) runs a command string built from a variable",
        why=("\"Convert this file\" and \"download this URL\" features get built as exec(`ffmpeg -i ${input} ...`); "
             "exec always runs through a shell, so ; and $() in the value run commands."),
        fp_trap=("execFile('ffmpeg', ['-i', input]) and spawn(cmd, [args]) without shell: true never use a shell and "
                 "are safe even with user input in an argument. A fully constant command is not flagged. Severity is "
                 "lower when the file does not look like a request handler."),
        fix_ref=_SBY + "#shell-commands",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="cmdi-python-shell",
        skill=SKILL,
        klass="OS command injection",
        severity="critical",
        stacks=["python", "django", "flask", "fastapi"],
        file_globs=_PY,
        exclude_globs=_TESTS + _LIBS,
        pattern="check_cmdi_python",
        message="os.system() / os.popen() or subprocess with shell=True runs a command built from a variable",
        why=("f-strings make os.system(f'convert {name} ...') and subprocess.run(cmd, shell=True) one-liners, so agents "
             "reach for them in upload and export handlers."),
        fp_trap=("subprocess.run(['convert', name, out]) with a list and no shell=True is safe. A value wrapped in "
                 "shlex.quote() is safe. Constant commands and click / typer command arguments (the operator's own "
                 "input) are not flagged; severity is lower outside request handlers."),
        fix_ref=_PY_REF + "#command-injection",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="cmdi-php-shell",
        skill=SKILL,
        klass="OS command injection",
        severity="critical",
        stacks=["php", "laravel"],
        file_globs=_PHP,
        exclude_globs=_TESTS + _LIBS + ["*.blade.php"],
        pattern="check_cmdi_php",
        message="shell_exec() / exec() / system() / passthru() or backticks run a command built from a variable",
        why="PHP's shell functions take one string; agents interpolate request values into it for image or PDF tools.",
        fp_trap=("A value passed through escapeshellarg() is safe, and constant commands are not flagged. Values checked "
                 "with is_numeric(), ctype_*() or filter_var() first are not flagged. PDO's ->exec() is a method, not the "
                 "shell function, and is not matched. Vendored libraries (libs/, vendor/, a license banner inside lib/) are "
                 "skipped."),
        fix_ref=_SBY + "#shell-commands",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="xss-react-dangerous-html",
        skill=SKILL,
        klass="XSS",
        severity="high",
        stacks=["node", "nextjs", "nextjs-app", "nextjs-pages", "react-vite", "cra", "expo"],
        file_globs=_JS,
        exclude_globs=_TESTS + _LIBS,
        pattern="check_xss_react_html",
        message="dangerouslySetInnerHTML renders a value with no sanitizer",
        why=("Rendering rich text, markdown or a model's answer as HTML is one prop away, and the demo content is "
             "harmless, so agents skip DOMPurify."),
        fp_trap=("A value wrapped in DOMPurify.sanitize() (or assigned from it, also through a useState setter), a fixed "
                 "string or template, an imported constant, a loop over a constant array, JSON.stringify() into a "
                 "JSON-LD script tag, syntax-highlighter output (shiki codeToHtml, hljs, Prism), mermaid.render() SVG "
                 "(unless securityLevel is loose) and marked with a DOMPurify postprocess hook are not flagged. The "
                 "shadcn/ui chart.tsx style tag is skipped, and a lint suppression that gives a reason lowers the finding "
                 "to low, as does a React Email template (mail clients run no scripts; still escape user text there). react-markdown without rehype-raw needs no dangerouslySetInnerHTML at all."),
        fix_ref=_SBY + "#rendering-html",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="xss-framework-raw-html",
        skill=SKILL,
        klass="XSS",
        severity="high",
        stacks=["node", "laravel", "php", "python", "django", "flask", "fastapi"],
        file_globs=["*.vue", "*.svelte", "*.html", "*.htm", "*.ts", "*.js", "*.mjs", "*.cjs", "*.ejs", "*.hbs",
                    "*.handlebars", "*.mustache", "*.pug", "*.jade", "*.njk", "*.twig"],
        exclude_globs=_TESTS + _LIBS,
        pattern="check_xss_framework_html",
        message=("v-html, {@html}, bypassSecurityTrustHtml or a server template's raw tag (EJS <%-, Handlebars {{{, "
                 "Pug !=, |safe / |raw, autoescape off) renders a value with no sanitizer"),
        why=("Vue, Svelte, Angular and the server template engines escape by default; agents opt out with v-html, "
             "{@html}, <%- or {{{ }}} to show rich text or markdown, or turn autoescape off to stop entities showing."),
        fp_trap=("Plain {{ }} / { } / <%= %> interpolation is escaped and never flagged. A value computed through "
                 "DOMPurify or another sanitizer in the component's script (also through a member assignment), or a "
                 "fixed string, is not flagged. EJS include() and layout body are not flagged. Angular's own [innerHTML] "
                 "binding is sanitized by Angular and is not matched. With a server-side purifier in the project, v-html "
                 "on API data is reported at medium."),
        fix_ref=_SBY + "#rendering-html",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="xss-dom-innerhtml",
        skill=SKILL,
        klass="XSS",
        severity="medium",
        stacks=["*"],
        file_globs=_JS + ["*.html", "*.htm", "*.vue", "*.svelte"],
        exclude_globs=_TESTS + _LIBS + _TOOLING + ["docs/**", "doc/**"],
        pattern="check_xss_dom_html",
        message="innerHTML / insertAdjacentHTML / document.write gets data built into HTML with no escaping",
        why=("Building a list with innerHTML = items.map(i => `<li>${i.name}</li>`) is the quickest way to render "
             "fetched data, and nothing escapes i.name."),
        fp_trap=("Assigning a fixed string, clearing with '', values passed through an escape function "
                 "(escapeHtml(x), DOMPurify.sanitize(x)), numbers and lengths, and lookups in an ALL_CAPS constant map "
                 "are not flagged. Unknown helper calls are not flagged, so a helper that escapes internally stays quiet. "
                 "jQuery .html(data.field) in a callback of the app's own $.ajax / $.getJSON is reported as low: servers "
                 "often send fragments they rendered with an escaping template. The docs/ site is not scanned."),
        fix_ref=_SBY + "#rendering-html",
        confidence="low",
        needs_confirmation=True,
    ),
    Rule(
        id="xss-markdown-rehype-raw",
        skill=SKILL,
        klass="XSS",
        severity="high",
        stacks=["node"],
        file_globs=_JS,
        exclude_globs=_TESTS + _LIBS,
        pattern="check_xss_rehype_raw",
        message="react-markdown / unified uses rehype-raw with no rehype-sanitize after it",
        why=("Chat UIs add rehype-raw so the model's HTML renders; react-markdown is safe by default only until that "
             "plugin is added."),
        fp_trap=("react-markdown without rehype-raw is safe and never flagged. rehype-raw followed by rehype-sanitize in "
                 "the same plugin list is safe; sanitize placed before raw is flagged. A sanitizer applied in another "
                 "shared config file needs a manual check."),
        fix_ref=_SBY + "#markdown-and-model-output",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="xss-blade-unescaped",
        skill=SKILL,
        klass="XSS",
        severity="high",
        stacks=["laravel", "php"],
        file_globs=["*.blade.php"],
        exclude_globs=_TESTS,
        pattern="check_xss_blade_raw",
        message="Blade {!! !!} prints a value without escaping",
        why="{!! !!} is how Blade prints HTML, so agents use it for rich text and markdown and sometimes for plain fields.",
        fp_trap=("{{ }} is escaped. {!! !!} around csrf_field(), method_field(), __() / trans() strings, "
                 "route()/url()/asset(), e(...), escape*() helpers, clean()/Purifier::clean(), form builders (Form::, "
                 "Html::, *Form::) and $slot is not flagged. json_encode() is flagged (medium) only outside a <script> "
                 "block, where a quote breaks out of an attribute. A project helper that builds HTML is reported once, low "
                 "when it escapes or renders a view; a markdown helper with html_input 'escape' or 'strip' and "
                 "allow_unsafe_links false is not flagged."),
        fix_ref=_LARAVEL_REF + "#blade-raw-output",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="xss-python-template-safe",
        skill=SKILL,
        klass="XSS",
        severity="high",
        stacks=["python", "django", "flask", "fastapi"],
        file_globs=_PY + ["*.html", "*.htm", "*.jinja", "*.jinja2", "*.j2", "*.djhtml"],
        exclude_globs=_TESTS,
        pattern="check_xss_python_templates",
        message="a Jinja / Django template uses |safe or autoescape off, or code calls mark_safe() / Markup() on a variable",
        why=("|safe and mark_safe() are the one-word fix when HTML shows up escaped, so agents add them to rich text, "
             "markdown output and sometimes user fields."),
        fp_trap=("|tojson|safe, json_script, values sanitized with bleach / nh3, format_html() and Markup('<b>{}</b>')"
                 ".format(x) (which escapes x) are safe. mark_safe() on a fixed string, an escape() result, "
                 "render_to_string() or Literal / int / date-typed values is not flagged. |safe in a plain-text template "
                 "(an email text part, SMS, subject or title template with no HTML tags) and on a {% cycle %} / {% with %} "
                 "constant is not flagged; on a server-made SVG or QR code, or in an HTML email template (an emails/ or "
                 "mail/ folder), it is low."),
        fix_ref=_PY_REF + "#template-xss",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="xss-reflected-response",
        skill=SKILL,
        klass="XSS (reflected)",
        severity="high",
        stacks=["node", "python", "php"],
        file_globs=_JS + _PY + _PHP,
        exclude_globs=_TESTS + _LIBS + _TOOLING,
        pattern="check_xss_reflected",
        message="request input is sent back inside an HTML response without escaping",
        why=("Quick endpoints build HTML with a template string: res.send(`<h1>${req.query.name}</h1>`), a Flask route "
             "returning f\"<p>{name}</p>\", or PHP echo $_GET[...]. Express and Flask send strings as text/html."),
        fp_trap=("Only request input is reported. Values passed through an escape function (escape-html, "
                 "markupsafe.escape, htmlspecialchars), JSON responses (res.json, jsonify, json_encode) and "
                 "render_template() / res.render() with autoescape are safe. PHP HTML built into a variable ($html .= "
                 "'<pre>' . $_GET['x']) that is printed later, maybe by another file, is reported at medium."),
        fix_ref=_SBY + "#rendering-html",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="cmdi-code-eval",
        skill=SKILL,
        klass="code injection",
        severity="critical",
        stacks=["node", "python", "php"],
        file_globs=_JS + _PY + _PHP,
        exclude_globs=_TESTS + _LIBS + _TOOLING,
        pattern="check_code_eval",
        message=("eval() / new Function() / exec(), a template compiled from a string, or an object deserializer "
                 "(pickle, yaml.load, node-serialize, unserialize) runs request input as code"),
        why=("Calculators, formula fields and \"run this snippet\" features get built with eval(req.body.expr); Flask "
             "pages get built with render_template_string(f\"...{name}...\"), which evaluates Jinja in the value. "
             "Import and session features reach for pickle.loads() or unserialize() because they round-trip any object."),
        fp_trap=("Only request input is reported, except node-serialize, yaml.load() without SafeLoader and js-yaml "
                 "load() before version 4: those are reported on any data (medium when the data's source is not traced "
                 "and the file is no request handler) but skipped when they read a file the developer named. PyYAML "
                 "pinned at 5.4 or newer makes a bare yaml.load() safe. eval of a constant, render_template_string() with "
                 "a fixed template and the value passed as a variable, ast.literal_eval(), yaml.safe_load() and pickle of "
                 "the app's own cache files are safe. PHP unserialize() of request data with ['allowed_classes' => false] "
                 "is medium, since the PHP manual still warns against it."),
        fix_ref=_SBY + "#code-evaluation",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="upload-client-filename",
        skill=SKILL,
        klass="file upload path traversal",
        severity="high",
        stacks=["node", "python", "php"],
        file_globs=_JS + _PY + _PHP,
        exclude_globs=_TESTS + _LIBS,
        pattern="check_upload_client_filename",
        message="an upload is written to disk under the file name the client sent",
        why=("multer's filename callback, Flask's file.filename and PHP's $_FILES name are the obvious names to save "
             "under; a name like ../../app.js writes outside the upload folder."),
        fp_trap=("path.basename(), secure_filename(), a random name (uuid, crypto.randomUUID(), random_bytes, "
                 "hashName()) and taking only the extension are safe. Django's storage.save() validates the path. "
                 "Using the original name only for display, a database column, a UI message or a browser-side File / "
                 "Promise is not flagged, and \"use client\" files are skipped. Laravel / Symfony move() keeps only the "
                 "base name, so it is medium (overwrite, client extension), and skipped for a fresh random folder. PHP "
                 "basename() of the client name is still reported when no extension allowlist exists."),
        fix_ref=_SBY + "#server-side-file-names",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="upload-client-mime-check",
        skill=SKILL,
        klass="file upload type check",
        severity="medium",
        stacks=["node", "python", "php"],
        file_globs=_JS + _PY + _PHP,
        exclude_globs=_TESTS + _LIBS,
        pattern="check_upload_client_mime",
        message="upload type is validated only by the Content-Type the client sent",
        why=("multer's fileFilter examples check file.mimetype; that header is set by the client, so an HTML or SVG file "
             "passes as image/png."),
        fp_trap=("A check of the file's bytes (file-type, finfo, getimagesize, Pillow, python-magic) or re-encoding the "
                 "image in the same file makes this safe. If the file is stored under a random name with a fixed "
                 "extension and served with nosniff, the header check is only cosmetic."),
        fix_ref=_SBY + "#validate-by-content",
        confidence="low",
        needs_confirmation=True,
        max_per_file=1,
    ),
    Rule(
        id="upload-no-size-limit",
        skill=SKILL,
        klass="file upload size",
        severity="medium",
        stacks=["node", "flask"],
        file_globs=_JS + _PY,
        exclude_globs=_TESTS + _LIBS,
        pattern="check_upload_no_size_limit",
        message="upload middleware has no file size limit",
        why="multer and express-fileupload accept files of any size by default; Flask has no request size limit until "
            "MAX_CONTENT_LENGTH is set.",
        fp_trap=("A limit enforced by the reverse proxy (nginx client_max_body_size) or the platform also works; check "
                 "the deploy config before reporting. multer({ limits: { fileSize } }) is safe."),
        fix_ref=_SBY + "#size-limits",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="path-traversal-request",
        skill=SKILL,
        klass="path traversal",
        severity="high",
        stacks=["node", "python", "php"],
        file_globs=_JS + _PY + _PHP,
        exclude_globs=_TESTS + _LIBS + _TOOLING,
        pattern="check_path_traversal",
        message="a file is read, written or sent from a path built with request input",
        why=("Download and preview endpoints get written as res.sendFile(path.join(dir, req.query.file)) or "
             "open(os.path.join(DIR, name)); ../ in the value reaches any file."),
        fp_trap=("path.basename(), secure_filename(), send_from_directory(), res.sendFile(name, { root }) and a "
                 "resolve-then-startsWith(root) check are safe, and so are PHP values checked with ctype_*(), is_numeric() "
                 "or an anchored preg_match(). FastAPI / Flask path parameters without the path converter cannot contain "
                 "a slash and are not flagged (they can still hold a backslash, a separator on Windows hosts). PHP "
                 "include of a fixed file is not matched. Archive entry names (zip slip) count only when the file uses "
                 "an archive library; tarfile extractall() is reported only without filter= in a request handler."),
        fix_ref=_SBY + "#file-paths-from-the-request",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="ssrf-request-url",
        skill=SKILL,
        klass="SSRF",
        severity="high",
        stacks=["node", "python", "php"],
        file_globs=_JS + _PY + _PHP,
        exclude_globs=_TESTS + _LIBS + _TOOLING,
        pattern="check_ssrf_request_url",
        message="server code fetches a URL taken from the request with no host allowlist or private-IP check",
        why=("Link previews, \"import from URL\", avatar-by-URL and webhook testers are built as fetch(req.query.url); "
             "the server then reaches cloud metadata and internal services for the caller."),
        fp_trap=("A URL with a fixed host where the request only fills the path or query "
                 "(`https://api.example.com/items/${id}`) is not SSRF and is not flagged, also when the fixed base is an "
                 "ALL_CAPS constant defined in the project; an unresolved base constant is medium. Files that allowlist "
                 "hosts, use an SSRF-filtering agent, or resolve the name and check the address are skipped; a check of "
                 "the host name as text, or an address check with redirects turned on, only lowers the finding to "
                 "medium. Comments and flag names do not count as guards. Browser-side fetch is not SSRF."),
        fix_ref=_SBY + "#server-side-fetch",
        confidence="medium",
        needs_confirmation=True,
    ),
    Rule(
        id="ssrf-next-image-any-host",
        skill=SKILL,
        klass="SSRF / open image proxy",
        severity="medium",
        stacks=["nextjs", "nextjs-app", "nextjs-pages"],
        file_globs=["next.config.js", "next.config.mjs", "next.config.ts", "next.config.cjs"],
        pattern="check_ssrf_next_image",
        message="next/image remotePatterns allows any hostname ('**'), or images.dangerouslyAllowLocalIP is true",
        why=("A wildcard host is the quickest way to stop the 'hostname is not configured' error for user avatars, and "
             "dangerouslyAllowLocalIP is the quickest way past a 400 on a private image host."),
        fp_trap=("A list of exact hosts (and a pathname) is not flagged, but an allowed host that redirects still sends "
                 "the optimizer elsewhere (Next.js 16 follows up to images.maximumRedirects, 3 by default, without "
                 "checking remotePatterns again), so check for open redirects or user uploads on those hosts. With "
                 "images.unoptimized: true or a custom loader the Next.js optimizer does not fetch, so the rule is "
                 "skipped."),
        fix_ref=_NEXT_REF + "#remote-images",
        confidence="high",
        needs_confirmation=False,
    ),
]
