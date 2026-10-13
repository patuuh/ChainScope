"""A small structural parser for Move, and the detectors built on it.

Why this exists rather than more regexes. `cs_move` needed four precision
iterations on M1 and four on M3 before they behaved, and each failure was the same
mistake: a regex that matched text instead of structure. It could not tell a
function *boundary* (so it credited a `dynamic_field::add` to the wrong function),
could not read a *parameter type* (so `TreasuryCapHolder<BLUE>` was invisible to a
pattern looking for `&mut`), and could not see that Move's `init` is private.

Three failure modes, one cause. This parses enough of the language to stop all
three:

  * `tokenize` strips comments and string/byte-string literals, so a brace or a
    keyword inside a string cannot shift the parse.
  * `parse_functions` brace-matches from the `fun` keyword, so bodies are exact.
  * parameters and return types are captured as structured values, so a detector
    can ask "does this take `&mut TreasuryCapHolder`" rather than "does this line
    contain the word cap".

Scope is deliberately the subset the detectors need - functions, their
modifiers/visibility, `acquires`, parameters with types, and the return type. It is
not a full type checker and does not try to be; Move's own verifier is what
guarantees the resource-safety properties these detectors assume.
"""

from __future__ import annotations

import re
import typing as t
from dataclasses import dataclass, field

__all__ = [
    "Token",
    "Param",
    "MoveFunction",
    "tokenize",
    "parse_functions",
    "parse_module",
    "iter_functions",
]

# ---------------------------------------------------------------- tokenizer

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUM = re.compile(r"[0-9][0-9a-fA-FxX_]*")

KEYWORDS = frozenset({
    "module", "public", "entry", "fun", "struct", "use", "const", "let", "if",
    "else", "while", "return", "move", "copy", "borrow", "borrow_mut", "mut",
    "acquires", "signer", "native", "friend", "package", "macro", "vector",
    "spec", "abort", "loop", "true", "false", "as", "phantom", "key", "store",
    "drop", "copy_", "const_",
})


@dataclass(frozen=True)
class Token:
    kind: str  # ident | number | string | punct | eof
    value: str
    line: int
    col: int = 0


def tokenize(src: str) -> list[Token]:
    """Lex Move source into tokens, discarding comments and literals' contents.

    Comments and string bodies are dropped entirely: a `}` inside a `b"..."` or a
    `fun` inside a `//` comment must not be able to alter brace matching. String
    tokens are kept as a single opaque token so detectors can still mention them.
    """
    out: list[Token] = []
    i, line, col, n = 0, 1, 0, len(src)

    while i < n:
        ch = src[i]
        # line comment
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            while i < n and src[i] != "\n":
                i += 1
            continue
        # block comment (Move supports nested ones)
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if src.startswith("/*", i):
                    depth += 1
                    i += 2
                elif src.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            continue
        # byte string / hex string, optionally prefixed (b"", x"")
        if ch in "bx" and i + 1 < n and src[i + 1] == '"':
            start_line = line
            j = src.find('"', i + 2)
            if j == -1:
                break
            body = src[i + 2 : j]
            out.append(Token("string", body, start_line, col))
            line += src.count("\n", i, j)
            i = j + 1
            continue
        if ch == '"':
            start_line = line
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == '"':
                    break
                j += 1
            out.append(Token("string", src[i + 1 : j], start_line, col))
            line += src.count("\n", i, min(j + 1, n))
            i = j + 1
            continue
        if ch == "\n":
            line += 1
            col = 0
            i += 1
            continue
        if ch.isspace():
            i += 1
            col += 1
            continue
        # identifier / keyword
        m = _IDENT.match(src, i)
        if m:
            word = m.group(0)
            out.append(
                Token("keyword" if word in KEYWORDS else "ident", word, line, col)
            )
            col += len(word)
            i = m.end()
            continue
        # number
        m = _NUM.match(src, i)
        if m:
            digits = m.group(0)
            out.append(Token("number", digits, line, col))
            col += len(digits)
            i = m.end()
            continue
        # punctuation, longest-match for the two-char forms Move uses
        two = src[i : i + 2]
        if two in ("::", "->", "=>", "==", "!=", "<=", ">=", "&&", "||", "<<", ">>"):
            out.append(Token("punct", two, line, col))
            col += 2
            i += 2
            continue
        out.append(Token("punct", ch, line, col))
        col += 1
        i += 1

    out.append(Token("eof", "", line, col))
    return out


# ------------------------------------------------------------------- parser


@dataclass
class Param:
    name: str
    type: str
    is_ref: bool = False
    is_mut_ref: bool = False


@dataclass
class MoveFunction:
    name: str
    line: int
    visibility: str = "private"       # public | public(package) | public(friend) | private
    is_entry: bool = False
    is_native: bool = False
    acquires: list[str] = field(default_factory=list)
    params: list[Param] = field(default_factory=list)
    ret_type: str | None = None
    body: str = ""

    def param_types(self) -> list[str]:
        return [p.type for p in self.params]

    def has_param_type(self, needle: str) -> bool:
        return any(needle in p.type for p in self.params)

    @property
    def is_public(self) -> bool:
        return self.visibility != "private"


def _render(tokens: list[Token], src: str) -> str:
    """Best-effort source text for a token span, used for pattern search in bodies."""
    if not tokens:
        return ""
    first, last = tokens[0], tokens[-1]
    starts = [0]
    for ln in range(1, first.line):
        starts.append(src.split("\n", ln)[0].__len__())  # placeholder, unused
    # simple: re-scan the source using line/col of the first token
    lines = src.split("\n")
    start_off = sum(len(l) + 1 for l in lines[: first.line - 1]) + first.col
    end_off = sum(len(l) + 1 for l in lines[: last.line - 1]) + last.col + len(last.value)
    return src[start_off:end_off]


def parse_functions(src: str) -> list[MoveFunction]:
    """Parse every `fun` in a Move source file."""
    toks = tokenize(src)
    funs: list[MoveFunction] = []
    i, n = 0, len(toks)

    while i < n:
        if toks[i].kind == "keyword" and toks[i].value == "fun":
            fn, i = _parse_one(toks, i, src)
            if fn is not None:
                funs.append(fn)
            continue
        i += 1
    return funs


def _parse_one(toks: list[Token], i: int, src: str) -> tuple[MoveFunction | None, int]:
    fn = MoveFunction(name="", line=toks[i].line)
    j = i + 1

    # `fun name<T>(...)`
    if j < len(toks) and toks[j].kind in ("ident", "keyword"):
        fn.name = toks[j].value
        j += 1
    while j < len(toks) and not (toks[j].kind == "punct" and toks[j].value == "("):
        j += 1
        if toks[j].kind == "eof":
            return None, j

    # parameters
    params_start = j
    depth = 0
    while j < len(toks) and toks[j].kind != "eof":
        if toks[j].kind == "punct" and toks[j].value == "(":
            depth += 1
        elif toks[j].kind == "punct" and toks[j].value == ")":
            depth -= 1
            if depth == 0:
                break
        j += 1
    param_toks = toks[params_start + 1 : j]
    fn.params = _parse_params(param_toks)

    # return type: `:` token until `{` or `;` (spec / native fun)
    j += 1
    if j < len(toks) and toks[j].kind == "punct" and toks[j].value == ":":
        ret_start = j + 1
        while (
            j < len(toks)
            and toks[j].kind != "eof"
            and not (toks[j].kind == "punct" and toks[j].value in ("{", ";"))
        ):
            j += 1
        fn.ret_type = " ".join(t.value for t in toks[ret_start:j]) or None
    fn.is_native = fn.ret_type is None and (
        j < len(toks) and toks[j].kind == "punct" and toks[j].value == ";"
    )

    # acquires clause
    while j < len(toks) and toks[j].kind != "eof":
        if toks[j].kind == "keyword" and toks[j].value == "acquires":
            k = j + 1
            while k < len(toks) and toks[k].kind == "ident":
                fn.acquires.append(toks[k].value)
                k += 1
                if k < len(toks) and toks[k].kind == "punct" and toks[k].value == ",":
                    k += 1
                    continue
                break
            j = k
        break

    # body
    if j < len(toks) and toks[j].kind == "punct" and toks[j].value == "{":
        depth, start = 0, j
        while j < len(toks) and toks[j].kind != "eof":
            if toks[j].kind == "punct" and toks[j].value == "{":
                depth += 1
            elif toks[j].kind == "punct" and toks[j].value == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        fn.body = _render(toks[start : j + 1], src)
        j += 1

    return fn, j


def _parse_params(toks: list[Token]) -> list[Param]:
    """Split a parameter token run into (name, type) pairs.

    Handles the forms that matter: `a: u64`, `a: &T`, `a: &mut T`,
    `a: vector<u8>`, `a: &mut Package`.
    """
    params: list[Param] = []
    groups: list[list[Token]] = []
    cur: list[Token] = []
    depth = 0
    for t in toks:
        if t.kind == "punct" and t.value in ("<", "(", "["):
            depth += 1
        elif t.kind == "punct" and t.value in (">", ")", "]"):
            depth -= 1
        if t.kind == "punct" and t.value == "," and depth == 0:
            groups.append(cur)
            cur = []
            continue
        cur.append(t)
    if cur:
        groups.append(cur)

    for g in groups:
        if not g:
            continue
        colon = next(
            (k for k, t in enumerate(g) if t.kind == "punct" and t.value == ":"), None
        )
        if colon is None:
            continue
        name = g[0].value if g else ""
        type_toks = g[colon + 1 :]
        type_str = _render(type_toks, "") or " ".join(t.value for t in type_toks)
        # _render needs src; fall back to the joined tokens, which is exact enough
        # for type matching (we only ever test for a substring).
        params.append(
            Param(
                name=name,
                type=type_str.strip(),
                is_ref=bool(type_toks and type_toks[0].value == "&"),
                is_mut_ref=bool(
                    len(type_toks) > 1
                    and type_toks[0].value == "&"
                    and type_toks[1].value == "mut"
                ),
            )
        )
    return params


# ------------------------------------------------------- modifiers (visibility)

_VIS_RE = re.compile(
    r"\bpublic(?:\s*\((?P<vis>package|friend)\))?\b"
)
_MOD_LINE = re.compile(
    r"^\s*(?:(?P<vis>public(?:\s*\((?P<vis_kind>package|friend)\))?)|entry)"
    r"(?:\s+(?:public(?:\s*\((?P<vis2>package|friend)\))?))*"
    r"(?:\s+entry)*\s*$"
)
# No trailing \b after the optional group: at `public(package)` a trailing \b
# would match between `public` and `(`, so the group never engaged and every
# qualified visibility collapsed to `public`.
_MOD_INLINE = re.compile(r"\bentry\b|\bpublic(?:\s*\((?P<vis>package|friend)\))?")


def parse_module(src: str) -> list[MoveFunction]:
    """Parse functions and attach their visibility / entry modifiers.

    Modifiers appear in two places and both are common:

        public entry fun f() { }        <- same line as `fun` (dominant style)
        #[test_only]
        public(package) fun g() { }      <- above, stacked

    Only scanning the line above missed every same-line modifier, which is why
    everything parsed as private.
    """
    funs = parse_functions(src)
    lines = src.split("\n")
    for fn in funs:
        # 1. same-line modifiers: text before the `fun` keyword on this line
        line = lines[fn.line - 1] if 0 < fn.line <= len(lines) else ""
        head = line.split("fun", 1)[0] if "fun" in line else ""
        if head:
            for m in _MOD_INLINE.finditer(head):
                if m.group(0).startswith("public"):
                    vis = m.group("vis")
                    fn.visibility = f"public({vis})" if vis else "public"
                elif m.group(0) == "entry":
                    fn.is_entry = True
        # 2. modifiers stacked on the lines above
        idx = fn.line - 2
        while idx >= 0:
            stripped = lines[idx].strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("#["):
                idx -= 1
                continue
            m = _MOD_LINE.match(lines[idx])
            if not m:
                break
            vis = m.group("vis") or m.group("vis2")
            if vis:
                fn.visibility = f"public({vis})"
            elif m.group("vis"):
                fn.visibility = "public"
            if "entry" in lines[idx]:
                fn.is_entry = True
            idx -= 1
    return funs


def iter_functions(src: str) -> list[MoveFunction]:
    """Alias for parse_module, kept for readability at call sites."""
    return parse_module(src)