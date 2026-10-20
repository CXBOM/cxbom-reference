"""Strict JSON parsing that keeps raw byte spans and number lexemes.

Owner: ATACE Working Group.

The proxy must decide on exactly the bytes a client will parse. It must also
re-emit the elements it keeps byte-for-byte when it removes blocked items. The
stdlib parser gives neither of those. It also keeps duplicate keys (last wins)
and accepts NaN. Both are parser differentials an attacker can use (premortem
A3, B3).
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass

MAX_DEPTH = 128
_WS = frozenset(b" \t\n\r")
_NUM = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")


class StrictJSONError(ValueError):
    """Input is not strict, finite, duplicate-free UTF-8 JSON."""


@dataclass(frozen=True)
class Node:
    kind: str                 # object, array, string, number, true, false, null
    start: int
    end: int
    value: object = None
    items: tuple = ()

    def get(self, key: str) -> "Node | None":
        if self.kind != "object":
            return None
        for k, _knode, vnode in self.items:
            if k == key:
                return vnode
        return None


def parse(data: bytes, max_bytes: int = 64 * 1024 * 1024) -> Node:
    """Parse strict JSON from bytes.

    Raises:
        StrictJSONError: data is not bytes, is too large, is not UTF-8, or is
            not strict, finite, duplicate-free JSON.
    """
    if type(data) is not bytes:
        # A str would parse fine but its byte spans would not be the wire
        # bytes, and a bytearray can change under the parser.
        raise StrictJSONError(f"parse() needs bytes, got {type(data).__name__}")
    if len(data) > max_bytes:
        raise StrictJSONError(f"message of {len(data)} bytes exceeds {max_bytes}")
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as e:
        raise StrictJSONError(f"invalid UTF-8 at byte {e.start}") from None
    try:
        p = _Parser(data)
        p.ws()
        node = p.value(0)
        p.ws()
        if p.i != len(data):
            p.fail("trailing data")
        return node
    except RecursionError:
        raise StrictJSONError("nesting too deep") from None


def to_python(node: Node) -> object:
    if node.kind == "object":
        return {k: to_python(v) for k, _kn, v in node.items}
    if node.kind == "array":
        return [to_python(v) for v in node.items]
    if node.kind == "number":
        lex = node.value
        return float(lex) if any(c in lex for c in ".eE") else int(lex)
    return node.value


class _Parser:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0
        self.n = len(data)

    def fail(self, msg: str) -> None:
        raise StrictJSONError(f"{msg} at byte {self.i}")

    def ws(self) -> None:
        d, i, n = self.d, self.i, self.n
        while i < n and d[i] in _WS:
            i += 1
        self.i = i

    def value(self, depth: int) -> Node:
        if depth >= MAX_DEPTH:
            self.fail("nesting too deep")
        if self.i >= self.n:
            self.fail("unexpected end of input")
        c = self.d[self.i]
        if c == 0x7B:
            return self.obj(depth)
        if c == 0x5B:
            return self.arr(depth)
        if c == 0x22:
            return self.string()
        if c == 0x74:
            return self.lit(b"true", "true", True)
        if c == 0x66:
            return self.lit(b"false", "false", False)
        if c == 0x6E:
            return self.lit(b"null", "null", None)
        if c == 0x2D or 0x30 <= c <= 0x39:
            return self.number()
        self.fail("unexpected byte")
        raise AssertionError("unreachable")

    def lit(self, word: bytes, kind: str, val: object) -> Node:
        if self.d[self.i:self.i + len(word)] != word:
            self.fail("invalid literal")
        s = self.i
        self.i += len(word)
        return Node(kind, s, self.i, val)

    def number(self) -> Node:
        m = _NUM.match(self.d, self.i)
        if not m:
            self.fail("invalid number")
        lex = m.group(0).decode("ascii")
        if len(lex) > 400:
            self.fail("number too long")
        if any(ch in lex for ch in ".eE") and not math.isfinite(float(lex)):
            self.fail("non-finite number")
        s = self.i
        self.i = m.end()
        return Node("number", s, self.i, lex)

    def string(self) -> Node:
        d, n = self.d, self.n
        s = self.i
        i = s + 1
        while True:
            if i >= n:
                self.i = i
                self.fail("unterminated string")
            c = d[i]
            if c == 0x22:
                break
            if c == 0x5C:
                i += 2
                continue
            if c < 0x20:
                self.i = i
                self.fail("control character in string")
            i += 1
        e = i + 1
        try:
            val = json.loads(d[s:e])
        except json.JSONDecodeError as ex:
            self.i = s
            self.fail(f"invalid string ({ex.msg})")
        try:
            val.encode("utf-8")
        except UnicodeEncodeError:
            self.i = s
            self.fail("lone surrogate in string")
        self.i = e
        return Node("string", s, e, val)

    def obj(self, depth: int) -> Node:
        s = self.i
        self.i += 1
        pairs = []
        seen: set[str] = set()
        self.ws()
        if self.i < self.n and self.d[self.i] == 0x7D:
            self.i += 1
            return Node("object", s, self.i, None, ())
        while True:
            self.ws()
            if self.i >= self.n or self.d[self.i] != 0x22:
                self.fail("expected string key")
            k = self.string()
            if k.value in seen:
                self.fail(f"duplicate key {k.value!r}")
            seen.add(k.value)
            self.ws()
            if self.i >= self.n or self.d[self.i] != 0x3A:
                self.fail("expected ':'")
            self.i += 1
            self.ws()
            v = self.value(depth + 1)
            pairs.append((k.value, k, v))
            self.ws()
            if self.i >= self.n:
                self.fail("unterminated object")
            c = self.d[self.i]
            if c == 0x2C:
                self.i += 1
                continue
            if c == 0x7D:
                self.i += 1
                return Node("object", s, self.i, None, tuple(pairs))
            self.fail("expected ',' or '}'")

    def arr(self, depth: int) -> Node:
        s = self.i
        self.i += 1
        items = []
        self.ws()
        if self.i < self.n and self.d[self.i] == 0x5D:
            self.i += 1
            return Node("array", s, self.i, None, ())
        while True:
            self.ws()
            items.append(self.value(depth + 1))
            self.ws()
            if self.i >= self.n:
                self.fail("unterminated array")
            c = self.d[self.i]
            if c == 0x2C:
                self.i += 1
                continue
            if c == 0x5D:
                self.i += 1
                return Node("array", s, self.i, None, tuple(items))
            self.fail("expected ',' or ']'")
