"""The binary-packing DSL resolver for ``bytes:`` fields.

A ``bytes:`` value is a string mixing literal bytes with ``{{ ... }}`` placeholders.
Everything below compiles down to the same two primitives - the bounded
expression engine (:mod:`crafty.core.expr`) and the bidirectional struct layer
(:mod:`crafty.core.structs`) - so the shorthand and the full expression form are
always equivalent and both round-trip.

Literals
    ``\\xNN`` hex byte, plus ``\\n \\r \\t \\0 \\\\``.

Placeholders
    ``{{= EXPR }}``            evaluate a bounded expression -> bytes
    ``{{hex:504b0304}}``       hex literal
    ``{{u16be:EXPR}}`` ...     fixed-width int (u8/u16be/u16le/u32be/u32le/u64..)
    ``{{len16be:field}}`` ...  length prefix of a field's bytes (len8/16/32, be/le)
    ``{{bytes:var}}``          insert a captured/extracted value as bytes
    ``{{str:EXPR}}``           insert a string (UTF-8)
    ``{{randstr:8}}`` ``{{randbytes:16}}``   randomised inputs
    ``{{pack:"!IH", a, b}}``   struct-style packing
    ``{{struct:Name(f=EXPR, ...)}}``   build bytes from a defined struct
    ``{{var}}``                a bare name/expression -> bytes

Anything more structured (nested TLV, ASN.1, conditional assembly) is a
``script`` step, not a bigger DSL - that boundary is deliberate.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from . import expr
from .expr import ExprError, as_bytes
from .structs import StructRegistry

_PLACEHOLDER = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)

_LEN_PACKERS = {
    "len8": "u8",
    "len16be": "u16be", "len16le": "u16le",
    "len32be": "u32be", "len32le": "u32le",
    "len64be": "u64be", "len64le": "u64le",
}

_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\x00", "\\": "\\", '"': '"', "'": "'"}

# Ergonomic prefix spellings that map to expression function names.
_PREFIX_ALIASES = {"randbytes": "rand_bytes", "randstr": "rand_str", "randint": "rand_int"}


class DSLError(ValueError):
    """Raised for a malformed placeholder or a resolution failure."""


@dataclass
class Context:
    """Everything a ``bytes:`` resolution needs: the live variables and structs."""

    variables: dict[str, Any] = field(default_factory=dict)
    structs: StructRegistry = field(default_factory=StructRegistry)


def _unescape_literal(text: str) -> bytes:
    out = bytearray()
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            if nxt == "x" and i + 4 <= len(text):
                try:
                    out.append(int(text[i + 2: i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            if nxt in _ESCAPES:
                out += _ESCAPES[nxt].encode("latin-1")
                i += 2
                continue
        out += c.encode("utf-8")
        i += 1
    return bytes(out)


def _resolve_struct(spec: str, ctx: Context) -> bytes:
    """Resolve ``Name(field=EXPR, ...)`` against the struct registry."""
    try:
        tree = ast.parse(spec.strip(), mode="eval")
    except SyntaxError as exc:
        raise DSLError(f"struct placeholder must look like Name(f=EXPR, ...): {exc.msg}") from exc
    call = tree.body
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name):
        raise DSLError("struct placeholder must look like Name(f=EXPR, ...)")
    if call.args or any(kw.arg is None for kw in call.keywords):
        raise DSLError("struct fields must be keyword arguments: Name(f=EXPR, ...)")
    name = call.func.id
    values: dict[str, Any] = {}
    for kw in call.keywords:
        values[kw.arg] = expr.evaluate(ast.unparse(kw.value), ctx.variables)
    return ctx.structs.get(name).pack(values, ctx.variables)


def _resolve_placeholder(body: str, ctx: Context) -> bytes:
    body = body.strip()
    if not body:
        raise DSLError("empty placeholder {{}}")

    # {{= EXPR}}
    if body.startswith("="):
        return expr.evaluate_bytes(body[1:].strip(), ctx.variables)

    head, sep, rest = body.partition(":")
    head = head.strip()
    rest = rest.strip()

    if sep:
        if head == "hex":
            try:
                return bytes.fromhex(rest.replace(" ", ""))
            except ValueError as exc:
                raise DSLError(f"bad hex literal {rest!r}: {exc}") from exc
        if head == "struct":
            return _resolve_struct(rest, ctx)
        if head == "pack":
            return expr.evaluate_bytes(f"pack({rest})", ctx.variables)
        if head == "bytes":
            return as_bytes(expr.evaluate(rest, ctx.variables))
        if head == "str":
            v = expr.evaluate(rest, ctx.variables)
            return (v if isinstance(v, str) else str(v)).encode("utf-8")
        fn = _PREFIX_ALIASES.get(head, head)
        if fn in expr.FUNCTIONS:  # u16be, randbytes, etc. as prefixes
            return expr.evaluate_bytes(f"{fn}({rest})", ctx.variables)
        if head in _LEN_PACKERS:
            return expr.evaluate_bytes(f"{_LEN_PACKERS[head]}(len({rest}))", ctx.variables)
        raise DSLError(f"unknown placeholder prefix {head!r}")

    # No colon: a bare name or a whole expression.
    return expr.evaluate_bytes(body, ctx.variables)


def resolve(template: Any, ctx: Context | None = None) -> bytes:
    """Resolve a ``bytes:`` template string (or raw bytes) to concrete bytes."""
    if isinstance(template, (bytes, bytearray)):
        return bytes(template)
    if not isinstance(template, str):
        raise DSLError(f"bytes field must be a string or bytes, got {type(template).__name__}")
    ctx = ctx or Context()

    out = bytearray()
    pos = 0
    for m in _PLACEHOLDER.finditer(template):
        out += _unescape_literal(template[pos:m.start()])
        try:
            out += _resolve_placeholder(m.group(1), ctx)
        except (ExprError,) as exc:
            raise DSLError(f"in {{{{{m.group(1).strip()}}}}}: {exc}") from exc
        pos = m.end()
    out += _unescape_literal(template[pos:])
    return bytes(out)
