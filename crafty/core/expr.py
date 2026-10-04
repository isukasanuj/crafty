"""Bounded value-expression engine.

This is the deliberate middle ground between the plain packing DSL and the full
scripting escape hatch. It evaluates *pure expressions that compute values* -
arithmetic, slicing, field references, and a fixed library of packing /
crypto / encoding helper functions. It has NO control flow: no statements, no
loops, no assignment, no ``goto``. A ternary (``a if c else b``) is permitted
because it is a pure value expression, not a branch in the program sense.

Why this exists: a checksum over a field, ``sha256(challenge)``, or
``u16be(len(body))`` are among the most common needs when modelling a protocol,
and without this layer every one of them would force a full ``script`` step.
Expressions-for-values keeps the "config stops where programming begins" line
(§ design principles) while removing the most common reasons to reach for Lua.

Safety model: the expression is parsed with :mod:`ast`, every node is checked
against a strict allow-list (no attribute access, no dunder, no lambda, no
comprehension, no import), and only then evaluated with an empty ``__builtins__``
and a namespace of {variables + whitelisted functions}. Because attribute access
is rejected, the usual ``().__class__.__bases__`` sandbox escapes are unavailable.
"""

from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import hmac as _hmac
import os
import random
import socket as _socket
import string
import struct as _struct
import zlib
from typing import Any, Callable, Mapping


class ExprError(ValueError):
    """Raised for a malformed, disallowed, or failed expression."""


# --------------------------------------------------------------------------- #
# Value coercion
# --------------------------------------------------------------------------- #
def as_bytes(value: Any) -> bytes:
    """Coerce an expression result to bytes.

    bytes/bytearray pass through; str is UTF-8 encoded. int is intentionally
    rejected because its byte width is ambiguous - the author must say which
    width via ``u8``/``u16be``/... or ``pack``. This prevents a silent
    "which endianness / how many bytes?" bug on the wire.
    """
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, bool):  # bool is an int subclass; catch before int
        raise ExprError("cannot place a bool on the wire; pack it explicitly")
    if isinstance(value, int):
        raise ExprError(
            "an int has no implicit byte width; wrap it, e.g. u16be(x) or pack('!I', x)"
        )
    raise ExprError(f"cannot convert {type(value).__name__} to bytes")


# --------------------------------------------------------------------------- #
# Helper function library (the crypto / encoding / packing surface)
# --------------------------------------------------------------------------- #
def _crc16_ccitt_false(data: Any) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF, no reflection, xorout 0).

    One concrete, documented CRC-16 variant. Others (MODBUS, XMODEM, ...) differ;
    if a protocol needs a different one, use ``pack`` + a ``script`` step. Being
    explicit here beats shipping an ambiguous ``crc16``.
    """
    b = as_bytes(data)
    crc = 0xFFFF
    for byte in b:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def _pack(fmt: Any, *args: Any) -> bytes:
    if not isinstance(fmt, str):
        raise ExprError("pack(): first argument must be a format string")
    try:
        return _struct.pack(fmt, *args)
    except _struct.error as exc:
        raise ExprError(f"pack({fmt!r}): {exc}") from exc


def _concat(*parts: Any) -> bytes:
    return b"".join(as_bytes(p) for p in parts)


def _make_int_packer(fmt: str) -> Callable[[Any], bytes]:
    def packer(x: Any) -> bytes:
        try:
            return _struct.pack(fmt, int(x))
        except (_struct.error, ValueError, TypeError) as exc:
            raise ExprError(f"integer pack {fmt!r} failed for {x!r}: {exc}") from exc

    return packer


def _digest(algo: str) -> Callable[[Any], bytes]:
    def hasher(x: Any) -> bytes:
        return hashlib.new(algo, as_bytes(x)).digest()

    return hasher


def _hmac_digest(algo: Any, key: Any, msg: Any) -> bytes:
    if not isinstance(algo, str):
        raise ExprError("hmac(): first argument is the algorithm name, e.g. 'sha256'")
    return _hmac.new(as_bytes(key), as_bytes(msg), algo).digest()


def _rand_bytes(n: Any) -> bytes:
    n = int(n)
    if not 0 <= n <= 65536:
        raise ExprError("rand_bytes(): length out of bounds (0..65536)")
    return os.urandom(n)


def _rand_str(n: Any, alphabet: Any = None) -> str:
    n = int(n)
    if not 0 <= n <= 65536:
        raise ExprError("rand_str(): length out of bounds (0..65536)")
    pool = alphabet if isinstance(alphabet, str) and alphabet else (string.ascii_letters + string.digits)
    return "".join(random.choice(pool) for _ in range(n))


FUNCTIONS: dict[str, Callable[..., Any]] = {
    # sizing / refs
    "len": lambda x: len(x),
    "int": lambda x, base=10: int(x, base) if isinstance(x, str) else int(x),
    "str": lambda x: x.decode("utf-8", "replace") if isinstance(x, (bytes, bytearray)) else str(x),
    "bytes": as_bytes,
    # fixed-width integer packers (explicit endianness, no guessing)
    "u8": _make_int_packer("!B"),
    "u16be": _make_int_packer("!H"),
    "u16le": _make_int_packer("<H"),
    "u32be": _make_int_packer("!I"),
    "u32le": _make_int_packer("<I"),
    "u64be": _make_int_packer("!Q"),
    "u64le": _make_int_packer("<Q"),
    "i8": _make_int_packer("!b"),
    "i16be": _make_int_packer("!h"),
    "i16le": _make_int_packer("<h"),
    "i32be": _make_int_packer("!i"),
    "i32le": _make_int_packer("<i"),
    # generic struct packing for anything the shorthands miss
    "pack": _pack,
    "concat": _concat,
    # encoding
    "ip4": lambda s: _socket.inet_aton(s if isinstance(s, str) else s.decode()),
    "hex2b": lambda s: bytes.fromhex(s.replace(" ", "") if isinstance(s, str) else s.decode()),
    "b2hex": lambda b: as_bytes(b).hex(),
    "b64e": lambda b: base64.b64encode(as_bytes(b)),
    "b64d": lambda s: base64.b64decode(s),
    "zlib_c": lambda b: zlib.compress(as_bytes(b)),
    "zlib_d": lambda b: zlib.decompress(as_bytes(b)),
    # checksums / digests
    "crc32": lambda b: binascii.crc32(as_bytes(b)) & 0xFFFFFFFF,
    "crc16": _crc16_ccitt_false,
    "md5": _digest("md5"),
    "sha1": _digest("sha1"),
    "sha256": _digest("sha256"),
    "sha512": _digest("sha512"),
    "hmac": _hmac_digest,
    # randomness
    "rand_bytes": _rand_bytes,
    "rand_str": _rand_str,
    "rand_int": lambda a, b: random.randint(int(a), int(b)),
    # small string helpers
    "upper": lambda s: s.upper(),
    "lower": lambda s: s.lower(),
    "strip": lambda s: s.strip(),
}


# --------------------------------------------------------------------------- #
# AST allow-list
# --------------------------------------------------------------------------- #
_ALLOWED_NODES: tuple[type, ...] = (
    ast.Expression,
    ast.Constant,
    ast.Name,
    ast.Load,
    ast.BinOp,
    ast.UnaryOp,
    ast.BoolOp,
    ast.Compare,
    ast.IfExp,            # pure value ternary, not control flow
    ast.Call,
    ast.Subscript,
    ast.Slice,
    ast.Tuple,
    ast.List,
    # operators
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.BitAnd, ast.BitOr, ast.BitXor, ast.LShift, ast.RShift,
    ast.USub, ast.UAdd, ast.Invert, ast.Not,
    ast.And, ast.Or,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE,
)


def _validate(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if not isinstance(node, _ALLOWED_NODES):
            raise ExprError(
                f"disallowed syntax in expression: {type(node).__name__} "
                "(no attribute access, assignment, loops, lambdas, or imports)"
            )
        # A Call may only target a bare name that is a known function.
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                raise ExprError("only direct calls to named helper functions are allowed")
            if node.func.id not in FUNCTIONS:
                raise ExprError(f"unknown function: {node.func.id}()")
            if any(kw.arg is None for kw in node.keywords):
                raise ExprError("**kwargs expansion is not allowed")


def evaluate(expression: str, variables: Mapping[str, Any] | None = None) -> Any:
    """Evaluate a bounded expression and return its value (any type)."""
    variables = variables or {}
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError as exc:
        raise ExprError(f"syntax error in expression {expression!r}: {exc.msg}") from exc
    _validate(tree)

    # Names resolve to variables; function names resolve from FUNCTIONS. A name
    # that is neither is a clear, early error rather than a NameError surprise.
    namespace: dict[str, Any] = {}
    namespace.update(FUNCTIONS)
    namespace.update(variables)  # variables win over function names if they collide

    code = compile(tree, "<crafty-expr>", "eval")
    try:
        return eval(code, {"__builtins__": {}}, namespace)  # noqa: S307 - sandboxed by AST allow-list
    except ExprError:
        raise
    except Exception as exc:  # pragma: no cover - surfaced to the author
        raise ExprError(f"error evaluating {expression!r}: {exc}") from exc


def evaluate_bytes(expression: str, variables: Mapping[str, Any] | None = None) -> bytes:
    """Evaluate and coerce to bytes (for ``bytes:`` field contexts)."""
    return as_bytes(evaluate(expression, variables))
