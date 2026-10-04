"""Bidirectional binary structs: define a message layout once, use it in both
directions.

This is the feature that moves a large part of the "hard 20%" of protocol work
out of the scripting escape hatch and back into the declarative grammar. The
plain DSL only *packs* bytes going out; real protocols also need to *parse*
structured responses - slice a field at a computed offset, follow a length
prefix, read a length-delimited body. A single ``StructDef`` does both:

    structs:
      Greeting:
        - { name: magic,   type: bytes, len: 4 }
        - { name: version, type: u16be }
        - { name: length,  type: u16be, value: "len(body)" }   # computed on pack
        - { name: body,    type: bytes, len: "length" }        # length ref on parse

    pack:  Greeting.pack({magic: b"CRFT", version: 1, body: b"hello"})
    parse: Greeting.parse(raw) -> {magic, version, length, body}

Design is deliberately a focused subset (the shapes that actually recur on the
wire), not a general grammar. Nested TLV / ASN.1 still belong in a ``script``
step; the struct layer is for fixed fields, fixed-width integers, and
length-delimited byte/string fields where the length is an earlier field.
"""

from __future__ import annotations

import struct as _struct
from dataclasses import dataclass
from typing import Any, Mapping

from .expr import ExprError, as_bytes, evaluate

# fmt: name -> (struct format, byte width)
_INT_FORMATS: dict[str, tuple[str, int]] = {
    "u8": ("!B", 1), "i8": ("!b", 1),
    "u16be": ("!H", 2), "u16le": ("<H", 2), "i16be": ("!h", 2), "i16le": ("<h", 2),
    "u32be": ("!I", 4), "u32le": ("<I", 4), "i32be": ("!i", 4), "i32le": ("<i", 4),
    "u64be": ("!Q", 8), "u64le": ("<Q", 8), "i64be": ("!q", 8), "i64le": ("<q", 8),
}


class StructError(ValueError):
    """Raised for a malformed struct definition or a pack/parse failure."""


@dataclass
class Field:
    name: str
    type: str                       # an int type, "bytes", "str", or "rest"
    length: Any = None              # int | expr-string (for bytes/str)
    value: Any = None               # expr-string computed at pack time (optional)
    encoding: str = "utf-8"         # for str fields

    def is_int(self) -> bool:
        return self.type in _INT_FORMATS


class StructDef:
    """A named, symmetric binary layout."""

    def __init__(self, name: str, fields: list[Field]):
        self.name = name
        self.fields = fields
        self._validate()

    # ------------------------------------------------------------------ #
    @classmethod
    def from_spec(cls, name: str, spec: list[Mapping[str, Any]]) -> "StructDef":
        if not isinstance(spec, list):
            raise StructError(f"struct {name!r}: fields must be a list")
        fields: list[Field] = []
        for i, raw in enumerate(spec):
            if not isinstance(raw, Mapping) or "name" not in raw or "type" not in raw:
                raise StructError(f"struct {name!r} field #{i}: needs 'name' and 'type'")
            fields.append(
                Field(
                    name=str(raw["name"]),
                    type=str(raw["type"]),
                    length=raw.get("len", raw.get("length")),
                    value=raw.get("value"),
                    encoding=str(raw.get("encoding", "utf-8")),
                )
            )
        return cls(name, fields)

    def _validate(self) -> None:
        seen: set[str] = set()
        for f in self.fields:
            if f.name in seen:
                raise StructError(f"struct {self.name!r}: duplicate field {f.name!r}")
            seen.add(f.name)
            if not (f.is_int() or f.type in ("bytes", "str", "rest")):
                raise StructError(f"struct {self.name!r}: unknown field type {f.type!r}")
            if f.type in ("bytes", "str") and f.length is None:
                raise StructError(
                    f"struct {self.name!r} field {f.name!r}: '{f.type}' needs a 'len'"
                )

    # ------------------------------------------------------------------ #
    def pack(self, values: Mapping[str, Any], variables: Mapping[str, Any] | None = None) -> bytes:
        """Serialise field values to bytes. Fields with a ``value:`` expression
        are computed from the other fields (and ``variables``), so length
        prefixes write themselves."""
        ctx: dict[str, Any] = dict(variables or {})
        ctx.update(values)
        out = bytearray()
        for f in self.fields:
            if f.value is not None:
                v = evaluate(str(f.value), ctx)
                ctx[f.name] = v  # make computed value visible to later fields
            elif f.name in values:
                v = values[f.name]
            else:
                raise StructError(f"struct {self.name!r}: missing value for field {f.name!r}")

            if f.is_int():
                fmt, _ = _INT_FORMATS[f.type]
                try:
                    out += _struct.pack(fmt, int(v))
                except (_struct.error, ValueError, TypeError) as exc:
                    raise StructError(f"struct {self.name!r} field {f.name!r}: {exc}") from exc
            elif f.type == "rest":
                out += as_bytes(v)
            else:  # bytes / str
                data = v.encode(f.encoding) if (f.type == "str" and isinstance(v, str)) else as_bytes(v)
                n = self._resolve_len(f, ctx)
                if n is not None and len(data) != n:
                    raise StructError(
                        f"struct {self.name!r} field {f.name!r}: expected {n} bytes, got {len(data)}"
                    )
                out += data
            ctx[f.name] = v  # expose this field's value to later fields' expressions
        return bytes(out)

    def parse(self, data: bytes, variables: Mapping[str, Any] | None = None) -> tuple[dict[str, Any], int]:
        """Deserialise bytes to a dict of field values. Returns (values, bytes_consumed).

        Lengths given as expressions are resolved against already-parsed fields,
        which is exactly how length-prefixed framing is read."""
        ctx: dict[str, Any] = dict(variables or {})
        values: dict[str, Any] = {}
        off = 0
        for f in self.fields:
            if f.is_int():
                fmt, width = _INT_FORMATS[f.type]
                if off + width > len(data):
                    raise StructError(
                        f"struct {self.name!r} field {f.name!r}: need {width} bytes at offset {off}, "
                        f"only {len(data) - off} left"
                    )
                (v,) = _struct.unpack(fmt, data[off:off + width])
                off += width
            elif f.type == "rest":
                v = data[off:]
                off = len(data)
            else:  # bytes / str
                n = self._resolve_len(f, {**ctx, **values})
                if n is None:
                    raise StructError(f"struct {self.name!r} field {f.name!r}: unresolved length on parse")
                if off + n > len(data):
                    raise StructError(
                        f"struct {self.name!r} field {f.name!r}: need {n} bytes at offset {off}, "
                        f"only {len(data) - off} left"
                    )
                chunk = data[off:off + n]
                off += n
                v = chunk.decode(f.encoding, "replace") if f.type == "str" else chunk
            values[f.name] = v
            ctx[f.name] = v
        return values, off

    # ------------------------------------------------------------------ #
    def _resolve_len(self, f: Field, ctx: Mapping[str, Any]) -> int | None:
        if f.length is None:
            return None
        if isinstance(f.length, int):
            return f.length
        try:
            n = evaluate(str(f.length), ctx)
        except ExprError as exc:
            raise StructError(f"struct {self.name!r} field {f.name!r}: bad len expression: {exc}") from exc
        if not isinstance(n, int):
            raise StructError(f"struct {self.name!r} field {f.name!r}: len must be an int, got {type(n).__name__}")
        return n


class StructRegistry:
    """Named structs available to a template/session."""

    def __init__(self) -> None:
        self._defs: dict[str, StructDef] = {}

    @classmethod
    def from_spec(cls, spec: Mapping[str, Any] | None) -> "StructRegistry":
        reg = cls()
        for name, fields in (spec or {}).items():
            reg._defs[name] = StructDef.from_spec(name, fields)
        return reg

    def __contains__(self, name: str) -> bool:
        return name in self._defs

    def get(self, name: str) -> StructDef:
        if name not in self._defs:
            raise StructError(f"unknown struct {name!r}")
        return self._defs[name]

    def names(self) -> list[str]:
        return list(self._defs)
