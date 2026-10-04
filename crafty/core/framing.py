"""Message framing for stream (TCP) reads.

Most binary TCP protocols are length-prefixed or delimiter-framed streams. A
``framing:`` block lets the recv loop read exactly one message without the author
hand-coding "read 4 bytes -> interpret length -> read N more". This is something
Nuclei's network type cannot express and it covers a large swath of real
services declaratively.

Supported forms::

    framing: { type: fixed, size: 1024 }

    framing:
      type: length-prefix
      offset: 0          # bytes before the length field (a fixed pre-header)
      size: 4            # width of the length field in bytes
      endian: be         # be | le
      counts: body       # body  -> length value = bytes AFTER the header
                         # total -> length value = whole message incl. header
      adjust: 0          # added to the computed body length

    framing: { type: delimiter, delimiter: "\r\n", include: true }

The reader is socket-agnostic: it is driven by a ``recv(n)`` callable returning
up to *n* bytes (``b""`` on EOF), so it is unit-testable without a real socket.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

DEFAULT_MAX_MESSAGE = 10 * 1024 * 1024  # hard cap: bounded by default


class FramingError(ValueError):
    """Raised for a malformed framing config or a framing read failure."""


class FrameTooLarge(FramingError):
    pass


@dataclass
class Framing:
    type: str = "fixed"
    size: int = 4096
    offset: int = 0
    endian: str = "be"
    counts: str = "body"          # body | total
    adjust: int = 0
    delimiter: bytes = b"\r\n"
    include: bool = True          # include the delimiter in the returned message
    max_message: int = DEFAULT_MAX_MESSAGE

    @classmethod
    def from_spec(cls, spec: Any) -> "Framing":
        # A bare integer or {read: N} means "fixed read of N bytes".
        if spec is None:
            return cls(type="fixed")
        if isinstance(spec, int):
            return cls(type="fixed", size=spec)
        if not isinstance(spec, Mapping):
            raise FramingError("framing must be a mapping, an int, or omitted")

        if "read" in spec and "type" not in spec:
            return cls(type="fixed", size=int(spec["read"]))

        ftype = str(spec.get("type", "fixed"))
        delim = spec.get("delimiter", "\r\n")
        delim_bytes = delim.encode("latin-1") if isinstance(delim, str) else bytes(delim)
        f = cls(
            type=ftype,
            size=int(spec.get("size", spec.get("read", 4096))),
            offset=int(spec.get("offset", 0)),
            endian=str(spec.get("endian", "be")).lower(),
            counts=str(spec.get("counts", "body")).lower(),
            adjust=int(spec.get("adjust", 0)),
            delimiter=delim_bytes,
            include=bool(spec.get("include", True)),
            max_message=int(spec.get("max_message", DEFAULT_MAX_MESSAGE)),
        )
        if f.type not in ("fixed", "length-prefix", "delimiter"):
            raise FramingError(f"unknown framing type {f.type!r}")
        if f.endian not in ("be", "le"):
            raise FramingError(f"framing endian must be 'be' or 'le', got {f.endian!r}")
        if f.counts not in ("body", "total"):
            raise FramingError(f"framing counts must be 'body' or 'total', got {f.counts!r}")
        return f


class FrameReader:
    """Reads one framed message at a time from a ``recv(n)`` callable."""

    def __init__(self, recv: Callable[[int], bytes], framing: Framing, prebuffer: bytes = b""):
        self._recv = recv
        self.f = framing
        self._buf = bytearray(prebuffer)

    @property
    def buffer(self) -> bytes:
        """Any bytes read past the end of the last frame (the next message)."""
        return bytes(self._buf)

    def _fill_to(self, n: int) -> bool:
        """Ensure the buffer holds at least *n* bytes. False on EOF before that."""
        if n > self.f.max_message:
            raise FrameTooLarge(f"framed message of {n} bytes exceeds cap {self.f.max_message}")
        while len(self._buf) < n:
            chunk = self._recv(min(65536, n - len(self._buf)))
            if not chunk:
                return False
            self._buf += chunk
        return True

    def read_frame(self) -> bytes | None:
        """Return exactly one framed message, or None on clean EOF with no data."""
        if self.f.type == "fixed":
            if not self._fill_to(self.f.size):
                if not self._buf:
                    return None
                # short read at EOF: return what we have (partial final record)
                out = bytes(self._buf)
                self._buf.clear()
                return out
            out = bytes(self._buf[: self.f.size])
            del self._buf[: self.f.size]
            return out

        if self.f.type == "length-prefix":
            header_len = self.f.offset + self.f.size
            if not self._fill_to(header_len):
                return None if not self._buf else self._eof_partial()
            raw_len = bytes(self._buf[self.f.offset: self.f.offset + self.f.size])
            length_value = int.from_bytes(raw_len, "big" if self.f.endian == "be" else "little")
            if self.f.counts == "total":
                total = length_value + self.f.adjust
            else:  # body
                total = header_len + length_value + self.f.adjust
            if total < header_len:
                raise FramingError(f"framing produced impossible message length {total}")
            if not self._fill_to(total):
                raise FramingError("stream closed before the full framed message arrived")
            out = bytes(self._buf[:total])
            del self._buf[:total]
            return out

        # delimiter
        idx = self._buf.find(self.f.delimiter)
        while idx == -1:
            if len(self._buf) > self.f.max_message:
                raise FrameTooLarge("delimiter not found within max_message cap")
            chunk = self._recv(65536)
            if not chunk:
                if not self._buf:
                    return None
                return self._eof_partial()
            self._buf += chunk
            idx = self._buf.find(self.f.delimiter)
        end = idx + len(self.f.delimiter)
        out = bytes(self._buf[: end if self.f.include else idx])
        del self._buf[:end]
        return out

    def _eof_partial(self) -> bytes:
        out = bytes(self._buf)
        self._buf.clear()
        return out
