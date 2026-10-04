"""Matchers: decide whether a response indicates the condition of interest.

A matcher runs against a named *part* (buffer) of the exchange - ``data`` (last
bytes read), ``request`` (last bytes sent), ``all`` (everything read so far), or
a per-step named buffer - and returns a bool. Multiple matchers in a step are
combined with ``matchers-condition: and | or`` (default ``or``). Any matcher may
set ``negative: true`` to invert it.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from . import expr


class MatcherError(ValueError):
    pass


def _part_bytes(part: str, buffers: Mapping[str, bytes]) -> bytes:
    return buffers.get(part, b"")


def _evaluate_one(spec: Mapping[str, Any], buffers: Mapping[str, bytes], variables: Mapping[str, Any]) -> bool:
    mtype = str(spec.get("type", "word"))
    part = str(spec.get("part", "data"))
    negative = bool(spec.get("negative", False))
    data = _part_bytes(part, buffers)

    if mtype == "binary":
        value = spec.get("value")
        if value is None:
            raise MatcherError("binary matcher needs 'value' (hex)")
        try:
            needle = bytes.fromhex(str(value).replace(" ", ""))
        except ValueError as exc:
            raise MatcherError(f"binary matcher bad hex {value!r}: {exc}") from exc
        offset = int(spec.get("offset", 0))
        if "offset" in spec or "length" in spec:
            length = int(spec.get("length", len(needle)))
            result = data[offset: offset + length] == needle[:length]
        else:
            result = needle in data

    elif mtype == "word":
        words = spec.get("words", spec.get("word"))
        if words is None:
            raise MatcherError("word matcher needs 'words'")
        if isinstance(words, (str, bytes)):
            words = [words]
        encoding = str(spec.get("encoding", "")).lower()
        needles = []
        for w in words:
            if encoding == "hex":
                needles.append(bytes.fromhex(str(w).replace(" ", "")))
            elif isinstance(w, bytes):
                needles.append(w)
            else:
                needles.append(str(w).encode("utf-8"))
        cond = str(spec.get("condition", "or")).lower()
        hits = [n in data for n in needles]
        result = all(hits) if cond == "and" else any(hits)

    elif mtype == "regex":
        patterns = spec.get("regex", spec.get("patterns"))
        if patterns is None:
            raise MatcherError("regex matcher needs 'regex'")
        if isinstance(patterns, str):
            patterns = [patterns]
        text = data.decode("latin-1", "replace")
        cond = str(spec.get("condition", "or")).lower()
        hits = [re.search(p, text) is not None for p in patterns]
        result = all(hits) if cond == "and" else any(hits)

    elif mtype == "len":
        n = len(data)
        lo = spec.get("min")
        hi = spec.get("max")
        exact = spec.get("value")
        result = True
        if exact is not None:
            result = result and n == int(exact)
        if lo is not None:
            result = result and n >= int(lo)
        if hi is not None:
            result = result and n <= int(hi)

    elif mtype == "status":
        # Connection/exchange outcome exposed by the engine as the _status variable
        # (e.g. "connected", "closed", "timeout", "refused").
        want = spec.get("value", spec.get("status"))
        result = str(variables.get("_status", "")) == str(want)

    elif mtype == "dsl":
        expression = spec.get("expression", spec.get("dsl"))
        if expression is None:
            raise MatcherError("dsl matcher needs 'expression'")
        ns = dict(variables)
        ns.update(buffers)  # parts are addressable in the expression too
        result = bool(expr.evaluate(str(expression), ns))

    else:
        raise MatcherError(f"unknown matcher type {mtype!r}")

    return (not result) if negative else result


def evaluate_matchers(
    specs: list[Mapping[str, Any]] | None,
    condition: str,
    buffers: Mapping[str, bytes],
    variables: Mapping[str, Any],
) -> bool:
    """Combine a step's matchers. With no matchers, the step always 'matches'."""
    if not specs:
        return True
    results = [_evaluate_one(s, buffers, variables) for s in specs]
    return all(results) if str(condition).lower() == "and" else any(results)
