"""Extractors: pull values out of an exchange and bind them to variables for use
in later steps (or, via ``save``/pass, other sessions).

Types:
    binary  - {name, part, offset, length}         -> bytes
    regex   - {name, part, regex, group}           -> str
    dsl     - {name, expression}                   -> any (expression over vars+parts)
    const   - {name, value}                        -> expression/literal value
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from . import expr


class ExtractorError(ValueError):
    pass


def _part_bytes(part: str, buffers: Mapping[str, bytes]) -> bytes:
    return buffers.get(part, b"")


def _extract_one(spec: Mapping[str, Any], buffers: Mapping[str, bytes], variables: Mapping[str, Any]) -> tuple[str, Any]:
    name = spec.get("name")
    if not name:
        raise ExtractorError("extractor needs a 'name'")
    etype = str(spec.get("type", "regex"))
    part = str(spec.get("part", "data"))
    data = _part_bytes(part, buffers)

    if etype == "binary":
        offset = int(spec.get("offset", 0))
        length = spec.get("length")
        value = data[offset: offset + int(length)] if length is not None else data[offset:]
    elif etype == "regex":
        pattern = spec.get("regex")
        if pattern is None:
            raise ExtractorError(f"extractor {name!r}: regex type needs 'regex'")
        group = int(spec.get("group", 1)) if spec.get("group") is not None else 0
        m = re.search(str(pattern), data.decode("latin-1", "replace"))
        value = (m.group(group) if group <= (m.re.groups if m else 0) else None) if m else None
    elif etype in ("dsl", "expr"):
        expression = spec.get("expression", spec.get("dsl"))
        if expression is None:
            raise ExtractorError(f"extractor {name!r}: dsl type needs 'expression'")
        ns = dict(variables)
        ns.update(buffers)
        value = expr.evaluate(str(expression), ns)
    elif etype in ("const", "named", "value"):
        raw = spec.get("value")
        if isinstance(raw, str):
            # allow either a literal or an expression; try expression, fall back to literal
            try:
                value = expr.evaluate(raw, variables)
            except expr.ExprError:
                value = raw
        else:
            value = raw
    else:
        raise ExtractorError(f"extractor {name!r}: unknown type {etype!r}")

    return str(name), value


def run_extractors(
    specs: list[Mapping[str, Any]] | Mapping[str, Any] | None,
    buffers: Mapping[str, bytes],
    variables: Mapping[str, Any],
) -> dict[str, Any]:
    """Return a dict of newly extracted variables.

    Accepts either a list of extractor specs, or the sugar form
    ``{varname: "{{expr}}"}`` used by ``on_match.extract``.
    """
    out: dict[str, Any] = {}
    if not specs:
        return out
    if isinstance(specs, Mapping):
        # sugar: {valid_user: "{{user}}"} -> bind each, resolving {{...}} as a var/expr.
        # Parts (data/request/all) are addressable alongside variables.
        ns = {**variables, **dict(buffers)}
        for name, raw in specs.items():
            if isinstance(raw, str):
                inner = raw.strip()
                if inner.startswith("{{") and inner.endswith("}}"):
                    inner = inner[2:-2].strip()
                try:
                    out[name] = expr.evaluate(inner, {**ns, **out})
                except expr.ExprError:
                    out[name] = raw
            else:
                out[name] = raw
        return out
    for spec in specs:
        name, value = _extract_one(spec, buffers, {**variables, **out})
        out[name] = value
    return out
