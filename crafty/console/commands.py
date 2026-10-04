"""Helpers for the console: option mapping (the round-trip rule in code), template
search, and table formatting.

The round-trip rule: every ``set`` must map to a template field so ``save`` can
write it back out. ``OPTION_PATHS`` below is that mapping made explicit - anything
not expressible as a path into the template is not a console option (it would be a
``script`` step instead)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml

# console key (lowercased) -> dotted path into the template, or "param"
OPTION_PATHS: dict[str, str] = {
    "mode": "mode",
    "target": "target",
    "rate": "tempo.rate",
    "jitter": "tempo.jitter",
    "concurrency": "tempo.concurrency",
    "preflight": "tempo.preflight",
    "timeout": "socket.timeout",
    "bind": "socket.bind",
    "respond_to": "selectivity.respond_to",
    "ignore": "selectivity.ignore",
    "cooldown": "selectivity.cooldown",
    "max_responses_per_host": "selectivity.max_responses_per_host",
    # namespaced aliases (naming convention from the spec)
    "tempo_rate": "tempo.rate",
    "tempo_jitter": "tempo.jitter",
    "tempo_concurrency": "tempo.concurrency",
    "sel_respond_to": "selectivity.respond_to",
    "sel_ignore": "selectivity.ignore",
    "sel_cooldown": "selectivity.cooldown",
    "mcast_group": "socket.multicast.group",
    "mcast_iface": "socket.multicast.interface",
    "tls_enable": "socket.tls",
}

_LIST_PATHS = {"selectivity.respond_to", "selectivity.ignore"}
_BOOL_PATHS = {"tempo.preflight", "socket.tls"}


def coerce_value(path: str, value: str) -> Any:
    if path in _LIST_PATHS:
        return [v.strip() for v in value.split(",") if v.strip()]
    if path in _BOOL_PATHS:
        return value.strip().lower() in ("1", "true", "yes", "on")
    return value


def set_nested(raw: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    node = raw
    for p in parts[:-1]:
        node = node.setdefault(p, {})
        if not isinstance(node, dict):
            raise ValueError(f"cannot set {path}: {p} is not a mapping")
    node[parts[-1]] = value


def get_nested(raw: dict, path: str) -> Any:
    node: Any = raw
    for p in path.split("."):
        if not isinstance(node, dict) or p not in node:
            return None
        node = node[p]
    return node


def iter_templates(root: str = "templates"):
    base = Path(root)
    if not base.exists():
        return
    for path in sorted(base.rglob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                yield path, raw
        except Exception:
            continue


def search_templates(query: str, root: str = "templates") -> list[tuple[Path, dict]]:
    """Filterable search over the ``info:`` block. Supports ``tag:``, ``role:``,
    ``proto:`` and plain substring (matched across id/name/tags)."""
    filters = {}
    terms = []
    for tok in query.split():
        if ":" in tok:
            k, _, v = tok.partition(":")
            filters[k.lower()] = v.lower()
        else:
            terms.append(tok.lower())

    results = []
    for path, raw in iter_templates(root):
        info = raw.get("info", {}) or {}
        tags = [str(x).lower() for x in info.get("tags", [])]
        hay = " ".join([str(raw.get("id", "")), str(info.get("name", "")), *tags]).lower()
        if "tag" in filters and filters["tag"] not in tags:
            continue
        if "role" in filters and filters["role"] != str(raw.get("role", "")).lower():
            continue
        if "proto" in filters and filters["proto"] != str(raw.get("transport", "")).lower():
            continue
        if "cve" in filters and filters["cve"] not in hay:
            continue
        if terms and not all(term in hay for term in terms):
            continue
        results.append((path, raw))
    return results


def table(headers: list[str], rows: list[list[str]]) -> str:
    cols = len(headers)
    widths = [len(h) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], len(str(r[i])) if i < len(r) else 0)
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    out = [line, "  ".join("-" * widths[i] for i in range(cols))]
    for r in rows:
        out.append("  ".join(str(r[i] if i < len(r) else "").ljust(widths[i]) for i in range(cols)))
    return "\n".join(out)
