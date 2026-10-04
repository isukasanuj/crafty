"""Template parsing, validation, and the operator-parameter layer.

A template is YAML. Validation is strict with precise messages, because for a
declarative tool the error UX *is* the product. Templates carry a ``version`` so
the library survives schema changes.

Two placeholder namespaces coexist and must not be confused:

* **operator parameters** - uppercase ``{{RHOST}}`` / ``{{RPORT|88}}`` in *config*
  scalar fields (target, bind, loop.over, selectivity, tempo, capture path).
  Filled from values the operator ``set`` in the console or passes on the CLI.
* **the binary DSL** - ``{{...}}`` inside ``bytes:`` fields, resolved at runtime
  against live variables (loop vars, extracted values). See :mod:`crafty.core.dsl`.

Operator parameters are also exposed as runtime variables, so a ``bytes:`` field
may reference ``{{RHOST}}`` as a plain variable too.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

SCHEMA_VERSION = 1

_PARAM_RE = re.compile(r"\{\{\s*([A-Z][A-Z0-9_]*)\s*(?:\|([^}]*))?\}\}")


class TemplateError(ValueError):
    pass


@dataclass
class Template:
    raw: dict
    path: Optional[str] = None

    # --- identity ------------------------------------------------------- #
    @property
    def id(self) -> str:
        return str(self.raw.get("id", Path(self.path).stem if self.path else "unnamed"))

    @property
    def info(self) -> dict:
        return self.raw.get("info", {}) or {}

    @property
    def transport(self) -> str:
        return str(self.raw.get("transport", "")).lower()

    @property
    def role(self) -> str:
        return str(self.raw.get("role", "")).lower()

    @property
    def mode(self) -> str:
        return str(self.raw.get("mode", "active")).lower()

    @property
    def structs_spec(self) -> dict:
        return self.raw.get("structs", {}) or {}

    # --- loading -------------------------------------------------------- #
    @classmethod
    def from_file(cls, path: str) -> "Template":
        text = Path(path).read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        if not isinstance(data, dict):
            raise TemplateError(f"{path}: template must be a YAML mapping")
        t = cls(raw=data, path=str(path))
        t.validate()
        return t

    @classmethod
    def from_dict(cls, data: dict, path: Optional[str] = None) -> "Template":
        t = cls(raw=dict(data), path=path)
        t.validate()
        return t

    # --- validation ----------------------------------------------------- #
    def validate(self) -> None:
        errs = self.lint()
        if errs:
            joined = "\n  - ".join(errs)
            raise TemplateError(f"invalid template {self.id!r}:\n  - {joined}")

    def lint(self) -> list[str]:
        e: list[str] = []
        if self.transport not in ("tcp", "udp"):
            e.append(f"transport must be 'tcp' or 'udp' (got {self.raw.get('transport')!r}); 'raw' is v2")
        if self.role not in ("client", "listener"):
            e.append(f"role must be 'client' or 'listener' (got {self.raw.get('role')!r})")
        if self.mode not in ("active", "analyze", "dry-run"):
            e.append(f"mode must be active|analyze|dry-run (got {self.mode!r})")

        if self.role == "client":
            if "target" not in self.raw:
                e.append("client template needs a 'target'")
            flow = self.raw.get("flow")
            if not isinstance(flow, list) or not flow:
                e.append("client template needs a non-empty 'flow' list")
        elif self.role == "listener":
            sock = self.raw.get("socket", {})
            if not isinstance(sock, dict) or "bind" not in sock:
                e.append("listener template needs socket.bind ('host:port')")
            if "on_receive" not in self.raw:
                e.append("listener template needs an 'on_receive' block")

        # structs, if present, must parse
        from ..core.structs import StructError, StructRegistry
        try:
            StructRegistry.from_spec(self.structs_spec)
        except StructError as exc:
            e.append(f"structs: {exc}")
        return e

    # --- parameters ----------------------------------------------------- #
    def declared_params(self) -> dict[str, Optional[str]]:
        """All ``{{UPPER}}`` parameters found in config scalars, mapped to their
        default (or None if required). ``defaults:`` in the template seeds values."""
        found: dict[str, Optional[str]] = {}

        def walk(node: Any, in_bytes: bool) -> None:
            if isinstance(node, str) and not in_bytes:
                for m in _PARAM_RE.finditer(node):
                    name, default = m.group(1), m.group(2)
                    found.setdefault(name, default)
            elif isinstance(node, dict):
                for k, v in node.items():
                    walk(v, in_bytes or k in ("bytes",))
            elif isinstance(node, list):
                for v in node:
                    walk(v, in_bytes)

        walk(self.raw, in_bytes=False)
        for name, val in (self.raw.get("defaults") or {}).items():
            found[name] = str(val)
        return found


def substitute_params(text: str, params: dict[str, Any]) -> str:
    """Resolve ``{{NAME}}`` / ``{{NAME|default}}`` in a config scalar from params."""
    def repl(m: re.Match) -> str:
        name, default = m.group(1), m.group(2)
        if name in params and params[name] is not None:
            return str(params[name])
        if default is not None:
            return default
        raise TemplateError(f"required parameter {name} is not set")
    return _PARAM_RE.sub(repl, text)
