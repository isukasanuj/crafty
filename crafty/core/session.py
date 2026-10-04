"""The Session: a named, running instance of (transport + role + socket + flow +
its live state). Sessions are concurrent and individually managed - the
abstraction that lets long-running listeners and short client probes coexist.

A template describes the config; running one instantiates a Session. ``save``
serialises a session's **config** back to a template (the round-trip rule) - not
its runtime *state* (loop position, captured loot, socket handles), which is why
"a template is a frozen session" is true of configuration only.
"""

from __future__ import annotations

import copy
import itertools
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import yaml

from ..loot import EventSink, LootWriter
from ..schema import Template
from .structs import StructRegistry

_ids = itertools.count(1)


@dataclass
class Session:
    template: Template
    params: dict[str, Any] = field(default_factory=dict)
    id: int = field(default_factory=lambda: next(_ids))
    variables: dict[str, Any] = field(default_factory=dict)
    state: str = "configured"          # configured|running|listening|done|killed|error
    stats: dict[str, Any] = field(default_factory=dict)
    created: float = field(default_factory=time.time)
    background: bool = False
    stop_event: threading.Event = field(default_factory=threading.Event)
    thread: Optional[threading.Thread] = None
    error: Optional[str] = None

    structs: StructRegistry = field(init=False)
    events: EventSink = field(init=False)
    loot: LootWriter = field(init=False)

    def __post_init__(self) -> None:
        self.structs = StructRegistry.from_spec(self.template.structs_spec)
        self.name = self.template.id
        self.events = EventSink(session=f"{self.id}:{self.name}")
        self.loot = LootWriter(session=f"{self.name}-{self.id}")
        # Seed runtime variables with effective params (template defaults overlaid by
        # operator params) so bytes: fields can reference defaulted params directly.
        self.variables.update(self.effective_params())

    def effective_params(self) -> dict[str, Any]:
        """Template-declared defaults overlaid by operator-set params."""
        defaults = {k: v for k, v in self.template.declared_params().items() if v is not None}
        return {**defaults, **self.params}

    # ------------------------------------------------------------------ #
    @property
    def transport(self) -> str:
        return self.template.transport

    @property
    def role(self) -> str:
        return self.template.role

    def runtime_vars(self) -> dict[str, Any]:
        return self.variables

    def describe_target(self) -> str:
        from ..schema import substitute_params
        try:
            if self.role == "client":
                return substitute_params(str(self.template.raw.get("target", "?")), self.params)
            bind = (self.template.raw.get("socket", {}) or {}).get("bind", "?")
            mc = (self.template.raw.get("socket", {}) or {}).get("multicast")
            return substitute_params(str(bind), self.params) + (" (mcast)" if mc else "")
        except Exception:
            return "?"

    def progress(self) -> str:
        if self.role == "listener":
            got = self.stats.get("responses", 0)
            obs = self.stats.get("observed", 0)
            return f"{obs} seen, {got} answered"
        done = self.stats.get("iterations", 0)
        total = self.stats.get("total")
        matched = self.stats.get("matched", 0)
        base = f"{done}/{total}" if total else f"{done}"
        return f"{base} ({matched} matched)" if matched else base

    # ------------------------------------------------------------------ #
    def set_on_log(self, cb: Callable[[str], None]) -> None:
        self.events.on_log = cb

    def request_stop(self) -> None:
        self.stop_event.set()

    def is_alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    # ------------------------------------------------------------------ #
    def to_template_dict(self) -> dict:
        """Serialise CONFIG back to a template dict (round-trip). Current operator
        params become the new ``defaults:``; runtime state is intentionally dropped."""
        raw = copy.deepcopy(self.template.raw)
        if self.params:
            raw.setdefault("defaults", {})
            raw["defaults"].update({k: v for k, v in self.params.items()})
        return raw

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            yaml.safe_dump(self.to_template_dict(), fh, sort_keys=False, default_flow_style=False)


class SessionRegistry:
    """Process-wide registry of sessions, addressable by id."""

    def __init__(self) -> None:
        self._sessions: dict[int, Session] = {}
        self._lock = threading.Lock()

    def add(self, session: Session) -> Session:
        with self._lock:
            self._sessions[session.id] = session
        return session

    def get(self, sid: int) -> Optional[Session]:
        return self._sessions.get(int(sid))

    def all(self) -> list[Session]:
        return list(self._sessions.values())

    def remove(self, sid: int) -> Optional[Session]:
        with self._lock:
            return self._sessions.pop(int(sid), None)

    def kill(self, sid: int) -> bool:
        s = self.get(sid)
        if not s:
            return False
        s.request_stop()
        if s.thread and s.thread.is_alive():
            s.thread.join(timeout=3.0)
        s.state = "killed"
        return True

    def kill_all(self) -> None:
        for s in self.all():
            self.kill(s.id)
