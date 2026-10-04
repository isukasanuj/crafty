"""Loot capture and the structured event stream.

Every send/recv/match/extract/capture is emitted as a structured event. This is
the backbone of three things at once: evidence for findings (real captured bytes,
not approximations), composability (JSONL out to a pipeline), and the fidelity of
``dry-run`` / capture-to-template. Loot is isolated per session.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional


def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


@dataclass
class Event:
    ts: float
    session: str
    kind: str                      # send | recv | match | extract | capture | log | open | close | error
    data: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        payload = {"ts": round(self.ts, 6), "session": self.session, "kind": self.kind, **self.data}
        return json.dumps(payload, default=str)


class EventSink:
    """Collects events in-memory and optionally mirrors them to a JSONL file and/or
    a human-readable callback (the console/CLI printer)."""

    def __init__(
        self,
        session: str,
        jsonl_path: Optional[str] = None,
        on_log: Optional[Callable[[str], None]] = None,
    ):
        self.session = session
        self.events: list[Event] = []
        self._lock = threading.Lock()
        self._fh = open(jsonl_path, "a", encoding="utf-8") if jsonl_path else None
        self.on_log = on_log

    def emit(self, kind: str, **data: Any) -> Event:
        ev = Event(ts=time.time(), session=self.session, kind=kind, data=data)
        with self._lock:
            self.events.append(ev)
            if self._fh:
                self._fh.write(ev.to_json() + "\n")
                self._fh.flush()
        return ev

    # convenience emitters -------------------------------------------------- #
    def sent(self, data: bytes, peer=None) -> None:
        self.emit("send", bytes=_b64(data), length=len(data), peer=peer)

    def received(self, data: bytes, peer=None) -> None:
        self.emit("recv", bytes=_b64(data), length=len(data), peer=peer)

    def log(self, message: str) -> None:
        self.emit("log", message=message)
        if self.on_log:
            self.on_log(message)

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


class LootWriter:
    """Writes captured artefacts (hashes, creds, raw payloads) to a per-session
    file under a loot directory."""

    def __init__(self, base_dir: str = "loot", session: str = "session"):
        self.base = Path(base_dir)
        self.session = session
        self._captures: list[dict[str, Any]] = []

    def capture(self, to: Optional[str], content: Any, meta: Optional[dict[str, Any]] = None) -> str:
        self.base.mkdir(parents=True, exist_ok=True)
        target = self.base / (to if to else f"{self.session}.loot")
        target.parent.mkdir(parents=True, exist_ok=True)
        line = content if isinstance(content, str) else (
            content.decode("latin-1") if isinstance(content, (bytes, bytearray)) else str(content)
        )
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(line.rstrip("\n") + "\n")
        self._captures.append({"to": str(target), "meta": meta or {}})
        return str(target)

    @property
    def captures(self) -> list[dict[str, Any]]:
        return list(self._captures)
