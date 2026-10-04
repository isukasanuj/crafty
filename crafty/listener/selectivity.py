"""Selective response - the operational win over Responder's blanket answering,
and the one footprint feature that is genuinely a pillar rather than table stakes.

Instead of answering every query, a listener answers only queries matching
``respond_to`` patterns, skips ``ignore`` patterns (canary/honey queries like
``*-canary*`` or ``wpad*``), caps responses per host, and cools down between
answers to the same host. This is what "quiet by configuration" concretely means.

Patterns are shell-style globs (``*.corp.local``), matched case-insensitively.
"""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..core.tempo import parse_duration


@dataclass
class Selectivity:
    respond_to: list[str] = field(default_factory=lambda: ["*"])
    ignore: list[str] = field(default_factory=list)
    max_responses_per_host: int | None = None
    cooldown: float = 0.0
    # runtime state (per-session, not serialised)
    _counts: dict[str, int] = field(default_factory=dict)
    _last_answer: dict[str, float] = field(default_factory=dict)

    @classmethod
    def from_spec(cls, spec: Mapping[str, Any] | None) -> "Selectivity":
        spec = spec or {}
        respond = spec.get("respond_to", ["*"])
        if isinstance(respond, str):
            respond = [respond]
        ignore = spec.get("ignore", [])
        if isinstance(ignore, str):
            ignore = [ignore]
        return cls(
            respond_to=[str(p) for p in respond],
            ignore=[str(p) for p in ignore],
            max_responses_per_host=(
                int(spec["max_responses_per_host"]) if spec.get("max_responses_per_host") is not None else None
            ),
            cooldown=parse_duration(spec.get("cooldown")),
        )

    @staticmethod
    def _matches_any(name: str, patterns: list[str]) -> bool:
        low = name.lower()
        return any(fnmatch.fnmatch(low, p.lower()) for p in patterns)

    def decide(self, query_name: str, host: str, now: float | None = None) -> tuple[bool, str]:
        """Return (should_respond, reason). ``reason`` explains a skip, for logging."""
        now = time.monotonic() if now is None else now
        if self.ignore and self._matches_any(query_name, self.ignore):
            return False, f"ignored (matches ignore pattern)"
        if not self._matches_any(query_name, self.respond_to):
            return False, "not in respond_to"
        if self.max_responses_per_host is not None and self._counts.get(host, 0) >= self.max_responses_per_host:
            return False, f"per-host cap reached ({self.max_responses_per_host})"
        if self.cooldown > 0:
            last = self._last_answer.get(host)
            if last is not None and (now - last) < self.cooldown:
                return False, f"cooldown ({self.cooldown:g}s) not elapsed"
        return True, "match"

    def record_response(self, host: str, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        self._counts[host] = self._counts.get(host, 0) + 1
        self._last_answer[host] = now
