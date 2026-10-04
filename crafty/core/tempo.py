"""Footprint and tempo controls.

These are a design *value* (match an engagement's noise budget), stated honestly:
they lower the odds of tripping noisy detections, they do not grant stealth.
Completed TCP handshakes are logged; poisoning puts wrong answers on the wire
that canaries catch. crafty never claims invisibility.

``Tempo`` covers the client knobs (rate, jitter, preflight). Listener footprint
(the genuinely novel selectivity: respond-to/ignore/cooldown/cap) lives in
:mod:`crafty.listener.selectivity`.
"""

from __future__ import annotations

import random
import re
import time
from dataclasses import dataclass
from typing import Any, Mapping


def _parse_rate(value: Any) -> float | None:
    """'5/s', '5', 5 -> actions per second. None -> unlimited."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    m = re.fullmatch(r"\s*([\d.]+)\s*(?:/\s*s(?:ec)?)?\s*", str(value))
    if not m:
        raise ValueError(f"bad rate {value!r} (use '5/s' or a number)")
    return float(m.group(1))


def parse_duration(value: Any) -> float:
    """'200ms', '2s', '1m', 5 -> seconds."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip().lower()
    m = re.fullmatch(r"([\d.]+)\s*(ms|s|m|h)?", s)
    if not m:
        raise ValueError(f"bad duration {value!r}")
    n = float(m.group(1))
    return {"ms": n / 1000, "s": n, "m": n * 60, "h": n * 3600, None: n}[m.group(2)]


def _parse_jitter(value: Any) -> tuple[float, float]:
    """'0-200ms', '200ms', None -> (low, high) seconds."""
    if value is None:
        return (0.0, 0.0)
    s = str(value).strip()
    if "-" in s:
        lo, hi = s.split("-", 1)
        return (parse_duration(lo if lo.strip() else "0"), parse_duration(hi))
    d = parse_duration(s)
    return (0.0, d)


@dataclass
class Tempo:
    rate: float | None = None          # actions per second (None = unlimited)
    jitter: tuple[float, float] = (0.0, 0.0)
    concurrency: int = 1
    preflight: bool = False
    _tokens: float = 0.0
    _last: float = 0.0

    @classmethod
    def from_spec(cls, spec: Mapping[str, Any] | None) -> "Tempo":
        spec = spec or {}
        return cls(
            rate=_parse_rate(spec.get("rate")),
            jitter=_parse_jitter(spec.get("jitter")),
            concurrency=int(spec.get("concurrency", 1)),
            preflight=bool(spec.get("preflight", False)),
            _last=time.monotonic(),
        )

    def pace(self, sleep=time.sleep) -> None:
        """Block as long as the configured rate + jitter require before an action."""
        if self.rate and self.rate > 0:
            now = time.monotonic()
            self._tokens = min(self.rate, self._tokens + (now - self._last) * self.rate)
            self._last = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self.rate
                sleep(wait)
                self._tokens = 0.0
                self._last = time.monotonic()
            else:
                self._tokens -= 1.0
        lo, hi = self.jitter
        if hi > 0:
            sleep(random.uniform(lo, hi))
