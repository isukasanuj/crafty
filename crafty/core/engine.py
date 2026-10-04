"""The flow executor: runs a Session's flow (client) or receive loop (listener).

Honours the operational posture (``mode``):
* ``active``   - send / respond / exchange for real.
* ``analyze``  - listener observes only, never responds (passive recon).
* ``dry-run``  - resolve the whole flow and emit the bytes that *would* go on the
  wire, send nothing. The safe way to learn what a template does.

Control flow is bounded by construction: ``over`` (list/file), ``repeat`` (count),
``until`` (condition + hard ``max``). There is no unbounded loop and no inline
branching; anything that needs real logic is a ``script`` step (deferred to v1).
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Optional

from ..listener.selectivity import Selectivity
from ..schema import substitute_params
from . import dsl, transport
from .dsl import Context
from .extractors import run_extractors
from .framing import Framing
from .matchers import evaluate_matchers
from .session import Session
from .tempo import Tempo, parse_duration


class EngineError(Exception):
    pass


# --------------------------------------------------------------------------- #
# A recording stand-in connection for dry-run (and testing).
# --------------------------------------------------------------------------- #
class DryConnection:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def send(self, data: bytes) -> int:
        self.sent.append(data)
        return len(data)

    def recv(self, framing: Framing) -> bytes:
        return b""

    def close(self) -> None:
        pass


class _RunCtx:
    def __init__(self, session: Session, conn: Any, tempo: Tempo):
        self.session = session
        self.conn = conn
        self.tempo = tempo
        self.buffers: dict[str, bytes] = {"data": b"", "request": b"", "all": b""}
        self.last_matched = False
        self.dry = session.template.mode == "dry-run"

    @property
    def dsl_ctx(self) -> Context:
        return Context(variables=self.session.variables, structs=self.session.structs)


# --------------------------------------------------------------------------- #
# Public entry
# --------------------------------------------------------------------------- #
def run(session: Session) -> Session:
    try:
        if session.role == "client":
            _run_client(session)
        elif session.role == "listener":
            _run_listener(session)
        else:
            raise EngineError(f"unknown role {session.role!r}")
    except Exception as exc:  # surface as session error, don't crash the console
        session.state = "error"
        session.error = str(exc)
        session.events.emit("error", message=str(exc))
    return session


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
def _split_hostport(value: str, default_port: Optional[int] = None) -> tuple[str, int]:
    value = value.strip()
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        return host, int(port)
    if default_port is not None:
        return value, default_port
    raise EngineError(f"expected host:port, got {value!r}")


def _run_client(session: Session) -> None:
    t = session.template
    params = session.effective_params()
    target = substitute_params(str(t.raw["target"]), params)
    host, port = _split_hostport(target)
    sock_cfg = t.raw.get("socket", {}) or {}
    timeout = parse_duration(sock_cfg.get("timeout", "5s")) or 5.0
    tempo = Tempo.from_spec(t.raw.get("tempo"))

    session.state = "running"
    if (tempo.preflight and t.transport == "tcp" and t.mode != "dry-run"
            and not transport.port_open(host, port, timeout)):
        session.events.log(f"preflight: {host}:{port} not open - skipping flow")
        session.state = "done"
        return

    if t.mode == "dry-run":
        conn: Any = DryConnection()
    else:
        conn = transport.open_client(
            t.transport, host, port, timeout,
            options=sock_cfg.get("options"), tls=sock_cfg.get("tls"),
        )
    session.events.emit("open", peer=f"{host}:{port}", transport=t.transport, mode=t.mode)
    ctx = _RunCtx(session, conn, tempo)
    try:
        for step in t.raw["flow"]:
            if session.stop_event.is_set():
                break
            _exec_step(step, ctx)
    finally:
        conn.close()
        session.events.emit("close")
        if session.state == "running":
            session.state = "done"


def _exec_step(step: dict, ctx: _RunCtx) -> None:
    if not isinstance(step, dict):
        raise EngineError(f"flow step must be a mapping, got {type(step).__name__}")
    if "loop" in step:
        _exec_loop(step["loop"], ctx)
    elif "send" in step or "recv" in step:
        _exec_exchange(step, ctx)
    elif "log" in step:
        ctx.session.events.log(_fmt(str(step["log"]), ctx))
    elif "set" in step:
        for name, raw in (step["set"] or {}).items():
            from . import expr
            ctx.session.variables[name] = expr.evaluate(str(raw), ctx.session.variables)
    elif "script" in step:
        ctx.session.events.log("script step is deferred to v1 (Starlark) - skipped")
    else:
        raise EngineError(f"unrecognised flow step with keys {list(step)}")


def _exec_exchange(step: dict, ctx: _RunCtx) -> None:
    session = ctx.session
    ctx.tempo.pace()

    if "send" in step:
        send_spec = step["send"]
        tmpl = send_spec["bytes"] if isinstance(send_spec, dict) else send_spec
        data = dsl.resolve(tmpl, ctx.dsl_ctx)
        ctx.buffers["request"] = data
        if ctx.dry:
            session.events.emit("send", bytes=_b64(data), length=len(data), note="dry-run: not sent")
        else:
            ctx.conn.send(data)
            session.events.sent(data, peer=f"{ctx.conn.peer[0]}:{ctx.conn.peer[1]}")

    if "recv" in step:
        framing = Framing.from_spec(step["recv"])
        data = b"" if ctx.dry else ctx.conn.recv(framing)
        ctx.buffers["data"] = data
        ctx.buffers["all"] = ctx.buffers.get("all", b"") + data
        if not ctx.dry:
            session.events.received(data)

    matched = evaluate_matchers(
        step.get("matchers"), step.get("matchers-condition", "or"), ctx.buffers, session.variables
    )
    ctx.last_matched = matched
    session.stats["iterations"] = session.stats.get("iterations", 0) + 1

    if matched:
        session.stats["matched"] = session.stats.get("matched", 0) + 1
        new = run_extractors(step.get("extract"), ctx.buffers, session.variables)
        session.variables.update(new)
        on_match = step.get("on_match")
        if on_match:
            session.variables.update(run_extractors(on_match.get("extract"), ctx.buffers, session.variables))
            if "log" in on_match:
                session.events.log(_fmt(str(on_match["log"]), ctx))
            _maybe_capture(on_match.get("capture"), ctx)
        _maybe_capture(step.get("capture"), ctx)


def _exec_loop(loop: dict, ctx: _RunCtx) -> None:
    do = loop.get("do") or []
    session = ctx.session

    if "over" in loop:
        items = _resolve_over(loop["over"], ctx)
        asname = str(loop.get("as", "item"))
        cap = loop.get("max")
        session.stats["total"] = len(items) if cap is None else min(len(items), int(cap))
        for i, item in enumerate(items):
            if cap is not None and i >= int(cap):
                break
            if session.stop_event.is_set():
                break
            session.variables[asname] = item.decode() if isinstance(item, bytes) else item
            for s in do:
                _exec_step(s, ctx)

    elif "repeat" in loop:
        n = int(loop["repeat"])
        delay = parse_duration(loop.get("delay"))
        session.stats["total"] = n
        for i in range(n):
            if session.stop_event.is_set():
                break
            for s in do:
                _exec_step(s, ctx)
            if delay and i < n - 1:
                time.sleep(delay)

    elif "until" in loop:
        cap = int(loop.get("max", 10))  # hard bound even for until
        delay = parse_duration(loop.get("delay"))
        session.stats["total"] = cap
        for i in range(cap):
            if session.stop_event.is_set():
                break
            for s in do:
                _exec_step(s, ctx)
            if _until_satisfied(loop["until"], ctx):
                break
            if delay and i < cap - 1:
                time.sleep(delay)
    else:
        raise EngineError("loop needs one of: over, repeat, until")


def _until_satisfied(until: Any, ctx: _RunCtx) -> bool:
    if isinstance(until, dict):
        if str(until.get("matcher", "")).lower() == "success":
            return ctx.last_matched
        if "matchers" in until:
            return evaluate_matchers(until["matchers"], until.get("matchers-condition", "or"),
                                     ctx.buffers, ctx.session.variables)
        if "dsl" in until:
            from . import expr
            return bool(expr.evaluate(str(until["dsl"]), {**ctx.session.variables, **ctx.buffers}))
    return bool(until)


def _resolve_over(value: Any, ctx: _RunCtx) -> list:
    if isinstance(value, list):
        return value
    text = substitute_params(str(value), ctx.session.effective_params()) if isinstance(value, str) else str(value)
    p = Path(text)
    if p.exists() and p.is_file():
        return [ln for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if "\n" in text:
        return [ln for ln in text.splitlines() if ln.strip()]
    if "," in text:
        return [v.strip() for v in text.split(",") if v.strip()]
    return [text]


# --------------------------------------------------------------------------- #
# Listener
# --------------------------------------------------------------------------- #
def _run_listener(session: Session) -> None:
    t = session.template
    params = session.effective_params()
    sock_cfg = t.raw.get("socket", {}) or {}
    bind = substitute_params(str(sock_cfg["bind"]), params)
    host, port = _split_hostport(bind)
    multicast = sock_cfg.get("multicast")
    if multicast:
        multicast = {k: (substitute_params(str(v), params) if isinstance(v, str) else v)
                     for k, v in multicast.items()}

    sel = Selectivity.from_spec(t.raw.get("selectivity"))
    on_receive = t.raw.get("on_receive", {}) or {}
    analyze = t.mode in ("analyze", "dry-run")

    sock = transport.open_listener(t.transport, host, port, sock_cfg.get("options"), multicast)
    sock.settimeout(0.5)  # so the stop flag is checked promptly
    session.state = "listening"
    session.events.emit("open", bind=f"{host}:{port}", transport=t.transport,
                        multicast=bool(multicast), mode=t.mode)
    try:
        if t.transport == "udp":
            _listen_udp(sock, session, sel, on_receive, analyze)
        else:
            _listen_tcp(sock, session, sel, on_receive, analyze)
    finally:
        sock.close()
        session.events.emit("close")
        if session.state == "listening":
            session.state = "done"


def _handle_incoming(data: bytes, peer: tuple, session: Session, sel: Selectivity,
                     on_receive: dict, analyze: bool) -> Optional[bytes]:
    session.stats["observed"] = session.stats.get("observed", 0) + 1
    session.variables["peer_host"] = peer[0]
    session.variables["peer_port"] = peer[1]
    session.variables["peer"] = f"{peer[0]}:{peer[1]}"
    buffers = {"data": data, "request": b"", "all": data}

    # Optional gate: does this packet concern us at all?
    if not evaluate_matchers(on_receive.get("match"), on_receive.get("matchers-condition", "or"),
                             buffers, session.variables):
        return None

    session.variables.update(run_extractors(on_receive.get("extract"), buffers, session.variables))
    query = str(session.variables.get("query", data.decode("latin-1", "replace")))

    should, reason = sel.decide(query, peer[0])
    if not should:
        session.events.log(f"skip {peer[0]} q={query!r}: {reason}")
        _maybe_capture_listener(on_receive.get("capture"), session, buffers)
        return None

    _maybe_capture_listener(on_receive.get("capture"), session, buffers)

    respond = on_receive.get("respond")
    if analyze or not respond:
        session.events.log(f"observe {peer[0]} q={query!r} (no response: "
                           f"{'analyze mode' if analyze else 'no respond block'})")
        return None

    ctx = Context(variables=session.variables, structs=session.structs)
    reply = dsl.resolve(respond["bytes"] if isinstance(respond, dict) else respond, ctx)
    sel.record_response(peer[0])
    session.stats["responses"] = session.stats.get("responses", 0) + 1
    session.events.log(f"respond to {peer[0]} q={query!r} ({len(reply)} bytes)")
    return reply


def _listen_udp(sock, session, sel, on_receive, analyze) -> None:
    import socket as _socket
    while not session.stop_event.is_set():
        try:
            data, peer = sock.recvfrom(65535)
        except _socket.timeout:
            continue
        except OSError:
            break
        session.events.received(data, peer=f"{peer[0]}:{peer[1]}")
        reply = _handle_incoming(data, peer, session, sel, on_receive, analyze)
        if reply:
            sock.sendto(reply, peer)
            session.events.sent(reply, peer=f"{peer[0]}:{peer[1]}")


def _listen_tcp(sock, session, sel, on_receive, analyze) -> None:
    import socket as _socket
    framing = Framing.from_spec(on_receive.get("recv", {"type": "fixed", "size": 4096}))
    while not session.stop_event.is_set():
        try:
            conn, peer = sock.accept()
        except _socket.timeout:
            continue
        except OSError:
            break
        with conn:
            conn.settimeout(2.0)
            try:
                reader = transport.FrameReader(conn.recv, framing)
                data = reader.read_frame() or b""
            except Exception:
                continue
            session.events.received(data, peer=f"{peer[0]}:{peer[1]}")
            reply = _handle_incoming(data, peer, session, sel, on_receive, analyze)
            if reply:
                conn.sendall(reply)
                session.events.sent(reply, peer=f"{peer[0]}:{peer[1]}")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode("ascii")


def _format(text: str, ns: dict) -> str:
    """Interpolate {{...}} in log/capture strings. Each placeholder is tried as a
    bounded expression first, then as a plain variable, then left literal."""
    import re
    from . import expr

    def repl(m):
        inner = m.group(1).strip()
        if inner.startswith("="):
            inner = inner[1:].strip()
        try:
            return str(expr.evaluate(inner, ns))
        except expr.ExprError:
            return str(ns.get(inner, m.group(0)))
    return re.sub(r"\{\{\s*([^}]+?)\s*\}\}", repl, text)


def _fmt(text: str, ctx: _RunCtx) -> str:
    return _format(text, {**ctx.session.variables, **ctx.buffers})


def _maybe_capture(cap: Any, ctx: _RunCtx) -> None:
    if not cap:
        return
    _write_capture(cap, ctx.session, ctx.buffers)


def _maybe_capture_listener(cap: Any, session: Session, buffers: dict) -> None:
    if not cap:
        return
    _write_capture(cap, session, buffers)


def _write_capture(cap: dict, session: Session, buffers: dict) -> None:
    to = cap.get("to")
    if "value" in cap:
        val = _format(str(cap["value"]), {**session.variables, **buffers})
    elif "part" in cap:
        val = buffers.get(cap["part"], b"")
    else:
        val = buffers.get("data", b"")
    path = session.loot.capture(to, val, meta={"peer": session.variables.get("peer")})
    session.events.emit("capture", to=path)
