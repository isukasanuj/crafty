"""The authorized-use banner and the explain/dry-run helpers that make crafty safe
to run on a live engagement."""

from __future__ import annotations

from .schema import Template, substitute_params

BANNER = r"""
                    __ _
  ___ _ __ __ _ / _| |_ _  _
 / __| '__/ _` | |_| __| | | |
| (__| | | (_| |  _| |_| |_| |
 \___|_|  \__,_|_|  \__|\__, |
                        |___/   v{version}

  Craft any TCP/UDP exchange - client or listener.
  AUTHORIZED TESTING ONLY. Use crafty solely against systems you own or are
  explicitly authorized in writing to test. Poisoning and spraying templates
  put real attacks on real wires. crafty tunes footprint; it never grants stealth.
"""


def banner(version: str = "0.1.0") -> str:
    return BANNER.format(version=version)


def explain(t: Template) -> str:
    """Plain-English, step-by-step description of what a template does - read it
    before you run it."""
    out: list[str] = []
    info = t.info
    out.append(f"# {info.get('name', t.id)}  [{t.id}]")
    if info.get("author"):
        out.append(f"  author: {info['author']}   severity: {info.get('severity', 'info')}")
    if info.get("tags"):
        out.append(f"  tags: {', '.join(info['tags'])}")
    out.append("")
    out.append(f"This is a {t.transport.upper()} {t.role} template (mode: {t.mode}).")

    params = t.declared_params()
    if params:
        out.append("")
        out.append("Operator parameters (set these before running):")
        for name, default in params.items():
            d = f"  (default: {default})" if default is not None else "  (required)"
            out.append(f"  - {name}{d}")

    if t.role == "client":
        out.append("")
        out.append(f"It connects to {t.raw.get('target')} and then:")
        _explain_flow(t.raw.get("flow", []), out, indent=1)
        tempo = t.raw.get("tempo")
        if tempo:
            out.append("")
            out.append(f"Footprint: {tempo}")
    else:
        sock = t.raw.get("socket", {}) or {}
        out.append("")
        out.append(f"It binds {sock.get('bind')}" + (" and joins multicast "
                   f"{sock['multicast'].get('group')}" if sock.get("multicast") else "") + ".")
        sel = t.raw.get("selectivity")
        if sel:
            out.append(f"It answers only: {sel.get('respond_to', ['*'])}; ignores: {sel.get('ignore', [])}.")
        onr = t.raw.get("on_receive", {}) or {}
        if onr.get("respond"):
            out.append("For each in-scope query it sends a crafted response and captures loot.")
        else:
            out.append("It observes queries (no response configured).")
        if t.mode == "analyze":
            out.append("Mode is 'analyze' - it will NEVER respond, only observe.")
    return "\n".join(out)


def _explain_flow(flow: list, out: list[str], indent: int) -> None:
    pad = "  " * indent
    for step in flow:
        if not isinstance(step, dict):
            continue
        if "loop" in step:
            loop = step["loop"]
            if "over" in loop:
                out.append(f"{pad}- for each {loop.get('as', 'item')} in {loop['over']}:")
            elif "repeat" in loop:
                out.append(f"{pad}- repeat {loop['repeat']} times:")
            elif "until" in loop:
                out.append(f"{pad}- retry (max {loop.get('max', 10)}) until the condition holds:")
            _explain_flow(loop.get("do", []), out, indent + 1)
        elif "send" in step or "recv" in step:
            bits = []
            if "send" in step:
                bits.append("send a crafted payload")
            if "recv" in step:
                bits.append("read the response")
            line = f"{pad}- {' and '.join(bits)}"
            if step.get("matchers"):
                line += f"; match on {len(step['matchers'])} condition(s)"
            if step.get("on_match", {}).get("log"):
                line += f"; on match, log: {step['on_match']['log']!r}"
            out.append(line)
        elif "log" in step:
            out.append(f"{pad}- log: {step['log']!r}")
        elif "set" in step:
            out.append(f"{pad}- set variables: {list(step['set'])}")
        elif "script" in step:
            out.append(f"{pad}- (script step - deferred to v1)")
