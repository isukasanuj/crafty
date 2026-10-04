"""Command-line entry point (template mode): batch, shareable, CI-friendly.

    crafty run <template> -t 10.0.0.5 --rate 5 --jitter 0-200ms
    crafty run <template> --mode dry-run
    crafty lint <template>
    crafty explain <template>
    crafty                       # drops into the interactive console
"""

from __future__ import annotations

import argparse
import os as _os
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .banner import banner, explain
from .core import engine
from .core.session import Session
from .loot import EventSink
from .schema import Template, TemplateError


def _apply_cli_params(raw: dict, args) -> dict:
    params: dict[str, str] = {}
    for item in args.set or []:
        if "=" not in item:
            raise SystemExit(f"--set expects KEY=VALUE, got {item!r}")
        k, _, v = item.partition("=")
        params[k.strip()] = v
    if args.target:
        if ":" in args.target:
            host, _, port = args.target.partition(":")
            params.setdefault("RHOST", host)
            params.setdefault("RPORT", port)
        else:
            params.setdefault("RHOST", args.target)
    if args.iface:
        params.setdefault("IFACE", args.iface)
    # live tempo overrides written into config so they round-trip
    if args.rate is not None:
        raw.setdefault("tempo", {})["rate"] = args.rate
    if args.jitter is not None:
        raw.setdefault("tempo", {})["jitter"] = args.jitter
    if args.mode:
        raw["mode"] = args.mode
    return params


def cmd_run(args) -> int:
    print(banner(__version__), file=sys.stderr)
    try:
        t = Template.from_file(args.template)
    except (TemplateError, FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    params = _apply_cli_params(t.raw, args)

    s = Session(template=t, params=params)
    # live, human-readable output + optional JSONL evidence stream
    s.events = EventSink(session=f"{s.id}:{s.name}", jsonl_path=args.jsonl,
                         on_log=lambda m: print(f"[{s.id}] {m}"))
    print(f"[*] running {t.id} ({t.transport}/{t.role}, mode={t.mode}) -> {s.describe_target()}")

    if t.role == "listener":
        print("[*] listener running; press Ctrl-C to stop")
        import threading
        th = threading.Thread(target=engine.run, args=(s,), daemon=True)
        th.start()
        try:
            while th.is_alive():
                th.join(0.3)
        except KeyboardInterrupt:
            print("\n[*] stopping listener...")
            s.request_stop()
            th.join(timeout=3)
    else:
        try:
            engine.run(s)
        except KeyboardInterrupt:
            s.request_stop()

    if s.state == "error":
        print(f"[!] session error: {s.error}", file=sys.stderr)
        return 1
    caps = s.loot.captures
    print(f"[*] done: {s.progress()}" + (f"; {len(caps)} capture(s) -> "
          f"{caps[-1]['to']}" if caps else ""))
    return 0


def cmd_lint(args) -> int:
    try:
        data = Path(args.template).read_text(encoding="utf-8")
        import yaml
        raw = yaml.safe_load(data)
        t = Template(raw=raw, path=args.template)
    except Exception as exc:
        print(f"{args.template}: cannot parse: {exc}")
        return 2
    errs = t.lint()
    if errs:
        print(f"{args.template}: INVALID")
        for e in errs:
            print(f"  - {e}")
        return 1
    print(f"{args.template}: OK  ({t.transport}/{t.role})")
    return 0


def cmd_explain(args) -> int:
    try:
        t = Template.from_file(args.template)
    except TemplateError as exc:
        print(f"error: {exc}")
        return 2
    print(explain(t))
    return 0


def cmd_export(args) -> int:
    from . import export as _export

    if getattr(args, "list_targets", False):
        print("available bundle targets (os/arch):")
        for key in sorted(_export.TARGETS):
            print(f"  {key}")
        return 0

    if not args.template:
        print("error: a template path is required (or use --list-targets)", file=sys.stderr)
        return 2
    try:
        t = Template.from_file(args.template)
    except (TemplateError, FileNotFoundError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Export bakes --set params and --mode into the artifact; -t host via --set RHOST=.
    params: dict = {}
    for item in args.set or []:
        if "=" not in item:
            print(f"--set expects KEY=VALUE, got {item!r}", file=sys.stderr)
            return 2
        k, _, v = item.partition("=")
        params[k.strip()] = v
    if args.mode:
        t.raw["mode"] = args.mode
    raw = t.raw

    fmt = args.format
    if fmt == "bundle" or args.target:
        if not args.target:
            print("error: --target <os/arch>[,<os/arch>...] is required for bundles "
                  "(see --list-targets)", file=sys.stderr)
            return 2
        out_dir = args.output or "dist"
        rc = 0
        for tgt in [x.strip() for x in args.target.split(",") if x.strip()]:
            try:
                print(f"[*] building self-contained bundle for {tgt} ...")
                produced = _export.export_bundle(raw, params, tgt, out_dir=out_dir, py_version=args.python)
                size = Path(produced).stat().st_size
                print(f"    -> {produced}  ({size/1_048_576:.1f} MB; no install needed on target)")
            except RuntimeError as exc:
                print(f"    ! {tgt}: {exc}", file=sys.stderr)
                rc = 1
        return rc

    if fmt == "exe":
        out = args.output or (Path(args.template).stem + (".exe" if _os.name == "nt" else ""))
        try:
            produced = _export.export_native(raw, params, out)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"[*] native single-file binary (this OS/arch only): {produced}")
        print("    for other targets:  crafty export ... --target <os>/<arch>")
        return 0

    # pyz
    out = args.output or (Path(args.template).stem + ".pyz")
    produced = _export.export_pyz(raw, params, out)
    print(f"[*] portable artifact (needs a Python 3 on the target): {produced}")
    print("    run:  python " + produced + "   (Linux/macOS: ./" + produced + ")")
    return 0


def cmd_console(args) -> int:
    from .console.repl import Console
    return Console().cmdloop()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="crafty", description="Craft any TCP/UDP exchange - client or listener.")
    p.add_argument("--version", action="version", version=f"crafty {__version__}")
    sub = p.add_subparsers(dest="command")

    r = sub.add_parser("run", help="run a template")
    r.add_argument("template")
    r.add_argument("-t", "--target", help="target host or host:port (sets RHOST/RPORT)")
    r.add_argument("-I", "--iface", help="interface/IP (sets IFACE)")
    r.add_argument("--set", action="append", metavar="KEY=VALUE", help="set a parameter")
    r.add_argument("--rate", help="requests/sec (e.g. 5 or 5/s)")
    r.add_argument("--jitter", help="randomised delay (e.g. 0-200ms)")
    r.add_argument("--mode", choices=["active", "analyze", "dry-run"], help="operational posture")
    r.add_argument("--jsonl", help="write the structured event stream to this JSONL file")
    r.set_defaults(func=cmd_run)

    l = sub.add_parser("lint", help="validate a template")
    l.add_argument("template")
    l.set_defaults(func=cmd_lint)

    e = sub.add_parser("explain", help="plain-English description of a template")
    e.add_argument("template")
    e.set_defaults(func=cmd_explain)

    x = sub.add_parser("export", help="export a template into a runnable artifact")
    x.add_argument("template", nargs="?", default=None)
    x.add_argument("--target", help="bundle target(s) os/arch, comma-separated (e.g. linux/arm64,windows/amd64)")
    x.add_argument("--format", choices=["bundle", "pyz", "exe"], default="bundle",
                   help="bundle=self-contained (needs --target); pyz=portable (needs Python on target); "
                        "exe=native single file (current OS only)")
    x.add_argument("-o", "--output", help="output directory (bundle) or file (pyz/exe)")
    x.add_argument("--set", action="append", metavar="KEY=VALUE", help="bake a parameter into the artifact")
    x.add_argument("--mode", choices=["active", "analyze", "dry-run"], help="bake an operational posture")
    x.add_argument("--python", default="3.12", help="CPython version for bundles (default 3.12)")
    x.add_argument("--list-targets", action="store_true", help="list available bundle targets and exit")
    x.set_defaults(func=cmd_export)

    c = sub.add_parser("console", help="interactive console (default)")
    c.set_defaults(func=cmd_console)
    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        return cmd_console(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
