#!/usr/bin/env python3
"""Clean-install sanity check for an INSTALLED crafty (not an editable one).

Run this from a directory that is NOT the repo, against a freshly pip/pipx-installed
crafty, to catch the whole class of "works in my working tree, broken once installed"
bugs: git-ignored modules, package data that wasn't shipped, unresolved templates.

CI runs it after building and installing the wheel; you can run it the same way.
Exits non-zero on the first problem.
"""

from __future__ import annotations

import copy
import importlib
import sys

SUBMODULES = [
    "crafty", "crafty.cli", "crafty.export", "crafty.paths", "crafty.banner",
    "crafty.core.engine", "crafty.core.session", "crafty.core.dsl", "crafty.core.structs",
    "crafty.core.framing", "crafty.core.expr", "crafty.core.matchers", "crafty.core.extractors",
    "crafty.core.transport", "crafty.core.tempo", "crafty.loot",
    "crafty.listener.selectivity", "crafty.schema",
    "crafty.console.repl", "crafty.console.commands",
]


def main() -> int:
    # 1. every subpackage/module imports (catches ignored/unshipped modules)
    for m in SUBMODULES:
        importlib.import_module(m)

    from crafty.paths import bundled_templates_dir, resolve_template

    # 2. the template library actually shipped inside the package
    tdir = bundled_templates_dir()
    tpls = list(tdir.rglob("*.yaml"))
    if len(tpls) < 100:
        print(f"FAIL: only {len(tpls)} bundled templates found in {tdir}", file=sys.stderr)
        return 1

    # 3. templates resolve by name from this (non-repo) cwd
    for name in ("banner-ssh", "selective-udp-responder", "length-prefixed-probe"):
        if resolve_template(name) is None:
            print(f"FAIL: could not resolve template {name!r} by name", file=sys.stderr)
            return 1

    # 4. a bundled template runs end-to-end in dry-run (bytes/struct/expr resolve)
    import yaml
    from crafty.core import engine
    from crafty.core.session import Session
    from crafty.schema import Template

    raw = yaml.safe_load(resolve_template("length-prefixed-probe").read_text(encoding="utf-8"))
    raw["mode"] = "dry-run"
    s = Session(template=Template.from_dict(raw), params={"RHOST": "127.0.0.1"})
    engine.run(s)
    if s.state == "error":
        print(f"FAIL: dry-run of a bundled template errored: {s.error}", file=sys.stderr)
        return 1

    print(f"clean-install check OK: {len(tpls)} templates shipped, "
          f"{len(SUBMODULES)} modules import, dry-run ran from {__import__('os').getcwd()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
