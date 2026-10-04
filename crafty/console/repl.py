"""The interactive console REPL.

Verbs mirror msfconsole / ligolo-ng so the muscle memory already exists:
``use / set / unset / run / run -j / sessions / sessions -i / background / jobs /
kill / save / show / loot / search / explain / banner / help / exit``.

The console is a live editor for the template object; the round-trip rule
(commands.OPTION_PATHS) is its bouncer.
"""

from __future__ import annotations

import cmd
import copy
import shlex
import threading
from pathlib import Path
from typing import Optional

import yaml

from .. import __version__
from ..banner import banner, explain
from ..core import engine
from ..core.session import Session, SessionRegistry
from ..schema import Template, TemplateError
from . import commands as C


class Console(cmd.Cmd):
    intro = ""
    def __init__(self, templates_dir: str = "templates", stdout=None):
        super().__init__(stdout=stdout)
        self.templates_dir = templates_dir
        self.registry = SessionRegistry()
        self.active: Optional[Template] = None
        self.active_name: Optional[str] = None
        self.params: dict = {}
        self.overrides: dict = {}          # dotted path -> value
        self.interacting: Optional[int] = None
        self._update_prompt()

    # ------------------------------------------------------------------ #
    def _p(self, *a):
        print(*a, file=self.stdout)

    def _update_prompt(self) -> None:
        if self.interacting is not None:
            self.prompt = f"crafty (session {self.interacting}) > "
        elif self.active_name:
            self.prompt = f"crafty ({self.active_name}) > "
        else:
            self.prompt = "crafty > "

    def cmdloop(self, intro=None):
        self._p(banner(__version__))
        try:
            super().cmdloop(intro="")
        except KeyboardInterrupt:
            self._p("\n(use 'exit' to quit; Ctrl-C again to force)")
            try:
                super().cmdloop(intro="")
            except KeyboardInterrupt:
                pass
        return 0

    # ------------------------------------------------------------------ #
    def _resolve_template_path(self, name: str) -> Optional[Path]:
        cands = [
            Path(name), Path(name + ".yaml"),
            Path(self.templates_dir) / name, Path(self.templates_dir) / f"{name}.yaml",
            Path(self.templates_dir) / "client" / f"{name}.yaml",
            Path(self.templates_dir) / "listener" / f"{name}.yaml",
        ]
        for c in cands:
            if c.exists() and c.is_file():
                return c
        return None

    def _resolved_raw(self) -> dict:
        raw = copy.deepcopy(self.active.raw)
        for path, value in self.overrides.items():
            C.set_nested(raw, path, value)
        return raw

    def _build_session(self) -> Session:
        t = Template.from_dict(self._resolved_raw(), path=self.active.path)
        return Session(template=t, params=dict(self.params))

    # --- use ----------------------------------------------------------- #
    def do_use(self, arg):
        """use <template> - load a template as the active config context."""
        arg = arg.strip()
        if not arg:
            self._p("usage: use <template>")
            return
        path = self._resolve_template_path(arg)
        if not path:
            self._p(f"template not found: {arg}  (try 'search')")
            return
        try:
            t = Template.from_file(str(path))
        except TemplateError as exc:
            self._p(f"invalid template:\n{exc}")
            return
        self.active = t
        self.active_name = t.id
        self.interacting = None
        self.params = {k: v for k, v in t.declared_params().items() if v is not None}
        self.overrides = {}
        self._p(f"[*] loaded {t.id} ({t.transport}/{t.role})")
        self._update_prompt()

    # --- set / unset --------------------------------------------------- #
    def do_set(self, arg):
        """set <option> <value> - set a parameter or config option."""
        if self.active is None:
            self._p("no template loaded; use <template> first")
            return
        parts = arg.split(None, 1)
        if len(parts) != 2:
            self._p("usage: set <option> <value>")
            return
        key, value = parts[0], parts[1].strip()
        lk = key.lower()
        if lk in C.OPTION_PATHS:
            path = C.OPTION_PATHS[lk]
            self.overrides[path] = C.coerce_value(path, value)
            self._p(f"{key} => {self.overrides[path]}")
        else:
            # treat as an operator parameter ({{KEY}})
            self.params[key] = value
            self._p(f"{key} => {value}")

    def do_unset(self, arg):
        """unset <option> - clear a previously set option/parameter."""
        key = arg.strip()
        lk = key.lower()
        if lk in C.OPTION_PATHS and C.OPTION_PATHS[lk] in self.overrides:
            del self.overrides[C.OPTION_PATHS[lk]]
            self._p(f"unset {key}")
        elif key in self.params:
            del self.params[key]
            self._p(f"unset {key}")
        else:
            self._p(f"not set: {key}")

    # --- run / jobs / sessions ----------------------------------------- #
    def do_run(self, arg):
        """run [-j] - run the active template (foreground, or -j to background)."""
        if self.active is None:
            self._p("no template loaded; use <template> first")
            return
        background = "-j" in arg.split()
        try:
            s = self._build_session()
        except TemplateError as exc:
            self._p(f"cannot run - template invalid:\n{exc}")
            return
        s.set_on_log(lambda m, sid=s.id: self._p(f"[{sid}] {m}"))
        self.registry.add(s)

        # Listeners are long-running -> always backgrounded.
        if background or s.role == "listener":
            s.background = True
            th = threading.Thread(target=engine.run, args=(s,), daemon=True)
            s.thread = th
            th.start()
            # give it a moment to bind/open so the confirmation line is accurate
            for _ in range(50):
                if s.state in ("running", "listening", "error", "done"):
                    break
                threading.Event().wait(0.01)
            self._p(f"[*] Session {s.id} opened ({s.transport}/{s.role} -> {s.describe_target()})")
        else:
            self._p(f"[*] Session {s.id} running ({s.transport}/{s.role} -> {s.describe_target()})")
            engine.run(s)
            self._p(f"[*] Session {s.id} {s.state}: {s.progress()}")

    def do_jobs(self, arg):
        """jobs - list running flows/listeners."""
        rows = [[str(s.id), s.name, f"{s.transport}/{s.role}", s.state]
                for s in self.registry.all() if s.is_alive()]
        self._p(C.table(["Id", "Name", "Type", "State"], rows) if rows else "no running jobs")

    def do_sessions(self, arg):
        """sessions [-i <id>] - list sessions, or interact with one."""
        toks = arg.split()
        if toks and toks[0] == "-i":
            if len(toks) < 2:
                self._p("usage: sessions -i <id>")
                return
            sid = int(toks[1])
            s = self.registry.get(sid)
            if not s:
                self._p(f"no such session: {sid}")
                return
            self.interacting = sid
            self._p(f"[*] interacting with session {sid} ({s.name}); 'background' to detach")
            self._update_prompt()
            return
        rows = []
        for s in self.registry.all():
            rows.append([str(s.id), f"{s.transport}/{s.role}", s.describe_target(), s.state, s.progress()])
        self._p(C.table(["Id", "Type", "Target/Bind", "State", "Progress"], rows)
                if rows else "no sessions")

    def do_background(self, arg):
        """background - detach from the current session."""
        if self.interacting is None:
            self._p("not interacting with a session")
            return
        self._p(f"[*] backgrounding session {self.interacting}")
        self.interacting = None
        self._update_prompt()

    def do_kill(self, arg):
        """kill <id> - terminate a session/job."""
        try:
            sid = int(arg.strip())
        except ValueError:
            self._p("usage: kill <id>")
            return
        if self.registry.kill(sid):
            self._p(f"[*] session {sid} killed")
            if self.interacting == sid:
                self.interacting = None
                self._update_prompt()
        else:
            self._p(f"no such session: {sid}")

    # --- save ---------------------------------------------------------- #
    def do_save(self, arg):
        """save [<id>] <file> - serialise a session (or active context) to a template."""
        toks = arg.split()
        if not toks:
            self._p("usage: save [<id>] <file>")
            return
        if len(toks) >= 2 and toks[0].isdigit():
            sid, path = int(toks[0]), toks[1]
            s = self.registry.get(sid)
            if not s:
                self._p(f"no such session: {sid}")
                return
            s.save(path)
            self._p(f"[*] session {sid} config saved to {path}")
        else:
            path = toks[0]
            if self.active is None:
                self._p("nothing to save; use <template> first")
                return
            raw = self._resolved_raw()
            if self.params:
                raw.setdefault("defaults", {}).update(self.params)
            with open(path, "w", encoding="utf-8") as fh:
                yaml.safe_dump(raw, fh, sort_keys=False)
            self._p(f"[*] active context saved to {path}")

    # --- show / loot / search / explain -------------------------------- #
    def do_export(self, arg):
        """export <os/arch>[,...] [dir] | export pyz <file> | export exe <file>

        Build a runnable artifact from the active context. A bundle (default)
        carries its own Python runtime and needs nothing installed on the target."""
        if self.active is None:
            self._p("no template loaded; use <template> first")
            return
        from .. import export as X
        toks = arg.split()
        if not toks:
            self._p("usage: export <os/arch>[,...] [dir] | export pyz <file> | export exe <file>")
            self._p("targets: " + ", ".join(sorted(X.TARGETS)))
            return
        raw = self._resolved_raw()
        params = dict(self.params)
        first = toks[0].lower()
        try:
            if first == "pyz":
                out = toks[1] if len(toks) > 1 else f"{self.active_name}.pyz"
                self._p(f"[*] portable artifact: {X.export_pyz(raw, params, out)} (needs Python on target)")
            elif first == "exe":
                out = toks[1] if len(toks) > 1 else str(self.active_name)
                self._p(f"[*] native single-file (this OS only): {X.export_native(raw, params, out)}")
            else:
                out_dir = toks[1] if len(toks) > 1 else "dist"
                for tgt in [x.strip() for x in first.split(",") if x.strip()]:
                    self._p(f"[*] building bundle for {tgt} ... (first build downloads a runtime)")
                    self._p(f"    -> {X.export_bundle(raw, params, tgt, out_dir=out_dir)}")
        except RuntimeError as exc:
            self._p(f"error: {exc}")

    def do_show(self, arg):
        """show options [-a] | config | sessions | jobs | loot."""
        what = (arg.strip() or "options").split()
        head = what[0]
        if head == "options":
            if self.active is None:
                self._p("no template loaded")
                return
            rows = []
            for name, default in self.active.declared_params().items():
                cur = self.params.get(name, default)
                rows.append([name, str(cur) if cur is not None else "", "required" if default is None else ""])
            for lk, path in C.OPTION_PATHS.items():
                if lk.startswith(("tempo_", "sel_", "mcast_", "tls_")):
                    continue  # show the short alias only in basic view
                cur = self.overrides.get(path, C.get_nested(self.active.raw, path))
                if cur is not None or "-a" in what:
                    rows.append([lk, str(cur) if cur is not None else "", ""])
            self._p(C.table(["Option", "Value", "Note"], rows))
        elif head == "config":
            if self.active is None:
                self._p("no template loaded")
                return
            self._p(yaml.safe_dump(self._resolved_raw(), sort_keys=False).rstrip())
        elif head == "sessions":
            self.do_sessions("")
        elif head == "jobs":
            self.do_jobs("")
        elif head == "loot":
            self.do_loot("")
        else:
            self._p("usage: show options [-a] | config | sessions | jobs | loot")

    def do_loot(self, arg):
        """loot - show captured data across sessions."""
        rows = []
        for s in self.registry.all():
            for cap in s.loot.captures:
                rows.append([str(s.id), s.name, cap["to"]])
        self._p(C.table(["Session", "Name", "File"], rows) if rows else "no loot captured yet")

    def do_search(self, arg):
        """search <query> - find templates (tag:, role:, proto:, or substring)."""
        results = C.search_templates(arg.strip(), self.templates_dir)
        if not results:
            self._p("no matching templates")
            return
        rows = []
        for path, raw in results:
            info = raw.get("info", {}) or {}
            rows.append([raw.get("id", path.stem), f"{raw.get('transport')}/{raw.get('role')}",
                         info.get("name", ""), ",".join(info.get("tags", []))])
        self._p(C.table(["Id", "Type", "Name", "Tags"], rows))

    def do_explain(self, arg):
        """explain [<template>] - plain-English description of a template."""
        if arg.strip():
            path = self._resolve_template_path(arg.strip())
            if not path:
                self._p(f"template not found: {arg}")
                return
            t = Template.from_file(str(path))
        elif self.active is not None:
            t = Template.from_dict(self._resolved_raw(), path=self.active.path)
        else:
            self._p("no template loaded")
            return
        self._p(explain(t))

    def do_banner(self, arg):
        """banner - print the crafty banner."""
        self._p(banner(__version__))

    def do_exit(self, arg):
        """exit - quit the console (kills running sessions)."""
        self.registry.kill_all()
        self._p("bye")
        return True

    do_quit = do_exit

    def do_EOF(self, arg):
        self._p("")
        return self.do_exit(arg)

    def emptyline(self):
        return False
