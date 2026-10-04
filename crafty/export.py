"""Export a template (or a console-created context) into a runnable artifact.

The requirement crafty targets: the operator picks an OS/arch and gets something
that RUNS ON THE TARGET WITH NOTHING INSTALLED - no Python, no pip, no packages.
A ``.pyz`` cannot do that (it needs a Python on the target), so the primary export
format is a **self-contained bundle**: a prebuilt, relocatable CPython *for the
chosen target* is packaged alongside the engine and the embedded template, with a
launcher. The target just unpacks and runs.

How cross-OS / cross-arch works from a single build machine: the runtimes come
from the ``python-build-standalone`` project as plain archives, one per OS+arch
triple. Downloading and unpacking one does not execute any target code, so a
Windows host can assemble a Linux/arm64 bundle (and vice-versa) with no emulation
and no container. There is no cross-compilation involved - the interpreter is
already compiled for the target; crafty only repackages it.

Honest limits:
* The artifact is a bundle (``.zip`` for Windows targets, ``.tar.gz`` for POSIX so
  the runtime's +x bits and symlinks survive), not one monolithic ``.exe``. A true
  single native file for *arbitrary* OS/arch from one host is not achievable for
  Python; that is the Go-port story.
* ``pyz`` (universal, needs Python on target) and ``exe`` (PyInstaller, current OS
  only) remain available for when they fit.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import stat
import sys
import tarfile
import tempfile
import urllib.request
import zipapp
import zipfile
from pathlib import Path
from typing import Optional

from . import __version__

# Exclude compiled extensions (e.g. PyYAML's _yaml.*.pyd/.so, which is platform-
# specific): only pure-Python code may travel into a cross-target bundle. PyYAML
# falls back to its pure-Python implementation when the C ext is absent.
_IGNORE = shutil.ignore_patterns(
    "__pycache__", "*.pyc", "tests", ".venv", "*.dist-info", "*.pyd", "*.so", "*.dylib",
)

# User-facing target -> python-build-standalone triple suffix (install_only).
TARGETS: dict[str, str] = {
    "windows/amd64": "x86_64-pc-windows-msvc-install_only",
    "windows/x64": "x86_64-pc-windows-msvc-install_only",
    "windows/x86": "i686-pc-windows-msvc-install_only",
    "linux/amd64": "x86_64-unknown-linux-gnu-install_only",
    "linux/x64": "x86_64-unknown-linux-gnu-install_only",
    "linux/x86": "i686-unknown-linux-gnu-install_only",
    "linux/arm64": "aarch64-unknown-linux-gnu-install_only",
    "linux/armv7": "armv7-unknown-linux-gnueabihf-install_only",
    "linux/musl-amd64": "x86_64-unknown-linux-musl-install_only",
    "linux/musl-arm64": "aarch64-unknown-linux-musl-install_only",
    "macos/arm64": "aarch64-apple-darwin-install_only",
    "macos/amd64": "x86_64-apple-darwin-install_only",
    "macos/x64": "x86_64-apple-darwin-install_only",
}

_RELEASES_API = "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"
_CACHE = Path.home() / ".crafty" / "runtimes"


# --------------------------------------------------------------------------- #
# The embedded runner (shared by pyz / native / bundle)
# --------------------------------------------------------------------------- #
def _runner_source(payload: dict) -> str:
    blob = json.dumps(payload)
    safe = blob.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    return f'''#!/usr/bin/env python3
"""crafty exported artifact - runs a single embedded template. AUTHORIZED USE ONLY."""
import argparse
import json
import sys
import threading

PAYLOAD = json.loads("""{safe}""")

from crafty.schema import Template
from crafty.core.session import Session
from crafty.core import engine
from crafty.banner import banner, explain


def main(argv=None):
    ap = argparse.ArgumentParser(description=str(PAYLOAD.get("info", "crafty exported template")))
    ap.add_argument("-t", "--target", help="target host or host:port (sets RHOST/RPORT)")
    ap.add_argument("-I", "--iface", help="interface/IP (sets IFACE)")
    ap.add_argument("--set", action="append", metavar="KEY=VALUE", default=[], help="set a parameter")
    ap.add_argument("--mode", choices=["active", "analyze", "dry-run"], help="operational posture")
    ap.add_argument("--explain", action="store_true", help="describe the template and exit")
    ap.add_argument("--jsonl", help="write the structured event stream to this JSONL file")
    args = ap.parse_args(argv)

    raw = dict(PAYLOAD["template"])
    params = dict(PAYLOAD.get("params", {{}}))
    for item in args.set:
        k, _, v = item.partition("=")
        params[k.strip()] = v
    if args.target:
        if ":" in args.target:
            h, _, p = args.target.partition(":")
            params.setdefault("RHOST", h); params.setdefault("RPORT", p)
        else:
            params.setdefault("RHOST", args.target)
    if args.iface:
        params.setdefault("IFACE", args.iface)
    if args.mode:
        raw["mode"] = args.mode

    t = Template.from_dict(raw)
    if args.explain:
        print(explain(t)); return 0

    print(banner(PAYLOAD.get("version", "0.1.0")), file=sys.stderr)
    s = Session(template=t, params=params)
    if args.jsonl:
        from crafty.loot import EventSink
        s.events = EventSink(session=f"{{s.id}}:{{s.name}}", jsonl_path=args.jsonl,
                             on_log=lambda m: print(f"[{{s.id}}] {{m}}"))
    else:
        s.set_on_log(lambda m: print(f"[{{s.id}}] {{m}}"))
    print(f"[*] {{t.id}} ({{t.transport}}/{{t.role}}, mode={{t.mode}}) -> {{s.describe_target()}}")

    if t.role == "listener":
        th = threading.Thread(target=engine.run, args=(s,), daemon=True)
        th.start()
        print("[*] listener running; Ctrl-C to stop")
        try:
            while th.is_alive():
                th.join(0.3)
        except KeyboardInterrupt:
            s.request_stop(); th.join(timeout=3)
    else:
        try:
            engine.run(s)
        except KeyboardInterrupt:
            s.request_stop()
    if s.state == "error":
        print(f"[!] error: {{s.error}}", file=sys.stderr); return 1
    print(f"[*] done: {{s.progress()}}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _build_payload(raw: dict, params: dict, info: str = "") -> dict:
    return {"version": __version__, "template": raw, "params": params or {}, "info": info}


def _stage_app(stage: Path, payload: dict) -> None:
    """Populate a staging dir with the runner + crafty + (pure-python) PyYAML."""
    pkg_dir = Path(__file__).resolve().parent
    shutil.copytree(pkg_dir, stage / "crafty", ignore=_IGNORE)
    import yaml  # bundle only the pure-python package (NOT the platform _yaml ext),
    yaml_dir = Path(yaml.__file__).resolve().parent  # so the bundle stays cross-target
    shutil.copytree(yaml_dir, stage / "yaml", ignore=_IGNORE)
    (stage / "__main__.py").write_text(_runner_source(payload), encoding="utf-8")


def _build_app_pyz(raw: dict, params: dict, dest: Path, interpreter: Optional[str] = None) -> Path:
    payload = _build_payload(raw, params, info=str(raw.get("id", "crafty")))
    with tempfile.TemporaryDirectory() as td:
        stage = Path(td) / "app"
        stage.mkdir()
        _stage_app(stage, payload)
        zipapp.create_archive(stage, target=str(dest), interpreter=interpreter)
    return dest


# --------------------------------------------------------------------------- #
# pyz (universal; needs Python on target)
# --------------------------------------------------------------------------- #
def export_pyz(raw: dict, params: dict, out_path: str, interpreter: str = "/usr/bin/env python3") -> str:
    out = Path(out_path)
    if out.suffix != ".pyz":
        out = out.with_suffix(".pyz")
    _build_app_pyz(raw, params, out, interpreter=interpreter)
    if os.name != "nt":
        out.chmod(out.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(out)


# --------------------------------------------------------------------------- #
# Self-contained bundle (any OS/arch; nothing installed on target)
# --------------------------------------------------------------------------- #
def _resolve_asset(suffix: str, py_version: str = "3.12") -> tuple[str, str]:
    req = urllib.request.Request(
        _RELEASES_API,
        headers={"User-Agent": "crafty-export", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    names = [(a["name"], a["browser_download_url"]) for a in data.get("assets", [])]
    want_end = suffix + ".tar.gz"
    matches = [(n, u) for n, u in names if n.endswith(want_end)]
    if not matches:
        raise RuntimeError(f"no python-build-standalone asset for '{suffix}' in release {data.get('tag_name')}")
    pref = [(n, u) for n, u in matches if f"cpython-{py_version}." in n]
    return (pref or matches)[0]


def _download_runtime(suffix: str, py_version: str = "3.12") -> Path:
    name, url = _resolve_asset(suffix, py_version)
    _CACHE.mkdir(parents=True, exist_ok=True)
    dest = _CACHE / name
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "crafty-export"})
    with urllib.request.urlopen(req, timeout=120) as r, open(tmp, "wb") as fh:
        shutil.copyfileobj(r, fh, length=1024 * 256)
    tmp.replace(dest)
    return dest


def export_bundle(raw: dict, params: dict, target: str, out_dir: str = ".",
                  py_version: str = "3.12") -> str:
    """Build a self-contained bundle for ``target`` ('os/arch'). Returns the path."""
    target = target.strip().lower()
    if target not in TARGETS:
        raise RuntimeError(f"unknown target {target!r}; choose from: {', '.join(sorted(TARGETS))}")
    suffix = TARGETS[target]
    os_name, arch = target.split("/", 1)
    is_windows = os_name == "windows"

    runtime_tar = _download_runtime(suffix, py_version)
    name = str(raw.get("id", "crafty"))
    root = f"crafty-{name}-{os_name}-{arch}"
    out_base = Path(out_dir) / root
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    # Build the app.pyz once (interpreter-agnostic; the launcher calls python on it).
    with tempfile.TemporaryDirectory() as td:
        app_pyz = Path(td) / "app.pyz"
        _build_app_pyz(raw, params, app_pyz, interpreter=None)
        readme = _bundle_readme(name, target, is_windows)

        if is_windows:
            launcher_name = f"{root}.cmd"
            launcher = (
                "@echo off\r\n"
                'setlocal\r\n'
                '"%~dp0python\\python.exe" "%~dp0app.pyz" %*\r\n'
            )
            out_path = str(out_base) + ".zip"
            _pack_zip(runtime_tar, out_path, root, app_pyz, launcher_name, launcher, readme)
        else:
            launcher_name = root  # e.g. ./crafty-tcp-banner-linux-arm64
            launcher = (
                "#!/bin/sh\n"
                'DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\n'
                'exec "$DIR/python/bin/python3" "$DIR/app.pyz" "$@"\n'
            )
            out_path = str(out_base) + ".tar.gz"
            _pack_tar(runtime_tar, out_path, root, app_pyz, launcher_name, launcher, readme)

    return out_path


def _bundle_readme(name: str, target: str, is_windows: bool) -> str:
    run = f"{target.replace('/', '-')} :  {'double-click ' if is_windows else './'}crafty-{name}-{target.replace('/', '-')}"
    how = (f'  {name}\\...\\{"the .cmd launcher" if is_windows else "run the launcher"}')
    return (
        f"crafty self-contained bundle for {target}\n"
        f"Template: {name}\n\n"
        "This bundle carries its own Python runtime. Nothing needs to be installed\n"
        "on this machine - unpack and run the launcher:\n\n"
        + ("  Windows:  run  crafty-" + name + "-" + target.replace('/', '-') + ".cmd\n"
           if is_windows else
           "  Linux/macOS:  chmod +x the launcher if needed, then ./the-launcher\n")
        + "\nPass template options at run time, e.g.  --set RHOST=10.0.0.5  --mode dry-run  --explain\n\n"
        "AUTHORIZED TESTING ONLY. Use only against systems you own or are explicitly\n"
        "authorized in writing to test.\n"
    )


def _pack_zip(runtime_tar: Path, out_path: str, root: str, app_pyz: Path,
              launcher_name: str, launcher: str, readme: str) -> None:
    """Windows target: extract runtime and zip everything under <root>/."""
    with tempfile.TemporaryDirectory() as td:
        extract = Path(td) / "x"
        with tarfile.open(runtime_tar, "r:gz") as tf:
            tf.extractall(extract)  # expected top-level: python/
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            base = extract
            for p in sorted(base.rglob("*")):
                if p.is_file():
                    zf.write(p, f"{root}/{p.relative_to(base).as_posix()}")
            zf.write(app_pyz, f"{root}/app.pyz")
            zf.writestr(f"{root}/{launcher_name}", launcher)
            zf.writestr(f"{root}/README.txt", readme)


def _pack_tar(runtime_tar: Path, out_path: str, root: str, app_pyz: Path,
              launcher_name: str, launcher: str, readme: str) -> None:
    """POSIX target: copy runtime tar members preserving mode + symlinks (so the
    bundled python stays executable even when building on Windows), then append
    the app, launcher (+x), and README under <root>/."""
    with tarfile.open(runtime_tar, "r:gz") as src, tarfile.open(out_path, "w:gz") as dst:
        for m in src.getmembers():
            m2 = tarfile.TarInfo(name=f"{root}/{m.name}")
            m2.size = m.size
            m2.mode = m.mode
            m2.type = m.type
            m2.linkname = m.linkname
            m2.uid, m2.gid = m.uid, m.gid
            m2.uname, m2.gname = m.uname, m.gname
            m2.mtime = m.mtime
            if m.isreg():
                f = src.extractfile(m)
                dst.addfile(m2, f)
            else:  # dirs, symlinks, hardlinks
                dst.addfile(m2)
        # app.pyz
        data = app_pyz.read_bytes()
        ti = tarfile.TarInfo(f"{root}/app.pyz"); ti.size = len(data); ti.mode = 0o644
        dst.addfile(ti, io.BytesIO(data))
        # launcher (executable)
        lb = launcher.encode()
        ti = tarfile.TarInfo(f"{root}/{launcher_name}"); ti.size = len(lb); ti.mode = 0o755
        dst.addfile(ti, io.BytesIO(lb))
        # readme
        rb = readme.encode()
        ti = tarfile.TarInfo(f"{root}/README.txt"); ti.size = len(rb); ti.mode = 0o644
        dst.addfile(ti, io.BytesIO(rb))


# --------------------------------------------------------------------------- #
# Native single-file (PyInstaller; current OS/arch only)
# --------------------------------------------------------------------------- #
def export_native(raw: dict, params: dict, out_path: str, python=sys.executable) -> str:
    try:
        import PyInstaller  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(
            "native export needs PyInstaller in this environment:\n"
            f"    {python} -m pip install pyinstaller\n"
            "PyInstaller builds only for the current OS/arch (no cross-compile). "
            "For other targets use  --target <os>/<arch>  (self-contained bundle)."
        ) from exc
    import subprocess

    out = Path(out_path)
    name = out.stem
    payload = _build_payload(raw, params, info=str(raw.get("id", "crafty")))
    with tempfile.TemporaryDirectory() as td:
        runner = Path(td) / f"{name}_runner.py"
        runner.write_text(_runner_source(payload), encoding="utf-8")
        distpath = str(out.parent) if str(out.parent) else "."
        cmd = [
            python, "-m", "PyInstaller", "--onefile", "--clean", "--noconfirm",
            "--name", name, "--distpath", distpath, "--workpath", str(Path(td) / "build"),
            "--specpath", str(td), "--hidden-import", "yaml", str(runner),
        ]
        subprocess.run(cmd, check=True)
    return str(Path(distpath) / (f"{name}.exe" if os.name == "nt" else name))
