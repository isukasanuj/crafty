"""Template resolution.

After `pip install`/`pipx install`, there is no `templates/` directory next to the
user's shell - the library ships *inside* the package. So templates are resolved
by name across a search path, newest-wins-closest-first:

1. the argument as a literal path (absolute, or relative to the cwd)
2. ``$CRAFTY_TEMPLATES``            (operator override)
3. ``./templates``                 (running from a repo checkout)
4. ``~/.crafty/templates``         (user's own library)
5. the templates bundled with the installed package

So ``crafty run banner-ssh`` works from any directory, and a full path still
works too.
"""

from __future__ import annotations

import os
from pathlib import Path

_SUBDIRS = ("", "client", "listener")


def bundled_templates_dir() -> Path:
    """The templates shipped inside the installed package."""
    return Path(__file__).resolve().parent / "templates"


def template_search_roots() -> list[Path]:
    roots: list[Path] = []
    env = os.environ.get("CRAFTY_TEMPLATES")
    if env:
        roots.append(Path(env))
    roots.append(Path.cwd() / "templates")
    roots.append(Path.home() / ".crafty" / "templates")
    roots.append(bundled_templates_dir())
    # de-dup while preserving order, keep only existing
    seen: set[str] = set()
    out: list[Path] = []
    for r in roots:
        try:
            key = str(r.resolve())
        except OSError:
            key = str(r)
        if key not in seen and r.exists():
            seen.add(key)
            out.append(r)
    return out


def resolve_template(arg: str) -> Path | None:
    """Resolve a template given a path or a bare name. Returns None if not found."""
    if not arg:
        return None
    p = Path(arg)
    if p.is_file():
        return p
    name = p.name
    if not name.endswith((".yaml", ".yml")):
        name += ".yaml"
    for root in template_search_roots():
        for sub in _SUBDIRS:
            cand = root / sub / name
            if cand.is_file():
                return cand
    return None


def primary_library_dir() -> Path:
    """The directory the console lists/searches by default: a local ./templates if
    present (dev), otherwise the bundled library."""
    local = Path.cwd() / "templates"
    return local if local.exists() else bundled_templates_dir()
