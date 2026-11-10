"""Locate the CLI executables the handlers actually invoke.

PATH is checked first, then the console-script directory that lives next
to the running interpreter (venv installs), which PATH often misses when
the server is started from an unactivated virtualenv — exactly the case
where `pip show apkleaks` said available while the handler said
missing_tool.

check_tools and every handler resolve through this module, so what the
inventory reports is what the tools really execute.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def find_cli(name: str) -> str | None:
    """Absolute path of *name* as the handlers would invoke it, or None."""
    if not name or os.path.basename(name) != name:
        # Only plain tool names are expected; anything else is a caller bug.
        return None
    hit = shutil.which(name)
    if hit:
        return hit
    candidates: list[Path] = []
    # NB: absolute(), not resolve() — a venv interpreter is usually a symlink;
    # resolving it would leave the venv's script directory entirely.
    candidates.append(Path(sys.executable).absolute().parent)
    scripts_name = "Scripts" if os.name == "nt" else "bin"
    candidates.append(Path(sys.prefix) / scripts_name)
    suffixes = (".exe", ".cmd", ".bat", "") if os.name == "nt" else ("",)
    seen: set[Path] = set()
    for directory in candidates:
        if directory in seen:
            continue
        seen.add(directory)
        for suffix in suffixes:
            candidate = directory / f"{name}{suffix}"
            try:
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return str(candidate)
            except OSError:  # pragma: no cover - defensive
                continue
    return None
