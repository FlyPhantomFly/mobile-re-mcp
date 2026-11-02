"""
handlers/memory.py — Per-target session notes.

Tools: memory_read, memory_write

Notes are stored at <data dir>/targets/<package>/memory.md
(default data dir: ~/.local/share/mobile-re-mcp, override with MOBILE_RE_MCP_HOME).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from mobile_re_mcp.paths import data_dir

logger = logging.getLogger(__name__)

_MAX_BYTES = 200_000
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*(:[A-Za-z0-9_.]{1,64})?")

_MEMORY_TEMPLATE = """\
## Target profile
- Package: {package}
- Framework: unknown
- SDK versions: unknown
- Protection tier: unknown

## Confirmed findings
_None yet._

## Tried and failed
_None yet._

## Current hypothesis
_Not yet established._

## Unknowns
- What protection mechanisms are active?
- What is the network communication pattern?
"""


class MemoryHandler:
    """Session notes read/write handler."""

    def _memory_path(self, package: str) -> Path:
        if not isinstance(package, str) or not _NAME.fullmatch(package):
            raise ValueError("package must be an Android package name such as com.example.app")
        base = (data_dir() / "targets").resolve()
        path = (base / package.replace(":", "_") / "memory.md").resolve()
        if base not in path.parents:
            raise ValueError("package resolves outside the notes folder")
        return path

    def memory_read(self, args: dict) -> dict:
        package = args.get("package", "")
        path = self._memory_path(package)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            content = _MEMORY_TEMPLATE.format(package=package)
            path.write_text(content, encoding="utf-8")
        else:
            content = path.read_text(encoding="utf-8")

        return {
            "status": "ok",
            "tool": "memory",
            "output": {"package": package, "content": content, "path": str(path)},
        }

    def memory_write(self, args: dict) -> dict:
        package = args.get("package", "")
        content = args.get("content", "")
        if not isinstance(content, str) or len(content.encode("utf-8")) > _MAX_BYTES:
            return {"status": "error", "tool": "memory", "error": f"content must be text under {_MAX_BYTES} bytes"}
        path = self._memory_path(package)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return {
            "status": "ok",
            "tool": "memory",
            "output": {"package": package, "path": str(path), "bytes_written": len(content)},
        }
