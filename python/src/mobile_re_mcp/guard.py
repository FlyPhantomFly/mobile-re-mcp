"""Argument checks applied to every tool call before a handler runs.

Environment:
  MOBILE_RE_MCP_ALLOWED_DIRS   os.pathsep-separated folders that file arguments must stay inside
  MOBILE_RE_MCP_DISABLE_TOOLS  comma-separated tool names to turn off
  MOBILE_RE_MCP_ALLOW_INSTALL  set to 1 to let the install_tool MCP tool run
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

# Host-side file arguments, by tool argument name.
PATH_KEYS = {
    "apk_path", "bundle_path", "capture_path", "gadget_path", "local", "output_apk",
    "output_dir", "output_path", "path", "record_file", "smali_dir", "so_path",
}
# Where each of those is written rather than read.
WRITE_KEYS = {"local", "output_apk", "output_dir", "output_path", "record_file"}
# Output files must keep one of these suffixes (tool -> key -> suffixes).
OUTPUT_SUFFIXES = {
    "mitm_export_har": {"output_path": {".har", ".json"}},
    "scrcpy_screenshot": {"output_path": {".png"}},
    "scrcpy_start": {"record_file": {".mp4", ".mkv"}},
}

_SYMBOL = re.compile(r"(0x[0-9a-fA-F]{1,16}|[A-Za-z0-9_.@]{1,200})")
_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*(:[A-Za-z0-9_.]{1,64})?")
_SERIAL = re.compile(r"[A-Za-z0-9._:\-]{1,100}")
_REMOTE_PATH = re.compile(r"/[A-Za-z0-9._/\-]{1,200}")
_ABIS = {"arm64", "arm", "x86_64", "x86", "arm64-v8a", "armeabi-v7a"}

_SENSITIVE_HOME = (
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".netrc", ".npmrc", ".pypirc",
    ".git-credentials", ".config/gh", ".config/opencode", ".config/git", ".claude", ".claude.json",
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zshenv",
    ".zprofile", ".zlogin", ".config/fish", ".local/share/keyrings",
)


class GuardError(ValueError):
    """Raised when a tool call is refused."""


def _csv(name: str) -> set[str]:
    return {x.strip() for x in os.environ.get(name, "").split(",") if x.strip()}


def disabled_tools() -> set[str]:
    off = _csv("MOBILE_RE_MCP_DISABLE_TOOLS")
    if os.environ.get("MOBILE_RE_MCP_ALLOW_INSTALL") != "1":
        off.add("install_tool")
    return off


def allowed_dirs() -> list[Path]:
    raw = os.environ.get("MOBILE_RE_MCP_ALLOWED_DIRS", "")
    return [Path(p).expanduser().resolve() for p in raw.split(os.pathsep) if p.strip()]


def _inside(path: Path, base: Path) -> bool:
    return path == base or base in path.parents


def check_path(value: Any, key: str, tool: str) -> None:
    if not isinstance(value, str) or not value:
        raise GuardError(f"'{key}' must be a non-empty string")
    if "\x00" in value:
        raise GuardError(f"'{key}' contains a NUL byte")
    if value.startswith("-"):
        raise GuardError(f"'{key}' must not start with '-'")
    resolved = Path(value).expanduser().resolve()
    home = Path.home().resolve()
    for rel in _SENSITIVE_HOME:
        if _inside(resolved, home / rel):
            raise GuardError(f"'{key}' points into a protected location ({rel})")
    if _inside(resolved, Path("/etc")) and key in WRITE_KEYS:
        raise GuardError(f"'{key}' may not write into /etc")
    dirs = allowed_dirs()
    if dirs and not any(_inside(resolved, d) for d in dirs):
        raise GuardError(f"'{key}' is outside MOBILE_RE_MCP_ALLOWED_DIRS")
    suffixes = OUTPUT_SUFFIXES.get(tool, {}).get(key)
    if suffixes and resolved.suffix.lower() not in suffixes:
        raise GuardError(f"'{key}' must end with one of: {', '.join(sorted(suffixes))}")


def validate(tool: str, args: Any) -> dict:
    """Return the checked arguments or raise GuardError."""
    if tool in disabled_tools():
        raise GuardError(
            "install_tool is off by default; set MOBILE_RE_MCP_ALLOW_INSTALL=1 to enable it"
            if tool == "install_tool"
            else f"tool '{tool}' is disabled by MOBILE_RE_MCP_DISABLE_TOOLS"
        )
    if args is None:
        return {}
    if not isinstance(args, dict):
        raise GuardError("arguments must be an object")
    for key in PATH_KEYS & args.keys():
        check_path(args[key], key, tool)
    _match(args, "serial", _SERIAL, "a device serial")
    _match(args, "package", _PACKAGE, "an Android package name")
    if tool == "native_disasm":
        _match(args, "target", _SYMBOL, "a symbol name or 0x offset", required=True)
    if tool == "frida_server_push":
        _match(args, "remote_path", _REMOTE_PATH, "an absolute device path")
        if "abi" in args and args["abi"] not in _ABIS:
            raise GuardError("'abi' must be one of " + ", ".join(sorted(_ABIS)))
    for key in ("port",):
        if key in args:
            try:
                port = int(args[key])
            except (TypeError, ValueError) as exc:
                raise GuardError("'port' must be an integer") from exc
            if not 1024 <= port <= 65535:
                raise GuardError("'port' must be between 1024 and 65535")
    return args


def _match(args: dict, key: str, pattern: re.Pattern, what: str, required: bool = False) -> None:
    if key not in args:
        if required:
            raise GuardError(f"'{key}' is required")
        return
    value = args[key]
    if value in (None, "") and not required:
        return
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise GuardError(f"'{key}' must be {what}")
