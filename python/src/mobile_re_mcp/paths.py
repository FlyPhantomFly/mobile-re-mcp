"""Filesystem locations used by the server. Nothing here runs at import time."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _private_dir(p: Path) -> Path:
    p.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            os.chmod(p, 0o700)
        except OSError:
            pass
    return p


def data_dir() -> Path:
    """Per-user data directory (target notes, captures, scratch files)."""
    env = os.environ.get("MOBILE_RE_MCP_HOME")
    if env:
        base = Path(env).expanduser()
    elif os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "mobile-re-mcp"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "mobile-re-mcp"
    return _private_dir(base)


def scratch_dir(*parts: str) -> Path:
    """Private (0700) working directory, used instead of the shared /tmp."""
    return _private_dir(data_dir().joinpath("scratch", *parts))


def captures_dir() -> Path:
    return _private_dir(data_dir() / "captures")


def tools_dir() -> Path:
    """Where downloaded RE tools live. Override with MOBILE_RE_MCP_TOOLS_DIR."""
    env = os.environ.get("MOBILE_RE_MCP_TOOLS_DIR")
    return Path(env).expanduser() if env else Path.home() / "tools"


def user_config_path() -> Path:
    env = os.environ.get("MOBILE_RE_MCP_CONFIG")
    if env:
        return Path(env).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "mobile-re-mcp" / "config.toml"


def ensure_tools_on_path() -> None:
    """Append the tools directory (and known subfolders) to PATH, last so system tools win."""
    td = tools_dir()
    extra = [td, td / "jadx" / "bin", td / "platform-tools", td / "il2cppdumper", td / "scrcpy"]
    current = os.environ.get("PATH", "").split(os.pathsep)
    add = [str(p) for p in extra if p.is_dir() and str(p) not in current]
    if add:
        os.environ["PATH"] = os.pathsep.join(current + add)


def python_executable() -> str:
    return sys.executable or "python3"
