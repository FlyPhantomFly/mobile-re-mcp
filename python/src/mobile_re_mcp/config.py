"""Settings from the packaged defaults, overridden by the user's config file."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mobile_re_mcp.paths import tools_dir, user_config_path

_DEFAULTS = Path(__file__).parent / "config.toml"


def _read(path: Path) -> dict:
    try:
        import tomllib
    except ImportError:  # Python < 3.11 is not supported, kept for safety
        return {}
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except (FileNotFoundError, PermissionError, ValueError):
        return {}


def load_config() -> dict[str, dict[str, Any]]:
    merged = _read(_DEFAULTS)
    for section, values in _read(user_config_path()).items():
        if isinstance(values, dict):
            merged.setdefault(section, {}).update(values)
    return merged


def signer_jar() -> Path:
    """Absolute path to uber-apk-signer. Never resolved against the working directory."""
    configured = str(load_config().get("signing", {}).get("jar_path", "") or "")
    if configured and Path(configured).is_absolute():
        return Path(configured)
    return tools_dir() / "signing" / "uber-apk-signer.jar"
