"""
handlers/signing.py — APK signing via uber-apk-signer.

Tools: apk_sign, apk_rebuild_sign
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from mobile_re_mcp.config import load_config, signer_jar

logger = logging.getLogger(__name__)

_TIMEOUT = 120


def _load_config() -> dict:
    """[signing] settings; jar_path is always an absolute path."""
    cfg = dict(load_config().get("signing", {}))
    cfg["jar_path"] = str(signer_jar())
    return cfg


def _check_tool(name: str) -> bool:
    import shutil
    return shutil.which(name) is not None


class SigningHandler:
    """APK signing handler using uber-apk-signer."""

    def apk_sign(self, args: dict) -> dict:
        apk_path = args.get("apk_path", "")
        cfg = _load_config()
        jar_path = cfg.get("jar_path", "uber-apk-signer.jar")

        if not Path(jar_path).exists():
            return {
                "status": "missing_tool",
                "tool": "uber-apk-signer",
                "error": f"uber-apk-signer jar not found at '{jar_path}'.",
                "hint": "Run mobile-re-mcp-py --setup, or set [signing].jar_path in ~/.config/mobile-re-mcp/config.toml.",
            }

        cmd = ["java", "-jar", jar_path, "--apks", apk_path]
        ks = cfg.get("keystore_path", "")
        if ks:
            cmd += [
                "--ks", ks,
                "--ksPass", cfg.get("keystore_password", ""),
                "--ksAlias", cfg.get("key_alias", ""),
                "--ksKeyPass", cfg.get("key_password", ""),
            ]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_TIMEOUT)
            signed_path = str(Path(apk_path).with_suffix("")) + "_signed.apk"
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "tool": "uber-apk-signer",
                "output": {"apk_path": apk_path, "signed_path": signed_path},
                "raw": proc.stdout,
                "error": proc.stderr if proc.returncode != 0 else None,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "uber-apk-signer", "error": "Timeout after 120s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "uber-apk-signer", "error": str(exc)}

    def apk_rebuild_sign(self, args: dict) -> dict:
        smali_dir = args.get("smali_dir", "")
        if not _check_tool("apktool"):
            return {"status": "missing_tool", "tool": "apktool", "error": "apktool not found on PATH."}

        rebuilt_apk = smali_dir.rstrip("/\\") + "_rebuilt.apk"
        try:
            proc = subprocess.run(
                ["apktool", "b", smali_dir, "-o", rebuilt_apk, "-f"],
                capture_output=True, text=True, timeout=_TIMEOUT,
            )
            if proc.returncode != 0:
                return {"status": "error", "tool": "apktool", "error": proc.stderr or proc.stdout}
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "apktool", "error": "Rebuild timeout after 120s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "apktool", "error": str(exc)}

        return self.apk_sign({"apk_path": rebuilt_apk})
