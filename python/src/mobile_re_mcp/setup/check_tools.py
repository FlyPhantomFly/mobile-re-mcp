"""
setup/check_tools.py — Verify all required tools are available.

Can be run standalone:
    python -m mobile_re_mcp.setup.check_tools

Returns structured JSON per tool so the MCP check_tools() tool
and the TUI dashboard both use identical data.
"""

from __future__ import annotations

import importlib
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class ToolStatus:
    name: str
    kind: str                   # "binary" | "python" | "java_jar" | "npm"
    available: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None
    install_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "available": self.available,
            "version": self.version,
            "path": self.path,
            "error": self.error,
            "install_hint": self.install_hint,
        }


# ---------------------------------------------------------------------------
# Individual checkers
# ---------------------------------------------------------------------------


def _check_binary(name: str, version_flag: str = "--version", hint: str = "") -> ToolStatus:
    """Check a CLI binary by running it with a version flag."""
    path = shutil.which(name)
    if path is None:
        return ToolStatus(
            name=name, kind="binary", available=False,
            error=f"'{name}' not on PATH", install_hint=hint,
        )
    try:
        result = subprocess.run(
            [name, version_flag], capture_output=True, text=True, timeout=10,
        )
        lines = (result.stdout or result.stderr).strip().splitlines()
        version = lines[0] if lines else "unknown"
        return ToolStatus(name=name, kind="binary", available=True, version=version, path=path)
    except subprocess.TimeoutExpired:
        return ToolStatus(name=name, kind="binary", available=True, path=path, version="timeout")
    except Exception as exc:  # noqa: BLE001
        return ToolStatus(name=name, kind="binary", available=True, path=path, error=str(exc))


def _check_python_module(name: str, import_name: Optional[str] = None, hint: str = "") -> ToolStatus:
    """Check a Python importable module."""
    mod_name = import_name or name.replace("-", "_")
    try:
        mod = importlib.import_module(mod_name)
        version = getattr(mod, "__version__", None) or getattr(mod, "VERSION", "installed")
        return ToolStatus(name=name, kind="python", available=True, version=str(version))
    except ImportError as exc:
        return ToolStatus(
            name=name, kind="python", available=False,
            error=str(exc), install_hint=hint or f"pip install {name}",
        )


def _check_java_jar(display_name: str, jar_path_str: str) -> ToolStatus:
    """Check a Java JAR is present and java is available."""
    java_path = shutil.which("java")
    if java_path is None:
        return ToolStatus(
            name=display_name, kind="java_jar", available=False,
            error="java not found on PATH — required to run the jar",
            install_hint="Install JDK 11+ and ensure java is on PATH",
        )
    jar_path = Path(jar_path_str)
    if jar_path.exists():
        return ToolStatus(name=display_name, kind="java_jar", available=True, path=str(jar_path))
    return ToolStatus(
        name=display_name, kind="java_jar", available=False,
        error=f"JAR not found at '{jar_path_str}'",
        install_hint=(
            "Download from https://github.com/patrickfav/uber-apk-signer/releases "
            "and update [signing].jar_path in config.toml  OR  run setup.sh"
        ),
    )


def _check_file(display_name: str, paths: list[str], kind: str = "binary", hint: str = "") -> ToolStatus:
    """Check that at least one file path from *paths* exists."""
    for p in paths:
        if Path(p).exists():
            return ToolStatus(name=display_name, kind=kind, available=True, path=p)
    return ToolStatus(
        name=display_name, kind=kind, available=False,
        error=f"Not found at: {paths[0]}",
        install_hint=hint,
    )


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _get_config_signing() -> dict:
    from mobile_re_mcp.config import load_config, signer_jar

    cfg = dict(load_config().get("signing", {}))
    cfg["jar_path"] = str(signer_jar())
    return cfg


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------


def check_all_tools() -> dict:
    """
    Check all required / optional tools.

    Return shape:
    {
        "status": "ok" | "degraded" | "error",
        "summary": {"total": N, "available": N, "missing": N},
        "tools": { "<name>": { ToolStatus dict } }
    }
    """
    cfg = _get_config_signing()
    jar_path = cfg.get("jar_path", "uber-apk-signer.jar")

    from mobile_re_mcp.paths import tools_dir as _tools_dir

    tools_dir = _tools_dir()

    # Frida version for device binary paths
    frida_version: str | None = None
    if shutil.which("frida"):
        try:
            r = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
            frida_version = r.stdout.strip()
        except Exception:  # noqa: BLE001
            pass

    frida_server_paths = [str(tools_dir / "frida-server")]
    frida_gadget_paths = list(tools_dir.glob("gadgets/frida-gadget-*.so")) if tools_dir.exists() else []

    checks: list[ToolStatus] = [
        # ── Core static analysis ───────────────────────────────────────────
        _check_binary("apktool", hint="Use install_tool('apktool')"),
        _check_binary("jadx", "--version", hint="Use install_tool('jadx')"),
        _check_python_module("apkid", hint="Use install_tool('apkid')"),
        _check_python_module("apkleaks", hint="Use install_tool('apkleaks')"),
        _check_python_module("androguard", hint="Use install_tool('androguard')"),
        _check_python_module("quark-engine", "quark", hint="Use install_tool('quark-engine')"),
        _check_binary("rg", "--version", hint="Manual install required (ripgrep)"),

        # ── Dynamic instrumentation ────────────────────────────────────────
        _check_python_module("frida", hint="Use install_tool('frida')"),
        _check_python_module("frida-tools", "frida_tools", hint="Use install_tool('frida-tools')"),
        _check_binary("frida", "--version", hint="Use install_tool('frida-tools')"),
        _check_binary("frida-ps", "--version", hint="Use install_tool('frida-tools')"),
        _check_binary("objection", "--version", hint="Use install_tool('objection')"),
        _check_python_module("fridump", hint="Use install_tool('fridump')"),

        # ── Device binaries on device (optional — need to be pushed) ──────
        _check_file(
            "frida-server (host binary)",
            frida_server_paths,
            hint=f"Extract matching frida-server-{frida_version or '<ver>'} into ~/tools/",
        ),
        ToolStatus(
            name="frida-gadget",
            kind="binary",
            available=bool(frida_gadget_paths),
            path=str(frida_gadget_paths[0]) if frida_gadget_paths else None,
            error=None if frida_gadget_paths else f"No frida-gadget .so found in {tools_dir}/gadgets/",
            install_hint="Manual frida-gadget download required",
        ),

        # ── Device control ─────────────────────────────────────────────────
        _check_binary("adb", "version", hint="Use install_tool('adb')"),

        # ── Network ────────────────────────────────────────────────────────
        _check_binary("mitmdump", "--version", hint="Use install_tool('mitmproxy')"),
        _check_binary("mitmproxy", "--version", hint="Use install_tool('mitmproxy')"),
        _check_python_module("mitmproxy", hint="Use install_tool('mitmproxy')"),

        # ── Binary analysis / RE (optional) ───────────────────────────────
        _check_binary("binwalk", "--help", hint="Manual install required"),
        _check_binary("r2", "--version", hint="Manual install required"),
        _check_python_module("capstone", hint="Use install_tool('capstone')"),
        _check_python_module("keystone-engine", "keystone", hint="Use install_tool('keystone-engine')"),

        # ── Signing & JAR tools ────────────────────────────────────────────
        _check_java_jar("uber-apk-signer", jar_path),
        _check_file(
            "smali.jar", [str(tools_dir / "smali.jar")],
            hint="Use install_tool('smali')",
        ),
        _check_file(
            "baksmali.jar", [str(tools_dir / "baksmali.jar")],
            hint="Use install_tool('baksmali')",
        ),
        _check_binary("Il2CppDumper", hint="Use install_tool('il2cppdumper')"),

        # ── Test keystore ──────────────────────────────────────────────────
        _check_file(
            "test keystore",
            [str(tools_dir / "signing" / "test.jks"), str(tools_dir / "signing" / "test.keystore")],
            hint="keytool -genkey ...",
        ),

        # ── npm tools (optional) ───────────────────────────────────────────
        _check_binary("apk-mitm", "--version", hint="Use install_tool('apk-mitm')"),
        _check_binary("frida-compile", "--version", hint="Use install_tool('frida-compile')"),

        # ── Dynamic frameworks (optional) ─────────────────────────────────
        _check_binary("medusa", "--version", hint="Use install_tool('medusa')"),

        # ── MCP SDK ────────────────────────────────────────────────────────
        _check_python_module("mcp", hint="pip install 'mcp>=1.30,<2'"),

        # ── Runtimes ───────────────────────────────────────────────────────
        _check_binary("java", "-version", hint="Install JDK 21+ from https://adoptium.net/"),
        _check_binary("node", "--version", hint="Download from https://nodejs.org/"),
        _check_binary("npm", "--version", hint="Bundled with Node.js"),
    ]

    tools_dict = {s.name: s.to_dict() for s in checks}
    available = sum(1 for s in checks if s.available)
    missing = len(checks) - available
    overall = "ok" if missing == 0 else ("degraded" if available > 0 else "error")

    return {
        "status": overall,
        "summary": {"total": len(checks), "available": available, "missing": missing},
        "tools": tools_dict,
    }


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    result = check_all_tools()
    print(json.dumps(result, indent=2))

    summary = result["summary"]
    print(
        f"\n[check_tools] {summary['available']}/{summary['total']} tools available "
        f"({summary['missing']} missing)",
        file=sys.stderr,
    )
    if result["status"] != "ok":
        missing_tools = [name for name, info in result["tools"].items() if not info["available"]]
        print(f"[check_tools] Missing: {', '.join(missing_tools)}", file=sys.stderr)
        print("[check_tools] Run setup.sh to install all tools in one step.", file=sys.stderr)
