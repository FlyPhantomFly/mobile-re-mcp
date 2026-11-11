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

from mobile_re_mcp.clitools import find_cli


@dataclass
class ToolStatus:
    name: str
    kind: str                   # "binary" | "python" | "java_jar" | "npm"
    available: bool
    version: Optional[str] = None
    path: Optional[str] = None
    error: Optional[str] = None
    install_hint: str = ""
    used_by: Optional[list[str]] = None   # MCP tool names that invoke this entry

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "available": self.available,
            "version": self.version,
            "path": self.path,
            "error": self.error,
            "install_hint": self.install_hint,
            "used_by": self.used_by or [],
        }


# ---------------------------------------------------------------------------
# Individual checkers
# ---------------------------------------------------------------------------


def _check_binary(
    name: str,
    version_flag: str = "--version",
    hint: str = "",
    kind: str = "binary",
    used_by: Optional[list[str]] = None,
) -> ToolStatus:
    """Check a CLI by running it with a version flag.

    Resolution goes through mobile_re_mcp.clitools.find_cli — the exact
    lookup the handlers use — so a console script living next to the
    interpreter counts just as much as one on PATH.
    """
    from mobile_re_mcp.clitools import find_cli

    used_by = used_by or []
    path = find_cli(name)
    if path is None:
        return ToolStatus(
            name=name, kind=kind, available=False, used_by=used_by,
            error=f"'{name}' not found on PATH (or next to the interpreter)",
            install_hint=hint,
        )
    try:
        result = subprocess.run(
            [path, version_flag], capture_output=True, text=True, timeout=10,
        )
        lines = (result.stdout or result.stderr).strip().splitlines()
        version = lines[0].strip() if lines else "unknown"
        return ToolStatus(name=name, kind=kind, available=True, version=version, path=path, used_by=used_by)
    except subprocess.TimeoutExpired:
        return ToolStatus(name=name, kind=kind, available=True, version="timeout", path=path, used_by=used_by)
    except Exception as exc:  # noqa: BLE001
        return ToolStatus(name=name, kind=kind, available=True, path=path, error=str(exc), used_by=used_by)


def _check_python_module(
    name: str,
    import_name: Optional[str] = None,
    hint: str = "",
    used_by: Optional[list[str]] = None,
) -> ToolStatus:
    """Check a Python importable module."""
    used_by = used_by or []
    mod_name = import_name or name.replace("-", "_")
    try:
        mod = importlib.import_module(mod_name)
        version = getattr(mod, "__version__", None) or getattr(mod, "VERSION", "installed")
        return ToolStatus(name=name, kind="python", available=True, version=str(version), used_by=used_by)
    except ImportError as exc:
        return ToolStatus(
            name=name, kind="python", available=False, used_by=used_by,
            error=str(exc), install_hint=hint or f"pip install {name}",
        )


def _check_medusa(used_by: Optional[list[str]] = None) -> ToolStatus:
    """Check for the Medusa RE framework, refusing the SSH-cracker namesake.

    Two unrelated tools are called 'medusa': the well-known SSH login
    cracker from foofus.net (the one usually on PATH) and Ch0pin's Frida
    script framework. The cracker's banner always identifies itself, so a
    run is the reliable disambiguator.
    """
    used_by = used_by or []
    from mobile_re_mcp.clitools import find_cli

    cli = find_cli("medusa")
    if cli is None:
        return ToolStatus(
            name="medusa", kind="binary", available=False, used_by=used_by,
            error="'medusa' not found on PATH",
            install_hint="RE framework: pip install 'git+https://github.com/Ch0pin/medusa' "
            "(do NOT install the SSH cracker of the same name)",
        )
    try:
        probe = subprocess.run([cli, "--version"], capture_output=True, text=True, timeout=10)
        banner = (probe.stdout or probe.stderr).strip().lower()
    except Exception:  # noqa: BLE001
        banner = ""
    if "foofus" in banner:
        return ToolStatus(
            name="medusa", kind="binary", available=False, path=cli, used_by=used_by,
            error="the 'medusa' on PATH is the SSH login cracker from foofus.net, "
            "not the Medusa RE framework this suite expects",
            install_hint="Get the framework from https://github.com/Ch0pin/medusa, "
            "or remove/rename the cracker to stop the name collision",
        )
    version = (banner or "installed").splitlines()[0]
    return ToolStatus(
        name="medusa", kind="binary", available=True, version=version, path=cli, used_by=used_by,
    )


def _check_java_jar(display_name: str, jar_path_str: str, used_by: Optional[list[str]] = None) -> ToolStatus:
    """Check a Java JAR is present and java is available."""
    used_by = used_by or []
    java_path = shutil.which("java")
    if java_path is None:
        return ToolStatus(
            name=display_name, kind="java_jar", available=False, used_by=used_by,
            error="java not found on PATH — required to run the jar",
            install_hint="Install JDK 11+ and ensure java is on PATH",
        )
    jar_path = Path(jar_path_str)
    if jar_path.exists():
        return ToolStatus(name=display_name, kind="java_jar", available=True, path=str(jar_path), used_by=used_by)
    return ToolStatus(
        name=display_name, kind="java_jar", available=False, used_by=used_by,
        error=f"JAR not found at '{jar_path_str}'",
        install_hint=(
            "Download from https://github.com/patrickfav/uber-apk-signer/releases "
            "and update [signing].jar_path in config.toml  OR  run setup.sh"
        ),
    )


def _check_file(display_name: str, paths: list[str], kind: str = "binary", hint: str = "",
                used_by: Optional[list[str]] = None) -> ToolStatus:
    """Check that at least one file path from *paths* exists."""
    used_by = used_by or []
    for p in paths:
        if Path(p).exists():
            return ToolStatus(name=display_name, kind=kind, available=True, path=p, used_by=used_by)
    return ToolStatus(
        name=display_name, kind=kind, available=False, used_by=used_by,
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
    _frida_cli = find_cli("frida")
    if _frida_cli:
        try:
            r = subprocess.run([_frida_cli, "--version"], capture_output=True, text=True, timeout=5)
            frida_version = r.stdout.strip()
        except Exception:  # noqa: BLE001
            pass

    frida_server_paths = [str(tools_dir / "frida-server")]
    frida_gadget_paths = list(tools_dir.glob("gadgets/frida-gadget-*.so")) if tools_dir.exists() else []

    checks: list[ToolStatus] = [
        # ── Core static analysis ───────────────────────────────────────────
        _check_binary("apktool", hint="Run mobile-re-mcp-py --setup, or install apktool yourself",
                      used_by=["apk_decompile", "inject_gadget", "apk_rebuild_sign"]),
        _check_binary("jadx", "--version", hint="Run mobile-re-mcp-py --setup, or install jadx yourself",
                      used_by=["apk_decompile_java"]),
        _check_binary("apkid", "--version", kind="python", hint="Run mobile-re-mcp-py --setup, or install apkid yourself",
                      used_by=["apk_identify", "apk_analyze_full", "rasp_identify", "rasp_bypass"]),
        _check_binary("apkleaks", "--version", kind="python", hint="Run mobile-re-mcp-py --setup, or install apkleaks yourself",
                      used_by=["apk_scan_secrets", "apk_analyze_full"]),
        _check_python_module("androguard", hint="Run mobile-re-mcp-py --setup, or install androguard yourself",
                             used_by=["manifest_parse", "analyze_code", "find_crypto_usage",
                                      "find_urls", "apk_analyze_full"]),
        _check_python_module("quark-engine", "quark", hint="Run mobile-re-mcp-py --setup, or install quark-engine yourself",
                             used_by=["quark_scan", "apk_analyze_full"]),
        _check_binary("rg", "--version", hint="Manual install required (ripgrep)",
                      used_by=["search_strings"]),

        # ── Dynamic instrumentation ────────────────────────────────────────
        _check_python_module("frida", hint="Run mobile-re-mcp-py --setup, or install frida yourself",
                             used_by=["frida_spawn", "frida_attach", "frida_inject", "frida_detach",
                                      "frida_status", "frida_memdump", "frida_find_bytes",
                                      "ssl_kill_switch"]),
        _check_python_module("frida-tools", "frida_tools", hint="Run mobile-re-mcp-py --setup, or install frida-tools yourself",
                             used_by=[]),
        _check_binary("frida", "--version", hint="Run mobile-re-mcp-py --setup, or install frida-tools yourself",
                      used_by=["frida_server_push", "frida_spawn_hluda"]),
        _check_binary("frida-ps", "--version", hint="Run mobile-re-mcp-py --setup, or install frida-tools yourself",
                      used_by=[]),
        _check_binary("objection", "--version", hint="Run mobile-re-mcp-py --setup, or install objection yourself",
                      used_by=["objection_run"]),

        # ── Device binaries on device (optional — need to be pushed) ──────
        _check_file(
            "frida-server (host binary)",
            frida_server_paths,
            hint=f"Extract matching frida-server-{frida_version or '<ver>'} into ~/tools/",
            used_by=["frida_server_push", "frida_spawn_hluda"],
        ),
        ToolStatus(
            name="frida-gadget",
            kind="binary",
            available=bool(frida_gadget_paths),
            path=str(frida_gadget_paths[0]) if frida_gadget_paths else None,
            error=None if frida_gadget_paths else f"No frida-gadget .so found in {tools_dir}/gadgets/",
            install_hint="Manual frida-gadget download required",
            used_by=["inject_gadget"],
        ),

        # ── Device control ─────────────────────────────────────────────────
        _check_binary("adb", "version", hint="Run mobile-re-mcp-py --setup, or install adb yourself",
                      used_by=["adb_devices", "adb_shell", "adb_install", "adb_pull", "adb_push",
                               "adb_logcat_start", "adb_logcat_read", "adb_logcat_stop",
                               "scrcpy_screenshot", "frida_server_push", "frida_spawn_hluda"]),

        # ── Network ────────────────────────────────────────────────────────
        _check_binary("mitmdump", "--version", hint="Run mobile-re-mcp-py --setup, or install mitmproxy yourself",
                      used_by=["mitm_start", "mitm_stop", "mitm_read_flows", "mitm_export_har"]),
        _check_binary("mitmproxy", "--version", hint="Run mobile-re-mcp-py --setup, or install mitmproxy yourself",
                      used_by=[]),
        _check_python_module("mitmproxy", hint="Run mobile-re-mcp-py --setup, or install mitmproxy yourself",
                             used_by=[]),

        # ── Binary analysis / RE (optional) ───────────────────────────────
        _check_binary("binwalk", "--help", hint="Manual install required",
                      used_by=[]),
        _check_binary("r2", "--version", hint="Manual install required",
                      used_by=["native_disasm"]),

        # ── Signing & JAR tools ────────────────────────────────────────────
        _check_java_jar("uber-apk-signer", jar_path, used_by=["apk_sign", "apk_rebuild_sign", "inject_gadget"]),
        _check_file(
            "smali.jar", [str(tools_dir / "smali.jar")],
            hint="apktool bundles smali; standalone jars are on Maven Central (com.android.tools.smali)",
            used_by=[],
        ),
        _check_file(
            "baksmali.jar", [str(tools_dir / "baksmali.jar")],
            hint="apktool bundles baksmali; standalone jars are on Maven Central (com.android.tools.smali)",
            used_by=[],
        ),
        _check_binary("Il2CppDumper", hint="Run mobile-re-mcp-py --setup, or install il2cppdumper yourself",
                      used_by=["il2cpp_dump"]),

        # ── Test keystore ──────────────────────────────────────────────────
        _check_file(
            "test keystore",
            [str(tools_dir / "signing" / "test.jks"), str(tools_dir / "signing" / "test.keystore")],
            hint="keytool -genkey ...",
            used_by=["apk_sign", "apk_rebuild_sign"],
        ),

        # ── npm tools (optional) ───────────────────────────────────────────
        _check_binary("apk-mitm", "--version", hint="Run mobile-re-mcp-py --setup, or install apk-mitm yourself",
                      used_by=[]),
        _check_binary("frida-compile", "--version", hint="Run mobile-re-mcp-py --setup, or install frida-compile yourself",
                      used_by=[]),

        # ── Dynamic frameworks (optional) ─────────────────────────────────
        _check_medusa(),

        # ── MCP SDK ────────────────────────────────────────────────────────
        _check_python_module("mcp", hint="pip install 'mcp>=1.30,<2'"),

        # ── Runtimes ───────────────────────────────────────────────────────
        _check_binary("java", "-version", hint="Install JDK 21+ from https://adoptium.net/",
                      used_by=["apk_sign", "apk_rebuild_sign", "inject_gadget", "il2cpp_dump", "blutter_extract"]),
        _check_binary("node", "--version", hint="Download from https://nodejs.org/",
                      used_by=["install_tool"]),
        _check_binary("npm", "--version", hint="Bundled with Node.js",
                      used_by=["install_tool"]),
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
