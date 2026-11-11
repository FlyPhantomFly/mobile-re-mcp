"""
server.py — MCP server factory: registers all tools, resources, and prompts.

All handler implementations live in mobile_re_mcp/handlers/*.
Tool logic is intentionally thin here; this file only wires registration.

Dispatch is non-blocking (F-PY-4): sync handlers run on worker threads via
module-level _run_tool; handler classes that hold process/session state
flag themselves with _SERIALIZE and get a dedicated single-worker pool.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

from mcp.server import Server
from mcp.types import (
    CallToolResult,
    GetPromptResult,
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
    Prompt,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)

from mobile_re_mcp import __version__, guard
from mobile_re_mcp.handlers.device import DeviceHandler
from mobile_re_mcp.handlers.dynamic import DynamicHandler
from mobile_re_mcp.handlers.flutter import FlutterHandler
from mobile_re_mcp.handlers.memory import MemoryHandler
from mobile_re_mcp.handlers.native import NativeHandler
from mobile_re_mcp.handlers.network import NetworkHandler
from mobile_re_mcp.handlers.patcher import PatcherHandler
from mobile_re_mcp.handlers.rasp import RaspHandler
from mobile_re_mcp.handlers.signing import SigningHandler
from mobile_re_mcp.handlers.static import StaticHandler
from mobile_re_mcp.setup.check_tools import check_all_tools
from mobile_re_mcp.setup.install_tool import install_tool as _install_tool

logger = logging.getLogger(__name__)

KNOWLEDGE_DIR = Path(__file__).parent / "knowledge"

# ---------------------------------------------------------------------------
# Tool schema definitions
# ---------------------------------------------------------------------------

TOOL_SCHEMAS: list[dict] = [
    # ── Static analysis ────────────────────────────────────────────────────
    {
        "name": "apk_decompile",
        "description": "Decompile an APK using apktool (smali + resources).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Absolute path to the APK"},
                "mode": {
                    "type": "string",
                    "enum": ["full", "resources_only", "smali_only"],
                    "default": "full",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "apk_decompile_java",
        "description": "Decompile APK to Java source using jadx.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Absolute path to the APK"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "apk_identify",
        "description": "Identify packers, obfuscators, and anti-tamper using apkid.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "apk_scan_secrets",
        "description": "Scan for hardcoded secrets and API keys using apkleaks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "apk_analyze_full",
        "description": (
            "Orchestrate all static tools: returns framework detected, "
            "protection tier, and top findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "quark_scan",
        "description": (
            "Run quark-engine behaviour rules over an APK and return scored "
            "behaviour matches (e.g. 'send SMS', 'load dex from external "
            "source'). Needs the rule set downloaded once via `freshquark`."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "keywords": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Only run rules whose crime/label contains one of these (case-insensitive).",
                },
                "min_score": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5,
                    "description": "Skip rules whose base score is below this (0 = no filter).",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Cap on returned behaviour matches (default 10).",
                },
                "rules_dir": {
                    "type": "string",
                    "description": "Optional directory of quark rule JSONs (default: freshquark's ~/.quark-engine/quark-rules).",
                },
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "manifest_parse",
        "description": "Parse AndroidManifest.xml — exported components, permissions, risk flags.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "search_strings",
        "description": "ripgrep search across a decompiled output directory.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Directory to search"},
                "pattern": {"type": "string", "description": "Search pattern (regex supported)"},
            },
            "required": ["path", "pattern"],
        },
    },
    # ── Dynamic instrumentation ────────────────────────────────────────────
    {
        "name": "frida_spawn",
        "description": "Spawn an app with Frida attached and inject a script.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "script": {"type": "string", "description": "Frida JS script content"},
                "config": {
                    "type": "object",
                    "description": "Posted as {'type':'config',…} after load (scripts using recv('config')).",
                },
            },
            "required": ["package"],
        },
    },
    {
        "name": "frida_attach",
        "description": "Attach Frida to a running process.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "script": {"type": "string", "description": "Optional script to load right after attach"},
                "config": {
                    "type": "object",
                    "description": "Posted as {'type':'config',…} after load (scripts using recv('config')).",
                },
            },
            "required": ["package"],
        },
    },
    {
        "name": "frida_inject",
        "description": "Inject a Frida JS script into the currently attached session.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "script": {"type": "string"},
                "config": {
                    "type": "object",
                    "description": "Posted as {'type':'config',…} after load (scripts using recv('config')).",
                },
            },
            "required": ["script"],
        },
    },
    {
        "name": "frida_read_output",
        "description": "Read buffered output from the active Frida session.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "frida_detach",
        "description": "Detach the current Frida session.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "frida_status",
        "description": (
            "No-op read: frida version, connected devices, frida-server "
            "responsiveness, and the current session state (package, "
            "script loaded, queued messages). Chain 'status → decide "
            "attach vs spawn'."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "objection_run",
        "description": "Run an objection command against a package.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "command": {"type": "string"},
            },
            "required": ["package", "command"],
        },
    },
    # ── Frida script library ───────────────────────────────────────────────
    {
        "name": "frida_list_scripts",
        "description": (
            "List built-in Frida JS scripts. Optional category filter.\n"
            "Categories: ssl_pinning, root_detection, frida_detection, "
            "crypto, memory, hooks, storage, network"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "description": "Filter by category (optional)",
                },
            },
        },
    },
    {
        "name": "frida_get_script",
        "description": "Retrieve the JS source of a named built-in Frida script.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Script name from frida_list_scripts"},
            },
            "required": ["name"],
        },
    },
    {
        "name": "frida_run_script",
        "description": (
            "Spawn a package and inject a named built-in script in one call.\n"
            "Use frida_list_scripts first to find the script_name."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "script_name": {"type": "string", "description": "Name from frida_list_scripts"},
                "config": {
                    "type": "object",
                    "description": "Posted as {'type':'config',…} after load (E-PY-6 protocol; shipped scripts re-scan on receipt).",
                },
            },
            "required": ["package", "script_name"],
        },
    },
    # ── Hluda / anti-detection spawn ──────────────────────────────────────
    {
        "name": "frida_spawn_hluda",
        "description": (
            "Spawn via hluda (StrongR-Frida) server which renames Frida internals,\n"
            "defeating port-scan and module-name RASP detection.\n"
            "Requires hluda frida-server pushed to device (use frida_server_push with hluda=true)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "script": {"type": "string", "description": "Frida JS script (optional)"},
                "port": {"type": "integer", "default": 27043, "description": "hluda listen port"},
            },
            "required": ["package"],
        },
    },
    {
        "name": "frida_server_push",
        "description": (
            "Find a local frida-server binary matching the installed frida-tools version\n"
            "and push it to the device via adb. Supports hluda variant."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "abi": {
                    "type": "string",
                    "enum": ["arm64", "arm", "x86_64", "x86"],
                    "default": "arm64",
                },
                "hluda": {
                    "type": "boolean",
                    "default": False,
                    "description": "Look for hluda binary instead of stock frida-server",
                },
                "remote_path": {
                    "type": "string",
                    "default": "/data/local/tmp/frida-server",
                },
            },
        },
    },
    # ── Memory operations ─────────────────────────────────────────────────
    {
        "name": "frida_memdump",
        "description": (
            "Dump all rw- memory regions from the running process to disk.\n"
            "Requires an active Frida session (call frida_attach first)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string", "description": "Package name (used for output folder)"},
                "output_dir": {"type": "string", "description": "Local path to dump to (optional)"},
            },
        },
    },
    {
        "name": "frida_find_bytes",
        "description": (
            "Search all rw- process memory for a UTF-8 string or hex byte pattern.\n"
            "Requires an active Frida session. Returns address, module, and 32-byte preview."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "search_string": {"type": "string", "description": "UTF-8 string to find"},
                "search_hex": {
                    "type": "string",
                    "description": "Hex bytes to find, e.g. 'deadbeef01020304'",
                },
                "max_results": {"type": "integer", "default": 20},
            },
        },
    },
    # ── Native library analysis — Gap #1 + #8 ────────────────────────────
    {
        "name": "native_strings",
        "description": (
            "Extract printable strings from a .so file or all .so libs in an APK.\n"
            "Falls back to pure-Python extraction on Windows (no `strings` binary needed)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "so_path": {"type": "string", "description": "Path to a .so file"},
                "apk_path": {"type": "string", "description": "Path to APK (extracts all .so)"},
                "abi": {"type": "string", "default": "arm64-v8a"},
                "min_len": {"type": "integer", "default": 8},
                "interesting_only": {"type": "boolean", "default": True,
                                     "description": "Filter to URLs, keys, long class names"},
            },
        },
    },
    {
        "name": "native_exports",
        "description": (
            "List exported symbols from a .so using readelf/nm.\n"
            "Falls back to pure ELF parser on Windows."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "so_path": {"type": "string"},
                "apk_path": {"type": "string"},
                "abi": {"type": "string", "default": "arm64-v8a"},
            },
        },
    },
    {
        "name": "native_disasm",
        "description": (
            "Disassemble a function or offset in a .so using radare2 (r2).\n"
            "Supports asm, graph, and pseudocode output modes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "so_path": {"type": "string"},
                "target": {"type": "string",
                           "description": "Symbol name or 0x<hex> offset to disassemble"},
                "n_instructions": {"type": "integer", "default": 32},
                "mode": {"type": "string", "enum": ["asm", "graph", "pseudocode"],
                         "default": "asm"},
            },
            "required": ["so_path", "target"],
        },
    },
    {
        "name": "il2cpp_dump",
        "description": (
            "Run Il2CppDumper on a Unity IL2CPP APK to recover class/method symbols.\n"
            "Extracts libil2cpp.so + global-metadata.dat then produces dump.cs + script.json."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "abi": {"type": "string", "default": "arm64-v8a"},
                "output_dir": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    # ── Flutter / Dart — Gap #2 ────────────────────────────────────────────
    {
        "name": "flutter_version",
        "description": (
            "Detect Flutter engine version and Dart SDK version from libflutter.so.\n"
            "Searches engine commit hash and cross-references with known SDK versions."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "so_path": {"type": "string", "description": "Direct path to libflutter.so"},
                "abi": {"type": "string", "default": "arm64-v8a"},
            },
        },
    },
    {
        "name": "dart_snapshot_info",
        "description": (
            "Identify Dart snapshot kind (AOT/JIT/AppJIT) and detect if ELF header was wiped\n"
            "(Zimperium zShield pattern). Run before blutter_extract."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "so_path": {"type": "string", "description": "Path to libapp.so"},
                "apk_path": {"type": "string"},
                "abi": {"type": "string", "default": "arm64-v8a"},
            },
        },
    },
    {
        "name": "blutter_extract",
        "description": (
            "Run Blutter on libapp.so to recover Dart class/method symbols.\n"
            "Produces ida_script.py + ghidra_script.py + asm/ + pp/ directories.\n"
            "Use dart_version arg to skip Blutter auto-detect if header is wiped."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "so_path": {"type": "string", "description": "Path to libapp.so"},
                "apk_path": {"type": "string"},
                "abi": {"type": "string", "default": "arm64-v8a"},
                "output_dir": {"type": "string"},
                "dart_version": {"type": "string",
                                  "description": "e.g. '3.1.0' — bypass Blutter auto-detect"},
            },
        },
    },
    # ── APK patching — Gap #6 ─────────────────────────────────────────────
    {
        "name": "smali_patch",
        "description": (
            "Patch a smali class file in an apktool-decompiled directory.\n"
            "Supports regex or literal replace, optionally scoped to a specific method.\n"
            "Call apk_rebuild_sign after patching."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "smali_dir": {"type": "string", "description": "apktool output directory"},
                "class_name": {"type": "string",
                               "description": "Java class name e.g. 'com.example.Security'"},
                "search": {"type": "string", "description": "String or regex to find"},
                "replace": {"type": "string", "description": "Replacement string"},
                "use_regex": {"type": "boolean", "default": False},
                "method_name": {"type": "string",
                                "description": "Restrict edit to this method only (optional)"},
            },
            "required": ["smali_dir", "class_name", "search", "replace"],
        },
    },
    {
        "name": "inject_gadget",
        "description": (
            "Embed frida-gadget into an APK and rebuild+sign it — full 6-step workflow:\n"
            "decompile → copy SO → write config → inject System.loadLibrary → rebuild → sign."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "abi": {"type": "string",
                        "enum": ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"],
                        "default": "arm64-v8a"},
                "gadget_path": {"type": "string",
                                "description": "Path to frida-gadget .so (optional — auto-detect)"},
                "gadget_config": {"type": "string",
                                  "description": "Frida gadget config JSON (optional)"},
                "output_apk": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    # ── Traffic reading — Gap #4 ──────────────────────────────────────────
    {
        "name": "mitm_read_flows",
        "description": (
            "Read captured mitmproxy flows as structured JSON.\n"
            "Optionally filter by URL substring or HTTP method."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "capture_path": {"type": "string",
                                 "description": "Path to .mitm file (defaults to active session)"},
                "filter_url": {"type": "string"},
                "filter_method": {"type": "string", "description": "e.g. 'POST'"},
                "max_flows": {"type": "integer", "default": 50},
            },
        },
    },
    {
        "name": "mitm_export_har",
        "description": (
            "Export mitmproxy capture to HAR format.\n"
            "Open in Chrome DevTools, Burp Suite, or Fiddler."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "capture_path": {"type": "string"},
                "output_path": {"type": "string"},
            },
        },
    },
    # ── Deep androguard — Gap #7 ──────────────────────────────────────────
    {
        "name": "analyze_code",
        "description": (
            "Cross-reference method calls across all classes using androguard.\n"
            "Filter by class prefix and/or method name substring."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "class_filter": {"type": "string",
                                 "description": "Java class prefix e.g. 'com.example'"},
                "method_filter": {"type": "string"},
                "max_results": {"type": "integer", "default": 100},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "find_crypto_usage",
        "description": (
            "Find all javax.crypto / java.security usages in the APK bytecode.\n"
            "Returns caller class+method and the crypto API referenced."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"apk_path": {"type": "string"}},
            "required": ["apk_path"],
        },
    },
    {
        "name": "find_urls",
        "description": (
            "Extract all hardcoded URLs, hostnames, and API endpoints from APK bytecode\n"
            "and assets. Categorises into api_endpoints and auth_endpoints."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "include_assets": {"type": "boolean", "default": True},
            },
            "required": ["apk_path"],
        },
    },
    # ── RASP assessment ────────────────────────────────────────────────────
    {
        "name": "rasp_identify",
        "description": (
            "Identify RASP SDK present in the APK "
            "(Guardsquare, Arxan, Promon, Zimperium, custom)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "rasp_bypass",
        "description": "Generate a Frida bypass script for an identified RASP protection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rasp_type": {
                    "type": "string",
                    "enum": ["guardsquare", "arxan", "promon", "zimperium", "custom"],
                },
                "protection": {
                    "type": "string",
                    "description": (
                        "Protection to bypass: root_detection, ssl_pinning, "
                        "frida_detection, integrity, emulator"
                    ),
                },
            },
            "required": ["rasp_type", "protection"],
        },
    },
    # ── Device control ─────────────────────────────────────────────────────
    {
        "name": "adb_devices",
        "description": "List connected ADB devices.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "adb_shell",
        "description": "Run a shell command on the connected device via ADB.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "serial": {"type": "string", "description": "Device serial (optional)"},
            },
            "required": ["command"],
        },
    },
    {
        "name": "adb_install",
        "description": "Install an APK on device via ADB.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
                "serial": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "adb_pull",
        "description": "Pull a file from the device to local disk.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "remote": {"type": "string"},
                "local": {"type": "string"},
                "serial": {"type": "string"},
            },
            "required": ["remote", "local"],
        },
    },
    {
        "name": "adb_push",
        "description": "Push a local file to the device.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "local": {"type": "string"},
                "remote": {"type": "string"},
                "serial": {"type": "string"},
            },
            "required": ["local", "remote"],
        },
    },
    {
        "name": "adb_logcat_start",
        "description": "Start capturing logcat output in a background thread.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "filter": {
                    "type": "string",
                    "description": "Logcat filter string, e.g. 'package:I *:S'",
                    "default": "*:V",
                },
                "serial": {"type": "string"},
            },
        },
    },
    {
        "name": "adb_logcat_read",
        "description": "Read buffered logcat lines.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "lines": {"type": "integer", "default": 100},
            },
        },
    },
    {
        "name": "adb_logcat_stop",
        "description": "Stop logcat capture and return final buffer.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "hermes_decode",
        "description": "Decode a React Native Hermes bytecode bundle (.hbc) using hermes-dec or hbctool.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string", "description": "Extracts bundle from APK if provided"},
                "bundle_path": {"type": "string", "description": "Path to the .bundle or .hbc file direct"},
                "output_dir": {"type": "string"},
            },
        },
    },
    {
        "name": "scrcpy_start",
        "description": "Start scrcpy to mirror the device UI and optionally record.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial": {"type": "string"},
                "bitrate": {"type": "integer", "default": 4},
                "max_fps": {"type": "integer", "default": 30},
                "record_file": {"type": "string", "description": "Path to save .mp4 recording"},
                "no_display": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "scrcpy_screenshot",
        "description": "Capture a UI screenshot from the device (returns local PNG path).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "serial": {"type": "string"},
                "output_path": {"type": "string", "description": "Optional custom local path"},
            },
        },
    },
    # ── Network ────────────────────────────────────────────────────────────
    {
        "name": "mitm_start",
        "description": "Start mitmproxy in transparent mode.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "default": 8080},
            },
        },
    },
    {
        "name": "mitm_stop",
        "description": "Stop mitmproxy and return the capture file path.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "ssl_kill_switch",
        "description": "Inject ssl-kill-switch2 Frida script to bypass SSL pinning.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
            },
            "required": ["package"],
        },
    },
    # ── Signing ────────────────────────────────────────────────────────────
    {
        "name": "apk_sign",
        "description": "Sign an APK with uber-apk-signer using config.toml [signing] settings.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "apk_path": {"type": "string"},
            },
            "required": ["apk_path"],
        },
    },
    {
        "name": "apk_rebuild_sign",
        "description": "Rebuild smali directory into APK then sign it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "smali_dir": {"type": "string", "description": "apktool output directory"},
            },
            "required": ["smali_dir"],
        },
    },
    # ── Memory ─────────────────────────────────────────────────────────────
    {
        "name": "memory_read",
        "description": "Read the per-target session memory file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
            },
            "required": ["package"],
        },
    },
    {
        "name": "memory_write",
        "description": "Write updated content to the per-target session memory file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "package": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["package", "content"],
        },
    },
    # ── Setup ──────────────────────────────────────────────────────────────
    {
        "name": "check_tools",
        "description": "Check availability of all required tools; returns structured JSON.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "install_tool",
        "description": "Attempt to install a missing tool.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string"},
            },
            "required": ["tool_name"],
        },
    },
]

# ---------------------------------------------------------------------------
# Resource definitions
# ---------------------------------------------------------------------------

RESOURCE_DEFS = [
    (
        "knowledge://detection-patterns",
        "detection-patterns.md",
        "Root, Frida, emulator, and integrity detection patterns + bypass counters",
    ),
    (
        "knowledge://bypass-playbooks",
        "bypass-playbooks.md",
        "SSL pinning, root, Frida, and RASP bypass escalation ladders",
    ),
    (
        "knowledge://framework-fingerprints",
        "framework-fingerprints.md",
        "Identify React Native, Flutter, Unity, Xamarin from APK artefacts",
    ),
    (
        "knowledge://crypto-patterns",
        "crypto-patterns.md",
        "Hardcoded keys, weak IV, and insecure cipher patterns",
    ),
    (
        "knowledge://common-mistakes",
        "common-mistakes.md",
        "Common mistakes made by junior pentesters on Android assessments",
    ),
]

# ---------------------------------------------------------------------------
# Prompt definitions
# ---------------------------------------------------------------------------

PROMPT_DEFS = [
    (
        "master-workflow",
        "MANDATORY: Master reasoning framework and step-by-step methodology for AI agents",
        "master-agent-workflow.md",
    ),
    (
        "first-look",
        "Ordered checklist for any new APK before running tools",
        "first-look.md",
    ),
    (
        "rasp-assess",
        "Full RASP assessment protocol step by step",
        "rasp-assess.md",
    ),
    (
        "bypass-ssl",
        "SSL pinning bypass escalation protocol",
        "bypass-ssl.md",
    ),
    (
        "bypass-root",
        "Root detection bypass escalation protocol",
        "bypass-root.md",
    ),
    (
        "bypass-frida",
        "Frida detection bypass escalation protocol",
        "bypass-frida.md",
    ),
    (
        "stuck",
        "Protocol for when a bypass attempt fails and you are blocked",
        "stuck.md",
    ),
]


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------


async def _run_tool(
    name: str,
    arguments: dict,
    dispatch: dict[str, Callable[..., object]],
    serial_pools: dict[int, ThreadPoolExecutor],
) -> CallToolResult:
    """Resolve and execute one tool call without blocking the event loop.

    * guard refusals → isError CallToolResult (never raised)
    * async handlers are awaited directly
    * sync handlers of stateless classes run on the default executor
      (``asyncio.to_thread``) — concurrent calls overlap freely
    * sync handlers of classes flagged ``_SERIALIZE`` (Dynamic/Network/
      Device: they own a Frida session, mitm process or logcat reader) run
      on a per-instance single-worker pool, so a second call queues
      instead of racing the first on shared state — same observable
      ordering as the old synchronous dispatch, minus the block
    """
    try:
        args = guard.validate(name, arguments)
    except guard.GuardError as exc:
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(
                {"status": "error", "tool": name, "error": f"refused: {exc}"}, indent=2))],
            isError=True,
        )

    handler = dispatch.get(name)
    if handler is None:
        result = {
            "status": "error",
            "tool": name,
            "error": f"Unknown tool: {name}",
        }
    else:
        try:
            if inspect.iscoroutinefunction(handler):
                result = await handler(args)
            else:
                bound_self = getattr(handler, "__self__", None)
                if getattr(bound_self, "_SERIALIZE", False):
                    pool = serial_pools.get(id(bound_self))
                    if pool is None:
                        pool = ThreadPoolExecutor(
                            max_workers=1, thread_name_prefix="mobile-re-serial"
                        )
                        serial_pools[id(bound_self)] = pool
                    result = await asyncio.get_running_loop().run_in_executor(
                        pool, handler, args
                    )
                else:
                    result = await asyncio.to_thread(handler, args)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Tool %s raised an exception", name)
            result = {
                "status": "error",
                "tool": name,
                "error": str(exc),
            }

    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(result, indent=2))]
    )


def create_server() -> Server:
    """Build and return a configured MCP Server instance."""

    server = Server("mobile-re-mcp-py", version=__version__)

    # Instantiate stateful handlers
    static = StaticHandler()
    dynamic = DynamicHandler()
    rasp = RaspHandler()
    device = DeviceHandler()
    network = NetworkHandler()
    signing = SigningHandler()
    memory = MemoryHandler()
    native = NativeHandler()
    flutter = FlutterHandler()
    patcher = PatcherHandler()

    # Dispatch table: tool_name → callable(args) → dict
    _dispatch: dict[str, object] = {
        # static
        "apk_decompile": static.apk_decompile,
        "apk_decompile_java": static.apk_decompile_java,
        "apk_identify": static.apk_identify,
        "apk_scan_secrets": static.apk_scan_secrets,
        "apk_analyze_full": static.apk_analyze_full,
        "quark_scan": static.quark_scan,
        "manifest_parse": static.manifest_parse,
        "search_strings": static.search_strings,
        # dynamic (original)
        "frida_spawn": dynamic.frida_spawn,
        "frida_attach": dynamic.frida_attach,
        "frida_inject": dynamic.frida_inject,
        "frida_read_output": dynamic.frida_read_output,
        "frida_detach": dynamic.frida_detach,
        "frida_status": dynamic.frida_status,
        "objection_run": dynamic.objection_run,
        # dynamic — script library
        "frida_list_scripts": dynamic.frida_list_scripts,
        "frida_get_script": dynamic.frida_get_script,
        "frida_run_script": dynamic.frida_run_script,
        # dynamic — hluda / anti-detection
        "frida_spawn_hluda": dynamic.frida_spawn_hluda,
        "frida_server_push": dynamic.frida_server_push,
        # dynamic — memory operations
        "frida_memdump": dynamic.frida_memdump,
        "frida_find_bytes": dynamic.frida_find_bytes,
        # rasp
        "rasp_identify": rasp.rasp_identify,
        "rasp_bypass": rasp.rasp_bypass,
        # device
        "adb_devices": device.adb_devices,
        "adb_shell": device.adb_shell,
        "adb_install": device.adb_install,
        "adb_pull": device.adb_pull,
        "adb_push": device.adb_push,
        "adb_logcat_start": device.adb_logcat_start,
        "adb_logcat_read": device.adb_logcat_read,
        "adb_logcat_stop": device.adb_logcat_stop,
        "hermes_decode": device.hermes_decode,
        "scrcpy_start": device.scrcpy_start,
        "scrcpy_screenshot": device.scrcpy_screenshot,
        # network
        "mitm_start": network.mitm_start,
        "mitm_stop": network.mitm_stop,
        "ssl_kill_switch": network.ssl_kill_switch,
        # signing
        "apk_sign": signing.apk_sign,
        "apk_rebuild_sign": signing.apk_rebuild_sign,
        # memory
        "memory_read": memory.memory_read,
        "memory_write": memory.memory_write,
        # static — deep androguard (Gap #7)
        "analyze_code": static.analyze_code,
        "find_crypto_usage": static.find_crypto_usage,
        "find_urls": static.find_urls,
        # native (Gap #1 + #8)
        "native_strings": native.native_strings,
        "native_exports": native.native_exports,
        "native_disasm": native.native_disasm,
        "il2cpp_dump": native.il2cpp_dump,
        # flutter (Gap #2)
        "flutter_version": flutter.flutter_version,
        "dart_snapshot_info": flutter.dart_snapshot_info,
        "blutter_extract": flutter.blutter_extract,
        # network — traffic reading (Gap #4)
        "mitm_read_flows": network.mitm_read_flows,
        "mitm_export_har": network.mitm_export_har,
        # patcher (Gap #6)
        "smali_patch": patcher.smali_patch,
        "inject_gadget": patcher.inject_gadget,
        # setup
        "check_tools": lambda _args: check_all_tools(),
        "install_tool": lambda args: _install_tool(args.get("tool_name", "")),
    }
    # One single-worker executor per stateful handler instance (F-PY-4):
    # dynamic (Frida session), network (mitm process), device (logcat).
    _serial_pools: dict[int, ThreadPoolExecutor] = {}

    # ── List tools ─────────────────────────────────────────────────────────

    @server.list_tools()
    async def list_tools() -> ListToolsResult:
        tools = [
            Tool(
                name=s["name"],
                description=s["description"],
                inputSchema=s["inputSchema"],
            )
            for s in TOOL_SCHEMAS
            if s["name"] not in guard.disabled_tools()
        ]
        return ListToolsResult(tools=tools)

    # ── Call tool ──────────────────────────────────────────────────────────

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> CallToolResult:
        return await _run_tool(name, arguments, _dispatch, _serial_pools)

    # ── List resources ─────────────────────────────────────────────────────

    @server.list_resources()
    async def list_resources() -> ListResourcesResult:
        resources = [
            Resource(uri=uri, name=filename, description=desc, mimeType="text/markdown")
            for uri, filename, desc in RESOURCE_DEFS
        ]
        return ListResourcesResult(resources=resources)

    # ── Read resource ──────────────────────────────────────────────────────

    @server.read_resource()
    async def read_resource(uri) -> str:
        uri = str(uri)
        match = next(
            ((u, f, d) for u, f, d in RESOURCE_DEFS if u == uri),
            None,
        )
        if match is None:
            raise ValueError(f"Unknown resource URI: {uri}")
        _uri, filename, _desc = match
        path = KNOWLEDGE_DIR / filename
        if not path.exists():
            text = f"# {filename}\n\n_Content not yet available._\n"
        else:
            text = path.read_text(encoding="utf-8")
        return text

    # ── List prompts ───────────────────────────────────────────────────────

    @server.list_prompts()
    async def list_prompts() -> ListPromptsResult:
        prompts = [
            Prompt(name=name, description=desc)
            for name, desc, _file in PROMPT_DEFS
        ]
        return ListPromptsResult(prompts=prompts)

    # ── Get prompt ─────────────────────────────────────────────────────────

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict | None) -> GetPromptResult:
        match = next((p for p in PROMPT_DEFS if p[0] == name), None)
        if match is None:
            raise ValueError(f"Unknown prompt: {name}")
        _name, desc, filename = match
        path = KNOWLEDGE_DIR / filename
        if path.exists():
            text = path.read_text(encoding="utf-8")
        else:
            text = f"# {name}\n\n_Prompt not yet implemented._\n"

        return GetPromptResult(
            description=desc,
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(type="text", text=text),
                )
            ],
        )

    # ── SSE helper ─────────────────────────────────────────────────────────

    async def run_stdio() -> None:
        from mcp.server.stdio import stdio_server

        async with stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                server.create_initialization_options(),
            )

    async def run_sse(host: str = "127.0.0.1", port: int = 8765) -> None:
        import hmac
        import os

        import uvicorn
        from mcp.server.sse import SseServerTransport
        from starlette.applications import Starlette
        from starlette.responses import PlainTextResponse, Response
        from starlette.routing import Mount, Route

        token = os.environ.get("MOBILE_RE_MCP_TOKEN", "")
        loopback = host in ("127.0.0.1", "::1", "localhost")
        if not loopback and not token:
            raise SystemExit(
                f"Refusing to listen on {host} without MOBILE_RE_MCP_TOKEN. "
                "This server can run adb and Frida commands."
            )

        try:
            from mcp.server.transport_security import TransportSecuritySettings

            hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"] + ([] if loopback else [f"{host}:*"])
            sse = SseServerTransport(
                "/messages/",
                security_settings=TransportSecuritySettings(
                    enable_dns_rebinding_protection=True,
                    allowed_hosts=hosts,
                    allowed_origins=["http://127.0.0.1:*", "http://localhost:*"],
                ),
            )
        except ImportError:
            sse = SseServerTransport("/messages/")

        async def handle_sse(request):  # noqa: ANN001
            async with sse.connect_sse(
                request.scope, request.receive, request._send  # type: ignore[attr-defined]
            ) as streams:
                await server.run(
                    streams[0], streams[1], server.create_initialization_options()
                )
            return Response()

        class BearerAuth:
            def __init__(self, app) -> None:  # noqa: ANN001
                self.app = app

            async def __call__(self, scope, receive, send) -> None:  # noqa: ANN001
                if token and scope["type"] == "http":
                    sent = dict(scope["headers"]).get(b"authorization", b"").decode()
                    if not hmac.compare_digest(sent, f"Bearer {token}"):
                        await PlainTextResponse("unauthorized", status_code=401)(scope, receive, send)
                        return
                await self.app(scope, receive, send)

        app = BearerAuth(
            Starlette(
                routes=[
                    Route("/sse", endpoint=handle_sse),
                    Mount("/messages/", app=sse.handle_post_message),
                ]
            )
        )
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        await uvicorn.Server(config).serve()

    # Attach transport helpers to the server object so __main__ can call them
    server.run_stdio = run_stdio  # type: ignore[attr-defined]
    server.run_sse = run_sse  # type: ignore[attr-defined]

    return server
