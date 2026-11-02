"""
frida_scripts/index.py — Script library index and loader.

Provides the script catalogue used by frida_list_scripts() and
frida_get_script() MCP tools. All scripts live as .js files in this
same package directory.
"""

from __future__ import annotations

from pathlib import Path

_SCRIPTS_DIR = Path(__file__).parent


def _script_dirs() -> list[Path]:
    """Folders searched for the catalogue's .js files: the user's own first, then the package."""
    from mobile_re_mcp.paths import data_dir

    return [data_dir() / "frida_scripts", _SCRIPTS_DIR]


def _find(file_name: str) -> Path | None:
    for d in _script_dirs():
        p = d / file_name
        if p.is_file():
            return p
    return None

# ---------------------------------------------------------------------------
# Script catalogue
# ---------------------------------------------------------------------------

SCRIPT_CATALOGUE: list[dict] = [
    {
        "name": "ssl_pinning_universal",
        "file": "ssl_pinning_universal.js",
        "category": "ssl_pinning",
        "description": "Universal SSL pinning bypass — OkHttp3/4, TrustKit, Conscrypt, native BoringSSL",
        "tags": ["ssl", "pinning", "okhttp", "trustkit", "conscrypt", "boring"],
        "usage": "frida -U -f <package> -l ssl_pinning_universal.js --no-pause",
    },
    {
        "name": "root_detection_bypass",
        "file": "root_detection_bypass.js",
        "category": "root_detection",
        "description": "Comprehensive root detection bypass — File.exists, Runtime.exec, PackageManager, Build props, RootBeer, native libc stat/access",
        "tags": ["root", "magisk", "supersu", "rootbeer", "libc"],
        "usage": "frida -U -f <package> -l root_detection_bypass.js --no-pause",
    },
    {
        "name": "frida_detection_bypass",
        "file": "frida_detection_bypass.js",
        "category": "frida_detection",
        "description": "Multi-layer Frida self-detection bypass — /proc/maps, port 27042, dlopen, strstr, debug flag",
        "tags": ["frida", "anti-detection", "port", "proc", "dlopen"],
        "usage": "Inject early via frida_spawn; combine with hluda server for RASP-hardened apps",
    },
    {
        "name": "crypto_monitor",
        "file": "crypto_monitor.js",
        "category": "crypto",
        "description": "Monitor all javax.crypto operations — log key material, IV, plaintext, ciphertext, HMAC, hash",
        "tags": ["crypto", "aes", "hmac", "sha", "key", "iv", "cipher"],
        "usage": "frida -U -f <package> -l crypto_monitor.js --no-pause",
    },
    {
        "name": "memory_scan",
        "file": "memory_scan.js",
        "category": "memory",
        "description": "Scan all rw- process memory regions for a UTF-8 string or hex byte pattern",
        "tags": ["memory", "scan", "bytes", "search", "heap"],
        "usage": "Inject then send config: {type:'config', search_string:'my_secret'} or search_hex:'deadbeef'",
    },
    {
        "name": "method_tracer",
        "file": "method_tracer.js",
        "category": "hooks",
        "description": "Trace all methods (or a specific one) on a Java class — log args and return values",
        "tags": ["trace", "hook", "java", "class", "method", "args"],
        "usage": "Inject then send config: {type:'config', class_name:'com.example.Foo', method_name:''}",
    },
    {
        "name": "storage_monitor",
        "file": "storage_monitor.js",
        "category": "storage",
        "description": "Monitor SharedPreferences writes, SQLite queries, FileInputStream/OutputStream, KeyStore",
        "tags": ["storage", "sharedprefs", "sqlite", "file", "keystore"],
        "usage": "frida -U -f <package> -l storage_monitor.js --no-pause",
    },
    {
        "name": "network_monitor",
        "file": "network_monitor.js",
        "category": "network",
        "description": "Monitor OkHttp requests/responses, HttpURLConnection, WebView.loadUrl, DNS lookups",
        "tags": ["network", "http", "okhttp", "webview", "dns", "request"],
        "usage": "frida -U -f <package> -l network_monitor.js --no-pause",
    },
]

_CATALOGUE_BY_NAME: dict[str, dict] = {s["name"]: s for s in SCRIPT_CATALOGUE}
_CATALOGUE_BY_CATEGORY: dict[str, list[dict]] = {}
for _s in SCRIPT_CATALOGUE:
    _CATALOGUE_BY_CATEGORY.setdefault(_s["category"], []).append(_s)


def list_scripts(category: str | None = None) -> list[dict]:
    """Script metadata for scripts that exist on disk, optionally filtered by category."""
    pool = _CATALOGUE_BY_CATEGORY.get(category.lower(), []) if category else SCRIPT_CATALOGUE
    return [m for m in pool if _find(m["file"]) is not None]


def get_categories() -> list[str]:
    """Return all categories that have at least one available script."""
    return sorted({m["category"] for m in list_scripts()})


def get_script_content(name: str) -> str | None:
    """Load and return the JS source for a named script, or None if not found."""
    path = get_script_path(name)
    return path.read_text(encoding="utf-8") if path else None


def get_script_path(name: str) -> Path | None:
    """Return the absolute path to a named script file."""
    meta = _CATALOGUE_BY_NAME.get(name)
    return _find(meta["file"]) if meta else None
