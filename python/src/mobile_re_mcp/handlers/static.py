"""
handlers/static.py — Static analysis handlers.

Tools: apk_decompile, apk_decompile_java, apk_identify, apk_scan_secrets,
       apk_analyze_full, manifest_parse, search_strings,
       analyze_code, find_crypto_usage, find_urls

Built against androguard 4.1.x; the xref helpers tolerate the shapes that
3.x returned as well (see _xref_names), so both versions keep working.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from mobile_re_mcp.clitools import find_cli as _find_cli

logger = logging.getLogger(__name__)

_TIMEOUT_DEFAULT = 120
_TIMEOUT_LONG = 300


def _check_tool(name: str) -> bool:
    """Return True if *name* is available on PATH."""
    import shutil

    return shutil.which(name) is not None


def _missing(tool: str) -> dict:
    return {
        "status": "missing_tool",
        "tool": tool,
        "error": f"'{tool}' not found on PATH.",
        "hint": f"Run mobile-re-mcp-py --setup, or install '{tool}' yourself.",
    }


def _not_found(tool: str, apk_path: str) -> dict:
    return {
        "status": "error",
        "tool": tool,
        "error": f"apk_path '{apk_path}' not found",
    }


class StaticHandler:
    """Stateless static analysis handler."""

    # ── apk_decompile ──────────────────────────────────────────────────────

    def apk_decompile(self, args: dict) -> dict:
        """[TOOL] apktool decompile."""
        if not _check_tool("apktool"):
            return _missing("apktool")

        apk_path = args.get("apk_path", "")
        mode = args.get("mode", "full")
        out_dir = str(Path(apk_path).with_suffix("")) + "_apktool"

        cmd = ["apktool", "d", apk_path, "-o", out_dir, "-f"]
        if mode == "resources_only":
            cmd += ["--no-src"]
        elif mode == "smali_only":
            cmd += ["--no-res"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_LONG,
            )
            if proc.returncode == 0:
                return {
                    "status": "ok",
                    "tool": "apktool",
                    "output": {"out_dir": out_dir, "mode": mode},
                    "raw": proc.stdout,
                }
            return {
                "status": "error",
                "tool": "apktool",
                "error": proc.stderr or proc.stdout,
                "raw": proc.stdout,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "apktool", "error": "Timeout after 300s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "apktool", "error": str(exc)}

    # ── apk_decompile_java ─────────────────────────────────────────────────

    def apk_decompile_java(self, args: dict) -> dict:
        """[TOOL] jadx decompile to Java."""
        if not _check_tool("jadx"):
            return _missing("jadx")

        apk_path = args.get("apk_path", "")
        out_dir = str(Path(apk_path).with_suffix("")) + "_jadx"

        try:
            proc = subprocess.run(
                ["jadx", "-d", out_dir, apk_path],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_LONG,
            )
            if proc.returncode == 0:
                return {
                    "status": "ok",
                    "tool": "jadx",
                    "output": {"out_dir": out_dir},
                    "raw": proc.stdout,
                }
            return {
                "status": "error",
                "tool": "jadx",
                "error": proc.stderr or proc.stdout,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "jadx", "error": "Timeout after 300s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "jadx", "error": str(exc)}

    # ── apk_identify ───────────────────────────────────────────────────────

    def apk_identify(self, args: dict) -> dict:
        """[TOOL] apkid — identify packers and obfuscators."""
        apkid_cli = _find_cli("apkid")
        if apkid_cli is None:
            return _missing("apkid")

        apk_path = args.get("apk_path", "")
        try:
            proc = subprocess.run(
                [apkid_cli, "--json", apk_path],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_DEFAULT,
            )
            try:
                parsed = json.loads(proc.stdout)
            except json.JSONDecodeError:
                parsed = {"raw_output": proc.stdout}

            return {
                "status": "ok",
                "tool": "apkid",
                "output": parsed,
                "raw": proc.stdout,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "apkid", "error": "Timeout after 120s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "apkid", "error": str(exc)}

    # ── apk_scan_secrets ───────────────────────────────────────────────────

    def apk_scan_secrets(self, args: dict) -> dict:
        """[TOOL] apkleaks — scan for hardcoded secrets."""
        apkleaks_cli = _find_cli("apkleaks")
        if apkleaks_cli is None:
            return _missing("apkleaks")

        apk_path = args.get("apk_path", "")
        out_json = str(Path(apk_path).with_suffix("")) + "_apkleaks.json"

        try:
            proc = subprocess.run(
                [apkleaks_cli, "-f", apk_path, "-o", out_json, "--json"],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_LONG,
            )
            try:
                with open(out_json) as fh:
                    findings = json.load(fh)
            except (FileNotFoundError, json.JSONDecodeError):
                findings = {"raw_output": proc.stdout}

            return {
                "status": "ok",
                "tool": "apkleaks",
                "output": {"findings": findings, "report_path": out_json},
                "raw": proc.stdout,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "apkleaks", "error": "Timeout after 300s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "apkleaks", "error": str(exc)}

    # ── apk_analyze_full ───────────────────────────────────────────────────

    def apk_analyze_full(self, args: dict) -> dict:
        """[TOOL] Orchestrate all static tools, synthesise findings.

        Children run one after the other; a child that fails no longer
        disappears into the output — its status is reported per tool and the
        overall result is "degraded" (some stages failed) or "error" (all of
        them failed) instead of a masked "ok".
        """
        apk_path = args.get("apk_path", "")
        if not apk_path or not Path(apk_path).exists():
            return _not_found("apk_analyze_full", apk_path)

        stages = [
            ("apkid", "apkid", self.apk_identify, {"apk_path": apk_path}),
            ("apkleaks", "secrets", self.apk_scan_secrets, {"apk_path": apk_path}),
            ("manifest", "manifest", self.manifest_parse, {"apk_path": apk_path}),
        ]

        tool_statuses: dict[str, str] = {}
        tool_errors: dict[str, str] = {}
        stage_outputs: dict[str, dict] = {"apkid": {}, "secrets": {}, "manifest": {}}
        manifest_result: dict = {}

        for label, output_key, fn, kw in stages:
            result = fn(kw)
            status = str(result.get("status", "error"))
            tool_statuses[label] = status
            if status == "ok":
                stage_outputs[output_key] = result.get("output", {}) or {}
                if label == "manifest":
                    manifest_result = result
            else:
                tool_errors[label] = str(result.get("error", "failed"))

        ok_count = sum(1 for s in tool_statuses.values() if s == "ok")
        if ok_count == len(stages):
            status = "ok"
        elif ok_count == 0:
            status = "error"
        else:
            status = "degraded"

        apkid_out = stage_outputs.get("apkid", {})
        analysis: dict = {
            "framework": _derive_framework(apkid_out),
            "protection_tier": _derive_protection_tier(apkid_out, manifest_result),
            "top_findings": _top_findings(stage_outputs),
            "apkid": stage_outputs["apkid"],
            "secrets": stage_outputs["secrets"],
            "manifest": stage_outputs["manifest"],
            "tool_statuses": tool_statuses,
        }
        if tool_errors:
            analysis["errors"] = tool_errors

        return {
            "status": status,
            "tool": "apk_analyze_full",
            "output": analysis,
            **({"error": "; ".join(f"{k}: {v}" for k, v in tool_errors.items())}
               if tool_errors else {}),
        }

    # ── manifest_parse ─────────────────────────────────────────────────────

    def manifest_parse(self, args: dict) -> dict:
        """[TOOL] Parse AndroidManifest.xml using androguard.

        Components are resolved straight from the manifest XML, which also
        flags components that are exported *by default*: an activity, service
        or receiver carrying an intent filter under targetSdk < 31, and
        providers on pre-17 SDK levels (auto-exported without an explicit
        android:exported attribute).
        """
        apk_path = args.get("apk_path", "")
        if not apk_path or not Path(apk_path).exists():
            return _not_found("manifest_parse", apk_path)

        loaded = _load_androguard()
        if loaded is None:
            return _missing("androguard")
        APK = loaded[0]

        try:
            apk = APK(apk_path)
            components = _component_entries(apk)

            exported_names: dict[str, list[str]] = {
                "activity": [], "activity-alias": [], "service": [],
                "receiver": [], "provider": [],
            }
            for comp in components:
                if comp["exported"]:
                    exported_names[comp["type"]].append(comp["name"])

            permissions = list(apk.get_permissions())
            output = {
                "package_name": str(apk.get_package()),
                "version_name": apk.get_androidversion_name(),
                "version_code": apk.get_androidversion_code(),
                "min_sdk": _as_int(apk.get_min_sdk_version()),
                "target_sdk": _as_int(apk.get_target_sdk_version()),
                "debuggable": _as_bool(
                    apk.get_attribute_value("application", "debuggable")
                ),
                "allow_backup": _as_bool(
                    apk.get_attribute_value("application", "allowBackup")
                ),
                "network_security_config": apk.get_attribute_value(
                    "application", "networkSecurityConfig"
                ),
                "permissions": permissions,
                "dangerous_permissions": [p for p in permissions if _is_dangerous(p)],
                "exported_activities": exported_names["activity"]
                + exported_names["activity-alias"],
                "exported_services": exported_names["service"],
                "exported_receivers": exported_names["receiver"],
                "exported_providers": exported_names["provider"],
                "exported_components": sorted(
                    comp["name"] for comp in components if comp["exported"]
                ),
                "components": components,
            }
            return {
                "status": "ok",
                "tool": "androguard",
                "output": output,
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "androguard", "error": str(exc)}

    # ── search_strings ─────────────────────────────────────────────────────

    def search_strings(self, args: dict) -> dict:
        """[TOOL] ripgrep search across decompiled output."""
        if not _check_tool("rg"):
            return _missing("rg (ripgrep)")

        path = args.get("path", "")
        pattern = args.get("pattern", "")

        try:
            proc = subprocess.run(
                ["rg", "--json", "-e", pattern, "--", path],
                capture_output=True,
                text=True,
                timeout=_TIMEOUT_DEFAULT,
            )
            matches = []
            for line in proc.stdout.splitlines():
                try:
                    obj = json.loads(line)
                    if obj.get("type") == "match":
                        matches.append(
                            {
                                "file": obj["data"]["path"]["text"],
                                "line": obj["data"]["line_number"],
                                "text": obj["data"]["lines"]["text"].rstrip("\n"),
                            }
                        )
                except (json.JSONDecodeError, KeyError):
                    continue

            return {
                "status": "ok",
                "tool": "ripgrep",
                "output": {"matches": matches, "total": len(matches)},
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "ripgrep", "error": "Timeout after 120s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "ripgrep", "error": str(exc)}

    # ── analyze_code — cross-reference search over the call graph ─────────

    def analyze_code(self, args: dict) -> dict:
        """Cross-reference method calls across all classes in an APK.

        Uses androguard to build a call graph and find callers/callees
        for a target method or class pattern.

        Args:
            apk_path:       path to APK
            class_filter:   Java class prefix to focus on (e.g. "com.example")
            method_filter:  method name substring to find
            max_results:    max methods to return (default 100)
        """
        apk_path = args.get("apk_path", "")
        if not apk_path or not Path(apk_path).exists():
            return _not_found("analyze_code", apk_path)

        if _load_androguard() is None:
            return _missing("androguard")

        class_filter = args.get("class_filter", "")
        method_filter = args.get("method_filter", "")
        try:
            max_results = int(args.get("max_results", 100))
        except (TypeError, ValueError):
            max_results = 100

        try:
            _apk, _dex, dx = _analyze_apk(apk_path)
            results: list[dict] = []

            for cls in dx.get_classes():
                class_name = _clean_class_name(getattr(cls, "name", cls))
                if class_filter and class_filter not in class_name:
                    continue

                for method in cls.get_methods():
                    m_name = str(method.name)
                    if method_filter and method_filter.lower() not in m_name.lower():
                        continue

                    callers = [
                        _format_ref(*_xref_names(ref))
                        for ref in method.get_xref_from()
                    ]
                    callees = [
                        _format_ref(*_xref_names(ref))
                        for ref in method.get_xref_to()
                    ]
                    results.append({
                        "class": class_name,
                        "method": m_name,
                        "callers": callers[:20],
                        "callees": callees[:20],
                    })

                    if len(results) >= max_results:
                        break

                if len(results) >= max_results:
                    break

            return {
                "status": "ok",
                "tool": "analyze_code",
                "output": {
                    "total": len(results),
                    "class_filter": class_filter,
                    "method_filter": method_filter,
                    "methods": results,
                },
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "analyze_code", "error": str(exc)}

    # ── find_crypto_usage — call-graph scan for crypto API call sites ─────

    def find_crypto_usage(self, args: dict) -> dict:
        """Find all javax.crypto / java.security usages in the APK bytecode.

        Returns class+method combinations that reference crypto APIs,
        along with argument types and constants (potential key material).

        Args:
            apk_path:   path to APK
        """
        apk_path = args.get("apk_path", "")
        if not apk_path or not Path(apk_path).exists():
            return _not_found("find_crypto_usage", apk_path)

        if _load_androguard() is None:
            return _missing("androguard")

        _CRYPTO_APIS = {
            "Ljavax/crypto/Cipher;": "Cipher",
            "Ljavax/crypto/Mac;": "Mac/HMAC",
            "Ljavax/crypto/SecretKeySpec;": "SecretKeySpec",
            "Ljavax/crypto/KeyGenerator;": "KeyGenerator",
            "Ljava/security/MessageDigest;": "MessageDigest",
            "Ljava/security/KeyStore;": "KeyStore",
            "Ljava/security/SecureRandom;": "SecureRandom",
            "Landroid/security/keystore/KeyGenParameterSpec;": "AndroidKeystore",
            "Ljavax/net/ssl/TrustManagerFactory;": "TrustManagerFactory",
            "Ljavax/net/ssl/SSLContext;": "SSLContext",
            "Lokhttp3/CertificatePinner;": "OkHttp-CertPinner",
        }

        try:
            _apk, _dex, dx = _analyze_apk(apk_path)

            crypto_usages: list[dict] = []
            seen: set[str] = set()

            # Crypto classes themselves are not call sites of interest.
            crypto_classes = {
                _clean_class_name(api) for api in _CRYPTO_APIS
            }

            for cls in dx.get_classes():
                class_name = _clean_class_name(getattr(cls, "name", cls))
                if class_name in crypto_classes:
                    continue

                for method in cls.get_methods():
                    for ref in method.get_xref_to():
                        callee_cls, _callee_meth = _xref_names(ref)
                        if callee_cls in _CRYPTO_APIS:
                            key = f"{class_name}:{method.name}:{callee_cls}"
                            if key not in seen:
                                seen.add(key)
                                crypto_usages.append({
                                    "caller_class": class_name,
                                    "caller_method": str(method.name),
                                    "crypto_api": _CRYPTO_APIS[callee_cls],
                                    "api_class": _clean_class_name(callee_cls),
                                })

            return {
                "status": "ok",
                "tool": "find_crypto_usage",
                "output": {
                    "total_usages": len(crypto_usages),
                    "usages": crypto_usages,
                    "summary": {
                        api: sum(1 for u in crypto_usages if u["crypto_api"] == api)
                        for api in set(u["crypto_api"] for u in crypto_usages)
                    },
                },
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "find_crypto_usage", "error": str(exc)}

    # ── find_urls — call-graph scan for crypto API call sites ─────────────

    def find_urls(self, args: dict) -> dict:
        """Extract all hardcoded URLs, hostnames, and API endpoints from APK bytecode.

        Uses androguard to scan string constants in all classes.

        Args:
            apk_path:       path to APK
            include_assets: also scan APK assets for URLs (default true)
        """
        import re as _re
        import zipfile as _zf

        apk_path = args.get("apk_path", "")
        include_assets = bool(args.get("include_assets", True))

        if not apk_path or not Path(apk_path).exists():
            return _not_found("find_urls", apk_path)

        if _load_androguard() is None:
            return _missing("androguard")

        _URL_RE = _re.compile(
            r"https?://[^\s\"'<>)\]]+|"
            r"wss?://[^\s\"'<>)\]]+|"
            r"[\w\-]+\.(?:com|io|net|org|co|dev|app|api|cloud|online|info|biz)"
            r"(?:/[^\s\"'<>)\]]*)?",
            _re.IGNORECASE
        )

        urls_from_code: set[str] = set()
        urls_from_assets: set[str] = set()

        try:
            _apk, _dex, dx = _analyze_apk(apk_path)

            # Scan all string constants in bytecode
            for cls in dx.get_classes():
                for method in cls.get_methods():
                    try:
                        for instruction in method.get_method().get_instructions():
                            if hasattr(instruction, "get_string"):
                                s = instruction.get_string()
                                if s and ("http" in s or "://" in s or "." in s):
                                    for match in _URL_RE.findall(s):
                                        if len(match) > 6:
                                            urls_from_code.add(match.rstrip(".,;"))
                    except Exception:  # noqa: BLE001
                        continue

            # Also scan string resources using AnalyzeAPK's string_analysis
            for s, _ in dx.get_strings_analysis().items():
                if s and ("http" in s or "://" in s):
                    for match in _URL_RE.findall(s):
                        if len(match) > 6:
                            urls_from_code.add(match.rstrip(".,;"))

        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "find_urls", "error": str(exc)}

        # Scan APK assets (JSON configs, XML, plain text)
        if include_assets:
            try:
                with _zf.ZipFile(apk_path) as zfile:
                    for name in zfile.namelist():
                        if name.startswith("assets/") and not name.endswith(".so"):
                            try:
                                text = zfile.read(name).decode("utf-8", errors="ignore")
                                for match in _URL_RE.findall(text):
                                    if len(match) > 6:
                                        urls_from_assets.add(match.rstrip(".,;"))
                            except Exception:  # noqa: BLE001
                                continue
            except Exception:  # noqa: BLE001
                pass

        all_urls = sorted(urls_from_code | urls_from_assets)

        # Categorise
        api_endpoints = [u for u in all_urls if "/api/" in u or "/v1/" in u or "/v2/" in u or "/graphql" in u]
        auth_endpoints = [u for u in all_urls if any(k in u.lower() for k in
                          ["login", "auth", "token", "oauth", "sso", "sign"])]

        return {
            "status": "ok",
            "tool": "find_urls",
            "output": {
                "total": len(all_urls),
                "from_bytecode": len(urls_from_code),
                "from_assets": len(urls_from_assets),
                "all_urls": all_urls,
                "api_endpoints": api_endpoints,
                "auth_endpoints": auth_endpoints,
            },
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

_DANGEROUS_PERMS = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
}


def _load_androguard():
    """Import androguard lazily, silencing its loguru DEBUG chatter.

    Returns ``(APK, AnalyzeAPK)`` on success, ``None`` when the extra is
    not installed.
    """
    try:
        from loguru import logger as _loguru  # type: ignore[import-not-found]

        _loguru.disable("androguard")
    except ImportError:
        pass
    try:
        from androguard.core.apk import APK  # type: ignore[import-not-found]
        from androguard.misc import AnalyzeAPK  # type: ignore[import-not-found]
    except ImportError:
        return None
    return APK, AnalyzeAPK


def _analyze_apk(apk_path: str):
    """Return ``(apk, dex, dx)`` from AnalyzeAPK.

    Kept module-level so tests can substitute a fake analysis without
    touching androguard. dex is a single DEX object on 3.x and a list of
    them on 4.x; handlers only need ``dx``.
    """
    loaded = _load_androguard()
    if loaded is None:
        raise ImportError("androguard is not installed")
    _APK, AnalyzeAPK = loaded
    return AnalyzeAPK(apk_path)


def _is_dangerous(perm: str) -> bool:
    return perm in _DANGEROUS_PERMS


def _as_bool(value: object) -> bool | None:
    """Manifest 'true'/'false'/bool into Python bool; None stays None."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1")


def _as_int(value: object) -> int | None:
    """SDK levels arrive as ints on 3.x and strings on 4.x — normalise."""
    try:
        return int(str(value)) if value is not None else None
    except (TypeError, ValueError):
        return None


def _clean_class_name(lform: object) -> str:
    """'Lcom/example/Foo;' → 'com.example.Foo' (L-prefix form tolerated)."""
    return str(lform).replace("/", ".").lstrip("L").rstrip(";")


def _format_ref(cls_name: object, meth_name: object) -> str:
    """One xref record → 'com.example.Caller.caller' style string."""
    class_name = _clean_class_name(cls_name) if cls_name is not None else ""
    method_name = str(meth_name) if meth_name is not None else ""
    if class_name and method_name:
        return f"{class_name}.{method_name}"
    return class_name or method_name


def _obj_name(obj: object) -> str:
    """Best-effort name of an androguard analysis object (or plain string)."""
    if obj is None:
        return ""
    if isinstance(obj, str):
        return obj
    name = getattr(obj, "name", None)
    if name is None:
        name = getattr(obj, "class_name", None)
    return str(name) if name is not None else str(obj)


def _xref_names(item: object) -> tuple[str, str]:
    """One call-graph record → (owner_class_Lform, owner_method_name).

    androguard changed the shape of ``get_xref_from()``/``get_xref_to()``
    between versions:

    * 4.x: set of ``(ClassAnalysis, MethodAnalysis, offset)`` 3-tuples,
      where the ``from`` items name the *caller* and ``to`` items the
      *callee*.
    * 3.x minors: ``(cls, meth)`` 2-tuples or plain method-analysis objects
      carrying ``class_name``/``name`` attributes.

    This shim understands all of them, so the tools work with either.
    """
    if isinstance(item, (tuple, list)):
        cls = item[0] if len(item) > 0 else None
        meth = item[1] if len(item) > 1 else None
        return _obj_name(cls), _obj_name(meth)
    cls = getattr(item, "class_name", None)
    if cls is None and hasattr(item, "get_class_name"):
        try:
            cls = item.get_class_name()
        except Exception:  # noqa: BLE001
            cls = None
    return _obj_name(cls), _obj_name(item)


def _resolve_component_name(name: object, package: str) -> str:
    """Android component-name shorthand → fully-qualified name."""
    name = str(name or "")
    if not name:
        return ""
    if name.startswith("."):
        return f"{package}{name}"
    if "." not in name:
        return f"{package}.{name}"
    return name


def _component_entries(apk) -> list[dict]:
    """All manifest components with their resolved exported state.

    ``exported`` is authoritative; ``exported_mode`` explains *why*:

    * ``explicit``            — android:exported given, value wins
    * ``auto-intent-filter``  — no attribute, has intent filter, targetSdk < 31
    * ``auto-pre-17``         — provider with targetSdk < 17 (auto-exported)
    * ``default-false``       — no attribute and no default that makes it exported
    """
    try:
        root = apk.get_android_manifest_xml()
        package = str(apk.get_package())
        target_sdk = int(apk.get_target_sdk_version() or 0)
        min_sdk = int(apk.get_min_sdk_version() or 0)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"cannot read manifest: {exc}") from exc

    app_el = root.find("application")
    if app_el is None:
        return []

    entries: list[dict] = []
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in app_el.findall(tag):
            name = _resolve_component_name(el.get(_ANDROID_NS + "name"), package)
            if not name:
                continue
            has_filter = el.find("intent-filter") is not None
            explicit = el.get(_ANDROID_NS + "exported")
            if explicit is not None:
                exported, mode = _as_bool(explicit) or False, "explicit"
            elif tag == "provider":
                exported = min_sdk < 17 or target_sdk < 17
                mode = "auto-pre-17" if exported else "default-false"
            else:
                exported = has_filter and target_sdk < 31
                mode = "auto-intent-filter" if exported else "default-false"
            entries.append({
                "name": name,
                "type": tag,
                "exported": exported,
                "exported_mode": mode,
                "has_intent_filter": has_filter,
            })
    return entries


def _top_findings(stage_outputs: dict) -> list[str]:
    """Short, human-readable summary lines from whichever stages succeeded."""
    findings: list[str] = []
    manifest_out = stage_outputs.get("manifest", {})
    if manifest_out:
        if manifest_out.get("debuggable"):
            findings.append("App is debuggable")
        exported = manifest_out.get("exported_components", [])
        if exported:
            findings.append(f"{len(exported)} exported component(s)")
        dangerous = manifest_out.get("dangerous_permissions", [])
        if dangerous:
            findings.append(f"{len(dangerous)} dangerous permission(s)")
    secrets_out = stage_outputs.get("secrets", {})
    findings_dict = secrets_out.get("findings", {})
    if isinstance(findings_dict, dict):
        count = sum(len(v) if isinstance(v, list) else 1 for v in findings_dict.values())
        if count:
            findings.append(f"{count} hardcoded secret(s)")
    return findings


def _derive_framework(apkid_output: dict) -> str | None:
    """Best-effort framework identification from apkid output."""
    raw = str(apkid_output).lower()
    if "flutter" in raw:
        return "Flutter"
    if "react native" in raw or "libreactnativejni" in raw:
        return "React Native"
    if "unity" in raw:
        return "Unity"
    if "xamarin" in raw:
        return "Xamarin"
    return "Native (Java/Kotlin)"


def _derive_protection_tier(apkid_output: dict, manifest_result: dict | None = None) -> str:
    """Estimate protection tier from apkid + manifest analysis."""
    del manifest_result  # kept for future manifest-based signals
    raw = str(apkid_output).lower()
    if any(k in raw for k in ["guardsquare", "dexguard", "arxan", "promon", "zimperium"]):
        return "enterprise"
    if any(k in raw for k in ["proguard", "r8", "obfuscator", "packer"]):
        return "standard"
    return "none"
