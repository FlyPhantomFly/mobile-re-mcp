"""
handlers/static.py — Static analysis handlers.

Tools: apk_decompile, apk_decompile_java, apk_identify,
       apk_scan_secrets, apk_analyze_full, manifest_parse, search_strings
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_TIMEOUT_DEFAULT = 120
_TIMEOUT_LONG = 300

_NOT_IMPL = {"status": "error", "error": "Handler not yet implemented"}


def _check_tool(name: str) -> bool:
    """Return True if *name* is available on PATH."""
    import shutil

    return shutil.which(name) is not None


def _missing(tool: str) -> dict:
    return {
        "status": "missing_tool",
        "tool": tool,
        "error": f"'{tool}' not found on PATH.",
        "hint": f"Run install_tool('{tool}') or see README for manual steps.",
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
        if not _check_tool("apkid"):
            return _missing("apkid")

        apk_path = args.get("apk_path", "")
        try:
            proc = subprocess.run(
                ["apkid", "--json", apk_path],
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
        if not _check_tool("apkleaks"):
            return _missing("apkleaks")

        apk_path = args.get("apk_path", "")
        out_json = str(Path(apk_path).with_suffix("")) + "_apkleaks.json"

        try:
            proc = subprocess.run(
                ["apkleaks", "-f", apk_path, "-o", out_json, "--json"],
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
        """[TOOL] Orchestrate all static tools, synthesise findings."""
        apk_path = args.get("apk_path", "")

        results: dict = {
            "status": "ok",
            "tool": "apk_analyze_full",
            "output": {
                "framework": None,
                "protection_tier": "unknown",
                "top_findings": [],
            },
        }

        # 1. apkid
        apkid_result = self.apk_identify({"apk_path": apk_path})
        results["output"]["apkid"] = apkid_result.get("output", {})

        # 2. apkleaks
        leaks_result = self.apk_scan_secrets({"apk_path": apk_path})
        results["output"]["secrets"] = leaks_result.get("output", {})

        # 3. manifest
        manifest_result = self.manifest_parse({"apk_path": apk_path})
        results["output"]["manifest"] = manifest_result.get("output", {})

        # Derive framework from apkid output
        apkid_out = apkid_result.get("output", {})
        framework = _derive_framework(apkid_out)
        results["output"]["framework"] = framework

        # Derive protection tier
        results["output"]["protection_tier"] = _derive_protection_tier(apkid_out, manifest_result)

        return results

    # ── manifest_parse ─────────────────────────────────────────────────────

    def manifest_parse(self, args: dict) -> dict:
        """[TOOL] Parse AndroidManifest.xml using androguard."""
        apk_path = args.get("apk_path", "")
        try:
            from androguard.core.apk import APK  # type: ignore[import]

            apk = APK(apk_path)
            exported_activities = [
                a for a in apk.get_activities() if apk.get_activity_is_exported(a)
            ]
            permissions = list(apk.get_permissions())
            dangerous_perms = [p for p in permissions if "DANGEROUS" in p or _is_dangerous(p)]

            return {
                "status": "ok",
                "tool": "androguard",
                "output": {
                    "package_name": apk.get_package(),
                    "version_name": apk.get_androidversion_name(),
                    "version_code": apk.get_androidversion_code(),
                    "min_sdk": apk.get_min_sdk_version(),
                    "target_sdk": apk.get_target_sdk_version(),
                    "exported_activities": exported_activities,
                    "exported_services": [
                        s for s in apk.get_services() if apk.get_declared_permissions_dict()
                    ],
                    "permissions": permissions,
                    "dangerous_permissions": dangerous_perms,
                    "debuggable": apk.get_attribute_value("application", "debuggable"),
                    "allow_backup": apk.get_attribute_value("application", "allowBackup"),
                    "network_security_config": apk.get_attribute_value(
                        "application", "networkSecurityConfig"
                    ),
                },
            }
        except ImportError:
            return _missing("androguard")
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

    # ── analyze_code (deep androguard) — Gap #7 ───────────────────────────

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
        try:
            from androguard.misc import AnalyzeAPK  # type: ignore[import]
        except ImportError:
            return {
                "status": "missing_tool", "tool": "androguard",
                "error": "androguard not installed", "hint": "pip install androguard",
            }

        apk_path = args.get("apk_path", "")
        class_filter = args.get("class_filter", "")
        method_filter = args.get("method_filter", "")
        max_results = int(args.get("max_results", 100))

        if not apk_path or not Path(apk_path).exists():
            return {"status": "error", "tool": "analyze_code",
                    "error": f"apk_path '{apk_path}' not found"}

        try:
            _, d, dx = AnalyzeAPK(apk_path)
            results: list[dict] = []

            for cls in dx.get_classes():
                class_name = cls.name.replace("/", ".").lstrip("L").rstrip(";")
                if class_filter and class_filter not in class_name:
                    continue

                for method in cls.get_methods():
                    m_name = method.name
                    if method_filter and method_filter.lower() not in m_name.lower():
                        continue

                    callers = [
                        str(c.class_name).replace("/", ".") + "." + str(c.name)
                        for c in method.get_xref_from()
                    ]
                    callees = [
                        str(c.class_name).replace("/", ".") + "." + str(c.name)
                        for c in method.get_xref_to()
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

    # ── find_crypto_usage — Gap #7 ────────────────────────────────────────

    def find_crypto_usage(self, args: dict) -> dict:
        """Find all javax.crypto / java.security usages in the APK bytecode.

        Returns class+method combinations that reference crypto APIs,
        along with argument types and constants (potential key material).

        Args:
            apk_path:   path to APK
        """
        try:
            from androguard.misc import AnalyzeAPK  # type: ignore[import]
        except ImportError:
            return {
                "status": "missing_tool", "tool": "androguard",
                "error": "androguard not installed", "hint": "pip install androguard",
            }

        apk_path = args.get("apk_path", "")
        if not apk_path or not Path(apk_path).exists():
            return {"status": "error", "tool": "find_crypto_usage",
                    "error": f"apk_path '{apk_path}' not found"}

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
            _, d, dx = AnalyzeAPK(apk_path)

            crypto_usages: list[dict] = []
            seen: set[str] = set()

            for cls in dx.get_classes():
                class_name = cls.name.replace("/", ".").lstrip("L").rstrip(";")
                # Skip the crypto classes themselves
                if any(api.replace("/", ".").lstrip("L") in class_name
                       for api in _CRYPTO_APIS):
                    continue

                for method in cls.get_methods():
                    for _, callee, _ in method.get_xref_to():
                        callee_cls = str(callee.class_name)
                        if callee_cls in _CRYPTO_APIS:
                            key = f"{class_name}:{method.name}:{callee_cls}"
                            if key not in seen:
                                seen.add(key)
                                crypto_usages.append({
                                    "caller_class": class_name,
                                    "caller_method": method.name,
                                    "crypto_api": _CRYPTO_APIS[callee_cls],
                                    "api_class": callee_cls.lstrip("L").rstrip(";").replace("/", "."),
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

    # ── find_urls — Gap #7 ────────────────────────────────────────────────

    def find_urls(self, args: dict) -> dict:
        """Extract all hardcoded URLs, hostnames, and API endpoints from APK bytecode.

        Uses androguard to scan string constants in all classes.

        Args:
            apk_path:       path to APK
            include_assets: also scan APK assets for URLs (default true)
        """
        try:
            from androguard.misc import AnalyzeAPK  # type: ignore[import]
        except ImportError:
            return {
                "status": "missing_tool", "tool": "androguard",
                "error": "androguard not installed", "hint": "pip install androguard",
            }

        import re as _re
        import zipfile as _zf

        apk_path = args.get("apk_path", "")
        include_assets = bool(args.get("include_assets", True))

        if not apk_path or not Path(apk_path).exists():
            return {"status": "error", "tool": "find_urls",
                    "error": f"apk_path '{apk_path}' not found"}

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
            _, d, dx = AnalyzeAPK(apk_path)

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


def _is_dangerous(perm: str) -> bool:
    return perm in _DANGEROUS_PERMS


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


def _derive_protection_tier(apkid_output: dict, manifest_result: dict) -> str:
    """Estimate protection tier from apkid + manifest analysis."""
    raw = str(apkid_output).lower()
    if any(k in raw for k in ["guardsquare", "dexguard", "arxan", "promon", "zimperium"]):
        return "enterprise"
    if any(k in raw for k in ["proguard", "r8", "obfuscator", "packer"]):
        return "standard"
    return "none"
