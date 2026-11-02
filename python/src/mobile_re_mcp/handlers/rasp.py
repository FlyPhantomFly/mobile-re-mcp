"""
handlers/rasp.py — RASP identification and bypass script generation.

Tools: rasp_identify, rasp_bypass
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# RASP signature database
# ---------------------------------------------------------------------------

# Maps RASP vendor → known package/class/library fingerprints
_RASP_SIGNATURES: dict[str, list[str]] = {
    "guardsquare": [
        "com.guardsquare",
        "com.saikoa.dexguard",
        "com.arxan",          # DexGuard also ships Arxan bundles sometimes
        "libdexguard",
        "libsgmain",          # Guardsquare SGX
    ],
    "arxan": [
        "com.arxan",
        "libarxan",
        "libguard",
    ],
    "promon": [
        "com.promon",
        "no.promon",
        "libshieldit",
    ],
    "zimperium": [
        "com.zimperium",
        "com.zdefend",
        "libzimperium",
        "libdisciplinesticky",  # zShield renamed lib
        "zshield",
    ],
}

# Maps RASP vendor + protection → Frida bypass script
_GS_ROOT = """\
// Guardsquare / DexGuard root detection bypass
Java.perform(function() {
    // Hook RootBeer if present
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() { return false; };
        RootBeer.isRootedWithoutBusyBox.implementation = function() { return false; };
        console.log("[BYPASS] RootBeer hooked");
    } catch(e) {}

    // Hook DexGuard's own attestation stub if it exists
    try {
        var DG = Java.use("com.saikoa.dexguard.runtime.RootDetection");
        DG.isDeviceRooted.implementation = function() { return false; };
        console.log("[BYPASS] DexGuard RootDetection hooked");
    } catch(e) {}
});
"""

# Maps RASP vendor + protection → Frida bypass script
_BYPASS_SCRIPTS: dict[str, dict[str, str]] = {
    "guardsquare": {
        "root_detection": _GS_ROOT,
        "ssl_pinning": """\
// Guardsquare SSL pinning bypass — OkHttp + TrustManager
Java.perform(function() {
    // OkHttp CertificatePinner
    try {
        var Pinner = Java.use("okhttp3.CertificatePinner");
        Pinner.check.overload("java.lang.String", "java.util.List").implementation = function() {
            console.log("[BYPASS] OkHttp CertificatePinner.check skipped");
        };
        Pinner["check$okhttp"].implementation = function() {
            console.log("[BYPASS] OkHttp CertificatePinner.check$okhttp skipped");
        };
    } catch(e) {}

    // Generic TrustManager bypass
    var TrustManager = Java.registerClass({
        name: "com.custom.UnpinnedTrustManager",
        implements: [Java.use("javax.net.ssl.X509TrustManager")],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.getDefault.implementation = function() { return ctx; };
    console.log("[BYPASS] TrustManager replaced");
});
""",
        "frida_detection": """\
// Generic Frida detection bypass (port scan + string checks)
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        if (path && (path.indexOf("frida") !== -1 || path.indexOf("gum-js") !== -1)) {
            args[0] = Memory.allocUtf8String("/proc/self/cmdline");
        }
    }
});
""",
        "integrity": """\
// Guardsquare integrity check bypass
Java.perform(function() {
    try {
        var IC = Java.use("com.guardsquare.runtime.IntegrityCheck");
        IC.verify.implementation = function() { return true; };
        console.log("[BYPASS] IntegrityCheck.verify hooked");
    } catch(e) {
        console.log("[INFO] IntegrityCheck class not found — may use native check");
    }
});
""",
    },
    "zimperium": {
        "root_detection": """\
// Zimperium zShield root detection bypass
Java.perform(function() {
    // zIAP / zDefend API stubs
    try {
        var zDef = Java.use("com.zimperium.zdefend.ZDefend");
        zDef.isRooted.implementation = function() { return false; };
        console.log("[BYPASS] Zimperium isRooted() hooked");
    } catch(e) {}
});

// Native: intercept libzimperium integrity checks
var libz = Process.findModuleByName("libzimperium.so") ||
           Process.findModuleByName("libdisciplinesticky.so");
if (libz) {
    var exports = libz.enumerateExports();
    exports.forEach(function(exp) {
        if (exp.name.indexOf("root") !== -1 || exp.name.indexOf("check") !== -1) {
            Interceptor.replace(exp.address, new NativeCallback(function() {
                console.log("[BYPASS] Native " + exp.name + " -> 0");
                return 0;
            }, "int", []));
        }
    });
}
""",
        "frida_detection": """\
// Zimperium anti-Frida bypass — use hluda (StrongR-Frida) server for best results
// This script patches the port scanner and /proc checks
var fopen = Module.findExportByName("libc.so", "fopen");
Interceptor.attach(fopen, {
    onEnter: function(args) {
        var p = args[0].readUtf8String();
        if (p && (p.indexOf("frida") !== -1 || p.indexOf("27042") !== -1)) {
            args[0] = Memory.allocUtf8String("/dev/null");
            console.log("[BYPASS] fopen frida path -> /dev/null");
        }
    }
});
""",
        "ssl_pinning": """\
// Zimperium SSL bypass (reuses generic OkHttp + native hook)
Java.perform(function() {
    try {
        var Pinner = Java.use("okhttp3.CertificatePinner");
        Pinner.check.overload("java.lang.String", "java.util.List").implementation = function() {};
        console.log("[BYPASS] OkHttp pinning disabled");
    } catch(e) {}
});
""",
    },
    "promon": {
        "root_detection": """\
// Promon Shield root bypass
Java.perform(function() {
    try {
        var P = Java.use("no.promon.shield.RootDetector");
        P.isRooted.implementation = function() { return false; };
        console.log("[BYPASS] Promon RootDetector.isRooted hooked");
    } catch(e) {}
});
""",
        "ssl_pinning": """\
// Promon Shield SSL bypass
Java.perform(function() {
    try {
        var Pinner = Java.use("okhttp3.CertificatePinner");
        Pinner.check.overload("java.lang.String","java.util.List").implementation = function() {};
    } catch(e) {}
    try {
        var TM = Java.use("no.promon.shield.tls.PromonTrustManager");
        TM.checkServerTrusted.implementation = function() {};
        console.log("[BYPASS] Promon TrustManager hooked");
    } catch(e) {}
});
""",
    },
    "arxan": {
        "integrity": """\
// Arxan integrity bypass — patches return value of integrity validation
Java.perform(function() {
    try {
        var A = Java.use("com.arxan.guardian.IntegrityVerification");
        A.verify.implementation = function() { return true; };
        console.log("[BYPASS] Arxan IntegrityVerification.verify hooked");
    } catch(e) {}
});
""",
    },
    "custom": {
        "root_detection": """\
// Generic root detection bypass
Java.perform(function() {
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        if (name && (name.indexOf("su") !== -1 || name.indexOf("magisk") !== -1)) {
            console.log("[BYPASS] File.exists blocked for: " + name);
            return false;
        }
        return this.exists();
    };
});
""",
        "ssl_pinning": """\
// Generic SSL pinning bypass via TrustManager replacement
Java.perform(function() {
    var TrustManager = Java.registerClass({
        name: "com.bypass.AllTrustManager",
        implements: [Java.use("javax.net.ssl.X509TrustManager")],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var ctx = SSLContext.getInstance("TLS");
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.getDefault.implementation = function() { return ctx; };
    console.log("[BYPASS] Generic TrustManager installed");
});
""",
        "frida_detection": """\
// Generic Frida detection bypass
Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
    onEnter: function(args) {
        var p = args[0].readUtf8String();
        if (p && p.indexOf("frida") !== -1) {
            args[0] = Memory.allocUtf8String("/dev/null");
        }
    }
});
""",
    },
}


class RaspHandler:
    """RASP identification and bypass script generator."""

    # ── rasp_identify ──────────────────────────────────────────────────────

    def rasp_identify(self, args: dict) -> dict:
        """Identify RASP SDK from APK artefacts using apkid + string grep."""
        apk_path = args.get("apk_path", "")
        detected: list[dict] = []

        # Strategy 1: string-scan the APK zip entries
        try:
            import zipfile

            with zipfile.ZipFile(apk_path) as zf:
                names_blob = " ".join(zf.namelist()).lower()
                for vendor, patterns in _RASP_SIGNATURES.items():
                    hits = [p for p in patterns if p.lower() in names_blob]
                    if hits:
                        detected.append(
                            {"vendor": vendor, "confidence": "high", "signals": hits}
                        )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ZIP scan failed: %s", exc)

        # Strategy 2: apkid output (if available)
        import shutil

        if shutil.which("apkid"):
            import subprocess

            try:
                proc = subprocess.run(
                    ["apkid", apk_path],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                output_lower = proc.stdout.lower()
                for vendor in _RASP_SIGNATURES:
                    if vendor in output_lower and not any(d["vendor"] == vendor for d in detected):
                        detected.append(
                            {"vendor": vendor, "confidence": "medium", "signals": ["apkid"]}
                        )
            except Exception as exc:  # noqa: BLE001
                logger.warning("apkid scan failed: %s", exc)

        protection_tier = "enterprise" if detected else "none"
        return {
            "status": "ok",
            "tool": "rasp_identify",
            "output": {
                "detected": detected,
                "protection_tier": protection_tier,
                "primary_rasp": detected[0]["vendor"] if detected else None,
            },
        }

    # ── rasp_bypass ────────────────────────────────────────────────────────

    def rasp_bypass(self, args: dict) -> dict:
        """Return a Frida bypass script for the identified RASP + protection."""
        rasp_type = args.get("rasp_type", "custom").lower()
        protection = args.get("protection", "root_detection").lower()

        vendor_scripts = _BYPASS_SCRIPTS.get(rasp_type, _BYPASS_SCRIPTS["custom"])
        script = vendor_scripts.get(protection)

        if script is None:
            # Fall back to generic custom bypass for this protection type
            script = _BYPASS_SCRIPTS["custom"].get(protection)

        if script is None:
            return {
                "status": "error",
                "tool": "rasp_bypass",
                "error": (
                    f"No bypass script for rasp_type='{rasp_type}' "
                    f"protection='{protection}'"
                ),
                "available_protections": list(vendor_scripts.keys()),
            }

        return {
            "status": "ok",
            "tool": "rasp_bypass",
            "output": {
                "rasp_type": rasp_type,
                "protection": protection,
                "script": script,
                "usage": (
                    "Save to bypass.js then: frida -U -f <package> -l bypass.js --no-pause"
                ),
            },
        }
