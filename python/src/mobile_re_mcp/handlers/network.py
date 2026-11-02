"""
handlers/network.py — Network interception handlers.

Tools: mitm_start, mitm_stop, ssl_kill_switch, mitm_read_flows, mitm_export_har
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from mobile_re_mcp.paths import captures_dir

logger = logging.getLogger(__name__)


def _check_tool(name: str) -> bool:
    import shutil

    return shutil.which(name) is not None


def _missing(tool: str) -> dict:
    return {
        "status": "missing_tool",
        "tool": tool,
        "error": f"'{tool}' not found. Run mobile-re-mcp-py --setup, or install '{tool}' yourself.",
    }


# ssl-kill-switch2 universal Frida script
_SSL_KILL_SWITCH_SCRIPT = """\
// ssl-kill-switch2 — universal SSL pinning bypass
// Covers: OkHttp, TrustKit, Conscrypt, native SSL_CTX
// Source: https://github.com/nabla-c0d3/ssl-kill-switch2

Java.perform(function() {
    // OkHttp v3/v4
    try {
        var Pinner = Java.use("okhttp3.CertificatePinner");
        Pinner.check.overload("java.lang.String","java.util.List").implementation = function() {
            console.log("[SSL-KS] OkHttp pinning bypassed");
        };
        Pinner["check$okhttp"].implementation = function() {};
    } catch(e) {}

    // TrustKit
    try {
        var TK = Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager");
        TK.checkServerTrusted.implementation = function() {
            console.log("[SSL-KS] TrustKit pinning bypassed");
        };
    } catch(e) {}

    // Trustmanager replacement
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var NullTrustManager = Java.registerClass({
        name: "com.bypass.NullTrustManager",
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, [NullTrustManager.$new()], null);
    SSLContext.getDefault.implementation = function() { return sslContext; };
    console.log("[SSL-KS] TrustManager replaced");
});

// Native OpenSSL / BoringSSL bypass
var SSL_CTX_set_verify = Module.findExportByName(null, "SSL_CTX_set_verify");
if (SSL_CTX_set_verify) {
    Interceptor.attach(SSL_CTX_set_verify, {
        onEnter: function(args) { args[1] = ptr(0); }
    });
    console.log("[SSL-KS] SSL_CTX_set_verify patched");
}
"""


class NetworkHandler:
    """Network interception handler.

    mitm_process is tracked as an instance variable so start/stop work
    across MCP tool calls within the same server session.
    """

    def __init__(self) -> None:
        self._mitm_proc: Optional[subprocess.Popen] = None
        self._mitm_capture_path: Optional[str] = None

    # ── mitm_start ─────────────────────────────────────────────────────────

    def mitm_start(self, args: dict) -> dict:
        if not _check_tool("mitmdump"):
            return _missing("mitmproxy")

        if self._mitm_proc and self._mitm_proc.poll() is None:
            return {
                "status": "ok",
                "tool": "mitmproxy",
                "output": {"message": "mitmproxy already running", "pid": self._mitm_proc.pid},
            }

        port = int(args.get("port", 8080))
        capture_dir = captures_dir()
        capture_path = str(capture_dir / f"capture_{int(time.time())}.mitm")
        self._mitm_capture_path = capture_path

        try:
            self._mitm_proc = subprocess.Popen(
                ["mitmdump", "--listen-host", "127.0.0.1", "-p", str(port), "-w", capture_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1)  # Give mitmproxy a moment to bind
            return {
                "status": "ok",
                "tool": "mitmproxy",
                "output": {
                    "started": True,
                    "port": port,
                    "capture_path": capture_path,
                    "pid": self._mitm_proc.pid,
                    "proxy_hint": (
                        f"Listening on 127.0.0.1:{port} only. Run `adb reverse tcp:{port} tcp:{port}` "
                        f"and set the device proxy to 127.0.0.1:{port}."
                    ),
                },
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "mitmproxy", "error": str(exc)}

    # ── mitm_stop ──────────────────────────────────────────────────────────

    def mitm_stop(self, args: dict) -> dict:  # noqa: ARG002
        if self._mitm_proc is None:
            return {"status": "ok", "tool": "mitmproxy", "output": {"message": "not running"}}

        try:
            self._mitm_proc.terminate()
            self._mitm_proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            self._mitm_proc.kill()

        capture_path = self._mitm_capture_path
        self._mitm_proc = None
        self._mitm_capture_path = None

        return {
            "status": "ok",
            "tool": "mitmproxy",
            "output": {"stopped": True, "capture_path": capture_path},
        }

    # ── ssl_kill_switch ────────────────────────────────────────────────────

    def ssl_kill_switch(self, args: dict) -> dict:
        """Inject the ssl-kill-switch2 Frida script into the target package."""
        package = args.get("package", "")
        try:
            import frida  # type: ignore[import]
        except ImportError:
            return {
                "status": "missing_tool",
                "tool": "frida",
                "error": "frida Python module not installed.",
            }

        try:
            device = frida.get_usb_device(timeout=10)
            session = device.attach(package)
            script = session.create_script(_SSL_KILL_SWITCH_SCRIPT)
            messages: list[str] = []

            def on_message(msg: dict, _data):  # noqa: ANN001
                if msg.get("type") == "send":
                    messages.append(str(msg.get("payload", "")))

            script.on("message", on_message)
            script.load()

            return {
                "status": "ok",
                "tool": "ssl_kill_switch",
                "output": {
                    "package": package,
                    "injected": True,
                    "messages": messages,
                    "note": "SSL pinning bypass active for this session.",
                },
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "ssl_kill_switch", "error": str(exc)}

    # ── mitm_read_flows — Gap #4 ───────────────────────────────────────────

    def mitm_read_flows(self, args: dict) -> dict:
        """Read captured mitmproxy flows as structured JSON using mitmproxy's API.

        Reads from the active capture file or a supplied path.
        Optionally filter by URL substring or HTTP method.

        Args:
            capture_path:  path to .mitm capture file (defaults to active session)
            filter_url:    URL substring to match (optional)
            filter_method: HTTP method filter e.g. "POST" (optional)
            max_flows:     maximum number of flows to return (default 50)
        """
        if not _check_tool("mitmdump"):
            return {"status": "missing_tool", "tool": "mitmproxy",
                    "error": "'mitmdump' not found", "hint": "pip install mitmproxy"}

        capture_path = args.get("capture_path", self._mitm_capture_path)
        if not capture_path or not Path(capture_path).exists():
            return {
                "status": "error",
                "tool": "mitm_read_flows",
                "error": "No capture file found. Run mitm_start first or supply capture_path.",
            }

        filter_url = args.get("filter_url", "")
        filter_method = (args.get("filter_method", "") or "").upper()
        max_flows = int(args.get("max_flows", 50))

        # Use mitmdump --script to export flows as JSON
        read_script = (
            "from mitmproxy import io as mio, http\n"
            "import sys, json\n"
            "flows = []\n"
            "with open(sys.argv[1], 'rb') as fh:\n"
            "    for f in mio.FlowReader(fh).stream():\n"
            "        if not isinstance(f, http.HTTPFlow): continue\n"
            "        entry = {\n"
            "            'method': f.request.method,\n"
            "            'url': f.request.pretty_url,\n"
            "            'request_headers': dict(f.request.headers),\n"
            "            'request_body': f.request.get_text(strict=False)[:2000],\n"
            "            'response_code': f.response.status_code if f.response else None,\n"
            "            'response_headers': dict(f.response.headers) if f.response else {},\n"
            "            'response_body': f.response.get_text(strict=False)[:2000] if f.response else '',\n"
            "        }\n"
            "        flows.append(entry)\n"
            "print(json.dumps(flows))\n"
        )

        try:
            proc = subprocess.run(
                [sys.executable, "-c", read_script, capture_path],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                return {"status": "error", "tool": "mitm_read_flows",
                        "error": proc.stderr[:1000]}

            import json as _json
            all_flows: list[dict] = _json.loads(proc.stdout)
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "mitm_read_flows", "error": str(exc)}

        # Apply filters
        filtered = all_flows
        if filter_url:
            filtered = [f for f in filtered if filter_url.lower() in f["url"].lower()]
        if filter_method:
            filtered = [f for f in filtered if f["method"].upper() == filter_method]

        return {
            "status": "ok",
            "tool": "mitm_read_flows",
            "output": {
                "capture_path": capture_path,
                "total_flows": len(all_flows),
                "filtered_flows": len(filtered),
                "flows": filtered[:max_flows],
            },
        }

    # ── mitm_export_har — Gap #4 ──────────────────────────────────────────

    def mitm_export_har(self, args: dict) -> dict:
        """Export captured mitmproxy flows to HAR (HTTP Archive) format.

        HAR files can be opened in Chrome DevTools, Fiddler, or Burp Suite.

        Args:
            capture_path:  path to .mitm file (defaults to active session)
            output_path:   where to write the .har file (optional)
        """
        if not _check_tool("mitmdump"):
            return {"status": "missing_tool", "tool": "mitmproxy",
                    "error": "'mitmdump' not found"}

        capture_path = args.get("capture_path", self._mitm_capture_path)
        if not capture_path or not Path(capture_path).exists():
            return {
                "status": "error",
                "tool": "mitm_export_har",
                "error": "No capture file. Run mitm_start first or supply capture_path.",
            }

        output_path = args.get("output_path",
                               str(Path(capture_path).with_suffix(".har")))

        # Fall back: manual HAR construction from the Python API
        har_script = (
            "from mitmproxy import io as mio, http\n"
            "import sys, json, datetime\n"
            "entries = []\n"
            "with open(sys.argv[1], 'rb') as fh:\n"
            "    for f in mio.FlowReader(fh).stream():\n"
            "        if not isinstance(f, http.HTTPFlow) or not f.response: continue\n"
            "        entries.append({\n"
            "            'startedDateTime': datetime.datetime.utcnow().isoformat() + 'Z',\n"
            "            'request': {\n"
            "                'method': f.request.method,\n"
            "                'url': f.request.pretty_url,\n"
            "                'httpVersion': 'HTTP/1.1',\n"
            "                'headers': [{'name': k, 'value': v} for k, v in f.request.headers.items()],\n"
            "                'queryString': [],\n"
            "                'cookies': [],\n"
            "                'headersSize': -1,\n"
            "                'bodySize': len(f.request.content),\n"
            "                'postData': {'mimeType': f.request.headers.get('content-type',''), 'text': f.request.get_text(strict=False)[:4000]} if f.request.content else None,\n"
            "            },\n"
            "            'response': {\n"
            "                'status': f.response.status_code,\n"
            "                'statusText': f.response.reason,\n"
            "                'httpVersion': 'HTTP/1.1',\n"
            "                'headers': [{'name': k, 'value': v} for k, v in f.response.headers.items()],\n"
            "                'cookies': [],\n"
            "                'content': {'size': len(f.response.content), 'mimeType': f.response.headers.get('content-type',''), 'text': f.response.get_text(strict=False)[:4000]},\n"
            "                'redirectURL': '',\n"
            "                'headersSize': -1,\n"
            "                'bodySize': len(f.response.content),\n"
            "            },\n"
            "            'time': 0,\n"
            "            'cache': {},\n"
            "            'timings': {'send': 0, 'wait': 0, 'receive': 0},\n"
            "        })\n"
            "har = {'log': {'version': '1.2', 'creator': {'name': 'mobile-re-mcp', 'version': '1'}, 'entries': entries}}\n"
            "with open(sys.argv[2], 'w') as out: json.dump(har, out, indent=2)\n"
            "print(f'Exported {len(entries)} flows')\n"
        )

        try:
            proc2 = subprocess.run(
                [sys.executable, "-c", har_script, capture_path, output_path],
                capture_output=True, text=True, timeout=60,
            )
            if proc2.returncode != 0:
                return {"status": "error", "tool": "mitm_export_har",
                        "error": proc2.stderr[:1000]}

            return {
                "status": "ok",
                "tool": "mitm_export_har",
                "output": {
                    "har_path": output_path,
                    "exists": Path(output_path).exists(),
                    "message": proc2.stdout.strip(),
                    "note": "Open in Chrome DevTools (Network → Import) or Burp Suite (Import HAR).",
                },
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "mitm_export_har", "error": "Timed out"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "mitm_export_har", "error": str(exc)}
