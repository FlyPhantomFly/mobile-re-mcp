"""
handlers/dynamic.py — Dynamic instrumentation handlers.

Tools (original):
  frida_spawn, frida_attach, frida_inject, frida_read_output,
  frida_detach, objection_run

Tools (new — gap #3):
  frida_list_scripts     list built-in JS script library
  frida_get_script       retrieve JS source from library
  frida_run_script       spawn + inject a named library script in one call
  frida_spawn_hluda      spawn using hluda (StrongR-Frida) adb server
  frida_server_push      push frida-server (or hluda) to device via adb
  frida_memdump          dump all rw memory to disk via fridump pattern
  frida_find_bytes       search process memory for byte pattern or string
"""

from __future__ import annotations

import logging
import queue
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any, Optional

from mobile_re_mcp.frida_scripts.index import (
    get_categories,
    get_script_content,
    list_scripts,
)

logger = logging.getLogger(__name__)

_TIMEOUT = 120
from mobile_re_mcp.paths import data_dir, tools_dir

_TOOLS_DIR = tools_dir()


def _check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def _missing(tool: str, hint: str = "") -> dict:
    return {
        "status": "missing_tool",
        "tool": tool,
        "error": f"'{tool}' not found. Run mobile-re-mcp-py --setup, or install '{tool}' yourself.",
        "hint": hint,
    }


class DynamicHandler:
    """Stateful dynamic instrumentation handler.

    frida_session, frida_script, and output_queue are instance-level.
    """

    # Runs via a dedicated single-worker executor instead of the default
    # thread pool: two concurrent calls must queue rather than race on
    # _frida_session/_frida_script/_output_queue (see server._run_tool).
    _SERIALIZE = True

    def __init__(self) -> None:
        self._frida_device: Any = None
        self._frida_session: Any = None
        self._frida_script: Any = None
        self._output_queue: queue.Queue[str] = queue.Queue()
        self._attached_package: Optional[str] = None

    # =========================================================================
    # Original tools
    # =========================================================================

    def frida_spawn(self, args: dict) -> dict:
        """Spawn an app with Frida and optionally inject a script."""
        try:
            import frida  # type: ignore[import]
        except ImportError:
            return _missing("frida", "pip install frida")

        package = args.get("package", "")
        script_src = args.get("script", "")
        script_config = args.get("config") or None

        try:
            device = frida.get_usb_device(timeout=10)
            pid = device.spawn([package])
            session = device.attach(pid)
            self._frida_device = device
            self._frida_session = session
            self._attached_package = package
            self._output_queue = queue.Queue()

            result = (
                self._load_script(script_src, config=script_config)
                if script_src
                else {"script_loaded": False}
            )

            device.resume(pid)
            return {
                "status": "ok",
                "tool": "frida",
                "output": {"package": package, "pid": pid, **result},
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "frida", "error": str(exc)}

    def frida_attach(self, args: dict) -> dict:
        """Attach to a running process."""
        try:
            import frida  # type: ignore[import]
        except ImportError:
            return _missing("frida")

        package = args.get("package", "")
        script_src = args.get("script", "")
        script_config = args.get("config") or None
        try:
            device = frida.get_usb_device(timeout=10)
            session = device.attach(package)
            self._frida_device = device
            self._frida_session = session
            self._attached_package = package
            self._output_queue = queue.Queue()

            result = (
                self._load_script(script_src, config=script_config)
                if script_src
                else {"script_loaded": False}
            )

            return {
                "status": "ok",
                "tool": "frida",
                "output": {"package": package, "attached": True, **result},
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "frida", "error": str(exc)}

    def frida_inject(self, args: dict) -> dict:
        """Inject a script into the currently attached session."""
        if self._frida_session is None:
            return {"status": "error", "tool": "frida", "error": "No active Frida session."}
        script_src = args.get("script", "")
        script_config = args.get("config") or None
        try:
            result = self._load_script(script_src, config=script_config)
            return {"status": "ok", "tool": "frida", "output": result}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "frida", "error": str(exc)}

    def frida_read_output(self, args: dict) -> dict:  # noqa: ARG002
        """Drain buffered Frida output messages."""
        messages: list[str] = []
        while True:
            try:
                messages.append(self._output_queue.get_nowait())
            except queue.Empty:
                break
        return {
            "status": "ok",
            "tool": "frida",
            "output": {"messages": messages, "count": len(messages)},
        }

    def frida_detach(self, args: dict) -> dict:  # noqa: ARG002
        """Detach the current Frida session."""
        if self._frida_session is None:
            return {"status": "ok", "tool": "frida", "output": {"detached": False}}
        try:
            self._frida_session.detach()
        except Exception:  # noqa: BLE001
            pass
        self._frida_session = None
        self._frida_script = None
        self._attached_package = None
        return {"status": "ok", "tool": "frida", "output": {"detached": True}}

    def frida_status(self, args: dict) -> dict:  # noqa: ARG002
        """No-op read: frida version, devices, and the handler's own state.

        Everything is best-effort: a section that cannot be introspected is
        reported as null/error instead of failing the whole status. Makes
        multi-turn sessions legible ("am I attached? to what?") and lets
        the caller chain "status → decide attach vs spawn".
        """
        info: dict = {"frida_version": None, "devices": [], "usb_device": None,
                      "frida_server_responsive": None, "session": None}

        try:
            import frida  # type: ignore[import]
            info["frida_version"] = frida.__version__
        except ImportError:
            return {
                "status": "missing_tool",
                "tool": "frida_status",
                "error": "frida is not installed in this Python environment.",
                "hint": "Run mobile-re-mcp-py --setup, or pip install frida.",
            }

        try:
            devices = [
                {"id": d.id, "name": d.name, "type": d.type}
                for d in frida.enumerate_devices()
            ]
            info["devices"] = devices
        except Exception as exc:  # noqa: BLE001
            info["devices"] = []
            info["devices_error"] = str(exc)

        usb = None
        for d in info["devices"]:
            if d.get("type") == "usb":
                usb = d
                break
        info["usb_device"] = usb

        if usb is not None:
            try:
                device = frida.get_usb_device(timeout=5)
                # A single cheap RPC proves frida-server is alive and
                # answering; enumerate_processes would be much heavier.
                front = device.get_frontmost_application()
                info["frida_server_responsive"] = True
                if front is not None:
                    info["frontmost_application"] = {
                        "identifier": front.identifier,
                        "name": front.name,
                        "pid": front.pid,
                    }
            except Exception as exc:  # noqa: BLE001
                info["frida_server_responsive"] = False
                info["frida_server_error"] = str(exc)

        # Handler-local state (no device round-trip).
        if self._frida_session is None:
            info["session"] = None
        else:
            alive = True
            try:
                alive = not self._frida_session.is_detached
            except Exception:  # noqa: BLE001 — older frida without the flag
                pass
            info["session"] = {
                "attached_package": self._attached_package,
                "alive": alive,
                "script_loaded": self._frida_script is not None,
                "queued_messages": self._output_queue.qsize(),
            }

        return {"status": "ok", "tool": "frida_status", "output": info}

    def objection_run(self, args: dict) -> dict:
        """Run an objection command against a package."""
        if not _check_tool("objection"):
            return _missing("objection", "pip install objection")

        package = args.get("package", "")
        command = args.get("command", "")
        try:
            proc = subprocess.run(
                ["objection", "--gadget", package, "run", command],
                capture_output=True, text=True, timeout=_TIMEOUT,
            )
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "tool": "objection",
                "output": {"stdout": proc.stdout, "stderr": proc.stderr},
                "raw": proc.stdout,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "objection", "error": "Timeout after 120s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "objection", "error": str(exc)}

    # =========================================================================
    # New tools — script library
    # =========================================================================

    def frida_list_scripts(self, args: dict) -> dict:
        """List built-in Frida scripts, optionally filtered by category."""
        category = args.get("category")
        scripts = list_scripts(category)
        categories = get_categories()

        return {
            "status": "ok",
            "tool": "frida_script_library",
            "output": {
                "scripts": [
                    {
                        "name": s["name"],
                        "category": s["category"],
                        "description": s["description"],
                        "tags": s["tags"],
                        "usage": s["usage"],
                    }
                    for s in scripts
                ],
                "total": len(scripts),
                "available_categories": categories,
            },
        }

    def frida_get_script(self, args: dict) -> dict:
        """Return the JS source of a named built-in script."""
        name = args.get("name", "")
        scripts = list_scripts()
        meta = next((s for s in scripts if s["name"] == name), None)
        if meta is None:
            return {
                "status": "error",
                "tool": "frida_script_library",
                "error": f"Script '{name}' not found.",
                "available": [s["name"] for s in scripts],
            }

        content = get_script_content(name)
        if content is None:
            return {
                "status": "error",
                "tool": "frida_script_library",
                "error": f"Script file for '{name}' is missing from the package.",
            }

        return {
            "status": "ok",
            "tool": "frida_script_library",
            "output": {
                "name": name,
                "category": meta["category"],
                "description": meta["description"],
                "usage": meta["usage"],
                "script": content,
            },
        }

    def frida_run_script(self, args: dict) -> dict:
        """Spawn a package and inject a named built-in script in a single call.

        *config* (E-PY-6) is posted as `{'type':'config', …}` after the
        script loads — the shipped scripts re-scan on receipt. The old
        `var X = …` str.replace injection is gone: quote-bearing values
        could break the generated source. Scripts that predate the
        protocol simply ignore the post, which is also why their
        `var X = ""` first-occurrence lines are kept in the library.
        """
        package = args.get("package", "")
        script_name = args.get("script_name", "")
        extra_config = args.get("config") or {}

        content = get_script_content(script_name)
        if content is None:
            avail = [s["name"] for s in list_scripts()]
            return {
                "status": "error",
                "tool": "frida_script_library",
                "error": f"Script '{script_name}' not found.",
                "available": avail,
            }

        spawn_args = {
            "package": package,
            "script": content,
            **({"config": extra_config} if extra_config else {}),
        }
        return self.frida_spawn(spawn_args)

    # =========================================================================
    # New tools — hluda support
    # =========================================================================

    def frida_spawn_hluda(self, args: dict) -> dict:
        """Spawn via hluda (StrongR-Frida) server on a non-standard port.

        Hluda renames Frida internals, defeating port-scan and
        module-name based Frida detection used by enterprise RASP SDKs.
        """
        try:
            import frida  # type: ignore[import]
        except ImportError:
            return _missing("frida")

        package = args.get("package", "")
        script_src = args.get("script", "")
        script_config = args.get("config") or None
        hluda_port = int(args.get("port", 27043))  # hluda default differs from stock

        try:
            # Connect to the device, specifying the hluda port
            device_manager = frida.get_device_manager()
            device = device_manager.add_remote_device(
                f"127.0.0.1:{hluda_port}",
                certificate=None,
                origin=None,
                token=None,
                keepalive_interval=-1,
            )
        except Exception:  # noqa: BLE001
            # Fall back to standard USB device (hluda may still be on standard adb forward)
            try:
                import frida as frida2  # type: ignore[import]
                device = frida2.get_usb_device(timeout=10)
            except Exception as exc2:  # noqa: BLE001
                return {"status": "error", "tool": "frida_hluda", "error": str(exc2)}

        try:
            pid = device.spawn([package])
            session = device.attach(pid)
            self._frida_device = device
            self._frida_session = session
            self._attached_package = package
            self._output_queue = queue.Queue()

            result = (
                self._load_script(script_src, config=script_config)
                if script_src
                else {"script_loaded": False}
            )

            device.resume(pid)
            return {
                "status": "ok",
                "tool": "frida_hluda",
                "output": {
                    "package": package,
                    "pid": pid,
                    "hluda_port": hluda_port,
                    "note": "Using hluda/StrongR-Frida — Frida detection bypassed at server level",
                    **result,
                },
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "frida_hluda", "error": str(exc),
                    "hint": "Ensure hluda frida-server is running: adb shell /data/local/tmp/frida-server &"}

    def frida_server_push(self, args: dict) -> dict:
        """Push frida-server (or hluda variant) to the device via adb.

        Automatically selects the correct ABI and matches the installed
        frida-tools version.
        """
        if not _check_tool("adb"):
            return _missing("adb", "Install Android SDK Platform-Tools")

        abi = args.get("abi", "arm64")      # arm64 | arm | x86_64 | x86
        use_hluda = bool(args.get("hluda", False))
        remote_path = args.get("remote_path", "/data/local/tmp/frida-server")

        # Determine frida version
        frida_version: Optional[str] = None
        if _check_tool("frida"):
            try:
                r = subprocess.run(["frida", "--version"], capture_output=True, text=True, timeout=5)
                frida_version = r.stdout.strip()
            except Exception:  # noqa: BLE001
                pass

        if frida_version is None:
            return {
                "status": "error",
                "tool": "frida_server_push",
                "error": "Could not determine frida version. Is frida-tools installed?",
                "hint": "pip install frida-tools",
            }

        # Look for a matching server binary in ~/tools/
        abi_map = {"arm64": "android-arm64", "arm": "android-arm",
                   "x86_64": "android-x86_64", "x86": "android-x86"}
        android_abi = abi_map.get(abi, "android-arm64")

        # Search common locations
        search_dirs = [_TOOLS_DIR, Path("/opt/frida")]
        server_binary: Optional[Path] = None
        for d in search_dirs:
            if not d.exists():
                continue
            for f in d.iterdir():
                if (("hluda" in f.name.lower() or "frida-server" in f.name.lower())
                        and android_abi in f.name
                        and frida_version in f.name
                        and f.is_file()):
                    server_binary = f
                    break
            if server_binary:
                break

        if server_binary is None:
            download_url = (
                f"https://github.com/frida/frida/releases/download/{frida_version}/"
                f"frida-server-{frida_version}-{android_abi}.xz"
            )
            if use_hluda:
                download_url = (
                    f"https://github.com/hluwa/strongR-frida-android/releases/download/"
                    f"{frida_version}/hluda-server-{frida_version}-{android_abi}"
                )
            return {
                "status": "missing_tool",
                "tool": "frida_server_push",
                "error": f"No matching frida-server binary found for version={frida_version} abi={android_abi}",
                "hint": f"Download from: {download_url}\nSave to: {_TOOLS_DIR}/",
                "frida_version": frida_version,
                "expected_abi": android_abi,
            }

        # Push to device
        try:
            push = subprocess.run(
                ["adb", "push", str(server_binary), remote_path],
                capture_output=True, text=True, timeout=60,
            )
            if push.returncode != 0:
                return {"status": "error", "tool": "frida_server_push",
                        "error": push.stderr or push.stdout}

            chmod = subprocess.run(
                ["adb", "shell", "chmod", "755", remote_path],
                capture_output=True, text=True, timeout=10,
            )

            if chmod.returncode != 0:
                return {"status": "error", "tool": "frida_server_push",
                        "error": chmod.stderr or chmod.stdout or "chmod failed on the device"}

            return {
                "status": "ok",
                "tool": "frida_server_push",
                "output": {
                    "local_binary": str(server_binary),
                    "remote_path": remote_path,
                    "frida_version": frida_version,
                    "abi": android_abi,
                    "hluda": use_hluda,
                    "start_command": f"adb shell {remote_path} &",
                    "note": "Start the server then re-run your Frida tool.",
                },
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "frida_server_push", "error": "adb push timed out"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "frida_server_push", "error": str(exc)}

    # =========================================================================
    # New tools — memory dumping (fridump / native)
    # =========================================================================

    def frida_memdump(self, args: dict) -> dict:
        """Dump all readable memory regions from the running process.

        Uses the built-in memory_scan script pattern; does NOT require
        fridump binary — works via the injected Frida session.
        """
        if self._frida_session is None:
            return {"status": "error", "tool": "frida_memdump",
                    "error": "No active Frida session. Call frida_attach first."}

        package = args.get("package", self._attached_package or "unknown")
        # E-PY-9: dumps are *output*, not downloaded tooling — they live
        # under data_dir()/dumps, not the tools-download dir.
        default_dir = data_dir() / "dumps" / package
        output_dir = Path(args.get("output_dir", str(default_dir)))
        output_dir.mkdir(parents=True, exist_ok=True)

        dump_script = r"""
var ranges = Process.enumerateRanges('rw-');
var results = [];
ranges.forEach(function(range) {
    try {
        var data = range.base.readByteArray(range.size);
        if (data) {
            send({
                type: 'range',
                base: range.base.toString(),
                size: range.size,
                module: (function(){
                    try { var m = Process.findModuleByAddress(range.base); return m ? m.name : ''; }
                    catch(_){ return ''; }
                })()
            }, data);
        }
    } catch(_) {}
});
send({type: 'done', total_ranges: ranges.length});
"""

        ranges_written: list[dict] = []
        done = threading.Event()

        def on_message(msg: dict, data: Any) -> None:
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                return
            ptype = payload.get("type")
            if ptype == "range" and data:
                base = payload["base"]
                mod = payload.get("module", "")
                filename = output_dir / f"{base}_{mod or 'anon'}.bin"
                try:
                    with open(filename, "wb") as fh:
                        fh.write(data)
                    ranges_written.append({
                        "base": base,
                        "size": payload["size"],
                        "module": mod,
                        "file": str(filename),
                    })
                except Exception:  # noqa: BLE001
                    pass
            elif ptype == "done":
                done.set()

        try:
            script = self._frida_session.create_script(dump_script)
            script.on("message", on_message)
            script.load()
            done.wait(timeout=120)
            script.unload()
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "frida_memdump", "error": str(exc)}

        total_bytes = sum(r["size"] for r in ranges_written)
        return {
            "status": "ok",
            "tool": "frida_memdump",
            "output": {
                "output_dir": str(output_dir),
                "ranges_written": len(ranges_written),
                "total_bytes": total_bytes,
                "ranges": ranges_written,
            },
        }

    def frida_find_bytes(self, args: dict) -> dict:
        """Search all rw- process memory for a byte pattern or UTF-8 string."""
        if self._frida_session is None:
            return {"status": "error", "tool": "frida_find_bytes",
                    "error": "No active Frida session. Call frida_attach first."}

        search_str = args.get("search_string", "")
        search_hex = args.get("search_hex", "")
        max_results = int(args.get("max_results", 20))

        if not search_str and not search_hex:
            return {"status": "error", "tool": "frida_find_bytes",
                    "error": "Provide 'search_string' or 'search_hex'"}

        scan_script_src = get_script_content("memory_scan")
        if scan_script_src is None:
            return {"status": "error", "tool": "frida_find_bytes",
                    "error": "Built-in memory_scan script not found."}

        matches: list[dict] = []
        done_event = threading.Event()

        def on_message(msg: dict, data: Any) -> None:  # noqa: ARG001
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                return
            if payload.get("type") == "match":
                matches.append(payload["match"])
            elif payload.get("type") == "scan_complete":
                done_event.set()

        # E-PY-6: primary path is the config protocol — load the script
        # unpatched, then post {'type':'config', …}; the script scans on
        # receipt. Fallback for runtimes without script.post: the var-line
        # contract (patch `var SEARCH_STRING = "";` first occurrences) —
        # the script then auto-scans at load.
        config = {"SEARCH_STRING": search_str, "SEARCH_HEX": search_hex,
                  "MAX_RESULTS": max_results}
        try:
            script = self._frida_session.create_script(scan_script_src)
            script.on("message", on_message)
            script.load()
            try:
                script.post({"type": "config", **config})
            except Exception:  # noqa: BLE001 — runtime without post support
                script.unload()
                matches.clear()
                done_event.clear()
                patched = scan_script_src
                if search_str:
                    patched = patched.replace(
                        'var SEARCH_STRING = "";', f'var SEARCH_STRING = "{search_str}";', 1
                    )
                if search_hex:
                    patched = patched.replace(
                        'var SEARCH_HEX = "";', f'var SEARCH_HEX = "{search_hex}";', 1
                    )
                patched = patched.replace(
                    'var MAX_RESULTS = 50;', f'var MAX_RESULTS = {max_results};', 1
                )
                script = self._frida_session.create_script(patched)
                script.on("message", on_message)
                script.load()
            done_event.wait(timeout=60)
            script.unload()
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "frida_find_bytes", "error": str(exc)}

        return {
            "status": "ok",
            "tool": "frida_find_bytes",
            "output": {
                "pattern": search_str or search_hex,
                "matches": matches,
                "total": len(matches),
                "via": "config-protocol",
            },
        }

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _load_script(self, src: str, config: Optional[dict] = None) -> dict:
        """Load and run a Frida script; route output to self._output_queue.

        With *config* (E-PY-6), `{'type':'config', ...}` is posted right
        after load. Shipped scripts register a `recv('config', …)` handler
        and re-scan/re-run on receipt; scripts that never recv are simply
        unaffected. This replaces the old str.replace injection into
        `var X = …` lines, which broke on quote-bearing values.
        """
        q = self._output_queue
        script = self._frida_session.create_script(src)

        def on_message(message: dict, data: Any) -> None:  # noqa: ARG001
            if message.get("type") == "send":
                q.put(str(message.get("payload", "")))
            elif message.get("type") == "error":
                q.put(f"[FRIDA ERROR] {message.get('description', '')}")

        script.on("message", on_message)
        script.load()
        if config:
            script.post({"type": "config", **config})
        self._frida_script = script
        return {"script_loaded": True}
