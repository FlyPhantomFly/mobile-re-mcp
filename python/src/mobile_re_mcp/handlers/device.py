"""
handlers/device.py — ADB device control + UI mirroring handlers.

Tools: adb_devices, adb_shell, adb_install, adb_pull, adb_push,
       adb_logcat_start, adb_logcat_read, adb_logcat_stop,
       hermes_decode, scrcpy_start, scrcpy_screenshot
"""

from __future__ import annotations

import logging
import queue
import shlex
import shutil
import subprocess
import threading
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

from mobile_re_mcp.paths import scratch_dir

_TIMEOUT = 120


def _check_adb() -> bool:
    import shutil

    return shutil.which("adb") is not None


def _missing_adb() -> dict:
    return {
        "status": "missing_tool",
        "tool": "adb",
        "error": "adb not found on PATH. Install Android SDK platform-tools.",
    }


def _adb(*args: str, serial: Optional[str] = None, timeout: int = _TIMEOUT) -> subprocess.CompletedProcess:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


class DeviceHandler:
    """Stateful ADB device handler.

    logcat_thread and logcat_queue are instance-level so we can safely
    start / stop / read without global state.
    """

    def __init__(self) -> None:
        self._logcat_proc: Optional[subprocess.Popen] = None
        self._logcat_queue: queue.Queue[str] = queue.Queue(maxsize=50_000)
        self._logcat_thread: Optional[threading.Thread] = None
        self._logcat_running = False

    # ── adb_devices ────────────────────────────────────────────────────────

    def adb_devices(self, args: dict) -> dict:  # noqa: ARG002
        if not _check_adb():
            return _missing_adb()
        try:
            proc = _adb("devices", "-l")
            lines = proc.stdout.strip().splitlines()
            devices = []
            for line in lines[1:]:  # skip header
                parts = line.split()
                if len(parts) >= 2 and parts[1] != "offline":
                    info = {"serial": parts[0], "state": parts[1]}
                    # Parse extra key=value tokens
                    for token in parts[2:]:
                        if "=" in token:
                            k, v = token.split("=", 1)
                            info[k] = v
                    devices.append(info)
            return {
                "status": "ok",
                "tool": "adb",
                "output": {"devices": devices, "count": len(devices)},
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "adb", "error": str(exc)}

    # ── adb_shell ──────────────────────────────────────────────────────────

    def adb_shell(self, args: dict) -> dict:
        if not _check_adb():
            return _missing_adb()
        command = args.get("command", "")
        serial = args.get("serial")
        # Split the command string safely so it works on both Windows and Linux
        cmd_parts = shlex.split(command) if command else []
        try:
            proc = _adb("shell", *cmd_parts, serial=serial)
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "tool": "adb",
                "output": {"stdout": proc.stdout, "stderr": proc.stderr},
                "raw": proc.stdout,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "adb", "error": "Timeout after 120s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "adb", "error": str(exc)}

    # ── adb_install ────────────────────────────────────────────────────────

    def adb_install(self, args: dict) -> dict:
        if not _check_adb():
            return _missing_adb()
        apk_path = args.get("apk_path", "")
        serial = args.get("serial")
        try:
            proc = _adb("install", "-r", "-t", apk_path, serial=serial, timeout=180)
            success = "Success" in proc.stdout
            return {
                "status": "ok" if success else "error",
                "tool": "adb",
                "output": {"apk_path": apk_path, "installed": success},
                "raw": proc.stdout,
                "error": proc.stderr if not success else None,
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "adb", "error": "Timeout after 180s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "adb", "error": str(exc)}

    # ── adb_pull ───────────────────────────────────────────────────────────

    def adb_pull(self, args: dict) -> dict:
        if not _check_adb():
            return _missing_adb()
        remote = args.get("remote", "")
        local = args.get("local", "")
        serial = args.get("serial")
        try:
            proc = _adb("pull", remote, local, serial=serial)
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "tool": "adb",
                "output": {"remote": remote, "local": local},
                "raw": proc.stdout,
                "error": proc.stderr if proc.returncode != 0 else None,
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "adb", "error": str(exc)}

    # ── adb_push ───────────────────────────────────────────────────────────

    def adb_push(self, args: dict) -> dict:
        if not _check_adb():
            return _missing_adb()
        local = args.get("local", "")
        remote = args.get("remote", "")
        serial = args.get("serial")
        try:
            proc = _adb("push", local, remote, serial=serial)
            return {
                "status": "ok" if proc.returncode == 0 else "error",
                "tool": "adb",
                "output": {"local": local, "remote": remote},
                "raw": proc.stdout,
                "error": proc.stderr if proc.returncode != 0 else None,
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "adb", "error": str(exc)}

    # ── adb_logcat_start ───────────────────────────────────────────────────

    def adb_logcat_start(self, args: dict) -> dict:
        if not _check_adb():
            return _missing_adb()
        if self._logcat_running:
            return {"status": "ok", "tool": "adb", "output": {"message": "logcat already running"}}

        filter_str = args.get("filter", "*:V")
        serial = args.get("serial")

        cmd = ["adb"]
        if serial:
            cmd += ["-s", serial]
        cmd += ["logcat", filter_str]

        try:
            self._logcat_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self._logcat_running = True
            self._logcat_queue = queue.Queue(maxsize=50_000)

            def _reader():
                assert self._logcat_proc is not None
                for line in self._logcat_proc.stdout:  # type: ignore[union-attr]
                    if not self._logcat_running:
                        break
                    if not self._logcat_queue.full():
                        self._logcat_queue.put(line.rstrip("\n"))

            self._logcat_thread = threading.Thread(target=_reader, daemon=True)
            self._logcat_thread.start()

            return {
                "status": "ok",
                "tool": "adb",
                "output": {"logcat_started": True, "filter": filter_str},
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "adb", "error": str(exc)}

    # ── adb_logcat_read ────────────────────────────────────────────────────

    def adb_logcat_read(self, args: dict) -> dict:
        lines_wanted = int(args.get("lines", 100))
        lines: list[str] = []
        while len(lines) < lines_wanted:
            try:
                lines.append(self._logcat_queue.get_nowait())
            except queue.Empty:
                break
        return {
            "status": "ok",
            "tool": "adb",
            "output": {"lines": lines, "count": len(lines)},
        }

    # ── adb_logcat_stop ────────────────────────────────────────────────────

    def adb_logcat_stop(self, args: dict) -> dict:  # noqa: ARG002
        self._logcat_running = False
        if self._logcat_proc:
            try:
                self._logcat_proc.terminate()
            except Exception:  # noqa: BLE001
                pass
            self._logcat_proc = None

        # Drain remaining buffer
        remaining: list[str] = []
        while True:
            try:
                remaining.append(self._logcat_queue.get_nowait())
            except queue.Empty:
                break

        return {
            "status": "ok",
            "tool": "adb",
            "output": {"logcat_stopped": True, "remaining_lines": remaining},
        }

    # ── hermes_decode ─────────────────────────────────────────────────────

    def hermes_decode(self, args: dict) -> dict:
        """Decode a Hermes bytecode bundle (.hbc) from a React Native APK.

        React Native apps ship with a pre-compiled Hermes bytecode file
        (typically assets/index.android.bundle or similar). This tool
        extracts and decompiles it using `hermes-dec` (or `hbctool`).

        Strategy:
          1. Extract the .bundle file from the APK
          2. Run hermes-dec (pip install hermes-dec) to produce readable JS
          3. Fall back to hbctool if hermes-dec is unavailable

        Args:
            apk_path:     path to the APK
            bundle_path:  explicit path to a .bundle/.hbc file (alternative to apk_path)
            output_dir:   where to write the decompiled JS (optional)
        """
        apk_path = args.get("apk_path", "")
        bundle_path_arg = args.get("bundle_path", "")
        output_dir = args.get("output_dir", "")

        bundle_file: Optional[Path] = None

        # 1. Locate the bundle file
        if bundle_path_arg and Path(bundle_path_arg).exists():
            bundle_file = Path(bundle_path_arg)
        elif apk_path and Path(apk_path).exists():
            bundle_file = self._extract_hermes_bundle(Path(apk_path))
            if bundle_file is None:
                return {
                    "status": "error",
                    "tool": "hermes_decode",
                    "error": (
                        "No Hermes .bundle file found in APK. "
                        "Is this a React Native + Hermes app?"
                    ),
                    "hint": (
                        "Run apk_identify() first to confirm React Native framework. "
                        "The bundle is usually in assets/index.android.bundle."
                    ),
                }
        else:
            return {"status": "error", "tool": "hermes_decode",
                    "error": "Provide apk_path or bundle_path"}

        out_dir = Path(output_dir) if output_dir else bundle_file.parent / "hermes_out"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_js = out_dir / (bundle_file.stem + "_decoded.js")

        # 2. Try hermes-dec first (pip install hermes-dec)
        if shutil.which("hermes-dec"):
            try:
                proc = subprocess.run(
                    ["hermes-dec", str(bundle_file), "-o", str(out_js)],
                    capture_output=True, text=True, timeout=120,
                )
                if proc.returncode == 0 and out_js.exists():
                    return self._hermes_success(bundle_file, out_js, out_dir, "hermes-dec", proc)
                # hermes-dec sometimes writes to stdout instead
                if proc.stdout:
                    out_js.write_text(proc.stdout, encoding="utf-8")
                    return self._hermes_success(bundle_file, out_js, out_dir, "hermes-dec", proc)
            except Exception:  # noqa: BLE001
                pass

        # 3. Try hbctool (npm install -g hbctool)
        if shutil.which("hbctool"):
            try:
                proc = subprocess.run(
                    ["hbctool", "disasm", str(bundle_file), str(out_dir / "hbc_disasm")],
                    capture_output=True, text=True, timeout=120,
                )
                if proc.returncode == 0:
                    return {
                        "status": "ok",
                        "tool": "hermes_decode",
                        "output": {
                            "bundle_file": str(bundle_file),
                            "output_dir": str(out_dir / "hbc_disasm"),
                            "decoder": "hbctool",
                            "note": "hbctool produces assembly-level output. For JS-level, install hermes-dec.",
                        },
                    }
            except Exception:  # noqa: BLE001
                pass

        return {
            "status": "missing_tool",
            "tool": "hermes_decode",
            "error": "Neither hermes-dec nor hbctool found",
            "hint": (
                "pip install hermes-dec    # preferred — outputs readable JS\n"
                "npm install -g hbctool   # alternative — outputs HBC assembly"
            ),
            "bundle_found_at": str(bundle_file),
        }

    def _extract_hermes_bundle(self, apk_path: Path) -> Optional[Path]:
        """Extract the Hermes .bundle file from an APK into a private scratch folder."""
        bundle_candidates = [
            "assets/index.android.bundle",
            "assets/index.bundle",
        ]
        try:
            with zipfile.ZipFile(str(apk_path)) as zf:
                names = zf.namelist()
                # Explicit candidates first
                for candidate in bundle_candidates:
                    if candidate in names:
                        dst = scratch_dir("hermes") / Path(candidate).name
                        dst.write_bytes(zf.read(candidate))
                        return dst
                # Fallback: any .bundle or .hbc in assets
                for name in names:
                    if name.startswith("assets/") and (
                        name.endswith(".bundle") or name.endswith(".hbc")
                    ):
                        dst = scratch_dir("hermes") / Path(name).name
                        dst.write_bytes(zf.read(name))
                        return dst
        except Exception:  # noqa: BLE001
            pass
        return None

    def _hermes_success(self, bundle: Path, out_js: Path, out_dir: Path,
                        decoder: str, proc: subprocess.CompletedProcess) -> dict:
        size = out_js.stat().st_size if out_js.exists() else 0
        return {
            "status": "ok",
            "tool": "hermes_decode",
            "output": {
                "bundle_file": str(bundle),
                "decoded_js": str(out_js),
                "output_dir": str(out_dir),
                "size_bytes": size,
                "decoder": decoder,
                "note": (
                    "Decoded JS is minified/obfuscated. "
                    "Use search_strings() or find_urls() on the output file for recon."
                ),
            },
        }

    # ── scrcpy_start ──────────────────────────────────────────────────────

    def scrcpy_start(self, args: dict) -> dict:
        """Start scrcpy to mirror the device screen on the host.

        scrcpy (https://github.com/Genymobile/scrcpy) provides real-time
        screen mirroring with optional recording. Useful for UI testing,
        verifying SSL bypass visually, and reproducing security flows.

        Args:
            serial:       device serial (optional, auto-selects if only one device)
            bitrate:      video bitrate in Mbps (default 4)
            max_fps:      max framerate (default 30)
            record_file:  path to record a .mp4 (optional)
            no_display:   if true, run headless (record only)
        """
        if not shutil.which("scrcpy"):
            return {
                "status": "missing_tool",
                "tool": "scrcpy",
                "error": "scrcpy not found",
                "hint": (
                    "Windows: choco install scrcpy  OR  scoop install scrcpy\n"
                    "macOS:   brew install scrcpy\n"
                    "Linux:   sudo apt install scrcpy  OR  snap install scrcpy"
                ),
            }

        serial = args.get("serial", "")
        bitrate = int(args.get("bitrate", 4))
        max_fps = int(args.get("max_fps", 30))
        record_file = args.get("record_file", "")
        no_display = bool(args.get("no_display", False))

        cmd = ["scrcpy", f"--video-bit-rate={bitrate}M", f"--max-fps={max_fps}"]
        if serial:
            cmd += ["--serial", serial]
        if record_file:
            cmd += ["--record", record_file]
        if no_display:
            cmd += ["--no-display"]

        try:
            # Launch scrcpy as a detached background process
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            return {
                "status": "ok",
                "tool": "scrcpy",
                "output": {
                    "launched": True,
                    "pid": proc.pid,
                    "serial": serial or "(auto)",
                    "bitrate_mbps": bitrate,
                    "max_fps": max_fps,
                    "record_file": record_file or None,
                    "note": "scrcpy is running in the background. Kill with scrcpy_stop() or terminate the PID.",
                },
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "scrcpy", "error": str(exc)}

    # ── scrcpy_screenshot ─────────────────────────────────────────────────

    def scrcpy_screenshot(self, args: dict) -> dict:
        """Capture a screenshot from the device via adb screencap.

        Does NOT require scrcpy — uses `adb exec-out screencap -p`.
        Returns the path of the saved PNG file.

        Args:
            output_path:  local path to save PNG (optional, defaults to a private scratch folder)
            serial:       device serial (optional)
        """
        if not _check_adb():
            return _missing_adb()

        import time
        output_path = args.get("output_path",
                               str(scratch_dir("screenshots") / f"screenshot_{int(time.time())}.png"))
        serial = args.get("serial", "")

        cmd = ["adb"]
        if serial:
            cmd += ["-s", serial]
        cmd += ["exec-out", "screencap", "-p"]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=15)
            if result.returncode != 0:
                return {
                    "status": "error",
                    "tool": "scrcpy_screenshot",
                    "error": result.stderr.decode("utf-8", errors="ignore"),
                }

            # adb exec-out screencap -p returns raw PNG bytes
            png_bytes = result.stdout
            if not png_bytes or png_bytes[:4] != b"\x89PNG":
                # On Windows, adb may add \r to line endings; strip them
                png_bytes = png_bytes.replace(b"\r\n", b"\n")

            if not png_bytes or png_bytes[:4] != b"\x89PNG":
                return {
                    "status": "error",
                    "tool": "scrcpy_screenshot",
                    "error": "Received data is not a valid PNG. Try scrcpy_start() + manual screenshot instead.",
                    "hint": "Some devices need: adb shell screencap /sdcard/sc.png && adb pull /sdcard/sc.png",
                }

            Path(output_path).write_bytes(png_bytes)
            return {
                "status": "ok",
                "tool": "scrcpy_screenshot",
                "output": {
                    "screenshot_path": output_path,
                    "size_bytes": len(png_bytes),
                    "note": "Open the PNG to review the current UI state of the device.",
                },
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "scrcpy_screenshot", "error": "adb screencap timed out"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "scrcpy_screenshot", "error": str(exc)}
