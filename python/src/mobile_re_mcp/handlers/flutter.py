"""
handlers/flutter.py — Flutter/Dart-specific reverse engineering handler.

Gaps covered:
  #2  flutter_version   — detect Dart/Flutter snapshot version from libflutter.so
      blutter_extract   — run Blutter on libapp.so to recover Dart symbols
      dart_snapshot_info — identify snapshot kind and engine commitish
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_TIMEOUT = 120
_TIMEOUT_LONG = 600   # Blutter can be very slow on large apps
from mobile_re_mcp.paths import scratch_dir, tools_dir

_TOOLS_DIR = tools_dir()


def _check(name: str) -> bool:
    return shutil.which(name) is not None


def _missing(tool: str, hint: str = "") -> dict:
    return {
        "status": "missing_tool",
        "tool": tool,
        "error": f"'{tool}' not found",
        "hint": hint,
    }


# ---------------------------------------------------------------------------
# Dart / Flutter version fingerprints
# ---------------------------------------------------------------------------

# Maps known engine commit hashes (first 8 chars) → Flutter SDK version
# Sourced from https://github.com/flutter/flutter/blob/master/bin/internal/engine.version
_ENGINE_TO_SDK: dict[str, str] = {
    "5419d2a": "3.19.0",
    "a6bc36d": "3.16.9",
    "efeeed2": "3.16.0",
    "899ab0c": "3.13.9",
    "535e2e2": "3.10.6",
    "f40e976": "3.7.12",
    "90c721b": "3.3.10",
    "5d07e58": "2.10.5",
    "273f12f": "2.8.1",
}

# Dart snapshot magic bytes → Dart version range
_SNAPSHOT_MAGIC: dict[bytes, str] = {
    bytes.fromhex("dcadbeef"): "Dart >= 2.15 (AppJITSnapshot)",
    bytes.fromhex("dcdcdcdc"): "Dart >= 2.12 (AOT, ELF-embedded)",
    bytes.fromhex("f5f5dcdc"): "Dart < 2.12 (AOT, standalone)",
}


class FlutterHandler:
    """Flutter/Dart reverse engineering handler."""

    # =========================================================================
    # flutter_version
    # =========================================================================

    def flutter_version(self, args: dict) -> dict:
        """Detect Flutter/Dart engine version from libflutter.so inside an APK.

        Searches for the engine commit hash embedded in the binary and
        cross-references it against the known SDK version map.
        """
        apk_path = args.get("apk_path", "")
        so_path = args.get("so_path", "")
        abi = args.get("abi", "arm64-v8a")

        libflutter_data: Optional[bytes] = None
        source = ""

        if so_path and Path(so_path).exists():
            libflutter_data = Path(so_path).read_bytes()
            source = so_path
        elif apk_path and Path(apk_path).exists():
            libflutter_data, source = self._extract_libflutter(apk_path, abi)
        else:
            return {"status": "error", "tool": "flutter_version",
                    "error": "Provide apk_path or so_path pointing to libflutter.so"}

        if libflutter_data is None:
            return {
                "status": "error",
                "tool": "flutter_version",
                "error": "libflutter.so not found in APK — is this actually a Flutter app?",
                "hint": "Run apk_identify to confirm framework first.",
            }

        result = self._analyze_libflutter(libflutter_data)
        result["source"] = source
        return {"status": "ok", "tool": "flutter_version", "output": result}

    def _extract_libflutter(self, apk_path: str, abi: str) -> tuple[Optional[bytes], str]:
        try:
            with zipfile.ZipFile(apk_path) as zf:
                target = f"lib/{abi}/libflutter.so"
                if target in zf.namelist():
                    return zf.read(target), target
                # Try other ABIs
                for name in zf.namelist():
                    if "libflutter.so" in name:
                        return zf.read(name), name
        except Exception as exc:  # noqa: BLE001
            logger.warning("APK extract failed: %s", exc)
        return None, ""

    def _analyze_libflutter(self, data: bytes) -> dict:
        """Extract version information from libflutter binary."""
        result: dict = {
            "engine_commit": None,
            "flutter_sdk_version": None,
            "dart_version_string": None,
            "snapshot_hash": None,
            "is_flutter": False,
        }

        # 1. Search for engine commit hash pattern: 40-char hex string
        #    Embedded as "engineVersion":<hash> or standalone in .rodata
        commit_pattern = re.compile(rb"([0-9a-f]{40})", re.IGNORECASE)
        commits = commit_pattern.findall(data)
        if commits:
            commit = commits[0].decode("ascii")
            result["engine_commit"] = commit
            # Look up SDK version
            short = commit[:7]
            result["flutter_sdk_version"] = _ENGINE_TO_SDK.get(short, f"unknown (commit: {short})")
            result["is_flutter"] = True

        # 2. Dart version string: "Dart VM version: X.Y.Z ..."
        dart_ver = re.search(rb"Dart VM version:\s*([\d.a-z\-]+)", data)
        if dart_ver:
            result["dart_version_string"] = dart_ver.group(1).decode("ascii", errors="ignore")
            result["is_flutter"] = True

        # 3. Engine release channel (stable/beta/dev/master)
        channel = re.search(rb"\x00(stable|beta|dev|master)\x00", data)
        if channel:
            result["channel"] = channel.group(1).decode("ascii")

        # 4. Flutter version string
        ver_str = re.search(rb"(\d+\.\d+\.\d+(?:\.\d+)?)\x00", data)
        if ver_str:
            candidate = ver_str.group(1).decode("ascii")
            result["version_string"] = candidate

        # 5. Check for snapshot magic in the binary (libapp.so might be embedded)
        for magic, desc in _SNAPSHOT_MAGIC.items():
            if magic in data:
                result["snapshot_magic"] = desc
                break

        return result

    # =========================================================================
    # dart_snapshot_info
    # =========================================================================

    def dart_snapshot_info(self, args: dict) -> dict:
        """Identify Dart snapshot kind and structure from libapp.so.

        Useful before running Blutter — determines AOT vs JIT vs AppJIT
        and warns if the header has been wiped (Zimperium zShield pattern).
        """
        so_path = args.get("so_path", "")
        apk_path = args.get("apk_path", "")
        abi = args.get("abi", "arm64-v8a")

        data: Optional[bytes] = None

        if so_path and Path(so_path).exists():
            data = Path(so_path).read_bytes()
        elif apk_path:
            try:
                with zipfile.ZipFile(apk_path) as zf:
                    target = f"lib/{abi}/libapp.so"
                    if target in zf.namelist():
                        data = zf.read(target)
            except Exception as exc:  # noqa: BLE001
                return {"status": "error", "tool": "dart_snapshot_info", "error": str(exc)}
        else:
            return {"status": "error", "tool": "dart_snapshot_info",
                    "error": "Provide so_path or apk_path"}

        if data is None:
            return {"status": "error", "tool": "dart_snapshot_info",
                    "error": "libapp.so not found"}

        is_elf = data[:4] == b"\x7fELF"
        header_wiped = data[:4] == b"\x00\x00\x00\x00"

        snapshot_kind = "unknown"
        magic_found = None
        for magic, desc in _SNAPSHOT_MAGIC.items():
            if magic in data[:512]:
                snapshot_kind = "AOT (embedded snapshot)"
                magic_found = desc
                break

        # Dart AOT ELF: has specific section names _kDartBSSData, _kDartVmSnapshotData
        aot_sections = []
        for section_marker in [b"_kDartVmSnapshotData", b"_kDartIsolateSnapshotData",
                                b"_kDartBSSData", b"_kDartVmSnapshotInstructions"]:
            if section_marker in data:
                aot_sections.append(section_marker.decode("ascii"))

        return {
            "status": "ok",
            "tool": "dart_snapshot_info",
            "output": {
                "is_elf": is_elf,
                "header_wiped": header_wiped,
                "snapshot_kind": "AOT ELF" if aot_sections else snapshot_kind,
                "snapshot_magic": magic_found,
                "aot_sections_found": aot_sections,
                "size_bytes": len(data),
                "warnings": (
                    ["ELF header wiped — likely Zimperium zShield or similar RASP. "
                     "Need runtime dump to reconstruct for Blutter."]
                    if header_wiped else []
                ),
            },
        }

    # =========================================================================
    # blutter_extract
    # =========================================================================

    def blutter_extract(self, args: dict) -> dict:
        """Run Blutter on libapp.so to recover Dart class/method symbols.

        Blutter produces:
          - ida_script.py / ghidra_script.py — symbol import scripts
          - asm/    — per-class Dart assembly
          - pp/     — pseudo-code (pretty-printed Dart)

        Blutter must be installed: https://github.com/worawit/blutter
        Requirements: Python + cmake + Ninja + ninja (blutter build)
        """
        so_path = args.get("so_path", "")
        apk_path = args.get("apk_path", "")
        abi = args.get("abi", "arm64-v8a")
        output_dir = args.get("output_dir", "")
        dart_version = args.get("dart_version", "")  # e.g. "3.1.0" — bypass auto-detect

        # Locate blutter
        blutter_paths = [
            _TOOLS_DIR / "blutter" / "blutter.py",
            Path("/opt/blutter/blutter.py"),
            Path.home() / "blutter" / "blutter.py",
        ]
        blutter_script: Optional[Path] = None
        for p in blutter_paths:
            if p.exists():
                blutter_script = p
                break

        if blutter_script is None:
            return {
                "status": "missing_tool",
                "tool": "blutter",
                "error": "Blutter not found",
                "hint": (
                    "git clone https://github.com/worawit/blutter\n"
                    f"Run setup then move/symlink to {_TOOLS_DIR}/blutter/"
                ),
            }

        # Prepare libapp.so
        libapp_path: Optional[Path] = None
        if so_path and Path(so_path).exists():
            libapp_path = Path(so_path)
        elif apk_path and Path(apk_path).exists():
            tmp_so = scratch_dir("flutter") / "libapp.so"
            try:
                with zipfile.ZipFile(apk_path) as zf:
                    target = f"lib/{abi}/libapp.so"
                    if target in zf.namelist():
                        tmp_so.write_bytes(zf.read(target))
                        libapp_path = tmp_so
            except Exception as exc:  # noqa: BLE001
                return {"status": "error", "tool": "blutter", "error": str(exc)}

        if libapp_path is None:
            return {"status": "error", "tool": "blutter",
                    "error": "libapp.so not found — provide so_path or apk_path"}

        out_dir = Path(output_dir) if output_dir else libapp_path.parent / "blutter_out"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Build blutter command
        cmd = ["python3", str(blutter_script), str(libapp_path), str(out_dir)]
        if dart_version:
            cmd += ["--dart-version", dart_version]

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=_TIMEOUT_LONG,
            )

            # Collect outputs
            output_files = {
                "ida_script": str(out_dir / "ida_script.py") if (out_dir / "ida_script.py").exists() else None,
                "ghidra_script": str(out_dir / "ghidra_script.py") if (out_dir / "ghidra_script.py").exists() else None,
                "asm_dir": str(out_dir / "asm") if (out_dir / "asm").exists() else None,
                "pp_dir": str(out_dir / "pp") if (out_dir / "pp").exists() else None,
            }

            success = any(v for v in output_files.values())

            return {
                "status": "ok" if success else "error",
                "tool": "blutter",
                "output": {
                    "libapp_path": str(libapp_path),
                    "output_dir": str(out_dir),
                    "files": output_files,
                    "raw_tail": (proc.stdout or proc.stderr)[-2000:],
                    "returncode": proc.returncode,
                    "note": (
                        "Load ida_script.py in IDA Pro or ghidra_script.py in Ghidra "
                        "to import all Dart symbols into your disassembler."
                    ),
                },
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "blutter",
                    "error": "Blutter timed out after 600s (large app — try --dart-version to skip auto-detect)"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "blutter", "error": str(exc)}
