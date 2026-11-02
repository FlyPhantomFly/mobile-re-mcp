"""
handlers/native.py — Native library analysis handler.

Gaps covered:
  #1  native_strings    — strings/readelf on .so files
      native_exports    — enumerate exported symbols
      native_disasm     — radare2 batch disassembly of a function
  #8  il2cpp_dump       — run Il2CppDumper on a Unity APK
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
_TIMEOUT_LONG = 300
from mobile_re_mcp.paths import scratch_dir, tools_dir

_TOOLS_DIR = tools_dir()


def _check(name: str) -> bool:
    return shutil.which(name) is not None


def _missing(tool: str, hint: str = "") -> dict:
    return {
        "status": "missing_tool",
        "tool": tool,
        "error": f"'{tool}' not found. Run install_tool('{tool}').",
        "hint": hint,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_native_libs(apk_path: str, abi: str = "arm64-v8a") -> list[Path]:
    """Extract .so files for the requested ABI from an APK into a temp dir."""
    extracted: list[Path] = []
    try:
        with zipfile.ZipFile(apk_path) as zf:
            for name in zf.namelist():
                if f"lib/{abi}/" in name and name.endswith(".so"):
                    tmp = scratch_dir("native_libs") / Path(name).name
                    tmp.parent.mkdir(parents=True, exist_ok=True)
                    tmp.write_bytes(zf.read(name))
                    extracted.append(tmp)
    except Exception as exc:  # noqa: BLE001
        logger.warning("APK extraction failed: %s", exc)
    return extracted


def _filter_interesting_strings(strings: list[str]) -> list[str]:
    """Heuristically filter strings that look like keys, URLs, or class names."""
    interesting = []
    for s in strings:
        if len(s) < 4:
            continue
        # URLs and endpoints
        if s.startswith(("http://", "https://", "ws://")) or "://" in s:
            interesting.append(s)
        # Looks like a path or package name
        elif "/" in s and len(s) > 8:
            interesting.append(s)
        # Hex-looking strings (possible keys)
        elif re.match(r"^[0-9a-fA-F]{16,}$", s):
            interesting.append(s)
        # Long words with mixed case (possible class names / symbols)
        elif len(s) > 20 and any(c.isupper() for c in s):
            interesting.append(s)
    return interesting


class NativeHandler:
    """Native library analysis handler."""

    # =========================================================================
    # Gap #1 — native_strings
    # =========================================================================

    def native_strings(self, args: dict) -> dict:
        """Extract printable strings from a .so file or all .so files in an APK.

        Uses `strings` binary if available, falls back to pure-Python
        extraction for Windows compatibility.
        """
        so_path = args.get("so_path", "")
        apk_path = args.get("apk_path", "")
        abi = args.get("abi", "arm64-v8a")
        min_len = int(args.get("min_len", 8))
        interesting_only = bool(args.get("interesting_only", True))

        so_files: list[Path] = []

        if so_path and Path(so_path).exists():
            so_files = [Path(so_path)]
        elif apk_path:
            so_files = _extract_native_libs(apk_path, abi)
        else:
            return {"status": "error", "tool": "native_strings",
                    "error": "Provide so_path or apk_path"}

        all_results: dict[str, dict] = {}

        for so in so_files:
            strings_list = self._extract_strings(so, min_len)
            filtered = _filter_interesting_strings(strings_list) if interesting_only else strings_list

            all_results[so.name] = {
                "total_strings": len(strings_list),
                "shown": len(filtered),
                "strings": filtered,
            }

        return {
            "status": "ok",
            "tool": "native_strings",
            "output": {
                "libs_analyzed": len(so_files),
                "interesting_only": interesting_only,
                "results": all_results,
            },
        }

    def _extract_strings(self, so_path: Path, min_len: int) -> list[str]:
        """Run `strings` binary or fall back to pure-Python extraction."""
        if _check("strings"):
            try:
                proc = subprocess.run(
                    ["strings", f"-n{min_len}", str(so_path)],
                    capture_output=True, text=True, timeout=_TIMEOUT,
                )
                return [s.strip() for s in proc.stdout.splitlines() if s.strip()]
            except Exception:  # noqa: BLE001
                pass

        # Pure-Python fallback (covers Windows where `strings` isn't on PATH)
        data = so_path.read_bytes()
        printable = set(range(0x20, 0x7F)) | {0x09, 0x0A}
        current: list[int] = []
        found: list[str] = []
        for byte in data:
            if byte in printable:
                current.append(byte)
            else:
                if len(current) >= min_len:
                    found.append(bytes(current).decode("ascii", errors="ignore"))
                current = []
        if len(current) >= min_len:
            found.append(bytes(current).decode("ascii", errors="ignore"))
        return found

    # =========================================================================
    # Gap #1 — native_exports
    # =========================================================================

    def native_exports(self, args: dict) -> dict:
        """List exported symbols from a .so using readelf or nm.

        Falls back to pure ELF parsing for Windows compatibility.
        """
        so_path = args.get("so_path", "")
        apk_path = args.get("apk_path", "")
        abi = args.get("abi", "arm64-v8a")

        so_files: list[Path] = []
        if so_path and Path(so_path).exists():
            so_files = [Path(so_path)]
        elif apk_path:
            so_files = _extract_native_libs(apk_path, abi)
        else:
            return {"status": "error", "tool": "native_exports",
                    "error": "Provide so_path or apk_path"}

        all_results: dict[str, list[dict]] = {}

        for so in so_files:
            exports = self._get_exports(so)
            all_results[so.name] = exports

        total = sum(len(v) for v in all_results.values())
        return {
            "status": "ok",
            "tool": "native_exports",
            "output": {
                "libs_analyzed": len(so_files),
                "total_exports": total,
                "exports": all_results,
            },
        }

    def _get_exports(self, so_path: Path) -> list[dict]:
        """Return exports via readelf → nm → pure ELF fallback."""
        # Try readelf first
        if _check("readelf"):
            try:
                proc = subprocess.run(
                    ["readelf", "--dyn-syms", "--wide", str(so_path)],
                    capture_output=True, text=True, timeout=_TIMEOUT,
                )
                return self._parse_readelf(proc.stdout)
            except Exception:  # noqa: BLE001
                pass

        # Try nm
        if _check("nm"):
            try:
                proc = subprocess.run(
                    ["nm", "--dynamic", "--defined-only", str(so_path)],
                    capture_output=True, text=True, timeout=_TIMEOUT,
                )
                return self._parse_nm(proc.stdout)
            except Exception:  # noqa: BLE001
                pass

        # Pure ELF fallback
        return self._parse_elf_exports(so_path)

    def _parse_readelf(self, output: str) -> list[dict]:
        exports = []
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 8 and parts[4] in ("FUNC", "OBJECT"):
                exports.append({
                    "name": parts[7],
                    "type": parts[4],
                    "size": parts[2],
                    "bind": parts[5],
                })
        return exports

    def _parse_nm(self, output: str) -> list[dict]:
        exports = []
        for line in output.splitlines():
            parts = line.strip().split(None, 2)
            if len(parts) == 3:
                exports.append({"address": parts[0], "type": parts[1], "name": parts[2]})
        return exports

    def _parse_elf_exports(self, so_path: Path) -> list[dict]:
        """Minimal ELF dynamic symbol table parser (pure Python, ARM64/x86_64)."""
        try:
            data = so_path.read_bytes()
        except Exception:  # noqa: BLE001
            return []

        if len(data) < 64 or data[:4] != b"\x7fELF":
            return []

        import struct

        is_64 = data[4] == 2  # EI_CLASS
        le = data[5] == 1     # EI_DATA little-endian

        endian = "<" if le else ">"

        if is_64:
            e_shoff, = struct.unpack_from(endian + "Q", data, 40)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 58)
            sh_fmt = endian + "IIQQQQIIQQ"
            sym_fmt = endian + "IBBHQQ"
            sym_size = 24
        else:
            e_shoff, = struct.unpack_from(endian + "I", data, 32)
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 48)
            sh_fmt = endian + "IIIIIIIIII"
            sym_fmt = endian + "IIIBBH"
            sym_size = 16

        exports: list[dict] = []

        try:
            sections = []
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                sh = struct.unpack_from(sh_fmt, data, off)
                sections.append(sh)

            strtab_data = b""
            dynsym_section = None

            for sh in sections:
                SHT_DYNSYM = 11
                SHT_STRTAB = 3
                if sh[1] == SHT_DYNSYM:
                    dynsym_section = sh
                elif sh[1] == SHT_STRTAB and strtab_data == b"":
                    strtab_off, strtab_sz = (sh[4], sh[5]) if is_64 else (sh[4], sh[5])
                    strtab_data = data[strtab_off: strtab_off + strtab_sz]

            if dynsym_section:
                ds_off = dynsym_section[4] if is_64 else dynsym_section[4]
                ds_sz = dynsym_section[5] if is_64 else dynsym_section[5]
                count = ds_sz // sym_size
                for i in range(count):
                    sym = struct.unpack_from(sym_fmt, data, ds_off + i * sym_size)
                    name_off = sym[0]
                    if strtab_data and name_off < len(strtab_data):
                        end = strtab_data.index(b"\x00", name_off)
                        name = strtab_data[name_off:end].decode("utf-8", errors="ignore")
                        if name:
                            exports.append({"name": name, "type": "ELF_SYM"})
        except Exception:  # noqa: BLE001
            pass

        return exports

    # =========================================================================
    # Gap #1 — native_disasm
    # =========================================================================

    def native_disasm(self, args: dict) -> dict:
        """Disassemble a function or offset in a .so using radare2 (r2).

        Requires radare2 (`r2`) on PATH.
        """
        if not _check("r2"):
            return _missing("r2", "sudo apt install radare2  OR  brew install radare2")

        so_path = args.get("so_path", "")
        target = args.get("target", "")        # symbol name or 0x<hex> offset
        n_instructions = max(1, min(int(args.get("n_instructions", 32)), 2000))
        mode = args.get("mode", "asm")         # asm | graph | pseudocode

        if not so_path or not Path(so_path).exists():
            return {"status": "error", "tool": "native_disasm",
                    "error": f"so_path '{so_path}' not found"}

        # radare2 treats ';' and '!' as command syntax, so only plain symbols and offsets get through.
        if not re.fullmatch(r"(0x[0-9a-fA-F]{1,16}|[A-Za-z0-9_.@]{1,200})", target):
            return {"status": "error", "tool": "native_disasm",
                    "error": "target must be a symbol name or a 0x offset"}
        seek = f"sym.{target}" if not target.startswith("0x") else target

        if mode == "graph":
            r2_cmds = f"aaa; agf @ {seek}"
        elif mode == "pseudocode":
            r2_cmds = f"aaa; pdg @ {seek}"
        else:
            r2_cmds = f"aaa; pd {n_instructions} @ {seek}; pif @ {seek}"

        try:
            proc = subprocess.run(
                ["r2", "-q", "-c", r2_cmds, str(so_path)],
                capture_output=True, text=True, timeout=_TIMEOUT_LONG,
            )
            if proc.returncode != 0 and not proc.stdout:
                return {"status": "error", "tool": "native_disasm",
                        "error": proc.stderr or "r2 returned no output"}

            return {
                "status": "ok",
                "tool": "native_disasm",
                "output": {
                    "so_path": so_path,
                    "target": target,
                    "mode": mode,
                    "disassembly": proc.stdout,
                },
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "native_disasm",
                    "error": "r2 timed out after 300s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "native_disasm", "error": str(exc)}

    # =========================================================================
    # Gap #8 — il2cpp_dump
    # =========================================================================

    def il2cpp_dump(self, args: dict) -> dict:
        """Run Il2CppDumper on a Unity IL2CPP APK.

        Extracts `global-metadata.dat` and `libil2cpp.so` from the APK,
        then runs Il2CppDumper to recover a `dump.cs` symbol file.

        Requires `dotnet` runtime + Il2CppDumper from https://github.com/Perfare/Il2CppDumper
        """
        apk_path = args.get("apk_path", "")
        abi = args.get("abi", "arm64-v8a")
        output_dir = args.get("output_dir", "")

        if not apk_path or not Path(apk_path).exists():
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": f"apk_path '{apk_path}' not found"}

        # Find Il2CppDumper
        dumper_paths = [
            _TOOLS_DIR / "il2cppdumper" / "Il2CppDumper",
            _TOOLS_DIR / "il2cppdumper" / "Il2CppDumper.exe",
            Path("/opt/il2cppdumper/Il2CppDumper"),
        ]
        dumper_bin: Optional[Path] = None
        for p in dumper_paths:
            if p.exists():
                dumper_bin = p
                break
        if dumper_bin is None and _check("Il2CppDumper"):
            dumper_bin = Path(shutil.which("Il2CppDumper"))  # type: ignore[arg-type]

        if dumper_bin is None:
            return {
                "status": "missing_tool",
                "tool": "il2cpp_dump",
                "error": "Il2CppDumper not found",
                "hint": (
                    "Download from https://github.com/Perfare/Il2CppDumper/releases\n"
                    f"Extract to {_TOOLS_DIR}/il2cppdumper/"
                ),
            }

        out_dir = Path(output_dir) if output_dir else Path(apk_path).parent / "il2cpp_out"
        out_dir.mkdir(parents=True, exist_ok=True)

        # Extract required files from APK
        metadata_path = out_dir / "global-metadata.dat"
        il2cpp_so_path = out_dir / f"libil2cpp_{abi}.so"

        try:
            with zipfile.ZipFile(apk_path) as zf:
                names = zf.namelist()

                meta_name = next(
                    (n for n in names if "global-metadata.dat" in n), None
                )
                if meta_name:
                    metadata_path.write_bytes(zf.read(meta_name))

                il2cpp_name = next(
                    (n for n in names if f"lib/{abi}/libil2cpp.so" in n), None
                )
                if il2cpp_name:
                    il2cpp_so_path.write_bytes(zf.read(il2cpp_name))

        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": f"APK extraction failed: {exc}"}

        if not metadata_path.exists():
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": "global-metadata.dat not found in APK. Is this a Unity IL2CPP app?"}
        if not il2cpp_so_path.exists():
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": f"libil2cpp.so for abi={abi} not found in APK."}

        # Run Il2CppDumper
        try:
            cmd = [str(dumper_bin), str(il2cpp_so_path), str(metadata_path), str(out_dir)]
            if not _check("Il2CppDumper") and str(dumper_bin).endswith(".exe"):
                cmd = ["dotnet", str(dumper_bin)] + cmd[1:]

            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                cwd=str(out_dir),
                timeout=_TIMEOUT_LONG,
            )

            dump_cs = out_dir / "dump.cs"
            script_json = out_dir / "script.json"

            return {
                "status": "ok" if dump_cs.exists() else "error",
                "tool": "il2cpp_dump",
                "output": {
                    "output_dir": str(out_dir),
                    "dump_cs": str(dump_cs) if dump_cs.exists() else None,
                    "script_json": str(script_json) if script_json.exists() else None,
                    "raw": proc.stdout[-2000:] if proc.stdout else proc.stderr[-2000:],
                    "note": (
                        "dump.cs contains class/method names. "
                        "Use with Ghidra Il2CppDumper script for full analysis."
                    ),
                },
            }
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "il2cpp_dump",
                    "error": "Il2CppDumper timed out after 300s"}
        except Exception as exc:  # noqa: BLE001
            return {"status": "error", "tool": "il2cpp_dump", "error": str(exc)}
