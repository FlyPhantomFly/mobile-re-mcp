"""
handlers/patcher.py — APK smali patching and Frida gadget injection handler.

Gaps covered:
  #6  smali_patch    — edit a specific class/method in decompiled smali
      inject_gadget  — embed frida-gadget .so into APK + rebuild + sign
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_TIMEOUT = 120
_TIMEOUT_LONG = 300
from mobile_re_mcp.config import load_config, signer_jar
from mobile_re_mcp.paths import tools_dir

_TOOLS_DIR = tools_dir()
_GADGETS_DIR = _TOOLS_DIR / "gadgets"


def _check(name: str) -> bool:
    return shutil.which(name) is not None


def _missing(tool: str, hint: str = "") -> dict:
    return {
        "status": "missing_tool",
        "tool": tool,
        "error": f"'{tool}' not found",
        "hint": hint,
    }


def _get_signing_config() -> dict:
    """Signing settings from the packaged defaults plus the user's config file."""
    cfg = dict(load_config().get("signing", {}))
    cfg["jar_path"] = str(signer_jar())
    return cfg


class PatcherHandler:
    """APK smali patching and gadget injection handler."""

    # =========================================================================
    # Gap #6 — smali_patch
    # =========================================================================

    def smali_patch(self, args: dict) -> dict:
        """Patch a specific smali class file.

        Finds the target class in a decompiled smali directory (from
        apktool), applies a regex or literal replacement, and writes
        the result back. Does NOT rebuild the APK — call apk_rebuild_sign
        after patching.

        Args:
            smali_dir:      apktool output directory
            class_name:     Java class name e.g. "com.example.Security"
            search:         string or regex pattern to find
            replace:        replacement string
            use_regex:      if true, treat search as regex (default false)
            method_name:    optional — restrict edit to this method only
        """
        smali_dir = Path(args.get("smali_dir", ""))
        class_name = args.get("class_name", "")
        search = args.get("search", "")
        replace = args.get("replace", "")
        use_regex = bool(args.get("use_regex", False))
        method_name = args.get("method_name", "")

        if not smali_dir.exists():
            return {"status": "error", "tool": "smali_patch",
                    "error": f"smali_dir '{smali_dir}' not found"}
        if not class_name or not search:
            return {"status": "error", "tool": "smali_patch",
                    "error": "Provide class_name and search pattern"}

        # Locate the .smali file
        smali_file = self._find_smali(smali_dir, class_name)
        if smali_file is None:
            return {
                "status": "error",
                "tool": "smali_patch",
                "error": f"Smali file for class '{class_name}' not found in {smali_dir}",
                "hint": "Check the class name using search_strings() first.",
            }

        original = smali_file.read_text(encoding="utf-8")

        if method_name:
            content = self._patch_in_method(original, method_name, search, replace, use_regex)
        else:
            content = self._do_replace(original, search, replace, use_regex)

        changes = content != original
        if changes:
            # Backup original
            backup = smali_file.with_suffix(".smali.bak")
            if not backup.exists():
                backup.write_text(original, encoding="utf-8")
            smali_file.write_text(content, encoding="utf-8")

        # Count replacements
        if use_regex:
            matches = len(re.findall(search, original))
        else:
            matches = original.count(search)

        return {
            "status": "ok",
            "tool": "smali_patch",
            "output": {
                "smali_file": str(smali_file),
                "class_name": class_name,
                "method_name": method_name or "(all methods)",
                "occurrences_found": matches,
                "patched": changes,
                "backup": str(smali_file.with_suffix(".smali.bak")) if changes else None,
                "next_step": "Call apk_rebuild_sign(smali_dir) to rebuild and sign the APK.",
            },
        }

    def _find_smali(self, smali_dir: Path, class_name: str) -> Optional[Path]:
        """Locate a smali file by Java class name."""
        # Convert com.example.Foo → com/example/Foo.smali
        relative = class_name.replace(".", "/") + ".smali"
        # May be in smali/, smali_classes2/, smali_classes3/
        for subdir in smali_dir.iterdir():
            if subdir.is_dir():
                candidate = subdir / relative
                if candidate.exists():
                    return candidate
        # Direct match
        direct = smali_dir / relative
        return direct if direct.exists() else None

    def _do_replace(self, text: str, search: str, replace: str, use_regex: bool) -> str:
        if use_regex:
            return re.sub(search, replace, text)
        return text.replace(search, replace)

    def _patch_in_method(self, text: str, method_name: str, search: str, replace: str,
                         use_regex: bool) -> str:
        """Apply replacement only within the named method block."""
        # Smali method block pattern: .method ... method_name ... .end method
        method_re = re.compile(
            r"(\.method[^\n]*" + re.escape(method_name) + r"[^\n]*\n)"
            r"(.*?)"
            r"(\.end method)",
            re.DOTALL,
        )

        def patch_body(m: re.Match) -> str:
            header, body, footer = m.group(1), m.group(2), m.group(3)
            patched_body = self._do_replace(body, search, replace, use_regex)
            return header + patched_body + footer

        return method_re.sub(patch_body, text)

    # =========================================================================
    # Gap #6 — inject_gadget
    # =========================================================================

    def inject_gadget(self, args: dict) -> dict:
        """Embed frida-gadget into an APK and rebuild + sign it.

        The full workflow:
        1. Decompile APK with apktool
        2. Copy frida-gadget .so into lib/<abi>/
        3. Find Application.onCreate (or main Activity) and inject System.loadLibrary
        4. Rebuild with apktool
        5. Sign with uber-apk-signer

        Args:
            apk_path:       path to the target APK
            abi:            arm64-v8a | armeabi-v7a | x86_64 | x86
            gadget_path:    path to frida-gadget .so (optional — auto-detect from ~/tools/gadgets/)
            gadget_config:  frida-gadget config JSON (optional — defaults to listen mode)
            output_apk:     output APK path (optional)
        """
        if not _check("apktool"):
            return _missing("apktool", "sudo apt install apktool  OR  choco install apktool")

        apk_path = Path(args.get("apk_path", ""))
        abi = args.get("abi", "arm64-v8a")
        gadget_path_arg = args.get("gadget_path", "")
        gadget_config = args.get("gadget_config", "")
        output_apk = args.get("output_apk", "")

        if not apk_path.exists():
            return {"status": "error", "tool": "inject_gadget",
                    "error": f"APK not found: {apk_path}"}

        # 1. Find or verify gadget .so
        gadget_so = self._find_gadget(gadget_path_arg, abi)
        if gadget_so is None:
            return {
                "status": "missing_tool",
                "tool": "inject_gadget",
                "error": f"frida-gadget .so for abi={abi} not found",
                "hint": (
                    f"Download from github.com/frida/frida/releases and place in {_GADGETS_DIR}/\n"
                    "OR use frida_server_push with the matching frida version."
                ),
            }

        # 2. Decompile
        work_dir = apk_path.parent / (apk_path.stem + "_gadget_work")
        try:
            proc = subprocess.run(
                ["apktool", "d", str(apk_path), "-o", str(work_dir), "-f"],
                capture_output=True, text=True, timeout=_TIMEOUT_LONG,
            )
            if proc.returncode != 0:
                return {"status": "error", "tool": "inject_gadget",
                        "error": f"apktool decompile failed: {proc.stderr}"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "inject_gadget", "error": "apktool timed out"}

        # 3. Copy gadget into lib/<abi>/
        lib_dir = work_dir / "lib" / abi
        lib_dir.mkdir(parents=True, exist_ok=True)
        gadget_dest = lib_dir / "libgadget.so"
        shutil.copy2(str(gadget_so), str(gadget_dest))

        # Optional: write gadget config JSON
        if gadget_config:
            config_dest = lib_dir / "libgadget.config.so"
            config_dest.write_text(gadget_config, encoding="utf-8")
        else:
            # Default: listen mode on port 27042
            config_dest = lib_dir / "libgadget.config.so"
            config_dest.write_text(
                '{"interaction":{"type":"listen","address":"127.0.0.1","port":27042}}\n',
                encoding="utf-8",
            )

        # 4. Inject System.loadLibrary("gadget") into Application.onCreate
        patched_class = self._inject_loadlibrary(work_dir)

        # 5. Rebuild
        out_apk_unsigned = apk_path.parent / (apk_path.stem + "_gadget_unsigned.apk")
        try:
            proc = subprocess.run(
                ["apktool", "b", str(work_dir), "-o", str(out_apk_unsigned)],
                capture_output=True, text=True, timeout=_TIMEOUT_LONG,
            )
            if proc.returncode != 0:
                return {"status": "error", "tool": "inject_gadget",
                        "error": f"apktool rebuild failed: {proc.stderr}"}
        except subprocess.TimeoutExpired:
            return {"status": "error", "tool": "inject_gadget", "error": "apktool rebuild timed out"}

        # 6. Sign
        cfg = _get_signing_config()
        jar_path = cfg.get("jar_path", "uber-apk-signer.jar")
        final_apk = Path(output_apk) if output_apk else apk_path.parent / (apk_path.stem + "_gadget.apk")

        signed_ok = False
        sign_error = ""
        if Path(jar_path).exists() and _check("java"):
            sign_cmd = ["java", "-jar", jar_path, "--apks", str(out_apk_unsigned),
                        "--out", str(apk_path.parent)]
            try:
                sp = subprocess.run(sign_cmd, capture_output=True, text=True, timeout=_TIMEOUT)
                if sp.returncode == 0:
                    # uber-apk-signer appends -aligned-debugSigned.apk
                    for candidate in apk_path.parent.glob("*gadget_unsigned*signed*.apk"):
                        candidate.rename(final_apk)
                    signed_ok = True
                else:
                    sign_error = sp.stderr or sp.stdout
            except Exception as exc:  # noqa: BLE001
                sign_error = str(exc)
        else:
            sign_error = "uber-apk-signer not configured. Sign manually."

        return {
            "status": "ok",
            "tool": "inject_gadget",
            "output": {
                "gadget_so": str(gadget_so),
                "work_dir": str(work_dir),
                "patched_class": patched_class,
                "unsigned_apk": str(out_apk_unsigned),
                "signed_apk": str(final_apk) if signed_ok else None,
                "signed": signed_ok,
                "sign_error": sign_error or None,
                "install_command": f"adb install -r {final_apk}" if signed_ok else None,
                "note": (
                    "Start frida-gadget listener: frida -H 127.0.0.1:27042"
                    if signed_ok else "Sign the APK first, then reinstall."
                ),
            },
        }

    def _find_gadget(self, explicit_path: str, abi: str) -> Optional[Path]:
        """Find the frida-gadget .so for the given ABI."""
        if explicit_path and Path(explicit_path).exists():
            return Path(explicit_path)

        abi_map = {
            "arm64-v8a": "android-arm64",
            "armeabi-v7a": "android-arm",
            "x86_64": "android-x86_64",
            "x86": "android-x86",
        }
        arch = abi_map.get(abi, "android-arm64")

        if _GADGETS_DIR.exists():
            for f in sorted(_GADGETS_DIR.glob(f"frida-gadget-*-{arch}*.so"), reverse=True):
                return f

        return None

    def _inject_loadlibrary(self, work_dir: Path) -> str:
        """Find Application.onCreate smali and inject System.loadLibrary("gadget")."""
        load_smali = (
            "    const-string v0, \"gadget\"\n"
            "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n"
        )

        # Try to find Application.onCreate first
        app_smali_files: list[Path] = []
        for d in work_dir.iterdir():
            if d.is_dir():
                app_smali_files += list(d.glob("**/Application.smali"))
                app_smali_files += list(d.glob("**/App.smali"))

        target_file: Optional[Path] = None
        if app_smali_files:
            target_file = app_smali_files[0]
        else:
            # Fall back to main Activity
            for d in work_dir.iterdir():
                if d.is_dir():
                    for smali in d.glob("**/*.smali"):
                        content = smali.read_text(encoding="utf-8", errors="ignore")
                        if ".method public constructor <init>" in content:
                            target_file = smali
                            break
                if target_file:
                    break

        if target_file is None:
            return "(could not inject — no suitable class found; inject manually)"

        content = target_file.read_text(encoding="utf-8", errors="ignore")

        # Insert after first .method public ... onCreate
        insert_after = re.compile(
            r"(\.method public onCreate\(Landroid/os/Bundle;\)V)",
            re.MULTILINE,
        )
        if insert_after.search(content):
            new_content = insert_after.sub(
                r"\1\n" + load_smali,
                content, count=1,
            )
        else:
            # Insert at very first .method
            first_method = re.compile(r"(\.method )", re.MULTILINE)
            new_content = first_method.sub(
                load_smali + r"\1",
                content, count=1,
            )

        target_file.write_text(new_content, encoding="utf-8")
        return str(target_file)
