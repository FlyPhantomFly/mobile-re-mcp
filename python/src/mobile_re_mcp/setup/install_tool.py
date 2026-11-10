"""
setup/install_tool.py — Downloads helper tools into ~/tools (or $MOBILE_RE_MCP_TOOLS_DIR).

Every download is pinned to a release and checked against a SHA-256 before it is used.
The install_tool MCP tool is off unless MOBILE_RE_MCP_ALLOW_INSTALL=1; `mobile-re-mcp-py --setup` always works.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from mobile_re_mcp.paths import tools_dir

_APKTOOL = "2.12.1"

# name -> (url, sha256). Hashes were taken from the upstream release files on 2026-11-02.
_PINNED: dict[str, tuple[str, str]] = {
    "apktool.jar": (
        f"https://github.com/iBotPeaches/Apktool/releases/download/v{_APKTOOL}/apktool_{_APKTOOL}.jar",
        "66cf4524a4a45a7f56567d08b2c9b6ec237bcdd78cee69fd4a59c8a0243aeafa",
    ),
    "apktool.sh": (
        f"https://raw.githubusercontent.com/iBotPeaches/Apktool/v{_APKTOOL}/scripts/linux/apktool",
        "493a9c98df968a25c373ca9df871ca77730c82954be4959b74e90adaf91a0e77",
    ),
    "apktool.bat": (
        f"https://raw.githubusercontent.com/iBotPeaches/Apktool/v{_APKTOOL}/scripts/windows/apktool.bat",
        "b27150908edde47533463e4a3cc518541b253b2a7bf16f21d0df33646afce8d3",
    ),
    "jadx.zip": (
        "https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip",
        "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974",
    ),
    "uber-apk-signer.jar": (
        "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar",
        "e1299fd6fcf4da527dd53735b56127e8ea922a321128123b9c32d619bba1d835",
    ),
    "il2cppdumper.zip": (
        "https://github.com/Perfare/Il2CppDumper/releases/download/v6.7.46/Il2CppDumper-net6-v6.7.46.zip",
        "db9bbbc538e33abfb057c7757ae5d6c1f16a05fdc0d13af8a5a67ea31faaba0c",
    ),
    "scrcpy-win.zip": (
        "https://github.com/Genymobile/scrcpy/releases/download/v5.0.1/scrcpy-win64-v5.0.1.zip",
        "b12a2c4ee8be317422451fc7dcf8ee20a71b5ea7ef9ad73ddd825a25316227a5",
    ),
}

_PIP_TOOLS: dict[str, str] = {
    "frida": "frida",
    "frida-tools": "frida-tools",
    "objection": "objection",
    "androguard": "androguard",
    "apkid": "apkid",
    "apkleaks": "apkleaks",
    "quark-engine": "quark-engine",
    "mitmproxy": "mitmproxy",
    "capstone": "capstone",
    "keystone-engine": "keystone-engine",
    "hermes-dec": "hermes-dec",
}

_NPM_TOOLS: dict[str, str] = {
    "apk-mitm": "apk-mitm",
    "frida-compile": "frida-compile",
}

# Tools with no automated recipe — the assistant must run the manual steps.
# 'medusa' is deliberately absent from _PIP_TOOLS: the PyPI package 'medusa'
# is the foofus.net SSH login cracker, NOT the Medusa RE framework.
_MANUAL_TOOLS: dict[str, str] = {
    "medusa": "Medusa RE framework — see https://github.com/Ch0pin/medusa "
    "(the PyPI 'medusa' package is an unrelated SSH cracker; do not install it)",
    "medusa-framework": "Medusa RE framework — see https://github.com/Ch0pin/medusa "
    "(the PyPI 'medusa' package is an unrelated SSH cracker; do not install it)",
    "fridump": "fridump was dropped from the setup recipes: frida_memdump does "
    "not use it (it walks memory maps through its own Frida session)",
}


class DownloadError(RuntimeError):
    pass


def _fetch(url: str):
    if not url.startswith("https://"):
        raise DownloadError(f"refusing non-https URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "mobile-re-mcp"})
    return urllib.request.urlopen(req, timeout=120)  # noqa: S310 (https enforced above)


def _download(key: str, dest: Path) -> None:
    """Download a pinned file to *dest*, keeping it only if the SHA-256 matches."""
    url, expected = _PINNED[key]
    dest.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=".download-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, _fetch(url) as resp:
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                digest.update(chunk)
                out.write(chunk)
        if digest.hexdigest() != expected:
            raise DownloadError(
                f"SHA-256 mismatch for {url}: expected {expected}, got {digest.hexdigest()}"
            )
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)


def _extract_zip(zip_path: Path, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    root = dest_dir.resolve()
    with zipfile.ZipFile(zip_path) as z:
        for member in z.infolist():
            target = (root / member.filename).resolve()
            if root != target and root not in target.parents:
                raise DownloadError(f"unsafe path in archive: {member.filename}")
        z.extractall(root)


def _download_zip(key: str, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    zip_path = dest_dir / ".archive.zip"
    try:
        _download(key, zip_path)
        _extract_zip(zip_path, dest_dir)
    finally:
        zip_path.unlink(missing_ok=True)


def _make_executable(path: Path) -> None:
    if os.name != "nt":
        os.chmod(path, 0o755)


def _result(fn) -> dict:
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Binary downloaders
# ---------------------------------------------------------------------------

def _install_apktool() -> dict:
    def run() -> dict:
        td = tools_dir()
        _download("apktool.jar", td / "apktool.jar")
        if os.name == "nt":
            _download("apktool.bat", td / "apktool.bat")
        else:
            _download("apktool.sh", td / "apktool")
            _make_executable(td / "apktool")
        return {"status": "ok", "message": f"apktool {_APKTOOL} installed and verified"}

    return _result(run)


def _install_jadx() -> dict:
    def run() -> dict:
        target = tools_dir() / "jadx"
        if target.exists():
            shutil.rmtree(target)
        _download_zip("jadx.zip", target)
        if os.name != "nt":
            _make_executable(target / "bin" / "jadx")
        return {"status": "ok", "message": "jadx 1.5.6 installed and verified"}

    return _result(run)


def _install_uber_apk_signer() -> dict:
    def run() -> dict:
        _download("uber-apk-signer.jar", tools_dir() / "signing" / "uber-apk-signer.jar")
        return {"status": "ok", "message": "uber-apk-signer 1.3.0 installed and verified"}

    return _result(run)


def _install_il2cppdumper() -> dict:
    def run() -> dict:
        _download_zip("il2cppdumper.zip", tools_dir() / "il2cppdumper")
        return {"status": "ok", "message": "Il2CppDumper 6.7.46 installed and verified"}

    return _result(run)


def _install_adb() -> dict:
    return {
        "status": "manual_required",
        "message": "adb is not downloaded automatically because Google only publishes an unversioned 'latest' build.",
        "instructions": "Linux: sudo apt install adb | Mac: brew install --cask android-platform-tools | Windows: https://developer.android.com/tools/releases/platform-tools",
    }


def _install_scrcpy() -> dict:
    if os.name != "nt":
        return {
            "status": "manual_required",
            "message": "scrcpy must be installed via your package manager on Linux and Mac",
            "instructions": "Linux: sudo apt install scrcpy | Mac: brew install scrcpy",
        }

    def run() -> dict:
        _download_zip("scrcpy-win.zip", tools_dir() / "scrcpy")
        return {"status": "ok", "message": "scrcpy 5.0.1 installed and verified"}

    return _result(run)


# ---------------------------------------------------------------------------
# pip / npm
# ---------------------------------------------------------------------------

def _frida_constraints() -> str | None:
    """Pin whatever Frida is installed now, so installing objection and friends can't move it."""
    pins = []
    for dist in ("frida", "frida-tools"):
        try:
            pins.append(f"{dist}=={importlib.metadata.version(dist)}")
        except importlib.metadata.PackageNotFoundError:
            continue
    if not pins:
        return None
    fd, name = tempfile.mkstemp(prefix="frida-constraints-", suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(pins) + "\n")
    return name


def _pip_install(display_name: str, package: str) -> dict:
    constraints = _frida_constraints()
    cmd = [sys.executable, "-m", "pip", "install", package]
    if constraints:
        cmd[4:4] = ["-c", constraints]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if proc.returncode == 0:
            return {"status": "ok", "message": f"Installed {package} into {sys.prefix}"}
        return {"status": "error", "error": (proc.stderr or proc.stdout)[-2000:]}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)}
    finally:
        if constraints:
            Path(constraints).unlink(missing_ok=True)


def _npm_install(display_name: str, package: str) -> dict:
    try:
        proc = subprocess.run(["npm", "install", "-g", package], capture_output=True, text=True, timeout=300)
        if proc.returncode == 0:
            return {"status": "ok", "message": f"npm installed {package}"}
        return {"status": "error", "error": (proc.stderr or proc.stdout)[-2000:]}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

_BINARY_INSTALLERS = {
    "apktool": _install_apktool,
    "jadx": _install_jadx,
    "uber-apk-signer": _install_uber_apk_signer,
    "il2cppdumper": _install_il2cppdumper,
    "adb": _install_adb,
    "scrcpy": _install_scrcpy,
}


def install_tool(tool_name: str) -> dict:
    """Install *tool_name* from a pinned download, pip, or npm."""
    if tool_name in _BINARY_INSTALLERS:
        return _BINARY_INSTALLERS[tool_name]()

    if tool_name in ("smali", "baksmali"):
        return {
            "status": "manual_required",
            "message": "apktool already bundles smali/baksmali. Standalone jars are on Maven Central (com.android.tools.smali).",
        }

    manual = _MANUAL_TOOLS.get(tool_name)
    if manual:
        return {"status": "manual_required", "message": manual}

    pip_pkg = _PIP_TOOLS.get(tool_name)
    if pip_pkg:
        return _pip_install(tool_name, pip_pkg)

    npm_pkg = _NPM_TOOLS.get(tool_name)
    if npm_pkg:
        if shutil.which("npm"):
            return _npm_install(tool_name, npm_pkg)
        return {"status": "error", "error": "npm not found. Install Node.js first."}

    return {
        "status": "error",
        "tool": tool_name,
        "error": f"No install recipe for '{tool_name}'.",
    }


def install_all_missing_tools() -> None:
    """Check all tools and install the missing ones."""
    from mobile_re_mcp.setup.check_tools import check_all_tools

    print("[*] Analyzing current environment...")
    tools = check_all_tools().get("tools", {})

    core_tools = [
        "apktool", "jadx", "uber-apk-signer", "il2cppdumper", "adb", "scrcpy",
        "frida", "frida-tools", "objection",
        "androguard", "apkid", "apkleaks", "quark-engine", "mitmproxy",
    ]

    for t in core_tools:
        if tools.get(t, {}).get("available", False):
            print(f"[+] Found: {t} (ready)")
            continue
        print(f"[-] Missing: {t}, installing...")
        res = install_tool(t)
        if res.get("status") == "ok":
            print(f"  [+] {res.get('message', 'Installed')}")
        else:
            err = res.get("error", res.get("message", "Unknown error"))
            print(f"  [!] {t}: {err}")
            if res.get("instructions"):
                print(f"      {res['instructions']}")
