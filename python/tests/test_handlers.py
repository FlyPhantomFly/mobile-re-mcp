import io
import subprocess

import pytest

from mobile_re_mcp.handlers import memory as memory_mod
from mobile_re_mcp.handlers import native as native_mod
from mobile_re_mcp.handlers import network as network_mod
from mobile_re_mcp.handlers import static as static_mod
from mobile_re_mcp.setup import install_tool as inst


def test_memory_roundtrip_and_traversal(isolated_env):
    m = memory_mod.MemoryHandler()
    out = m.memory_write({"package": "com.example.app", "content": "hello"})
    assert out["status"] == "ok"
    assert "/.local/share/mobile-re-mcp/targets/com.example.app/memory.md" in out["output"]["path"]
    assert m.memory_read({"package": "com.example.app"})["output"]["content"] == "hello"
    for bad in ("../../x", "/etc", "a/b", ".hidden"):
        with pytest.raises(ValueError):
            m.memory_read({"package": bad})


def test_memory_size_limit():
    out = memory_mod.MemoryHandler().memory_write({"package": "a.b", "content": "x" * 300_000})
    assert out["status"] == "error"


def test_search_strings_cannot_inject_rg_options(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(static_mod, "_check_tool", lambda n: True)
    monkeypatch.setattr(static_mod.subprocess, "run", fake_run)
    static_mod.StaticHandler().search_strings({"pattern": "--pre=/tmp/evil.sh", "path": "/work"})
    cmd = seen["cmd"]
    assert cmd[:2] == ["rg", "--json"]
    assert cmd[cmd.index("-e") + 1] == "--pre=/tmp/evil.sh"
    assert cmd[-2:] == ["--", "/work"]


def test_native_disasm_blocks_injection_even_without_guard(tmp_path, monkeypatch):
    so = tmp_path / "lib.so"
    so.write_bytes(b"\x7fELF")
    called = []
    monkeypatch.setattr(native_mod, "_check", lambda n: True)
    monkeypatch.setattr(native_mod.subprocess, "run", lambda *a, **k: called.append(a))
    out = native_mod.NativeHandler().native_disasm({"so_path": str(so), "target": "main;!id"})
    assert out["status"] == "error" and not called


def test_mitm_listens_on_loopback_only(monkeypatch):
    seen = {}

    class FakeProc:
        pid = 1

        def poll(self):
            return None

    def fake_popen(cmd, **kw):
        seen["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(network_mod, "_check_tool", lambda n: True)
    monkeypatch.setattr(network_mod.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(network_mod.time, "sleep", lambda s: None)
    out = network_mod.NetworkHandler().mitm_start({"port": 8080})
    assert out["status"] == "ok"
    cmd = seen["cmd"]
    assert cmd[cmd.index("--listen-host") + 1] == "127.0.0.1"
    assert "adb reverse" in out["output"]["proxy_hint"]


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_download_requires_matching_sha256(tmp_path, monkeypatch):
    import hashlib

    data = b"payload"
    monkeypatch.setitem(inst._PINNED, "t.jar", ("https://example.invalid/t.jar", hashlib.sha256(data).hexdigest()))
    monkeypatch.setattr(inst, "_fetch", lambda url: _Resp(data))
    dest = tmp_path / "t.jar"
    inst._download("t.jar", dest)
    assert dest.read_bytes() == data

    monkeypatch.setattr(inst, "_fetch", lambda url: _Resp(b"tampered"))
    bad = tmp_path / "bad.jar"
    with pytest.raises(inst.DownloadError):
        inst._download("t.jar", bad)
    assert not bad.exists()
    assert [p.name for p in tmp_path.iterdir() if p.name.startswith(".download-")] == []


def test_download_refuses_plain_http():
    with pytest.raises(inst.DownloadError):
        inst._fetch("http://example.com/x")


def test_zip_slip_is_rejected(tmp_path):
    import zipfile

    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../../escape.txt", "x")
    with pytest.raises(inst.DownloadError):
        inst._extract_zip(z, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()


def test_every_pin_has_a_real_sha256():
    for name, (url, digest) in inst._PINNED.items():
        assert url.startswith("https://"), name
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), name


def test_frida_script_library_ships_every_catalogue_script(isolated_env):
    """F-PY-3: the package ships its 8 scripts — the library must not be empty."""
    from mobile_re_mcp.frida_scripts import index

    expected = {
        "ssl_pinning_universal", "root_detection_bypass", "frida_detection_bypass",
        "crypto_monitor", "memory_scan", "method_tracer", "storage_monitor",
        "network_monitor",
    }
    assert {s["name"] for s in index.SCRIPT_CATALOGUE} == expected
    on_disk = {m["name"] for m in index.list_scripts()}
    assert on_disk == expected, f"missing on disk: {sorted(expected - on_disk)}"
    for meta in index.list_scripts():
        content = index.get_script_content(meta["name"])
        assert content and content.strip(), meta["name"]


def test_user_script_override_precedence(isolated_env):
    from mobile_re_mcp.frida_scripts import index

    d = isolated_env / ".local" / "share" / "mobile-re-mcp" / "frida_scripts"
    d.mkdir(parents=True)
    (d / "crypto_monitor.js").write_text("// mine")
    assert index.get_script_content("crypto_monitor") == "// mine"  # override wins
    # ...but every other script still resolves to the shipped library
    assert index.get_script_content("ssl_pinning_universal") is not None
    assert "// mine" not in index.get_script_content("memory_scan")


def test_shipped_scripts_register_and_rearm_the_config_protocol():
    """Every script accepts {type:'config', ...}: UPPER primary, lowercase fallback."""
    from mobile_re_mcp.frida_scripts import index

    for meta in index.SCRIPT_CATALOGUE:
        src = index.get_script_content(meta["name"])
        # one registration + one re-arm inside the handler
        assert src.count('recv("config"') >= 2, meta["name"]
        assert "function _onConfig" in src, meta["name"]


def test_shipped_scripts_use_only_frida_17_globals():
    """D-5: the bare `process` global is gone in frida 17 (QuickJS).

    memory_scan called `process.enumerateRanges("rw-")`, which turned
    every scan into `ReferenceError: 'process' is not defined` at
    runtime — `node --check` cannot catch missing script globals, so the
    guard is a source-level scan for the lowercase pre-QuickJS names.
    """
    import re

    from mobile_re_mcp.frida_scripts import index

    bare = re.compile(
        r"(?<![.\w])process\.(enumerateRanges|enumerateModules|enumerateThreads|"
        r"enumerateMallocRanges|getModuleByName|findModuleByName|"
        r"isDebuggerPaused|setExceptionHandler)\b"
    )
    for meta in index.SCRIPT_CATALOGUE:
        src = index.get_script_content(meta["name"])
        assert not bare.search(src), (
            f"{meta['name']} uses the pre-frida-17 bare `process` global"
        )


def test_memory_scan_contract_for_frida_find_bytes():
    """frida_find_bytes str.replace-patches these exact lines — they must exist."""
    from mobile_re_mcp.frida_scripts import index

    src = index.get_script_content("memory_scan")
    assert 'var SEARCH_STRING = "";' in src
    assert 'var SEARCH_HEX = "";' in src
    assert 'var MAX_RESULTS = 50;' in src
    # ...and produces the message shapes the handler consumes
    # (pretty-printed across lines: `type: "match",` then `match: {`)
    assert 'type: "match",' in src and "match: {" in src
    assert 'type: "scan_complete"' in src
    # method_tracer's handler contract
    tracer = index.get_script_content("method_tracer")
    assert 'type: "method_trace"' in tracer


def test_signer_jar_is_never_relative(isolated_env):
    from mobile_re_mcp.config import signer_jar

    assert signer_jar().is_absolute()
    assert signer_jar().name == "uber-apk-signer.jar"
