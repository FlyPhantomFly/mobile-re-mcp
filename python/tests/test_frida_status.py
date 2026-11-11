"""Regression tests for frida_status (extension E-PY-7).

No device needed: the fake frida module is injected into sys.modules, so
the device enumeration and responsiveness probe run hermetically.
"""

import sys
import types

import pytest

from mobile_re_mcp.handlers import dynamic as dynamic_mod


class _FakeDevice:
    def __init__(self, ident, name, dtype):
        self.id = ident
        self.name = name
        self.type = dtype

    def get_frontmost_application(self):
        if self.type == "usb":
            return types.SimpleNamespace(
                identifier="com.example.app", name="Example", pid=4321
            )
        raise RuntimeError("not a usb device")


@pytest.fixture()
def fake_frida(monkeypatch):
    mod = types.ModuleType("frida")
    mod.__version__ = "17.9.1-test"
    usb = _FakeDevice("f982678d", "CPH2487", "usb")
    local = _FakeDevice("local", "Local System", "local")
    mod.enumerate_devices = lambda: [local, usb]
    mod.get_usb_device = lambda timeout=5: usb
    monkeypatch.setitem(sys.modules, "frida", mod)
    return mod


def test_frida_status_missing_engine(monkeypatch):
    monkeypatch.setitem(sys.modules, "frida", None)  # forces ImportError
    result = dynamic_mod.DynamicHandler().frida_status({})
    assert result["status"] == "missing_tool"
    assert "frida" in result["error"]


def test_frida_status_detached_handler(fake_frida):
    """No session → session null, but device inventory still reported."""
    result = dynamic_mod.DynamicHandler().frida_status({})
    assert result["status"] == "ok"
    out = result["output"]
    assert out["frida_version"] == "17.9.1-test"
    assert [d["type"] for d in out["devices"]] == ["local", "usb"]
    assert out["usb_device"]["id"] == "f982678d"
    assert out["frida_server_responsive"] is True
    assert out["frontmost_application"]["identifier"] == "com.example.app"
    assert out["session"] is None


def test_frida_status_reports_handler_session(fake_frida):
    handler = dynamic_mod.DynamicHandler()
    session = types.SimpleNamespace(is_detached=False)
    handler._frida_session = session
    handler._attached_package = "com.example.app"
    handler._frida_script = object()
    handler._output_queue.put("msg")
    result = handler.frida_status({})
    session_info = result["output"]["session"]
    assert session_info == {
        "attached_package": "com.example.app",
        "alive": True,
        "script_loaded": True,
        "queued_messages": 1,
    }


def test_frida_status_survives_a_dead_server(fake_frida, monkeypatch):
    """If frida-server is down, status stays ok with responsive=False."""
    def refuse(timeout=5):
        raise RuntimeError("closed")

    monkeypatch.setattr(fake_frida, "get_usb_device", refuse)
    result = dynamic_mod.DynamicHandler().frida_status({})
    assert result["status"] == "ok"
    out = result["output"]
    assert out["frida_server_responsive"] is False
    assert "closed" in out["frida_server_error"]
    assert out["session"] is None


def test_frida_status_handles_old_session_objects(fake_frida):
    """Sessions without is_detached still report (alive defaults True)."""
    handler = dynamic_mod.DynamicHandler()
    handler._frida_session = object()  # no is_detached attribute
    result = handler.frida_status({})
    assert result["output"]["session"]["alive"] is True
    assert result["output"]["session"]["script_loaded"] is False


def test_frida_status_skips_device_probe_without_usb(fake_frida, monkeypatch):
    """No usb device in the list → no responsiveness probe at all."""
    monkeypatch.setattr(
        fake_frida, "enumerate_devices",
        lambda: [_FakeDevice("local", "Local System", "local")]
    )
    result = dynamic_mod.DynamicHandler().frida_status({})
    out = result["output"]
    assert out["usb_device"] is None
    assert out["frida_server_responsive"] is None
