"""Regression tests for the Frida config protocol (extension E-PY-6).

No device needed: a fake session/script records what the handler posts,
so the Python side of the protocol is testable hermetically.
"""

import queue
import sys
import types

import pytest

from mobile_re_mcp.handlers import dynamic as dynamic_mod


class _FakeScript:
    """Records the loaded source and any post() calls."""

    def __init__(self, src):
        self.src = src
        self.posted: list[dict] = []
        self.handlers: list[tuple[str, object]] = []
        self.loaded = False
        self.unloaded = False

    def on(self, event, handler):
        self.handlers.append((event, handler))

    def load(self):
        self.loaded = True

    def post(self, message):
        self.posted.append(message)

    def unload(self):
        self.unloaded = True


class _FakeSession:
    def __init__(self):
        self.created: list[_FakeScript] = []

    def create_script(self, src):
        script = _FakeScript(src)
        self.created.append(script)
        return script


@pytest.fixture()
def handler():
    h = dynamic_mod.DynamicHandler()
    h._frida_session = _FakeSession()
    return h


def test_run_script_posts_config_instead_of_patch(handler):
    """frida_run_script no longer str.replaces the source; it posts config."""
    calls: list[dict] = []
    original_spawn = dynamic_mod.DynamicHandler.frida_spawn

    def fake_spawn(self, args):
        calls.append(args)
        return {"status": "ok", "tool": "frida", "output": {"script_loaded": True}}

    dynamic_mod.DynamicHandler.frida_spawn = fake_spawn
    try:
        result = handler.frida_run_script(
            {
                "package": "com.example.app",
                "script_name": "memory_scan",
                "config": {"SEARCH_STRING": 'needle "with quotes"', "MAX_RESULTS": 5},
            }
        )
    finally:
        dynamic_mod.DynamicHandler.frida_spawn = original_spawn

    assert result["status"] == "ok"
    sent = calls[0]
    # The shipped source is untouched — the var-line contract stays intact.
    assert 'var SEARCH_STRING = "";' in sent["script"]
    assert 'needle "with quotes"' not in sent["script"]
    # The config travels as a first-class argument instead.
    assert sent["config"] == {"SEARCH_STRING": 'needle "with quotes"', "MAX_RESULTS": 5}


def test_load_script_posts_config_after_load(handler):
    handler._load_script("var X = 0;", config={"SEARCH_STRING": "abc"})
    script = handler._frida_session.created[0]
    assert script.loaded
    assert script.posted == [{"type": "config", "SEARCH_STRING": "abc"}]


def test_load_script_without_config_posts_nothing(handler):
    handler._load_script("var X = 0;")
    script = handler._frida_session.created[0]
    assert script.posted == []


def _completing_script(session):
    """A create_script that returns scripts firing scan_complete on load."""

    def create(src):
        script = _FakeScript(src)
        session.created.append(script)
        original_load = script.load

        def load_with_reply():
            original_load()
            for event, h in script.handlers:
                if event == "message":
                    h({"type": "send", "payload": {"type": "scan_complete",
                                                   "scanned_ranges": 1, "matches": 0}}, None)

        script.load = load_with_reply  # type: ignore[method-assign]
        return script

    return create


def test_find_bytes_uses_config_protocol(handler, monkeypatch):
    """frida_find_bytes loads unpatched and posts the search as config."""
    monkeypatch.setattr(
        handler._frida_session, "create_script",
        _completing_script(handler._frida_session)
    )

    result = handler.frida_find_bytes({"search_string": "token"})

    assert result["status"] == "ok"
    assert result["output"]["via"] == "config-protocol"
    script = handler._frida_session.created[0]
    # The shipped script is loaded UNPATCHED...
    assert 'var SEARCH_STRING = "";' in script.src
    # ...and the search arrives as a config message.
    assert script.posted == [{"type": "config", "SEARCH_STRING": "token",
                              "SEARCH_HEX": "", "MAX_RESULTS": 20}]


def test_find_bytes_falls_back_to_var_line_contract(handler, monkeypatch):
    """When script.post is unsupported, the var-line replace path still runs."""
    session = handler._frida_session

    def create(src):
        script = _FakeScript(src)
        session.created.append(script)
        original_load = script.load

        def boom(_msg):
            raise RuntimeError("no post in this runtime")

        def load_with_reply():
            original_load()
            for event, h in script.handlers:
                if event == "message":
                    h({"type": "send", "payload": {"type": "scan_complete",
                                                   "scanned_ranges": 1, "matches": 0}}, None)

        script.post = boom  # type: ignore[method-assign]
        script.load = load_with_reply  # type: ignore[method-assign]
        return script

    monkeypatch.setattr(session, "create_script", create)

    result = handler.frida_find_bytes({"search_string": "needle", "max_results": 7})
    assert result["status"] == "ok"
    assert result["output"]["pattern"] == "needle"
    # The fallback loaded a second, patched source.
    assert len(session.created) == 2
    patched = session.created[1]
    assert 'var SEARCH_STRING = "needle";' in patched.src
    assert 'var MAX_RESULTS = 7;' in patched.src


def test_find_bytes_requires_session():
    h = dynamic_mod.DynamicHandler()
    result = h.frida_find_bytes({"search_string": "x"})
    assert result["status"] == "error"
    assert "frida_attach" in result["error"]


# ── frida_memdump: per-range cap prevents device-side OOM (D-7) ──────────

def test_memdump_caps_range_size_and_reports_skips(handler, monkeypatch):
    """The dump script must embed the range cap and the summary reports skips."""
    session = handler._frida_session
    script_holder: list = []

    def create(src):
        script = _FakeScript(src)
        session.created.append(script)
        original_load = script.load

        def load_with_reply():
            original_load()
            for event, cb in script.handlers:
                if event == "message":
                    cb({"type": "send", "payload": {
                        "type": "done", "total_ranges": 760, "skipped_large": 6,
                    }}, None)

        script.load = load_with_reply  # type: ignore[method-assign]
        script_holder.append(script)
        return script

    monkeypatch.setattr(session, "create_script", create)
    handler._frida_session = session
    handler._attached_package = "com.example.app"

    result = handler.frida_memdump({})
    assert result["status"] == "ok"
    out = result["output"]
    assert out["skipped_large"] == 6
    assert out["total_ranges"] == 760
    assert out["max_range_mb"] == 32  # the new default cap
    src = script_holder[0].src
    assert "var MAX_RANGE = " in src and "skipped" in src
    assert "32 * 1024 * 1024" in src or str(32 * 1024 * 1024) in src

    custom = handler.frida_memdump({"max_range_mb": 8})
    assert custom["status"] == "ok"
    assert custom["output"]["max_range_mb"] == 8


def test_memdump_requires_session():
    h = dynamic_mod.DynamicHandler()
    result = h.frida_memdump({})
    assert result["status"] == "error"
    assert "frida_attach" in result["error"]


def test_read_output_drains_queue():
    h = dynamic_mod.DynamicHandler()
    h._output_queue = queue.Queue()
    h._output_queue.put("one")
    h._output_queue.put("two")
    out = h.frida_read_output({})
    assert out["output"]["messages"] == ["one", "two"]
    assert h.frida_read_output({})["output"]["count"] == 0


# ── D-6: attach by package identifier maps through enumerate_applications ──

class _FakeFridaDevice:
    def __init__(self, fail_by_name=True):
        self.fail_by_name = fail_by_name
        self.attached: list[object] = []

    def attach(self, target):
        if self.fail_by_name and isinstance(target, str):
            raise RuntimeError(f"unable to find process with name '{target}'")
        self.attached.append(target)
        return object()

    def enumerate_applications(self):
        return [
            types.SimpleNamespace(identifier="com.android.chrome", name="Chrome", pid=11),
            types.SimpleNamespace(identifier="com.termux.api", name="Termux:API", pid=28081),
        ]

    def enumerate_processes(self):
        return [
            types.SimpleNamespace(pid=1, name="Termux:API"),
            types.SimpleNamespace(pid=2, name="com.android.chrome"),
        ]


def test_attach_maps_package_identifier_to_pid(monkeypatch):
    """D-6: identifier attach fails on labels — the handler maps id → pid."""
    handler = dynamic_mod.DynamicHandler()
    device = _FakeFridaDevice()
    fake = types.ModuleType("frida")
    fake.get_usb_device = lambda timeout=10: device
    monkeypatch.setitem(sys.modules, "frida", fake)

    result = handler.frida_attach({"package": "com.termux.api"})
    assert result["status"] == "ok"
    assert device.attached == [28081], "must retry with the mapped pid"


def test_attach_direct_when_name_lookup_works(monkeypatch):
    """When frida's own lookup succeeds there is no second enumeration."""
    handler = dynamic_mod.DynamicHandler()
    device = _FakeFridaDevice(fail_by_name=False)
    fake = types.ModuleType("frida")
    fake.get_usb_device = lambda timeout=10: device
    monkeypatch.setitem(sys.modules, "frida", fake)

    result = handler.frida_attach({"package": "com.termux.api"})
    assert result["status"] == "ok"
    assert device.attached == ["com.termux.api"]


def test_attach_reports_failure_when_nothing_matches(monkeypatch):
    handler = dynamic_mod.DynamicHandler()

    class Dead(_FakeFridaDevice):
        def enumerate_applications(self):
            return []

    device = Dead()
    fake = types.ModuleType("frida")
    fake.get_usb_device = lambda timeout=10: device
    monkeypatch.setitem(sys.modules, "frida", fake)

    result = handler.frida_attach({"package": "com.notrunning.app"})
    assert result["status"] == "error"
    assert "unable to find process" in result["error"]


# ── MOBILE_RE_MCP_FRIDA_ENDPOINT: stealth servers on non-default ports ──

def test_frida_endpoint_env(monkeypatch):
    monkeypatch.delenv("MOBILE_RE_MCP_FRIDA_ENDPOINT", raising=False)
    assert dynamic_mod.frida_endpoint() is None
    monkeypatch.setenv("MOBILE_RE_MCP_FRIDA_ENDPOINT", "127.0.0.1:31337")
    assert dynamic_mod.frida_endpoint() == "127.0.0.1:31337"
    monkeypatch.setenv("MOBILE_RE_MCP_FRIDA_ENDPOINT", "   ")
    assert dynamic_mod.frida_endpoint() is None


def test_get_frida_device_uses_endpoint_when_set(monkeypatch):
    """Stealth setup: MOBILE_RE_MCP_FRIDA_ENDPOINT wins over USB discovery."""
    monkeypatch.setenv("MOBILE_RE_MCP_FRIDA_ENDPOINT", "127.0.0.1:31337")
    fake = types.ModuleType("frida")
    manager = types.SimpleNamespace(
        add_remote_device=lambda endpoint: f"remote:{endpoint}"
    )
    fake.get_device_manager = lambda: manager
    calls = []
    fake.get_usb_device = lambda timeout=10: calls.append(timeout) or "usb"
    monkeypatch.setitem(sys.modules, "frida", fake)

    assert dynamic_mod._get_frida_device() == "remote:127.0.0.1:31337"
    assert calls == [], "must not probe USB when an endpoint is configured"

    monkeypatch.delenv("MOBILE_RE_MCP_FRIDA_ENDPOINT")
    assert dynamic_mod._get_frida_device() == "usb"
