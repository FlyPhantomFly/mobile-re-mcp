"""Regression tests for the Frida config protocol (extension E-PY-6).

No device needed: a fake session/script records what the handler posts,
so the Python side of the protocol is testable hermetically.
"""

import queue

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


def test_read_output_drains_queue():
    h = dynamic_mod.DynamicHandler()
    h._output_queue = queue.Queue()
    h._output_queue.put("one")
    h._output_queue.put("two")
    out = h.frida_read_output({})
    assert out["output"]["messages"] == ["one", "two"]
    assert h.frida_read_output({})["output"]["count"] == 0
