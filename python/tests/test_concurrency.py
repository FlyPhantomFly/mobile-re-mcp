"""Concurrency regression tests for the F-PY-4 non-blocking dispatch.

_run_tool must free the event loop while a slow sync handler runs, and
must queue concurrent calls to stateful handler classes instead of
letting them race on shared state.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from mobile_re_mcp.handlers.device import DeviceHandler
from mobile_re_mcp.handlers.dynamic import DynamicHandler
from mobile_re_mcp.handlers.network import NetworkHandler
from mobile_re_mcp.server import _run_tool
from mcp.types import CallToolResult

pytest.importorskip("mcp")


class _StatefulHandler:
    """Stands in for Dynamic/Network/Device: holds nominally shared state."""

    _SERIALIZE = True

    def __init__(self) -> None:
        self.log: list[tuple[float, float]] = []

    def work(self, args: dict) -> dict:
        start = time.monotonic()
        time.sleep(args["sleep"])
        self.log.append((start, time.monotonic()))
        return {"status": "ok"}


class _SlowHandler:
    """Stateless: two methods — one slow, one instant."""

    def __init__(self) -> None:
        self.done: list[tuple[str, float]] = []

    def slow(self, args: dict) -> dict:
        time.sleep(args["sleep"])
        self.done.append(("slow", time.monotonic()))
        return {"status": "ok", "who": "slow"}

    def fast(self, args: dict) -> dict:
        self.done.append(("fast", time.monotonic()))
        return {"status": "ok", "who": "fast"}


def _result(res: CallToolResult) -> dict:
    import json

    return json.loads(res.content[0].text)


def test_stateless_slow_handler_does_not_block_the_loop():
    """A slow sync handler must not stall the loop (F-PY-4).

    'slow' is scheduled FIRST: inline dispatch would block the loop for
    its whole run, so 'fast' could only finish after it. Under to_thread
    the loop stays free and 'fast' completes while 'slow' still sleeps.
    """
    slow = _SlowHandler()
    dispatch = {"slow": slow.slow, "fast": slow.fast}
    pools = {}

    async def go():
        slow_task = asyncio.create_task(_run_tool("slow", {"sleep": 0.3}, dispatch, pools))
        fast_task = asyncio.create_task(_run_tool("fast", {}, dispatch, pools))
        return await asyncio.gather(slow_task, fast_task)

    slow_res, fast_res = asyncio.run(go())
    marks = {who: t for who, t in slow.done}
    assert [who for who, _t in slow.done] == ["fast", "slow"]
    assert marks["fast"] < marks["slow"], marks
    assert _result(slow_res)["who"] == "slow"
    assert _result(fast_res)["who"] == "fast"


def test_stateful_handlers_never_overlap():
    stateful = _StatefulHandler()
    dispatch = {"a": stateful.work, "b": stateful.work}
    pools = {}

    async def go():
        return await asyncio.gather(
            _run_tool("a", {"sleep": 0.25}, dispatch, pools),
            _run_tool("b", {"sleep": 0.25}, dispatch, pools),
        )

    asyncio.run(go())
    intervals = sorted(stateful.log)
    assert len(intervals) == 2
    # queueing, not racing: later start is not before earlier end
    assert intervals[1][0] >= intervals[0][1] - 0.05


def test_stateful_flag_is_set_on_the_stateful_classes_and_lambdas_are_free():
    # Semantics flags (the wiring _run_tool keys on)
    assert DynamicHandler._SERIALIZE is True
    assert NetworkHandler._SERIALIZE is True
    assert DeviceHandler._SERIALIZE is True
    # plain function/lambda dispatches have no bound _SERIALIZE
    assert getattr(lambda _a: {}, "_SERIALIZE", False) is False


def test_unknown_tool_and_guard_paths_look_the_same():
    dispatch = {"echo": lambda args: {"status": "ok"}}
    res = asyncio.run(_run_tool("nope", {}, dispatch, {}))
    assert res.isError is False  # 'Unknown tool' is a normal result, not protocol error
    assert _result(res)["status"] == "error"

    # guard refusal (install_tool is off by default) → isError + structured body
    res = asyncio.run(_run_tool("install_tool", {"tool_name": "jadx"}, {"echo": lambda a: {}}, {}))
    assert res.isError is True
    assert "refused" in _result(res)["error"]


def test_handler_exception_is_reported_not_raised():
    def boom(args: dict) -> dict:
        raise RuntimeError("kaboom")

    res = asyncio.run(_run_tool("boom", {}, {"boom": boom}, {}))
    assert res.isError is False
    assert _result(res) == {"status": "error", "tool": "boom", "error": "kaboom"}
