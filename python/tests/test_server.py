import asyncio
import json
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def _session_run(env, fn):
    params = StdioServerParameters(command=sys.executable, args=["-m", "mobile_re_mcp"], env=env)
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as s:
            await s.initialize()
            return await fn(s)


def _env(tmp_path, **extra):
    import os

    env = dict(os.environ)
    env.update({"HOME": str(tmp_path), "MOBILE_RE_MCP_HOME": str(tmp_path / "data")})
    env.update(extra)
    return env


def test_lists_tools_and_hides_install_tool(tmp_path):
    async def go(s):
        return [t.name for t in (await s.list_tools()).tools]

    names = asyncio.run(_session_run(_env(tmp_path), go))
    assert len(names) >= 50
    assert "native_disasm" in names and "adb_shell" in names
    assert "install_tool" not in names


def test_disable_env_hides_tools(tmp_path):
    async def go(s):
        return [t.name for t in (await s.list_tools()).tools]

    names = asyncio.run(_session_run(_env(tmp_path, MOBILE_RE_MCP_DISABLE_TOOLS="adb_shell"), go))
    assert "adb_shell" not in names and "adb_devices" in names


def test_injection_attempt_is_refused_over_mcp(tmp_path):
    async def go(s):
        return await s.call_tool("native_disasm", {"so_path": "/x/lib.so", "target": "main;!id"})

    res = asyncio.run(_session_run(_env(tmp_path), go))
    assert res.isError
    assert "refused" in json.loads(res.content[0].text)["error"]


def test_check_tools_runs(tmp_path):
    async def go(s):
        return await s.call_tool("check_tools", {})

    res = asyncio.run(_session_run(_env(tmp_path), go))
    assert not res.isError
    assert "tools" in json.loads(res.content[0].text)


def test_resources_and_prompts(tmp_path):
    async def go(s):
        return (await s.list_resources()).resources, (await s.list_prompts()).prompts

    resources, prompts = asyncio.run(_session_run(_env(tmp_path), go))
    assert resources and prompts
