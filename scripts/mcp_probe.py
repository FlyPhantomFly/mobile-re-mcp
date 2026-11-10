#!/usr/bin/env python3
"""Spawn a mobile-re-mcp MCP server over stdio and probe it.

Used for before/after verification while developing (RFC-style budget testing):

    # the installed package:
    ./scripts/mcp_probe.py --command "$(which mobile-re-mcp-py)" --list-tools

    # a working tree:
    ./scripts/mcp_probe.py --command python3 --args -m mobile_re_mcp \
        --env PYTHONPATH=python/src --call manifest_parse='{"apk_path": "/x/a.apk"}'

`--call` values are "tool=json-arguments" pairs; results print as JSON.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def _run(params: StdioServerParameters, want_tools: bool, calls: list[tuple[str, dict]]) -> dict:
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            out: dict = {}
            if want_tools:
                res = await session.list_tools()
                out["tools"] = sorted(t.name for t in res.tools)
                out["tool_count"] = len(res.tools)
            for name, args in calls:
                res = await session.call_tool(name, args)
                texts = [b.text for b in (res.content or []) if getattr(b, "text", None)]
                out[name] = {"isError": res.isError, "text": "\n".join(texts)}
            return out


def _parse_env(pairs: list[str]) -> dict[str, str]:
    env = dict(os.environ)
    for pair in pairs:
        key, _, value = pair.partition("=")
        env[key] = value
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--command", required=True, help="server executable")
    parser.add_argument("--args", default="", help="comma-separated args for the server")
    parser.add_argument("--env", action="append", default=[], help="KEY=VALUE passed through to the server")
    parser.add_argument("--list-tools", action="store_true")
    parser.add_argument("--call", action="append", default=[], metavar="TOOL=JSON")
    args = parser.parse_args()

    server_args = [a for a in args.args.split(",") if a]
    params = StdioServerParameters(command=args.command, args=server_args, env=_parse_env(args.env))
    calls = []
    for c in args.call:
        name, _, raw = c.partition("=")
        calls.append((name, json.loads(raw) if raw.strip() else {}))
    result = asyncio.run(_run(params, args.list_tools, calls))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
