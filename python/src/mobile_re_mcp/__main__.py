"""
Entry point for the mobile-re-mcp MCP server.

Usage:
    python -m mobile_re_mcp           # stdio transport (default)
    python -m mobile_re_mcp --transport sse --port 8765  # SSE, loopback only
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mobile-re-mcp-py",
        description="Android dynamic analysis MCP server (Python half of mobile-re-mcp)",
    )
    p.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport to use (default: stdio)",
    )
    p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Address for SSE transport (default: 127.0.0.1). Anything else needs MOBILE_RE_MCP_TOKEN.",
    )
    p.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port for SSE transport (default: 8765)",
    )
    p.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    p.add_argument(
        "--setup",
        action="store_true",
        help="Automatically download and install all missing RE tools into ~/tools",
    )
    return p


def main() -> None:
    """Main entry point — starts the MCP server."""
    parser = _build_parser()
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if args.setup:
        print("[*] Starting zero-touch automated setup...")
        from mobile_re_mcp.setup.install_tool import install_all_missing_tools
        install_all_missing_tools()
        print("[*] Setup complete! You can now start the MCP server.")
        sys.exit(0)

    from mobile_re_mcp.paths import ensure_tools_on_path

    ensure_tools_on_path()

    # Import here so startup errors surface cleanly
    from mobile_re_mcp.server import create_server

    server = create_server()

    if args.transport == "stdio":
        logger.info("Starting mobile-re-mcp over stdio")
        asyncio.run(server.run_stdio())
    else:
        logger.info("Starting mobile-re-mcp SSE on %s:%d", args.host, args.port)
        asyncio.run(server.run_sse(host=args.host, port=args.port))


if __name__ == "__main__":
    main()
