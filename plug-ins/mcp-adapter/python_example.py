"""Govern an MCP (FastMCP) server's tools with IAGA Sentinel.

    pip install mcp iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent (see README.md), then run this server.

`govern_tool` wraps each handler so every tools/call is inspected first; a
dangerous call (e.g. a shell with `curl … | sh`) is blocked before it runs.
One signed receipt per tools/call.
"""
from mcp.server.fastmcp import FastMCP

from iaga_sentinel.adapters.mcp import govern_tool

mcp = FastMCP("governed-server")


@mcp.tool()
@govern_tool(
    agent_id="mcp-demo",
    tool_name="filesystem.read",
    base_url="http://localhost:4010",
)
async def read_file(path: str) -> str:
    """Read a UTF-8 text file."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


if __name__ == "__main__":
    mcp.run()
