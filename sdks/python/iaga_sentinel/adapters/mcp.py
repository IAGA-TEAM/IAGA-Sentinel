"""Dependency-light MCP tool governance for IAGA Sentinel.

`govern_tool` wraps an MCP tool handler so every ``tools/call`` is inspected
before the handler runs. Use it when you build an MCP server (e.g. FastMCP):

    @mcp.tool()
    @govern_tool(agent_id="mcp-demo", tool_name="filesystem.read")
    async def read_file(path: str) -> str: ...

allow -> runs; block/review -> PermissionError. One receipt per ``tools/call``.
The injected `ctx`/`context` argument (if any) is excluded from the payload.

For transparent, server-agnostic wrapping of an *external* MCP server, use the
`iaga proxy` command instead (it intercepts every tools/call round-trip).

The default ``framework`` is "model-context-tool" (not "mcp"): the server treats
explicit MCP-protocol traffic specially (a protocol guard), but this wrapper
governs the tool *call* at the handler level, not the raw JSON-RPC envelope.

See plug-ins/mcp-adapter/ for a runnable example.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from ..types import ActionType
from ._common import AdapterConfig, governed_callable


def govern_tool(
    *,
    agent_id: str,
    tool_name: Optional[str] = None,
    base_url: str = "http://localhost:4010",
    api_key: Optional[str] = None,
    framework: str = "model-context-tool",
    action_type: Optional[ActionType] = None,
    fail_closed: bool = False,
    action_types: Optional[Mapping[str, ActionType]] = None,
    workspace_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    session_id: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> Callable[[Callable], Callable]:
    config = AdapterConfig(
        agent_id=agent_id,
        api_key=api_key,
        base_url=base_url,
        framework=framework,
        workspace_id=workspace_id,
        tenant_id=tenant_id,
        session_id=session_id,
        metadata=metadata,
        fail_closed=fail_closed,
        action_types=action_types,
    )

    def decorator(handler: Callable) -> Callable:
        return governed_callable(
            config, handler, tool_name=tool_name, action_type=action_type
        )

    return decorator
