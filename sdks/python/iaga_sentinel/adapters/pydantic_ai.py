"""Dependency-light Pydantic AI tool governance for IAGA Sentinel.

`governed_tool` wraps a Pydantic AI tool function so each call is inspected
before the body runs. Stack it under `@agent.tool` / `@agent.tool_plain`:

    @agent.tool
    @governed_tool(agent_id="support", base_url="http://localhost:4010")
    async def refund(ctx, order_id: str) -> str: ...

allow -> runs; block/review -> PermissionError. The `ctx`/`context` argument is
excluded from the inspected payload.

See plug-ins/pydantic-ai-adapter/ for a runnable example.
"""
from __future__ import annotations

from typing import Any, Callable, Mapping, Optional

from ..types import ActionType
from ._common import AdapterConfig, governed_callable


def governed_tool(
    *,
    agent_id: str,
    base_url: str = "http://localhost:4010",
    api_key: Optional[str] = None,
    framework: str = "pydantic-ai",
    tool_name: Optional[str] = None,
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

    def decorator(func: Callable) -> Callable:
        return governed_callable(
            config, func, tool_name=tool_name, action_type=action_type
        )

    return decorator
