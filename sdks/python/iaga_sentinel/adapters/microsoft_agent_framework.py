"""Dependency-light Microsoft Agent Framework middleware for IAGA Sentinel.

Returns a function-invocation middleware `async (context, call_next)` that
inspects each tool/function call before it runs: allow -> awaits `call_next()`
(no args; the Agent Framework mutates `context` in place); block/review ->
raises PermissionError without calling `call_next` (the call never executes).
The `(context, call_next)` shape also matches Semantic Kernel filters.

Best-effort, duck-typed: it reads `context.function.name` (falling back to
`context.function_name`) and `context.arguments`; it does not import the
framework, so it tracks whatever exposes that shape.

See plug-ins/microsoft-agent-framework-adapter/ for a runnable example.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable, Mapping, Optional

from ..types import ActionType
from ._common import AdapterConfig, build_request, inspect_async, resolve_action_type


def _function_name(context: Any) -> str:
    fn = getattr(context, "function", None)
    name = getattr(fn, "name", None) or getattr(context, "function_name", None)
    return str(name) if name else "ms-agent.tool"


def _arguments(context: Any) -> dict[str, Any]:
    args = getattr(context, "arguments", None)
    if isinstance(args, dict):
        return args
    if args is None:
        return {}
    try:
        return dict(args)  # KernelArguments is mapping-like
    except (TypeError, ValueError):
        return {"input": str(args)}


def sentinel_middleware(
    *,
    agent_id: str,
    base_url: str = "http://localhost:4010",
    api_key: Optional[str] = None,
    framework: str = "microsoft-agent-framework",
    fail_closed: bool = False,
    action_types: Optional[Mapping[str, ActionType]] = None,
    workspace_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    session_id: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> Callable[[Any, Callable[[], Awaitable[Any]]], Awaitable[Any]]:
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

    async def middleware(
        context: Any, call_next: Callable[[], Awaitable[Any]]
    ) -> Any:
        tool_name = _function_name(context)
        # Raises PermissionError on block/review (so `call_next` is never called
        # and the tool does not run); transport errors follow the fail-open/closed
        # policy. `call_next` takes no arguments; `context` is mutated in place.
        await inspect_async(
            config,
            build_request(
                config,
                tool_name=tool_name,
                action_type=resolve_action_type(config, tool_name),
                payload=_arguments(context),
            ),
        )
        return await call_next()

    return middleware
