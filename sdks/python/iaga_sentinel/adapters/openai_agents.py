"""Dependency-light OpenAI Agents SDK governance for IAGA Sentinel.

Two hooks (use either or both):

  * `governed_tool(...)` wraps a plain function before `@function_tool`, so the
    tool call is inspected before it runs (block/review -> PermissionError).
  * `iaga_tool_guardrail(...)` returns a tool-input guardrail callable taking a
    single guardrail-data argument; attach it to a function tool / agent. It does
    not raise: allow returns `ToolGuardrailFunctionOutput.allow()`, block/review
    returns `reject_content`, so the tool does not run and the model is told why.

Does not import `agents`; the guardrail return value uses the SDK's
`ToolGuardrailFunctionOutput` when available, else a duck-typed fallback.

See plug-ins/openai-agents-adapter/ for a runnable example.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Mapping, Optional

import httpx

from ..client import AsyncSentinelClient
from ..types import ActionType
from ._common import AdapterConfig, build_request, governed_callable, resolve_action_type


def governed_tool(
    *,
    agent_id: str,
    base_url: str = "http://localhost:4010",
    api_key: Optional[str] = None,
    framework: str = "openai-agents",
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


class _FallbackOutput:
    """Fallback when `agents.ToolGuardrailFunctionOutput` isn't importable."""

    def __init__(self, behavior: dict):
        self.behavior = behavior
        self.output_info = None


def _allow_output() -> Any:
    try:
        from agents import ToolGuardrailFunctionOutput  # type: ignore

        return ToolGuardrailFunctionOutput.allow()
    except Exception:
        return _FallbackOutput({"type": "allow"})


def _reject_output(message: str) -> Any:
    try:
        from agents import ToolGuardrailFunctionOutput  # type: ignore

        return ToolGuardrailFunctionOutput.reject_content(message)
    except Exception:
        return _FallbackOutput({"type": "reject_content", "message": message})


def _as_guardrail(func: Callable) -> Any:
    try:
        from agents import tool_input_guardrail  # type: ignore

        return tool_input_guardrail(func)
    except Exception:
        return func


def _guardrail_tool_name(ctx: Any) -> str:
    return (
        getattr(ctx, "qualified_tool_name", None)
        or getattr(ctx, "tool_name", None)
        or "openai-agents.tool"
    )


def _guardrail_payload(ctx: Any) -> dict[str, Any]:
    raw = getattr(ctx, "tool_input", None)
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"input": parsed}
        except json.JSONDecodeError:
            return {"input": raw}
    return {} if raw is None else {"input": str(raw)}


def iaga_tool_guardrail(
    *,
    agent_id: str,
    base_url: str = "http://localhost:4010",
    api_key: Optional[str] = None,
    framework: str = "openai-agents",
    fail_closed: bool = False,
    action_types: Optional[Mapping[str, ActionType]] = None,
    workspace_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    session_id: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> Any:
    """Build an OpenAI Agents **tool-input guardrail** backed by IAGA Sentinel.

    Attach it to a function tool:

        @function_tool(tool_input_guardrails=[iaga_tool_guardrail(agent_id="ops")])
        def deploy(env: str) -> str: ...

    allow -> ``ToolGuardrailFunctionOutput.allow()``; block/review ->
    ``reject_content`` (the tool does not run and the model is told why).
    Transport errors follow the fail-open/closed policy.
    """
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

    async def guardrail(data: Any) -> Any:
        ctx = getattr(data, "context", None) or data
        tool_name = _guardrail_tool_name(ctx)
        request = build_request(
            config,
            tool_name=tool_name,
            action_type=resolve_action_type(config, tool_name),
            payload=_guardrail_payload(ctx),
        )
        try:
            async with AsyncSentinelClient(
                base_url=config.base_url, api_key=config.api_key
            ) as client:
                result = await client.inspect(request)
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code < 500:
                raise
            if config.fail_closed:
                return _reject_output(f"IAGA Sentinel unreachable: {exc}")
            return _allow_output()

        if result.blocked or result.needs_review:
            reasons = ", ".join(result.risk.reasons) or result.decision.value
            return _reject_output(f"IAGA Sentinel {result.decision.value}: {reasons}")
        return _allow_output()

    return _as_guardrail(guardrail)
