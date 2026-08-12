"""Shared helpers for dependency-light framework adapters."""

from __future__ import annotations

import asyncio
import functools
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

import httpx

from .._payload import _safe_value, named_payload
from ..client import SentinelClient, AsyncSentinelClient
from ..types import (
    ActionDetail,
    ActionType,
    GovernanceResult,
    InspectRequest,
    resolve_unreachable,
)


@dataclass(frozen=True)
class AdapterConfig:
    agent_id: str
    api_key: Optional[str] = None
    base_url: str = "http://localhost:4010"
    framework: str = "sdk-adapter"
    workspace_id: Optional[str] = None
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None
    fail_closed: bool = False
    #: Tool name -> action type, for tools whose name the heuristic below cannot
    #: read. A framework only ever hands the adapter a name, so without this the
    #: guess is final: most real tool names (`search_docs`, `lookup_customer`,
    #: `get_weather`) resolve to `custom`, which no shipped example policy
    #: allows. Declaring the narrow type here is the alternative to widening the
    #: policy to `custom`, and it is the better one — `custom` is the least
    #: specific thing you can tell the policy engine about a tool.
    action_types: Optional[Mapping[str, ActionType]] = None


def build_request(
    config: AdapterConfig,
    *,
    tool_name: str,
    action_type: ActionType,
    payload: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
) -> InspectRequest:
    combined_metadata = dict(config.metadata or {})
    combined_metadata.update(metadata or {})
    return InspectRequest(
        agent_id=config.agent_id,
        tenant_id=config.tenant_id,
        workspace_id=config.workspace_id,
        framework=config.framework,
        action=ActionDetail(type=action_type, tool_name=tool_name, payload=payload),
        metadata=combined_metadata or None,
        session_id=config.session_id,
    )


def ensure_allowed(result: GovernanceResult, tool_name: str) -> None:
    if result.blocked:
        raise PermissionError(
            f"IAGA Sentinel blocked '{tool_name}' (risk={result.risk.score}): "
            f"{', '.join(result.risk.reasons)}"
        )
    if result.needs_review:
        raise PermissionError(
            f"IAGA Sentinel requires review for '{tool_name}' "
            f"(review_id={result.review_request_id}, risk={result.risk.score})"
        )


def serialize_args(args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {"args": list(args)}
    payload.update(kwargs)
    return payload


def resolve_action_type(
    config: AdapterConfig,
    tool_name: str,
    default: Optional[ActionType] = None,
) -> ActionType:
    """The action type to report for `tool_name`: declared first, then `default`,
    then the name heuristic.

    EVERY adapter routes through here, so one `action_types={...}` covers
    whichever entry point the framework happens to call. `default` exists for
    the adapters that already knew the answer without guessing — the OpenAI
    wrapper only ever emits two tool names and both really are http — so they
    can honour a declaration without their undeclared behaviour changing.
    """
    declared = (config.action_types or {}).get(tool_name)
    if declared is not None:
        return declared
    return default if default is not None else infer_action_type(tool_name)


def infer_action_type(tool_name: str, default: ActionType = ActionType.CUSTOM) -> ActionType:
    tool = tool_name.lower()
    if "http" in tool or "openai" in tool or "response" in tool:
        return ActionType.HTTP
    if "shell" in tool or "terminal" in tool:
        return ActionType.SHELL
    if "read" in tool or "file" in tool:
        return ActionType.FILE_READ
    if "write" in tool:
        return ActionType.FILE_WRITE
    return default


def inspect_sync(config: AdapterConfig, request: InspectRequest) -> GovernanceResult:
    try:
        with SentinelClient(base_url=config.base_url, api_key=config.api_key) as client:
            result = client.inspect(request)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code < 500:
            raise
        return resolve_unreachable(
            request.action.tool_name, exc, fail_closed=config.fail_closed
        )
    except httpx.TransportError as exc:
        return resolve_unreachable(
            request.action.tool_name, exc, fail_closed=config.fail_closed
        )
    ensure_allowed(result, request.action.tool_name)
    return result


async def inspect_async(config: AdapterConfig, request: InspectRequest) -> GovernanceResult:
    try:
        async with AsyncSentinelClient(
            base_url=config.base_url,
            api_key=config.api_key,
        ) as client:
            result = await client.inspect(request)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code < 500:
            raise
        return resolve_unreachable(
            request.action.tool_name, exc, fail_closed=config.fail_closed
        )
    except httpx.TransportError as exc:
        return resolve_unreachable(
            request.action.tool_name, exc, fail_closed=config.fail_closed
        )
    ensure_allowed(result, request.action.tool_name)
    return result


def run_guarded_sync(
    config: AdapterConfig,
    *,
    tool_name: str,
    action_type: ActionType,
    payload: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
    call: Callable[[], Any],
) -> Any:
    inspect_sync(
        config,
        build_request(
            config,
            tool_name=tool_name,
            action_type=action_type,
            payload=payload,
            metadata=metadata,
        ),
    )
    return call()


async def run_guarded_async(
    config: AdapterConfig,
    *,
    tool_name: str,
    action_type: ActionType,
    payload: dict[str, Any],
    metadata: Optional[dict[str, Any]] = None,
    call: Callable[[], Any],
) -> Any:
    await inspect_async(
        config,
        build_request(
            config,
            tool_name=tool_name,
            action_type=action_type,
            payload=payload,
            metadata=metadata,
        ),
    )
    return await call()


def governed_callable(
    config: AdapterConfig,
    func: Callable,
    *,
    tool_name: Optional[str] = None,
    action_type: Optional[ActionType] = None,
    exclude: tuple[str, ...] = ("self", "ctx", "context"),
) -> Callable:
    """Wrap a tool function so each call is inspected before it runs.

    Preserves sync/async. The payload is built from the call's named arguments
    (minus ``exclude``); block/review raise PermissionError, transport errors
    follow the fail-open/closed policy on ``config``.
    """
    name = tool_name or getattr(func, "__name__", "tool")
    resolved_type = action_type or resolve_action_type(config, name)

    if asyncio.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            return await run_guarded_async(
                config,
                tool_name=name,
                action_type=resolved_type,
                payload=named_payload(func, args, kwargs, exclude=exclude),
                call=lambda: func(*args, **kwargs),
            )

        return async_wrapper

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        return run_guarded_sync(
            config,
            tool_name=name,
            action_type=resolved_type,
            payload=named_payload(func, args, kwargs, exclude=exclude),
            call=lambda: func(*args, **kwargs),
        )

    return sync_wrapper
