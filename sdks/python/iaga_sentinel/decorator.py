"""Decorator for governing tool calls with IAGA Sentinel.

See plug-ins/custom-adapter/ for a runnable example.
"""

from __future__ import annotations

import asyncio
import functools
from typing import Any, Callable, Optional

import httpx

from ._payload import named_payload
from .client import SentinelClient, AsyncSentinelClient
from .types import (
    ActionDetail,
    ActionType,
    GovernanceDecision,
    InspectRequest,
    resolve_unreachable,
)


def governed(
    agent_id: str,
    tool_name: Optional[str] = None,
    action_type: ActionType = ActionType.CUSTOM,
    framework: str = "python-sdk",
    base_url: str = "http://localhost:4010",
    api_key: Optional[str] = None,
    on_block: Optional[Callable] = None,
    on_review: Optional[Callable] = None,
    fail_closed: bool = False,
):
    """Decorator that runs governance check before executing the function.

    Usage:
        @governed(agent_id="builder-01", tool_name="file.write")
        def write_file(path: str, content: str):
            ...

        @governed(agent_id="researcher-01", action_type=ActionType.HTTP)
        async def fetch_url(url: str):
            ...
    """

    def decorator(func: Callable) -> Callable:
        resolved_tool_name = tool_name or func.__name__

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                payload = _build_payload(args, kwargs, func)
                request = InspectRequest(
                    agent_id=agent_id,
                    framework=framework,
                    action=ActionDetail(
                        type=action_type,
                        tool_name=resolved_tool_name,
                        payload=payload,
                    ),
                )

                try:
                    async with AsyncSentinelClient(base_url=base_url, api_key=api_key) as client:
                        result = await client.inspect(request)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code < 500:
                        raise
                    result = resolve_unreachable(
                        resolved_tool_name, exc, fail_closed=fail_closed
                    )
                except httpx.TransportError as exc:
                    result = resolve_unreachable(
                        resolved_tool_name, exc, fail_closed=fail_closed
                    )

                if result.blocked:
                    if on_block:
                        return on_block(result)
                    raise PermissionError(
                        f"IAGA Sentinel blocked '{resolved_tool_name}': "
                        f"{', '.join(result.risk.reasons)}"
                    )
                if result.needs_review:
                    if on_review:
                        return on_review(result)
                    raise PermissionError(
                        f"IAGA Sentinel requires review for '{resolved_tool_name}' "
                        f"(review_id={result.review_request_id})"
                    )

                return await func(*args, **kwargs)

            return async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                payload = _build_payload(args, kwargs, func)
                request = InspectRequest(
                    agent_id=agent_id,
                    framework=framework,
                    action=ActionDetail(
                        type=action_type,
                        tool_name=resolved_tool_name,
                        payload=payload,
                    ),
                )

                try:
                    with SentinelClient(base_url=base_url, api_key=api_key) as client:
                        result = client.inspect(request)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code < 500:
                        raise
                    result = resolve_unreachable(
                        resolved_tool_name, exc, fail_closed=fail_closed
                    )
                except httpx.TransportError as exc:
                    result = resolve_unreachable(
                        resolved_tool_name, exc, fail_closed=fail_closed
                    )

                if result.blocked:
                    if on_block:
                        return on_block(result)
                    raise PermissionError(
                        f"IAGA Sentinel blocked '{resolved_tool_name}': "
                        f"{', '.join(result.risk.reasons)}"
                    )
                if result.needs_review:
                    if on_review:
                        return on_review(result)
                    raise PermissionError(
                        f"IAGA Sentinel requires review for '{resolved_tool_name}' "
                        f"(review_id={result.review_request_id})"
                    )

                return func(*args, **kwargs)

            return sync_wrapper

    return decorator


def _build_payload(args: tuple, kwargs: dict, func: Callable) -> dict[str, Any]:
    """Build payload dict from function arguments.

    Delegates to :func:`named_payload` so ``@governed`` and ``governed_callable``
    build the SAME payload. Two divergences used to sit here, and both reached
    the signed receipt:

    * No ``exclude`` set. ``@governed`` on a bound method serialised ``self``
      through the ``str(val)`` fallback into ``action.payload``, which is hashed
      into the receipt - so an instance repr, potentially carrying a credential
      held on the object, was signed. ``named_payload`` has always excluded
      ``self``/``ctx``/``context``.
    * Positional arguments past ``len(params)`` were DROPPED, so a ``*args`` call
      under-reported what it did. ``named_payload`` names them ``arg{i}``.

    Not delegated wholesale to ``governed_callable``: ``ensure_allowed`` raises
    inside ``inspect_sync``/``inspect_async`` before ``call()`` runs, so the
    ``on_block``/``on_review`` callbacks could no longer receive the
    ``GovernanceResult``.

    .. warning::

       ``named_payload``'s default ``exclude`` is ``("self", "ctx", "context")``,
       so this change ALSO stops sending arguments named ``ctx``/``context``.
       That is a deliberate but real reduction in detection surface: a plain
       ``def run_query(sql, context)`` used to put ``context`` in front of the
       static-risk pattern scan, the taint tracker and the receipt input hash,
       and no longer does. ``self`` is the one that had to go — it is an
       instance repr nobody chose to send. If a caller needs ``context``
       governed, pass it under a different parameter name.
    """
    return named_payload(func, args, kwargs)
