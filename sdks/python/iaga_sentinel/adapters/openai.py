"""Dependency-light OpenAI wrapper for IAGA Sentinel.

See plug-ins/openai-adapter/ for a runnable example.
"""

from __future__ import annotations

import inspect
from typing import Any, Mapping, Optional

from ..types import ActionType
from ._common import (
    AdapterConfig,
    resolve_action_type,
    run_guarded_async,
    run_guarded_sync,
    serialize_args,
)


class _ResponsesAdapter:
    def __init__(self, wrapper: "SentinelOpenAIWrapper"):
        self._wrapper = wrapper

    def create(self, *args: Any, **kwargs: Any) -> Any:
        payload = serialize_args(args, kwargs)
        return self._wrapper._run(
            tool_name="openai.responses.create",
            # Both tool names this wrapper can emit really are http, so that
            # stays the default — but a declared type must still win, or the
            # constructor accepts `action_types` and ignores it.
            action_type=resolve_action_type(
                self._wrapper._config, "openai.responses.create", default=ActionType.HTTP
            ),
            payload=payload,
            call=lambda: self._wrapper._client.responses.create(*args, **kwargs),
        )


class _ChatCompletionsAdapter:
    def __init__(self, wrapper: "SentinelOpenAIWrapper"):
        self._wrapper = wrapper

    def create(self, *args: Any, **kwargs: Any) -> Any:
        payload = serialize_args(args, kwargs)
        return self._wrapper._run(
            tool_name="openai.chat.completions.create",
            action_type=resolve_action_type(
                self._wrapper._config,
                "openai.chat.completions.create",
                default=ActionType.HTTP,
            ),
            payload=payload,
            call=lambda: self._wrapper._client.chat.completions.create(*args, **kwargs),
        )


class _ChatAdapter:
    def __init__(self, wrapper: "SentinelOpenAIWrapper"):
        self.completions = _ChatCompletionsAdapter(wrapper)


class SentinelOpenAIWrapper:
    """Wrap an OpenAI or AsyncOpenAI client with a governance preflight."""

    def __init__(self, client: Any, config: AdapterConfig):
        self._client = client
        self._config = config
        self._async_mode = _is_async_openai_client(client)
        self.responses = _ResponsesAdapter(self)
        self.chat = _ChatAdapter(self)

    def _run(
        self,
        *,
        tool_name: str,
        action_type: ActionType,
        payload: dict[str, Any],
        call: Any,
    ) -> Any:
        if self._async_mode:

            async def run_async() -> Any:
                return await run_guarded_async(
                    self._config,
                    tool_name=tool_name,
                    action_type=action_type,
                    payload=payload,
                    call=call,
                )

            return run_async()

        return run_guarded_sync(
            self._config,
            tool_name=tool_name,
            action_type=action_type,
            payload=payload,
            call=call,
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def sentinel_wrap_openai(
    client: Any,
    *,
    agent_id: str,
    api_key: Optional[str] = None,
    base_url: str = "http://localhost:4010",
    framework: str = "openai",
    workspace_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    session_id: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    fail_closed: bool = False,
    action_types: Optional[Mapping[str, ActionType]] = None,
) -> SentinelOpenAIWrapper:
    return SentinelOpenAIWrapper(
        client,
        AdapterConfig(
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
        ),
    )


def _is_async_openai_client(client: Any) -> bool:
    responses_create = getattr(getattr(client, "responses", None), "create", None)
    chat_create = getattr(
        getattr(getattr(client, "chat", None), "completions", None),
        "create",
        None,
    )
    return bool(
        (responses_create and inspect.iscoroutinefunction(responses_create))
        or (chat_create and inspect.iscoroutinefunction(chat_create))
    )
