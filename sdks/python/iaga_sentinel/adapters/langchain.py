"""Dependency-light LangChain callback helpers for IAGA Sentinel.

See plug-ins/langchain-adapter/ for a runnable example.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from ..types import ActionType
from ._common import (
    AdapterConfig,
    _safe_value,
    build_request,
    resolve_action_type,
    inspect_async,
    inspect_sync,
)


def _tool_payload(input_str: str, kwargs: dict) -> dict:
    """JSON-safe payload from LangChain's on_tool_start args.

    LangChain passes runtime kwargs (run_id as a UUID, metadata, ...) that aren't
    JSON-serializable, so we keep only the input string and the clean `inputs`.
    """
    payload: dict = {"input": input_str}
    inputs = kwargs.get("inputs")
    if isinstance(inputs, dict):
        payload["inputs"] = _safe_value(inputs)
    return payload


class SentinelCallbackHandler:
    """Minimal callback handler compatible with LangChain-style tool hooks."""

    # LangChain's CallbackManager reads these on every handler via getattr.
    # raise_error=True makes it propagate our PermissionError (otherwise callback
    # exceptions are only logged and swallowed); the ignore_* flags avoid
    # AttributeError. We don't subclass BaseCallbackHandler, to stay dependency-light.
    raise_error: bool = True
    run_inline: bool = True
    ignore_llm: bool = False
    ignore_retry: bool = False
    ignore_chain: bool = False
    ignore_agent: bool = False
    ignore_retriever: bool = False
    ignore_chat_model: bool = False
    ignore_custom_event: bool = False

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:4010",
        framework: str = "langchain",
        workspace_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        fail_closed: bool = False,
        action_types: Optional[Mapping[str, ActionType]] = None,
    ):
        self._config = AdapterConfig(
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

    def guard_tool(
        self,
        tool_name: str,
        payload: dict[str, Any],
        action_type: Optional[ActionType] = None,
    ) -> None:
        inspect_sync(
            self._config,
            build_request(
                self._config,
                tool_name=tool_name,
                action_type=action_type
                or resolve_action_type(
                    self._config, tool_name, default=ActionType.CUSTOM
                ),
                payload=payload,
            ),
        )

    async def aguard_tool(
        self,
        tool_name: str,
        payload: dict[str, Any],
        action_type: Optional[ActionType] = None,
    ) -> None:
        await inspect_async(
            self._config,
            build_request(
                self._config,
                tool_name=tool_name,
                action_type=action_type
                or resolve_action_type(
                    self._config, tool_name, default=ActionType.CUSTOM
                ),
                payload=payload,
            ),
        )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = str(serialized.get("name") or serialized.get("id") or "langchain.tool")
        action_type = resolve_action_type(self._config, tool_name)
        payload = _tool_payload(input_str, kwargs)
        self.guard_tool(tool_name, payload, action_type=action_type)

    async def aon_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        tool_name = str(serialized.get("name") or serialized.get("id") or "langchain.tool")
        action_type = resolve_action_type(self._config, tool_name)
        payload = _tool_payload(input_str, kwargs)
        await self.aguard_tool(tool_name, payload, action_type=action_type)

    def __getattr__(self, name: str) -> Any:
        # LangChain calls many lifecycle callbacks (on_tool_end, on_llm_start, ...);
        # only on_tool_start governs. Return a no-op for the rest so raise_error=True
        # surfaces our PermissionError without tripping on unimplemented callbacks.
        if name.startswith("on_") or name.startswith("aon_"):
            def _noop(*args: Any, **kwargs: Any) -> None:
                return None

            return _noop
        raise AttributeError(name)
