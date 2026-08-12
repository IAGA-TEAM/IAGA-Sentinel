"""Dependency-light LlamaIndex callback handler for IAGA Sentinel.

Register `IagaCallbackHandler` on LlamaIndex's `CallbackManager`; it gates the
`FUNCTION_CALL` event, inspecting each tool call before it runs. allow -> runs;
block/review -> raises PermissionError. Does not import llama_index: it
duck-types the event type and the payload keys (`tool`, `function_call`).

See plug-ins/llamaindex-adapter/ for a runnable example.
"""
from __future__ import annotations

import json
from typing import Any, Mapping, Optional

from ..types import ActionType
from ._common import AdapterConfig, build_request, inspect_sync, resolve_action_type


def _is_function_call(event_type: Any) -> bool:
    value = getattr(event_type, "value", event_type)
    return str(value).lower() == "function_call"


def _extract(payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    tool = payload.get("tool")
    tool_name = "llamaindex.tool"
    if tool is not None:
        meta = getattr(tool, "metadata", None)
        tool_name = (
            getattr(meta, "name", None) or getattr(tool, "name", None) or tool_name
        )
    raw = payload.get("function_call")
    args: dict[str, Any] = {}
    if isinstance(raw, dict):
        args = raw
    elif isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            args = parsed if isinstance(parsed, dict) else {"input": parsed}
        except json.JSONDecodeError:
            args = {"input": raw}
    return str(tool_name), args


class IagaCallbackHandler:
    """LlamaIndex `BaseCallbackHandler`-compatible governance gate on tool calls."""

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:4010",
        framework: str = "llamaindex",
        workspace_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        fail_closed: bool = False,
        action_types: Optional[Mapping[str, ActionType]] = None,
    ):
        # LlamaIndex passes these to BaseCallbackHandler.__init__; accept and ignore.
        self.event_starts_to_ignore: tuple = ()
        self.event_ends_to_ignore: tuple = ()
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

    def on_event_start(
        self,
        event_type: Any,
        payload: Optional[dict[str, Any]] = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        if payload and _is_function_call(event_type):
            tool_name, args = _extract(payload)
            inspect_sync(
                self._config,
                build_request(
                    self._config,
                    tool_name=tool_name,
                    action_type=resolve_action_type(self._config, tool_name),
                    payload=args,
                ),
            )
        return event_id

    def on_event_end(
        self,
        event_type: Any,
        payload: Optional[dict[str, Any]] = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        return None

    def start_trace(self, trace_id: Optional[str] = None) -> None:
        return None

    def end_trace(
        self,
        trace_id: Optional[str] = None,
        trace_map: Optional[dict[str, list[str]]] = None,
    ) -> None:
        return None
