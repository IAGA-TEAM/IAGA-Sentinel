"""Dependency-light LangGraph tool-node governance for IAGA Sentinel.

LangGraph runs tool calls through a ``ToolNode``. ``GovernedToolNode`` is a
drop-in node that inspects every tool call before it runs: allow -> execute the
tool and return its ``ToolMessage``; block/review -> raise ``PermissionError``
(same enforcement as the other adapters). Pure LLM nodes produce no action and
need no receipt, so they are left untouched.

This module does not import langgraph/langchain; it duck-types the state
(``{"messages": [...]}``), the last message's ``tool_calls`` and each tool's
``invoke``/``func``/callable interface, and builds a ``ToolMessage`` via a lazy
import (falling back to a plain dict if langchain_core is absent).

See plug-ins/langgraph-adapter/ for a runnable example.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from ..types import ActionType
from ._common import AdapterConfig, build_request, inspect_sync, resolve_action_type


def _make_tool_message(content: str, name: str, tool_call_id: str) -> Any:
    try:  # langchain_core is present in any real LangGraph install
        from langchain_core.messages import ToolMessage

        return ToolMessage(content=content, name=name, tool_call_id=tool_call_id)
    except Exception:
        return {
            "role": "tool",
            "name": name,
            "content": content,
            "tool_call_id": tool_call_id,
        }


def _tool_name(tool: Any) -> Optional[str]:
    return getattr(tool, "name", None) or getattr(tool, "__name__", None)


def _invoke_tool(tool: Any, args: Any) -> Any:
    if hasattr(tool, "invoke"):
        return tool.invoke(args)
    if hasattr(tool, "func"):
        return tool.func(**args) if isinstance(args, dict) else tool.func(args)
    if callable(tool):
        return tool(**args) if isinstance(args, dict) else tool(args)
    raise TypeError(f"don't know how to invoke tool {tool!r}")


class GovernedToolNode:
    """A LangGraph tool node that governs each tool call through IAGA Sentinel."""

    def __init__(
        self,
        tools: Any,
        *,
        agent_id: str,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:4010",
        framework: str = "langgraph",
        workspace_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        fail_closed: bool = False,
        action_types: Optional[Mapping[str, ActionType]] = None,
        action_type: Optional[ActionType] = None,
    ):
        self._tools = {
            name: tool for tool in tools if (name := _tool_name(tool)) is not None
        }
        self._action_type = action_type
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

    @staticmethod
    def _tool_calls(state: Any) -> list[dict[str, Any]]:
        messages = state["messages"] if isinstance(state, dict) else state.messages
        if not messages:
            return []
        last = messages[-1]
        calls = getattr(last, "tool_calls", None)
        if calls is None and isinstance(last, dict):
            calls = last.get("tool_calls")
        return list(calls or [])

    def _guard(self, name: str, args: Any) -> None:
        payload = dict(args) if isinstance(args, dict) else {"input": args}
        action_type = self._action_type or resolve_action_type(self._config, name)
        # Raises PermissionError on block/review; fail-open on transport errors.
        inspect_sync(
            self._config,
            build_request(
                self._config,
                tool_name=name,
                action_type=action_type,
                payload=payload,
            ),
        )

    def __call__(self, state: Any) -> dict[str, Any]:
        outputs = []
        for call in self._tool_calls(state):
            name = call["name"]
            args = call.get("args", {})
            self._guard(name, args)
            tool = self._tools.get(name)
            if tool is None:
                raise KeyError(f"tool '{name}' not registered with GovernedToolNode")
            result = _invoke_tool(tool, args)
            outputs.append(_make_tool_message(str(result), name, call.get("id", "")))
        return {"messages": outputs}

    # LangGraph calls nodes via .invoke() too; mirror __call__.
    def invoke(self, state: Any, config: Any = None) -> dict[str, Any]:
        return self(state)
