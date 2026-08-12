"""Dependency-light CrewAI guardrail helpers for IAGA Sentinel."""

from __future__ import annotations

from typing import Any, Mapping, Optional

from ..types import ActionType
from ._common import (
    AdapterConfig,
    build_request,
    inspect_async,
    inspect_sync,
    resolve_action_type,
)


class SentinelGuardrail:
    """Guardrail object that can be called before a CrewAI tool/action runs.

    See plug-ins/crewai-adapter/ for a runnable example.
    """

    def __init__(
        self,
        *,
        agent_id: str,
        api_key: Optional[str] = None,
        base_url: str = "http://localhost:4010",
        framework: str = "crewai",
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

    def validate(
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

    async def avalidate(
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

    def __call__(
        self,
        tool_name: str,
        payload: dict[str, Any],
        action_type: Optional[ActionType] = None,
    ) -> dict[str, Any]:
        self.validate(tool_name, payload, action_type=action_type)
        return payload
