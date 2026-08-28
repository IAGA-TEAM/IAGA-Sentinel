"""Sync and async HTTP clients for the IAGA Sentinel API."""

from __future__ import annotations

from typing import Any, Mapping, Optional

import httpx

from .types import GovernanceResult, InspectRequest

JsonDict = dict[str, Any]


class SentinelApiError(httpx.HTTPStatusError):
    """An error response from the Sentinel API, carrying the server's message.

    ``_raise_for_status(response)`` raises ``httpx.HTTPStatusError``, whose text
    is the status line and a link to MDN — the server's own explanation is
    discarded. A first-time user calling ``inspect()`` for an agent that has no
    profile saw only ``Client error '404 Not Found'`` and had no way to guess the
    cause, while the TypeScript client showed ``agent_not_found: Agent not found:
    builder-01`` for the same request.

    Subclasses ``httpx.HTTPStatusError`` on purpose, so code that already
    catches that keeps working.
    """

    def __init__(self, response: httpx.Response) -> None:
        try:
            body: Any = response.json()
        except Exception:  # noqa: BLE001 - a non-JSON error body is still useful
            body = response.text
        detail = ""
        if isinstance(body, dict):
            detail = str(body.get("message") or body.get("error") or "").strip()
        elif isinstance(body, str):
            detail = body.strip()[:400]
        path = response.request.url.path if response.request else "<unknown>"
        message = f"{response.status_code} {path}"
        if detail:
            message = f"{message}: {detail}"
        super().__init__(message, request=response.request, response=response)
        self.status_code = response.status_code
        self.body = body


def _raise_for_status(response: httpx.Response) -> None:
    """Like ``_raise_for_status(response)``, but keeps the server's message."""
    if response.is_success:
        return
    raise SentinelApiError(response)


def _clean_params(params: Mapping[str, Any]) -> JsonDict:
    return {key: value for key, value in params.items() if value is not None}


def _normalize_inspect_request(request: InspectRequest | Mapping[str, Any]) -> JsonDict:
    if isinstance(request, InspectRequest):
        return request.to_dict()
    return dict(request)


class AsyncSentinelClient:
    """Async client for the IAGA Sentinel governance API."""

    def __init__(
        self,
        base_url: str = "http://localhost:4010",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        capability_token: Optional[str] = None,
    ):
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        # The token minted by `issue_token`. Every docstring that
        # returns one tells the caller to present it in this header; until
        # 2.1.0 the client had no way to. ponytail: one header, set once at
        # construction -- a token is bound to one agent, and so is a client.
        if capability_token:
            headers["X-IAGA-Capability-Token"] = capability_token
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    async def _get(self, path: str, **params: Any) -> Any:
        response = await self._client.get(path, params=_clean_params(params))
        _raise_for_status(response)
        return response.json()

    async def _post(self, path: str, json: Optional[JsonDict] = None) -> Any:
        response = await self._client.post(path, json=json)
        _raise_for_status(response)
        return response.json()

    async def _put(self, path: str, json: JsonDict) -> Any:
        response = await self._client.put(path, json=json)
        _raise_for_status(response)
        return response.json()

    async def _delete(self, path: str) -> None:
        response = await self._client.delete(path)
        _raise_for_status(response)

    async def inspect(self, request: InspectRequest | Mapping[str, Any]) -> GovernanceResult:
        response = await self._client.post(
            "/v1/inspect",
            json=_normalize_inspect_request(request),
        )
        _raise_for_status(response)
        return GovernanceResult.from_dict(response.json())

    async def list_audit(self) -> list[JsonDict]:
        return await self._get("/v1/audit")

    async def export_audit(
        self,
        *,
        format: str = "json",
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> str | list[JsonDict]:
        response = await self._client.get(
            "/v1/audit/export",
            params=_clean_params(
                {
                    "format": format,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    "decision": decision,
                    "from_date": from_date,
                    "to_date": to_date,
                    "limit": limit,
                }
            ),
        )
        _raise_for_status(response)
        if format == "csv":
            return response.text
        return response.json()

    async def get_stats(self) -> JsonDict:
        return await self._get("/v1/audit/stats")

    async def get_analytics(self, agent_id: Optional[str] = None) -> list[JsonDict]:
        if agent_id:
            return await self._get(f"/v1/analytics/agents/{agent_id}")
        return await self._get("/v1/analytics/agents")

    async def list_reviews(self) -> list[JsonDict]:
        return await self._get("/v1/reviews")

    async def resolve_review(self, review_id: str, status: str) -> JsonDict:
        return await self._post(f"/v1/reviews/{review_id}", {"status": status})

    async def list_profiles(self) -> list[JsonDict]:
        return await self._get("/v1/profiles")

    async def get_profile(self, agent_id: str) -> JsonDict:
        return await self._get(f"/v1/profiles/{agent_id}")

    async def create_profile(self, profile: Mapping[str, Any]) -> JsonDict:
        return await self._post("/v1/profiles", dict(profile))

    async def update_profile(self, profile: Mapping[str, Any]) -> JsonDict:
        agent_id = str(profile["agentId"])
        return await self._put(f"/v1/profiles/{agent_id}", dict(profile))

    async def delete_profile(self, agent_id: str) -> None:
        await self._delete(f"/v1/profiles/{agent_id}")

    async def list_workspaces(self) -> list[JsonDict]:
        return await self._get("/v1/workspaces")

    async def get_workspace(self, workspace_id: str) -> JsonDict:
        return await self._get(f"/v1/workspaces/{workspace_id}")

    async def create_workspace(self, workspace: Mapping[str, Any]) -> JsonDict:
        return await self._post("/v1/workspaces", dict(workspace))

    async def update_workspace(self, workspace: Mapping[str, Any]) -> JsonDict:
        workspace_id = str(workspace["workspaceId"])
        return await self._put(f"/v1/workspaces/{workspace_id}", dict(workspace))

    async def delete_workspace(self, workspace_id: str) -> None:
        await self._delete(f"/v1/workspaces/{workspace_id}")

    async def list_keys(self) -> list[JsonDict]:
        return await self._get("/v1/auth/keys")

    async def create_key(
        self,
        label: str,
        scope: str = "admin",
        agent_id: Optional[str] = None,
    ) -> JsonDict:
        body: JsonDict = {"label": label, "scope": scope}
        if agent_id is not None:
            body["agentId"] = agent_id
        return await self._post("/v1/auth/keys", body)

    async def delete_key(self, key_id: str) -> None:
        await self._delete(f"/v1/auth/keys/{key_id}")

    async def list_webhooks(self) -> list[JsonDict]:
        return await self._get("/v1/webhooks")

    async def register_webhook(
        self,
        url: str,
        secret: str,
        event_filter: Optional[list[str]] = None,
    ) -> JsonDict:
        return await self._post(
            "/v1/webhooks",
            {
                "url": url,
                "secret": secret,
                "eventFilter": event_filter or [],
            },
        )

    async def delete_webhook(self, webhook_id: str) -> None:
        await self._delete(f"/v1/webhooks/{webhook_id}")

    async def get_dlq(self) -> list[JsonDict]:
        return await self._get("/v1/webhooks/dlq")

    async def retry_dlq(self, entry_id: str) -> JsonDict:
        return await self._post(f"/v1/webhooks/dlq/{entry_id}/retry")

    async def delete_dlq(self, entry_id: str) -> None:
        await self._delete(f"/v1/webhooks/dlq/{entry_id}")

    async def list_sessions(self) -> list[JsonDict]:
        return await self._get("/v1/sessions")

    async def get_session_metrics(self, session_id: str) -> JsonDict:
        return await self._get(f"/v1/sessions/{session_id}/metrics")

    async def list_identities(self) -> list[JsonDict]:
        return await self._get("/v1/nhi/identities")

    async def register_identity(
        self,
        agent_id: str,
        workspace_id: Optional[str] = None,
        capabilities: Optional[list[str]] = None,
    ) -> JsonDict:
        return await self._post(
            "/v1/nhi/identities",
            {
                "agentId": agent_id,
                "workspaceId": workspace_id,
                "capabilities": capabilities or [],
            },
        )

    async def attest(self, agent_id: str, challenge: str) -> JsonDict:
        return await self._post(
            "/v1/nhi/attest",
            {"agentId": agent_id, "challenge": challenge},
        )

    async def create_challenge(self, agent_id: str) -> JsonDict:
        return await self._post("/v1/nhi/challenge", {"agentId": agent_id})

    async def verify_attestation(
        self,
        agent_id: str,
        challenge_id: str,
        signature: str,
    ) -> JsonDict:
        return await self._post(
            "/v1/nhi/verify",
            {
                "agentId": agent_id,
                "challengeId": challenge_id,
                "signature": signature,
            },
        )

    async def issue_token(
        self,
        agent_id: str,
        capabilities: list[str],
        ttl_seconds: int = 3600,
    ) -> JsonDict:
        """Mint a capability token bound to ``agent_id``.

        Requires an ADMIN key (2.1.0): the route had no guard, so any
        agent-scoped key could mint ``capabilities=["*"]`` for any agent.

        Present the returned ``tokenId`` in the ``X-IAGA-Capability-Token``
        header to use it. ``read:self`` lets an agent read its own
        ``/v1/profiles/{agent_id}`` and ``/v1/analytics/agents/{agent_id}``,
        which are otherwise admin-only. A token is bound to one agent and can
        never read another's data, whatever capabilities it carries.
        """
        return await self._post(
            "/v1/nhi/tokens",
            {
                "agentId": agent_id,
                "capabilities": capabilities,
                "ttlSeconds": ttl_seconds,
            },
        )

    async def list_tokens(self) -> list[JsonDict]:
        """List the capability tokens currently outstanding. ADMIN key.

        Signatures are withheld: this answers "what is authorized right now",
        which is the question an operator asks before revoking. Without it the
        SDK could mint and revoke but not enumerate, so revoking meant already
        knowing the ``tokenId`` you were looking for.
        """
        return await self._get("/v1/nhi/tokens")

    async def revoke_token(self, token_id: str) -> None:
        """Revoke a capability token. Requires an ADMIN key.

        Durable and fleet-wide: the stored row is the authority, so there is no
        in-process cache to go stale. New in 2.1.0 -- revocation was
        implemented but had no route, so a token could never be withdrawn.
        """
        await self._delete(f"/v1/nhi/tokens/{token_id}")

    async def get_risk_weights(self) -> JsonDict:
        return await self._get("/v1/risk/weights")

    async def submit_feedback(self, feedback: str) -> JsonDict:
        return await self._post("/v1/risk/feedback", {"feedback": feedback})

    async def list_pending_sandbox(self) -> list[JsonDict]:
        return await self._get("/v1/sandbox/pending")

    async def approve_sandbox(self, sandbox_id: str) -> JsonDict:
        return await self._post(f"/v1/sandbox/{sandbox_id}/approve")

    async def reject_sandbox(self, sandbox_id: str) -> JsonDict:
        return await self._post(f"/v1/sandbox/{sandbox_id}/reject")

    async def verify_policy(self, workspace_id: str) -> JsonDict:
        return await self._get(f"/v1/policy/verify/{workspace_id}")

    async def scan_response(self, request: Mapping[str, Any]) -> JsonDict:
        return await self._post("/v1/response/scan", dict(request))

    async def get_patterns(self) -> list[JsonDict]:
        return await self._get("/v1/response/patterns")

    async def scan_firewall(self, text: str) -> JsonDict:
        return await self._post("/v1/firewall/scan", {"text": text})

    async def get_firewall_stats(self) -> JsonDict:
        return await self._get("/v1/firewall/stats")

    async def list_spans(self) -> list[JsonDict]:
        return await self._get("/v1/telemetry/spans")

    async def get_metrics(self) -> list[JsonDict]:
        return await self._get("/v1/telemetry/metrics")

    async def export_telemetry(self) -> list[JsonDict]:
        return await self._get("/v1/telemetry/export")

    async def list_fingerprints(self) -> list[JsonDict]:
        return await self._get("/v1/fingerprint")

    async def get_fingerprint(self, agent_id: str) -> JsonDict:
        return await self._get(f"/v1/fingerprint/{agent_id}")

    async def get_status(self, agent_id: str) -> JsonDict:
        return await self._get(f"/v1/rate-limit/status/{agent_id}")

    async def get_config(self) -> JsonDict:
        return await self._get("/v1/rate-limit/config")

    async def set_config(self, config: Mapping[str, Any]) -> JsonDict:
        return await self._post("/v1/rate-limit/config", dict(config))

    async def list_indicators(self) -> list[JsonDict]:
        return await self._get("/v1/threat-intel/indicators")

    async def add_indicator(self, indicator: Mapping[str, Any]) -> JsonDict:
        return await self._post("/v1/threat-intel/indicators", dict(indicator))

    async def delete_indicator(self, indicator_id: str) -> None:
        await self._delete(f"/v1/threat-intel/indicators/{indicator_id}")

    async def get_threat_intel_stats(self) -> JsonDict:
        return await self._get("/v1/threat-intel/stats")

    async def check_threats(self, content: str) -> JsonDict:
        return await self._post("/v1/threat-intel/check", {"content": content})

    async def list_templates(self) -> list[JsonDict]:
        return await self._get("/v1/templates")

    async def get_template(self, template_id: str) -> JsonDict:
        return await self._get(f"/v1/templates/{template_id}")

    async def list_workspace_rules(self, workspace_id: str) -> list[JsonDict]:
        return await self._get(f"/v1/workspaces/{workspace_id}/rules")

    async def add_workspace_rule(
        self,
        workspace_id: str,
        rule: Mapping[str, Any],
    ) -> JsonDict:
        return await self._post(f"/v1/workspaces/{workspace_id}/rules", dict(rule))

    async def list_plugins(self) -> JsonDict:
        return await self._get("/v1/plugins")

    async def reload_plugins(self) -> JsonDict:
        return await self._post("/v1/plugins/reload")

    async def list_demo_scenarios(self) -> list[JsonDict]:
        return await self._get("/v1/demo/scenarios")

    async def run_demo_adapter(self) -> list[JsonDict]:
        return await self._post("/v1/demo/run-adapter")

    async def health(self) -> JsonDict:
        return await self._get("/health")

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "AsyncSentinelClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()


class SentinelClient:
    """Sync client for the IAGA Sentinel governance API."""

    def __init__(
        self,
        base_url: str = "http://localhost:4010",
        api_key: Optional[str] = None,
        timeout: float = 10.0,
        capability_token: Optional[str] = None,
    ):
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        # The token minted by `issue_token`. Every docstring that
        # returns one tells the caller to present it in this header; until
        # 2.1.0 the client had no way to. ponytail: one header, set once at
        # construction -- a token is bound to one agent, and so is a client.
        if capability_token:
            headers["X-IAGA-Capability-Token"] = capability_token
        self._client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    def _get(self, path: str, **params: Any) -> Any:
        response = self._client.get(path, params=_clean_params(params))
        _raise_for_status(response)
        return response.json()

    def _post(self, path: str, json: Optional[JsonDict] = None) -> Any:
        response = self._client.post(path, json=json)
        _raise_for_status(response)
        return response.json()

    def _put(self, path: str, json: JsonDict) -> Any:
        response = self._client.put(path, json=json)
        _raise_for_status(response)
        return response.json()

    def _delete(self, path: str) -> None:
        response = self._client.delete(path)
        _raise_for_status(response)

    def inspect(self, request: InspectRequest | Mapping[str, Any]) -> GovernanceResult:
        response = self._client.post(
            "/v1/inspect",
            json=_normalize_inspect_request(request),
        )
        _raise_for_status(response)
        return GovernanceResult.from_dict(response.json())

    def list_audit(self) -> list[JsonDict]:
        return self._get("/v1/audit")

    def export_audit(
        self,
        *,
        format: str = "json",
        tenant_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> str | list[JsonDict]:
        response = self._client.get(
            "/v1/audit/export",
            params=_clean_params(
                {
                    "format": format,
                    "tenant_id": tenant_id,
                    "agent_id": agent_id,
                    "decision": decision,
                    "from_date": from_date,
                    "to_date": to_date,
                    "limit": limit,
                }
            ),
        )
        _raise_for_status(response)
        if format == "csv":
            return response.text
        return response.json()

    def get_stats(self) -> JsonDict:
        return self._get("/v1/audit/stats")

    def get_analytics(self, agent_id: Optional[str] = None) -> list[JsonDict]:
        if agent_id:
            return self._get(f"/v1/analytics/agents/{agent_id}")
        return self._get("/v1/analytics/agents")

    def list_reviews(self) -> list[JsonDict]:
        return self._get("/v1/reviews")

    def resolve_review(self, review_id: str, status: str) -> JsonDict:
        return self._post(f"/v1/reviews/{review_id}", {"status": status})

    def list_profiles(self) -> list[JsonDict]:
        return self._get("/v1/profiles")

    def get_profile(self, agent_id: str) -> JsonDict:
        return self._get(f"/v1/profiles/{agent_id}")

    def create_profile(self, profile: Mapping[str, Any]) -> JsonDict:
        return self._post("/v1/profiles", dict(profile))

    def update_profile(self, profile: Mapping[str, Any]) -> JsonDict:
        agent_id = str(profile["agentId"])
        return self._put(f"/v1/profiles/{agent_id}", dict(profile))

    def delete_profile(self, agent_id: str) -> None:
        self._delete(f"/v1/profiles/{agent_id}")

    def list_workspaces(self) -> list[JsonDict]:
        return self._get("/v1/workspaces")

    def get_workspace(self, workspace_id: str) -> JsonDict:
        return self._get(f"/v1/workspaces/{workspace_id}")

    def create_workspace(self, workspace: Mapping[str, Any]) -> JsonDict:
        return self._post("/v1/workspaces", dict(workspace))

    def update_workspace(self, workspace: Mapping[str, Any]) -> JsonDict:
        workspace_id = str(workspace["workspaceId"])
        return self._put(f"/v1/workspaces/{workspace_id}", dict(workspace))

    def delete_workspace(self, workspace_id: str) -> None:
        self._delete(f"/v1/workspaces/{workspace_id}")

    def list_keys(self) -> list[JsonDict]:
        return self._get("/v1/auth/keys")

    def create_key(
        self,
        label: str,
        scope: str = "admin",
        agent_id: Optional[str] = None,
    ) -> JsonDict:
        body: JsonDict = {"label": label, "scope": scope}
        if agent_id is not None:
            body["agentId"] = agent_id
        return self._post("/v1/auth/keys", body)

    def delete_key(self, key_id: str) -> None:
        self._delete(f"/v1/auth/keys/{key_id}")

    def list_webhooks(self) -> list[JsonDict]:
        return self._get("/v1/webhooks")

    def register_webhook(
        self,
        url: str,
        secret: str,
        event_filter: Optional[list[str]] = None,
    ) -> JsonDict:
        return self._post(
            "/v1/webhooks",
            {
                "url": url,
                "secret": secret,
                "eventFilter": event_filter or [],
            },
        )

    def delete_webhook(self, webhook_id: str) -> None:
        self._delete(f"/v1/webhooks/{webhook_id}")

    def get_dlq(self) -> list[JsonDict]:
        return self._get("/v1/webhooks/dlq")

    def retry_dlq(self, entry_id: str) -> JsonDict:
        return self._post(f"/v1/webhooks/dlq/{entry_id}/retry")

    def delete_dlq(self, entry_id: str) -> None:
        self._delete(f"/v1/webhooks/dlq/{entry_id}")

    def list_sessions(self) -> list[JsonDict]:
        return self._get("/v1/sessions")

    def get_session_metrics(self, session_id: str) -> JsonDict:
        return self._get(f"/v1/sessions/{session_id}/metrics")

    def list_identities(self) -> list[JsonDict]:
        return self._get("/v1/nhi/identities")

    def register_identity(
        self,
        agent_id: str,
        workspace_id: Optional[str] = None,
        capabilities: Optional[list[str]] = None,
    ) -> JsonDict:
        return self._post(
            "/v1/nhi/identities",
            {
                "agentId": agent_id,
                "workspaceId": workspace_id,
                "capabilities": capabilities or [],
            },
        )

    def attest(self, agent_id: str, challenge: str) -> JsonDict:
        return self._post(
            "/v1/nhi/attest",
            {"agentId": agent_id, "challenge": challenge},
        )

    def create_challenge(self, agent_id: str) -> JsonDict:
        return self._post("/v1/nhi/challenge", {"agentId": agent_id})

    def verify_attestation(
        self,
        agent_id: str,
        challenge_id: str,
        signature: str,
    ) -> JsonDict:
        return self._post(
            "/v1/nhi/verify",
            {
                "agentId": agent_id,
                "challengeId": challenge_id,
                "signature": signature,
            },
        )

    def issue_token(
        self,
        agent_id: str,
        capabilities: list[str],
        ttl_seconds: int = 3600,
    ) -> JsonDict:
        """Mint a capability token bound to ``agent_id``.

        Requires an ADMIN key (2.1.0): the route had no guard, so any
        agent-scoped key could mint ``capabilities=["*"]`` for any agent.

        Present the returned ``tokenId`` in the ``X-IAGA-Capability-Token``
        header to use it. ``read:self`` lets an agent read its own
        ``/v1/profiles/{agent_id}`` and ``/v1/analytics/agents/{agent_id}``,
        which are otherwise admin-only. A token is bound to one agent and can
        never read another's data, whatever capabilities it carries.
        """
        return self._post(
            "/v1/nhi/tokens",
            {
                "agentId": agent_id,
                "capabilities": capabilities,
                "ttlSeconds": ttl_seconds,
            },
        )

    def list_tokens(self) -> list[JsonDict]:
        """List outstanding capability tokens. ADMIN key. See the async twin."""
        return self._get("/v1/nhi/tokens")

    def revoke_token(self, token_id: str) -> None:
        """Revoke a capability token. Requires an ADMIN key. See the async twin."""
        self._delete(f"/v1/nhi/tokens/{token_id}")

    def get_risk_weights(self) -> JsonDict:
        return self._get("/v1/risk/weights")

    def submit_feedback(self, feedback: str) -> JsonDict:
        return self._post("/v1/risk/feedback", {"feedback": feedback})

    def list_pending_sandbox(self) -> list[JsonDict]:
        return self._get("/v1/sandbox/pending")

    def approve_sandbox(self, sandbox_id: str) -> JsonDict:
        return self._post(f"/v1/sandbox/{sandbox_id}/approve")

    def reject_sandbox(self, sandbox_id: str) -> JsonDict:
        return self._post(f"/v1/sandbox/{sandbox_id}/reject")

    def verify_policy(self, workspace_id: str) -> JsonDict:
        return self._get(f"/v1/policy/verify/{workspace_id}")

    def scan_response(self, request: Mapping[str, Any]) -> JsonDict:
        return self._post("/v1/response/scan", dict(request))

    def get_patterns(self) -> list[JsonDict]:
        return self._get("/v1/response/patterns")

    def scan_firewall(self, text: str) -> JsonDict:
        return self._post("/v1/firewall/scan", {"text": text})

    def get_firewall_stats(self) -> JsonDict:
        return self._get("/v1/firewall/stats")

    def list_spans(self) -> list[JsonDict]:
        return self._get("/v1/telemetry/spans")

    def get_metrics(self) -> list[JsonDict]:
        return self._get("/v1/telemetry/metrics")

    def export_telemetry(self) -> list[JsonDict]:
        return self._get("/v1/telemetry/export")

    def list_fingerprints(self) -> list[JsonDict]:
        return self._get("/v1/fingerprint")

    def get_fingerprint(self, agent_id: str) -> JsonDict:
        return self._get(f"/v1/fingerprint/{agent_id}")

    def get_status(self, agent_id: str) -> JsonDict:
        return self._get(f"/v1/rate-limit/status/{agent_id}")

    def get_config(self) -> JsonDict:
        return self._get("/v1/rate-limit/config")

    def set_config(self, config: Mapping[str, Any]) -> JsonDict:
        return self._post("/v1/rate-limit/config", dict(config))

    def list_indicators(self) -> list[JsonDict]:
        return self._get("/v1/threat-intel/indicators")

    def add_indicator(self, indicator: Mapping[str, Any]) -> JsonDict:
        return self._post("/v1/threat-intel/indicators", dict(indicator))

    def delete_indicator(self, indicator_id: str) -> None:
        self._delete(f"/v1/threat-intel/indicators/{indicator_id}")

    def get_threat_intel_stats(self) -> JsonDict:
        return self._get("/v1/threat-intel/stats")

    def check_threats(self, content: str) -> JsonDict:
        return self._post("/v1/threat-intel/check", {"content": content})

    def list_templates(self) -> list[JsonDict]:
        return self._get("/v1/templates")

    def get_template(self, template_id: str) -> JsonDict:
        return self._get(f"/v1/templates/{template_id}")

    def list_workspace_rules(self, workspace_id: str) -> list[JsonDict]:
        return self._get(f"/v1/workspaces/{workspace_id}/rules")

    def add_workspace_rule(self, workspace_id: str, rule: Mapping[str, Any]) -> JsonDict:
        return self._post(f"/v1/workspaces/{workspace_id}/rules", dict(rule))

    def list_plugins(self) -> JsonDict:
        return self._get("/v1/plugins")

    def reload_plugins(self) -> JsonDict:
        return self._post("/v1/plugins/reload")

    def list_demo_scenarios(self) -> list[JsonDict]:
        return self._get("/v1/demo/scenarios")

    def run_demo_adapter(self) -> list[JsonDict]:
        return self._post("/v1/demo/run-adapter")

    def health(self) -> JsonDict:
        return self._get("/health")

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SentinelClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()
