"""Type definitions for the IAGA Sentinel Python SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

JsonDict = dict[str, Any]


class GovernanceDecision(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class ActionType(str, Enum):
    SHELL = "shell"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    HTTP = "http"
    DB_QUERY = "db_query"
    EMAIL = "email"
    CUSTOM = "custom"


class ReviewStatus(str, Enum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ProtocolKind(str, Enum):
    MCP = "mcp"
    ACP = "acp"
    A2A = "a2a"
    HTTP_FUNCTION = "http-function"
    UNKNOWN = "unknown"


@dataclass
class ActionDetail:
    type: ActionType
    tool_name: str
    payload: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return {
            "type": self.type.value,
            "toolName": self.tool_name,
            "payload": self.payload,
        }


@dataclass
class InspectRequest:
    agent_id: str
    framework: str
    action: ActionDetail
    tenant_id: Optional[str] = None
    workspace_id: Optional[str] = None
    protocol: Optional[ProtocolKind | str] = None
    requested_secrets: Optional[list[str]] = None
    metadata: Optional[JsonDict] = None
    session_id: Optional[str] = None

    def to_dict(self) -> JsonDict:
        data: JsonDict = {
            "agentId": self.agent_id,
            "framework": self.framework,
            "action": self.action.to_dict(),
        }
        if self.tenant_id is not None:
            data["tenantId"] = self.tenant_id
        if self.workspace_id is not None:
            data["workspaceId"] = self.workspace_id
        if self.protocol is not None:
            data["protocol"] = (
                self.protocol.value
                if isinstance(self.protocol, ProtocolKind)
                else self.protocol
            )
        if self.requested_secrets is not None:
            data["requestedSecrets"] = self.requested_secrets

        metadata = dict(self.metadata or {})
        if self.session_id is not None:
            metadata["sessionId"] = self.session_id
        if metadata:
            data["metadata"] = metadata

        return data


@dataclass
class RiskScore:
    score: int
    decision: GovernanceDecision
    reasons: list[str]


@dataclass
class SchemaValidation:
    tool_name: str
    valid: bool
    findings: list[str]

    @classmethod
    def from_dict(cls, data: JsonDict) -> "SchemaValidation":
        return cls(
            tool_name=str(data.get("toolName", "")),
            valid=bool(data.get("valid", False)),
            findings=list(data.get("findings", [])),
        )


@dataclass
class SecretPlan:
    approved: list[str]
    denied: list[str]

    @classmethod
    def from_dict(cls, data: JsonDict) -> "SecretPlan":
        return cls(
            approved=list(data.get("approved", [])),
            denied=list(data.get("denied", [])),
        )


@dataclass
class PluginResult:
    risk_score: int
    findings: list[str]
    decision_hint: Optional[str] = None

    @classmethod
    def from_dict(cls, data: JsonDict) -> "PluginResult":
        return cls(
            risk_score=int(data.get("riskScore", 0)),
            findings=list(data.get("findings", [])),
            decision_hint=data.get("decisionHint"),
        )


@dataclass
class PluginOutput:
    plugin_name: str
    plugin_version: str
    execution_ms: int
    result: PluginResult

    @classmethod
    def from_dict(cls, data: JsonDict) -> "PluginOutput":
        return cls(
            plugin_name=str(data.get("pluginName", "")),
            plugin_version=str(data.get("pluginVersion", "")),
            execution_ms=int(data.get("executionMs", 0)),
            result=PluginResult.from_dict(dict(data.get("result", {}))),
        )


@dataclass
class GovernanceResult:
    trace_id: str
    decision: GovernanceDecision
    review_status: ReviewStatus
    risk: RiskScore
    policy_findings: list[str]
    protocol: ProtocolKind
    normalized_payload: JsonDict = field(default_factory=dict)
    schema_validation: SchemaValidation = field(
        default_factory=lambda: SchemaValidation("", False, [])
    )
    secret_plan: SecretPlan = field(default_factory=lambda: SecretPlan([], []))
    review_request_id: Optional[str] = None
    plugin_results: list[PluginOutput] = field(default_factory=list)
    audit_event: JsonDict = field(default_factory=dict)
    profile: JsonDict = field(default_factory=dict)
    workspace_policy: JsonDict = field(default_factory=dict)
    # The role each layer plays in a verdict: `veto` (can decide on its own),
    # `scoring` (contributes to the composite), or `advisory` (reported, never
    # decisive). Carried so an SDK consumer is not left to guess that four of
    # the ten layer blocks — `sandboxResult`, the behavioural fingerprint,
    # `telemetrySpan` and `policyVerification` — cannot move a decision, and
    # neither can the session graph's `advisoryScore` sub-field; treating them
    # as active defences overstates coverage. Note the session graph's signed
    # `anomalyScore` is a
    # different field and IS decisive: it is a term in the composite and
    # escalates to review on its own at 50.
    # Empty against an older server that does not send it.
    layer_roles: JsonDict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: JsonDict) -> "GovernanceResult":
        risk_data = dict(data.get("risk", {}))
        decision = GovernanceDecision(str(data.get("decision", "block")))
        protocol_raw = str(data.get("protocol", "unknown"))

        try:
            protocol = ProtocolKind(protocol_raw)
        except ValueError:
            protocol = ProtocolKind.UNKNOWN

        return cls(
            trace_id=str(data.get("traceId", "")),
            decision=decision,
            review_status=ReviewStatus(data.get("reviewStatus", "not_required")),
            risk=RiskScore(
                score=int(risk_data.get("score", 0)),
                decision=GovernanceDecision(
                    str(risk_data.get("decision", decision.value))
                ),
                reasons=list(risk_data.get("reasons", [])),
            ),
            policy_findings=list(data.get("policyFindings", [])),
            protocol=protocol,
            normalized_payload=dict(data.get("normalizedPayload", {})),
            schema_validation=SchemaValidation.from_dict(
                dict(data.get("schemaValidation", {}))
            ),
            secret_plan=SecretPlan.from_dict(dict(data.get("secretPlan", {}))),
            review_request_id=data.get("reviewRequestId"),
            plugin_results=[
                PluginOutput.from_dict(dict(item))
                for item in data.get("pluginResults", [])
            ],
            audit_event=dict(data.get("auditEvent", {})),
            profile=dict(data.get("profile", {})),
            workspace_policy=dict(data.get("workspacePolicy", {})),
            layer_roles=dict(data.get("layerRoles", {})),
        )

    def is_advisory_layer(self, layer: str) -> bool:
        """Whether `layer` is reported but cannot move a verdict.

        A consumer building its own risk view should not sum advisory layers in
        with the deciding ones. Unknown layers return False so a missing
        `layerRoles` (older server) does not silently reclassify everything.
        """
        role = self.layer_roles.get(layer)
        return isinstance(role, dict) and role.get("role") == "advisory"

    @property
    def allowed(self) -> bool:
        return self.decision == GovernanceDecision.ALLOW

    @property
    def blocked(self) -> bool:
        return self.decision == GovernanceDecision.BLOCK

    @property
    def needs_review(self) -> bool:
        return self.decision == GovernanceDecision.REVIEW

    @classmethod
    def fail_open(
        cls, reason: str = "IAGA Sentinel unreachable; failing open"
    ) -> "GovernanceResult":
        """Synthesize an ``allow`` result for the transport fail-open path.

        Used when the IAGA sidecar is unreachable and the operator has not
        opted into fail-closed; the action proceeds but no receipt is signed.
        """
        return cls(
            trace_id="",
            decision=GovernanceDecision.ALLOW,
            review_status=ReviewStatus.NOT_REQUIRED,
            risk=RiskScore(score=0, decision=GovernanceDecision.ALLOW, reasons=[reason]),
            policy_findings=[],
            protocol=ProtocolKind.UNKNOWN,
        )


def resolve_unreachable(
    tool_name: str, exc: Exception, *, fail_closed: bool
) -> GovernanceResult:
    """Apply the transport-error policy: fail-open (default) or fail-closed.

    Adapters fail **open** on transport errors by default, so a governance
    outage does not take the agent down; operators may opt into fail-closed.
    """
    if fail_closed:
        raise PermissionError(
            f"IAGA Sentinel unreachable for '{tool_name}' (fail-closed): {exc}"
        ) from exc
    return GovernanceResult.fail_open(
        f"IAGA Sentinel unreachable ({exc}); failing open"
    )
