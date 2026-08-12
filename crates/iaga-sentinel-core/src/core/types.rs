use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::plugins::PluginOutput;

// 1.5 cost-control: the canonical cost/usage types live in the leaf crate
// `iaga-sentinel-cost`; re-exported here so the rest of core (and tests) can
// reach them via `crate::core::types::*`.
pub use iaga_sentinel_cost::{CostSource, UsageData, UsageReport};

// ── Tenant ──

/// A tenant owns multiple workspaces. All data is scoped to a tenant.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tenant {
    pub tenant_id: String,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

// ── Enums ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtocolKind {
    Mcp,
    Acp,
    A2a,
    HttpFunction,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Shell,
    FileRead,
    FileWrite,
    Http,
    DbQuery,
    Email,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GovernanceDecision {
    Allow,
    Review,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    NotRequired,
    Pending,
    Approved,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentRole {
    Builder,
    Researcher,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewAction {
    Approved,
    Rejected,
}

// ── Request / Response ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectRequest {
    pub agent_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub framework: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<ProtocolKind>,
    pub action: ActionDetail,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_secrets: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
    /// 1.5 cost-control: optional usage reported by the caller (an agent SDK or
    /// any client). Captured into the receipt + audit cost ledger when the host
    /// build enables `cost-control`; ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionDetail {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    pub tool_name: String,
    pub payload: HashMap<String, serde_json::Value>,
}

// ── Risk ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub score: u32,
    pub decision: GovernanceDecision,
    pub reasons: Vec<String>,
}

// ── Profiles & Policies ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProfile {
    pub agent_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub workspace_id: String,
    pub framework: String,
    pub role: AgentRole,
    pub approved_tools: Vec<String>,
    pub approved_secrets: Vec<String>,
    pub baseline_action_types: Vec<ActionType>,
    /// Default tool trust score for risk scoring (0.0-1.0). Defaults to 0.7.
    #[serde(default = "default_tool_trust")]
    pub tool_trust: f64,
}

fn default_tool_trust() -> f64 {
    0.7
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolPolicy {
    pub tool_name: String,
    pub allowed_action_types: Vec<ActionType>,
    pub max_decision: GovernanceDecision,
    #[serde(default)]
    pub requires_human_review: bool,
    /// Payload keys that carry this tool's egress destination, in priority
    /// order. Declaring them turns the domain allowlist from best-effort into
    /// fail-closed for THIS tool: a payload exposing none of them is blocked
    /// rather than allowed (see `evaluate_policy`).
    ///
    /// Empty means "not declared", which keeps the legacy behaviour: a fixed
    /// `destination`/`url`/`endpoint`/`href` probe that silently skips the
    /// allowlist when it finds nothing. That fallback is why this field exists,
    /// and why the default must stay empty rather than become a guess.
    ///
    /// # Why per-tool and not per-action-type
    ///
    /// The obvious version of this fix — fail closed on any `Http` action with
    /// no recognisable destination — shipped as `fe52454` and was reverted by
    /// `ad51406` four days later, because it blocked `openai.chat.completions
    /// .create`: an HTTP action whose destination lives in the SDK, not in the
    /// payload. The discriminator is not the action type but whether THIS tool
    /// takes a caller-controlled destination, which is per-tool information and
    /// belongs here.
    ///
    /// # Why `skip_serializing_if`
    ///
    /// `pipeline::policy_hash::workspace_policy_hash` digests the whole
    /// serialized `WorkspacePolicy`, and that digest is bound into every signed
    /// receipt. Skipping the empty case keeps a policy that has not adopted the
    /// field serializing byte-for-byte as before, so existing receipts stay tied
    /// to an unchanged hash. Only a workspace that actually declares a field
    /// gets a new hash — which is correct, because its governance really did
    /// change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub destination_fields: Vec<String>,
}

/// Sensible `destination_fields` for a generic caller-controlled HTTP fetch.
///
/// Wider than the legacy fixed probe (`destination`/`url`/`endpoint`/`href`) on
/// purpose: once a tool declares its fields the extraction is fail-closed, so a
/// name that is merely *unusual* — `uri`, `target`, `webhook` — should be
/// host-checked against the allowlist rather than turned into a refusal. The
/// names NOT listed here are the point: they now block instead of slipping
/// through.
pub const DEFAULT_EGRESS_DESTINATION_FIELDS: [&str; 7] = [
    "destination",
    "url",
    "uri",
    "endpoint",
    "href",
    "target",
    "webhook",
];

impl ToolPolicy {
    /// `destination_fields` for a tool whose destination is an ordinary
    /// caller-supplied URL.
    pub fn default_egress_fields() -> Vec<String> {
        DEFAULT_EGRESS_DESTINATION_FIELDS
            .iter()
            .map(|s| (*s).to_string())
            .collect()
    }
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self {
            tool_name: String::new(),
            allowed_action_types: Vec::new(),
            // The safe end of the scale: a tool nobody configured should not be
            // more permissive than one somebody did.
            max_decision: GovernanceDecision::Block,
            requires_human_review: false,
            destination_fields: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePolicy {
    pub workspace_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub allowed_protocols: Vec<ProtocolKind>,
    pub tools: Vec<ToolPolicy>,
    pub allowed_domains: Vec<String>,
    /// Risk score threshold for blocking decisions (0-100). Default: 70.
    #[serde(default = "default_threshold_block")]
    pub threshold_block: u32,
    /// Risk score threshold for review decisions (0-100). Default: 35.
    #[serde(default = "default_threshold_review")]
    pub threshold_review: u32,
}

fn default_threshold_block() -> u32 {
    70
}

fn default_threshold_review() -> u32 {
    35
}

// ── Secrets ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretInjectionPlan {
    pub approved: Vec<String>,
    pub denied: Vec<String>,
}

// ── Audit ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub event_id: String,
    pub agent_id: String,
    pub framework: String,
    pub action_type: ActionType,
    pub tool_name: String,
    pub decision: GovernanceDecision,
    pub timestamp: String,
    pub reasons: Vec<String>,
}

// ── Governance Result ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaValidation {
    pub tool_name: String,
    pub valid: bool,
    pub findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceResult {
    pub trace_id: String,
    pub protocol: ProtocolKind,
    pub normalized_payload: HashMap<String, serde_json::Value>,
    pub decision: GovernanceDecision,
    pub review_status: ReviewStatus,
    pub risk: RiskScore,
    pub secret_plan: SecretInjectionPlan,
    pub audit_event: AuditEvent,
    pub profile: AgentProfile,
    pub workspace_policy: WorkspacePolicy,
    pub policy_findings: Vec<String>,
    pub schema_validation: SchemaValidation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_request_id: Option<String>,
    // ── 8-Layer Security Stack ──
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_graph: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint_analysis: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adaptive_risk: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub injection_firewall: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_verification: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telemetry_span: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavioral_fingerprint: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_intel: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_results: Option<Vec<PluginOutput>>,
    /// Advisory signals computed from process-global mutable state (session
    /// burst + prior-block history, adaptive baseline velocity/novelty,
    /// behavioral fingerprint anomalies). Surfaced for dashboards/alerting but
    /// DELIBERATELY excluded from the signed verdict (`decision`/`risk`/
    /// `reasons`), so the receipt stays reproducible from its recorded inputs
    /// alone (D1 / DET-* cluster). `None` when no advisory signal fired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<serde_json::Value>,
    /// What each layer block above is allowed to do to a verdict.
    ///
    /// A response that lists ten layer blocks with no further qualification
    /// invites the reader to count ten defences. Four of them cannot move a
    /// verdict at all, by construction and on purpose:
    ///
    ///  * `behavioralFingerprint` — its risk contribution is pinned to 0
    ///    (`DET-BEHAVIORAL-2`), because it is derived from process-global
    ///    mutable state that a receipt cannot reproduce.
    ///  * `sandboxResult` — the composite in `tool_risk` has no sandbox term.
    ///    It is containment and reporting, not scoring.
    ///  * `policyVerification` — it lints the WORKSPACE POLICY, not the
    ///    request. `execute_pipeline` computes it, serializes it and never
    ///    reads it back, so no issue it reports changes a verdict at any
    ///    severity.
    ///  * `telemetrySpan` — an emitted span reference. Nothing reads it back.
    ///
    /// Not one of the ten, and the reason this list used to say three:
    /// `sessionGraph.advisoryScore` is a SUB-FIELD of the session graph block,
    /// not a block of its own — prior-block history and the wall-clock burst,
    /// excluded from the signed verdict. It is NOT the same field as
    /// `anomalyScore`, which is signed, is a term in the composite and
    /// escalates to review on its own at 50.
    ///
    /// Publishing that distinction machine-readably is the same class of fix as
    /// 2.0.1 ("layers that reported themselves present and were not") and the
    /// removal of the adaptive block arm: a layer must not appear to be doing
    /// more than it does. No verdict changes because of this field.
    #[serde(default = "layer_roles")]
    pub layer_roles: serde_json::Value,
}

/// The fixed role table serialized into [`GovernanceResult::layer_roles`].
///
/// `veto` — can force a decision on its own. `scoring` — contributes a term to
/// the composite risk score. `advisory` — reported, never decisive.
pub fn layer_roles() -> serde_json::Value {
    serde_json::json!({
        "sessionGraph": {
            "role": "veto",
            "note": "Attack signatures veto; `advisoryScore` does not."
        },
        "taintAnalysis": { "role": "veto" },
        "injectionFirewall": { "role": "veto" },
        "threatIntel": { "role": "veto" },
        "schemaValidation": { "role": "veto" },
        "policyFindings": { "role": "veto" },
        "policyVerification": {
            "role": "advisory",
            "note": "Lints the WORKSPACE POLICY, not the request. \
                     `execute_pipeline` computes it, serializes it and never \
                     reads it back, so no issue it reports — at any severity — \
                     changes a verdict. It answers 'is this policy coherent', \
                     which is a question about configuration; `policyFindings` \
                     is the arm that judges the request and vetoes."
        },
        "adaptiveRisk": {
            "role": "scoring",
            "note": "Contributes to the composite and can escalate to review. \
                     It has NO score-driven block arm: at its default weights \
                     the signed ceiling of its four signals is below the block \
                     threshold, so `block` here comes only from the categorical \
                     exfiltration override. (Admin feedback via \
                     POST /v1/risk/feedback re-normalises those weights and can \
                     lift the ceiling; it still cannot block, because the \
                     decision has no score arm to reach.) Its `advisory` array \
                     is excluded from the signed score entirely."
        },
        "sandboxResult": {
            "role": "advisory",
            "note": "Containment and reporting. The composite risk formula has \
                     no sandbox term, so this never moves a verdict."
        },
        "behavioralFingerprint": {
            "role": "advisory",
            "note": "Risk contribution pinned to 0 (DET-BEHAVIORAL-2): derived \
                     from process-global mutable state a receipt cannot \
                     reproduce."
        },
        "telemetrySpan": {
            "role": "advisory",
            "note": "An emitted OTel span reference. Nothing reads it back, and \
                     no risk term is derived from it."
        },
        "pluginResults": {
            "role": "veto",
            "note": "Vetoes and scores. `tool_risk` weights the plugin layer at \
                     0.10 of the composite, but `execute_pipeline` also lets a \
                     plugin force a decision outright: a `decision_hint` of \
                     `block`, or a plugin score at or above the workspace block \
                     threshold — a comparison on the plugin's OWN scale, not \
                     the composite, so the 0.10 weight does not bound it. A \
                     plugin error escalates to review."
        },
        "advisory": {
            "role": "advisory",
            "note": "Excluded from the signed verdict by construction (D1)."
        }
    })
}

// ── Review Request ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRequest {
    pub id: String,
    pub agent_id: String,
    pub workspace_id: String,
    pub tool_name: String,
    pub decision: GovernanceDecision,
    pub status: String,
    pub risk_score: u32,
    pub reasons: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

// ── Stored Audit Event (with extra fields) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredAuditEvent {
    pub event_id: String,
    pub agent_id: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub framework: String,
    pub action_type: ActionType,
    pub tool_name: String,
    /// SHA-256 (hex) of the canonical action payload. Computed once in the
    /// pipeline and bound into the signed receipt's `input_hash`
    /// (PROOF-INPUTHASH-BIND-3), so the receipt commits to *what* the action
    /// did, not just which tool ran. Not persisted as an audit-store column;
    /// `#[serde(default)]` leaves it empty for events read back from the DB or
    /// deserialized from before this field existed.
    #[serde(default)]
    pub input_sha256: String,
    pub decision: GovernanceDecision,
    pub timestamp: String,
    pub reasons: Vec<String>,
    pub review_status: ReviewStatus,
    pub risk_score: u32,
    /// 1.5 cost-control: optional usage/cost ledger for this action.
    /// `None` (and elided) unless the host captured usage for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<iaga_sentinel_cost::UsageData>,
    /// Explicit `metadata.sessionId` for this action, when the caller supplied
    /// one. Used as the signed-receipt `run_id` so multiple actions in a logical
    /// session form one hash-chained run. `None` (and elided from serialization)
    /// when absent, in which case the receipt logger falls back to `event_id`
    /// (one receipt per run) and the serialized event stays byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

// ── Response Scanning ──

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResponseDecision {
    Allow,
    Review,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseScanRequest {
    pub request_id: String,
    pub agent_id: String,
    pub tool_name: String,
    pub response_payload: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResponseScanResult {
    pub request_id: String,
    pub decision: ResponseDecision,
    pub risk_score: u32,
    pub findings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SensitivePattern {
    pub name: String,
    pub description: String,
    pub category: String,
}

// ── Agent Behavioral Fingerprint (API response) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentFingerprintResponse {
    pub agent_id: String,
    pub total_requests: u64,
    pub tool_usage: HashMap<String, u64>,
    pub action_types: HashMap<String, u64>,
    pub avg_risk_score: f64,
    pub peak_risk_score: f64,
    pub hourly_pattern: [u64; 24],
    pub anomaly_score: f64,
    pub first_seen: String,
    pub last_seen: String,
    pub flags: Vec<String>,
}

// ── Rate Limiting ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitConfig {
    pub max_per_minute: u32,
    pub max_per_hour: u32,
    pub burst_limit: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_per_minute: 60,
            max_per_hour: 1000,
            burst_limit: 10,
        }
    }
}

// ── Config file ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelConfig {
    pub profiles: Vec<AgentProfile>,
    pub workspaces: Vec<WorkspacePolicy>,
    #[serde(default)]
    pub vault: Vec<String>,
}

// ── Audit Export & Analytics ──

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AuditExportFilter {
    pub tenant_id: Option<String>,
    pub agent_id: Option<String>,
    pub decision: Option<String>,
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditStats {
    pub total_events: u64,
    pub decisions: HashMap<String, u64>,
    pub top_agents: Vec<(String, u64)>,
    pub top_tools: Vec<(String, u64)>,
    pub avg_risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentAnalytics {
    pub agent_id: String,
    pub total_requests: u64,
    pub decisions: HashMap<String, u64>,
    pub avg_risk_score: f64,
    pub top_tools: Vec<(String, u64)>,
    pub last_activity: String,
    pub trust_score: f64,
}

// ── Cost Control (1.5) ──

/// Aggregate spend over a window. `gross = net + savings`: `net` is what was
/// actually paid, `savings` is what cache hits avoided.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CostSummary {
    pub gross_cost_usd: f64,
    pub net_cost_usd: f64,
    pub savings_usd: f64,
    pub total_tokens: u64,
    pub cache_hits: u64,
    pub total_actions: u64,
}

/// Spend grouped by a single key (agent, model, or tool).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostByKey {
    pub key: String,
    pub net_cost_usd: f64,
    pub savings_usd: f64,
    pub total_tokens: u64,
    pub actions: u64,
    pub cache_hits: u64,
}

/// Spend in one time bucket (hourly or daily) for trend charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CostBucket {
    pub bucket: String,
    pub net_cost_usd: f64,
    pub savings_usd: f64,
    pub total_tokens: u64,
    pub actions: u64,
}

/// Query parameters shared by the `/v1/cost/*` endpoints and the `iaga cost`
/// CLI. All optional; `bucket` is `"hour"` (default) or `"day"`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CostQuery {
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    pub bucket: Option<String>,
    pub limit: Option<u32>,
}

// ── Demo scenario ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoScenario {
    pub step: String,
    pub title: String,
    pub request: InspectRequest,
}

#[derive(Debug, Serialize)]
pub struct DemoResult {
    pub step: String,
    pub title: String,
    pub decision: GovernanceDecision,
    pub risk: u32,
}

#[cfg(test)]
mod layer_roles_tests {
    use super::*;

    /// `layerRoles` exists to stop a layer from appearing to do more than it
    /// does — the 2.0.1 defect class. A test that only checked the field was
    /// present would itself be that defect: it would pass whatever the table
    /// claimed. So this pins the table against the two properties that make a
    /// role a lie if violated.
    ///
    /// `veto` layers are checked elsewhere against the pipeline; here the point
    /// is the advisory ones, because "advisory" is the claim a reader most needs
    /// to trust. Every layer the case study calls advisory —
    /// `behavioralFingerprint`, `sandboxResult`, and `policyVerification`
    /// (computed and never read back) — must say so.
    #[test]
    fn the_advisory_layers_are_marked_advisory() {
        let roles = layer_roles();
        for layer in [
            "behavioralFingerprint",
            "sandboxResult",
            "policyVerification",
            "advisory",
        ] {
            assert_eq!(
                roles[layer]["role"], "advisory",
                "{layer} must be marked advisory; claiming otherwise overstates \
                 coverage, which is exactly the failure layerRoles exists to \
                 prevent"
            );
        }
    }

    /// The scoring layer must not be sold as a veto. Its block arm was removed
    /// because its signed ceiling sits below the threshold; calling it `veto`
    /// would re-introduce the claim the removal retracted.
    #[test]
    fn adaptive_risk_is_scoring_not_veto() {
        let roles = layer_roles();
        assert_eq!(roles["adaptiveRisk"]["role"], "scoring");
    }

    /// Every role value must be one of the three defined kinds. A typo like
    /// "vето" or "advsory" would otherwise render in the API as a silent
    /// downgrade nobody notices.
    #[test]
    fn every_role_is_one_of_the_three_kinds() {
        let roles = layer_roles();
        let obj = roles.as_object().expect("layer_roles is an object");
        for (layer, spec) in obj {
            let role = spec["role"].as_str().unwrap_or("<missing>");
            assert!(
                matches!(role, "veto" | "scoring" | "advisory"),
                "{layer} has role {role:?}, which is not one of veto/scoring/advisory"
            );
        }
    }
}
