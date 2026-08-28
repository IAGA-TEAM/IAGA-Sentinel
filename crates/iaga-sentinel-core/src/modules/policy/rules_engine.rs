//! Policy-as-Code v2 Rules Engine
//!
//! Provides conditional rules with match criteria, time windows,
//! payload inspection, and risk-score thresholds. Rules are evaluated
//! in priority order; the first matching rule wins.

use serde::{Deserialize, Serialize};

use crate::core::types::{ActionType, AgentRole, GovernanceDecision, InspectRequest};

use super::time_window::TimeWindow;

// ── Rule Types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRule {
    /// Unique identifier for this rule.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// Priority (lower = evaluated first). Default: 0.
    #[serde(default)]
    pub priority: i32,
    /// Criteria the request must match for this rule to apply.
    #[serde(default)]
    pub match_criteria: MatchCriteria,
    /// Additional conditions that must be true.
    #[serde(default)]
    pub conditions: ConditionSet,
    /// Decision to apply if the rule matches.
    pub decision: GovernanceDecision,
    /// Optional reason string attached to governance findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether this rule is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatchCriteria {
    /// Match on action type (e.g. "shell", "http"). Empty = match all.
    #[serde(default)]
    pub action_type: Vec<ActionType>,
    /// Match on tool name patterns. Empty = match all.
    #[serde(default)]
    pub tool_name: Vec<String>,
    /// Match on agent roles. Empty = match all.
    #[serde(default)]
    pub agent_role: Vec<AgentRole>,
    /// Match on specific agent IDs. Empty = match all.
    #[serde(default)]
    pub agent_id: Vec<String>,
    /// Match on frameworks. Empty = match all.
    #[serde(default)]
    pub framework: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConditionSet {
    /// Time window during which this rule is active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// Maximum ADAPTIVE score for this rule to apply (at or below → applies).
    ///
    /// The ADAPTIVE layer score, not the composite `risk.score` the API
    /// returns. They are different scales and they do not overlap where it
    /// matters: the adaptive score's arithmetic ceiling is 64 at default
    /// weights and its measured band is 9..48, while the composite spans 2..84.
    /// Named `*_risk_score` until 2.1.0, which read as "the number I can see in
    /// the response" and is what made the shipped `review-high-risk-shell` rule
    /// (`min 60`) unreachable and `soc2-shell-hours` (`max 40`, decision Allow)
    /// fire almost unconditionally.
    ///
    /// It is not fixable by rescaling: the composite depends on
    /// `minimum_decision`, which this rule match produces, so feeding it back
    /// here is a genuine cycle -- and the 64 ceiling holds only for the default
    /// weights, which `POST /v1/risk/feedback` can renormalise upward.
    ///
    /// `alias` is load-bearing: rules are persisted as opaque JSON
    /// (`sqlite.rs`/`postgres.rs` store `conditions` as a string), so without it
    /// a stored `maxRiskScore` would deserialize to `None` and the gate would
    /// silently vanish -- turning a bounded Allow into an unconditional one.
    #[serde(skip_serializing_if = "Option::is_none", alias = "maxRiskScore")]
    pub max_adaptive_score: Option<u32>,
    /// Minimum ADAPTIVE score for this rule to apply. See
    /// [`ConditionSet::max_adaptive_score`] for the scale and the alias.
    #[serde(skip_serializing_if = "Option::is_none", alias = "minRiskScore")]
    pub min_adaptive_score: Option<u32>,
    /// Payload must contain ALL of these strings.
    #[serde(default)]
    pub payload_contains: Vec<String>,
    /// Payload must NOT contain any of these strings.
    #[serde(default)]
    pub payload_excludes: Vec<String>,
}

// ── Rule Evaluation ──

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub decision: GovernanceDecision,
    pub reason: String,
}

/// Evaluate rules against an inspect request and optional context.
/// Rules are sorted by priority (ascending), first match wins.
pub fn evaluate_rules(
    rules: &[PolicyRule],
    input: &InspectRequest,
    agent_role: AgentRole,
    current_risk_score: Option<u32>,
    decision_time: chrono::DateTime<chrono::Utc>,
) -> Option<RuleMatch> {
    let mut sorted: Vec<&PolicyRule> = rules.iter().filter(|r| r.enabled).collect();
    sorted.sort_by_key(|r| r.priority);

    let payload_str = serde_json::to_string(&input.action.payload).unwrap_or_default();

    for rule in sorted {
        if matches_criteria(&rule.match_criteria, input, agent_role)
            && check_conditions(
                &rule.conditions,
                &payload_str,
                current_risk_score,
                decision_time,
            )
        {
            let reason = rule.reason.clone().unwrap_or_else(|| {
                format!("policy rule '{}' matched → {:?}", rule.name, rule.decision)
            });
            return Some(RuleMatch {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                decision: rule.decision,
                reason,
            });
        }
    }

    None
}

fn matches_criteria(
    criteria: &MatchCriteria,
    input: &InspectRequest,
    agent_role: AgentRole,
) -> bool {
    // Action type
    if !criteria.action_type.is_empty() && !criteria.action_type.contains(&input.action.action_type)
    {
        return false;
    }

    // Tool name
    if !criteria.tool_name.is_empty() {
        let matches_tool = criteria.tool_name.iter().any(|pattern| {
            if pattern.contains('*') {
                // Simple glob: "filesystem.*" matches "filesystem.read"
                let prefix = pattern.trim_end_matches('*');
                input.action.tool_name.starts_with(prefix)
            } else {
                &input.action.tool_name == pattern
            }
        });
        if !matches_tool {
            return false;
        }
    }

    // Agent role
    if !criteria.agent_role.is_empty() && !criteria.agent_role.contains(&agent_role) {
        return false;
    }

    // Agent ID
    if !criteria.agent_id.is_empty() && !criteria.agent_id.contains(&input.agent_id) {
        return false;
    }

    // Framework
    if !criteria.framework.is_empty() && !criteria.framework.contains(&input.framework) {
        return false;
    }

    true
}

fn check_conditions(
    conditions: &ConditionSet,
    payload_str: &str,
    current_risk: Option<u32>,
    decision_time: chrono::DateTime<chrono::Utc>,
) -> bool {
    // Time window. DET-DICTUM-3: evaluate against the pipeline's single
    // `decision_time`, not a fresh wall-clock read, so a matched (signed) rule
    // replays identically.
    if let Some(ref tw) = conditions.time_window {
        if !tw.is_active_at(decision_time) {
            return false;
        }
    }

    // Risk score bounds
    if let Some(max) = conditions.max_adaptive_score {
        if let Some(risk) = current_risk {
            if risk > max {
                return false;
            }
        }
    }
    if let Some(min) = conditions.min_adaptive_score {
        if let Some(risk) = current_risk {
            if risk < min {
                return false;
            }
        }
    }

    // Payload contains
    let payload_lower = payload_str.to_lowercase();
    for required in &conditions.payload_contains {
        if !payload_lower.contains(&required.to_lowercase()) {
            return false;
        }
    }

    // Payload excludes
    for excluded in &conditions.payload_excludes {
        if payload_lower.contains(&excluded.to_lowercase()) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::ActionDetail;
    use std::collections::HashMap;

    fn make_request(action_type: ActionType, tool: &str) -> InspectRequest {
        InspectRequest {
            agent_id: "test-agent".into(),
            tenant_id: None,
            workspace_id: Some("test-ws".into()),
            framework: "anthropic".into(),
            protocol: None,
            action: ActionDetail {
                action_type,
                tool_name: tool.into(),
                payload: HashMap::new(),
            },
            requested_secrets: None,
            metadata: None,
            usage: None,
        }
    }

    /// Fixed decision time for rule tests (none exercise time windows).
    fn test_time() -> chrono::DateTime<chrono::Utc> {
        use chrono::TimeZone;
        chrono::Utc.with_ymd_and_hms(2026, 4, 14, 12, 0, 0).unwrap()
    }

    #[test]
    fn test_simple_block_rule() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "block-email".into(),
            priority: 0,
            match_criteria: MatchCriteria {
                action_type: vec![ActionType::Email],
                ..Default::default()
            },
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Block,
            reason: Some("Email disabled".into()),
            enabled: true,
        }];

        let req = make_request(ActionType::Email, "smtp.send");
        let result = evaluate_rules(&rules, &req, AgentRole::Builder, None, test_time());
        assert!(result.is_some());
        assert_eq!(result.unwrap().decision, GovernanceDecision::Block);
    }

    #[test]
    fn test_no_match_returns_none() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "block-email".into(),
            priority: 0,
            match_criteria: MatchCriteria {
                action_type: vec![ActionType::Email],
                ..Default::default()
            },
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Block,
            reason: None,
            enabled: true,
        }];

        let req = make_request(ActionType::FileRead, "filesystem.read");
        let result = evaluate_rules(&rules, &req, AgentRole::Builder, None, test_time());
        assert!(result.is_none());
    }

    #[test]
    fn test_risk_score_condition() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "allow-low-risk".into(),
            priority: 0,
            match_criteria: MatchCriteria::default(),
            conditions: ConditionSet {
                max_adaptive_score: Some(30),
                ..Default::default()
            },
            decision: GovernanceDecision::Allow,
            reason: None,
            enabled: true,
        }];

        let req = make_request(ActionType::Shell, "terminal.exec");
        // Risk 20 → should match (under 30)
        assert!(evaluate_rules(&rules, &req, AgentRole::Builder, Some(20), test_time()).is_some());
        // Risk 50 → should NOT match (over 30)
        assert!(evaluate_rules(&rules, &req, AgentRole::Builder, Some(50), test_time()).is_none());
    }

    #[test]
    fn test_priority_ordering() {
        let rules = vec![
            PolicyRule {
                id: "r1".into(),
                name: "low-priority-allow".into(),
                priority: 10,
                match_criteria: MatchCriteria::default(),
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Allow,
                reason: None,
                enabled: true,
            },
            PolicyRule {
                id: "r2".into(),
                name: "high-priority-block".into(),
                priority: 1,
                match_criteria: MatchCriteria::default(),
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Block,
                reason: None,
                enabled: true,
            },
        ];

        let req = make_request(ActionType::Shell, "terminal.exec");
        let result = evaluate_rules(&rules, &req, AgentRole::Builder, None, test_time());
        assert_eq!(result.unwrap().decision, GovernanceDecision::Block);
    }

    #[test]
    fn test_disabled_rule_skipped() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "disabled".into(),
            priority: 0,
            match_criteria: MatchCriteria::default(),
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Block,
            reason: None,
            enabled: false,
        }];

        let req = make_request(ActionType::Shell, "terminal.exec");
        assert!(evaluate_rules(&rules, &req, AgentRole::Builder, None, test_time()).is_none());
    }

    #[test]
    fn test_tool_glob_pattern() {
        let rules = vec![PolicyRule {
            id: "r1".into(),
            name: "block-fs-writes".into(),
            priority: 0,
            match_criteria: MatchCriteria {
                tool_name: vec!["filesystem.*".into()],
                ..Default::default()
            },
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Review,
            reason: None,
            enabled: true,
        }];

        let req = make_request(ActionType::FileWrite, "filesystem.write");
        assert!(evaluate_rules(&rules, &req, AgentRole::Builder, None, test_time()).is_some());

        let req2 = make_request(ActionType::Shell, "terminal.exec");
        assert!(evaluate_rules(&rules, &req2, AgentRole::Builder, None, test_time()).is_none());
    }

    /// Rules are persisted as an opaque JSON string, so the 2.1.0 rename from
    /// `minRiskScore`/`maxRiskScore` had to stay wire-compatible. Without the
    /// serde aliases a stored rule's bound would deserialize to `None` and the
    /// gate would silently disappear -- and for a `maxRiskScore`-bounded Allow
    /// that is fail-OPEN: a bounded allowance becomes an unconditional one.
    #[test]
    fn the_legacy_risk_score_condition_keys_still_deserialize() {
        let stored = r#"{"minRiskScore":20,"maxRiskScore":45}"#;
        let conditions: ConditionSet =
            serde_json::from_str(stored).expect("a stored rule must still parse");

        assert_eq!(
            conditions.min_adaptive_score,
            Some(20),
            "minRiskScore was dropped; the lower bound silently vanished"
        );
        assert_eq!(
            conditions.max_adaptive_score,
            Some(45),
            "maxRiskScore was dropped; a bounded Allow became unconditional"
        );
    }

    /// The new names are what gets WRITTEN back.
    #[test]
    fn conditions_serialize_under_the_adaptive_names() {
        let conditions = ConditionSet {
            min_adaptive_score: Some(35),
            ..Default::default()
        };
        let json = serde_json::to_string(&conditions).expect("serialize");
        assert!(
            json.contains("minAdaptiveScore"),
            "expected the renamed key, got {json}"
        );
    }
}
