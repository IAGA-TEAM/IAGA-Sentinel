//! Built-in policy templates for common deployment scenarios.
//!
//! Templates provide pre-configured workspace policies and rules
//! that can be applied as starting points or inherited via `extends`.

use serde::{Deserialize, Serialize};

use crate::core::types::{
    ActionType, GovernanceDecision, ProtocolKind, ToolPolicy, WorkspacePolicy,
};

use crate::modules::risk::adaptive_scorer;

use super::rules_engine::{ConditionSet, MatchCriteria, PolicyRule};
use super::time_window::TimeWindow;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyTemplate {
    pub template_id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub workspace: WorkspacePolicy,
    pub rules: Vec<PolicyRule>,
    pub builtin: bool,
}

/// Return all built-in policy templates.
pub fn builtin_templates() -> Vec<PolicyTemplate> {
    vec![
        strict_production(),
        permissive_dev(),
        compliance_hipaa(),
        compliance_soc2(),
        ml_pipeline(),
    ]
}

/// Get a built-in template by ID.
pub fn get_builtin_template(template_id: &str) -> Option<PolicyTemplate> {
    builtin_templates()
        .into_iter()
        .find(|t| t.template_id == template_id)
}

// ── Template Definitions ──

fn strict_production() -> PolicyTemplate {
    PolicyTemplate {
        template_id: "strict-production".into(),
        name: "Strict Production".into(),
        description: "Block by default, whitelist tools, low thresholds. Suitable for production deployments where security is paramount.".into(),
        category: "production".into(),
        builtin: true,
        workspace: WorkspacePolicy {
            workspace_id: "strict-production".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::Mcp, ProtocolKind::A2a],
            tools: vec![
                ToolPolicy {
                    tool_name: "filesystem.read".into(),
                    allowed_action_types: vec![ActionType::FileRead],
                    max_decision: GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                },
            ],
            allowed_domains: vec![],
            threshold_block: 50,
            threshold_review: 25,
        },
        rules: vec![
            PolicyRule {
                id: "sp-block-shell".into(),
                name: "block-all-shell".into(),
                priority: 0,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Shell],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Block,
                reason: Some("Shell execution disabled in production".into()),
                enabled: true,
            },
            PolicyRule {
                id: "sp-block-email".into(),
                name: "block-all-email".into(),
                priority: 0,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Email],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Block,
                reason: Some("Email sending disabled in production".into()),
                enabled: true,
            },
            PolicyRule {
                id: "sp-review-http".into(),
                name: "review-all-http".into(),
                priority: 5,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Http],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Review,
                reason: Some("All HTTP egress requires review in production".into()),
                enabled: true,
            },
        ],
    }
}

fn permissive_dev() -> PolicyTemplate {
    PolicyTemplate {
        template_id: "permissive-dev".into(),
        name: "Permissive Development".into(),
        description: "Allow most operations, review only risky ones. High thresholds for development environments.".into(),
        category: "development".into(),
        builtin: true,
        workspace: WorkspacePolicy {
            workspace_id: "permissive-dev".into(),
            tenant_id: None,
            allowed_protocols: vec![
                ProtocolKind::Mcp,
                ProtocolKind::Acp,
                ProtocolKind::A2a,
                ProtocolKind::HttpFunction,
            ],
            tools: vec![
                ToolPolicy {
                    tool_name: "*".into(),
                    allowed_action_types: vec![
                        ActionType::Shell,
                        ActionType::FileRead,
                        ActionType::FileWrite,
                        ActionType::Http,
                        ActionType::DbQuery,
                        ActionType::Custom,
                    ],
                    max_decision: GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                },
            ],
            allowed_domains: vec![],
            threshold_block: 85,
            threshold_review: 60,
        },
        rules: vec![
            PolicyRule {
                id: "pd-review-high-risk".into(),
                name: "review-high-risk-shell".into(),
                priority: 0,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Shell],
                    ..Default::default()
                },
                conditions: ConditionSet {
                    // The ADAPTIVE score, whose measured band is 9..48 (ceiling
                    // 64 at default weights) -- not the composite 0..100 the API
                    // reports. At 60 this rule could not fire: 60 is above the
                    // whole measured band, and the [60,64] tail requires
                    // `context_risk == 90`, which only happens on `taint.blocked`,
                    // by which point the pipeline has already forced Block. So it
                    // was never the reason for any verdict.
                    min_adaptive_score: Some(adaptive_scorer::ADAPTIVE_THRESHOLD_REVIEW),
                    ..Default::default()
                },
                decision: GovernanceDecision::Review,
                reason: Some("High-risk shell commands need review even in dev".into()),
                enabled: true,
            },
        ],
    }
}

fn compliance_hipaa() -> PolicyTemplate {
    PolicyTemplate {
        template_id: "compliance-hipaa".into(),
        name: "HIPAA-aligned starting policy".into(),
        description:
            "Starting policy for healthcare workflows: blocks email egress, reviews network \
             and database access, blocks shell execution. A starting point only; does not \
             by itself satisfy HIPAA obligations."
                .into(),
        category: "compliance".into(),
        builtin: true,
        workspace: WorkspacePolicy {
            workspace_id: "compliance-hipaa".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::Mcp],
            tools: vec![
                ToolPolicy {
                    tool_name: "filesystem.read".into(),
                    allowed_action_types: vec![ActionType::FileRead],
                    max_decision: GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                },
                ToolPolicy {
                    tool_name: "db.query".into(),
                    allowed_action_types: vec![ActionType::DbQuery],
                    max_decision: GovernanceDecision::Review,
                    requires_human_review: true,
                    ..Default::default()
                },
            ],
            allowed_domains: vec![],
            threshold_block: 40,
            threshold_review: 20,
        },
        rules: vec![
            PolicyRule {
                id: "hipaa-block-email".into(),
                name: "block-email-egress".into(),
                priority: 0,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Email],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Block,
                reason: Some("Email egress blocked under HIPAA policy".into()),
                enabled: true,
            },
            PolicyRule {
                id: "hipaa-review-http".into(),
                name: "review-all-http".into(),
                priority: 0,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Http],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Review,
                reason: Some("All network egress requires review under HIPAA".into()),
                enabled: true,
            },
            PolicyRule {
                id: "hipaa-block-shell".into(),
                name: "block-shell".into(),
                priority: 0,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Shell],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Block,
                reason: Some("Shell execution not permitted under HIPAA".into()),
                enabled: true,
            },
        ],
    }
}

fn compliance_soc2() -> PolicyTemplate {
    PolicyTemplate {
        template_id: "compliance-soc2".into(),
        name: "SOC 2-aligned starting policy".into(),
        description: "Starting policy aligned with common SOC 2 change-management controls: \
            reviews all writes, restricts shell execution to business hours. A starting point \
            only; not a SOC 2 attestation."
            .into(),
        category: "compliance".into(),
        builtin: true,
        workspace: WorkspacePolicy {
            workspace_id: "compliance-soc2".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::Mcp, ProtocolKind::A2a],
            tools: vec![
                ToolPolicy {
                    tool_name: "filesystem.read".into(),
                    allowed_action_types: vec![ActionType::FileRead],
                    max_decision: GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                },
                ToolPolicy {
                    tool_name: "filesystem.write".into(),
                    allowed_action_types: vec![ActionType::FileWrite],
                    max_decision: GovernanceDecision::Review,
                    requires_human_review: true,
                    ..Default::default()
                },
            ],
            allowed_domains: vec![],
            threshold_block: 55,
            threshold_review: 30,
        },
        rules: vec![
            PolicyRule {
                id: "soc2-review-writes".into(),
                name: "review-all-writes".into(),
                priority: 0,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::FileWrite, ActionType::DbQuery],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Review,
                reason: Some("All write operations require review under SOC 2".into()),
                enabled: true,
            },
            PolicyRule {
                id: "soc2-shell-hours".into(),
                name: "shell-business-hours-only".into(),
                priority: 5,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Shell],
                    ..Default::default()
                },
                conditions: ConditionSet {
                    time_window: Some(TimeWindow {
                        start: "09:00".into(),
                        end: "18:00".into(),
                        timezone: "UTC".into(),
                        days: vec![
                            "monday".into(),
                            "tuesday".into(),
                            "wednesday".into(),
                            "thursday".into(),
                            "friday".into(),
                        ],
                    }),
                    // Also the ADAPTIVE score. This one moved verdicts rather
                    // than being merely dead: the adaptive mean is 23.6, so a cap
                    // of 40 was satisfied by nearly every request, and an Allow
                    // rule that always matches downgrades a Review to Allow
                    // during business hours. Capping at the adaptive REVIEW
                    // threshold makes "with low risk" mean what the reason string
                    // says, and it can only ever be stricter than the old 40.
                    max_adaptive_score: Some(adaptive_scorer::ADAPTIVE_THRESHOLD_REVIEW),
                    ..Default::default()
                },
                decision: GovernanceDecision::Allow,
                reason: Some("Shell allowed during business hours with low risk".into()),
                enabled: true,
            },
            PolicyRule {
                id: "soc2-shell-block-off-hours".into(),
                name: "block-shell-off-hours".into(),
                priority: 10,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Shell],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Block,
                reason: Some("Shell execution blocked outside business hours".into()),
                enabled: true,
            },
        ],
    }
}

fn ml_pipeline() -> PolicyTemplate {
    PolicyTemplate {
        template_id: "ml-pipeline".into(),
        name: "ML Pipeline".into(),
        description: "ML workflows: allow data read/query ops, block shell, review HTTP egress."
            .into(),
        category: "ml".into(),
        builtin: true,
        workspace: WorkspacePolicy {
            workspace_id: "ml-pipeline".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::Mcp, ProtocolKind::HttpFunction],
            tools: vec![
                ToolPolicy {
                    tool_name: "data.read".into(),
                    allowed_action_types: vec![ActionType::FileRead, ActionType::DbQuery],
                    max_decision: GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                },
                ToolPolicy {
                    tool_name: "model.inference".into(),
                    allowed_action_types: vec![ActionType::Http],
                    max_decision: GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                },
            ],
            allowed_domains: vec![],
            threshold_block: 65,
            threshold_review: 35,
        },
        rules: vec![
            PolicyRule {
                id: "ml-block-shell".into(),
                name: "block-shell".into(),
                priority: 0,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Shell],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Block,
                reason: Some("Shell execution not permitted in ML pipelines".into()),
                enabled: true,
            },
            PolicyRule {
                id: "ml-review-http".into(),
                name: "review-http-egress".into(),
                priority: 5,
                match_criteria: MatchCriteria {
                    action_type: vec![ActionType::Http],
                    ..Default::default()
                },
                conditions: ConditionSet::default(),
                decision: GovernanceDecision::Review,
                reason: Some("HTTP egress requires review in ML pipelines".into()),
                enabled: true,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_templates_count() {
        let templates = builtin_templates();
        assert_eq!(templates.len(), 5);
    }

    #[test]
    fn test_get_builtin_template() {
        assert!(get_builtin_template("strict-production").is_some());
        assert!(get_builtin_template("permissive-dev").is_some());
        assert!(get_builtin_template("compliance-hipaa").is_some());
        assert!(get_builtin_template("compliance-soc2").is_some());
        assert!(get_builtin_template("ml-pipeline").is_some());
        assert!(get_builtin_template("nonexistent").is_none());
    }

    #[test]
    fn test_strict_production_blocks_shell() {
        let tpl = get_builtin_template("strict-production").unwrap();
        let shell_rule = tpl
            .rules
            .iter()
            .find(|r| r.match_criteria.action_type.contains(&ActionType::Shell));
        assert!(shell_rule.is_some());
        assert_eq!(shell_rule.unwrap().decision, GovernanceDecision::Block);
    }

    #[test]
    fn test_permissive_dev_high_thresholds() {
        let tpl = get_builtin_template("permissive-dev").unwrap();
        assert!(tpl.workspace.threshold_block >= 80);
        assert!(tpl.workspace.threshold_review >= 50);
    }

    #[test]
    fn test_all_templates_are_builtin() {
        for tpl in builtin_templates() {
            assert!(
                tpl.builtin,
                "template {} should be builtin",
                tpl.template_id
            );
        }
    }
}
