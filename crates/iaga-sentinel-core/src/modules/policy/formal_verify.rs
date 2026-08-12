//! LAYER 6, Formal Policy Verification
//!
//! SAT-solver-inspired consistency, completeness, and satisfiability checks
//! for workspace policies. Catches contradictions, unreachable states, and
//! privilege escalation paths BEFORE they hit production.

use std::collections::{HashMap, HashSet};

use serde::Serialize;

use crate::core::types::{ActionType, GovernanceDecision, ToolPolicy, WorkspacePolicy};

// ── Types ──

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationResult {
    pub workspace_id: String,
    pub consistent: bool,
    pub complete: bool,
    pub satisfiable: bool,
    pub issues: Vec<PolicyIssue>,
    pub coverage: CoverageReport,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyIssue {
    pub severity: String,
    pub category: String,
    pub description: String,
    pub affected_tools: Vec<String>,
    pub suggestion: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageReport {
    pub total_action_types: usize,
    pub covered_action_types: usize,
    pub coverage_pct: f64,
    pub uncovered: Vec<String>,
    pub tools_with_no_actions: Vec<String>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── All Action Types ──

fn all_action_types() -> Vec<ActionType> {
    vec![
        ActionType::Shell,
        ActionType::FileRead,
        ActionType::FileWrite,
        ActionType::Http,
        ActionType::DbQuery,
        ActionType::Email,
        ActionType::Custom,
    ]
}

fn action_type_name(at: &ActionType) -> &'static str {
    match at {
        ActionType::Shell => "shell",
        ActionType::FileRead => "file_read",
        ActionType::FileWrite => "file_write",
        ActionType::Http => "http",
        ActionType::DbQuery => "db_query",
        ActionType::Email => "email",
        ActionType::Custom => "custom",
    }
}

// ── Consistency Check ──
// Detects contradictions within the policy:
// - Tool allows action type X but workspace blocks protocol needed for X
// - Tool marked as "allow" but also "requires_human_review"
// - Duplicate tool definitions with conflicting settings

fn check_consistency(policy: &WorkspacePolicy) -> Vec<PolicyIssue> {
    let mut issues = Vec::new();

    // Check for duplicate tool names with conflicting settings
    let mut tool_map: HashMap<&str, Vec<&ToolPolicy>> = HashMap::new();
    for tool in &policy.tools {
        tool_map.entry(&tool.tool_name).or_default().push(tool);
    }

    for (name, entries) in &tool_map {
        if entries.len() > 1 {
            // Check for conflicting max_decision
            let decisions: HashSet<String> = entries
                .iter()
                .map(|t| format!("{:?}", t.max_decision))
                .collect();
            if decisions.len() > 1 {
                issues.push(PolicyIssue {
                    severity: "critical".into(),
                    category: "contradiction".into(),
                    description: format!(
                        "Tool '{}' has {} duplicate entries with conflicting decisions: {:?}",
                        name, entries.len(), decisions
                    ),
                    affected_tools: vec![name.to_string()],
                    suggestion: "Remove duplicate tool entries and keep one authoritative definition".into(),
                });
            }
        }
    }

    // Check for tools that require review but max_decision is Allow
    for tool in &policy.tools {
        if tool.requires_human_review && tool.max_decision == GovernanceDecision::Allow {
            issues.push(PolicyIssue {
                severity: "high".into(),
                category: "contradiction".into(),
                description: format!(
                    "Tool '{}' requires human review but max_decision is Allow, review will never trigger",
                    tool.tool_name
                ),
                affected_tools: vec![tool.tool_name.clone()],
                suggestion: "Set max_decision to Review if human review is required".into(),
            });
        }
    }

    // Check for tools with empty action types
    for tool in &policy.tools {
        if tool.allowed_action_types.is_empty() {
            issues.push(PolicyIssue {
                severity: "high".into(),
                category: "dead_rule".into(),
                description: format!(
                    "Tool '{}' has no allowed action types, all requests will be blocked",
                    tool.tool_name
                ),
                affected_tools: vec![tool.tool_name.clone()],
                suggestion: "Add at least one allowed action type or remove the tool entry".into(),
            });
        }
    }

    // Check for tools with Block max_decision but allowed action types
    for tool in &policy.tools {
        if tool.max_decision == GovernanceDecision::Block && !tool.allowed_action_types.is_empty() {
            issues.push(PolicyIssue {
                severity: "medium".into(),
                category: "contradiction".into(),
                description: format!(
                    "Tool '{}' has max_decision=Block but lists allowed action types, action types are meaningless",
                    tool.tool_name
                ),
                affected_tools: vec![tool.tool_name.clone()],
                suggestion: "Either remove allowed_action_types or change max_decision".into(),
            });
        }
    }

    issues
}

// ── Completeness Check ──
// Ensures all action types are covered by at least one tool rule.

fn check_completeness(policy: &WorkspacePolicy) -> (Vec<PolicyIssue>, CoverageReport) {
    let mut issues = Vec::new();
    let all_types = all_action_types();
    let mut covered: HashSet<String> = HashSet::new();
    let mut tools_with_no_actions = Vec::new();

    for tool in &policy.tools {
        if tool.allowed_action_types.is_empty() {
            tools_with_no_actions.push(tool.tool_name.clone());
        }
        for at in &tool.allowed_action_types {
            covered.insert(action_type_name(at).to_string());
        }
    }

    let uncovered: Vec<String> = all_types
        .iter()
        .map(|at| action_type_name(at).to_string())
        .filter(|name| !covered.contains(name))
        .collect();

    if !uncovered.is_empty() {
        issues.push(PolicyIssue {
            severity: "medium".into(),
            category: "incomplete_coverage".into(),
            description: format!(
                "Action types not covered by any tool: [{}]",
                uncovered.join(", ")
            ),
            affected_tools: Vec::new(),
            suggestion: "Add tool rules covering these action types or confirm they should be implicitly blocked".into(),
        });
    }

    let coverage_pct = if all_types.is_empty() {
        100.0
    } else {
        (covered.len() as f64 / all_types.len() as f64) * 100.0
    };

    let report = CoverageReport {
        total_action_types: all_types.len(),
        covered_action_types: covered.len(),
        coverage_pct,
        uncovered,
        tools_with_no_actions,
    };

    (issues, report)
}

// ── Satisfiability Check ──
// Detects impossible states:
// - No allowed protocols means nothing can ever run
// - No allowed domains means all HTTP blocked
// - Circular dependencies

fn check_satisfiability(policy: &WorkspacePolicy) -> Vec<PolicyIssue> {
    let mut issues = Vec::new();

    // No protocols allowed
    if policy.allowed_protocols.is_empty() {
        issues.push(PolicyIssue {
            severity: "critical".into(),
            category: "unsatisfiable".into(),
            description: "No protocols are allowed, all requests will be blocked".into(),
            affected_tools: Vec::new(),
            suggestion: "Add at least one allowed protocol (e.g., Mcp, Acp)".into(),
        });
    }

    // No tools defined
    if policy.tools.is_empty() {
        issues.push(PolicyIssue {
            severity: "critical".into(),
            category: "unsatisfiable".into(),
            description: "No tools are defined, all tool calls will be blocked".into(),
            affected_tools: Vec::new(),
            suggestion: "Define tool policies for expected tools".into(),
        });
    }

    // All tools are blocked
    let all_blocked = policy
        .tools
        .iter()
        .all(|t| t.max_decision == GovernanceDecision::Block);
    if !policy.tools.is_empty() && all_blocked {
        issues.push(PolicyIssue {
            severity: "critical".into(),
            category: "unsatisfiable".into(),
            description: "All tools have max_decision=Block, nothing can execute".into(),
            affected_tools: policy.tools.iter().map(|t| t.tool_name.clone()).collect(),
            suggestion: "Set max_decision to Allow or Review for at least one tool".into(),
        });
    }

    // Tool names whose HTTP destination is baked into a provider client rather
    // than supplied in the payload. Suggesting `destinationFields` for these
    // would turn a fail-closed extraction on a payload that legitimately has no
    // URL — the shape that broke the OpenAI adapter in 1.9.2 and had to be
    // reverted.
    fn looks_like_provider_sdk(tool_name: &str) -> bool {
        const PROVIDER_PREFIXES: [&str; 7] = [
            "openai.",
            "anthropic.",
            "azure.",
            "bedrock.",
            "vertex.",
            "cohere.",
            "mistral.",
        ];
        let lower = tool_name.to_ascii_lowercase();
        PROVIDER_PREFIXES.iter().any(|p| lower.starts_with(p))
            || lower.contains("chat.completions")
            || lower.contains("model.inference")
    }

    // HTTP tools without allowed domains
    let has_http_tools = policy
        .tools
        .iter()
        .any(|t| t.allowed_action_types.contains(&ActionType::Http));
    if has_http_tools && policy.allowed_domains.is_empty() {
        issues.push(PolicyIssue {
            severity: "high".into(),
            category: "unsatisfiable".into(),
            description:
                "Tools allow HTTP actions but no domains are whitelisted, all HTTP will be blocked"
                    .into(),
            affected_tools: policy
                .tools
                .iter()
                .filter(|t| t.allowed_action_types.contains(&ActionType::Http))
                .map(|t| t.tool_name.clone())
                .collect(),
            suggestion: "Add allowed domains or remove HTTP from tool action types".into(),
        });
    }

    // HTTP tools that never say where their destination lives.
    //
    // Without `destination_fields` the domain allowlist is applied by a fixed
    // four-name probe (`destination`/`url`/`endpoint`/`href`). A caller naming
    // its target anything else — `target`, `uri`, `callback`, `webhook` — is
    // invisible to it, and finding nothing SKIPS the allowlist rather than
    // failing closed. That is how a POST to an unlisted host scored 2 and was
    // allowed in the live suite. A declaring tool is host-checked on any of its
    // declared names and refused when the payload exposes none.
    //
    // Not raised for tools whose destination is not caller-supplied: an LLM SDK
    // call carries its endpoint in the client, and declaring there would refuse
    // every legitimate call. The heuristic is deliberately crude — it only asks
    // whether the tool name looks like a provider SDK path — because the cost of
    // a false "declare this" suggestion is a broken integration.
    let undeclared_egress: Vec<&ToolPolicy> = policy
        .tools
        .iter()
        .filter(|t| {
            t.allowed_action_types.contains(&ActionType::Http)
                && t.destination_fields.is_empty()
                && t.tool_name != "*"
                && !looks_like_provider_sdk(&t.tool_name)
        })
        .collect();
    if !undeclared_egress.is_empty() {
        issues.push(PolicyIssue {
            severity: "medium".into(),
            category: "weak-enforcement".into(),
            description:
                "HTTP tools do not declare destinationFields, so the domain allowlist is applied \
                 only to the legacy field names destination/url/endpoint/href and is skipped \
                 entirely for a payload that names its target anything else"
                    .into(),
            affected_tools: undeclared_egress
                .iter()
                .map(|t| t.tool_name.clone())
                .collect(),
            suggestion: "Add destinationFields (e.g. [destination, url, uri, endpoint, href, \
                         target]) to each tool whose destination is caller-supplied"
                .into(),
        });
    }

    // Privilege escalation check: tools that can shell AND http with Allow
    let dangerous_combos: Vec<&ToolPolicy> = policy
        .tools
        .iter()
        .filter(|t| {
            t.max_decision == GovernanceDecision::Allow
                && t.allowed_action_types.contains(&ActionType::Shell)
                && (t.allowed_action_types.contains(&ActionType::Http)
                    || t.allowed_action_types.contains(&ActionType::Email))
        })
        .collect();

    for tool in dangerous_combos {
        issues.push(PolicyIssue {
            severity: "high".into(),
            category: "privilege_escalation".into(),
            description: format!(
                "Tool '{}' can execute shell AND network actions with Allow, potential exfiltration path",
                tool.tool_name
            ),
            affected_tools: vec![tool.tool_name.clone()],
            suggestion: "Separate shell and network capabilities into different tools, or require human review".into(),
        });
    }

    issues
}

// ── Main Verification ──

pub fn verify_policy(policy: &WorkspacePolicy) -> VerificationResult {
    let consistency_issues = check_consistency(policy);
    let (completeness_issues, coverage) = check_completeness(policy);
    let satisfiability_issues = check_satisfiability(policy);

    let mut all_issues = Vec::new();
    all_issues.extend(consistency_issues);
    all_issues.extend(completeness_issues);
    all_issues.extend(satisfiability_issues);

    let consistent = !all_issues.iter().any(|i| i.category == "contradiction");
    let complete = coverage.coverage_pct >= 100.0;
    let satisfiable = !all_issues.iter().any(|i| i.category == "unsatisfiable");

    VerificationResult {
        workspace_id: policy.workspace_id.clone(),
        consistent,
        complete,
        satisfiable,
        issues: all_issues,
        coverage,
        timestamp: now_ms(),
    }
}
