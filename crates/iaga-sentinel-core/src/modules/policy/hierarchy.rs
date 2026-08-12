//! Policy hierarchy, template inheritance via `extends`.
//!
//! A workspace policy can `extends: "base-secure"` to inherit tools,
//! protocols, rules, and thresholds from a base template. The child
//! policy's values override the parent where specified.

use crate::core::types::WorkspacePolicy;

use super::rules_engine::PolicyRule;
use super::templates::{get_builtin_template, PolicyTemplate};

/// Result of resolving a policy hierarchy.
#[derive(Debug, Clone)]
pub struct ResolvedPolicy {
    pub workspace: WorkspacePolicy,
    pub rules: Vec<PolicyRule>,
    pub chain: Vec<String>,
}

/// Resolve a workspace policy that may extend a template.
///
/// If `extends` names a known template, the workspace inherits the
/// template's tools, protocols, and rules. The child's explicit values
/// override the parent.
pub fn resolve_hierarchy(
    workspace: &WorkspacePolicy,
    rules: &[PolicyRule],
    extends: Option<&str>,
) -> ResolvedPolicy {
    match extends.and_then(get_builtin_template) {
        Some(parent) => merge_with_parent(workspace, rules, &parent),
        None => ResolvedPolicy {
            workspace: workspace.clone(),
            rules: rules.to_vec(),
            chain: vec![workspace.workspace_id.clone()],
        },
    }
}

fn merge_with_parent(
    child: &WorkspacePolicy,
    child_rules: &[PolicyRule],
    parent: &PolicyTemplate,
) -> ResolvedPolicy {
    let mut merged_workspace = parent.workspace.clone();

    // Child overrides
    merged_workspace.workspace_id = child.workspace_id.clone();
    merged_workspace.tenant_id = child.tenant_id.clone();

    // Merge tools: child tools override parent tools with the same name
    for child_tool in &child.tools {
        if let Some(pos) = merged_workspace
            .tools
            .iter()
            .position(|t| t.tool_name == child_tool.tool_name)
        {
            merged_workspace.tools[pos] = child_tool.clone();
        } else {
            merged_workspace.tools.push(child_tool.clone());
        }
    }

    // Child protocols extend parent (union)
    for proto in &child.allowed_protocols {
        if !merged_workspace.allowed_protocols.contains(proto) {
            merged_workspace.allowed_protocols.push(*proto);
        }
    }

    // Child domains extend parent (union)
    for domain in &child.allowed_domains {
        if !merged_workspace.allowed_domains.contains(domain) {
            merged_workspace.allowed_domains.push(domain.clone());
        }
    }

    // Child thresholds override parent (if non-default, use child's)
    if child.threshold_block != 70 {
        merged_workspace.threshold_block = child.threshold_block;
    }
    if child.threshold_review != 35 {
        merged_workspace.threshold_review = child.threshold_review;
    }

    // Rules: parent rules first, then child rules (child has higher priority by order)
    let mut merged_rules = parent.rules.clone();
    // Remove parent rules that the child overrides (same id)
    let child_ids: Vec<&str> = child_rules.iter().map(|r| r.id.as_str()).collect();
    merged_rules.retain(|r| !child_ids.contains(&r.id.as_str()));
    merged_rules.extend(child_rules.iter().cloned());

    ResolvedPolicy {
        chain: vec![parent.template_id.clone(), child.workspace_id.clone()],
        workspace: merged_workspace,
        rules: merged_rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{ActionType, GovernanceDecision, ProtocolKind, ToolPolicy};

    fn child_workspace() -> WorkspacePolicy {
        WorkspacePolicy {
            workspace_id: "my-prod".into(),
            tenant_id: Some("acme".into()),
            allowed_protocols: vec![ProtocolKind::Acp],
            tools: vec![ToolPolicy {
                tool_name: "custom.tool".into(),
                allowed_action_types: vec![ActionType::Custom],
                max_decision: GovernanceDecision::Allow,
                requires_human_review: false,
                ..Default::default()
            }],
            allowed_domains: vec!["api.acme.com".into()],
            threshold_block: 55,
            threshold_review: 35, // same as default → won't override
        }
    }

    #[test]
    fn test_resolve_without_extends() {
        let ws = child_workspace();
        let resolved = resolve_hierarchy(&ws, &[], None);
        assert_eq!(resolved.workspace.workspace_id, "my-prod");
        assert_eq!(resolved.chain.len(), 1);
    }

    #[test]
    fn test_resolve_with_extends_strict_production() {
        let ws = child_workspace();
        let resolved = resolve_hierarchy(&ws, &[], Some("strict-production"));
        // Chain should show parent → child
        assert_eq!(resolved.chain.len(), 2);
        assert_eq!(resolved.chain[0], "strict-production");
        assert_eq!(resolved.chain[1], "my-prod");

        // Child tool should be present
        assert!(resolved
            .workspace
            .tools
            .iter()
            .any(|t| t.tool_name == "custom.tool"));

        // Parent tool should also be present
        assert!(resolved
            .workspace
            .tools
            .iter()
            .any(|t| t.tool_name == "filesystem.read"));

        // Child protocol (Acp) should be merged with parent protocols
        assert!(resolved
            .workspace
            .allowed_protocols
            .contains(&ProtocolKind::Acp));

        // Child threshold override
        assert_eq!(resolved.workspace.threshold_block, 55);

        // Inherited rules from parent (strict-production has 3 rules)
        assert!(resolved.rules.len() >= 3);
    }

    #[test]
    fn test_resolve_nonexistent_parent_falls_back() {
        let ws = child_workspace();
        let resolved = resolve_hierarchy(&ws, &[], Some("nonexistent-template"));
        assert_eq!(resolved.chain.len(), 1);
        assert_eq!(resolved.workspace.workspace_id, "my-prod");
    }

    #[test]
    fn test_child_rules_override_parent() {
        use super::super::rules_engine::{ConditionSet, MatchCriteria, PolicyRule};

        let ws = child_workspace();
        let child_rules = vec![PolicyRule {
            id: "sp-block-shell".into(), // same id as parent rule
            name: "allow-shell-in-my-prod".into(),
            priority: 0,
            match_criteria: MatchCriteria {
                action_type: vec![ActionType::Shell],
                ..Default::default()
            },
            conditions: ConditionSet::default(),
            decision: GovernanceDecision::Allow,
            reason: Some("Override: shell allowed in my-prod".into()),
            enabled: true,
        }];

        let resolved = resolve_hierarchy(&ws, &child_rules, Some("strict-production"));

        // The child's override should replace the parent's block rule
        let shell_rules: Vec<_> = resolved
            .rules
            .iter()
            .filter(|r| r.id == "sp-block-shell")
            .collect();
        assert_eq!(shell_rules.len(), 1);
        assert_eq!(shell_rules[0].decision, GovernanceDecision::Allow);
    }
}
