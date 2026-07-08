use crate::core::types::{
    AgentProfile, GovernanceDecision, InspectRequest, ProtocolKind, WorkspacePolicy,
};

pub struct PolicyEvaluation {
    pub findings: Vec<String>,
    pub minimum_decision: GovernanceDecision,
}

pub fn evaluate_policy(
    input: &InspectRequest,
    profile: &AgentProfile,
    workspace_policy: &WorkspacePolicy,
    protocol: ProtocolKind,
) -> PolicyEvaluation {
    let mut findings: Vec<String> = Vec::new();
    let mut minimum_decision = GovernanceDecision::Allow;

    // Check protocol allowed
    if !workspace_policy.allowed_protocols.contains(&protocol) {
        findings.push(format!(
            "protocol {:?} is not allowed for workspace {}",
            protocol, workspace_policy.workspace_id
        ));
        minimum_decision = GovernanceDecision::Block;
    }

    // Check tool policy
    let tool_policy = workspace_policy
        .tools
        .iter()
        .find(|t| t.tool_name == input.action.tool_name);

    match tool_policy {
        None => {
            findings.push(format!(
                "tool {} is not registered in workspace policy",
                input.action.tool_name
            ));
            minimum_decision = GovernanceDecision::Block;
        }
        Some(tp) => {
            if !tp.allowed_action_types.contains(&input.action.action_type) {
                findings.push(format!(
                    "tool {} cannot run action type {:?}",
                    input.action.tool_name, input.action.action_type
                ));
                minimum_decision = GovernanceDecision::Block;
            }

            if tp.requires_human_review && minimum_decision != GovernanceDecision::Block {
                findings.push(format!(
                    "tool {} requires human review",
                    input.action.tool_name
                ));
                minimum_decision = GovernanceDecision::Review;
            }

            if tp.max_decision == GovernanceDecision::Review
                && minimum_decision == GovernanceDecision::Allow
            {
                findings.push(format!(
                    "tool {} is capped at review in workspace policy",
                    input.action.tool_name
                ));
                minimum_decision = GovernanceDecision::Review;
            }
        }
    }

    // Check agent approved for tool
    if !profile.approved_tools.contains(&input.action.tool_name) {
        findings.push(format!(
            "agent {} is not approved for tool {}",
            profile.agent_id, input.action.tool_name
        ));
        minimum_decision = GovernanceDecision::Block;
    }

    // Check baseline action types
    if !profile
        .baseline_action_types
        .contains(&input.action.action_type)
    {
        findings.push(format!(
            "action type {:?} is outside baseline for agent {}",
            input.action.action_type, profile.agent_id
        ));
        if minimum_decision == GovernanceDecision::Allow {
            minimum_decision = GovernanceDecision::Review;
        }
    }

    // Check destination domain. Host-aware: a full URL like
    // `https://api.github.com/x` is normalized to its host before being matched
    // (case-insensitively) against the bare-host allowlist, so structured URLs
    // are no longer spuriously blocked. Mirrors the Dictum `url_host()` builtin.
    if let Some(destination) = extract_destination(&input.action.payload) {
        let host = host_of(&destination);
        let allowed = workspace_policy
            .allowed_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&host));
        if !allowed {
            findings.push(format!(
                "destination {destination} (host {host}) is outside allowed workspace domains"
            ));
            minimum_decision = GovernanceDecision::Block;
        }
    }

    if findings.is_empty() {
        findings.push("request matched registered tool and workspace policy".to_string());
    }

    PolicyEvaluation {
        findings,
        minimum_decision,
    }
}

fn extract_destination(
    payload: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<String> {
    // Priority-ordered destination/URL field names. Callers name the target
    // differently (`url`, `endpoint`, `href`); checking only `destination` let a
    // URL in any other field slip past the domain allowlist (issue #20).
    ["destination", "url", "endpoint", "href"]
        .iter()
        .find_map(|k| payload.get(*k).and_then(|v| v.as_str()))
        .map(|s| s.to_string())
}

/// Extract the lowercased host from a URL or bare-host string.
///
/// Pure mirror of `iaga_sentinel_dictum::extract_host`. It is duplicated here on
/// purpose: `iaga-sentinel-dictum` is an *optional* dependency (behind the default
/// `dictum` feature) and this module compiles in every feature configuration, so
/// it cannot import the Dictum one. Strips scheme, userinfo, port, and
/// path/query/fragment; preserves a bracketed IPv6 literal. A bare host is
/// returned unchanged (lowercased), so existing bare-host allowlists keep
/// working; unparseable input yields "" (matches no allowlist entry).
fn host_of(s: &str) -> String {
    let after_scheme = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        match rest.split_once(']') {
            Some((h6, _)) => format!("[{h6}]"),
            None => hostport.to_string(),
        }
    } else {
        hostport
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(hostport)
            .to_string()
    };
    host.to_ascii_lowercase()
}

#[cfg(test)]
mod host_tests {
    use super::host_of;

    #[test]
    fn full_url_to_bare_host() {
        assert_eq!(
            host_of("https://api.github.com/repos/x?y=1"),
            "api.github.com"
        );
        assert_eq!(
            host_of("http://user:pass@API.GitHub.com:8443/p"),
            "api.github.com"
        );
    }

    #[test]
    fn bare_host_unchanged() {
        assert_eq!(host_of("api.github.com"), "api.github.com");
        assert_eq!(host_of("evil.com"), "evil.com");
    }

    #[test]
    fn ipv6_and_garbage() {
        assert_eq!(host_of("http://[::1]:8080/"), "[::1]");
        assert_eq!(host_of(""), "");
    }
}
