//! Deterministic digest of the resolved workspace policy.
//!
//! Without a Dictum overlay the receipt's `policy_hash` used to be a constant
//! placeholder (`SHA256("iaga-sentinel-policy-v0")`), so the YAML policy that
//! actually decides most verdicts was never bound into the signed bytes
//! (CRYPTO-POLICYHASH-7a). This module hashes the real resolved
//! [`WorkspacePolicy`] so an auditor can tie a receipt to the exact policy
//! that produced it.
//!
//! `ponytail:` we sort the order-insensitive lists (domains, protocols, tools,
//! per-tool action types) and serialize with `serde_json` — the struct has no
//! maps, so the bytes are stable under list reordering without pulling in a
//! full RFC 8785 canonicalizer.

use sha2::{Digest, Sha256};

use crate::core::types::WorkspacePolicy;

/// Hex-encoded SHA-256 of the canonicalized workspace policy (id, protocols,
/// domains, tools + their action types/decisions, and the block/review
/// thresholds). Stable under reordering of any of the lists.
pub fn workspace_policy_hash(policy: &WorkspacePolicy) -> String {
    let mut p = policy.clone();
    p.allowed_domains.sort();
    // ProtocolKind / ActionType need no `Ord` derive: sort by their Debug form,
    // which is a deterministic total order (ponytail).
    p.allowed_protocols.sort_by_key(|k| format!("{k:?}"));
    p.tools.sort_by(|a, b| a.tool_name.cmp(&b.tool_name));
    for t in &mut p.tools {
        t.allowed_action_types.sort_by_key(|a| format!("{a:?}"));
        // Order-insensitive like the other lists: `destination_fields` is a
        // priority order for extraction, but two policies listing the same keys
        // govern identically and must hash identically. Note this list is
        // `skip_serializing_if = "Vec::is_empty"`, so a policy that never
        // declared one still hashes exactly as it did before the field existed.
        t.destination_fields.sort();
    }
    // Cannot fail: WorkspacePolicy is a plain struct with no maps.
    let bytes = serde_json::to_vec(&p).expect("WorkspacePolicy serializes");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{ActionType, GovernanceDecision, ProtocolKind, ToolPolicy};

    fn policy() -> WorkspacePolicy {
        WorkspacePolicy {
            workspace_id: "ws-demo".into(),
            tenant_id: None,
            allowed_protocols: vec![ProtocolKind::Mcp, ProtocolKind::HttpFunction],
            tools: vec![
                ToolPolicy {
                    tool_name: "filesystem.read".into(),
                    allowed_action_types: vec![ActionType::FileRead],
                    max_decision: GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                },
                ToolPolicy {
                    tool_name: "http.fetch".into(),
                    allowed_action_types: vec![ActionType::Http],
                    max_decision: GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                },
            ],
            allowed_domains: vec!["api.github.com".into(), "hooks.slack.com".into()],
            threshold_block: 70,
            threshold_review: 35,
        }
    }

    #[test]
    fn hash_is_64_hex_and_not_the_default_placeholder() {
        let h = workspace_policy_hash(&policy());
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        // Must differ from the old constant placeholder digest.
        let placeholder = {
            let mut hasher = Sha256::new();
            hasher.update(b"iaga-sentinel-policy-v0");
            hex::encode(hasher.finalize())
        };
        assert_ne!(h, placeholder);
    }

    /// Adding `destination_fields` to `ToolPolicy` must not re-hash policies
    /// that do not use it.
    ///
    /// This digest is bound into every signed receipt, so a field that
    /// serialized unconditionally would have silently invalidated the tie
    /// between every already-issued receipt and the policy it names — a
    /// migration nobody asked for, caused by adding an empty vector. The
    /// `skip_serializing_if = "Vec::is_empty"` attribute is what prevents it,
    /// and this test is what stops the attribute being dropped.
    #[test]
    fn an_undeclared_destination_field_does_not_appear_in_the_hashed_bytes() {
        let p = policy();
        assert!(p.tools.iter().all(|t| t.destination_fields.is_empty()));
        let bytes = serde_json::to_string(&p).expect("serializes");
        assert!(
            !bytes.contains("destinationFields"),
            "an empty destination_fields reached the hashed bytes, which \
             re-hashes every workspace that never adopted the field: {bytes}"
        );

        // And declaring one DOES move the hash — the field is inert only while
        // unused, not always.
        let mut declared = policy();
        declared.tools[0].destination_fields = vec!["target".into()];
        assert_ne!(workspace_policy_hash(&p), workspace_policy_hash(&declared));
    }

    #[test]
    fn hash_is_stable_under_domain_and_tool_reordering() {
        let mut a = policy();
        let mut b = policy();
        b.allowed_domains.reverse();
        b.tools.reverse();
        b.allowed_protocols.reverse();
        assert_eq!(workspace_policy_hash(&a), workspace_policy_hash(&b));
        // Sanity: changing a threshold changes the hash.
        a.threshold_block = 90;
        assert_ne!(workspace_policy_hash(&a), workspace_policy_hash(&b));
    }
}
