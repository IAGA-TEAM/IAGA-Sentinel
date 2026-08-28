//! Every field the policy structs SERIALIZE must be documented in `docs/openapi.yaml`.
//!
//! Not a tidiness rule. `WorkspacePolicy` carries `thresholdBlock` and
//! `thresholdReview`, the two numbers that decide what gets blocked, and both
//! have serde defaults (70 and 35). The spec documented four properties and
//! neither threshold, so a client generated strictly from the spec sends a
//! `PUT /v1/workspaces/{id}` body without them — and the handler, obeying
//! ordinary PUT-replaces semantics, answers `200 OK` and resets a workspace
//! hardened to 40/20 back to 70/35.
//!
//! Measured against a live 2.1.0 server: harden to 40/20, `PUT` a body built
//! from exactly the properties the spec lists, `200 OK`, read back 70/35. The
//! operator is told nothing. That is the same shape as the 2.0.2 defect where
//! every Postgres workspace was silently governed at 70/35 while its
//! configuration said otherwise — a security control that is accepted and
//! quietly discarded.
//!
//! `AgentProfile.toolTrust` is the same hazard one layer down: a scoring knob
//! with a serde default that the spec never mentions.
//!
//! The test asserts one direction only — every serialized field is documented.
//! A documented field that the struct does not serialize is a different problem
//! and is not what bit us here.

use std::collections::BTreeSet;

use iaga_sentinel::core::types::{
    ActionType, AgentProfile, AgentRole, ProtocolKind, WorkspacePolicy,
};

/// Property names declared under `components.schemas.<name>.properties`.
///
/// Hand-parsed rather than pulled through a YAML crate, following
/// `layer_roles_openapi_parity.rs`: the spec is indented consistently and a
/// dependency for one lookup is not worth it. Schema names sit at 4 spaces,
/// `properties:` at 6, and property names at 8.
fn documented_properties(schema: &str) -> BTreeSet<String> {
    let spec = include_str!("../../../docs/openapi.yaml");
    let header = format!("    {schema}:");
    let mut out = BTreeSet::new();
    let mut in_schema = false;
    let mut in_properties = false;

    for line in spec.lines() {
        if line == header {
            in_schema = true;
            continue;
        }
        if !in_schema {
            continue;
        }
        // Any other 4-space key ends this schema.
        if line.starts_with("    ") && !line.starts_with("     ") && line.trim().ends_with(':') {
            break;
        }
        if line.trim() == "properties:" {
            in_properties = line.starts_with("      ") && !line.starts_with("       ");
            continue;
        }
        // edition 2021: no let-chains, so this nests.
        if in_properties && line.starts_with("        ") && !line.starts_with("         ") {
            if let Some(name) = line.trim().strip_suffix(':') {
                if name.chars().all(|c| c.is_ascii_alphanumeric()) {
                    out.insert(name.to_string());
                }
            }
        }
    }
    assert!(!out.is_empty(), "no properties found for schema {schema}");
    out
}

fn serialized_keys<T: serde::Serialize>(value: &T) -> BTreeSet<String> {
    match serde_json::to_value(value).expect("serialize") {
        serde_json::Value::Object(map) => map.keys().cloned().collect(),
        other => panic!("expected an object, got {other}"),
    }
}

#[test]
fn every_workspace_policy_field_is_documented() {
    let policy = WorkspacePolicy {
        workspace_id: "ws-parity".into(),
        tenant_id: None,
        allowed_protocols: vec![ProtocolKind::HttpFunction],
        tools: vec![],
        allowed_domains: vec!["example.com".into()],
        threshold_block: 40,
        threshold_review: 20,
    };
    let served = serialized_keys(&policy);
    let documented = documented_properties("WorkspacePolicy");
    let missing: Vec<_> = served.difference(&documented).cloned().collect();

    assert!(
        missing.is_empty(),
        "WorkspacePolicy serializes fields the OpenAPI spec does not document: {missing:?}.\n\
         A client generated from the spec omits them on PUT and the handler resets them to their \
         serde defaults with 200 OK — for thresholdBlock/thresholdReview that silently un-hardens \
         the workspace.\nserved: {served:?}\ndocumented: {documented:?}"
    );
}

#[test]
fn every_agent_profile_field_is_documented() {
    let profile = AgentProfile {
        agent_id: "parity-agent".into(),
        tenant_id: None,
        workspace_id: "ws-parity".into(),
        framework: "openai".into(),
        role: AgentRole::Builder,
        approved_tools: vec![],
        approved_secrets: vec![],
        baseline_action_types: vec![ActionType::Http],
        tool_trust: 0.7,
    };
    let served = serialized_keys(&profile);
    let documented = documented_properties("AgentProfile");
    let missing: Vec<_> = served.difference(&documented).cloned().collect();

    assert!(
        missing.is_empty(),
        "AgentProfile serializes fields the OpenAPI spec does not document: {missing:?}.\n\
         served: {served:?}\ndocumented: {documented:?}"
    );
}
