//! `layerRoles` and `docs/openapi.yaml` must agree, and must cover every layer.
//!
//! Two independent statements of the same fact drifted apart inside one change
//! set. `layer_roles()` publishes `policyVerification` as **advisory** — that is
//! the whole point of the S3 correction, and the CHANGELOG says so — while the
//! same diff wrote `L6 formal policy verification result. VETO.` into the
//! published API contract. A consumer reading the spec and a consumer reading
//! the response got opposite answers about whether that layer can refuse.
//!
//! The map also omitted two blocks the response actually carries:
//!
//!   * `telemetrySpan` — openapi already labelled it ADVISORY, but because the
//!     map had no entry, the SDK helper `is_advisory_layer("telemetrySpan")`
//!     answered **false**: the one layer the map forgot was reported as if it
//!     could veto.
//!   * `pluginResults` — not advisory at all. `tool_risk.rs` weights
//!     `layers.plugins` at **0.10** of the composite, so it is a scoring layer
//!     with real weight and no published role.
//!
//! Nothing tied the two files together, which is why the drift was invisible.

use std::collections::BTreeMap;

use iaga_sentinel::core::types::layer_roles;

/// `<layer>: <ROLE>` as stated in the openapi descriptions.
fn openapi_roles() -> BTreeMap<String, String> {
    let spec = include_str!("../../../docs/openapi.yaml");
    let mut out = BTreeMap::new();
    let mut current: Option<String> = None;

    for line in spec.lines() {
        let trimmed = line.trim();
        // A property key under GovernanceResult.properties, e.g. `sessionGraph:`
        if let Some(name) = trimmed.strip_suffix(':') {
            if name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && name.chars().next().is_some_and(|c| c.is_lowercase())
            {
                current = Some(name.to_string());
            }
        }
        for role in ["VETO", "SCORING", "ADVISORY"] {
            if trimmed.contains(role) {
                if let Some(name) = current.clone() {
                    out.entry(name).or_insert_with(|| role.to_lowercase());
                }
            }
        }
    }
    out
}

#[test]
fn openapi_and_layer_roles_state_the_same_role_for_every_layer_both_mention() {
    let map = layer_roles();
    let map = map.as_object().expect("layer_roles is an object");
    let spec = openapi_roles();

    let mut disagreements: Vec<String> = Vec::new();
    for (layer, spec_role) in &spec {
        let Some(entry) = map.get(layer) else {
            continue;
        };
        let map_role = entry
            .get("role")
            .and_then(|r| r.as_str())
            .unwrap_or("<missing>");
        if map_role != spec_role {
            disagreements.push(format!(
                "{layer}: openapi says {spec_role}, layer_roles says {map_role}"
            ));
        }
    }

    assert!(
        disagreements.is_empty(),
        "the published contract and the runtime map disagree about which layers \
         can refuse an action: {disagreements:#?}"
    );
}

#[test]
fn layer_roles_covers_every_layer_openapi_publishes_a_role_for() {
    let map = layer_roles();
    let map = map.as_object().expect("layer_roles is an object");

    let spec = openapi_roles();
    let missing: Vec<&String> = spec
        .keys()
        .filter(|layer| !map.contains_key(*layer))
        .collect();

    assert!(
        missing.is_empty(),
        "openapi publishes a role for these layers and `layerRoles` has no entry, \
         so `is_advisory_layer` answers false for them — indistinguishable from \
         a veto layer: {missing:#?}"
    );
}

/// Every `note` is copied verbatim into the inspect response body.
///
/// The notes are written as multi-line Rust string literals. A literal that
/// ends its line with `\` swallows the next line's indentation; one that does
/// not bakes that indentation into the string. Both forms compile, look the
/// same in the source, and differ only in what the API actually returns — so
/// the mistake is invisible until someone reads the JSON. `telemetrySpan` and
/// `pluginResults`, the two entries added to close the coverage gap above,
/// shipped with a 22-space run in the middle of a sentence.
#[test]
fn layer_role_notes_are_clean_prose() {
    let map = layer_roles();
    let map = map.as_object().expect("layer_roles is an object");

    let mut malformed: Vec<String> = Vec::new();
    for (layer, entry) in map {
        let Some(note) = entry.get("note").and_then(|n| n.as_str()) else {
            continue;
        };
        if note.contains("  ") {
            malformed.push(format!(
                "{layer}: run of spaces inside the published note — {note:?}"
            ));
        }
        if note.contains('\n') || note.contains('\t') {
            malformed.push(format!("{layer}: raw control character in note — {note:?}"));
        }
    }

    assert!(
        malformed.is_empty(),
        "these notes are serialized straight into the API response and are not \
         clean prose (a multi-line literal is missing its `\\` continuation): \
         {malformed:#?}"
    );
}
