//! Pins the arithmetic of `score_tool_risk_with_thresholds`.
//!
//! Mutation testing over this module (cargo-mutants, 76 mutants across
//! `tool_risk.rs` and `pipeline/policy_hash.rs`) reported **35 survivors, all of
//! them here**: `+` could become `-`, `*` could become `/`, `<` could become
//! `>`, a `!` could be deleted, and the whole 561-test suite stayed green.
//! `policy_hash.rs` lost 0 of its 4.
//!
//! This is the function the architecture document names as the place where
//! "Block vs Review vs Allow is actually decided", so its arithmetic having no
//! test is the single widest gap the audit found in the suite.
//!
//! These tests assert exact values rather than `>=` bands on purpose: a band
//! assertion is what let the weights drift untested in the first place.

use iaga_sentinel::core::types::{
    ActionDetail, ActionType, GovernanceDecision, InspectRequest, ProtocolKind,
};
use iaga_sentinel::modules::policy::tool_risk::{
    score_tool_risk_with_thresholds, LayerRiskContributions, THRESHOLD_BLOCK, THRESHOLD_REVIEW,
};
use std::collections::HashMap;

/// A request with no pattern risk of its own, so the composite is exactly the
/// weighted sum of the layer inputs and nothing else.
fn inert_request() -> InspectRequest {
    InspectRequest {
        agent_id: "arith".into(),
        tenant_id: None,
        workspace_id: None,
        framework: "audit".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::FileRead,
            tool_name: "filesystem.read".into(),
            payload: HashMap::new(),
        },
        metadata: None,
        usage: None,
        requested_secrets: None,
    }
}

fn score_of(layers: &LayerRiskContributions, minimum: GovernanceDecision) -> u32 {
    score_tool_risk_with_thresholds(
        &inert_request(),
        minimum,
        &[],
        layers,
        "{}",
        THRESHOLD_BLOCK,
        THRESHOLD_REVIEW,
    )
    .score
}

/// Each layer weight, isolated. Driving one layer to 100 and leaving the rest at
/// zero makes the composite equal that layer's weight in percent, so the whole
/// weighting table is pinned by construction — and any `*`→`/` or `+`→`-` in the
/// composite moves at least one of these rows.
#[test]
fn each_layer_contributes_exactly_its_documented_weight() {
    /// (label, "saturate this one layer", the weight it must contribute).
    type Case = (&'static str, fn(&mut LayerRiskContributions), u32);
    let cases: &[Case] = &[
        ("adaptive 20%", |l| l.adaptive = 100, 20),
        ("firewall 20%", |l| l.firewall = 100, 20),
        ("policy 15%", |l| l.policy = 100, 15),
        (
            "behavioral 15% (shares the max with policy)",
            |l| l.behavioral = 100,
            15,
        ),
        ("taint 15%", |l| l.taint = 100, 15),
        (
            "threat_intel 15% (shares the max with taint)",
            |l| l.threat_intel = 100,
            15,
        ),
        ("secrets 10%", |l| l.secrets = 100, 10),
        ("plugins 10%", |l| l.plugins = 100, 10),
        ("session_graph 5%", |l| l.session_graph = 100, 5),
    ];
    for (name, set, expected) in cases {
        let mut layers = LayerRiskContributions::default();
        set(&mut layers);
        assert_eq!(
            score_of(&layers, GovernanceDecision::Allow),
            *expected,
            "{name}: a layer at 100 must contribute exactly its weight"
        );
    }
}

/// `policy` and `behavioral` share one 15% slot via `max`, as do `taint` and
/// `threat_intel`. Both at 100 must still yield 15, not 30 — the pairing is the
/// part a reader is most likely to get wrong when editing the composite.
#[test]
fn paired_layers_share_one_slot_instead_of_stacking() {
    let both_policy = LayerRiskContributions {
        policy: 100,
        behavioral: 100,
        ..Default::default()
    };
    assert_eq!(
        score_of(&both_policy, GovernanceDecision::Allow),
        15,
        "policy and behavioral share a single 15% slot through max()"
    );

    let both_taint = LayerRiskContributions {
        taint: 100,
        threat_intel: 100,
        ..Default::default()
    };
    assert_eq!(
        score_of(&both_taint, GovernanceDecision::Allow),
        15,
        "taint and threat_intel share a single 15% slot through max()"
    );
}

/// Every layer saturated at once, with no pattern risk: exactly 95.
///
/// Not 100, and the gap is the point. The layer slots are
/// 0.20 + 0.20 + 0.15 + 0.15 + 0.10 + 0.05 + 0.10 = **0.95**; the remaining 0.15
/// belongs to `pattern_score`, which is computed from the request rather than
/// from a layer. Adding it makes the table sum to **1.10**, so the weights are
/// not a partition of 1.0 and the `.min(100)` clamp is load-bearing rather than
/// defensive — a request that is both pattern-risky and saturated on every layer
/// computes 110 before clamping.
///
/// This test asserted 100 when it was written, on the assumption the weights
/// summed to one. The code was right and the assumption was wrong.
#[test]
fn all_layers_saturated_without_pattern_risk_sum_to_ninety_five() {
    let layers = LayerRiskContributions {
        firewall: 100,
        threat_intel: 100,
        taint: 100,
        session_graph: 100,
        adaptive: 100,
        behavioral: 100,
        policy: 100,
        secrets: 100,
        plugins: 100,
    };
    assert_eq!(
        score_of(&layers, GovernanceDecision::Allow),
        95,
        "the seven layer slots must sum to 0.95; the remaining 0.15 is the          pattern slot, which this request deliberately leaves at zero"
    );
}

/// The escalation rescale. When a layer forces Block but the composite is below
/// the block threshold, the score is lifted INTO the block band without being
/// flattened to a constant: it must land at or above the threshold, stay within
/// 100, and still order two different composites.
#[test]
fn escalation_lifts_into_the_band_and_preserves_ordering() {
    let low = LayerRiskContributions {
        adaptive: 10,
        ..Default::default()
    };
    let high = LayerRiskContributions {
        adaptive: 60,
        ..Default::default()
    };

    let low_allow = score_of(&low, GovernanceDecision::Allow);
    let high_allow = score_of(&high, GovernanceDecision::Allow);
    assert!(
        low_allow < THRESHOLD_BLOCK && high_allow < THRESHOLD_BLOCK,
        "precondition: both composites must start below the block threshold \
         ({low_allow}, {high_allow})"
    );

    let low_block = score_of(&low, GovernanceDecision::Block);
    let high_block = score_of(&high, GovernanceDecision::Block);

    // Exact, not a band. `score = threshold_block + (score * headroom / 100)`
    // with headroom = 100 - 70 = 30, so composite 2 -> 70 + 0 = 70 and
    // composite 12 -> 70 + 3 = 73. Asserting only "at least 70, and ordered"
    // let `*` become `+` in that expression without any test noticing.
    assert_eq!(
        (low_allow, low_block),
        (2, 70),
        "composite 2 escalated to Block must land exactly on the threshold"
    );
    assert_eq!(
        (high_allow, high_block),
        (12, 73),
        "composite 12 escalated to Block must land at 70 + (12 * 30 / 100)"
    );
    assert!(
        high_block > low_block,
        "the rescale must preserve granularity within the band: {high_block} vs {low_block}"
    );
}

/// The same for the Review band, including its upper edge: a rescaled Review
/// must not spill over into Block.
#[test]
fn review_escalation_stays_inside_its_own_band() {
    let layers = LayerRiskContributions {
        adaptive: 10,
        ..Default::default()
    };
    let score = score_of(&layers, GovernanceDecision::Review);
    assert!(
        score >= THRESHOLD_REVIEW,
        "a Review forced by a layer must score at least {THRESHOLD_REVIEW}, got {score}"
    );
    assert!(
        score < THRESHOLD_BLOCK,
        "a rescaled Review must not reach the block band, got {score}"
    );
}

/// Stricter-wins, the rule the whole layering rests on: the final decision is
/// the stricter of the layer floor and the score band, never the weaker one.
///
/// The `>` at the merge could be replaced with `<`, `==` or `>=` without a
/// single existing test noticing, because the escalation above usually makes
/// both sides agree before the comparison runs. These cases are built so the two
/// sides genuinely disagree.
#[test]
fn the_final_decision_is_the_stricter_of_floor_and_score() {
    // Score says Allow, a layer floor says Review -> Review.
    let quiet = LayerRiskContributions {
        adaptive: 5,
        ..Default::default()
    };
    let r = score_tool_risk_with_thresholds(
        &inert_request(),
        GovernanceDecision::Review,
        &[],
        &quiet,
        "{}",
        THRESHOLD_BLOCK,
        THRESHOLD_REVIEW,
    );
    assert_eq!(
        r.decision,
        GovernanceDecision::Review,
        "a layer floor of Review must survive a quiet score"
    );

    // Score alone reaches Block; the floor is Allow -> Block.
    let loud = LayerRiskContributions {
        firewall: 100,
        adaptive: 100,
        taint: 100,
        policy: 100,
        secrets: 100,
        plugins: 100,
        session_graph: 100,
        behavioral: 100,
        threat_intel: 100,
    };
    let r = score_tool_risk_with_thresholds(
        &inert_request(),
        GovernanceDecision::Allow,
        &[],
        &loud,
        "{}",
        THRESHOLD_BLOCK,
        THRESHOLD_REVIEW,
    );
    assert_eq!(
        r.decision,
        GovernanceDecision::Block,
        "a score in the block band must Block even when no layer forced it"
    );

    // Both quiet -> Allow. The complement, so a merge that always returns the
    // stricter constant cannot pass the three together.
    let r = score_tool_risk_with_thresholds(
        &inert_request(),
        GovernanceDecision::Allow,
        &[],
        &quiet,
        "{}",
        THRESHOLD_BLOCK,
        THRESHOLD_REVIEW,
    );
    assert_eq!(
        r.decision,
        GovernanceDecision::Allow,
        "a quiet score with no floor must stay Allow"
    );
}
