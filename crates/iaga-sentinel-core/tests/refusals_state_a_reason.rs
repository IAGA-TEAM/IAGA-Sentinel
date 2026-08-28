//! A refusal must say why it refused — including in the signed receipt.
//!
//! `score_tool_risk_with_thresholds` fell back to `"no high-risk rule matched"`
//! whenever no layer had pushed a reason. That is a true statement about RULE
//! matching, but the verdict can also come from the composite score crossing a
//! threshold with nothing vetoing — and then the caller got
//! `"decision": "block"` alongside `"reasons": ["no high-risk rule matched"]`.
//!
//! `reasons` is copied verbatim into the signed `ReceiptBody`, so that
//! self-contradiction was not merely a confusing API response: it was written
//! into the audit event, into the human review queue, and into the cryptographic
//! evidence this product exists to produce. An operator cannot act on "nothing
//! matched" as an explanation for a refusal.
//!
//! The thresholds are driven to a value that guarantees the score crosses them
//! without any veto layer firing, which is the shape the pipeline could not
//! easily be steered into from outside.

use iaga_sentinel::core::types::{ActionDetail, ActionType, GovernanceDecision, InspectRequest};
use iaga_sentinel::modules::policy::tool_risk::LayerRiskContributions;

fn request() -> InspectRequest {
    InspectRequest {
        agent_id: "reason-agent".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openai".into(),
        protocol: None,
        action: ActionDetail {
            action_type: ActionType::Http,
            tool_name: "http.fetch".into(),
            payload: Default::default(),
        },
        requested_secrets: None,
        metadata: None,
        usage: None,
    }
}

fn score_with(
    threshold_block: u32,
    threshold_review: u32,
) -> iaga_sentinel::core::types::RiskScore {
    iaga_sentinel::modules::policy::tool_risk::score_tool_risk_with_thresholds(
        &request(),
        GovernanceDecision::Allow,
        &[],
        &LayerRiskContributions::default(),
        "{}",
        threshold_block,
        threshold_review,
    )
}

/// Thresholds of zero force the score over the line with nothing vetoing.
#[test]
fn a_block_never_says_only_that_nothing_matched() {
    let risk = score_with(0, 0);
    assert_eq!(risk.decision, GovernanceDecision::Block);
    assert!(
        !risk.reasons.is_empty(),
        "a refusal must carry at least one reason"
    );
    assert_ne!(
        risk.reasons,
        vec!["no high-risk rule matched".to_string()],
        "a block whose only reason is that nothing matched is a contradiction, \
         and it is signed into the receipt"
    );
    assert!(
        risk.reasons
            .iter()
            .any(|r| r.contains("block threshold") && r.contains("risk score")),
        "the reason must name the score and the threshold it crossed: {:?}",
        risk.reasons
    );
}

/// The same for a review: the queue is where a human reads this.
#[test]
fn a_review_never_says_only_that_nothing_matched() {
    // Block out of reach, review at zero.
    let risk = score_with(100, 0);
    assert_eq!(risk.decision, GovernanceDecision::Review);
    assert_ne!(
        risk.reasons,
        vec!["no high-risk rule matched".to_string()],
        "a review with no stated cause is what a human is asked to adjudicate"
    );
    assert!(
        risk.reasons.iter().any(|r| r.contains("review threshold")),
        "the reason must name the review threshold: {:?}",
        risk.reasons
    );
}

/// An allow may still say nothing matched — there is nothing to explain.
#[test]
fn an_allow_may_still_say_nothing_matched() {
    let risk = score_with(100, 99);
    assert_eq!(risk.decision, GovernanceDecision::Allow);
    assert_eq!(
        risk.reasons,
        vec!["no high-risk rule matched".to_string()],
        "the wording that was always correct for an allow is unchanged"
    );
}
