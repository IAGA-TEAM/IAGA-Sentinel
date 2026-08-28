use once_cell::sync::Lazy;
use regex::Regex;

use crate::core::types::{ActionType, GovernanceDecision, InspectRequest, RiskScore};

static HIGH_RISK_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"(?i)rm\s+-rf",
        r"(?i)chmod\s+777",
        r"(?i)curl.+\|.+sh",
        r"(?i)powershell.+-enc",
        r"(?i)base64",
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
});

static SUSPICIOUS_URL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [r"(?i)ngrok", r"(?i)pastebin", r"(?i)discordapp"]
        .iter()
        .filter_map(|p| Regex::new(p).ok())
        .collect()
});

/// Unified decision thresholds (single source of truth).
pub const THRESHOLD_BLOCK: u32 = 70;
pub const THRESHOLD_REVIEW: u32 = 35;

/// Accumulated risk contributions from each security layer.
/// Built up in execute_pipeline and passed here for final scoring.
#[derive(Debug, Default)]
pub struct LayerRiskContributions {
    /// Firewall detection score (0-100)
    pub firewall: u32,
    /// Threat intelligence match score
    pub threat_intel: u32,
    /// Taint tracking violation score
    pub taint: u32,
    /// Session graph anomaly score
    pub session_graph: u32,
    /// Adaptive risk ensemble score
    pub adaptive: u32,
    /// Behavioral fingerprint anomaly score
    pub behavioral: u32,
    /// Policy violations (not approved, baseline deviation, etc.)
    pub policy: u32,
    /// Secret injection risk
    pub secrets: u32,
    /// Optional WASM plugin risk contribution
    pub plugins: u32,
}

pub fn score_tool_risk_with_thresholds(
    input: &InspectRequest,
    minimum_decision: GovernanceDecision,
    policy_findings: &[String],
    layers: &LayerRiskContributions,
    // PERF-PAYLOAD-3X-1: the canonical payload string is serialized once in the
    // pipeline and threaded in, instead of being re-serialized here.
    payload_text: &str,
    threshold_block: u32,
    threshold_review: u32,
) -> RiskScore {
    let mut reasons: Vec<String> = Vec::new();

    // ── Local pattern scoring (fast, deterministic) ──
    let mut pattern_score: u32 = 0;

    if input.action.action_type == ActionType::Shell {
        pattern_score += 25;
        reasons.push("shell execution requires elevated scrutiny".to_string());
    }

    for pattern in HIGH_RISK_PATTERNS.iter() {
        if pattern.is_match(payload_text) {
            pattern_score += 40;
            reasons.push(format!("matched high-risk pattern: {}", pattern.as_str()));
        }
    }

    for pattern in SUSPICIOUS_URL_PATTERNS.iter() {
        if pattern.is_match(payload_text) {
            pattern_score += 25;
            reasons.push(format!(
                "matched suspicious destination: {}",
                pattern.as_str()
            ));
        }
    }

    if input
        .requested_secrets
        .as_ref()
        .is_some_and(|s| !s.is_empty())
    {
        pattern_score += 15;
        reasons.push("action requests dynamic secret injection".to_string());
    }

    if input.action.action_type == ActionType::DbQuery {
        pattern_score += 20;
        reasons.push("database access should be policy-gated".to_string());
    }

    if policy_findings
        .iter()
        .any(|f| f.contains("outside baseline"))
    {
        pattern_score += 20;
        reasons.push("behavior deviates from baseline".to_string());
    }

    pattern_score = pattern_score.min(100);

    // ── Composite score from the SCORING layers ──
    // Each contributes proportionally to its detection confidence; we take the
    // MAX within a signal group to avoid double-counting, then weight.
    //
    // NOT "all 8 layers", despite the eight-layer framing elsewhere:
    //   - Sandbox has NO term here. It is advisory containment; nothing it does
    //     enters this score (see `sandboxResult` in `layer_roles`).
    //   - `behavioral` appears only as `policy.max(behavioral)`, and its risk
    //     contribution is pinned to 0 upstream (DET-BEHAVIORAL-2 in
    //     execute_pipeline), so the max is always `policy`. The term is kept for
    //     the day that pin is lifted, not because it currently adds anything.
    // The weights below sum to 1.10, NOT 1.0, so `.min(100)` below is a real
    // clamp rather than a defensive no-op: a request saturating every slot
    // reaches 110 before it is capped. (Leaving the pattern slot at zero, as
    // `tests/tool_risk_arithmetic.rs` does, gives the 0.95 that test asserts.)
    //
    // Weight allocation:
    //   - Pattern matching (local):  15% , fast regex-based detection
    //   - Adaptive ensemble:         20% , 5-signal ML-style scoring
    //   - Firewall:                  20% , injection-specific detection
    //   - Policy (behavioral inert): 15% , authorization & baseline
    //   - Taint + threat intel:      15% , data flow & IOC matching
    //   - Secrets:                   10% , vault policy enforcement
    //   - Session graph:              5% , `layers.session_graph`, which
    //                                     `execute_pipeline` sets to the SIGNED
    //                                     `anomaly_score`. The separate
    //                                     `advisoryScore` is not weighted here.
    //   - WASM plugins:              10% , custom detectors/community extensions

    let composite = (pattern_score as f64 * 0.15)
        + (layers.adaptive as f64 * 0.20)
        + (layers.firewall as f64 * 0.20)
        + ((layers.policy.max(layers.behavioral)) as f64 * 0.15)
        + ((layers.taint.max(layers.threat_intel)) as f64 * 0.15)
        + (layers.secrets as f64 * 0.10)
        + (layers.session_graph as f64 * 0.05)
        + (layers.plugins as f64 * 0.10);

    let mut score = (composite.round() as u32).min(100);

    // Surface the policy-layer findings that drove an escalation, so a Block or
    // Review verdict is never reasonless. Without this, a decision forced by the
    // policy layer (e.g. "destination ... outside allowed domains", "tool ... is
    // not registered") would show only the vague "escalated by security layers"
    // note below. `reasons` flows to both the audit event and the signed
    // receipt. Skip the benign "matched" placeholder and dedupe.
    if minimum_decision != GovernanceDecision::Allow {
        for f in policy_findings {
            if f.contains("matched registered tool and workspace policy") {
                continue;
            }
            if !reasons.iter().any(|r| r == f) {
                reasons.push(f.clone());
            }
        }
    }

    // ── Decision-aware score adjustment ──
    // When security layers force a higher decision, the score should
    // reflect that severity, but proportionally, not as a flat floor.
    // This ensures Block decisions always score >= 70 and Review >= 35,
    // while preserving granularity WITHIN each band.
    match minimum_decision {
        GovernanceDecision::Block => {
            if score < threshold_block {
                let headroom = 100u32.saturating_sub(threshold_block);
                score = threshold_block + (score * headroom / 100).min(headroom);
                reasons.push(format!(
                    "escalated by security layers (raw composite: {:.0})",
                    composite
                ));
            }
        }
        GovernanceDecision::Review => {
            if score < threshold_review {
                let headroom = threshold_block.saturating_sub(threshold_review);
                score = threshold_review + (score * headroom / 100).min(headroom);
                reasons.push(format!(
                    "escalated to review by security layers (raw composite: {:.0})",
                    composite
                ));
            }
        }
        GovernanceDecision::Allow => {}
    }

    score = score.min(100);

    // ── Final decision ──
    let score_decision = if score >= threshold_block {
        GovernanceDecision::Block
    } else if score >= threshold_review {
        GovernanceDecision::Review
    } else {
        GovernanceDecision::Allow
    };

    let final_decision = if minimum_decision > score_decision {
        minimum_decision
    } else {
        score_decision
    };

    // A refusal always says why it refused.
    //
    // "no high-risk rule matched" is a true statement about RULE matching, and
    // it was emitted whenever nothing had pushed a reason — including when the
    // verdict came from the composite score crossing a threshold rather than
    // from any single layer vetoing. That produced a `block` whose only stated
    // reason was that nothing matched, and because `reasons` is copied verbatim
    // into the signed `ReceiptBody`, the self-contradiction was written into the
    // audit event, the human review queue and the cryptographic evidence.
    //
    // An operator reading "no high-risk rule matched" next to "block" cannot act
    // on it, and on an evidence product the receipt is the deliverable. So the
    // fallback now depends on what was actually decided: only an Allow can say
    // nothing matched; anything else names the score and the threshold it
    // reached, which is precisely what happened.
    if reasons.is_empty() {
        reasons.push(match final_decision {
            GovernanceDecision::Allow => "no high-risk rule matched".to_string(),
            GovernanceDecision::Review => format!(
                "composite risk score {score} reached the review threshold ({threshold_review}); \
                 no single layer vetoed"
            ),
            GovernanceDecision::Block => format!(
                "composite risk score {score} reached the block threshold ({threshold_block}); \
                 no single layer vetoed"
            ),
        });
    }

    // DET-REASONS-MERGE: `reasons` is copied verbatim into the signed ReceiptBody,
    // so its order is part of the bit-exact-replay guarantee. Several upstream
    // layers build reason strings from HashSet/HashMap iteration (taint summary,
    // session-graph taint accumulation, firewall categories), whose order is
    // process-randomized. Canonicalize once here, the single choke point where
    // every layer's findings converge, so identical inputs yield byte-identical
    // signed receipts.
    reasons.sort();
    reasons.dedup();

    RiskScore {
        score,
        decision: final_decision,
        reasons,
    }
}

#[cfg(test)]
mod reasons_determinism_tests {
    use super::*;
    use crate::core::types::{ActionDetail, ActionType, InspectRequest};
    use std::collections::HashMap;

    fn shell_rm_rf_request() -> InspectRequest {
        let mut payload = HashMap::new();
        payload.insert("cmd".to_string(), serde_json::json!("rm -rf /"));
        InspectRequest {
            agent_id: "a".into(),
            tenant_id: None,
            workspace_id: None,
            framework: "test".into(),
            protocol: None,
            action: ActionDetail {
                action_type: ActionType::Shell,
                tool_name: "bash".into(),
                payload,
            },
            requested_secrets: None,
            metadata: None,
            usage: None,
        }
    }

    /// DET-REASONS-MERGE: the signed `reasons` vector must be canonical (sorted,
    /// no consecutive duplicates) and identical across runs for identical input.
    #[test]
    fn reasons_are_sorted_deduped_and_reproducible() {
        let req = shell_rm_rf_request();
        let payload_text = serde_json::to_string(&req.action.payload).unwrap_or_default();
        let layers = LayerRiskContributions::default();
        // Intentionally unsorted + duplicated policy findings.
        let findings = vec![
            "zzz policy finding".to_string(),
            "aaa policy finding".to_string(),
            "zzz policy finding".to_string(),
        ];

        let r1 = score_tool_risk_with_thresholds(
            &req,
            GovernanceDecision::Block,
            &findings,
            &layers,
            &payload_text,
            THRESHOLD_BLOCK,
            THRESHOLD_REVIEW,
        );

        let mut expected_sorted = r1.reasons.clone();
        expected_sorted.sort();
        assert_eq!(r1.reasons, expected_sorted, "reasons must be sorted");

        let mut expected_dedup = r1.reasons.clone();
        expected_dedup.dedup();
        assert_eq!(
            r1.reasons, expected_dedup,
            "reasons must have no consecutive duplicates"
        );

        let r2 = score_tool_risk_with_thresholds(
            &req,
            GovernanceDecision::Block,
            &findings,
            &layers,
            &payload_text,
            THRESHOLD_BLOCK,
            THRESHOLD_REVIEW,
        );
        assert_eq!(
            r1.reasons, r2.reasons,
            "identical input must yield identical reason order"
        );
    }
}
