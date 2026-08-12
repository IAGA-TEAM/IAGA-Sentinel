//! Property-based tests for IAGA Sentinel security layers.
//!
//! Uses proptest to verify invariants that must hold for ALL possible inputs,
//! not just hand-picked examples.

use std::collections::HashSet;

use proptest::prelude::*;

use iaga_sentinel::modules::injection_firewall::prompt_firewall;
use iaga_sentinel::modules::risk::adaptive_scorer::{self, AdaptiveScoreInput};
use iaga_sentinel::modules::session_graph::session_dag;
use iaga_sentinel::modules::taint::taint_tracker;

// ── Strategies ──

fn action_type_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("file_read".to_string()),
        Just("file_write".to_string()),
        Just("shell".to_string()),
        Just("http".to_string()),
        Just("db_query".to_string()),
        Just("email".to_string()),
        Just("custom".to_string()),
        "[a-z_]{1,20}",
    ]
}

fn tool_name_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("bash".to_string()),
        Just("curl".to_string()),
        Just("psql".to_string()),
        Just("filesystem.read".to_string()),
        Just("http.fetch".to_string()),
        Just("terminal.exec".to_string()),
        "[a-z.]{1,30}",
    ]
}

fn taint_label_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("untrusted_user".to_string()),
        Just("external_tool".to_string()),
        Just("local_fs".to_string()),
        Just("secret".to_string()),
        Just("internal_api".to_string()),
        Just("shell_output".to_string()),
        Just("db_result".to_string()),
        Just("network_response".to_string()),
    ]
}

fn taint_set_strategy() -> impl Strategy<Value = HashSet<String>> {
    prop::collection::hash_set(taint_label_strategy(), 0..5)
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 7, Prompt Injection Firewall
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Risk score must always be in [0, 100].
    #[test]
    fn firewall_score_in_valid_range(text in "\\PC{0,2000}") {
        let result = prompt_firewall::scan_prompt(&text);
        prop_assert!(result.risk_score <= 100,
            "risk_score {} exceeds 100 for input len={}", result.risk_score, text.len());
    }

    /// blocked must be true iff risk_score >= 75.
    #[test]
    fn firewall_blocked_iff_score_gte_75(text in "\\PC{0,2000}") {
        let result = prompt_firewall::scan_prompt(&text);
        prop_assert_eq!(result.blocked, result.risk_score >= 75,
            "blocked={} but risk_score={}", result.blocked, result.risk_score);
    }

    /// Determinism: same input must always produce the same score and decision.
    #[test]
    fn firewall_deterministic(text in "\\PC{0,500}") {
        let r1 = prompt_firewall::scan_prompt(&text);
        let r2 = prompt_firewall::scan_prompt(&text);
        prop_assert_eq!(r1.risk_score, r2.risk_score, "non-deterministic score");
        prop_assert_eq!(r1.blocked, r2.blocked, "non-deterministic decision");
    }

    /// stages_run must be at least 2 (stage 1 and 2 always run).
    #[test]
    fn firewall_minimum_stages(text in "\\PC{0,1000}") {
        let result = prompt_firewall::scan_prompt(&text);
        prop_assert!(result.stages_run >= 2,
            "stages_run={} but minimum is 2", result.stages_run);
    }

    /// quick_scan must agree with scan_prompt.
    #[test]
    fn firewall_quick_scan_consistent(text in "\\PC{0,500}") {
        let full = prompt_firewall::scan_prompt(&text);
        let (blocked, score) = prompt_firewall::quick_scan(&text);
        prop_assert_eq!(full.blocked, blocked, "quick_scan blocked disagrees");
        prop_assert_eq!(full.risk_score, score, "quick_scan score disagrees");
    }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 2, Taint Tracking
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Accumulated labels must be a superset of inherited taints (monotonic).
    #[test]
    fn taint_accumulation_monotonic(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        payload in "\\PC{0,500}",
        inherited in taint_set_strategy(),
    ) {
        let result = taint_tracker::analyze_taint(&action, &tool, &payload, &inherited);
        for label in &inherited {
            prop_assert!(result.accumulated_labels.contains(label),
                "inherited label '{}' missing from accumulated", label);
        }
    }

    // ponytail: `taint_classify_sink_no_panic` and
    // `taint_classify_source_no_panic` used to sit here. Both are strictly
    // subsumed by `taint_analyze_no_panic` below: `analyze_taint` calls
    // `classify_source` and `classify_sink` unconditionally, with the
    // arguments passed straight through, and drives them over the SAME
    // generators. At 500 cases each that was 1,000 generated inputs reaching
    // no code the surviving property does not already reach.

    /// analyze_taint must not panic on arbitrary inputs.
    #[test]
    fn taint_analyze_no_panic(
        action in "\\PC{0,100}",
        tool in "\\PC{0,100}",
        payload in "\\PC{0,500}",
        inherited in taint_set_strategy(),
    ) {
        let _ = taint_tracker::analyze_taint(&action, &tool, &payload, &inherited);
    }

    /// Determinism: same inputs produce same result.
    #[test]
    fn taint_deterministic(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        payload in "[a-zA-Z0-9 /._]{0,200}",
        inherited in taint_set_strategy(),
    ) {
        let r1 = taint_tracker::analyze_taint(&action, &tool, &payload, &inherited);
        let r2 = taint_tracker::analyze_taint(&action, &tool, &payload, &inherited);
        prop_assert_eq!(r1.blocked, r2.blocked, "non-deterministic blocked");
        prop_assert_eq!(r1.exfiltration_detected, r2.exfiltration_detected,
            "non-deterministic exfiltration");
        prop_assert_eq!(r1.source_taints, r2.source_taints,
            "non-deterministic source taints");
    }

    /// Secret paths must be detected by classify_source.
    #[test]
    fn taint_detects_secret_paths(
        path in prop_oneof![
            Just(".env"),
            Just(".ssh/id_rsa"),
            Just("credentials.json"),
            Just("vault/secrets"),
            Just("config.pem"),
        ],
    ) {
        let payload = format!(r#"{{"path": "{}"}}"#, path);
        let labels = taint_tracker::classify_source("file_read", "filesystem.read", &payload);
        prop_assert!(labels.contains(&"secret".to_string()) || labels.contains(&"local_fs".to_string()),
            "secret path '{}' not detected, got labels: {:?}", path, labels);
    }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 4, Adaptive Risk Scoring
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// Total score must always be in [0, 100].
    #[test]
    fn adaptive_score_in_valid_range(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        payload in "[a-zA-Z0-9 /._]{0,200}",
        call_count in 0u32..100,
        trust in 0.0f64..=1.0,
    ) {
        let input = AdaptiveScoreInput {
            agent_id: "prop-test-agent",
            action_type: &action,
            tool_name: &tool,
            payload_str: &payload,
            taint_result: None,
            session_call_count: call_count,
            call_timestamps: &[],
            agent_trust: trust,
            tool_trust: trust,
        };
        let result = adaptive_scorer::calculate_adaptive_risk(&input, chrono::Utc::now());
        prop_assert!(result.total_score <= 100,
            "total_score {} exceeds 100", result.total_score);
    }

    /// Decision must be consistent with score thresholds.
    #[test]
    fn adaptive_decision_matches_thresholds(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        payload in "[a-zA-Z0-9 ]{0,100}",
        trust in 0.0f64..=1.0,
    ) {
        let input = AdaptiveScoreInput {
            agent_id: "prop-test-agent",
            action_type: &action,
            tool_name: &tool,
            payload_str: &payload,
            taint_result: None,
            session_call_count: 1,
            call_timestamps: &[],
            agent_trust: trust,
            tool_trust: trust,
        };
        let result = adaptive_scorer::calculate_adaptive_risk(&input, chrono::Utc::now());

        // Without exfiltration, decision must follow the score thresholds — and
        // "block" is not among them: this layer has no score-driven block arm,
        // so the only categorical route to a block is the exfiltration override,
        // which these generators never set.
        //
        // Reference the constant rather than restating it: this used to say
        // `>= 70` and silently became a SECOND, wrong source of truth when the
        // layer got its own threshold. It kept passing only because
        // `taint_result: None` pins `context_risk` to 0, which caps the
        // reachable score at 41.5 under these generators — so the band that
        // actually changed was never generated here. Widening the generators to
        // supply a taint result is what would make this property meaningful.
        prop_assert_ne!(result.decision.as_str(), "block",
            "score={} produced a block with no exfiltration flag; the \
             score-driven block arm was removed", result.total_score);
        if result.total_score >= adaptive_scorer::ADAPTIVE_THRESHOLD_REVIEW {
            prop_assert_eq!(result.decision, "human_review",
                "score={} should be human_review", result.total_score);
        } else {
            prop_assert_eq!(result.decision, "pass",
                "score={} should be pass", result.total_score);
        }
    }

    /// The signed ensemble always has the 4 signed signals (static, context,
    /// off-hours, reputation) plus the 2 advisory signals (behavioral, burst).
    #[test]
    fn adaptive_always_has_signed_and_advisory_signals(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        trust in 0.0f64..=1.0,
    ) {
        let input = AdaptiveScoreInput {
            agent_id: "prop-test-agent",
            action_type: &action,
            tool_name: &tool,
            payload_str: "",
            taint_result: None,
            session_call_count: 1,
            call_timestamps: &[],
            agent_trust: trust,
            tool_trust: trust,
        };
        let result = adaptive_scorer::calculate_adaptive_risk(&input, chrono::Utc::now());
        prop_assert_eq!(result.signals.len(), 4,
            "expected 4 signed signals, got {}", result.signals.len());
        prop_assert_eq!(result.advisory.len(), 2,
            "expected 2 advisory signals, got {}", result.advisory.len());
    }

    /// Exfiltration in taint must force block decision.
    #[test]
    fn adaptive_exfiltration_forces_block(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        trust in 0.0f64..=1.0,
    ) {
        let taint = iaga_sentinel::modules::taint::taint_tracker::TaintAnalysisResult {
            source_taints: vec!["secret".to_string()],
            sink_type: Some("network_egress".to_string()),
            accumulated_labels: HashSet::from(["secret".to_string()]),
            violations: vec![],
            blocked: true,
            exfiltration_detected: true,
            summary: "exfiltration".to_string(),
        };
        let input = AdaptiveScoreInput {
            agent_id: "prop-test-agent",
            action_type: &action,
            tool_name: &tool,
            payload_str: "",
            taint_result: Some(&taint),
            session_call_count: 1,
            call_timestamps: &[],
            agent_trust: trust,
            tool_trust: trust,
        };
        let result = adaptive_scorer::calculate_adaptive_risk(&input, chrono::Utc::now());
        let decision = result.decision.clone();
        prop_assert_eq!(decision, "block",
            "exfiltration_detected but decision={}", result.decision);
    }
}

// ═══════════════════════════════════════════════════════════════════
// LAYER 1, Session Graph / DAG
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// anomaly_score must be in [0, 100].
    #[test]
    fn session_anomaly_score_in_range(
        action in action_type_strategy(),
        tool in tool_name_strategy(),
        taints in taint_set_strategy(),
    ) {
        let session_id = format!("prop-session-{}", uuid::Uuid::new_v4());
        let result = session_dag::add_tool_call_to_session(
            &session_id, "prop-agent", &tool, &action, taints,
        );
        prop_assert!(result.anomaly_score <= 100,
            "anomaly_score {} exceeds 100", result.anomaly_score);
    }

    /// add_tool_call_to_session must not panic on arbitrary inputs.
    #[test]
    fn session_no_panic_arbitrary(
        action in "\\PC{0,50}",
        tool in "\\PC{0,50}",
        taints in taint_set_strategy(),
    ) {
        let session_id = format!("prop-panic-{}", uuid::Uuid::new_v4());
        let _ = session_dag::add_tool_call_to_session(
            &session_id, "prop-agent", &tool, &action, taints,
        );
    }

    /// First call to a new session with a known action type must be allowed.
    #[test]
    fn session_first_call_allowed(
        action in prop_oneof![
            Just("file_read".to_string()),
            Just("file_write".to_string()),
            Just("shell".to_string()),
            Just("http".to_string()),
            Just("db_query".to_string()),
            Just("email".to_string()),
        ],
        tool in tool_name_strategy(),
    ) {
        let session_id = format!("prop-first-{}", uuid::Uuid::new_v4());
        let result = session_dag::add_tool_call_to_session(
            &session_id, "prop-agent", &tool, &action, HashSet::new(),
        );
        prop_assert!(result.transition_allowed,
            "first call to new session should be allowed for action={}, got new_state={}", action, result.new_state);
    }

    /// Multiple calls to the same session must produce monotonically increasing node counts.
    #[test]
    fn session_node_ids_unique(
        actions in prop::collection::vec(action_type_strategy(), 2..5),
    ) {
        let session_id = format!("prop-multi-{}", uuid::Uuid::new_v4());
        let mut node_ids = Vec::new();
        for action in &actions {
            let result = session_dag::add_tool_call_to_session(
                &session_id, "prop-agent", "test-tool", action, HashSet::new(),
            );
            if !result.node_id.is_empty() {
                node_ids.push(result.node_id.clone());
            }
        }
        let unique: HashSet<_> = node_ids.iter().collect();
        prop_assert_eq!(unique.len(), node_ids.len(),
            "duplicate node IDs in session: {:?}", node_ids);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Receipt signing-bytes round-trip determinism (TESTS-FUZZ-NO-DETERMINISM-10)
// ═══════════════════════════════════════════════════════════════════

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// `signing_bytes` must be a serialize -> parse -> serialize **fixpoint**:
    /// re-serializing a parsed receipt yields byte-identical output. This guards
    /// against a field that does not round-trip cleanly (lost data, or a nested
    /// JSON map whose key order is not canonical), which would let two encodings
    /// of the same verdict produce different signed bytes / chain hashes. The
    /// nested `ml_scores` map is generated with arbitrary (and possibly
    /// out-of-order, duplicate) keys to exercise the risky path.
    #[test]
    fn signing_bytes_roundtrip_is_a_fixpoint(
        keys in prop::collection::vec("[a-z]{1,8}", 0..8),
        vals in prop::collection::vec(any::<i64>(), 0..8),
        reasons in prop::collection::vec("[ -~]{0,40}", 0..4),
        risk in any::<u32>(),
        feed in proptest::option::of("[0-9a-f]{64}"),
    ) {
        use iaga_sentinel_receipts::{MlScoreBundle, ReceiptBody, Verdict};

        let mut map = serde_json::Map::new();
        for (k, v) in keys.iter().zip(vals.iter()) {
            map.insert(k.clone(), serde_json::json!(v));
        }
        let body = ReceiptBody {
            run_id: "fuzz-run".into(),
            seq: 0,
            parent_hash: None,
            input_hash: "a".repeat(64),
            policy_hash: "b".repeat(64),
            threat_feed_hash: feed,
            plugin_digests: vec![],
            model_digests: vec![],
            ml_scores: Some(MlScoreBundle(serde_json::Value::Object(map))),
            verdict: Verdict::Review,
            reasons,
            risk_score: risk,
            timestamp: "2026-01-01T00:00:00Z".into(),
            signer_key_id: "ed25519:fuzz".into(),
            pipeline_inputs_capture: None,
            apl_eval_trace: None,
            ml_inference_inputs: None,
            is_authoritative: None,
            usage: None,
        };

        let s1 = body.signing_bytes().expect("signing_bytes s1");
        let parsed: ReceiptBody = serde_json::from_slice(&s1).expect("parse");
        let s2 = parsed.signing_bytes().expect("signing_bytes s2");
        prop_assert_eq!(s1, s2, "signing_bytes must be a serialize->parse fixpoint");
    }
}
