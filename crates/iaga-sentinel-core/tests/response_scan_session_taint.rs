//! `/v1/response/scan` must not inherit a session's SOURCE labels as if the
//! response were an egress sink.
//!
//! `scan_response` passed `"http"` to the taint layer, which maps to
//! `SinkType::NetworkEgress`, whose forbidden set includes `LOCAL_FS` and
//! `DB_RESULT`. The inherited session labels are folded in before the check, so
//! one `file_read` anywhere in a session made EVERY later response scan in that
//! session Block at risk 80 regardless of what came back. The ordinary
//! "read a file, then summarise it" flow was broken deterministically from the
//! second step, and each false Block also wrote a signed audit record.
//!
//! Its own test binary because it drives the process-global `SESSION_TAINTS`
//! map; sharing a binary with unrelated cases is how that turns flaky.
//!
//! Every test uses a session id of its own and NEVER calls `reset_sessions()`:
//! that helper clears the whole map, so under the default parallel runner one
//! test wipes the session another has just seeded. Unique ids give each test the
//! clean slate the reset was reaching for, without the shared-state race.

use std::collections::{HashMap, HashSet};

use iaga_sentinel::core::types::{ResponseDecision, ResponseScanRequest};
use iaga_sentinel::modules::taint::taint_tracker;
use iaga_sentinel::pipeline::execute_pipeline::scan_response;

const SESSION: &str = "sess-response-scan-taint";
const SESSION_NO_META: &str = "sess-response-scan-no-metadata";

fn request(session: &str, payload: serde_json::Value) -> ResponseScanRequest {
    let mut metadata = HashMap::new();
    metadata.insert(
        "sessionId".to_string(),
        serde_json::Value::String(session.to_string()),
    );
    ResponseScanRequest {
        request_id: "req-1".to_string(),
        agent_id: "agent-response-scan".to_string(),
        tool_name: "summarise".to_string(),
        response_payload: payload,
        metadata: Some(metadata),
    }
}

/// Replays what `/v1/inspect` does for a `file_read`: LOCAL_FS lands in the
/// session's accumulated label set.
fn seed_file_read(session: &str) {
    let result = taint_tracker::analyze_taint(
        "file_read",
        "Read",
        r#"{"path":"README.md"}"#,
        &HashSet::new(),
    );
    taint_tracker::update_session_taint(session, &result.accumulated_labels);
    assert!(
        taint_tracker::get_session_taint(session).contains(taint_tracker::LOCAL_FS),
        "precondition: the file_read must have tainted the session with local_fs"
    );
}

#[test]
fn read_a_file_then_summarise_it_is_not_blocked() {
    seed_file_read(SESSION);

    let result = scan_response(&request(
        SESSION,
        serde_json::json!({ "summary": "The README explains how to install the CLI." }),
    ));

    assert_eq!(
        result.decision,
        ResponseDecision::Allow,
        "a benign summary must not be blocked because the session read a file \
         earlier: risk={} findings={:?}",
        result.risk_score,
        result.findings
    );
    assert!(
        result.risk_score < 80,
        "risk must not be forced to the block floor: {}",
        result.risk_score
    );
    assert!(
        !result.findings.iter().any(|f| f.contains("exfiltration")),
        "no exfiltration evidence may be recorded for inbound data: {:?}",
        result.findings
    );
}

/// The same request without the session id already worked; pinning it proves
/// the fix is about the inherited labels and not about the payload.
#[test]
fn the_same_response_without_a_session_is_also_allowed() {
    let mut req = request(
        SESSION_NO_META,
        serde_json::json!({ "summary": "all good" }),
    );
    req.metadata = None;
    let result = scan_response(&req);

    assert_eq!(result.decision, ResponseDecision::Allow);
}

/// COVERAGE GUARD, and the reason this file exists in the shape it does.
///
/// Catching a credential coming back from a tool is what this endpoint is FOR,
/// and it is the thing most easily destroyed while fixing the false positive
/// above: SECRET is forbidden at the egress sink too, so retargeting the sink
/// without keeping SECRET *blocking* silently turns every leaked key into an
/// Allow. An earlier draft of this very fix did exactly that -- measured against
/// 2.0.2, every `.cred/*` case in the audit corpus went Block/80 -> Allow/0.
#[test]
fn a_credential_in_the_response_is_still_blocked() {
    for (label, payload) in [
        (
            "anthropic",
            "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("aws", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI7EXAMPLEKEY"),
        ("openai", "sk-AAAAAAAAAAAAAAAAAAAAAAAA"),
    ] {
        let result = scan_response(&request(
            &format!("sess-cred-{label}"),
            serde_json::json!({ "body": payload }),
        ));

        assert_eq!(
            result.decision,
            ResponseDecision::Block,
            "a {label} credential in a tool response must be blocked: {:?}",
            result.findings
        );
        assert!(
            result.risk_score >= 80,
            "a leaked credential must score at the block floor, got {}",
            result.risk_score
        );
    }
}

/// Blocked on its OWN content, with no session history at all.
#[test]
fn a_credential_is_blocked_without_any_session() {
    let mut req = request(
        "unused",
        serde_json::json!({ "body": "sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" }),
    );
    req.metadata = None;

    assert_eq!(scan_response(&req).decision, ResponseDecision::Block);
}

/// Inherited session labels describe what the SESSION touched, not what this
/// payload contains, so they must not decide this verdict in either direction.
/// A `.env` read earlier in the session leaves SECRET on the session; a later
/// clean response is still clean.
#[test]
fn an_inherited_secret_label_does_not_block_a_clean_response() {
    let session = "sess-inherited-secret";
    let mut labels = HashSet::new();
    labels.insert(taint_tracker::SECRET.to_string());
    taint_tracker::update_session_taint(session, &labels);

    let result = scan_response(&request(session, serde_json::json!({ "summary": "ok" })));

    assert_eq!(
        result.decision,
        ResponseDecision::Allow,
        "the session's history is not this response's content: {:?}",
        result.findings
    );
}
