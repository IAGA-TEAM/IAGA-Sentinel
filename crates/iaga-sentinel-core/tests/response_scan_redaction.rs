//! `redactedPayload` must not hand back the secret it just found.
//!
//! The sensitive-pattern table drives BOTH the finding and the redaction: every
//! match is replaced by that pattern's `redact_with` marker. So a pattern that
//! matches less than the secret redacts less than the secret, and the leftover
//! is published in the one field whose entire purpose is to be safe to show.
//!
//! `private_key_block` matched only the BEGIN line
//! (`-----BEGIN\s+(RSA\s+|EC\s+|...)?PRIVATE KEY-----`), so a PEM came back as
//! `[REDACTED-PRIVATE-KEY]\n<the entire key body>\n-----END RSA PRIVATE KEY-----`
//! — correctly flagged, correctly blocked, and still fully disclosed. The
//! marker made it look handled, which is worse than an obvious miss.
//!
//! Measured against a live 2.1.0 server before the fix, `/v1/response/scan` on
//! a 60-character RSA body returned every one of those characters in
//! `redactedPayload`.

use std::collections::HashMap;

use iaga_sentinel::core::types::ResponseScanRequest;
use iaga_sentinel::pipeline::execute_pipeline::scan_response;

fn scan(payload: &str) -> (String, Vec<String>) {
    let req = ResponseScanRequest {
        request_id: "redaction-test".into(),
        agent_id: "redaction-agent".into(),
        tool_name: "tool.output".into(),
        response_payload: serde_json::json!(payload),
        metadata: Some(HashMap::new()),
    };
    let out = scan_response(&req);
    (
        serde_json::to_string(&out.redacted_payload).unwrap_or_default(),
        out.findings,
    )
}

/// The body of a PEM private key must not survive redaction.
///
/// The marker string is deliberately long and unique so a partial redaction
/// cannot pass by accident.
#[test]
fn a_pem_private_key_body_is_not_returned_in_the_redacted_payload() {
    let body = "MIIEowIBAAKCAQEA".to_string() + &"J".repeat(60);
    for header in [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
    ] {
        let footer = header.replace("BEGIN", "END");
        let payload = format!("{header}\n{body}\n{footer}");
        let (redacted, findings) = scan(&payload);

        assert!(
            findings.iter().any(|f| f.contains("private_key_block")),
            "{header}: the key must still be FOUND, findings: {findings:?}"
        );
        assert!(
            !redacted.contains(&body),
            "{header}: the key body is still in redactedPayload: {redacted}"
        );
        assert!(
            !redacted.contains(&footer),
            "{header}: the PEM footer is still in redactedPayload: {redacted}"
        );
        assert!(
            redacted.contains("[REDACTED-PRIVATE-KEY]"),
            "{header}: the marker is missing: {redacted}"
        );
    }
}

/// A truncated key — BEGIN with no END — must not leak either.
///
/// This is the case a narrower "match the whole block" fix would miss: with no
/// END marker an anchored block pattern does not match at all, which would have
/// been a REGRESSION on the header-only behaviour rather than a fix.
#[test]
fn a_pem_private_key_without_its_end_marker_is_still_fully_redacted() {
    let body = "MIIEowIBAAKCAQEA".to_string() + &"K".repeat(60);
    let payload = format!("-----BEGIN RSA PRIVATE KEY-----\n{body}");
    let (redacted, findings) = scan(&payload);

    assert!(
        findings.iter().any(|f| f.contains("private_key_block")),
        "a truncated key must still be found, findings: {findings:?}"
    );
    assert!(
        !redacted.contains(&body),
        "truncated key body still disclosed: {redacted}"
    );
}

/// Two keys in one payload are both redacted, and the text between them is kept.
///
/// Guards the obvious over-correction: a greedy block match would swallow
/// everything from the first BEGIN to the last END, silently eating any content
/// in between and reporting one occurrence where there are two.
#[test]
fn two_keys_are_redacted_separately_and_the_text_between_them_survives() {
    let a = "MIIEowIBAAKCAQEA".to_string() + &"A".repeat(60);
    let b = "MIIEowIBAAKCAQEA".to_string() + &"B".repeat(60);
    let payload = format!(
        "-----BEGIN RSA PRIVATE KEY-----\n{a}\n-----END RSA PRIVATE KEY-----\n\
         KEEP-THIS-MIDDLE-TEXT\n\
         -----BEGIN EC PRIVATE KEY-----\n{b}\n-----END EC PRIVATE KEY-----"
    );
    let (redacted, findings) = scan(&payload);

    assert!(!redacted.contains(&a), "first key body leaked: {redacted}");
    assert!(!redacted.contains(&b), "second key body leaked: {redacted}");
    assert!(
        redacted.contains("KEEP-THIS-MIDDLE-TEXT"),
        "redaction swallowed the text between the two keys: {redacted}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f.contains("private_key_block") && f.contains('2')),
        "two keys must be reported as two occurrences, findings: {findings:?}"
    );
}

/// An ordinary payload with no secret raises no key finding.
///
/// `redactedPayload` is `null` when nothing matched — there is nothing to
/// redact — so this asserts on the findings, not on the payload. (Asserting on
/// the payload here is a harness error I made first and had to correct.)
#[test]
fn a_clean_payload_raises_no_private_key_finding() {
    let payload = "the deploy finished, see -----BEGIN NOTES----- for details";
    let (redacted, findings) = scan(payload);
    assert!(
        !findings.iter().any(|f| f.contains("private_key_block")),
        "no key here, findings: {findings:?}"
    );
    assert_eq!(redacted, "null", "nothing matched, so nothing is redacted");
}
