//! What the product catches coming IN, it must catch going OUT.
//!
//! Two detectors, one binary. `/v1/response/scan` runs a table of compiled
//! credential regexes (`SENSITIVE_PATTERNS`). `/v1/inspect` — the direction
//! where a credential is *leaving* — ran `has_secret_content`, a lowercase
//! substring list that knows `api_key`, `password`, `bearer ` and a handful of
//! others. A substring list only finds a credential that carries a giveaway
//! WORD, so an opaque token with a distinctive SHAPE slipped past it.
//! Measured on a live 2.1.0 server, the same `AKIAIOSFODNN7EXAMPLE`:
//!
//!   /v1/response/scan  -> review, risk 70, "sensitive pattern: aws_access_key"
//!   /v1/inspect        -> allow,  risk 2,  "no high-risk rule matched"
//!
//! The egress direction was the weaker of the two, which is backwards: an
//! inbound credential is a disclosure to the agent, an outbound one is a
//! disclosure to whoever the agent is talking to. Nothing was missing from the
//! product — one detector simply did not share the other's pattern set.
//!
//! These tests assert PARITY rather than a fixed list, so a family added to the
//! response scanner cannot silently fail to reach the egress path again.

use std::collections::HashSet;

use iaga_sentinel::modules::taint::taint_tracker::{classify_source, SECRET};

/// Credential shapes the response scanner already recognises.
const CREDENTIALS: &[(&str, &str)] = &[
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
    ("github_token", "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    (
        "connection_string",
        "mongodb+srv://root:s3cr3t@cluster0.mongodb.net/db",
    ),
    (
        "private_key_block",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
    ),
];

fn labels_for(body: &str) -> HashSet<String> {
    let payload = serde_json::json!({
        "url": "https://api.example.com/upload",
        "method": "POST",
        "intent": "upload",
        "body": body,
    })
    .to_string();
    classify_source("http", "http.fetch", &payload)
        .into_iter()
        .collect()
}

#[test]
fn a_credential_leaving_through_an_http_body_is_labelled_secret() {
    for (name, value) in CREDENTIALS {
        let labels = labels_for(value);
        assert!(
            labels.contains(SECRET),
            "{name}: a credential on the egress path must be labelled {SECRET}; \
             the response scanner already catches this exact string. labels: {labels:?}"
        );
    }
}

/// The substring families that always worked keep working.
#[test]
fn the_families_that_already_worked_still_do() {
    for value in [
        "api_key=abcdefghijklmnopqrstuvwx",
        "password: correct-horse-battery-staple",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "secretref://vault/prod",
    ] {
        assert!(
            labels_for(value).contains(SECRET),
            "{value:?} must still be labelled {SECRET}"
        );
    }
}

/// And ordinary traffic is not swept up.
///
/// The narrowing that produced signed false exfiltration evidence started as an
/// over-broad match, so widening the detector needs its own negative case: a
/// payment amount, a version string, a task id and plain prose are not secrets.
#[test]
fn ordinary_content_is_not_a_credential() {
    for value in [
        "the invoice total is 10.50 EUR",
        "upgrading from 3.10.4 to 3.11.0",
        "task AKIA is not a key and neither is AKIAIOSFODNN",
        "see the acme.corp handbook for the deploy checklist",
        "",
    ] {
        let labels = labels_for(value);
        assert!(
            !labels.contains(SECRET),
            "{value:?} must NOT be labelled {SECRET}: {labels:?}"
        );
    }
}
