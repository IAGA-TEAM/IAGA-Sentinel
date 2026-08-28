//! A capability token's signature covers `expires_at` **as a string**, so the
//! string a backend hands back has to be byte-identical to the one that was
//! signed. On SQLite it is: the column is TEXT and sqlx returns what was
//! written. On Postgres it is not: `0008_capability_tokens.sql` declares
//! `expires_at TIMESTAMPTZ`, and `PostgresStore::get_capability_token` renders
//! it back with
//!
//! ```sql
//! to_char(expires_at, 'YYYY-MM-DD"T"HH24:MI:SS.US+00:00')
//! ```
//!
//! which always emits **exactly six** fractional digits, while
//! `chrono::DateTime::to_rfc3339` emits **zero, three, six or nine** depending
//! on the value (`SecondsFormat::AutoSi`).
//!
//! These tests run without a Postgres server: they apply the exact rendering
//! that `to_char` applies and then ask the production verifier whether the
//! token still verifies. The `receipts` table is the counter-example that shows
//! this was a known shape in this repository — its `timestamp` column is TEXT on
//! Postgres too, precisely because the value is signed.

use chrono::{DateTime, SecondsFormat, Utc};
use iaga_sentinel::modules::nhi::crypto_identity::{
    issue_capability_token, register_identity, verify_token_signature, CapabilityToken,
};

/// Exactly what `to_char(ts, 'YYYY-MM-DD"T"HH24:MI:SS.US+00:00')` produces for
/// a `TIMESTAMPTZ` under a UTC session, which is what the pool sets.
///
/// `US` is microseconds, zero-padded to six digits, always present.
fn as_postgres_renders_it(rfc3339: &str) -> String {
    let parsed: DateTime<Utc> = DateTime::parse_from_rfc3339(rfc3339)
        .expect("mint must emit RFC3339")
        .with_timezone(&Utc);
    // TIMESTAMPTZ stores microseconds, so anything finer is truncated on write.
    parsed.to_rfc3339_opts(SecondsFormat::Micros, false)
}

/// The whole defect in one assertion, at the level a Postgres deployment sees.
///
/// One mint is not enough to state this deterministically: a timestamp whose
/// nanoseconds happen to be an exact multiple of 1000 renders the same either
/// way and passes by luck. Minting many and requiring **every** one to survive
/// removes the luck, and the failure direction is always toward red — a token
/// that verifies is never reported as broken.
#[test]
fn every_minted_token_verifies_after_the_postgres_timestamp_round_trip() {
    let agent = "cap-pg-roundtrip";
    register_identity(agent, None, vec![]);

    let mut broken: Vec<(String, String)> = Vec::new();
    for _ in 0..64 {
        let token = issue_capability_token(agent, vec!["read:self".to_string()], 3600)
            .expect("agent is registered");

        let round_tripped = CapabilityToken {
            expires_at: as_postgres_renders_it(&token.expires_at),
            ..token.clone()
        };

        if !verify_token_signature(&round_tripped) {
            broken.push((token.expires_at.clone(), round_tripped.expires_at.clone()));
        }
    }

    assert!(
        broken.is_empty(),
        "{} of 64 tokens stopped verifying after a Postgres TIMESTAMPTZ round trip. \
         The signature covers `expires_at` verbatim, so the minted rendering must be the \
         one Postgres renders back. First three (signed -> read back):\n  {}",
        broken.len(),
        broken
            .iter()
            .take(3)
            .map(|(a, b)| format!("{a}  ->  {b}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// The invariant stated directly, so a future change to the mint that
/// reintroduces variable precision fails here with an obvious message rather
/// than through a signature check three layers away.
#[test]
fn the_minted_expiry_is_already_at_microsecond_precision() {
    let agent = "cap-pg-precision";
    register_identity(agent, None, vec![]);

    for _ in 0..64 {
        let token =
            issue_capability_token(agent, vec!["read:self".to_string()], 3600).expect("registered");
        assert_eq!(
            token.expires_at,
            as_postgres_renders_it(&token.expires_at),
            "expiresAt must be minted at the precision every backend renders back"
        );
        assert_eq!(
            token.issued_at,
            as_postgres_renders_it(&token.issued_at),
            "issuedAt is rendered by the same to_char and is returned to the caller"
        );
    }
}
