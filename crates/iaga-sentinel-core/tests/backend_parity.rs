//! Backend parity: the values a workspace policy is GOVERNED by must survive a
//! round-trip through Postgres unchanged, and must match what SQLite returns.
//!
//! This file exists because of a bug that nothing could have caught. Four
//! columns in `workspace_policies` / `audit_events` / `review_requests` are
//! declared `INTEGER` (int4), and `pg_row_to_*` read them as `i64`. sqlx's
//! Postgres type check is strict equality against `INT8`, so every one of those
//! reads was REJECTED at decode time and `unwrap_or` silently substituted the
//! fallback constant. Effect: every workspace was governed at 70/35 whatever it
//! had configured, and since `threshold_block` / `threshold_review` feed
//! `workspace_policy_hash`, the wrong values were bound into every signed
//! receipt.
//!
//! Two gaps let that ship:
//!
//!  1. `iaga-sentinel-core` had NO Postgres integration test. The CI step that
//!     runs `cargo test -p iaga-sentinel-core --features postgres` against a
//!     live `postgres:16` service already existed — it was simply vacuous,
//!     because no test in this crate touched a Postgres decode path.
//!  2. `clippy` runs at default features, and `postgres` is not one of them, so
//!     `storage/postgres.rs` was never linted.
//!
//! The fix keeps the shape that hid the bug — `unwrap_or_else(|e| { warn!();
//! constant })` — so a wrong width still degrades to a constant plus a log line
//! nobody asserts. Therefore these tests assert the VALUE, never the log.
//!
//! Follows `iaga-sentinel-receipts/tests/postgres_store.rs`: the suite runs when
//! `IAGA_SENTINEL_TEST_PG_URL` is set and skips cleanly otherwise, so
//! `cargo test --features postgres` still passes on a machine with no database.
//! Deliberately NOT `#[ignore]` — an ignored test reports as "not run" in a way
//! that reads the same whether the database was absent or the suite was
//! forgotten.

#![cfg(feature = "postgres")]

use std::sync::OnceLock;

use iaga_sentinel::auth::api_keys::generate_api_key;
use iaga_sentinel::core::types::{
    ActionType, GovernanceDecision, ProtocolKind, ReviewRequest, ReviewStatus, StoredAuditEvent,
    ToolPolicy, WorkspacePolicy,
};
use iaga_sentinel::modules::nhi::crypto_identity::{
    issue_capability_token, register_identity, verify_token_signature,
};
use iaga_sentinel::storage::postgres::PostgresStorage;
use iaga_sentinel::storage::traits::{
    ApiKeyStore, AuditStore, KeyScope, NhiStore, PolicyStore, ReviewStore,
};

/// Values chosen so that a decode failure is unmistakable: each differs from
/// its own fallback constant (70 / 35) AND from the other, so an implementation
/// that returns a constant — either the fallback or the other column's value —
/// fails. `threshold_block = 55` is exactly the bug: under the i64 read it came
/// back 70.
const BLOCK: u32 = 55;
const REVIEW: u32 = 22;
/// Distinct from both thresholds so a cross-wired column is visible too.
const RISK: u32 = 41;

/// Serializes the cases: they share fixed row ids in one database, so two of
/// them running concurrently would delete each other's fixtures. Mirrors
/// `postgres_store.rs`.
static TEST_LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();

fn test_lock() -> &'static tokio::sync::Mutex<()> {
    TEST_LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Opens a store against `IAGA_SENTINEL_TEST_PG_URL`, or `None` to skip.
///
/// The skip is ANNOUNCED. Silence here is how the whole point of this file gets
/// lost: with no database reachable every case returns early and reports `ok`,
/// so a green `cargo test --features postgres` reads identically whether the
/// assertions ran or whether nothing did. `postgres_store.rs` prints its skips
/// for the same reason.
async fn pg_store(case: &str) -> Option<PostgresStorage> {
    let Some(url) = std::env::var("IAGA_SENTINEL_TEST_PG_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
    else {
        eprintln!(
            "skipped: {case} — IAGA_SENTINEL_TEST_PG_URL unset, so NO Postgres decode path \
             was exercised by this run"
        );
        return None;
    };
    Some(
        PostgresStorage::new(&url)
            .await
            .expect("open postgres storage"),
    )
}

fn policy(workspace_id: &str) -> WorkspacePolicy {
    WorkspacePolicy {
        workspace_id: workspace_id.into(),
        tenant_id: None,
        allowed_protocols: vec![ProtocolKind::HttpFunction],
        tools: vec![ToolPolicy {
            tool_name: "http.fetch".into(),
            allowed_action_types: vec![ActionType::Http],
            max_decision: GovernanceDecision::Allow,
            requires_human_review: false,
            ..Default::default()
        }],
        allowed_domains: vec!["api.github.com".into()],
        threshold_block: BLOCK,
        threshold_review: REVIEW,
    }
}

/// B2, directly: the thresholds a workspace is governed by must come back as
/// they were stored.
#[tokio::test]
async fn workspace_thresholds_survive_a_postgres_round_trip() {
    let _guard = test_lock().lock().await;
    let Some(store) = pg_store("workspace_thresholds_survive_a_postgres_round_trip").await else {
        return;
    };
    let ws = "parity-thresholds";
    store.upsert_workspace(&policy(ws)).await.expect("upsert");

    let got = store.get_workspace_policy(ws).await.expect("read back");

    assert_eq!(
        got.threshold_block,
        BLOCK,
        "threshold_block came back {} instead of {BLOCK}. {} means the INTEGER \
         column failed to decode and the fallback constant was substituted — \
         the workspace is governed at a threshold it never configured, and that \
         value is bound into every signed receipt via workspace_policy_hash.",
        got.threshold_block,
        if got.threshold_block == 70 {
            "70 specifically"
        } else {
            "That"
        }
    );
    assert_eq!(
        got.threshold_review, REVIEW,
        "threshold_review came back {} instead of {REVIEW}",
        got.threshold_review
    );

    store.delete_workspace(ws).await.expect("cleanup");
}

/// The same decode path on the audit read. `risk_score` is the column whose
/// measured symptom was "every row reported riskScore 0".
#[tokio::test]
async fn audit_risk_score_survives_a_postgres_round_trip() {
    let _guard = test_lock().lock().await;
    let Some(store) = pg_store("audit_risk_score_survives_a_postgres_round_trip").await else {
        return;
    };
    // Nonce: the event_id is the primary key, so a fixed one makes this pass
    // exactly once per database and then fail on duplicate-key forever after.
    let event_id = format!("parity-risk-score-{}", uuid::Uuid::new_v4().simple());
    let event = StoredAuditEvent {
        event_id: event_id.clone(),
        agent_id: "parity-agent".into(),
        tenant_id: None,
        framework: "test".into(),
        action_type: ActionType::Http,
        tool_name: "http.fetch".into(),
        input_sha256: String::new(),
        decision: GovernanceDecision::Allow,
        timestamp: "2026-08-07T12:00:00Z".into(),
        reasons: vec!["parity".into()],
        review_status: ReviewStatus::NotRequired,
        risk_score: RISK,
        usage: None,
        session_id: None,
    };
    store.append(&event).await.expect("append");

    let rows = AuditStore::list(&store, 200).await.expect("list");
    let found = rows
        .iter()
        .find(|r| r.event_id == event_id)
        .expect("the appended event is readable");

    assert_eq!(
        found.risk_score, RISK,
        "risk_score came back {} instead of {RISK}; 0 means the INTEGER column \
         failed to decode and every audit row is reporting a risk it never had",
        found.risk_score
    );
}

/// The Postgres half of "the audit read is chronological".
///
/// `tests/audit_read_order.rs` pins this for SQLite, where the bug lived — the
/// column default was whole seconds, so `event_id DESC` (a UUID) became the real
/// order. Postgres never had that symptom, but it had the other half of the same
/// defect: `created_at` defaulted to `NOW()`, the moment the write-behind task
/// landed, not the moment the decision was made. Both INSERTs now bind the
/// pipeline's decision time, and nothing here would have failed if the Postgres
/// bind were reverted — so this is that witness.
///
/// The rows are appended in the WRONG order on purpose, with ids whose UUID sort
/// disagrees with their chronology, so only a read that orders by the bound
/// timestamp can pass.
#[tokio::test]
async fn the_postgres_audit_read_is_ordered_by_decision_time() {
    let _guard = test_lock().lock().await;
    let Some(store) = pg_store("the_postgres_audit_read_is_ordered_by_decision_time").await else {
        return;
    };

    // A nonce per run: the ids are the assertion, so rows left by an earlier run
    // (or by a deliberately-reverted counterfactual build) must not be read back
    // as if this run had written them.
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let agent = format!("parity-chrono-{nonce}");
    let ids = [
        format!("zz-{nonce}"),
        format!("aa-{nonce}"),
        format!("mm-{nonce}"),
    ];
    // Written newest-first; must read back newest-first regardless.
    let rows = [
        (&ids[0], "2026-08-07T12:00:00.300000Z"),
        (&ids[1], "2026-08-07T12:00:00.100000Z"),
        (&ids[2], "2026-08-07T12:00:00.200000Z"),
    ];
    for (event_id, ts) in rows {
        let event = StoredAuditEvent {
            event_id: event_id.clone(),
            agent_id: agent.clone(),
            tenant_id: None,
            framework: "test".into(),
            action_type: ActionType::Http,
            tool_name: "http.fetch".into(),
            input_sha256: String::new(),
            decision: GovernanceDecision::Allow,
            timestamp: ts.into(),
            reasons: vec![],
            review_status: ReviewStatus::NotRequired,
            risk_score: 1,
            usage: None,
            session_id: None,
        };
        store.append(&event).await.expect("append");
    }

    let listed = AuditStore::list(&store, 500).await.expect("list");
    let got: Vec<&str> = listed
        .iter()
        .filter(|r| r.agent_id == agent)
        .map(|r| r.event_id.as_str())
        .collect();

    assert_eq!(
        got,
        vec![ids[0].as_str(), ids[2].as_str(), ids[1].as_str()],
        "the Postgres audit read must be newest-first by DECISION time. Rows were \
         appended zz, aa, mm; only an order that reads the bound decision time \
         yields zz, mm, aa. If this regresses, check the bound value in the \
         INSERT, not the ORDER BY. got {got:?}"
    );
}

/// The FOURTH `INTEGER` column, and the only one of the four with no coverage
/// at all until now: `review_requests.risk_score`, decoded in `pg_row_to_review`.
///
/// It matters more than its obscurity suggests. A review request is what a human
/// is shown before approving an action; a risk score that silently reads back as
/// 0 means the reviewer is asked to sign off on something the console tells them
/// is harmless. Same decode bug, but the symptom lands on a person rather than
/// in a log.
#[tokio::test]
async fn review_risk_score_survives_a_postgres_round_trip() {
    let _guard = test_lock().lock().await;
    let Some(store) = pg_store("review_risk_score_survives_a_postgres_round_trip").await else {
        return;
    };
    // Same reason as the audit case above: a fixed primary key makes this
    // single-use per database.
    let id = format!("parity-review-risk-{}", uuid::Uuid::new_v4().simple());
    let review = ReviewRequest {
        id: id.clone(),
        agent_id: "parity-agent".into(),
        workspace_id: "parity-ws".into(),
        tool_name: "terminal.exec".into(),
        decision: GovernanceDecision::Review,
        status: "pending".into(),
        risk_score: RISK,
        reasons: vec!["parity".into()],
        created_at: "2026-08-09T12:00:00Z".into(),
        updated_at: "2026-08-09T12:00:00Z".into(),
    };
    ReviewStore::create(&store, &review).await.expect("create");

    let got = ReviewStore::get(&store, &id).await.expect("read back");

    assert_eq!(
        got.risk_score, RISK,
        "review risk_score came back {} instead of {RISK}; 0 means a reviewer is \
         being shown a risk the request never had",
        got.risk_score
    );
}

/// Parity proper: the two backends must agree. Asserting Postgres against a
/// literal proves it decodes; asserting it against SQLite proves the two
/// backends cannot silently diverge, which is the class of bug B2 belonged to.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn both_backends_return_the_same_thresholds() {
    let _guard = test_lock().lock().await;
    let Some(pg) = pg_store("both_backends_return_the_same_thresholds").await else {
        return;
    };
    let ws = "parity-cross-backend";

    let sqlite = iaga_sentinel::storage::sqlite::SqliteStorage::new("sqlite::memory:")
        .await
        .expect("open sqlite storage");

    sqlite.upsert_workspace(&policy(ws)).await.expect("upsert");
    pg.upsert_workspace(&policy(ws)).await.expect("upsert");

    let from_sqlite = sqlite.get_workspace_policy(ws).await.expect("sqlite read");
    let from_pg = pg.get_workspace_policy(ws).await.expect("postgres read");

    assert_eq!(
        (from_pg.threshold_block, from_pg.threshold_review),
        (from_sqlite.threshold_block, from_sqlite.threshold_review),
        "the backends disagree on the governing thresholds: postgres {:?} vs \
         sqlite {:?}",
        (from_pg.threshold_block, from_pg.threshold_review),
        (from_sqlite.threshold_block, from_sqlite.threshold_review),
    );

    pg.delete_workspace(ws).await.expect("cleanup");
}

// ── 2.1.0: the two tables this release adds ──
//
// `0008_capability_tokens` and `0009_api_key_agent_binding` reach a live
// Postgres in CI only as DDL: `PostgresStorage::new` runs the migrator, so the
// schema is exercised, but until these two cases nothing read a row back. Both
// tables are on an authorization path, and both have the shape that produced
// the 2.0.1 incident this file was written for — a value that is signed or
// compared, crossing a column whose Postgres type differs from SQLite's
// (`TIMESTAMPTZ` vs `TEXT`, and a nullable `agent_id` that decides whether a
// key fails closed).

/// The signature covers `expires_at` **as a string**, and on Postgres that
/// string is re-rendered by `to_char` on the way out. `capability_token_pg_roundtrip.rs`
/// proves the rendering is lossless by simulating it; this proves the real
/// column does the same thing, which is the half a simulation cannot.
#[tokio::test]
async fn a_capability_token_still_verifies_after_a_postgres_round_trip() {
    let _guard = test_lock().lock().await;
    let Some(store) =
        pg_store("a_capability_token_still_verifies_after_a_postgres_round_trip").await
    else {
        return;
    };

    let agent = "parity-capability-token";
    register_identity(agent, None, vec![]);
    let token = issue_capability_token(agent, vec!["read:self".to_string()], 3600)
        .expect("agent is registered");

    store
        .store_capability_token(&token)
        .await
        .expect("store token");
    let back = store
        .get_capability_token(&token.token_id)
        .await
        .expect("read token")
        .expect("the token that was just stored must come back");

    assert_eq!(back.agent_id, token.agent_id);
    assert_eq!(back.capabilities, token.capabilities);
    assert!(back.valid, "a freshly issued token must come back valid");
    assert!(
        verify_token_signature(&back),
        "the token stopped verifying after Postgres: expires_at was signed as {:?} \
         and came back as {:?}",
        token.expires_at,
        back.expires_at,
    );

    assert!(
        store
            .revoke_capability_token(&token.token_id)
            .await
            .expect("revoke"),
        "revoking a token that exists must report that it did",
    );
}

/// `0009` adds `api_keys.agent_id`. The whole guard rests on that column
/// surviving the read: a binding that decodes to `None` does not fail open —
/// it fails closed with `agent_key_unbound` — but it locks a correctly created
/// key out of its own data, which on Postgres nothing checked.
#[tokio::test]
async fn an_agent_scoped_keys_binding_survives_a_postgres_round_trip() {
    let _guard = test_lock().lock().await;
    let Some(store) = pg_store("an_agent_scoped_keys_binding_survives_a_postgres_round_trip").await
    else {
        return;
    };

    let key_id = format!("parity-agent-key-{}", uuid::Uuid::new_v4());
    let (raw, hash) = generate_api_key();
    store
        .store_key_scoped(
            &key_id,
            &hash,
            "parity",
            &raw,
            KeyScope::Agent,
            Some("parity-bound-agent"),
        )
        .await
        .expect("store agent-scoped key");

    let verified = store
        .verify_raw_key_scoped(&raw)
        .await
        .expect("verify")
        .expect("a key that was just stored must verify");

    assert_eq!(verified.scope, KeyScope::Agent);
    assert_eq!(
        verified.agent_id.as_deref(),
        Some("parity-bound-agent"),
        "the binding did not survive Postgres; an agent-scoped key that reads back \
         unbound is locked out of its own data with agent_key_unbound",
    );

    store.delete_key(&key_id).await.expect("cleanup");
}
