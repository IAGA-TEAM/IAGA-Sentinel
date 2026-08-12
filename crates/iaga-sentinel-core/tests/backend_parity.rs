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

use iaga_sentinel::core::types::{
    ActionType, GovernanceDecision, ProtocolKind, ReviewRequest, ReviewStatus, StoredAuditEvent,
    ToolPolicy, WorkspacePolicy,
};
use iaga_sentinel::storage::postgres::PostgresStorage;
use iaga_sentinel::storage::traits::{AuditStore, PolicyStore, ReviewStore};

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
