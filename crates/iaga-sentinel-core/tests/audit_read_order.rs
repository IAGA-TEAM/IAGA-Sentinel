//! The audit read path must return a TOTAL order.
//!
//! `created_at` is the sort key, and the INSERT now supplies it from the
//! pipeline's decision time at microsecond precision. Rows can still tie — two
//! decisions in the same microsecond, or the fixture below, which holds
//! `timestamp` constant on purpose — and without a tie-break the page boundary
//! is whatever the query plan happened to produce: two calls can return
//! different rows, and the two storage backends can disagree about the same
//! data.
//!
//! It used to default to `datetime('now')` — WHOLE SECONDS — so the tie was not
//! an edge case but the normal state, and `event_id DESC` (a UUID) was the
//! de-facto order. `rows_written_in_the_same_second_come_back_newest_first`
//! pins the chronology; everything else here pins the tie-break.
//!
//! The tie-break exists in the queries and had no test at all: `event_id DESC`
//! appeared in exactly two files, both of them source, and removing it from all
//! six queries left `cargo test` completely green. These tests are written
//! against `SqliteStorage` directly rather than over HTTP because a tie has to
//! be forced — every row is given the same decision time — which is trivial here
//! and racy through a server.
//!
//! # What these tests do and do not pin
//!
//! They pin the CONTRACT a caller depends on — that the read is totally ordered
//! and that a narrow read is a prefix of a wider one. They do NOT isolate the
//! `ORDER BY` clause from the schema. Measured: with the composite index added
//! in migration `0007` present, deleting `, event_id DESC` from every query
//! leaves these tests green, because SQLite can walk
//! `idx_audit_created_event` backwards and gets `event_id DESC` for free. The
//! same is true of the top-N stats, where the natural `GROUP BY` output order
//! already matches the tie-break.
//!
//! That is worth stating rather than leaving as an implied guarantee: a reader
//! who assumes these tests protect the clause would be wrong. What they protect
//! is the behaviour — and the behaviour would still break if someone changed the
//! sort COLUMN, dropped the index and the tie-break together, or moved to a
//! backend whose planner does not offer the same accident. Removing the clause
//! on the strength of "the index covers it" would be relying on a query plan,
//! which is exactly the kind of unwritten dependency this file exists to make
//! visible.

use iaga_sentinel::core::types::{
    ActionType, AuditExportFilter, GovernanceDecision, ReviewStatus, StoredAuditEvent,
};
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::AuditStore;
use uuid::Uuid;

async fn store() -> SqliteStorage {
    SqliteStorage::new(&format!(
        "sqlite:file:audit-order-{}?mode=memory&cache=shared",
        Uuid::new_v4()
    ))
    .await
    .expect("sqlite")
}

fn event(event_id: &str, agent_id: &str) -> StoredAuditEvent {
    StoredAuditEvent {
        event_id: event_id.into(),
        agent_id: agent_id.into(),
        tenant_id: None,
        framework: "test".into(),
        action_type: ActionType::Http,
        tool_name: "http.fetch".into(),
        input_sha256: String::new(),
        decision: GovernanceDecision::Allow,
        // Same instant for every row: `timestamp` is the pipeline's decision
        // time and is NOT what the query orders by, so holding it constant keeps
        // it from accidentally standing in for the sort key.
        timestamp: "2026-08-09T12:00:00Z".into(),
        reasons: vec![],
        review_status: ReviewStatus::NotRequired,
        risk_score: 1,
        usage: None,
        session_id: None,
    }
}

/// Ids chosen so that insertion order and the required output order differ.
/// Sorted descending they are e, d, c, b, a; they are written a..e.
const IDS: [&str; 5] = ["a-evt", "b-evt", "c-evt", "d-evt", "e-evt"];

async fn seed(s: &SqliteStorage, agent: &str) {
    for id in IDS {
        s.append(&event(id, agent)).await.expect("append");
    }
}

/// `/v1/audit`. All five rows land in one second, so `created_at` alone cannot
/// separate them and only the `event_id DESC` tie-break decides the order.
#[tokio::test]
async fn the_unfiltered_audit_list_is_totally_ordered() {
    let s = store().await;
    seed(&s, "order-agent").await;

    let rows = AuditStore::list(&s, 50).await.expect("list");
    let got: Vec<&str> = rows.iter().map(|r| r.event_id.as_str()).collect();

    let mut want: Vec<&str> = IDS.to_vec();
    want.sort_by(|a, b| b.cmp(a));

    assert_eq!(
        got, want,
        "rows tied on created_at must fall back to event_id DESC; got {got:?}"
    );
}

/// Totally ordered is not the same as ordered by TIME, and the difference is
/// what an auditor actually reads.
///
/// `created_at` used to be left to the column default, `datetime('now')` —
/// whole seconds — so every row written inside one second tied and the
/// `event_id DESC` tie-break, a UUID, became the real order. Measured on a live
/// server with five sequential requests: the newest event came back FOURTH, and
/// the returned order matched `sorted(event_id, reverse=True)` exactly. Postgres
/// has microsecond `NOW()` and did not tie, so the two backends disagreed about
/// the same data.
///
/// These rows land in one second but carry distinct decision timestamps, and
/// their ids are chosen so the tie-break would give a DIFFERENT answer
/// (`event_id DESC` = z, m, a; chronological = m, z, a). Only a read that
/// actually orders by time can pass.
#[tokio::test]
async fn rows_written_in_the_same_second_come_back_newest_first() {
    let s = store().await;
    for (id, ts) in [
        ("a-evt", "2026-08-09T12:00:00.100000Z"),
        ("z-evt", "2026-08-09T12:00:00.200000Z"),
        ("m-evt", "2026-08-09T12:00:00.300000Z"),
    ] {
        let mut e = event(id, "chrono-agent");
        e.timestamp = ts.into();
        s.append(&e).await.expect("append");
    }

    let rows = AuditStore::list(&s, 50).await.expect("list");
    let got: Vec<&str> = rows.iter().map(|r| r.event_id.as_str()).collect();

    assert_eq!(
        got,
        vec!["m-evt", "z-evt", "a-evt"],
        "the audit read must be newest-first by decision time. `event_id DESC` \
         alone would answer [\"z-evt\", \"m-evt\", \"a-evt\"], which is the bug: \
         a deterministic order that is not a chronological one. got {got:?}"
    );
}

/// `/v1/audit/export`. The filtered path is a separate query and carries its own
/// copy of the ORDER BY, so it needs its own witness.
#[tokio::test]
async fn the_filtered_audit_export_is_totally_ordered() {
    let s = store().await;
    seed(&s, "order-agent").await;
    // A second agent, to prove the predicate and the ordering compose.
    s.append(&event("z-evt", "other-agent"))
        .await
        .expect("append");

    let rows = s
        .list_filtered(&AuditExportFilter {
            agent_id: Some("order-agent".into()),
            ..Default::default()
        })
        .await
        .expect("export");
    let got: Vec<&str> = rows.iter().map(|r| r.event_id.as_str()).collect();

    let mut want: Vec<&str> = IDS.to_vec();
    want.sort_by(|a, b| b.cmp(a));

    assert_eq!(got, want, "export must be totally ordered too; got {got:?}");
    assert!(
        !got.contains(&"z-evt"),
        "the agent_id predicate must still filter"
    );
}

/// Repeating the same read must give the same answer. This is the property a
/// caller depends on when it pages by asking for a larger limit, since
/// `AuditExportQuery` has no cursor: page N+1 is only meaningful if page N was
/// a stable prefix.
#[tokio::test]
async fn repeated_reads_return_the_same_prefix() {
    let s = store().await;
    seed(&s, "order-agent").await;

    let first: Vec<String> = AuditStore::list(&s, 3)
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.event_id)
        .collect();
    let wider: Vec<String> = AuditStore::list(&s, 5)
        .await
        .expect("list")
        .into_iter()
        .map(|r| r.event_id)
        .collect();

    assert_eq!(
        wider[..first.len()],
        first[..],
        "a narrower read must be a prefix of a wider one, or paging by limit \
         silently skips or repeats rows"
    );
}

/// The top-N stats share the same defect class: `ORDER BY cnt DESC` alone lets
/// the `LIMIT 10` boundary fall wherever the plan puts it when counts tie.
#[tokio::test]
async fn the_top_agent_stats_break_ties_deterministically() {
    let s = store().await;
    // Three agents, one event each: a three-way tie on count.
    for agent in ["agent-c", "agent-a", "agent-b"] {
        s.append(&event(&format!("{agent}-evt"), agent))
            .await
            .expect("append");
    }

    let stats = s.stats().await.expect("stats");
    let names: Vec<&str> = stats.top_agents.iter().map(|(a, _)| a.as_str()).collect();

    assert_eq!(
        names,
        vec!["agent-a", "agent-b", "agent-c"],
        "agents tied on count must be ordered by agent_id, or which ones \
         survive LIMIT 10 is arbitrary: {names:?}"
    );
}

/// `tenant_id` is a documented export filter that SQLite accepted and ignored.
///
/// The handler destructured it into `AuditExportFilter` and the SQLite query
/// simply never referenced it — four WHERE predicates where the Postgres twin
/// has five. So `?tenant_id=X` returned rows from every tenant on the DEFAULT
/// backend, and the exported row serialized `"tenantId": null` because the
/// column was missing from the projection too.
///
/// Not a confidentiality bug: the endpoint is admin-only, `AuthContext` carries
/// no tenant, and `GET /v1/audit` already hands the same caller everything. It
/// is a filter that did not filter, and two backends disagreeing about one
/// request. It shipped with no test, which is why it survived.
#[tokio::test]
async fn the_export_filters_by_tenant_and_returns_the_tenant_id() {
    let s = store().await;

    for (id, tenant) in [("t1-a", "tenant-one"), ("t2-a", "tenant-two")] {
        let mut e = event(id, "agent-x");
        e.tenant_id = Some(tenant.into());
        s.append(&e).await.expect("append");
    }
    // A row with no tenant at all must not be swept in by a tenant filter.
    s.append(&event("none-a", "agent-x")).await.expect("append");

    let filter = AuditExportFilter {
        tenant_id: Some("tenant-one".into()),
        agent_id: None,
        decision: None,
        from_date: None,
        to_date: None,
        limit: Some(100),
    };
    let got = s.list_filtered(&filter).await.expect("filtered");

    let ids: Vec<&str> = got.iter().map(|e| e.event_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["t1-a"],
        "`tenant_id` must actually filter; got {ids:?}"
    );
    assert_eq!(
        got[0].tenant_id.as_deref(),
        Some("tenant-one"),
        "the exported row must carry its tenant, not null — the column was \
         missing from the SQLite projection"
    );
}
