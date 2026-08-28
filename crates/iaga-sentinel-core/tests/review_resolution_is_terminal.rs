//! A resolved review cannot be quietly rewritten.
//!
//! `update_status` was an unconditional `UPDATE ... WHERE id = ?`, with no
//! state-machine guard and no history table. Measured against a live 2.1.0
//! server: approve a request (`200 OK`, `status: approved`), then post
//! `rejected` to the same id (`200 OK`, `status: rejected`). One surviving row,
//! two authoritative-looking answers, and nothing anywhere recording that the
//! decision had ever been anything else — no actor, no previous value, no
//! appended audit row.
//!
//! For a product whose deliverable is the evidence record, a human-in-the-loop
//! decision that can be silently rewritten is not a record. Resolution is now
//! terminal: the transition is guarded in the WHERE clause, so a second attempt
//! is refused and names the decision that already stands.
//!
//! The guard lives in SQL rather than in a read-then-write so two concurrent
//! resolutions cannot both succeed — exactly one updates a row.

use iaga_sentinel::core::types::{GovernanceDecision, ReviewRequest};
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::ReviewStore;
use uuid::Uuid;

async fn store() -> SqliteStorage {
    SqliteStorage::new(&format!(
        "sqlite:file:review-terminal-{}?mode=memory&cache=shared",
        Uuid::new_v4()
    ))
    .await
    .expect("in-memory sqlite")
}

fn pending(id: &str) -> ReviewRequest {
    ReviewRequest {
        id: id.to_string(),
        agent_id: "review-agent".into(),
        workspace_id: "ws-demo".into(),
        tool_name: "shell.exec".into(),
        decision: GovernanceDecision::Review,
        status: "pending".into(),
        risk_score: 55,
        reasons: vec!["needs a human".into()],
        created_at: "2026-08-22T12:00:00+00:00".into(),
        updated_at: "2026-08-22T12:00:00+00:00".into(),
    }
}

#[tokio::test]
async fn a_pending_review_can_be_resolved_once() {
    let s = store().await;
    let id = "rev-once";
    s.create(&pending(id)).await.expect("seed");

    let resolved = s
        .update_status(id, "approved")
        .await
        .expect("first resolve");
    assert_eq!(resolved.status, "approved");
    assert_eq!(s.get(id).await.expect("read back").status, "approved");
}

/// The measured defect.
#[tokio::test]
async fn a_resolved_review_cannot_be_re_flipped() {
    let s = store().await;
    let id = "rev-reflip";
    s.create(&pending(id)).await.expect("seed");
    s.update_status(id, "approved")
        .await
        .expect("first resolve");

    let err = s
        .update_status(id, "rejected")
        .await
        .expect_err("a second resolution must be refused, not silently applied");
    let msg = err.to_string();
    assert!(
        msg.contains("already resolved") && msg.contains("approved"),
        "the refusal must name the decision that stands: {msg}"
    );

    assert_eq!(
        s.get(id).await.expect("read back").status,
        "approved",
        "the stored decision must be the first one"
    );
}

/// Re-approving an already-approved review is refused too: the point is that
/// the record is final, not that the value happens to match.
#[tokio::test]
async fn re_asserting_the_same_decision_is_also_refused() {
    let s = store().await;
    let id = "rev-same";
    s.create(&pending(id)).await.expect("seed");
    s.update_status(id, "approved")
        .await
        .expect("first resolve");

    assert!(
        s.update_status(id, "approved").await.is_err(),
        "a resolution is final regardless of the value"
    );
}

/// An unknown id is still ReviewNotFound, not the already-resolved error — the
/// two ways to affect no rows must stay distinguishable.
#[tokio::test]
async fn an_unknown_review_id_is_still_not_found() {
    let s = store().await;
    let err = s
        .update_status("rev-does-not-exist", "approved")
        .await
        .expect_err("unknown id must error");
    let msg = err.to_string();
    assert!(
        !msg.contains("already resolved"),
        "an unknown id is not an already-resolved review: {msg}"
    );
}
