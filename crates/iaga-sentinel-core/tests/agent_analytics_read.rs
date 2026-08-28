//! `agent_analytics` had no test at all, on either backend.
//!
//! It computed each agent's top-5 tools by concatenating EVERY audit row's
//! `tool_name` into one string (`STRING_AGG` / `GROUP_CONCAT`) and splitting it
//! back apart in Rust. Three consequences, pinned below:
//!
//!   * a tool whose own name contains a comma became two phantom tools;
//!   * the top-5 cut came out of a `HashMap` plus a count-only sort, so which of
//!     several tools tied on count survived was arbitrary and could differ
//!     between runs and between backends;
//!   * the string grew with the number of EVENTS, not the number of distinct
//!     tools, which is unbounded work for a five-element list.
//!
//! Written against `SqliteStorage` directly, like `audit_read_order.rs`: the
//! comma and the tie both have to be forced, which is trivial here and racy over
//! HTTP. The Postgres twin runs the same SQL shape but has no test of its own on
//! that backend; `backend_parity.rs` covers the storage round-trips, not this query.

use iaga_sentinel::core::types::{ActionType, GovernanceDecision, ReviewStatus, StoredAuditEvent};
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::AuditStore;
use uuid::Uuid;

async fn store() -> SqliteStorage {
    SqliteStorage::new(&format!(
        "sqlite:file:agent-analytics-{}?mode=memory&cache=shared",
        Uuid::new_v4()
    ))
    .await
    .expect("sqlite")
}

fn event(agent_id: &str, tool_name: &str, decision: GovernanceDecision) -> StoredAuditEvent {
    StoredAuditEvent {
        event_id: Uuid::new_v4().to_string(),
        agent_id: agent_id.into(),
        tenant_id: None,
        framework: "test".into(),
        action_type: ActionType::Http,
        tool_name: tool_name.into(),
        input_sha256: String::new(),
        decision,
        timestamp: "2026-08-19T12:00:00Z".into(),
        reasons: vec![],
        review_status: ReviewStatus::NotRequired,
        risk_score: 10,
        usage: None,
        session_id: None,
    }
}

async fn seed(s: &SqliteStorage, agent: &str, tool: &str, times: usize) {
    for _ in 0..times {
        s.append(&event(agent, tool, GovernanceDecision::Allow))
            .await
            .expect("append");
    }
}

#[tokio::test]
async fn a_tool_name_containing_a_comma_is_one_tool() {
    let s = store().await;
    seed(&s, "comma-agent", "read,write", 3).await;

    let analytics = s.agent_analytics(Some("comma-agent")).await.expect("read");
    let agent = analytics.first().expect("one agent row");

    assert_eq!(
        agent.top_tools,
        vec![("read,write".to_string(), 3)],
        "splitting the aggregate on ',' invented two tools out of one"
    );
    assert_eq!(agent.total_requests, 3);
}

#[tokio::test]
async fn tools_tied_on_count_break_deterministically_by_name() {
    let s = store().await;
    // Written in an order that does not match the required output order, and
    // every tool tied at exactly one call, so ONLY the tie-break decides.
    for tool in ["delta", "bravo", "echo", "alpha", "charlie", "foxtrot"] {
        seed(&s, "tie-agent", tool, 1).await;
    }

    let first = s.agent_analytics(Some("tie-agent")).await.expect("read");
    let names: Vec<&str> = first[0]
        .top_tools
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();

    assert_eq!(
        names,
        vec!["alpha", "bravo", "charlie", "delta", "echo"],
        "a five-way tie must cut by tool_name ASC, not by HashMap order"
    );

    // Re-read: a HashMap-ordered implementation can pass once by luck.
    for _ in 0..5 {
        let again = s.agent_analytics(Some("tie-agent")).await.expect("read");
        let again_names: Vec<&str> = again[0]
            .top_tools
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(again_names, names, "top_tools must be stable across reads");
    }
}

#[tokio::test]
async fn counts_and_ordering_are_by_frequency_first() {
    let s = store().await;
    seed(&s, "freq-agent", "rare", 1).await;
    seed(&s, "freq-agent", "common", 5).await;
    seed(&s, "freq-agent", "middling", 3).await;

    let analytics = s.agent_analytics(Some("freq-agent")).await.expect("read");
    let agent = &analytics[0];

    assert_eq!(
        agent.top_tools,
        vec![
            ("common".to_string(), 5),
            ("middling".to_string(), 3),
            ("rare".to_string(), 1),
        ]
    );
    assert_eq!(agent.total_requests, 9);
}

#[tokio::test]
async fn only_the_top_five_tools_are_reported() {
    let s = store().await;
    for (i, tool) in ["t1", "t2", "t3", "t4", "t5", "t6", "t7"]
        .iter()
        .enumerate()
    {
        seed(&s, "many-agent", tool, 7 - i).await;
    }

    let analytics = s.agent_analytics(Some("many-agent")).await.expect("read");
    assert_eq!(analytics[0].top_tools.len(), 5);
    assert_eq!(analytics[0].top_tools[0].0, "t1");
}

#[tokio::test]
async fn decisions_are_counted_per_agent() {
    let s = store().await;
    for decision in [
        GovernanceDecision::Allow,
        GovernanceDecision::Allow,
        GovernanceDecision::Block,
        GovernanceDecision::Review,
    ] {
        s.append(&event("dec-agent", "http.fetch", decision))
            .await
            .expect("append");
    }

    let analytics = s.agent_analytics(Some("dec-agent")).await.expect("read");
    let decisions = &analytics[0].decisions;

    assert_eq!(decisions.get("allow").copied(), Some(2));
    assert_eq!(decisions.get("block").copied(), Some(1));
    assert_eq!(decisions.get("review").copied(), Some(1));
}

/// The unfiltered read must not leak one agent's tools into another's row, and
/// must still be ordered by volume. This is the shape the dashboard requests.
#[tokio::test]
async fn the_fleet_read_keeps_agents_separate() {
    let s = store().await;
    seed(&s, "busy-agent", "busy-tool", 4).await;
    seed(&s, "quiet-agent", "quiet-tool", 1).await;

    let analytics = s.agent_analytics(None).await.expect("read");
    assert_eq!(analytics.len(), 2);

    assert_eq!(analytics[0].agent_id, "busy-agent", "ordered by volume");
    assert_eq!(
        analytics[0].top_tools,
        vec![("busy-tool".to_string(), 4)],
        "an agent's row must contain only its own tools"
    );
    assert_eq!(analytics[1].top_tools, vec![("quiet-tool".to_string(), 1)]);
    assert_eq!(analytics[1].decisions.get("allow").copied(), Some(1));
}
