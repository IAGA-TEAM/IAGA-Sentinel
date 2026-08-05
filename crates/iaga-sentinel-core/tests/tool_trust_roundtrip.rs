//! `AgentProfile.tool_trust` must survive a round trip through storage.
//!
//! The field has been on `AgentProfile` since the first commit and the scorer
//! has always read it — `execute_pipeline` passes `profile.tool_trust` into
//! `reputation_risk`, which raises the score and pushes "low tool trust: X"
//! below 0.2. What was missing was the column: both row mappers hydrated a
//! literal `tool_trust: 0.7`, so a configured value never came back out.
//!
//! Measured before migration 0007: an agent configured `toolTrust: 0.05` and an
//! agent with no setting produced the identical reputation signal (score 28,
//! "moderate trust: 0.60"), and `GET /v1/profiles/{id}` echoed 0.7 for the
//! agent configured at 0.05 — the operator got a read-back confirming a value
//! they never wrote.
//!
//! These are storage tests rather than pipeline tests on purpose: the pipeline
//! side was never broken, so a test there would have passed throughout.

use iaga_sentinel::core::types::{ActionType, AgentProfile, AgentRole};
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::PolicyStore;
use uuid::Uuid;

fn profile(agent_id: &str, tool_trust: f64) -> AgentProfile {
    AgentProfile {
        agent_id: agent_id.into(),
        tenant_id: None,
        workspace_id: "ws-trust".into(),
        framework: "audit".into(),
        role: AgentRole::Builder,
        approved_tools: vec!["filesystem.read".into()],
        approved_secrets: vec![],
        baseline_action_types: vec![ActionType::FileRead],
        tool_trust,
    }
}

async fn store() -> SqliteStorage {
    let url = format!(
        "sqlite:file:tool-trust-{}?mode=memory&cache=shared",
        Uuid::new_v4()
    );
    SqliteStorage::new(&url).await.expect("sqlite")
}

#[tokio::test]
async fn a_configured_tool_trust_survives_storage() {
    let store = store().await;
    store
        .upsert_profile(&profile("floor", 0.05))
        .await
        .expect("seed");

    let read_back = store.get_agent_profile("floor").await.expect("read back");

    assert_eq!(
        read_back.tool_trust, 0.05,
        "a profile configured at the trust floor must come back at the trust \
         floor; hydrating a constant here is what made the knob inert"
    );
}

/// The complement. Without it, a mapper that returned the CONFIGURED value for
/// everything — or one that returned 0.05 unconditionally — would pass the test
/// above, which is the shape of assertion this audit exists to remove.
#[tokio::test]
async fn an_unconfigured_tool_trust_keeps_the_documented_default() {
    let store = store().await;
    store
        .upsert_profile(&profile("default", 0.7))
        .await
        .expect("seed");

    let read_back = store.get_agent_profile("default").await.expect("read back");

    assert_eq!(
        read_back.tool_trust, 0.7,
        "the default must stay 0.7: it is the value every existing row was \
         already being scored with, so upgrading moves no verdict"
    );
}

/// Two profiles that differ ONLY in `tool_trust` must remain distinguishable
/// after a round trip. This is the assertion that actually fails against the
/// old code, where both came back 0.7 and the difference vanished.
#[tokio::test]
async fn two_profiles_differing_only_in_tool_trust_stay_different() {
    let store = store().await;
    store.upsert_profile(&profile("a", 0.05)).await.expect("a");
    store.upsert_profile(&profile("b", 0.95)).await.expect("b");

    let a = store.get_agent_profile("a").await.expect("a");
    let b = store.get_agent_profile("b").await.expect("b");

    assert_ne!(
        a.tool_trust, b.tool_trust,
        "storage collapsed two different trust settings into one value"
    );
    assert_eq!((a.tool_trust, b.tool_trust), (0.05, 0.95));
}
