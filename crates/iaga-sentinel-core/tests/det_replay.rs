//! DET-REPLAY-REALPIPELINE-2 + DET-SIGNBYTES-ORDER-6.
//!
//! The product's central claim is "bit-exact on replay": the signed verdict is
//! reproducible from the recorded inputs alone. This test runs the *real*
//! `execute_pipeline` twice on the same request with a pinned `decision_time`
//! (and the process-global state reset between runs) and asserts the two signed
//! `ReceiptBody`s are byte-identical, plus a guard that the JSON serialization
//! the receipt relies on stays key-ordered (preserve_order off).

#![cfg(all(feature = "receipts", feature = "sqlite"))]

use std::sync::Arc;

use chrono::{DateTime, TimeZone, Utc};
use iaga_sentinel::config::env::{AppEnv, NodeEnv, ServiceMode};
use iaga_sentinel::core::types::*;
use iaga_sentinel::demo::scenarios::{demo_profiles, demo_workspace_policies};
use iaga_sentinel::events::bus::EventBus;
use iaga_sentinel::events::webhooks::{DeadLetterQueue, WebhookManager};
use iaga_sentinel::modules::fingerprint::behavioral::BehavioralEngine;
use iaga_sentinel::modules::nhi::crypto_identity;
use iaga_sentinel::modules::rate_limit::limiter::RateLimiter;
use iaga_sentinel::modules::risk::adaptive_scorer;
use iaga_sentinel::modules::session_graph::session_dag;
use iaga_sentinel::modules::taint::taint_tracker;
use iaga_sentinel::modules::threat_intel::feed::ThreatFeed;
use iaga_sentinel::pipeline::execute_pipeline::execute_pipeline_at;
use iaga_sentinel::pipeline::receipts::SignedReceiptLogger;
use iaga_sentinel::plugins::PluginRegistry;
use iaga_sentinel::server::app_state::AppState;
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::{PolicyStore, StorageBackend};

use iaga_sentinel_receipts::{
    ReceiptBody, ReceiptSigner, ReceiptStore, Signer, SqliteReceiptStore,
};

/// Reset every process-global the SIGNED verdict can read, so a re-run is a
/// pure function of (request + resolved policy + decision_time + ML digest).
fn reset_global_state() {
    adaptive_scorer::reset_weights();
    adaptive_scorer::reset_baselines();
    session_dag::reset_sessions();
    taint_tracker::reset_sessions();
    crypto_identity::reset_state();
}

async fn build_state(receipts: Arc<SignedReceiptLogger>) -> Arc<AppState> {
    let storage = Arc::new(
        SqliteStorage::new("sqlite::memory:")
            .await
            .expect("in-memory sqlite"),
    );
    for profile in demo_profiles() {
        storage
            .upsert_profile(&profile)
            .await
            .expect("seed profile");
    }
    for policy in demo_workspace_policies() {
        storage
            .upsert_workspace(&policy)
            .await
            .expect("seed workspace");
    }

    Arc::new(AppState {
        audit_store: storage.clone(),
        review_store: storage.clone(),
        policy_store: storage.clone(),
        api_key_store: storage.clone(),
        nhi_store: storage.clone(),
        session_store: storage.clone(),
        taint_store: storage.clone(),
        fingerprint_store: storage.clone(),
        rate_limit_store: storage.clone(),
        event_bus: EventBus::new(64),
        webhook_manager: Arc::new(WebhookManager::new(Arc::new(DeadLetterQueue::new()))),
        behavioral_engine: Arc::new(BehavioralEngine::new()),
        rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig::default())),
        threat_feed: Arc::new(ThreatFeed::with_builtin_indicators()),
        plugin_registry: Arc::new(PluginRegistry::default()),
        storage_backend: StorageBackend::Sqlite,
        env: AppEnv {
            port: 4010,
            host: "127.0.0.1".to_string(),
            node_env: NodeEnv::Test,
            default_mode: ServiceMode::Gateway,
            cors_origins: None,
        },
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts: Some(receipts),
        reasoning: None,
        #[cfg(feature = "dictum")]
        dictum_overlay: None,
    })
}

fn benign_request(session_id: &str) -> InspectRequest {
    InspectRequest {
        agent_id: "openclaw-builder-01".into(),
        tenant_id: None,
        workspace_id: Some("ws-demo".into()),
        framework: "openclaw".into(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type: ActionType::FileRead,
            tool_name: "filesystem.read".into(),
            payload: [
                ("path".to_string(), serde_json::json!("src/config.json")),
                (
                    "intent".to_string(),
                    serde_json::json!("read configuration"),
                ),
            ]
            .into_iter()
            .collect(),
        },
        requested_secrets: None,
        metadata: Some(
            [("sessionId".to_string(), serde_json::json!(session_id))]
                .into_iter()
                .collect(),
        ),
        usage: None,
    }
}

/// Run the real pipeline once with a fresh receipt store (so the receipt is
/// always seq 0) sharing the given signer, and return (verdict, receipt body).
async fn run_once(
    signer: Arc<dyn Signer>,
    store_tag: u32,
    session_id: &str,
    decision_time: DateTime<Utc>,
) -> (GovernanceResult, ReceiptBody) {
    reset_global_state();

    // Shared-cache in-memory DB so the store's pool sees one database; unique
    // per run so each chain starts empty (receipt is seq 0).
    let url = format!("sqlite:file:det-replay-{store_tag}?mode=memory&cache=shared");
    let store = Arc::new(
        SqliteReceiptStore::new(&url, signer.verifying_key())
            .await
            .expect("receipt store"),
    );
    let logger = Arc::new(SignedReceiptLogger::new(
        store.clone() as Arc<dyn ReceiptStore>,
        signer,
        "a".repeat(64), // fixed policy hash, identical across runs
    ));
    let state = build_state(logger).await;

    let req = benign_request(session_id);
    let result = execute_pipeline_at(&req, &state, decision_time)
        .await
        .expect("pipeline ok");

    // run_id is qualified by the agent (PIP-RUNID-COLLISION): agent_id:session_id.
    let run_id = format!("{}:{}", req.agent_id, session_id);
    let receipts = store.get_run(&run_id).await.expect("get_run");
    assert_eq!(receipts.len(), 1, "expected exactly one receipt");
    assert_eq!(receipts[0].body.seq, 0, "fresh store -> seq 0");
    (result, receipts[0].body.clone())
}

#[tokio::test]
async fn pipeline_replay_is_bit_exact() {
    // One signer shared across both runs (a different key would change
    // signer_key_id and so the bytes).
    let signer: Arc<dyn Signer> = Arc::new(ReceiptSigner::generate());
    // Pinned decision time, deliberately off-hours (03:30 UTC) so the signed
    // off-hours signal is exercised and must reproduce.
    let dt = Utc.with_ymd_and_hms(2026, 6, 16, 3, 30, 0).unwrap();

    let (r1, body1) = run_once(signer.clone(), 1, "det-replay-session", dt).await;
    let (r2, body2) = run_once(signer.clone(), 2, "det-replay-session", dt).await;

    // Signed verdict fields reproduce exactly.
    assert_eq!(r1.decision, r2.decision, "decision must reproduce");
    assert_eq!(r1.risk.score, r2.risk.score, "risk score must reproduce");
    assert_eq!(r1.risk.reasons, r2.risk.reasons, "reasons must reproduce");
    assert_eq!(
        r1.audit_event.timestamp, r2.audit_event.timestamp,
        "timestamp comes from decision_time and must reproduce"
    );
    // Sanity: a fresh random event_id per run proves these are distinct runs,
    // not the same object — and that event_id is (correctly) NOT in the bytes.
    assert_ne!(
        r1.audit_event.event_id, r2.audit_event.event_id,
        "event_id is random per run"
    );

    // The signed receipt body is byte-identical on replay.
    let b1 = body1.signing_bytes().expect("bytes1");
    let b2 = body2.signing_bytes().expect("bytes2");
    assert_eq!(
        b1, b2,
        "ReceiptBody::signing_bytes must be bit-exact on replay"
    );

    // The payload digest is actually bound (input_hash is non-empty and stable).
    assert_eq!(body1.input_hash, body2.input_hash);
    assert_eq!(body1.input_hash.len(), 64, "input_hash is a hex SHA-256");
}

/// DET-SIGNBYTES-ORDER-6: the receipt's `input_hash` (over the canonical
/// payload) and `signing_bytes` are deterministic only because `serde_json`
/// serializes object keys in sorted order (the `preserve_order` feature is
/// OFF). If a future dependency unification flipped it on, insertion order
/// would leak into the signed bytes silently. This guards that invariant.
#[test]
fn json_object_serialization_is_key_ordered() {
    let mut m = serde_json::Map::new();
    m.insert("zebra".to_string(), serde_json::json!(1));
    m.insert("alpha".to_string(), serde_json::json!(2));
    m.insert("mango".to_string(), serde_json::json!(3));
    let s = serde_json::to_string(&serde_json::Value::Object(m)).unwrap();
    assert_eq!(
        s, r#"{"alpha":2,"mango":3,"zebra":1}"#,
        "serde_json must serialize object keys sorted (preserve_order OFF); the \
         receipt input_hash + signing_bytes determinism depends on it"
    );
}
