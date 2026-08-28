//! Real-HTTP end-to-end tests for 1.5 cost control.
//!
//! These drive a live `axum` server over real `reqwest` calls (same harness as
//! `e2e_http_tests.rs`): an inspect request carrying `usage` is captured into
//! the cost ledger, surfaced through the `/v1/cost/*` API, and — with a Dictum
//! budget policy loaded — a session that exceeds its threshold is blocked while
//! other sessions stay unaffected.
//!
//! Gated on `cost-control` + `dictum` (both present in the default + cost-control
//! build the CI cost-control job runs).

#![cfg(all(feature = "cost-control", feature = "dictum"))]

use std::net::SocketAddr;
use std::sync::Arc;

use iaga_sentinel::auth::api_keys::generate_api_key;
use iaga_sentinel::config::env::{AppEnv, NodeEnv, ServiceMode};
use iaga_sentinel::core::types::RateLimitConfig;
use iaga_sentinel::demo::scenarios::{demo_profiles, demo_workspace_policies};
use iaga_sentinel::events::bus::EventBus;
use iaga_sentinel::events::webhooks::{DeadLetterQueue, WebhookManager};
use iaga_sentinel::modules::fingerprint::behavioral::BehavioralEngine;
use iaga_sentinel::modules::rate_limit::limiter::RateLimiter;
use iaga_sentinel::modules::threat_intel::feed::ThreatFeed;
use iaga_sentinel::pipeline::dictum_overlay::DictumOverlay;
use iaga_sentinel::plugins::PluginRegistry;
use iaga_sentinel::server::app_state::AppState;
use iaga_sentinel::server::create_server::create_router;
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::{ApiKeyStore, PolicyStore, StorageBackend};
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

struct TestServer {
    address: SocketAddr,
    api_key: String,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Compile a Dictum overlay whose only policy blocks once a session's prior
/// cumulative spend (injected by cost-control as `usage.session_cost_usd`)
/// passes a literal $5 threshold — no env needed, fully deterministic. Dictum has
/// no float literals, so the threshold is the integer `5`; `cmp_values` compares
/// the float spend against it correctly.
fn budget_overlay() -> Arc<DictumOverlay> {
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .suffix(".dictum")
        .tempfile()
        .expect("create temp dictum file");
    write!(
        file,
        "policy \"session_budget\" {{\n  when usage.session_cost_usd > 5\n  then block, reason=\"session budget exceeded\"\n}}\n"
    )
    .expect("write dictum policy");
    let overlay = DictumOverlay::load(file.path()).expect("load budget overlay");
    Arc::new(overlay)
}

async fn spawn(dictum_overlay: Option<Arc<DictumOverlay>>) -> TestServer {
    let db_url = format!(
        "sqlite:file:cost-e2e-{}?mode=memory&cache=shared",
        Uuid::new_v4()
    );
    let storage = Arc::new(SqliteStorage::new(&db_url).await.expect("in-memory sqlite"));

    for profile in demo_profiles() {
        storage
            .upsert_profile(&profile)
            .await
            .expect("seed profile");
    }
    for workspace in demo_workspace_policies() {
        storage
            .upsert_workspace(&workspace)
            .await
            .expect("seed workspace");
    }
    let (raw_key, key_hash) = generate_api_key();
    storage
        .store_key("seeded-key", &key_hash, "cost-e2e", &raw_key)
        .await
        .expect("seed api key");

    let state = Arc::new(AppState {
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
            port: 0,
            host: "127.0.0.1".to_string(),
            node_env: NodeEnv::Test,
            default_mode: ServiceMode::Gateway,
            cors_origins: None,
        },
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts: None,
        reasoning: None,
        dictum_overlay,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let address = listener.local_addr().expect("listener addr");
    let router = create_router(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("server runs");
    });

    TestServer {
        address,
        api_key: raw_key,
        task,
    }
}

fn auth_client(api_key: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {api_key}").parse().expect("auth header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("reqwest client")
}

/// A safe (read-only) inspect body carrying caller-reported usage. `costUsd`
/// wins over the pricing table, so the asserted dollar amount is exact.
fn inspect_body(session: &str, cost_usd: f64) -> Value {
    serde_json::json!({
        "agentId": "openclaw-builder-01",
        "workspaceId": "ws-demo",
        "framework": "openclaw",
        "action": {
            "type": "file_read",
            "toolName": "filesystem.read",
            "payload": { "path": "README.md", "intent": "read docs" }
        },
        "metadata": { "sessionId": session },
        "usage": {
            "provider": "anthropic",
            "model": "claude-sonnet-4-6",
            "promptTokens": 1000,
            "completionTokens": 500,
            "costUsd": cost_usd
        }
    })
}

#[tokio::test]
async fn cost_is_captured_and_aggregated_over_http() {
    let server = spawn(None).await;
    let client = auth_client(&server.api_key);
    let base = server.base_url();

    // A governed inspect carrying usage is allowed and captured.
    let inspect = client
        .post(format!("{base}/v1/inspect"))
        .json(&inspect_body("cost-cap-1", 0.02))
        .send()
        .await
        .expect("inspect should succeed");
    assert_eq!(inspect.status(), StatusCode::OK);
    let inspect_json: Value = inspect.json().await.expect("inspect json");
    assert_eq!(inspect_json["decision"], "allow");

    // /v1/cost/summary reflects exactly the reported spend + tokens.
    let summary: Value = client
        .get(format!("{base}/v1/cost/summary"))
        .send()
        .await
        .expect("summary should succeed")
        .json()
        .await
        .expect("summary json");
    assert_eq!(summary["enabled"], true);
    let s = &summary["summary"];
    assert_eq!(s["totalActions"], 1);
    assert_eq!(s["totalTokens"], 1500);
    let net = s["netCostUsd"].as_f64().expect("netCostUsd");
    assert!((net - 0.02).abs() < 1e-9, "net cost = {net}");

    // /v1/cost/by-model attributes it to the right model.
    let by_model: Value = client
        .get(format!("{base}/v1/cost/by-model"))
        .send()
        .await
        .expect("by-model should succeed")
        .json()
        .await
        .expect("by-model json");
    let rows = by_model["rows"].as_array().expect("rows array");
    assert!(
        rows.iter().any(|r| r["key"] == "claude-sonnet-4-6"
            && (r["netCostUsd"].as_f64().unwrap_or_default() - 0.02).abs() < 1e-9),
        "expected sonnet row at $0.02, got {rows:?}"
    );

    // budget + pricing endpoints are live (feature enabled).
    let budget: Value = client
        .get(format!("{base}/v1/cost/budget"))
        .send()
        .await
        .expect("budget should succeed")
        .json()
        .await
        .expect("budget json");
    assert_eq!(budget["enabled"], true);
    let pricing: Value = client
        .get(format!("{base}/v1/cost/pricing"))
        .send()
        .await
        .expect("pricing should succeed")
        .json()
        .await
        .expect("pricing json");
    assert_eq!(pricing["enabled"], true);
}

#[tokio::test]
async fn dictum_budget_blocks_session_over_threshold_but_not_others() {
    let server = spawn(Some(budget_overlay())).await;
    let client = auth_client(&server.api_key);
    let base = server.base_url();
    let session = "cost-budget-session";

    // First call: no prior spend (0 <= $5) -> allowed; records $10 for the session.
    let first: Value = client
        .post(format!("{base}/v1/inspect"))
        .json(&inspect_body(session, 10.0))
        .send()
        .await
        .expect("first inspect should succeed")
        .json()
        .await
        .expect("first json");
    assert_eq!(
        first["decision"], "allow",
        "first call is under budget, got {first:?}"
    );

    // Second call, same session: prior spend $10 > $5 -> Dictum budget policy blocks.
    let second: Value = client
        .post(format!("{base}/v1/inspect"))
        .json(&inspect_body(session, 10.0))
        .send()
        .await
        .expect("second inspect should succeed")
        .json()
        .await
        .expect("second json");
    assert_eq!(
        second["decision"], "block",
        "second call is over budget and must block, got {second:?}"
    );

    // A different session is unaffected (per-session isolation).
    let other: Value = client
        .post(format!("{base}/v1/inspect"))
        .json(&inspect_body("cost-budget-other-session", 10.0))
        .send()
        .await
        .expect("other-session inspect should succeed")
        .json()
        .await
        .expect("other json");
    assert_eq!(
        other["decision"], "allow",
        "an unrelated session must not be blocked, got {other:?}"
    );
}
