//! A human asked to approve a `review` must be told which rule asked for it.
//!
//! `execute_pipeline` builds the caller-facing `risk.reasons` first, then
//! *clones* it and appends the causes that are not risk scoring — the
//! `dictum[...]` overlay attribution and the cost-control budget refusal — onto
//! the clone, which becomes `audit_event.reasons` and, through it, the signed
//! receipt. The review request was populated from `risk.reasons`, so exactly
//! those two causes never reached the queue.
//!
//! Measured against a live server with an overlay whose only rule forces a
//! review, `GET /v1/reviews` showed the reviewer:
//!
//!     - request matched registered tool and workspace policy
//!     - no high-risk rule matched
//!
//! for an action that is in front of them *only* because of that rule. The
//! attribution existed the whole time, one field away, in `auditEvent.reasons`.
//! AGENTS.md states the contract as "Nothing is silent — a refusal always says
//! which rule refused it."
//!
//! Self-contained rather than built on `tests/support/app_state.rs`: that helper
//! pins `dictum_overlay: None`, and an overlay is the whole point here. Same
//! shape as `cost_control_e2e.rs`, which needs an overlay for the same reason.

#![cfg(feature = "dictum")]

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
use serde_json::Value;
use uuid::Uuid;

const RULE: &str = "human_reviews_repo_reads";

struct TestServer {
    address: SocketAddr,
    api_key: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An overlay whose only rule fires on every repository read. Nothing else in
/// the pipeline escalates this action, so whatever verdict comes back is that
/// rule's doing — which is exactly the case under test.
fn overlay(verdict: &str, reason: &str) -> Arc<DictumOverlay> {
    use std::io::Write;
    let mut file = tempfile::Builder::new()
        .suffix(".dictum")
        .tempfile()
        .expect("temp dictum file");
    write!(
        file,
        "policy \"{RULE}\" {{\n  when action.kind == \"file_read\"\n  \
         then {verdict}, reason=\"{reason}\"\n}}\n"
    )
    .expect("write dictum policy");
    Arc::new(DictumOverlay::load(file.path()).expect("overlay loads"))
}

async fn spawn_with(verdict: &str, reason: &str) -> TestServer {
    let db_url = format!(
        "sqlite:file:review-reasons-{}?mode=memory&cache=shared",
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
        .store_key("seeded-key", &key_hash, "review-reasons", &raw_key)
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
            default_mode: ServiceMode::Sidecar,
            cors_origins: None,
        },
        auth_cache: iaga_sentinel::auth::cache::AuthCache::from_env(),
        receipts: None,
        reasoning: None,
        dictum_overlay: Some(overlay(verdict, reason)),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("addr");
    let router = create_router(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });

    TestServer {
        address,
        api_key: raw_key,
        task,
    }
}

async fn spawn() -> TestServer {
    spawn_with("review", "a human checks repository reads").await
}

/// A policy that fires `then allow` is still why the action was judged the way
/// it was, and it now says so in `risk.reasons` — a new caller-visible shape on
/// the ALLOW path, where nothing appeared before. Pinned because the obvious
/// tidy-up is to push the attribution only when the verdict actually changes,
/// and that would silently drop it from the audit event and the receipt too.
#[tokio::test]
async fn an_allow_policy_that_fires_is_attributed_as_well() {
    let server = spawn_with("allow", "reads of this repo are fine").await;
    let base = format!("http://{}", server.address);

    let inspect: Value = reqwest::Client::new()
        .post(format!("{base}/v1/inspect"))
        .bearer_auth(&server.api_key)
        .json(&serde_json::json!({
            "agentId": "openclaw-builder-01",
            "framework": "openclaw",
            "protocol": "http-function",
            "action": {
                "type": "file_read",
                "toolName": "filesystem.read",
                "payload": { "path": "README.md" }
            }
        }))
        .send()
        .await
        .expect("inspect responds")
        .json()
        .await
        .expect("inspect returns json");

    assert_eq!(inspect["decision"], "allow", "got {inspect}");

    let risk: Vec<String> = inspect["risk"]["reasons"]
        .as_array()
        .expect("risk reasons")
        .iter()
        .map(|r| r.to_string())
        .collect();
    let audit: Vec<String> = inspect["auditEvent"]["reasons"]
        .as_array()
        .expect("audit reasons")
        .iter()
        .map(|r| r.to_string())
        .collect();

    assert!(
        risk.iter().any(|r| r.contains(RULE)),
        "an allow policy that fired must still be attributed to the caller: {risk:?}"
    );
    assert_eq!(
        audit.iter().filter(|r| r.contains(RULE)).count(),
        1,
        "and exactly once in the audit event: {audit:?}"
    );
    assert!(
        inspect["reviewRequestId"].is_null(),
        "an allow must not open a review request: {inspect}"
    );
}

#[tokio::test]
async fn the_review_queue_names_the_rule_that_demanded_the_review() {
    let server = spawn().await;
    let base = format!("http://{}", server.address);
    let client = reqwest::Client::new();

    let inspect: Value = client
        .post(format!("{base}/v1/inspect"))
        .bearer_auth(&server.api_key)
        .json(&serde_json::json!({
            "agentId": "openclaw-builder-01",
            "framework": "openclaw",
            "protocol": "http-function",
            "action": {
                "type": "file_read",
                "toolName": "filesystem.read",
                "payload": { "path": "README.md" }
            }
        }))
        .send()
        .await
        .expect("inspect responds")
        .json()
        .await
        .expect("inspect returns json");

    assert_eq!(
        inspect["decision"], "review",
        "the overlay must be what escalates this read; got {inspect}"
    );
    let request_id = inspect["reviewRequestId"]
        .as_str()
        .expect("a review verdict opens a review request")
        .to_string();

    // The attribution is recorded — this is the field the receipt is built from.
    let audit_reasons: Vec<String> = inspect["auditEvent"]["reasons"]
        .as_array()
        .expect("audit reasons")
        .iter()
        .map(|r| r.to_string())
        .collect();
    assert!(
        audit_reasons.iter().any(|r| r.contains(RULE)),
        "precondition: the audit event should already carry the attribution, \
         so any failure below is about what the QUEUE shows, not about whether \
         the overlay fired. audit reasons: {audit_reasons:?}"
    );

    let queue: Value = client
        .get(format!("{base}/v1/reviews"))
        .bearer_auth(&server.api_key)
        .send()
        .await
        .expect("reviews responds")
        .json()
        .await
        .expect("reviews returns json");

    let entry = queue
        .as_array()
        .expect("reviews is a list")
        .iter()
        .find(|r| r["id"] == request_id.as_str())
        .unwrap_or_else(|| panic!("review {request_id} missing from the queue: {queue}"));

    let shown: Vec<String> = entry["reasons"]
        .as_array()
        .expect("queue entry reasons")
        .iter()
        .map(|r| r.to_string())
        .collect();

    assert!(
        shown.iter().any(|r| r.contains(RULE)),
        "the human deciding this request is shown {shown:?}, which never names \
         the rule that put it in front of them. The attribution is one field \
         away in auditEvent.reasons: {audit_reasons:?}"
    );
}

/// The same omission, one layer earlier: what the CALLER is told.
///
/// `risk.reasons` is the field every consumer surfaces as the cause — the SDKs
/// raise `PermissionError` with it, `scripts/demo_run.*` prints it as "Why:",
/// and the dashboard Live feed shows its first entry next to the verdict. It
/// already carries non-scoring causes (a policy refusal reads "tool X is not
/// registered in workspace policy" there), so the overlay attribution being
/// absent is an inconsistency, not a boundary: an action refused only by a
/// Dictum rule came back as
/// `{"decision":"block","risk":{"score":2,"reasons":["no high-risk rule matched"]}}`
/// — a refusal whose one stated reason contradicts it.
#[tokio::test]
async fn the_caller_is_told_which_rule_refused_the_action() {
    let server = spawn().await;
    let base = format!("http://{}", server.address);

    let inspect: Value = reqwest::Client::new()
        .post(format!("{base}/v1/inspect"))
        .bearer_auth(&server.api_key)
        .json(&serde_json::json!({
            "agentId": "openclaw-builder-01",
            "framework": "openclaw",
            "protocol": "http-function",
            "action": {
                "type": "file_read",
                "toolName": "filesystem.read",
                "payload": { "path": "README.md" }
            }
        }))
        .send()
        .await
        .expect("inspect responds")
        .json()
        .await
        .expect("inspect returns json");

    let reasons: Vec<String> = inspect["risk"]["reasons"]
        .as_array()
        .expect("risk reasons")
        .iter()
        .map(|r| r.to_string())
        .collect();

    assert!(
        reasons.iter().any(|r| r.contains(RULE)),
        "the caller is told decision={} with risk.reasons {reasons:?}, which \
         never names the rule that refused it",
        inspect["decision"]
    );

    // The attribution must appear once, not once per surface: `audit_event`
    // takes a clone of `risk.reasons` before the causes are appended, so a fix
    // that appends to both must not end up double-listing them in the audit.
    let audit: Vec<String> = inspect["auditEvent"]["reasons"]
        .as_array()
        .expect("audit reasons")
        .iter()
        .map(|r| r.to_string())
        .collect();
    assert_eq!(
        audit.iter().filter(|r| r.contains(RULE)).count(),
        1,
        "the attribution is duplicated in auditEvent.reasons: {audit:?}"
    );
}
