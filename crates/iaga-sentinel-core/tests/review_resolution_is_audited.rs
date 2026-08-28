//! Resolving a review must be visible in the audit trail.
//!
//! Measured against this tree before the change: an action on `terminal.exec`
//! (the demo tool with `requiresHumanReview: true`) came back `review` and
//! opened a request; `POST /v1/reviews/{id}` returned `200`; and `GET /v1/audit`
//! then returned exactly one row for that action, still `reviewStatus:
//! "pending"`, with no second row and no actor anywhere. The exportable
//! evidence record — the deliverable of this product — said no human had ever
//! adjudicated anything.
//!
//! Two things were missing and both are needed:
//!
//!   * the LINK. The `ReviewRequest` minted its own UUID, and neither table has
//!     a foreign key to the other, so nothing could say which action an
//!     adjudication belonged to. The request now carries the governed action's
//!     `event_id`.
//!   * the RECORD. The resolution is APPENDED as its own audit event rather
//!     than rewriting the governed action's row. That row's `timestamp` is the
//!     DECISION time and there is no second column for the adjudication time,
//!     so rewriting it in place would assert a human approved the action at the
//!     instant it was governed; the signed receipt was already built from the
//!     row as it stood, so an in-place update would also put the SQL log out of
//!     step with the evidence replayed from it. `append` is the only write
//!     `AuditStore` has.
//!
//! Consequence, asserted below rather than left implicit: the governed action's
//! own row keeps `reviewStatus: pending` for good. It records what was true
//! when the action was governed. The adjudication is the later row, joined to
//! it by `review-request:<eventId>` in `reasons`.

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
use iaga_sentinel::plugins::PluginRegistry;
use iaga_sentinel::server::app_state::AppState;
use iaga_sentinel::server::create_server::create_router;
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::{ApiKeyStore, PolicyStore, StorageBackend};
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

const AGENT: &str = "openclaw-builder-01";

struct TestServer {
    address: SocketAddr,
    api_key: String,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn() -> TestServer {
    let storage = Arc::new(
        SqliteStorage::new(&format!(
            "sqlite:file:review-audit-{}?mode=memory&cache=shared",
            Uuid::new_v4()
        ))
        .await
        .expect("in-memory sqlite"),
    );
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
        .store_key("seeded-key", &key_hash, "review-audit", &raw_key)
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
        #[cfg(feature = "dictum")]
        dictum_overlay: None,
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

fn client(key: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {key}").parse().expect("header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("client")
}

/// Drive one action into the review queue and return its inspect response.
async fn raise_a_review(server: &TestServer, admin: &reqwest::Client) -> Value {
    let res = admin
        .post(server.url("/v1/inspect"))
        .json(&serde_json::json!({
            "agentId": AGENT,
            "workspaceId": "ws-demo",
            "framework": "openai",
            "action": {
                "type": "shell",
                "toolName": "terminal.exec",
                "payload": { "command": "ls -la", "method": "exec", "intent": "list files" }
            }
        }))
        .send()
        .await
        .expect("inspect");
    assert_eq!(res.status(), StatusCode::OK, "inspect must answer");
    let body: Value = res.json().await.expect("inspect json");
    assert_eq!(
        body["decision"], "review",
        "terminal.exec is the demo tool with requiresHumanReview: true; got {body}"
    );
    body
}

async fn audit_rows(server: &TestServer, admin: &reqwest::Client) -> Vec<Value> {
    let res = admin
        .get(server.url("/v1/audit?limit=200"))
        .send()
        .await
        .expect("audit");
    let body: Value = res.json().await.expect("audit json");
    match body {
        Value::Array(rows) => rows,
        Value::Object(ref o) => o
            .get("events")
            .and_then(|e| e.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The review request and the audit event it was raised for share an id.
#[tokio::test]
async fn a_review_request_carries_the_id_of_the_action_that_opened_it() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let inspected = raise_a_review(&server, &admin).await;

    let review_id = inspected["reviewRequestId"]
        .as_str()
        .expect("a review verdict must publish its request id");
    let event_id = inspected["auditEvent"]["eventId"]
        .as_str()
        .expect("the response carries the audit event");

    assert_eq!(
        review_id, event_id,
        "the review must be joinable to the action it adjudicates"
    );
}

/// Resolving appends its own audit event, naming the outcome and the actor.
#[tokio::test]
async fn resolving_a_review_appends_an_audit_event() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let inspected = raise_a_review(&server, &admin).await;
    let review_id = inspected["reviewRequestId"]
        .as_str()
        .expect("id")
        .to_string();

    let before = audit_rows(&server, &admin).await.len();

    let res = admin
        .post(server.url(&format!("/v1/reviews/{review_id}")))
        .json(&serde_json::json!({ "status": "approved" }))
        .send()
        .await
        .expect("resolve");
    assert_eq!(res.status(), StatusCode::OK, "resolution must succeed");

    let rows = audit_rows(&server, &admin).await;
    assert_eq!(
        rows.len(),
        before + 1,
        "the adjudication must be appended as its own row"
    );

    let resolution = rows
        .iter()
        .find(|r| r["framework"] == "review-resolution")
        .unwrap_or_else(|| panic!("no review-resolution row in {rows:#?}"));

    assert_eq!(resolution["reviewStatus"], "approved");
    assert_eq!(resolution["agentId"], AGENT);

    let reasons: Vec<String> = resolution["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .map(|r| r.as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        reasons.iter().any(|r| r == "review-resolved:approved"),
        "the outcome must be stated: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|r| r == &format!("review-request:{review_id}")),
        "the row must join back to the request it adjudicates: {reasons:?}"
    );
    assert!(
        reasons.iter().any(|r| r.starts_with("resolved-by:")),
        "the resolving actor must be recorded: {reasons:?}"
    );
}

/// A rejection is recorded as a rejection, not as an approval.
#[tokio::test]
async fn a_rejection_is_recorded_as_a_rejection() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let inspected = raise_a_review(&server, &admin).await;
    let review_id = inspected["reviewRequestId"]
        .as_str()
        .expect("id")
        .to_string();

    admin
        .post(server.url(&format!("/v1/reviews/{review_id}")))
        .json(&serde_json::json!({ "status": "rejected" }))
        .send()
        .await
        .expect("resolve");

    let rows = audit_rows(&server, &admin).await;
    let resolution = rows
        .iter()
        .find(|r| r["framework"] == "review-resolution")
        .expect("a resolution row");
    assert_eq!(resolution["reviewStatus"], "rejected");
    assert_eq!(
        resolution["decision"], "block",
        "a rejection says the action may NOT proceed"
    );
}

/// The governed action's own row is never rewritten.
///
/// Asserted rather than left implicit: it keeps `reviewStatus: pending` because
/// that is what was true when the action was governed, and because the signed
/// receipt was built from it as it stood. The adjudication lives in the appended
/// row, joined by `review-request:<eventId>`.
#[tokio::test]
async fn the_governed_actions_own_row_is_not_rewritten() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let inspected = raise_a_review(&server, &admin).await;
    let review_id = inspected["reviewRequestId"]
        .as_str()
        .expect("id")
        .to_string();

    admin
        .post(server.url(&format!("/v1/reviews/{review_id}")))
        .json(&serde_json::json!({ "status": "approved" }))
        .send()
        .await
        .expect("resolve");

    let rows = audit_rows(&server, &admin).await;
    let governed = rows
        .iter()
        .find(|r| r["eventId"] == review_id.as_str())
        .expect("the governed action's row");
    assert_eq!(
        governed["reviewStatus"], "pending",
        "the governed row records what was true when the action was governed"
    );
    assert_ne!(
        governed["framework"], "review-resolution",
        "the two rows are distinct"
    );
}
