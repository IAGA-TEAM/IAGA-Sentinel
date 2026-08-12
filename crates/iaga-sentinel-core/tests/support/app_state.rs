//! An `AppState` backed by a throwaway SQLite database, for tests that want the
//! shipped defaults and nothing else.
//!
//! This is NOT yet the one place `AppState` gets built, and the docstring used
//! to claim it was. Measured in this tree: `taint_agent_window.rs` is the only
//! consumer, seven integration tests still hand-write the literal
//! (`containment_activation`, `cost_control_e2e`, `demo_e2e`, `det_replay`,
//! `e2e_http_tests`, `integration_tests`, `review_queue_reasons`), and
//! production carries seven more (six in `src/main.rs`, one in
//! `src/mcp_server/server.rs`).
//!
//! The pressure it was written to relieve is real — `AppState` has no
//! `Default`, so every new field is a compile error in nine files at once — but
//! the remaining seven tests are not simply un-migrated: each supplies its own
//! `plugin_registry`, `event_bus`, `webhook_manager`, `cors_origins` or
//! `dictum_overlay`, which this helper fixes. Adopting them means growing a
//! builder, not deleting a literal. Until that happens, treat this as a
//! convenience for the default case rather than a consolidation.
//!
//! Include with:
//!
//! ```ignore
//! #[path = "support/app_state.rs"]
//! mod app_state_support;
//! ```

#![allow(dead_code)] // each test binary uses a different subset

use std::net::SocketAddr;
use std::sync::Arc;

use iaga_sentinel::auth::api_keys::generate_api_key;
use iaga_sentinel::config::env::{AppEnv, NodeEnv, ServiceMode};
use iaga_sentinel::core::types::{
    ActionType, AgentProfile, AgentRole, GovernanceDecision, ProtocolKind, RateLimitConfig,
    ToolPolicy, WorkspacePolicy,
};
use iaga_sentinel::events::bus::EventBus;
use iaga_sentinel::events::webhooks::{DeadLetterQueue, WebhookManager};
use iaga_sentinel::modules::fingerprint::behavioral::BehavioralEngine;
use iaga_sentinel::modules::rate_limit::limiter::RateLimiter;
use iaga_sentinel::modules::threat_intel::feed::ThreatFeed;
use iaga_sentinel::plugins::PluginRegistry;
use iaga_sentinel::server::app_state::AppState;
use iaga_sentinel::server::create_server::create_router;
use iaga_sentinel::storage::sqlite::SqliteStorage;
use iaga_sentinel::storage::traits::{ApiKeyStore, StorageBackend};
use uuid::Uuid;

/// A running server plus the key needed to talk to it. Aborts on drop.
pub struct TestServer {
    pub address: SocketAddr,
    pub api_key: String,
    pub storage: Arc<SqliteStorage>,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }

    /// A client that already carries the bearer header.
    pub fn client(&self) -> reqwest::Client {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::AUTHORIZATION,
            format!("Bearer {}", self.api_key).parse().expect("header"),
        );
        reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .expect("client")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// An `AppState` with every store pointed at one in-memory SQLite database.
///
/// `label` only has to be unique enough to keep two concurrently-running test
/// binaries off each other's database; a UUID is appended regardless.
pub async fn state_with_sqlite(label: &str) -> (Arc<AppState>, Arc<SqliteStorage>, String) {
    let db_url = format!(
        "sqlite:file:{}-{}?mode=memory&cache=shared",
        label,
        Uuid::new_v4()
    );
    let storage = Arc::new(SqliteStorage::new(&db_url).await.expect("sqlite"));

    let (raw_key, key_hash) = generate_api_key();
    storage
        .store_key("seeded-key", &key_hash, label, &raw_key)
        .await
        .expect("seed key");

    let state = Arc::new(AppState {
        audit_store: storage.clone(),
        review_store: storage.clone(),
        policy_store: storage.clone(),
        api_key_store: storage.clone(),
        tenant_store: storage.clone(),
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

    (state, storage, raw_key)
}

/// Bind an ephemeral port and serve `state` on it.
pub async fn serve(
    state: Arc<AppState>,
    storage: Arc<SqliteStorage>,
    api_key: String,
) -> TestServer {
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
        api_key,
        storage,
        task,
    }
}

/// A tool a workspace allows outright.
pub fn allow_tool(name: &str, at: ActionType) -> ToolPolicy {
    ToolPolicy {
        tool_name: name.into(),
        allowed_action_types: vec![at],
        max_decision: GovernanceDecision::Allow,
        requires_human_review: false,
        ..Default::default()
    }
}

/// A workspace at the shipped default thresholds.
pub fn workspace(
    workspace_id: &str,
    tools: Vec<ToolPolicy>,
    allowed_domains: Vec<String>,
) -> WorkspacePolicy {
    WorkspacePolicy {
        workspace_id: workspace_id.into(),
        tenant_id: None,
        allowed_protocols: vec![ProtocolKind::Mcp, ProtocolKind::HttpFunction],
        allowed_domains,
        tools,
        threshold_block: 70,
        threshold_review: 35,
    }
}

/// A builder-role agent approved for `tools`.
pub fn agent(
    agent_id: &str,
    workspace_id: &str,
    tools: &[&str],
    types: Vec<ActionType>,
) -> AgentProfile {
    AgentProfile {
        agent_id: agent_id.into(),
        tenant_id: None,
        workspace_id: workspace_id.into(),
        framework: "test".into(),
        role: AgentRole::Builder,
        approved_tools: tools.iter().map(|t| (*t).to_string()).collect(),
        approved_secrets: vec![],
        baseline_action_types: types,
        tool_trust: 0.7,
    }
}
