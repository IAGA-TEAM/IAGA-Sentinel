//! The access log must name the key that made the request.
//!
//! `agentId` on `/v1/inspect` is asserted by the caller and an API key is not
//! bound to an agent (see the Known gaps entry in CHANGELOG.md), so an action
//! submitted under someone else's agent id was attributable to nothing at all:
//! the audit row records the asserted agent, and the request log recorded
//! method, path, status and elapsed — and no identity. This does not close that
//! gap; it makes the request traceable to a key in the operator's own logs.
//!
//! The mechanism is not obvious and is the reason this test exists.
//! `request_logging_middleware` is layered onto the MERGED router while
//! `auth_middleware` is layered onto the protected half alone, so the logger is
//! the OUTER layer and runs FIRST inbound: when it could read
//! `request.extensions()`, auth has not run; by the time auth inserts
//! `AuthContext`, the request has been moved into `next.run(...)`. axum copies
//! nothing from request extensions onto the response, so `AuthContext::run`
//! puts a copy in the RESPONSE extensions deliberately.
//!
//! TWO requests, not one. The first misses the auth cache and takes the cold
//! Argon2 path; every subsequent request takes `auth_cache.lookup`, which is
//! the path production actually runs (the cache is on by default). A test that
//! issued one request would witness only the cold branch.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use iaga_sentinel::auth::api_keys::generate_api_key;
use iaga_sentinel::config::env::{AppEnv, NodeEnv, ServiceMode};
use iaga_sentinel::core::types::RateLimitConfig;
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

/// A `MakeWriter` that appends every formatted event to a shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("log buffer").clone()).into_owned()
    }
}

impl io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

async fn spawn() -> (SocketAddr, String) {
    let storage = Arc::new(
        SqliteStorage::new(&format!(
            "sqlite:file:req-log-{}?mode=memory&cache=shared",
            Uuid::new_v4()
        ))
        .await
        .expect("in-memory sqlite"),
    );
    let (raw_key, key_hash) = generate_api_key();
    storage
        .store_key("log-key", &key_hash, "req-log", &raw_key)
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
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve");
    });
    (address, raw_key)
}

/// One test, one global subscriber: `set_global_default` can only be called
/// once per process, so everything this file asserts happens in here.
#[tokio::test]
async fn the_access_log_names_the_key_on_both_the_cold_and_the_cached_path() {
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("one subscriber per process");

    let (address, key) = spawn().await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/v1/auth/keys");

    // 1. cold path — auth cache miss, Argon2 verification.
    let first = client
        .get(&url)
        .bearer_auth(&key)
        .send()
        .await
        .expect("first request");
    assert!(first.status().is_success(), "admin key must be accepted");

    // 2. cached path — what every later request in production takes.
    let second = client
        .get(&url)
        .bearer_auth(&key)
        .send()
        .await
        .expect("second request");
    assert!(second.status().is_success());

    // Give the server task a moment to emit both completion lines.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let log = captured.text();

    let completed: Vec<&str> = log
        .lines()
        .filter(|l| l.contains("http request completed") && l.contains("/v1/auth/keys"))
        .collect();
    assert!(
        completed.len() >= 2,
        "both requests must be logged; got {}:\n{log}",
        completed.len()
    );
    for line in &completed {
        assert!(
            line.contains("key_id="),
            "every completed-request line must name the key: {line}"
        );
        assert!(
            !line.contains("key_id=-"),
            "an authenticated request must not log the no-identity placeholder: {line}"
        );
    }

    // An unauthenticated request is rejected before auth attaches anything, and
    // must log the placeholder rather than inventing an actor.
    let anon = client.get(&url).send().await.expect("anonymous request");
    assert!(anon.status().is_client_error(), "no key must be refused");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let log = captured.text();
    let anon_line = log
        .lines()
        .rfind(|l| l.contains("http request completed") && l.contains("/v1/auth/keys"))
        .expect("the anonymous request must be logged");
    assert!(
        anon_line.contains("key_id=-"),
        "a request with no identity logs the placeholder, never a guess: {anon_line}"
    );
}
