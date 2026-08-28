//! Capability tokens are an authorization primitive as of 2.1.0.
//!
//! Through 2.0.2 the product minted, signed, stored and published a credential
//! that authorized nothing: `verify_capability_token` never checked the
//! signature (so `signature` was decorative and the token was an opaque bearer
//! id), the tokens lived in a process-global `HashMap` (forgotten on restart,
//! invisible to other replicas), `revoke_token` had no route at all, and the
//! issuing route had no admin guard -- so any agent-scoped key could mint
//! `capabilities: ["*"]` for any agent.
//!
//! What it grants: an agent reading its OWN governance data. The per-agent
//! reads became admin-only in this same release (#18-class cross-tenant fix),
//! which left an agent with no way to see its own record. The token is bound to
//! exactly one `agent_id`, so it cannot widen into another agent's data no
//! matter what capabilities it lists.

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
use iaga_sentinel::storage::traits::{ApiKeyStore, NhiStore, PolicyStore, StorageBackend};
use reqwest::StatusCode;
use serde_json::Value;
use uuid::Uuid;

const CAP_HEADER: &str = "x-iaga-capability-token";
const AGENT: &str = "openclaw-builder-01";

struct TestServer {
    address: SocketAddr,
    api_key: String,
    storage: Arc<SqliteStorage>,
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
            "sqlite:file:cap-tokens-{}?mode=memory&cache=shared",
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
        .store_key("seeded-key", &key_hash, "cap", &raw_key)
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
        storage,
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

async fn agent_key(server: &TestServer, admin: &reqwest::Client) -> String {
    let created = admin
        .post(server.url("/v1/auth/keys"))
        .json(&serde_json::json!({
            "label": "cap-agent",
            "scope": "agent",
            "agentId": AGENT
        }))
        .send()
        .await
        .expect("create key");
    assert_eq!(created.status(), StatusCode::CREATED);
    let body: Value = created.json().await.expect("json");
    body["key"].as_str().expect("raw key").to_string()
}

/// Register the NHI identity, then mint a token for it.
async fn mint(
    server: &TestServer,
    admin: &reqwest::Client,
    agent_id: &str,
    capabilities: Value,
) -> Value {
    let registered = admin
        .post(server.url("/v1/nhi/identities"))
        .json(&serde_json::json!({ "agentId": agent_id, "capabilities": [] }))
        .send()
        .await
        .expect("register identity");
    assert!(
        registered.status().is_success(),
        "identity registration failed: {}",
        registered.status()
    );

    let issued = admin
        .post(server.url("/v1/nhi/tokens"))
        .json(&serde_json::json!({
            "agentId": agent_id,
            "capabilities": capabilities,
            "ttlSeconds": 3600
        }))
        .send()
        .await
        .expect("issue token");
    assert_eq!(issued.status(), StatusCode::CREATED, "issuing must succeed");
    issued.json().await.expect("token json")
}

#[tokio::test]
async fn issuing_a_capability_token_requires_admin() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);

    let resp = agent
        .post(server.url("/v1/nhi/tokens"))
        .json(&serde_json::json!({
            "agentId": AGENT,
            "capabilities": ["*"],
            "ttlSeconds": 3600
        }))
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "an agent key must not mint capability tokens, least of all `*`"
    );
    let body: Value = resp.json().await.expect("json");
    assert_eq!(body["error"], "admin_scope_required");
}

#[tokio::test]
async fn a_capability_token_grants_an_agent_its_own_record() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);
    let token = mint(&server, &admin, AGENT, serde_json::json!(["read:self"])).await;
    let token_id = token["tokenId"].as_str().expect("tokenId");

    // Without the token: refused, because the per-agent reads are admin-only.
    let without = agent
        .get(server.url(&format!("/v1/profiles/{AGENT}")))
        .send()
        .await
        .expect("request");
    assert_eq!(without.status(), StatusCode::FORBIDDEN);
    let body: Value = without.json().await.expect("json");
    assert_eq!(body["error"], "capability_required");

    // With it: allowed. This is the access the token actually grants.
    let with = agent
        .get(server.url(&format!("/v1/profiles/{AGENT}")))
        .header(CAP_HEADER, token_id)
        .send()
        .await
        .expect("request");
    assert_eq!(
        with.status(),
        StatusCode::OK,
        "a read:self token must open the agent's own profile"
    );
    let profile: Value = with.json().await.expect("json");
    assert_eq!(profile["agentId"], AGENT);
}

#[tokio::test]
async fn a_capability_token_does_not_widen_to_another_agent() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);
    // Deliberately the WILDCARD, to prove the binding beats the capability list.
    let token = mint(&server, &admin, AGENT, serde_json::json!(["*"])).await;
    let token_id = token["tokenId"].as_str().expect("tokenId");

    let resp = agent
        .get(server.url("/v1/profiles/openclaw-reviewer-01"))
        .header(CAP_HEADER, token_id)
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a token bound to {AGENT} must not read another agent even with `*`"
    );
}

#[tokio::test]
async fn a_revoked_capability_token_stops_working() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);
    let token = mint(&server, &admin, AGENT, serde_json::json!(["read:self"])).await;
    let token_id = token["tokenId"].as_str().expect("tokenId").to_string();

    let before = agent
        .get(server.url(&format!("/v1/profiles/{AGENT}")))
        .header(CAP_HEADER, &token_id)
        .send()
        .await
        .expect("request");
    assert_eq!(before.status(), StatusCode::OK, "precondition");

    let revoked = admin
        .delete(server.url(&format!("/v1/nhi/tokens/{token_id}")))
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);

    let after = agent
        .get(server.url(&format!("/v1/profiles/{AGENT}")))
        .header(CAP_HEADER, &token_id)
        .send()
        .await
        .expect("request");
    assert_eq!(
        after.status(),
        StatusCode::FORBIDDEN,
        "revocation must take effect immediately"
    );
}

#[tokio::test]
async fn revoking_a_capability_token_requires_admin() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);
    let token = mint(&server, &admin, AGENT, serde_json::json!(["read:self"])).await;
    let token_id = token["tokenId"].as_str().expect("tokenId");

    let resp = agent
        .delete(server.url(&format!("/v1/nhi/tokens/{token_id}")))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn an_unknown_token_id_is_refused_like_a_wrong_capability() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);

    let resp = agent
        .get(server.url(&format!("/v1/profiles/{AGENT}")))
        .header(CAP_HEADER, "00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body: Value = resp.json().await.expect("json");
    assert_eq!(
        body["error"], "capability_required",
        "an unknown id must not be distinguishable from an insufficient one"
    );
}

/// Admin keys are unaffected: the capability path is strictly additive.
#[tokio::test]
async fn an_admin_key_still_reads_any_agent_without_a_token() {
    let server = spawn().await;
    let admin = client(&server.api_key);

    for path in [
        format!("/v1/profiles/{AGENT}"),
        format!("/v1/analytics/agents/{AGENT}"),
    ] {
        let resp = admin.get(server.url(&path)).send().await.expect("request");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "admin must still read {path}"
        );
    }
}

/// The token also opens the analytics read, which is the other half of "its own
/// governance record".
#[tokio::test]
async fn a_capability_token_grants_its_own_analytics() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);
    let token = mint(&server, &admin, AGENT, serde_json::json!(["read:self"])).await;
    let token_id = token["tokenId"].as_str().expect("tokenId");

    let resp = agent
        .get(server.url(&format!("/v1/analytics/agents/{AGENT}")))
        .header(CAP_HEADER, token_id)
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::OK);
}

/// The issued token is persisted, not held in process memory: verification
/// reads it back out of the store on every request.
#[tokio::test]
async fn an_issued_token_is_persisted() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let token = mint(&server, &admin, AGENT, serde_json::json!(["read:self"])).await;

    assert!(token["signature"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(token["agentId"], AGENT);
    assert_eq!(token["valid"], true);

    // The name promises the durable half, and until now the body only read the
    // response JSON back -- which a purely in-memory mint would have satisfied
    // just as well. The row is the authority for revocation and for surviving a
    // restart, so the row is what this has to look at.
    let stored = server
        .storage
        .get_capability_token(token["tokenId"].as_str().expect("tokenId"))
        .await
        .expect("storage read")
        .expect("the issued token must be in storage, not just in the response");
    assert_eq!(stored.agent_id, AGENT);
    assert_eq!(stored.signature, token["signature"].as_str().unwrap());
    assert_eq!(stored.expires_at, token["expiresAt"].as_str().unwrap());
    assert!(stored.valid);
}

/// The other two routes the `CAP_READ_SELF` doc names.
///
/// Until 2.1.0 that sentence described four routes and only two of them had
/// actually been closed, so an agent reached its own fingerprint and rate-limit
/// state by having any key at all -- and so did every other agent's. Now the
/// refusal and the token are the same shape as profile and analytics.
#[tokio::test]
async fn a_capability_token_grants_its_own_fingerprint_and_rate_limit_state() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);
    let token = mint(&server, &admin, AGENT, serde_json::json!(["read:self"])).await;
    let token_id = token["tokenId"].as_str().expect("tokenId");

    for path in [
        format!("/v1/fingerprint/{AGENT}"),
        format!("/v1/rate-limit/status/{AGENT}"),
    ] {
        let without = agent.get(server.url(&path)).send().await.expect("request");
        assert_eq!(
            without.status(),
            StatusCode::FORBIDDEN,
            "a bare agent key must not read {path}"
        );
        let body: Value = without.json().await.expect("json");
        assert_eq!(body["error"], "capability_required", "for {path}");

        let with = agent
            .get(server.url(&path))
            .header(CAP_HEADER, token_id)
            .send()
            .await
            .expect("request");
        // 404 is a legitimate answer for a fingerprint that has not been built
        // yet; what must NOT come back is a 403. The point of the assertion is
        // the authorization decision, not whether the record exists.
        assert_ne!(
            with.status(),
            StatusCode::FORBIDDEN,
            "a read:self token must open {path} for its own agent"
        );
    }
}

/// The binding holds on the two new routes as well: the wildcard does not widen.
#[tokio::test]
async fn a_capability_token_does_not_widen_to_another_agents_fingerprint() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = client(&agent_key(&server, &admin).await);
    let token = mint(&server, &admin, AGENT, serde_json::json!(["*"])).await;
    let token_id = token["tokenId"].as_str().expect("tokenId");

    for path in [
        "/v1/fingerprint/openclaw-reviewer-01",
        "/v1/rate-limit/status/openclaw-reviewer-01",
    ] {
        let resp = agent
            .get(server.url(path))
            .header(CAP_HEADER, token_id)
            .send()
            .await
            .expect("request");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "a token bound to {AGENT} must not open {path}"
        );
    }
}

/// Registering an identity over HTTP must reach durable storage.
///
/// 0008 made the TOKEN durable so that "a token which now grants access has to
/// survive a restart". The identity it is bound to did not follow: the whole
/// verification path reads the agent's derived secret out of the in-memory
/// `IDENTITIES` map (`verify_token_signature`, which fails closed when the
/// agent is absent), and `main.rs` rehydrates that map at boot from
/// `list_identities()`. So an identity that never reaches storage is an
/// identity that is not there after a restart -- and every durable token bound
/// to it stops verifying, which is precisely what 0008 was added to prevent.
///
/// `execute_pipeline` has persisted its auto-registered identities since
/// v0.4.0; the explicit registration route never did.
#[tokio::test]
async fn a_registered_identity_reaches_durable_storage() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = "durable-identity-agent";

    let registered = admin
        .post(server.url("/v1/nhi/identities"))
        .json(&serde_json::json!({ "agentId": agent, "capabilities": ["read:self"] }))
        .send()
        .await
        .expect("register identity");
    assert_eq!(registered.status(), StatusCode::CREATED);

    let stored = server
        .storage
        .get_identity(agent)
        .await
        .expect("storage read");
    assert!(
        stored.is_some(),
        "201 Created but nothing was written: after a restart this agent is gone          and every capability token bound to it stops verifying"
    );

    // The secret is the half that actually matters: rehydration needs it to
    // rebuild `IDENTITIES`, and without it the token signature cannot verify.
    let secret = server
        .storage
        .get_secret_key_hex(agent)
        .await
        .expect("storage read");
    assert!(
        secret.is_some_and(|s| !s.is_empty()),
        "identity stored without its derived secret: rehydration cannot verify its tokens"
    );
}

/// A TTL that cannot be honoured is refused, not minted.
///
/// `ttlSeconds` went straight into `Duration::seconds`. A negative value minted
/// `201 valid: true` on a token that was already expired — the API said good,
/// every check said no — and a value large enough to push the expiry past year
/// 9999 minted one that could not be rendered back at all. Both were dead on
/// arrival and neither said so.
#[tokio::test]
async fn an_unusable_ttl_is_refused_rather_than_minted() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = "ttl-agent";
    admin
        .post(server.url("/v1/nhi/identities"))
        .json(&serde_json::json!({ "agentId": agent, "capabilities": [] }))
        .send()
        .await
        .expect("register identity");

    for ttl in [-1_i64, 0, i64::MAX, 400 * 24 * 60 * 60] {
        let res = admin
            .post(server.url("/v1/nhi/tokens"))
            .json(&serde_json::json!({
                "agentId": agent, "capabilities": ["read:self"], "ttlSeconds": ttl
            }))
            .send()
            .await
            .expect("issue token");
        assert_ne!(
            res.status(),
            StatusCode::CREATED,
            "ttlSeconds={ttl} must not mint a token"
        );
    }
}

/// An ordinary TTL still works, and so does the boundary.
#[tokio::test]
async fn a_usable_ttl_still_mints() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent = "ttl-ok-agent";
    admin
        .post(server.url("/v1/nhi/identities"))
        .json(&serde_json::json!({ "agentId": agent, "capabilities": [] }))
        .send()
        .await
        .expect("register identity");

    for ttl in [1_i64, 3600, 365 * 24 * 60 * 60] {
        let res = admin
            .post(server.url("/v1/nhi/tokens"))
            .json(&serde_json::json!({
                "agentId": agent, "capabilities": ["read:self"], "ttlSeconds": ttl
            }))
            .send()
            .await
            .expect("issue token");
        assert_eq!(
            res.status(),
            StatusCode::CREATED,
            "ttlSeconds={ttl} is legitimate and must mint"
        );
    }
}

/// An operator can see what is currently authorized.
///
/// Minting and revoking both take an id the caller already holds, so until this
/// route existed a token could only be withdrawn if someone had written its id
/// down at mint time. For a bearer credential that grants access to another
/// agent's governance data, "what is live right now" had no answer.
#[tokio::test]
async fn outstanding_tokens_can_be_listed() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let a = mint(&server, &admin, AGENT, serde_json::json!(["read:self"])).await;
    let b = mint(
        &server,
        &admin,
        "second-agent",
        serde_json::json!(["read:self"]),
    )
    .await;

    let res = admin
        .get(server.url("/v1/nhi/tokens"))
        .send()
        .await
        .expect("list tokens");
    assert_eq!(res.status(), StatusCode::OK);
    let listed: Vec<Value> = res.json().await.expect("token list json");

    let ids: Vec<&str> = listed
        .iter()
        .filter_map(|t| t["tokenId"].as_str())
        .collect();
    for token in [&a, &b] {
        let id = token["tokenId"].as_str().expect("tokenId");
        assert!(
            ids.contains(&id),
            "minted token {id} must be listed: {ids:?}"
        );
    }

    let row = listed
        .iter()
        .find(|t| t["tokenId"] == a["tokenId"])
        .expect("the first token");
    assert_eq!(row["agentId"], AGENT);
    assert_eq!(row["valid"], true);
    assert!(row["expiresAt"].as_str().is_some_and(|s| !s.is_empty()));
}

/// The signature is the server's own HMAC over the row. An inventory does not
/// need it, and publishing it would hand out a valid MAC under the agent's
/// derived secret next to the exact plaintext it covers.
#[tokio::test]
async fn the_listing_never_publishes_a_token_signature() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let minted = mint(&server, &admin, AGENT, serde_json::json!(["read:self"])).await;
    let signature = minted["signature"].as_str().expect("mint returns one");

    let listed: Vec<Value> = admin
        .get(server.url("/v1/nhi/tokens"))
        .send()
        .await
        .expect("list tokens")
        .json()
        .await
        .expect("json");

    let body = serde_json::to_string(&listed).expect("serialize");
    assert!(
        !body.contains(signature),
        "the listing leaked a token signature: {body}"
    );
    for row in &listed {
        assert!(
            row.get("signature").is_none(),
            "no row may carry a signature field: {row}"
        );
    }
}

/// Admin-only, like minting and revoking.
#[tokio::test]
async fn listing_tokens_requires_admin() {
    let server = spawn().await;
    let admin = client(&server.api_key);
    let agent_key = agent_key(&server, &admin).await;

    let res = client(&agent_key)
        .get(server.url("/v1/nhi/tokens"))
        .send()
        .await
        .expect("list tokens");
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "an agent-scoped key must not enumerate the fleet's tokens"
    );
}
