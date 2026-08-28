//! An agent-scoped API key must not submit evidence as another agent.

#[path = "support/app_state.rs"]
mod app_state_support;

use iaga_sentinel::auth::api_keys::generate_api_key;
use iaga_sentinel::core::types::ActionType;
use iaga_sentinel::storage::traits::{ApiKeyStore, KeyScope, PolicyStore};
use reqwest::StatusCode;
use serde_json::{json, Value};

async fn server() -> app_state_support::TestServer {
    let (state, storage, key) = app_state_support::state_with_sqlite("agent-key-binding").await;
    storage
        .upsert_workspace(&app_state_support::workspace(
            "binding-ws",
            vec![app_state_support::allow_tool(
                "filesystem.read",
                ActionType::FileRead,
            )],
            vec![],
        ))
        .await
        .expect("workspace");
    for agent_id in ["bound-agent", "other-agent"] {
        storage
            .upsert_profile(&app_state_support::agent(
                agent_id,
                "binding-ws",
                &["filesystem.read"],
                vec![ActionType::FileRead],
            ))
            .await
            .expect("profile");
    }
    app_state_support::serve(state, storage, key).await
}

fn inspect(agent_id: &str) -> Value {
    json!({
        "agentId": agent_id,
        "workspaceId": "binding-ws",
        "framework": "test",
        "protocol": "mcp",
        "action": {
            "type": "file_read",
            "toolName": "filesystem.read",
            "payload": {"path": "README.md"}
        }
    })
}

async fn bound_key(server: &app_state_support::TestServer, agent_id: &str) -> String {
    let created = server
        .client()
        .post(format!("{}/v1/auth/keys", server.base_url()))
        .json(&json!({"label": "bound", "scope": "agent", "agentId": agent_id}))
        .send()
        .await
        .expect("create bound key");
    assert_eq!(created.status(), StatusCode::CREATED);
    created.json::<Value>().await.expect("created JSON")["key"]
        .as_str()
        .expect("raw key")
        .to_string()
}

fn client(key: &str) -> reqwest::Client {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::AUTHORIZATION,
        format!("Bearer {key}").parse().expect("bearer header"),
    );
    reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("client")
}

#[tokio::test]
async fn one_agent_key_cannot_impersonate_another_agent() {
    let server = server().await;
    let admin = server.client();
    let created = admin
        .post(format!("{}/v1/auth/keys", server.base_url()))
        .json(&json!({"label": "bound", "scope": "agent", "agentId": "bound-agent"}))
        .send()
        .await
        .expect("create bound key");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: Value = created.json().await.expect("created JSON");
    let agent = reqwest::Client::new();
    let bearer = format!("Bearer {}", created["key"].as_str().expect("raw key"));

    let own = agent
        .post(format!("{}/v1/inspect", server.base_url()))
        .header(reqwest::header::AUTHORIZATION, &bearer)
        .json(&inspect("bound-agent"))
        .send()
        .await
        .expect("own inspect");
    assert_eq!(own.status(), StatusCode::OK, "own identity must work");

    let other = agent
        .post(format!("{}/v1/inspect", server.base_url()))
        .header(reqwest::header::AUTHORIZATION, &bearer)
        .json(&inspect("other-agent"))
        .send()
        .await
        .expect("impersonating inspect");
    let status = other.status();
    let body: Value = other.json().await.expect("error JSON");
    assert_eq!(status, StatusCode::FORBIDDEN, "cross-agent body: {body}");
    assert_eq!(body["error"], "agent_scope_mismatch");
    assert_eq!(created["agentId"], "bound-agent");
}

#[tokio::test]
async fn agent_keys_require_a_nonempty_binding() {
    let server = server().await;
    for body in [
        json!({"label": "missing", "scope": "agent"}),
        json!({"label": "blank", "scope": "agent", "agentId": "  "}),
    ] {
        let response = server
            .client()
            .post(format!("{}/v1/auth/keys", server.base_url()))
            .json(&body)
            .send()
            .await
            .expect("create invalid agent key");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "body={body}");
    }
}

#[tokio::test]
async fn migrated_unbound_agent_keys_fail_closed_until_rotated() {
    let server = server().await;
    let (raw, hash) = generate_api_key();
    server
        .storage
        .store_key_scoped("legacy-agent", &hash, "legacy", &raw, KeyScope::Agent, None)
        .await
        .expect("store legacy key");

    let response = client(&raw)
        .post(format!("{}/v1/inspect", server.base_url()))
        .json(&inspect("bound-agent"))
        .send()
        .await
        .expect("legacy inspect");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "agent_key_unbound"
    );
}

#[tokio::test]
async fn response_scan_cannot_be_attributed_to_another_agent() {
    let server = server().await;
    let agent = client(&bound_key(&server, "bound-agent").await);
    let response = agent
        .post(format!("{}/v1/response/scan", server.base_url()))
        .json(&json!({
            "requestId": "foreign-response",
            "agentId": "other-agent",
            "toolName": "tool.output",
            "responsePayload": "benign"
        }))
        .send()
        .await
        .expect("response scan");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "agent_scope_mismatch"
    );
}

#[tokio::test]
async fn nhi_identity_operations_cannot_target_another_agent() {
    let server = server().await;
    let registered = server
        .client()
        .post(format!("{}/v1/nhi/identities", server.base_url()))
        .json(&json!({"agentId": "other-agent", "capabilities": []}))
        .send()
        .await
        .expect("register identity");
    assert_eq!(registered.status(), StatusCode::CREATED);

    let agent = client(&bound_key(&server, "bound-agent").await);
    let response = agent
        .post(format!("{}/v1/nhi/challenge", server.base_url()))
        .json(&json!({"agentId": "other-agent"}))
        .send()
        .await
        .expect("challenge");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = agent
        .post(format!("{}/v1/nhi/attest", server.base_url()))
        .json(&json!({"agentId": "other-agent", "challenge": "foreign"}))
        .send()
        .await
        .expect("attestation");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = agent
        .post(format!("{}/v1/nhi/verify", server.base_url()))
        .json(&json!({
            "agentId": "other-agent",
            "challengeId": "foreign",
            "signature": "00"
        }))
        .send()
        .await
        .expect("verification");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn capability_token_does_not_widen_the_api_keys_identity() {
    let server = server().await;
    let admin = server.client();
    admin
        .post(format!("{}/v1/nhi/identities", server.base_url()))
        .json(&json!({"agentId": "other-agent", "capabilities": []}))
        .send()
        .await
        .expect("register identity");
    let token: Value = admin
        .post(format!("{}/v1/nhi/tokens", server.base_url()))
        .json(&json!({
            "agentId": "other-agent",
            "capabilities": ["read:self"],
            "ttlSeconds": 60
        }))
        .send()
        .await
        .expect("mint token")
        .json()
        .await
        .expect("token JSON");

    let response = client(&bound_key(&server, "bound-agent").await)
        .get(format!("{}/v1/profiles/other-agent", server.base_url()))
        .header(
            "x-iaga-capability-token",
            token["tokenId"].as_str().expect("token id"),
        )
        .send()
        .await
        .expect("cross-agent profile");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "agent_scope_mismatch"
    );
}

#[tokio::test]
async fn demo_adapter_that_submits_multiple_agents_is_admin_only() {
    let server = server().await;
    let response = client(&bound_key(&server, "bound-agent").await)
        .post(format!("{}/v1/demo/run-adapter", server.base_url()))
        .send()
        .await
        .expect("run adapter");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"],
        "admin_scope_required"
    );
}
