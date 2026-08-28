#[path = "support/app_state.rs"]
mod app_state_support;

use reqwest::{Response, StatusCode};
use serde_json::{json, Value};

async fn start_server() -> app_state_support::TestServer {
    let (state, storage, key) = app_state_support::state_with_sqlite("http-error-contract").await;
    app_state_support::serve(state, storage, key).await
}

async fn error_mismatch(
    label: &str,
    response: Response,
    status: StatusCode,
    code: &str,
    message: String,
) -> Option<String> {
    let actual_status = response.status();
    let body: Value = response
        .json()
        .await
        .unwrap_or_else(|error| json!({"bodyParseError": error.to_string()}));
    let expected = json!({"error": code, "message": message});
    (actual_status != status || body != expected)
        .then(|| format!("{label}: expected {status} {expected}, got {actual_status} {body}"))
}

#[tokio::test]
async fn missing_resources_share_the_not_found_contract() {
    let server = start_server().await;
    let client = server.client();
    let base = server.base_url();
    let id = uuid::Uuid::new_v4().to_string();
    let agent = format!("missing-agent-{id}");
    let mut failures = Vec::new();

    let cases = [
        (
            "DLQ retry",
            client
                .post(format!("{base}/v1/webhooks/dlq/{id}/retry"))
                .send()
                .await
                .expect("DLQ retry request"),
            format!("DLQ entry not found: {id}"),
        ),
        (
            "DLQ delete",
            client
                .delete(format!("{base}/v1/webhooks/dlq/{id}"))
                .send()
                .await
                .expect("DLQ delete request"),
            format!("DLQ entry not found: {id}"),
        ),
        (
            "webhook delete",
            client
                .delete(format!("{base}/v1/webhooks/{id}"))
                .send()
                .await
                .expect("webhook delete request"),
            format!("Webhook not found: {id}"),
        ),
        (
            "capability token revoke",
            client
                .delete(format!("{base}/v1/nhi/tokens/{id}"))
                .send()
                .await
                .expect("token revoke request"),
            format!("Capability token not found: {id}"),
        ),
        (
            "capability token issue",
            client
                .post(format!("{base}/v1/nhi/tokens"))
                .json(&json!({
                    "agentId": agent,
                    "capabilities": ["read:self"],
                    "ttlSeconds": 60
                }))
                .send()
                .await
                .expect("token issue request"),
            format!(
                "No NHI identity for {agent}; register it with POST /v1/nhi/identities, or let the agent's first governed action create it"
            ),
        ),
        (
            "identity challenge",
            client
                .post(format!("{base}/v1/nhi/challenge"))
                .json(&json!({"agentId": agent}))
                .send()
                .await
                .expect("challenge request"),
            format!(
                "No NHI identity for {agent}; register it with POST /v1/nhi/identities, or let the agent's first governed action create it"
            ),
        ),
        (
            "sandbox approve",
            client
                .post(format!("{base}/v1/sandbox/{id}/approve"))
                .send()
                .await
                .expect("sandbox approve request"),
            format!("Sandbox entry not found: {id}"),
        ),
        (
            "sandbox reject",
            client
                .post(format!("{base}/v1/sandbox/{id}/reject"))
                .send()
                .await
                .expect("sandbox reject request"),
            format!("Sandbox entry not found: {id}"),
        ),
        (
            "fingerprint read",
            client
                .get(format!("{base}/v1/fingerprint/{agent}"))
                .send()
                .await
                .expect("fingerprint request"),
            format!("No behavioural fingerprint for agent: {agent}"),
        ),
        (
            "threat indicator delete",
            client
                .delete(format!("{base}/v1/threat-intel/indicators/{id}"))
                .send()
                .await
                .expect("threat indicator delete request"),
            format!("Threat indicator not found: {id}"),
        ),
        (
            "template read",
            client
                .get(format!("{base}/v1/templates/{id}"))
                .send()
                .await
                .expect("template request"),
            format!("Template not found: {id}"),
        ),
        (
            "session metrics",
            client
                .get(format!("{base}/v1/sessions/{id}/metrics"))
                .send()
                .await
                .expect("session metrics request"),
            format!("Session not found: {id}"),
        ),
    ];

    for (label, response, message) in cases {
        if let Some(failure) =
            error_mismatch(label, response, StatusCode::NOT_FOUND, "not_found", message).await
        {
            failures.push(failure);
        }
    }

    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[tokio::test]
async fn unsupported_audit_export_formats_are_rejected() {
    let server = start_server().await;
    let client = server.client();
    let base = server.base_url();

    for format in ["xml", "CSV"] {
        let response = client
            .get(format!("{base}/v1/audit/export?format={format}"))
            .send()
            .await
            .expect("audit export request");
        let status = response.status();
        let body: Value = response.json().await.expect("JSON error response");
        assert_eq!(status, StatusCode::BAD_REQUEST, "format={format}: {body}");
        assert_eq!(body["error"], "invalid_request", "format={format}: {body}");
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("json") && message.contains("csv"),
            "format={format}: {body}"
        );
    }
}

#[tokio::test]
async fn supported_and_empty_audit_export_formats_still_work() {
    let server = start_server().await;
    let client = server.client();
    let base = server.base_url();

    for query in ["", "?format=json", "?format=csv", "?format="] {
        let response = client
            .get(format!("{base}/v1/audit/export{query}"))
            .send()
            .await
            .expect("audit export request");
        assert_eq!(response.status(), StatusCode::OK, "query {query:?}");
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if query == "?format=csv" {
            assert!(content_type.starts_with("text/csv"), "{content_type}");
        } else {
            assert!(
                content_type.starts_with("application/json"),
                "{content_type}"
            );
        }
    }
}
