use std::sync::Arc;

use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncWriteExt, BufReader};

use crate::core::errors::SentinelError;
use crate::core::types::{InspectRequest, ResponseScanRequest};
use crate::events::bus::SentinelEvent;
use crate::mcp_proxy::protocol::{
    CappedLines, JsonRpcRequest, JsonRpcResponse, McpToolCallParams, McpToolInfo, MAX_LINE_BYTES,
};
use crate::pipeline::execute_pipeline::{execute_pipeline, scan_response};
use crate::server::app_state::AppState;

const DEFAULT_MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const TOOL_INSPECT: &str = "iaga.inspect";
const TOOL_RESPONSE_SCAN: &str = "iaga.response_scan";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InitializeResult {
    protocol_version: String,
    capabilities: Value,
    server_info: ServerInfo,
}

#[derive(Serialize)]
struct ServerInfo {
    name: String,
    version: String,
}

#[derive(Serialize)]
struct ToolContent {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolCallResult {
    content: Vec<ToolContent>,
    is_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    structured_content: Option<Value>,
}

pub async fn run_mcp_server(state: Arc<AppState>) -> Result<(), SentinelError> {
    tracing::info!("Starting MCP server mode");

    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = CappedLines::new(BufReader::new(stdin), MAX_LINE_BYTES);

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(error = %error, "Invalid JSON-RPC request in MCP server mode");
                continue;
            }
        };

        if let Some(response) = handle_request(&request, &state).await {
            let line = match serde_json::to_string(&response) {
                Ok(line) => line,
                Err(error) => {
                    tracing::error!(error = %error, "Failed to serialize MCP server response");
                    continue;
                }
            };

            stdout.write_all(line.as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }

    Ok(())
}

async fn handle_request(
    request: &JsonRpcRequest,
    state: &Arc<AppState>,
) -> Option<JsonRpcResponse> {
    match request.method.as_str() {
        "initialize" => Some(handle_initialize(request)),
        "notifications/initialized" => None,
        "ping" => Some(JsonRpcResponse::success(request.id.clone(), json!({}))),
        "tools/list" => Some(JsonRpcResponse::success(
            request.id.clone(),
            json!({ "tools": tool_definitions() }),
        )),
        "tools/call" => Some(handle_tool_call(request, state).await),
        method if request.id.is_none() && method.starts_with("notifications/") => None,
        _ => Some(JsonRpcResponse::error(
            request.id.clone(),
            -32601,
            format!(
                "Method '{}' not supported by IAGA Sentinel MCP server",
                request.method
            ),
        )),
    }
}

fn handle_initialize(request: &JsonRpcRequest) -> JsonRpcResponse {
    let protocol_version = request
        .params
        .as_object()
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_MCP_PROTOCOL_VERSION)
        .to_string();

    JsonRpcResponse::success(
        request.id.clone(),
        serde_json::to_value(InitializeResult {
            protocol_version,
            capabilities: json!({ "tools": {} }),
            server_info: ServerInfo {
                name: "iaga-sentinel".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
        })
        .unwrap_or_else(|_| json!({})),
    )
}

async fn handle_tool_call(request: &JsonRpcRequest, state: &Arc<AppState>) -> JsonRpcResponse {
    let tool_call: McpToolCallParams = match serde_json::from_value(request.params.clone()) {
        Ok(tool_call) => tool_call,
        Err(error) => {
            return JsonRpcResponse::error(
                request.id.clone(),
                -32602,
                format!("Invalid tools/call params: {error}"),
            );
        }
    };

    let arguments = match serde_json::to_value(&tool_call.arguments) {
        Ok(arguments) => arguments,
        Err(error) => {
            return JsonRpcResponse::error(
                request.id.clone(),
                -32603,
                format!("Failed to serialize tool arguments: {error}"),
            );
        }
    };

    let result = match tool_call.name.as_str() {
        TOOL_INSPECT | "inspect" => match serde_json::from_value::<InspectRequest>(arguments) {
            Ok(inspect_request) => match execute_pipeline(&inspect_request, state).await {
                Ok(result) => {
                    state
                        .event_bus
                        .publish(SentinelEvent::from_governance_result(&result));
                    tool_success(&result)
                }
                Err(error) => tool_failure(&format!("inspect failed: {error}")),
            },
            Err(error) => {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    -32602,
                    format!("Invalid inspect arguments: {error}"),
                );
            }
        },
        TOOL_RESPONSE_SCAN | "response_scan" => {
            match serde_json::from_value::<ResponseScanRequest>(arguments) {
                Ok(scan_request) => {
                    let result = scan_response(&scan_request);
                    tool_success(&result)
                }
                Err(error) => {
                    return JsonRpcResponse::error(
                        request.id.clone(),
                        -32602,
                        format!("Invalid response_scan arguments: {error}"),
                    );
                }
            }
        }
        _ => {
            return JsonRpcResponse::error(
                request.id.clone(),
                -32601,
                format!("Unknown IAGA Sentinel tool '{}'", tool_call.name),
            );
        }
    };

    JsonRpcResponse::success(request.id.clone(), result)
}

fn tool_definitions() -> Vec<McpToolInfo> {
    vec![
        McpToolInfo {
            name: TOOL_INSPECT.to_string(),
            description: Some(
                "Run an IAGA Sentinel governance inspection on an action before you take it. \
                 Returns allow | review | block plus risk and signed evidence. \
                 action.payload should carry the target tool's fields — filesystem.read: {path}; \
                 filesystem.write: {path, content}; terminal.exec: {command}; \
                 http.fetch: {method, and a destination under any of destination/url/uri/ \
                 endpoint/href/target/webhook}. An `intent` string is optional but recommended \
                 (it enriches the receipt; it is not required and never causes a block on its own)."
                    .to_string(),
            ),
            input_schema: Some(json!({
                "type": "object",
                "required": ["agentId", "framework", "action"],
                "properties": {
                    "agentId": { "type": "string" },
                    "tenantId": { "type": ["string", "null"] },
                    "workspaceId": { "type": ["string", "null"] },
                    "framework": { "type": "string" },
                    "protocol": {
                        "type": ["string", "null"],
                        "enum": ["mcp", "acp", "a2a", "http-function", "unknown", null]
                    },
                    "requestedSecrets": {
                        "type": ["array", "null"],
                        "items": { "type": "string" }
                    },
                    "metadata": { "type": ["object", "null"] },
                    "action": {
                        "type": "object",
                        "required": ["type", "toolName", "payload"],
                        "properties": {
                            "type": {
                                "type": "string",
                                "enum": ["shell", "file_read", "file_write", "http", "db_query", "email", "custom"]
                            },
                            "toolName": { "type": "string" },
                            "payload": {
                                "type": "object",
                                "description": "Target tool's fields. filesystem.read: {path}; filesystem.write: {path, content}; terminal.exec: {command}; http.fetch: {method, plus a destination under any of destination/url/uri/endpoint/href/target/webhook}. Optional `intent` (string) is recommended for the evidence trail but never required."
                            }
                        }
                    }
                }
            })),
        },
        McpToolInfo {
            name: TOOL_RESPONSE_SCAN.to_string(),
            description: Some("Scan a tool response for leaked secrets or PII".to_string()),
            input_schema: Some(json!({
                "type": "object",
                "required": ["requestId", "agentId", "toolName", "responsePayload"],
                "properties": {
                    "requestId": { "type": "string" },
                    "agentId": { "type": "string" },
                    "toolName": { "type": "string" },
                    "responsePayload": {},
                    "metadata": { "type": ["object", "null"] }
                }
            })),
        },
    ]
}

fn tool_success<T: Serialize>(payload: &T) -> Value {
    let structured_content = serde_json::to_value(payload).unwrap_or_else(|_| json!({}));
    serde_json::to_value(ToolCallResult {
        content: vec![ToolContent {
            content_type: "text".to_string(),
            text: serde_json::to_string_pretty(&structured_content)
                .unwrap_or_else(|error| format!("serialization failed: {error}")),
        }],
        is_error: false,
        structured_content: Some(structured_content),
    })
    .unwrap_or_else(|_| json!({}))
}

fn tool_failure(message: &str) -> Value {
    serde_json::to_value(ToolCallResult {
        content: vec![ToolContent {
            content_type: "text".to_string(),
            text: message.to_string(),
        }],
        is_error: true,
        structured_content: Some(json!({ "error": message })),
    })
    .unwrap_or_else(|_| json!({}))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use serde_json::json;

    use crate::config::env::{AppEnv, NodeEnv, ServiceMode};
    use crate::core::types::{
        ActionDetail, ActionType, AgentProfile, AgentRole, ProtocolKind, RateLimitConfig,
        ToolPolicy, WorkspacePolicy,
    };
    use crate::events::bus::EventBus;
    use crate::events::webhooks::{DeadLetterQueue, WebhookManager};
    use crate::modules::fingerprint::behavioral::BehavioralEngine;
    use crate::modules::rate_limit::limiter::RateLimiter;
    use crate::modules::threat_intel::feed::ThreatFeed;
    use crate::plugins::PluginRegistry;
    use crate::storage::sqlite::SqliteStorage;
    use crate::storage::traits::{PolicyStore, StorageBackend};

    use super::*;

    async fn build_state() -> Arc<AppState> {
        let storage = Arc::new(
            SqliteStorage::new("sqlite::memory:")
                .await
                .expect("failed to create in-memory SQLite"),
        );

        storage
            .upsert_profile(&AgentProfile {
                agent_id: "mcp-server-agent".into(),
                tenant_id: None,
                workspace_id: "ws-mcp-server".into(),
                framework: "mcp".into(),
                role: AgentRole::Builder,
                approved_tools: vec!["filesystem.read".into()],
                approved_secrets: vec![],
                baseline_action_types: vec![ActionType::FileRead],
                tool_trust: 0.7,
            })
            .await
            .expect("failed to seed profile");

        storage
            .upsert_workspace(&WorkspacePolicy {
                workspace_id: "ws-mcp-server".into(),
                tenant_id: None,
                allowed_protocols: vec![ProtocolKind::Mcp],
                tools: vec![ToolPolicy {
                    tool_name: "filesystem.read".into(),
                    allowed_action_types: vec![ActionType::FileRead],
                    max_decision: crate::core::types::GovernanceDecision::Allow,
                    requires_human_review: false,
                    ..Default::default()
                }],
                allowed_domains: vec![],
                threshold_block: 70,
                threshold_review: 35,
            })
            .await
            .expect("failed to seed workspace");

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
            event_bus: EventBus::new(32),
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
            auth_cache: crate::auth::cache::AuthCache::from_env(),
            receipts: None,
            reasoning: None,
            #[cfg(feature = "dictum")]
            dictum_overlay: None,
        })
    }

    #[tokio::test]
    async fn test_initialize_returns_tools_capability() {
        let state = build_state().await;
        let response = handle_request(
            &JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(1)),
                method: "initialize".into(),
                params: json!({ "protocolVersion": "2024-11-05" }),
            },
            &state,
        )
        .await
        .expect("initialize should return a response");

        let result = response.result.expect("initialize should return result");
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(result["capabilities"]["tools"].is_object());
        assert_eq!(result["serverInfo"]["name"], "iaga-sentinel");
    }

    #[tokio::test]
    async fn test_tools_list_exposes_governance_tools() {
        let state = build_state().await;
        let response = handle_request(
            &JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(2)),
                method: "tools/list".into(),
                params: json!({}),
            },
            &state,
        )
        .await
        .expect("tools/list should return a response");

        let tools = response.result.expect("tools/list should return result")["tools"]
            .as_array()
            .cloned()
            .expect("tools list should be an array");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], TOOL_INSPECT);
        assert_eq!(tools[1]["name"], TOOL_RESPONSE_SCAN);
    }

    #[tokio::test]
    async fn test_tools_call_inspect_returns_structured_result() {
        let state = build_state().await;
        let mut arguments = HashMap::new();
        arguments.insert("agentId".to_string(), json!("mcp-server-agent"));
        arguments.insert("workspaceId".to_string(), json!("ws-mcp-server"));
        arguments.insert("framework".to_string(), json!("mcp"));
        arguments.insert("protocol".to_string(), json!("mcp"));
        arguments.insert(
            "action".to_string(),
            json!(ActionDetail {
                action_type: ActionType::FileRead,
                tool_name: "filesystem.read".into(),
                payload: HashMap::from([
                    ("path".to_string(), json!("README.md")),
                    ("intent".to_string(), json!("read documentation")),
                ]),
            }),
        );

        let response = handle_request(
            &JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(3)),
                method: "tools/call".into(),
                params: json!({
                    "name": TOOL_INSPECT,
                    "arguments": arguments,
                }),
            },
            &state,
        )
        .await
        .expect("tools/call should return a response");

        let result = response.result.expect("tools/call should return result");
        assert_eq!(result["isError"], false);
        assert_eq!(result["structuredContent"]["decision"], "allow");
        assert_eq!(result["structuredContent"]["protocol"], "mcp");
    }

    /// Regression (F2): `iaga mcp-server` used to build `AppState` with
    /// `dictum_overlay = None`, so an agent's authored policy never governed the
    /// calls it made over MCP — it only shared a database with `iaga serve`.
    /// With the overlay present, the MCP inspect path must apply it. Here a
    /// policy tightens an otherwise-`allow` `file_read` to `review`, and the
    /// attribution must surface in `auditEvent.reasons`.
    #[cfg(feature = "dictum")]
    #[tokio::test]
    async fn test_tools_call_inspect_applies_dictum_overlay() {
        use crate::pipeline::dictum_overlay::DictumOverlay;

        let dir = std::env::temp_dir().join(format!(
            "iaga-mcp-overlay-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("agent_rules.dictum");
        std::fs::write(
            &file,
            r#"policy "human_reviews_reads" { when action.kind == "file_read" then review, reason="a human reviews reads" }"#,
        )
        .expect("write policy");
        let overlay = DictumOverlay::load(&file).expect("overlay must load");
        let _ = std::fs::remove_file(&file);

        let mut state = build_state().await;
        Arc::get_mut(&mut state)
            .expect("state is uniquely owned here")
            .dictum_overlay = Some(Arc::new(overlay));

        let mut arguments = HashMap::new();
        arguments.insert("agentId".to_string(), json!("mcp-server-agent"));
        arguments.insert("workspaceId".to_string(), json!("ws-mcp-server"));
        arguments.insert("framework".to_string(), json!("mcp"));
        arguments.insert("protocol".to_string(), json!("mcp"));
        arguments.insert(
            "action".to_string(),
            json!(ActionDetail {
                action_type: ActionType::FileRead,
                tool_name: "filesystem.read".into(),
                payload: HashMap::from([
                    ("path".to_string(), json!("README.md")),
                    ("intent".to_string(), json!("read documentation")),
                ]),
            }),
        );

        let response = handle_request(
            &JsonRpcRequest {
                jsonrpc: "2.0".into(),
                id: Some(json!(4)),
                method: "tools/call".into(),
                params: json!({ "name": TOOL_INSPECT, "arguments": arguments }),
            },
            &state,
        )
        .await
        .expect("tools/call should return a response");

        let result = response.result.expect("tools/call should return result");
        assert_eq!(
            result["structuredContent"]["decision"], "review",
            "overlay must tighten the MCP verdict from allow to review"
        );
        let reasons = result["structuredContent"]["auditEvent"]["reasons"]
            .as_array()
            .expect("auditEvent.reasons should be an array");
        assert!(
            reasons.iter().any(|r| r
                .as_str()
                .map(|s| s.contains("dictum[human_reviews_reads]"))
                .unwrap_or(false)),
            "overlay attribution must appear in auditEvent.reasons, got: {reasons:?}"
        );
    }
}
