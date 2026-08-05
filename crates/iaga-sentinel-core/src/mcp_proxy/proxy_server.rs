use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};

use crate::core::errors::SentinelError;
use crate::server::app_state::AppState;

use super::protocol::*;
#[cfg(feature = "cost-control")]
use super::tool_interceptor::infer_action_type;
use super::tool_interceptor::{intercept_tool_call, InterceptResult};

/// Record a `tools/call` that arrived as a notification and was dropped.
///
/// Separate from the governance path on purpose: nothing was governed, because
/// nothing was executed. The row exists so that "someone tried to invoke a tool
/// through this proxy in a shape that bypasses the request/response contract" is
/// answerable from the audit log rather than from whatever kept the proxy's
/// stderr. It is recorded as a Block, since that is what happened to the call.
///
/// Best-effort: a storage failure must not take down a live proxy that is
/// otherwise correctly refusing the call.
pub(crate) async fn audit_dropped_notification(
    request: &JsonRpcRequest,
    config: &McpProxyConfig,
    state: &Arc<AppState>,
) {
    let tool_name = serde_json::from_value::<McpToolCallParams>(request.params.clone())
        .map(|p| p.name)
        .unwrap_or_else(|_| "<unparseable>".to_string());

    let stored = crate::core::types::StoredAuditEvent {
        event_id: uuid::Uuid::new_v4().to_string(),
        agent_id: config.agent_id.clone(),
        tenant_id: None,
        framework: "mcp-proxy".to_string(),
        action_type: crate::core::types::ActionType::Custom,
        tool_name,
        input_sha256: String::new(),
        decision: crate::core::types::GovernanceDecision::Block,
        timestamp: chrono::Utc::now().to_rfc3339(),
        reasons: vec![
            "dropped tools/call sent as a JSON-RPC notification (no id)".to_string(),
            "refused to forward an ungoverned tool call".to_string(),
        ],
        review_status: crate::core::types::ReviewStatus::NotRequired,
        risk_score: 0,
        usage: None,
        session_id: None,
    };
    if let Err(e) = state.audit_store.append(&stored).await {
        tracing::error!(error = %e, "failed to audit a dropped tools/call notification");
    }
}

/// MCP Proxy Server configuration.
pub struct McpProxyConfig {
    /// Agent ID to use for governance checks.
    pub agent_id: String,
    /// Command to launch the downstream MCP server.
    pub downstream_command: String,
    /// Arguments for the downstream command.
    pub downstream_args: Vec<String>,
    /// Environment variables for the downstream process.
    pub downstream_env: HashMap<String, String>,
}

/// Run the MCP proxy: reads JSON-RPC from stdin, governs tools/call,
/// forwards to downstream MCP server, returns responses to stdout.
pub async fn run_mcp_proxy(
    config: McpProxyConfig,
    state: Arc<AppState>,
) -> Result<(), SentinelError> {
    tracing::info!(
        agent_id = %config.agent_id,
        downstream = %config.downstream_command,
        "Starting MCP proxy mode"
    );

    // Spawn downstream MCP server
    let mut downstream = spawn_downstream(&config)?;
    let downstream_stdin = downstream
        .stdin
        .take()
        .ok_or_else(|| SentinelError::Proxy("Failed to capture downstream stdin".into()))?;
    let downstream_stdout = downstream
        .stdout
        .take()
        .ok_or_else(|| SentinelError::Proxy("Failed to capture downstream stdout".into()))?;

    let mut downstream_writer = downstream_stdin;
    let mut downstream_reader = CappedLines::new(BufReader::new(downstream_stdout), MAX_LINE_BYTES);

    // Read from our stdin (client → proxy)
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut client_reader = CappedLines::new(BufReader::new(stdin), MAX_LINE_BYTES);

    loop {
        tokio::select! {
            // Client → Proxy
            line = client_reader.next_line() => {
                match line {
                    Ok(Some(line)) if !line.trim().is_empty() => {
                        let request: JsonRpcRequest = match serde_json::from_str(&line) {
                            Ok(r) => r,
                            Err(e) => {
                                tracing::warn!(error = %e, "Invalid JSON-RPC from client");
                                continue;
                            }
                        };

                        // PIP-MCP-NOTIFY-1: a JSON-RPC message with no `id` is a
                        // notification. It gets no response, so relaying one and
                        // then waiting for a reply blocks the proxy forever — and
                        // `notifications/initialized` is the mandatory third step
                        // of the MCP handshake, so every spec-compliant client hit
                        // this on its first connection. Forward and move on.
                        // A `tools/call` without an id is malformed (tools/call is
                        // a request); drop it rather than forward an ungoverned call.
                        if request.id.is_none() {
                            if request.method == "tools/call" {
                                tracing::warn!(
                                    "dropping malformed tools/call notification (no id); \
                                     refusing to forward an ungoverned tool call"
                                );
                                // ...and record it. Dropping was correct — forwarding
                                // would have been an ungoverned tool call — but the
                                // only trace was a stderr line, and stderr is exactly
                                // what a client discards (stdout is kept clean for the
                                // JSON-RPC channel). An attempt to invoke a tool
                                // outside governance that leaves no durable record is
                                // worse than the crash this branch replaced: the crash
                                // was at least visible.
                                audit_dropped_notification(&request, &config, &state).await;
                            } else {
                                forward_notification(&request, &mut downstream_writer).await;
                            }
                            continue;
                        }

                        match request.method.as_str() {
                            "tools/call" => {
                                let response = handle_tool_call(&request, &config, &state, &mut downstream_writer, &mut downstream_reader).await;
                                let out = match serde_json::to_string(&response) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        tracing::error!(error = %e, "Failed to serialize MCP response");
                                        continue;
                                    }
                                };
                                let _ = stdout.write_all(out.as_bytes()).await;
                                let _ = stdout.write_all(b"\n").await;
                                let _ = stdout.flush().await;
                            }
                            _ => {
                                // Pass-through: forward to downstream and relay response
                                let response = forward_and_relay(&request, &mut downstream_writer, &mut downstream_reader).await;
                                let out = match serde_json::to_string(&response) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        tracing::error!(error = %e, "Failed to serialize MCP response");
                                        continue;
                                    }
                                };
                                let _ = stdout.write_all(out.as_bytes()).await;
                                let _ = stdout.write_all(b"\n").await;
                                let _ = stdout.flush().await;
                            }
                        }
                    }
                    Ok(None) => {
                        tracing::info!("Client stdin closed, shutting down proxy");
                        break;
                    }
                    Ok(Some(_)) => continue, // empty line
                    Err(e) => {
                        tracing::error!(error = %e, "Error reading from client stdin");
                        break;
                    }
                }
            }
        }
    }

    // Cleanup
    let _ = downstream.kill().await;
    Ok(())
}

fn spawn_downstream(config: &McpProxyConfig) -> Result<Child, SentinelError> {
    let mut cmd = Command::new(&config.downstream_command);
    cmd.args(&config.downstream_args)
        .envs(&config.downstream_env)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit());

    cmd.spawn().map_err(|e| {
        SentinelError::Proxy(format!(
            "Failed to spawn downstream MCP server '{}': {e}",
            config.downstream_command
        ))
    })
}

async fn handle_tool_call(
    request: &JsonRpcRequest,
    config: &McpProxyConfig,
    state: &Arc<AppState>,
    downstream_writer: &mut tokio::process::ChildStdin,
    downstream_reader: &mut CappedLines<BufReader<tokio::process::ChildStdout>>,
) -> JsonRpcResponse {
    // Parse tool call params
    let tool_call: McpToolCallParams = match serde_json::from_value(request.params.clone()) {
        Ok(tc) => tc,
        Err(e) => {
            return JsonRpcResponse::error(
                request.id.clone(),
                -32602,
                format!("Invalid tools/call params: {e}"),
            );
        }
    };

    tracing::info!(
        tool = %tool_call.name,
        agent_id = %config.agent_id,
        "Intercepting MCP tool call"
    );

    // Run governance pipeline
    let intercept = intercept_tool_call(state, &config.agent_id, &tool_call).await;

    match intercept {
        InterceptResult::Allow => {
            // 1.5 cost-control (deterministic response cache): serve a prior
            // result for an identical, safe, read-only call instead of paying
            // for it again. Governance has already allowed this call above.
            #[cfg(feature = "cost-control")]
            {
                use crate::modules::cost::cache;
                let action_type = infer_action_type(&tool_call.name);
                let tainted =
                    !crate::modules::taint::taint_tracker::get_session_taint(&config.agent_id)
                        .is_empty();
                if cache::is_cacheable(action_type) && !tainted {
                    let args = serde_json::to_value(&tool_call.arguments).unwrap_or_default();
                    let key = cache::CacheKey {
                        agent_id: config.agent_id.clone(),
                        tool_name: tool_call.name.clone(),
                        args_hash: cache::args_hash(&args),
                    };
                    if let Some(hit) = cache::get(&key) {
                        tracing::info!(tool = %tool_call.name, "cache HIT, serving cached result without forwarding downstream");
                        return JsonRpcResponse::success(request.id.clone(), hit.result_json);
                    }
                    let resp =
                        forward_and_relay(request, downstream_writer, downstream_reader).await;
                    if let Some(result) = resp.result.clone() {
                        let cost = cache::estimate_cost_micros(&result);
                        cache::put(key, result, cost);
                    }
                    return resp;
                }
            }
            tracing::info!(tool = %tool_call.name, "ALLOW, forwarding to downstream");
            // Forward original request to downstream
            forward_and_relay(request, downstream_writer, downstream_reader).await
        }
        InterceptResult::Review {
            review_id,
            risk_score,
        } => {
            tracing::warn!(
                tool = %tool_call.name,
                review_id = %review_id,
                risk_score = risk_score,
                "REVIEW, tool call held for human review"
            );
            JsonRpcResponse::error_with_data(
                request.id.clone(),
                -32001,
                format!(
                    "Tool '{}' requires human review (risk score: {})",
                    tool_call.name, risk_score
                ),
                serde_json::json!({
                    "governance": "review",
                    "reviewId": review_id,
                    "riskScore": risk_score,
                    "tool": tool_call.name,
                }),
            )
        }
        InterceptResult::Block {
            reasons,
            risk_score,
        } => {
            tracing::warn!(
                tool = %tool_call.name,
                risk_score = risk_score,
                reasons = ?reasons,
                "BLOCK, tool call denied by governance"
            );
            JsonRpcResponse::error_with_data(
                request.id.clone(),
                -32000,
                format!(
                    "Tool '{}' blocked by IAGA Sentinel governance (risk score: {})",
                    tool_call.name, risk_score
                ),
                serde_json::json!({
                    "governance": "block",
                    "riskScore": risk_score,
                    "reasons": reasons,
                    "tool": tool_call.name,
                }),
            )
        }
    }
}

/// Relay a JSON-RPC notification downstream without waiting for a reply.
///
/// Notifications carry no `id` and are never answered (JSON-RPC 2.0 §4.1), so
/// there is nothing to read back and nothing to return to the client.
async fn forward_notification(
    request: &JsonRpcRequest,
    downstream_writer: &mut tokio::process::ChildStdin,
) {
    let line = match serde_json::to_string(request) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize MCP notification");
            return;
        }
    };
    if let Err(e) = downstream_writer.write_all(line.as_bytes()).await {
        tracing::error!(error = %e, "Failed to write notification to downstream");
        return;
    }
    if let Err(e) = downstream_writer.write_all(b"\n").await {
        tracing::error!(error = %e, "Failed to write notification to downstream");
        return;
    }
    let _ = downstream_writer.flush().await;
}

async fn forward_and_relay(
    request: &JsonRpcRequest,
    downstream_writer: &mut tokio::process::ChildStdin,
    downstream_reader: &mut CappedLines<BufReader<tokio::process::ChildStdout>>,
) -> JsonRpcResponse {
    // Send to downstream
    let line = match serde_json::to_string(request) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize MCP request");
            return JsonRpcResponse::error(
                request.id.clone(),
                -32603,
                format!("Failed to serialize request: {e}"),
            );
        }
    };
    if let Err(e) = downstream_writer.write_all(line.as_bytes()).await {
        return JsonRpcResponse::error(
            request.id.clone(),
            -32603,
            format!("Failed to write to downstream: {e}"),
        );
    }
    if let Err(e) = downstream_writer.write_all(b"\n").await {
        return JsonRpcResponse::error(
            request.id.clone(),
            -32603,
            format!("Failed to write to downstream: {e}"),
        );
    }
    let _ = downstream_writer.flush().await;

    // Read response from downstream
    match downstream_reader.next_line().await {
        Ok(Some(resp_line)) => match serde_json::from_str::<JsonRpcResponse>(&resp_line) {
            Ok(resp) => resp,
            Err(e) => JsonRpcResponse::error(
                request.id.clone(),
                -32603,
                format!("Invalid JSON-RPC from downstream: {e}"),
            ),
        },
        Ok(None) => JsonRpcResponse::error(
            request.id.clone(),
            -32603,
            "Downstream server closed connection".to_string(),
        ),
        Err(e) => JsonRpcResponse::error(
            request.id.clone(),
            -32603,
            format!("Error reading from downstream: {e}"),
        ),
    }
}
