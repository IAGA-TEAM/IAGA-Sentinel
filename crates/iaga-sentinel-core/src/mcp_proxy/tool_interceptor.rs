use std::collections::HashMap;
use std::sync::Arc;

use crate::core::types::*;
use crate::events::bus::SentinelEvent;
use crate::pipeline::execute_pipeline::execute_pipeline;
use crate::server::app_state::AppState;

use super::protocol::McpToolCallParams;

/// Result of governance check on an MCP tool call.
pub enum InterceptResult {
    /// Tool call is allowed, forward to downstream server.
    Allow,
    /// Tool call needs human review, return pending status.
    Review { review_id: String, risk_score: u32 },
    /// Tool call is blocked, return error to client.
    Block {
        reasons: Vec<String>,
        risk_score: u32,
    },
}

/// Intercept an MCP tools/call request through the governance pipeline.
///
/// `session_id` is the run identity minted once per process by its caller
/// (`run_mcp_proxy` or `run_doctor`).
pub async fn intercept_tool_call(
    state: &Arc<AppState>,
    agent_id: &str,
    session_id: &str,
    tool_call: &McpToolCallParams,
) -> InterceptResult {
    // Map MCP tool call → InspectRequest
    let action_type = infer_action_type(&tool_call.name);
    let payload: HashMap<String, serde_json::Value> = tool_call
        .arguments
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let request = InspectRequest {
        agent_id: agent_id.to_string(),
        tenant_id: None,
        workspace_id: None,
        framework: "mcp".to_string(),
        protocol: Some(ProtocolKind::Mcp),
        action: ActionDetail {
            action_type,
            tool_name: tool_call.name.clone(),
            payload,
        },
        requested_secrets: None,
        // This same key scopes the receipt chain, session DAG, taint and spend
        // state. Proxy and doctor each keep one agent id for the process life.
        metadata: Some(HashMap::from([(
            "sessionId".to_string(),
            serde_json::Value::String(session_id.to_string()),
        )])),
        usage: None,
    };

    match execute_pipeline(&request, state).await {
        Ok(result) => {
            // Emit event
            state
                .event_bus
                .publish(SentinelEvent::from_governance_result(&result));

            match result.decision {
                GovernanceDecision::Allow => InterceptResult::Allow,
                GovernanceDecision::Review => InterceptResult::Review {
                    review_id: result.review_request_id.unwrap_or_default(),
                    risk_score: result.risk.score,
                },
                GovernanceDecision::Block => InterceptResult::Block {
                    reasons: result.risk.reasons,
                    risk_score: result.risk.score,
                },
            }
        }
        Err(e) => {
            tracing::error!(error = %e, tool = %tool_call.name, "Pipeline error during MCP intercept");
            // Fail-closed: block on pipeline error
            InterceptResult::Block {
                reasons: vec![format!("governance pipeline error: {e}")],
                risk_score: 100,
            }
        }
    }
}

/// Infer ActionType from tool name heuristic.
pub(crate) fn infer_action_type(tool_name: &str) -> ActionType {
    let lower = tool_name.to_lowercase();
    if lower.contains("read")
        || lower.contains("get")
        || lower.contains("list")
        || lower.contains("search")
    {
        ActionType::FileRead
    } else if lower.contains("write")
        || lower.contains("create")
        || lower.contains("update")
        || lower.contains("edit")
    {
        ActionType::FileWrite
    } else if lower.contains("exec")
        || lower.contains("run")
        || lower.contains("shell")
        || lower.contains("bash")
        || lower.contains("command")
    {
        ActionType::Shell
    } else if lower.contains("http")
        || lower.contains("fetch")
        || lower.contains("request")
        || lower.contains("curl")
    {
        ActionType::Http
    } else if lower.contains("query")
        || lower.contains("sql")
        || lower.contains("db")
        || lower.contains("database")
    {
        ActionType::DbQuery
    } else if lower.contains("email") || lower.contains("mail") || lower.contains("send") {
        ActionType::Email
    } else {
        ActionType::Custom
    }
}
