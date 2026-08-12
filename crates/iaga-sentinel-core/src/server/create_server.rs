use axum::{
    extract::{Path, Request, State},
    http::{HeaderValue, StatusCode},
    middleware as axum_middleware,
    response::{Html, IntoResponse, Json, Response},
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Instant;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::auth::api_keys::generate_api_key;
use crate::auth::middleware::auth_middleware;
use crate::auth::middleware::is_open_mode_enabled;
use crate::auth::middleware::RequireAdmin;
use crate::core::errors::SentinelError;
use crate::core::types::*;
use crate::dashboard::index_html::render_dashboard_html;
use crate::events::bus::SentinelEvent;
use crate::events::sse::sse_handler;
use crate::events::webhooks::WebhookConfig;
use crate::modules::injection_firewall::prompt_firewall;
use crate::modules::nhi::crypto_identity;
use crate::modules::policy::formal_verify;
use crate::modules::risk::adaptive_scorer;
use crate::modules::sandbox::sandbox_executor;
use crate::modules::session_graph::session_dag;
use crate::modules::telemetry::otel_emitter;
use crate::modules::threat_intel::feed::ThreatIndicator;
use crate::pipeline::execute_pipeline::{execute_pipeline, get_sensitive_patterns, scan_response};
use crate::server::app_state::AppState;
use crate::storage::traits::KeyScope;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    ok: bool,
    service: String,
    mode: String,
    version: String,
    auth_required: bool,
    open_mode: bool,
    api_keys_configured: bool,
}

#[derive(Deserialize)]
struct ReviewBody {
    status: ReviewAction,
}

#[derive(Deserialize)]
struct CreateApiKeyBody {
    label: String,
    /// 1.5.2 optional key scope: "admin" (default, full access) or "agent"
    /// (governance surface only).
    #[serde(default)]
    scope: Option<String>,
}

#[derive(Serialize)]
struct ApiKeyCreated {
    id: String,
    key: String,
    label: String,
    scope: String,
}

#[derive(Deserialize)]
struct CreateWebhookBody {
    url: String,
    secret: String,
    #[serde(default)]
    event_filter: Vec<String>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    // Public routes (no auth)
    let public = Router::new()
        .route("/", get(dashboard_handler))
        .route("/health", get(health_handler))
        .route("/dashboard/context", get(health_handler));

    // Protected routes (auth middleware)
    let protected = Router::new()
        // Core pipeline
        .route("/v1/inspect", post(inspect_handler))
        // Audit
        .route("/v1/audit", get(audit_handler))
        // Audit export & stats
        .route("/v1/audit/export", get(audit_export_handler))
        .route("/v1/audit/stats", get(audit_stats_handler))
        // Analytics
        .route("/v1/analytics/agents", get(analytics_agents_handler))
        .route(
            "/v1/analytics/agents/{agent_id}",
            get(analytics_agent_handler),
        )
        // Reviews
        .route("/v1/reviews", get(reviews_handler))
        .route("/v1/reviews/{id}", post(review_action_handler))
        // Profiles CRUD
        .route("/v1/profiles", get(list_profiles_handler))
        .route("/v1/profiles", post(upsert_profile_handler))
        .route("/v1/profiles/{agent_id}", get(get_profile_handler))
        .route("/v1/profiles/{agent_id}", put(upsert_profile_handler))
        .route("/v1/profiles/{agent_id}", delete(delete_profile_handler))
        // Workspaces CRUD
        .route("/v1/workspaces", get(list_workspaces_handler))
        .route("/v1/workspaces", post(upsert_workspace_handler))
        .route("/v1/workspaces/{workspace_id}", get(get_workspace_handler))
        .route(
            "/v1/workspaces/{workspace_id}",
            put(upsert_workspace_handler),
        )
        .route(
            "/v1/workspaces/{workspace_id}",
            delete(delete_workspace_handler),
        )
        // API Keys
        .route("/v1/auth/keys", get(list_api_keys_handler))
        .route("/v1/auth/keys", post(create_api_key_handler))
        .route("/v1/auth/keys/{id}", delete(delete_api_key_handler))
        // Webhooks
        .route("/v1/webhooks", get(list_webhooks_handler))
        .route("/v1/webhooks", post(create_webhook_handler))
        .route("/v1/webhooks/{id}", delete(delete_webhook_handler))
        // Webhook Dead Letter Queue
        .route("/v1/webhooks/dlq", get(list_dlq_handler))
        .route("/v1/webhooks/dlq/{id}/retry", post(retry_dlq_handler))
        .route("/v1/webhooks/dlq/{id}", delete(delete_dlq_handler))
        // SSE event stream
        .route("/v1/events/stream", get(sse_handler))
        // ── 8-Layer Security Stack ──
        // L1: Session Graph
        .route("/v1/sessions", get(list_sessions_handler))
        .route("/v1/sessions/{id}/metrics", get(session_metrics_handler))
        // L2: Taint (inline in pipeline, no separate endpoint needed)
        // L3: NHI Identity
        .route("/v1/nhi/identities", get(list_identities_handler))
        .route("/v1/nhi/identities", post(register_identity_handler))
        .route("/v1/nhi/attest", post(attest_handler))
        .route("/v1/nhi/challenge", post(create_challenge_handler))
        .route("/v1/nhi/verify", post(verify_attestation_handler))
        .route("/v1/nhi/tokens", post(issue_token_handler))
        // L4: Risk Scoring
        .route("/v1/risk/weights", get(risk_weights_handler))
        .route("/v1/risk/weights/reset", post(risk_weights_reset_handler))
        .route("/v1/risk/feedback", post(risk_feedback_handler))
        // L5: Sandbox
        .route("/v1/sandbox/pending", get(sandbox_pending_handler))
        .route("/v1/sandbox/{id}/approve", post(sandbox_approve_handler))
        .route("/v1/sandbox/{id}/reject", post(sandbox_reject_handler))
        // L6: Policy Verification
        .route(
            "/v1/policy/verify/{workspace_id}",
            get(verify_policy_handler),
        )
        // Response scanning
        .route("/v1/response/scan", post(response_scan_handler))
        .route("/v1/response/patterns", get(response_patterns_handler))
        // L7: Injection Firewall
        .route("/v1/firewall/scan", post(firewall_scan_handler))
        .route("/v1/firewall/stats", get(firewall_stats_handler))
        // L8: Telemetry
        .route("/v1/telemetry/spans", get(telemetry_spans_handler))
        .route("/v1/telemetry/metrics", get(telemetry_metrics_handler))
        .route("/v1/telemetry/export", get(telemetry_export_handler))
        // Behavioral Fingerprinting
        .route("/v1/fingerprint", get(list_fingerprints_handler))
        .route("/v1/fingerprint/{agent_id}", get(get_fingerprint_handler))
        // Rate Limiting
        .route(
            "/v1/rate-limit/status/{agent_id}",
            get(rate_limit_status_handler),
        )
        .route("/v1/rate-limit/config", get(get_rate_limit_config_handler))
        .route(
            "/v1/rate-limit/config",
            post(update_rate_limit_config_handler),
        )
        // Threat Intelligence Feed
        .route(
            "/v1/threat-intel/indicators",
            get(list_threat_indicators_handler),
        )
        .route(
            "/v1/threat-intel/indicators",
            post(add_threat_indicator_handler),
        )
        .route(
            "/v1/threat-intel/indicators/{id}",
            delete(delete_threat_indicator_handler),
        )
        .route("/v1/threat-intel/stats", get(threat_intel_stats_handler))
        .route("/v1/threat-intel/check", post(threat_intel_check_handler))
        // v0.4.0: Policy Templates & Rules Engine
        .route("/v1/templates", get(list_templates_handler))
        .route("/v1/templates/{template_id}", get(get_template_handler))
        .route(
            "/v1/workspaces/{workspace_id}/rules",
            get(list_workspace_rules_handler),
        )
        .route(
            "/v1/workspaces/{workspace_id}/rules",
            post(add_workspace_rule_handler),
        )
        // v0.4.0: WASM Plugins
        .route("/v1/plugins", get(list_plugins_handler))
        .route("/v1/plugins/reload", post(reload_plugins_handler))
        // ── 1.0 Pillar surfaces ──
        // M2, Signed receipts read API
        .route("/v1/receipts", get(receipts_list_handler))
        .route("/v1/receipts/{run_id}", get(receipts_run_handler))
        // 1.5 cost-control: spend observability (always mounted; handlers report
        // `enabled: false` when the cost-control feature is compiled out).
        .route("/v1/cost/summary", get(cost_summary_handler))
        .route("/v1/cost/by-agent", get(cost_by_agent_handler))
        .route("/v1/cost/by-model", get(cost_by_model_handler))
        .route("/v1/cost/by-tool", get(cost_by_tool_handler))
        .route("/v1/cost/over-time", get(cost_over_time_handler))
        .route("/v1/cost/budget", get(cost_budget_handler))
        .route("/v1/cost/pricing", get(cost_pricing_handler))
        // M3 / M6, Dictum live overlay status
        .route("/v1/policy/overlay", get(policy_overlay_handler))
        // M3.5, Reasoning plane status
        .route("/v1/reasoning/status", get(reasoning_status_handler))
        // M4, Enforcement kernel status
        .route("/v1/kernel/status", get(kernel_status_handler))
        // Demo
        .route("/v1/demo/scenarios", get(demo_scenarios_handler))
        .route("/v1/demo/run-adapter", post(run_adapter_handler))
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    public
        .merge(protected)
        .layer(axum_middleware::from_fn(request_logging_middleware))
        .layer({
            use axum::http::{header, HeaderValue, Method};
            use tower_http::cors::AllowOrigin;

            // `IAGA_SENTINEL_CORS_ORIGINS` (comma-separated) restricts CORS to
            // an explicit allowlist; unset keeps the permissive `Any` of
            // releases before 1.5.2.
            let allow_origin: AllowOrigin =
                match &state.env.cors_origins {
                    Some(origins) => AllowOrigin::list(origins.iter().filter_map(|o| {
                        match o.parse::<HeaderValue>() {
                            Ok(v) => Some(v),
                            Err(_) => {
                                tracing::warn!(origin = %o, "ignoring unparseable CORS origin");
                                None
                            }
                        }
                    })),
                    None => AllowOrigin::any(),
                };

            CorsLayer::new()
                .allow_origin(allow_origin)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        })
        .with_state(state)
}

async fn request_logging_middleware(request: Request, next: axum::middleware::Next) -> Response {
    const REQUEST_ID_HEADER: &str = "x-request-id";

    let mut request = request;
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string())
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    if let Ok(header) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert(REQUEST_ID_HEADER, header);
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let started_at = Instant::now();

    let mut response = next.run(request).await;
    let status = response.status();
    let elapsed_ms = started_at.elapsed().as_millis() as u64;

    if let Ok(header) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, header);
    }

    if status.is_server_error() {
        tracing::error!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            elapsed_ms,
            "http request completed"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            elapsed_ms,
            "http request completed"
        );
    } else {
        tracing::info!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            elapsed_ms,
            "http request completed"
        );
    }

    response
}

// ── Dashboard ──

async fn dashboard_handler() -> Html<String> {
    Html(render_dashboard_html())
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let api_keys_configured = state
        .api_key_store
        .list_keys()
        .await
        .map(|keys| !keys.is_empty())
        .unwrap_or(false);
    let open_mode = is_open_mode_enabled();

    Json(HealthResponse {
        ok: true,
        service: "iaga-sentinel".into(),
        mode: state.env.default_mode.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        auth_required: api_keys_configured || !open_mode,
        open_mode,
        api_keys_configured,
    })
}

// ── Core Pipeline ──

async fn inspect_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<InspectRequest>,
) -> Result<impl IntoResponse, SentinelError> {
    let result = execute_pipeline(&payload, &state).await?;

    tracing::info!(
        trace_id = %result.trace_id,
        agent_id = %payload.agent_id,
        tool_name = %payload.action.tool_name,
        decision = ?result.decision,
        "governed agent action"
    );

    // Emit event to bus (SSE + webhooks)
    state
        .event_bus
        .publish(SentinelEvent::from_governance_result(&result));

    Ok(Json(result))
}

// ── Audit ──

async fn audit_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<StoredAuditEvent>>, SentinelError> {
    let events = state.audit_store.list(100).await?;
    Ok(Json(events))
}

// ── Audit Export & Stats ──

#[derive(Deserialize)]
struct AuditExportQuery {
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    from_date: Option<String>,
    #[serde(default)]
    to_date: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

async fn audit_export_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<AuditExportQuery>,
) -> Result<impl IntoResponse, SentinelError> {
    let filter = AuditExportFilter {
        tenant_id: query.tenant_id,
        agent_id: query.agent_id,
        decision: query.decision,
        from_date: query.from_date,
        to_date: query.to_date,
        limit: query.limit,
    };

    let events = state.audit_store.list_filtered(&filter).await?;

    match query.format.as_deref() {
        Some("csv") => {
            let mut csv = String::from("event_id,agent_id,framework,action_type,tool_name,decision,risk_score,review_status,timestamp\n");
            for e in &events {
                let at = serde_json::to_value(e.action_type)
                    .unwrap_or_default()
                    .as_str()
                    .unwrap_or("custom")
                    .to_string();
                let dec = serde_json::to_value(e.decision)
                    .unwrap_or_default()
                    .as_str()
                    .unwrap_or("allow")
                    .to_string();
                let rs = serde_json::to_value(e.review_status)
                    .unwrap_or_default()
                    .as_str()
                    .unwrap_or("not_required")
                    .to_string();
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    e.event_id,
                    e.agent_id,
                    e.framework,
                    at,
                    e.tool_name,
                    dec,
                    e.risk_score,
                    rs,
                    e.timestamp
                ));
            }
            Ok(([(axum::http::header::CONTENT_TYPE, "text/csv")], csv).into_response())
        }
        _ => Ok(Json(events).into_response()),
    }
}

async fn audit_stats_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<AuditStats>, SentinelError> {
    let stats = state.audit_store.stats().await?;
    Ok(Json(stats))
}

// ── Analytics ──

async fn analytics_agents_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AgentAnalytics>>, SentinelError> {
    let analytics = state.audit_store.agent_analytics(None).await?;
    Ok(Json(analytics))
}

async fn analytics_agent_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<AgentAnalytics>>, SentinelError> {
    let analytics = state.audit_store.agent_analytics(Some(&agent_id)).await?;
    Ok(Json(analytics))
}

// ── Reviews ──

async fn reviews_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ReviewRequest>>, SentinelError> {
    let reviews = state.review_store.list().await?;
    Ok(Json(reviews))
}

async fn review_action_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> Result<Json<ReviewRequest>, SentinelError> {
    let status_str = match body.status {
        ReviewAction::Approved => "approved",
        ReviewAction::Rejected => "rejected",
    };
    let updated = state.review_store.update_status(&id, status_str).await?;

    // Emit review resolved event
    state.event_bus.publish(SentinelEvent::ReviewResolved {
        review_id: id,
        status: status_str.to_string(),
    });

    Ok(Json(updated))
}

// ── Profiles CRUD ──

async fn list_profiles_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AgentProfile>>, SentinelError> {
    let profiles = state.policy_store.list_profiles().await?;
    Ok(Json(profiles))
}

async fn get_profile_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentProfile>, SentinelError> {
    let profile = state.policy_store.get_agent_profile(&agent_id).await?;
    Ok(Json(profile))
}

async fn upsert_profile_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Json(profile): Json<AgentProfile>,
) -> Result<impl IntoResponse, SentinelError> {
    state.policy_store.upsert_profile(&profile).await?;
    Ok((StatusCode::OK, Json(profile)))
}

async fn delete_profile_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Result<StatusCode, SentinelError> {
    state.policy_store.delete_profile(&agent_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Workspaces CRUD ──

async fn list_workspaces_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<WorkspacePolicy>>, SentinelError> {
    let workspaces = state.policy_store.list_workspaces().await?;
    Ok(Json(workspaces))
}

async fn get_workspace_handler(
    State(state): State<Arc<AppState>>,
    Path(workspace_id): Path<String>,
) -> Result<Json<WorkspacePolicy>, SentinelError> {
    let ws = state
        .policy_store
        .get_workspace_policy(&workspace_id)
        .await?;
    Ok(Json(ws))
}

async fn upsert_workspace_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Json(policy): Json<WorkspacePolicy>,
) -> Result<impl IntoResponse, SentinelError> {
    state.policy_store.upsert_workspace(&policy).await?;
    Ok((StatusCode::OK, Json(policy)))
}

async fn delete_workspace_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(workspace_id): Path<String>,
) -> Result<StatusCode, SentinelError> {
    state.policy_store.delete_workspace(&workspace_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── API Keys (admin scope required, 1.5.2) ──

async fn list_api_keys_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::storage::traits::ApiKeyRecord>>, SentinelError> {
    let keys = state.api_key_store.list_keys().await?;
    Ok(Json(keys))
}

async fn create_api_key_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateApiKeyBody>,
) -> Result<(StatusCode, Json<ApiKeyCreated>), SentinelError> {
    let scope = match body.scope.as_deref() {
        None | Some("admin") => KeyScope::Admin,
        Some("agent") => KeyScope::Agent,
        Some(other) => {
            return Err(SentinelError::InvalidRequest(format!(
                "invalid scope `{other}`: expected `admin` or `agent`"
            )))
        }
    };
    let (raw_key, key_hash) = generate_api_key();
    let key_id = uuid::Uuid::new_v4().to_string();
    state
        .api_key_store
        .store_key_scoped(&key_id, &key_hash, &body.label, &raw_key, scope)
        .await?;
    state.auth_cache.set_keys_exist(true);
    Ok((
        StatusCode::CREATED,
        Json(ApiKeyCreated {
            id: key_id,
            key: raw_key,
            label: body.label,
            scope: scope.as_str().to_string(),
        }),
    ))
}

async fn delete_api_key_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, SentinelError> {
    state.api_key_store.delete_key(&id).await?;
    // Deletion must take effect immediately, not after the cache TTL.
    state.auth_cache.invalidate_key_id(&id);
    Ok(StatusCode::NO_CONTENT)
}

// ── Demo ──

async fn demo_scenarios_handler() -> Json<Vec<DemoScenario>> {
    Json(crate::demo::scenarios::demo_scenarios())
}

async fn run_adapter_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DemoResult>>, SentinelError> {
    let scenarios = crate::demo::scenarios::demo_scenarios();
    let mut results = Vec::new();

    for scenario in &scenarios {
        let result = execute_pipeline(&scenario.request, &state).await?;
        tracing::info!(
            agent_id = %scenario.request.agent_id,
            tool_name = %scenario.request.action.tool_name,
            decision = ?result.decision,
            "adapter scenario governed"
        );
        results.push(DemoResult {
            step: scenario.step.clone(),
            title: scenario.title.clone(),
            decision: result.decision,
            risk: result.risk.score,
        });
    }

    Ok(Json(results))
}

// ── L1: Session Graph ──

async fn list_sessions_handler() -> Json<Vec<serde_json::Value>> {
    let sessions = session_dag::list_active_sessions();
    let json: Vec<serde_json::Value> = sessions
        .into_iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();
    Json(json)
}

async fn session_metrics_handler(Path(id): Path<String>) -> impl IntoResponse {
    match session_dag::get_session_metrics(&id) {
        Some(m) => (
            StatusCode::OK,
            Json(serde_json::to_value(m).unwrap_or_default()),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── L3: NHI Identity ──

async fn list_identities_handler() -> Json<Vec<serde_json::Value>> {
    let ids = crypto_identity::list_identities();
    let json: Vec<serde_json::Value> = ids
        .into_iter()
        .filter_map(|i| serde_json::to_value(i).ok())
        .collect();
    Json(json)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterIdentityBody {
    agent_id: String,
    workspace_id: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
}

async fn register_identity_handler(
    _admin: RequireAdmin,
    Json(body): Json<RegisterIdentityBody>,
) -> (StatusCode, Json<serde_json::Value>) {
    let identity = crypto_identity::register_identity(
        &body.agent_id,
        body.workspace_id.as_deref(),
        body.capabilities,
    );
    (
        StatusCode::CREATED,
        Json(serde_json::to_value(identity).unwrap_or_default()),
    )
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestBody {
    agent_id: String,
    challenge: String,
}

async fn attest_handler(Json(body): Json<AttestBody>) -> Json<serde_json::Value> {
    let result = crypto_identity::attest_agent(&body.agent_id, &body.challenge);
    Json(serde_json::to_value(result).unwrap_or_default())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateChallengeBody {
    agent_id: String,
}

async fn create_challenge_handler(Json(body): Json<CreateChallengeBody>) -> impl IntoResponse {
    match crypto_identity::create_challenge(&body.agent_id) {
        Some(challenge) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(challenge).unwrap_or_default()),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent not registered"})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyAttestBody {
    agent_id: String,
    challenge_id: String,
    signature: String,
}

async fn verify_attestation_handler(Json(body): Json<VerifyAttestBody>) -> Json<serde_json::Value> {
    let result =
        crypto_identity::verify_attestation(&body.agent_id, &body.challenge_id, &body.signature);
    Json(serde_json::to_value(result).unwrap_or_default())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueTokenBody {
    agent_id: String,
    capabilities: Vec<String>,
    #[serde(default = "default_ttl")]
    ttl_seconds: i64,
}

fn default_ttl() -> i64 {
    3600
}

async fn issue_token_handler(Json(body): Json<IssueTokenBody>) -> impl IntoResponse {
    match crypto_identity::issue_capability_token(
        &body.agent_id,
        body.capabilities,
        body.ttl_seconds,
    ) {
        Some(token) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(token).unwrap_or_default()),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent not registered"})),
        )
            .into_response(),
    }
}

// ── L4: Risk Scoring ──

async fn risk_weights_handler() -> Json<serde_json::Value> {
    let weights = adaptive_scorer::get_current_weights();
    Json(serde_json::to_value(weights).unwrap_or_default())
}

/// 1.5.2: drop feedback-learned adjustments and restore the default weights.
/// Weights are process-global across all agents, so resetting them is an
/// administrative action.
async fn risk_weights_reset_handler(_admin: RequireAdmin) -> Json<serde_json::Value> {
    adaptive_scorer::reset_weights();
    let weights = adaptive_scorer::get_current_weights();
    Json(serde_json::json!({
        "reset": true,
        "weights": serde_json::to_value(weights).unwrap_or_default()
    }))
}

#[derive(Deserialize)]
struct FeedbackBody {
    feedback: String,
}

async fn risk_feedback_handler(
    _admin: RequireAdmin,
    Json(body): Json<FeedbackBody>,
) -> Json<serde_json::Value> {
    adaptive_scorer::apply_feedback(&body.feedback);
    let weights = adaptive_scorer::get_current_weights();
    Json(serde_json::json!({
        "applied": body.feedback,
        "weights": serde_json::to_value(weights).unwrap_or_default()
    }))
}

// ── L5: Sandbox ──

async fn sandbox_pending_handler() -> Json<Vec<serde_json::Value>> {
    let pending = sandbox_executor::list_pending();
    let json: Vec<serde_json::Value> = pending
        .into_iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();
    Json(json)
}

/// Approving a sandboxed action releases work the pipeline held back for a
/// human, so it is an administrative decision - the same reasoning as
/// `risk_weights_reset_handler` and `reload_plugins_handler`. Without
/// `RequireAdmin` any agent-scoped key could approve the very action it was
/// stopped from taking.
async fn sandbox_approve_handler(
    _admin: RequireAdmin,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match sandbox_executor::approve_sandbox(&id) {
        Some(r) => (
            StatusCode::OK,
            Json(serde_json::to_value(r).unwrap_or_default()),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "sandbox not found"})),
        )
            .into_response(),
    }
}

async fn sandbox_reject_handler(_admin: RequireAdmin, Path(id): Path<String>) -> impl IntoResponse {
    match sandbox_executor::reject_sandbox(&id) {
        Some(r) => (
            StatusCode::OK,
            Json(serde_json::to_value(r).unwrap_or_default()),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "sandbox not found"})),
        )
            .into_response(),
    }
}

// ── L6: Policy Verification ──

async fn verify_policy_handler(
    State(state): State<Arc<AppState>>,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    let policy = state
        .policy_store
        .get_workspace_policy(&workspace_id)
        .await?;
    let result = formal_verify::verify_policy(&policy);
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
}

// ── L7: Injection Firewall ──

#[derive(Deserialize)]
struct FirewallScanBody {
    text: String,
}

async fn firewall_scan_handler(Json(body): Json<FirewallScanBody>) -> Json<serde_json::Value> {
    let result = prompt_firewall::scan_prompt(&body.text);
    Json(serde_json::to_value(result).unwrap_or_default())
}

async fn firewall_stats_handler() -> Json<serde_json::Value> {
    let stats = prompt_firewall::get_firewall_stats();
    Json(serde_json::to_value(stats).unwrap_or_default())
}

// ── L8: Telemetry ──

async fn telemetry_spans_handler() -> Json<Vec<serde_json::Value>> {
    let spans = otel_emitter::get_recent_spans(100);
    let json: Vec<serde_json::Value> = spans
        .into_iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();
    Json(json)
}

async fn telemetry_metrics_handler() -> Json<Vec<serde_json::Value>> {
    let metrics = otel_emitter::get_recent_metrics(100);
    let json: Vec<serde_json::Value> = metrics
        .into_iter()
        .filter_map(|m| serde_json::to_value(m).ok())
        .collect();
    Json(json)
}

async fn telemetry_export_handler() -> Json<Vec<serde_json::Value>> {
    let records = otel_emitter::export_otlp_json(200);
    let json: Vec<serde_json::Value> = records
        .into_iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();
    Json(json)
}

// ── Response Scanning ──

async fn response_scan_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ResponseScanRequest>,
) -> Result<Json<ResponseScanResult>, SentinelError> {
    let result = scan_response(&payload);

    tracing::info!(
        request_id = %payload.request_id,
        agent_id = %payload.agent_id,
        tool_name = %payload.tool_name,
        decision = ?result.decision,
        risk_score = result.risk_score,
        "scanned tool response"
    );

    // A response-side Block is a terminal governance decision, so it must land
    // in the audit log and a signed receipt for EU AI Act Art.12 evidence (#15).
    // No workspace policy is resolved on this path, so bind no policy/threat
    // hash; this is purely additive and leaves existing receipts byte-identical.
    if result.decision == ResponseDecision::Block {
        let payload_str = serde_json::to_string(&payload.response_payload).unwrap_or_default();
        let stored = StoredAuditEvent {
            event_id: Uuid::new_v4().to_string(),
            agent_id: payload.agent_id.clone(),
            tenant_id: None,
            framework: "response-scan".to_string(),
            action_type: ActionType::Custom,
            tool_name: payload.tool_name.clone(),
            input_sha256: hex::encode(Sha256::digest(payload_str.as_bytes())),
            decision: GovernanceDecision::Block,
            timestamp: chrono::Utc::now().to_rfc3339(),
            reasons: result.findings.clone(),
            review_status: ReviewStatus::NotRequired,
            risk_score: result.risk_score,
            usage: None,
            session_id: payload
                .metadata
                .as_ref()
                .and_then(|m| m.get("sessionId"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string()),
        };
        if let Err(e) = state.audit_store.append(&stored).await {
            tracing::error!(event_id = %stored.event_id, error = %e, "failed to persist response-block audit event");
        }
        if let Some(rl) = state.receipts.as_ref() {
            rl.record(
                &stored,
                None,
                None,
                crate::pipeline::receipts::ReceiptContext {
                    policy_hash: None,
                    threat_feed_hash: None,
                    dictum_trace: None,
                },
            )
            .await?;
        }
    }

    Ok(Json(result))
}

async fn response_patterns_handler() -> Json<Vec<SensitivePattern>> {
    Json(get_sensitive_patterns())
}

// ── Behavioral Fingerprinting ──

async fn get_fingerprint_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> impl IntoResponse {
    match state.behavioral_engine.get_fingerprint(&agent_id) {
        Some(fp) => (
            StatusCode::OK,
            Json(serde_json::to_value(fp).unwrap_or_default()),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent fingerprint not found"})),
        )
            .into_response(),
    }
}

async fn list_fingerprints_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<serde_json::Value>> {
    let fingerprints = state.behavioral_engine.list_fingerprints();
    let json: Vec<serde_json::Value> = fingerprints
        .into_iter()
        .filter_map(|fp| serde_json::to_value(fp).ok())
        .collect();
    Json(json)
}

// ── Rate Limiting ──

async fn rate_limit_status_handler(
    State(state): State<Arc<AppState>>,
    Path(agent_id): Path<String>,
) -> Json<serde_json::Value> {
    let status = state.rate_limiter.status(&agent_id).await;
    Json(serde_json::to_value(status).unwrap_or_default())
}

async fn get_rate_limit_config_handler(
    State(state): State<Arc<AppState>>,
) -> Json<RateLimitConfig> {
    let config = state.rate_limiter.get_config().await;
    Json(config)
}

async fn update_rate_limit_config_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Json(new_config): Json<RateLimitConfig>,
) -> Json<RateLimitConfig> {
    state.rate_limiter.update_config(new_config.clone()).await;
    Json(new_config)
}

// ── Threat Intelligence Feed ──

async fn list_threat_indicators_handler(
    State(state): State<Arc<AppState>>,
) -> Json<Vec<ThreatIndicator>> {
    Json(state.threat_feed.list_indicators())
}

async fn add_threat_indicator_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Json(indicator): Json<ThreatIndicator>,
) -> (StatusCode, Json<ThreatIndicator>) {
    state.threat_feed.add_indicator(indicator.clone());
    (StatusCode::CREATED, Json(indicator))
}

async fn delete_threat_indicator_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.threat_feed.remove_indicator(&id) {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "indicator not found"})),
        )
            .into_response()
    }
}

async fn threat_intel_stats_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let stats = state.threat_feed.get_stats();
    Json(serde_json::to_value(stats).unwrap_or_default())
}

#[derive(Deserialize)]
struct ThreatCheckBody {
    content: String,
}

async fn threat_intel_check_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ThreatCheckBody>,
) -> Json<serde_json::Value> {
    let matches = state.threat_feed.check_threats(&body.content);
    Json(serde_json::json!({
        "matches": matches,
        "matched": !matches.is_empty(),
        "count": matches.len()
    }))
}

// ── Webhooks ──

async fn list_webhooks_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<WebhookConfig>>, SentinelError> {
    let hooks = state.webhook_manager.list().await;
    Ok(Json(hooks))
}

async fn create_webhook_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateWebhookBody>,
) -> Result<(StatusCode, Json<WebhookConfig>), SentinelError> {
    let hook = state
        .webhook_manager
        .register(body.url, body.secret, body.event_filter)
        .await;
    Ok((StatusCode::CREATED, Json(hook)))
}

async fn delete_webhook_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, SentinelError> {
    state.webhook_manager.unregister(&id).await?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Webhook DLQ ──

async fn list_dlq_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Json<Vec<crate::events::webhooks::DeadLetterEntry>> {
    let entries = state.webhook_manager.dlq().list().await;
    Json(entries)
}

async fn retry_dlq_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<StatusCode, SentinelError> {
    state.webhook_manager.retry_dlq_entry(&id).await?;
    Ok(StatusCode::OK)
}

async fn delete_dlq_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if state.webhook_manager.dlq().remove(&id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "DLQ entry not found"})),
        )
            .into_response()
    }
}

// ── v0.4.0: Policy Templates ──

async fn list_plugins_handler(
    State(state): State<Arc<AppState>>,
) -> Json<crate::plugins::PluginRegistrySnapshot> {
    Json(state.plugin_registry.snapshot())
}

async fn reload_plugins_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Json<crate::plugins::PluginRegistrySnapshot> {
    Json(state.plugin_registry.reload())
}

async fn list_templates_handler() -> Json<serde_json::Value> {
    use crate::modules::policy::templates::builtin_templates;
    let templates: Vec<_> = builtin_templates()
        .iter()
        .map(|t| {
            serde_json::json!({
                "templateId": t.template_id,
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "builtin": t.builtin,
                "rulesCount": t.rules.len(),
                "toolsCount": t.workspace.tools.len(),
            })
        })
        .collect();
    Json(serde_json::json!({ "templates": templates, "count": templates.len() }))
}

async fn get_template_handler(
    Path(template_id): Path<String>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    use crate::modules::policy::templates::get_builtin_template;
    match get_builtin_template(&template_id) {
        Some(tpl) => Ok(Json(serde_json::json!({
            "templateId": tpl.template_id,
            "name": tpl.name,
            "description": tpl.description,
            "category": tpl.category,
            "builtin": tpl.builtin,
            "workspace": tpl.workspace,
            "rules": tpl.rules,
        }))),
        None => Err(SentinelError::InvalidRequest(format!(
            "template '{template_id}' not found"
        ))),
    }
}

// ── v0.4.0: Policy Rules per Workspace ──

async fn list_workspace_rules_handler(
    State(state): State<Arc<AppState>>,
    Path(workspace_id): Path<String>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    state
        .policy_store
        .get_workspace_policy(&workspace_id)
        .await?;
    let rules = state
        .policy_store
        .list_workspace_rules(&workspace_id)
        .await?;
    Ok(Json(
        serde_json::json!({ "rules": rules, "count": rules.len() }),
    ))
}

async fn add_workspace_rule_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(workspace_id): Path<String>,
    Json(rule): Json<crate::modules::policy::rules_engine::PolicyRule>,
) -> Result<(StatusCode, Json<serde_json::Value>), SentinelError> {
    if rule.id.trim().is_empty() {
        return Err(SentinelError::InvalidRequest(
            "workspace rule id must not be empty".into(),
        ));
    }
    if rule.name.trim().is_empty() {
        return Err(SentinelError::InvalidRequest(
            "workspace rule name must not be empty".into(),
        ));
    }

    state
        .policy_store
        .get_workspace_policy(&workspace_id)
        .await?;
    state
        .policy_store
        .upsert_workspace_rule(&workspace_id, &rule)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "persisted",
            "rule": {
                "id": rule.id,
                "name": rule.name,
                "priority": rule.priority,
                "decision": rule.decision,
                "enabled": rule.enabled,
            }
        })),
    ))
}

// ── 1.0 Pillar surfaces ──

/// M2, list signed receipt runs. Returns `{ signerKeyId, policyHash,
/// runs: [...] }`. Empty runs array when receipts feature is disabled
/// or no runs have been recorded yet.
#[derive(Deserialize)]
struct ReceiptsQuery {
    #[serde(default = "default_receipts_limit")]
    limit: u32,
}
fn default_receipts_limit() -> u32 {
    50
}

async fn receipts_list_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<ReceiptsQuery>,
) -> Json<serde_json::Value> {
    let runs = match state.receipts.as_ref() {
        Some(rl) => rl.list_runs_json(q.limit).await,
        None => serde_json::Value::Array(Vec::new()),
    };
    let signer = state
        .receipts
        .as_ref()
        .and_then(|rl| rl.signer_key_id())
        .unwrap_or_else(|| "(receipts disabled)".to_string());
    let policy_hash = state
        .receipts
        .as_ref()
        .and_then(|rl| rl.policy_hash())
        .unwrap_or_else(|| "(receipts disabled)".to_string());
    Json(serde_json::json!({
        "enabled": state.receipts.is_some(),
        "signerKeyId": signer,
        "policyHash": policy_hash,
        "runs": runs,
    }))
}

async fn receipts_run_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(run_id): Path<String>,
) -> Json<serde_json::Value> {
    match state.receipts.as_ref() {
        Some(rl) => Json(rl.get_run_json(&run_id).await),
        None => Json(serde_json::json!({
            "enabled": false,
            "receipts": [],
            "verify": null,
        })),
    }
}

async fn policy_overlay_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    #[cfg(feature = "dictum")]
    {
        match state.dictum_overlay.as_ref() {
            Some(overlay) => Json(serde_json::json!({
                "enabled": true,
                "loaded": true,
                "policyCount": overlay.policy_count(),
                "policyHash": overlay.policy_hash(),
                "source": overlay.source_path().display().to_string(),
            })),
            None => Json(serde_json::json!({
                "enabled": true,
                "loaded": false,
                "policyCount": 0,
                "policyHash": null,
                "source": null,
            })),
        }
    }
    #[cfg(not(feature = "dictum"))]
    {
        let _ = state;
        Json(serde_json::json!({
            "enabled": false,
            "loaded": false,
            "policyCount": 0,
            "policyHash": null,
            "source": null,
        }))
    }
}

async fn reasoning_status_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let (engine, models) = match state.reasoning.as_ref() {
        Some(rh) => (
            rh.engine_name().to_string(),
            rh.model_digests()
                .into_iter()
                .map(|(name, sha)| serde_json::json!({"name": name, "sha256": sha}))
                .collect::<Vec<_>>(),
        ),
        None => ("(none)".to_string(), Vec::new()),
    };
    let ml_feature_enabled = cfg!(feature = "ml");
    Json(serde_json::json!({
        "enabled": state.reasoning.is_some(),
        "engine": engine,
        "models": models,
        "mlFeatureCompiled": ml_feature_enabled,
    }))
}

async fn kernel_status_handler() -> Json<serde_json::Value> {
    #[cfg(feature = "kernel")]
    {
        use iaga_sentinel_kernel::{EnforcementKernel, UserspaceKernel};
        let k = UserspaceKernel::allow_all();
        let linux_bpf = cfg!(feature = "linux-bpf") && cfg!(target_os = "linux");
        Json(serde_json::json!({
            "enabled": true,
            "backend": k.backend_name(),
            "authoritative": k.is_authoritative(),
            "linuxBpfScaffold": linux_bpf,
        }))
    }
    #[cfg(not(feature = "kernel"))]
    {
        Json(serde_json::json!({
            "enabled": false,
            "backend": "(disabled)",
            "authoritative": false,
            "linuxBpfScaffold": false,
        }))
    }
}

// ── 1.5 cost-control: /v1/cost/* (ADR 0020) ──

#[cfg(feature = "cost-control")]
async fn cost_summary_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<CostQuery>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    let mut summary = state
        .audit_store
        .cost_summary(q.from_date.as_deref(), q.to_date.as_deref())
        .await?;
    // Fold in deterministic-cache savings: cost reduction is surfaced here, not
    // as audit rows, so it never double-counts the per-call governance event.
    let cache = crate::modules::cost::cache::stats();
    summary.savings_usd += iaga_sentinel_cost::micros_to_usd(cache.savings_micros);
    summary.cache_hits += cache.hits;
    summary.gross_cost_usd = summary.net_cost_usd + summary.savings_usd;
    Ok(Json(
        serde_json::json!({ "enabled": true, "summary": summary }),
    ))
}
#[cfg(not(feature = "cost-control"))]
async fn cost_summary_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "enabled": false }))
}

#[cfg(feature = "cost-control")]
async fn cost_by_agent_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<CostQuery>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    let rows = state
        .audit_store
        .cost_by_agent(
            q.from_date.as_deref(),
            q.to_date.as_deref(),
            q.limit.unwrap_or(20),
        )
        .await?;
    Ok(Json(serde_json::json!({ "enabled": true, "rows": rows })))
}
#[cfg(not(feature = "cost-control"))]
async fn cost_by_agent_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "enabled": false }))
}

#[cfg(feature = "cost-control")]
async fn cost_by_model_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<CostQuery>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    let rows = state
        .audit_store
        .cost_by_model(
            q.from_date.as_deref(),
            q.to_date.as_deref(),
            q.limit.unwrap_or(20),
        )
        .await?;
    Ok(Json(serde_json::json!({ "enabled": true, "rows": rows })))
}
#[cfg(not(feature = "cost-control"))]
async fn cost_by_model_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "enabled": false }))
}

#[cfg(feature = "cost-control")]
async fn cost_by_tool_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<CostQuery>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    let rows = state
        .audit_store
        .cost_by_tool(
            q.from_date.as_deref(),
            q.to_date.as_deref(),
            q.limit.unwrap_or(20),
        )
        .await?;
    Ok(Json(serde_json::json!({ "enabled": true, "rows": rows })))
}
#[cfg(not(feature = "cost-control"))]
async fn cost_by_tool_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "enabled": false }))
}

#[cfg(feature = "cost-control")]
async fn cost_over_time_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<CostQuery>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    let bucket = q.bucket.as_deref().unwrap_or("hour").to_string();
    let rows = state
        .audit_store
        .cost_over_time(q.from_date.as_deref(), q.to_date.as_deref(), &bucket)
        .await?;
    Ok(Json(
        serde_json::json!({ "enabled": true, "bucket": bucket, "rows": rows }),
    ))
}
#[cfg(not(feature = "cost-control"))]
async fn cost_over_time_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "enabled": false }))
}

#[cfg(feature = "cost-control")]
async fn cost_budget_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "enabled": true,
        "sessionLimitUsd": crate::pipeline::cost::session_budget_usd(),
    }))
}
#[cfg(not(feature = "cost-control"))]
async fn cost_budget_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "enabled": false }))
}

#[cfg(feature = "cost-control")]
async fn cost_pricing_handler() -> Json<serde_json::Value> {
    let table = serde_json::to_value(crate::pipeline::cost::pricing()).unwrap_or_default();
    // `builtinEffectiveDate` is additive (1.5.2): the `pricing` payload shape
    // is unchanged. It dates the BUILT-IN list; a table loaded from
    // IAGA_SENTINEL_PRICING_FILE has whatever freshness the operator gave it.
    Json(serde_json::json!({
        "enabled": true,
        "pricing": table,
        "builtinEffectiveDate": iaga_sentinel_cost::BUILTIN_PRICING_EFFECTIVE_DATE,
    }))
}
#[cfg(not(feature = "cost-control"))]
async fn cost_pricing_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "enabled": false }))
}
