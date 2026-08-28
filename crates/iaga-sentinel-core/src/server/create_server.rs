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
use crate::auth::middleware::{
    authorize_agent_scope, AuthContext, CapabilityTokenHeader, RequireAdmin,
};
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
    #[serde(default, rename = "agentId")]
    agent_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiKeyCreated {
    id: String,
    key: String,
    label: String,
    scope: String,
    agent_id: Option<String>,
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
        .route("/v1/nhi/tokens", get(list_tokens_handler))
        .route("/v1/nhi/tokens/{token_id}", delete(revoke_token_handler))
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
            use axum::http::{header, HeaderName, HeaderValue, Method};
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
                // `x-iaga-capability-token` is the documented way for an
                // agent-scoped caller to read its own record, so a browser has
                // to be allowed to send it -- without this the header is
                // stripped at preflight and the remedy works only from curl.
                .allow_headers([
                    header::CONTENT_TYPE,
                    header::AUTHORIZATION,
                    HeaderName::from_static(crate::auth::middleware::CAPABILITY_TOKEN_HEADER),
                ])
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

    // WHICH KEY made this request. Read from the RESPONSE extensions because
    // this middleware is the OUTER layer: it runs first inbound, before
    // `auth_middleware` has put anything in the request, and the request is
    // gone by the time it has. `AuthContext::run` leaves the copy here for
    // exactly this line.
    //
    // `-` rather than a name when there is none: open mode, an unauthenticated
    // route, or a rejected request that never reached auth. Never guessed.
    let key_id = response
        .extensions()
        .get::<crate::auth::middleware::AuthContext>()
        .and_then(|ctx| ctx.key_id.clone())
        .unwrap_or_else(|| "-".to_string());

    if status.is_server_error() {
        tracing::error!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            key_id = %key_id,
            elapsed_ms,
            "http request completed"
        );
    } else if status.is_client_error() {
        tracing::warn!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            key_id = %key_id,
            elapsed_ms,
            "http request completed"
        );
    } else {
        tracing::info!(
            request_id = %request_id,
            method = %method,
            path = %path,
            status = status.as_u16(),
            key_id = %key_id,
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
    auth: AuthContext,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<InspectRequest>,
) -> Result<impl IntoResponse, SentinelError> {
    auth.authorize_agent_id(&payload.agent_id)?;
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

/// RFC 4180 quoting for one CSV field.
///
/// The export interpolated every field straight into the row, and `agent_id`,
/// `framework` and `tool_name` are free-form strings taken from the caller's
/// `/v1/inspect` body and from `POST /v1/profiles` — so an agent, including a
/// hostile one, chooses their contents. A comma shifted every later column, a
/// bare quote broke the field, and a newline split one audit record into two
/// rows, the second of which parses as a whole event with a fabricated
/// `event_id`. Measured on a live 2.1.0 export: 5 of 33 records malformed.
///
/// ponytail: the rule is four lines. A csv crate for one writer is a
/// dependency for nothing.
fn csv_field(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

async fn audit_export_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(query): axum::extract::Query<AuditExportQuery>,
) -> Result<impl IntoResponse, SentinelError> {
    // An empty value is equivalent to the documented JSON default.
    let requested_format = query
        .format
        .as_deref()
        .filter(|format| !format.is_empty())
        .unwrap_or("json");
    if requested_format != "json" && requested_format != "csv" {
        return Err(SentinelError::InvalidRequest(format!(
            "unsupported format `{requested_format}`: expected `json` or `csv`"
        )));
    }

    let filter = AuditExportFilter {
        tenant_id: query.tenant_id,
        agent_id: query.agent_id,
        decision: query.decision,
        from_date: query.from_date,
        to_date: query.to_date,
        limit: query.limit,
    };

    let events = state.audit_store.list_filtered(&filter).await?;

    match requested_format {
        "csv" => {
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
                    csv_field(&e.event_id),
                    csv_field(&e.agent_id),
                    csv_field(&e.framework),
                    csv_field(&at),
                    csv_field(&e.tool_name),
                    csv_field(&dec),
                    e.risk_score,
                    csv_field(&rs),
                    csv_field(&e.timestamp)
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

/// Reads across every agent in the store, so it is the same cross-tenant read
/// that `RequireAdmin` already guards on `/v1/audit` (issue #18). The write
/// halves of the governance surface were gated then; these read halves were
/// never reviewed and stayed open to any agent-scoped key.
async fn analytics_agents_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AgentAnalytics>>, SentinelError> {
    let analytics = state.audit_store.agent_analytics(None).await?;
    Ok(Json(analytics))
}

/// Admin, OR an agent reading its OWN analytics with a capability token.
///
/// The per-agent reads became admin-only in 2.1.0, which left an agent no way
/// to see its own governance record. `read:self` is exactly that access, and
/// the token is bound to one `agent_id`, so it cannot widen into another's.
async fn analytics_agent_handler(
    capability: CapabilityTokenHeader,
    State(state): State<Arc<AppState>>,
    request_parts: axum::http::Extensions,
    Path(agent_id): Path<String>,
) -> Result<Json<Vec<AgentAnalytics>>, SentinelError> {
    authorize_agent_scope(
        &state,
        &request_parts,
        &capability,
        &agent_id,
        crypto_identity::CAP_READ_SELF,
    )
    .await?;
    let analytics = state.audit_store.agent_analytics(Some(&agent_id)).await?;
    Ok(Json(analytics))
}

// ── Reviews ──

async fn reviews_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ReviewRequest>>, SentinelError> {
    let reviews = state.review_store.list().await?;
    Ok(Json(reviews))
}

/// Resolving a review is an operator decision, exactly like releasing a
/// sandboxed action (`sandbox_approve_handler`). Without this guard an
/// agent-scoped key could list the queue, find the ReviewRequest raised against
/// its own action, and mark it `approved`. That does not release the execution -
/// nothing re-reads the status - but it publishes `ReviewResolved` on the event
/// bus and the console then shows the entry as settled by a human. For a product
/// whose deliverable is the evidence record, falsifying the human-in-the-loop
/// trail is the whole injury.
async fn review_action_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    extensions: axum::http::Extensions,
    Path(id): Path<String>,
    Json(body): Json<ReviewBody>,
) -> Result<Json<ReviewRequest>, SentinelError> {
    let status_str = match body.status {
        ReviewAction::Approved => "approved",
        ReviewAction::Rejected => "rejected",
    };
    let updated = state.review_store.update_status(&id, status_str).await?;

    // Open mode, and legacy `ApiKeyStore` impls that only report a boolean
    // match, carry no key id. Record that rather than inventing an actor.
    let actor = extensions
        .get::<crate::auth::middleware::AuthContext>()
        .and_then(|ctx| ctx.key_id.clone())
        .unwrap_or_else(|| "unattributed".to_string());
    let resolved_json = serde_json::to_string(&updated).unwrap_or_default();
    let resolution = StoredAuditEvent {
        event_id: Uuid::new_v4().to_string(),
        agent_id: updated.agent_id.clone(),
        // `review_requests` HAS a `tenant_id` column on both backends
        // (migrations/{sqlite,postgres}/0001_initial.sql:27) and nothing has
        // ever written it: `ReviewRequest` has no such field and the pipeline's
        // INSERT lists ten columns without it, so it is NULL on every row.
        // Nothing to copy, and recovering it would mean re-reading the agent
        // profile and half-implementing the pipeline's
        // `profile.tenant_id.or(workspace.tenant_id)` rule. Consequence, stated:
        // `/v1/audit/export?tenant_id=X` returns the governed action and NOT
        // this adjudication.
        tenant_id: None,
        framework: "review-resolution".to_string(),
        action_type: ActionType::Custom,
        tool_name: updated.tool_name.clone(),
        // Binds the resolved request itself — id, outcome, resolution time, the
        // reasons the human was shown — into the receipt's input hash.
        input_sha256: hex::encode(Sha256::digest(resolved_json.as_bytes())),
        // The human's answer on the same scale as every other row: an approval
        // says the action may proceed, a rejection says it may not.
        decision: match body.status {
            ReviewAction::Approved => GovernanceDecision::Allow,
            ReviewAction::Rejected => GovernanceDecision::Block,
        },
        timestamp: updated.updated_at.clone(),
        reasons: vec![
            format!("review-resolved:{status_str}"),
            // A ReviewRequest's id IS the `event_id` of the action that opened
            // it, so this line joins the two rows in an export. Requests opened
            // before that change carry an unrelated UUID and simply do not join
            // — which is why this names the REQUEST and does not claim an event
            // by that id exists.
            format!("review-request:{id}"),
            format!("resolved-by:{actor}"),
        ],
        review_status: match body.status {
            ReviewAction::Approved => ReviewStatus::Approved,
            ReviewAction::Rejected => ReviewStatus::Rejected,
        },
        // COPIED from the request being adjudicated, not measured here: no
        // action was governed at this instant. Kept rather than zeroed because
        // 0 would assert "no risk" inside the signed receipt, and the receipt
        // body has no framework/tool field — `reasons[0]` is the only thing in
        // it that says this is an adjudication.
        risk_score: updated.risk_score,
        usage: None,
        session_id: None,
    };
    if let Err(e) = state.audit_store.append(&resolution).await {
        tracing::error!(
            event_id = %resolution.event_id,
            review_id = %id,
            error = %e,
            "failed to persist review-resolution audit event"
        );
    }
    if let Some(rl) = state.receipts.as_ref() {
        // Not `?`, unlike every other `record` call site: this one cannot honour
        // `IAGA_SENTINEL_RECEIPT_FAIL_CLOSED`. Fail-closed means "no verdict
        // without evidence", and the verdict here is already committed —
        // `update_status` is terminal and cannot be rolled back — so a 500 would
        // tell the operator their resolution failed when it stands.
        if let Err(e) = rl
            .record(
                &resolution,
                None,
                None,
                crate::pipeline::receipts::ReceiptContext {
                    policy_hash: None,
                    threat_feed_hash: None,
                    dictum_trace: None,
                },
            )
            .await
        {
            tracing::error!(review_id = %id, error = %e, "review-resolution receipt not recorded");
        }
    }

    // Emit review resolved event
    state.event_bus.publish(SentinelEvent::ReviewResolved {
        review_id: id,
        status: status_str.to_string(),
    });

    Ok(Json(updated))
}

// ── Profiles CRUD ──

async fn list_profiles_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<AgentProfile>>, SentinelError> {
    let profiles = state.policy_store.list_profiles().await?;
    Ok(Json(profiles))
}

async fn get_profile_handler(
    capability: CapabilityTokenHeader,
    State(state): State<Arc<AppState>>,
    request_parts: axum::http::Extensions,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentProfile>, SentinelError> {
    authorize_agent_scope(
        &state,
        &request_parts,
        &capability,
        &agent_id,
        crypto_identity::CAP_READ_SELF,
    )
    .await?;
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

/// The highest-value read of the set: a workspace policy carries
/// `threshold_block`, `threshold_review` and `allowed_domains`, so an
/// agent-scoped key that can read it learns the exact score at which it gets
/// blocked and can trim itself to `threshold_block - 1`.
async fn list_workspaces_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<WorkspacePolicy>>, SentinelError> {
    let workspaces = state.policy_store.list_workspaces().await?;
    Ok(Json(workspaces))
}

async fn get_workspace_handler(
    _admin: RequireAdmin,
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
    // A threshold that moves is worth a line in the log.
    //
    // PUT replaces, and both thresholds carry serde defaults, so a body that
    // simply omits them resets a workspace hardened to 40/20 back to 70/35 and
    // answers 200 OK. That is correct HTTP and a genuinely dangerous default:
    // 2.0.2 shipped with every Postgres workspace silently governed at 70/35
    // while its configuration said otherwise, and nobody noticed because
    // nothing said anything. The fields are documented in `docs/openapi.yaml`
    // now (with a parity test so they cannot fall out again); this makes the
    // change audible as well as documented.
    if let Ok(previous) = state
        .policy_store
        .get_workspace_policy(&policy.workspace_id)
        .await
    {
        if previous.threshold_block != policy.threshold_block
            || previous.threshold_review != policy.threshold_review
        {
            tracing::warn!(
                workspace_id = %policy.workspace_id,
                from_block = previous.threshold_block,
                to_block = policy.threshold_block,
                from_review = previous.threshold_review,
                to_review = policy.threshold_review,
                "workspace risk thresholds changed by an API write; omitting them on a PUT \
                 resets them to the defaults (70/35)"
            );
        }
    }
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
    let agent_id = match scope {
        KeyScope::Agent => Some(
            body.agent_id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    SentinelError::InvalidRequest(
                        "agentId is required when scope is `agent`".into(),
                    )
                })?
                .to_string(),
        ),
        KeyScope::Admin if body.agent_id.is_some() => {
            return Err(SentinelError::InvalidRequest(
                "agentId is only valid when scope is `agent`".into(),
            ))
        }
        KeyScope::Admin => None,
    };
    let (raw_key, key_hash) = generate_api_key();
    let key_id = uuid::Uuid::new_v4().to_string();
    state
        .api_key_store
        .store_key_scoped(
            &key_id,
            &key_hash,
            &body.label,
            &raw_key,
            scope,
            agent_id.as_deref(),
        )
        .await?;
    state.auth_cache.set_keys_exist(true);
    Ok((
        StatusCode::CREATED,
        Json(ApiKeyCreated {
            id: key_id,
            key: raw_key,
            label: body.label,
            scope: scope.as_str().to_string(),
            agent_id,
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
    _admin: RequireAdmin,
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

/// Admin-scoped: other agents' live session graphs.
async fn list_sessions_handler(_admin: RequireAdmin) -> Json<Vec<serde_json::Value>> {
    let sessions = session_dag::list_active_sessions();
    let json: Vec<serde_json::Value> = sessions
        .into_iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();
    Json(json)
}

/// Admin-scoped, with `GET /v1/sessions`. Not scoped by `read:self`: the path
/// carries a SESSION id, not an agent id, so there is nothing to bind a
/// per-agent token against without a lookup this route does not need.
async fn session_metrics_handler(
    _admin: RequireAdmin,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    match session_dag::get_session_metrics(&id) {
        Some(m) => Ok(Json(serde_json::to_value(m).unwrap_or_default())),
        None => Err(SentinelError::NotFound(format!("Session not found: {id}"))),
    }
}

// ── L3: NHI Identity ──

/// Admin-scoped: every registered agent id, SPIFFE id, key commitment and
/// trust score -- the target list for the per-agent reads this release closes.
/// Its `POST` twin has been admin-only since the identity surface existed.
async fn list_identities_handler(_admin: RequireAdmin) -> Json<Vec<serde_json::Value>> {
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
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterIdentityBody>,
) -> Result<impl IntoResponse, SentinelError> {
    let identity = crypto_identity::register_identity(
        &body.agent_id,
        body.workspace_id.as_deref(),
        body.capabilities,
    );
    // Persisted before it is acknowledged, for the same reason the token is:
    // `verify_token_signature` reads the agent's derived secret out of the
    // in-memory registry and fails closed when it is absent, and `main.rs`
    // rebuilds that registry at boot from `list_identities()`. An identity that
    // never reached storage is gone after a restart, and every durable
    // capability token bound to it stops verifying -- which is exactly what
    // migration 0008 was added to prevent. `execute_pipeline` has persisted its
    // auto-registered identities since v0.4.0; this route never did.
    let secret_hex = crypto_identity::get_secret_key_hex(&body.agent_id).unwrap_or_default();
    state
        .nhi_store
        .store_identity(&identity, &secret_hex)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(identity).unwrap_or_default()),
    )
        .into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestBody {
    agent_id: String,
    challenge: String,
}

async fn attest_handler(
    auth: AuthContext,
    Json(body): Json<AttestBody>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    auth.authorize_agent_id(&body.agent_id)?;
    let result = crypto_identity::attest_agent(&body.agent_id, &body.challenge);
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateChallengeBody {
    agent_id: String,
}

async fn create_challenge_handler(
    auth: AuthContext,
    Json(body): Json<CreateChallengeBody>,
) -> Result<impl IntoResponse, SentinelError> {
    auth.authorize_agent_id(&body.agent_id)?;
    match crypto_identity::create_challenge(&body.agent_id) {
        Some(challenge) => Ok((
            StatusCode::CREATED,
            Json(serde_json::to_value(challenge).unwrap_or_default()),
        )
            .into_response()),
        // Naming the remedy, because this 404 is reachable on the happy path:
        // an agent can have a profile and an agent-scoped key and still have no
        // NHI identity, since the identity is created lazily by its first
        // governed action. 2.1.0 makes that gap matter — `read:self` is the
        // documented answer to the reads this release closes, so "not
        // registered" is what a user hits while following the upgrade notes.
        None => Err(SentinelError::NotFound(format!(
            "No NHI identity for {}; register it with POST /v1/nhi/identities, \
             or let the agent's first governed action create it",
            body.agent_id
        ))),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyAttestBody {
    agent_id: String,
    challenge_id: String,
    signature: String,
}

async fn verify_attestation_handler(
    auth: AuthContext,
    Json(body): Json<VerifyAttestBody>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    auth.authorize_agent_id(&body.agent_id)?;
    let result =
        crypto_identity::verify_attestation(&body.agent_id, &body.challenge_id, &body.signature);
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
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

/// Minting a capability token is an operator action.
///
/// It had no guard at all, so any agent-scoped key could mint
/// `capabilities: ["*"]` for any registered agent id. That was harmless only
/// because nothing verified the token; the moment it started granting access it
/// would have been a privilege-escalation hole, so the guard lands in the same
/// change that gives the token teeth.
async fn issue_token_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Json(body): Json<IssueTokenBody>,
) -> Result<impl IntoResponse, SentinelError> {
    // A TTL that cannot be honoured is refused rather than minted.
    //
    // `ttlSeconds` went straight into `Duration::seconds`, so a negative value
    // minted a `201 valid: true` token that was already expired — a credential
    // the API says is good and every check rejects — and a value large enough to
    // push the expiry past year 9999 minted one that cannot even be rendered
    // back, so it was dead on arrival in the same way. Neither told the caller
    // anything.
    //
    // The ceiling exists because a capability token is a bearer credential with
    // no revocation pressure on the holder: the only reason to mint a ten-year
    // one is that nothing stopped you. A year is far past any legitimate agent
    // session and still a finite blast radius; `DELETE /v1/nhi/tokens/{id}`
    // remains the way to end one early.
    const MAX_TTL_SECONDS: i64 = 365 * 24 * 60 * 60;
    if body.ttl_seconds <= 0 || body.ttl_seconds > MAX_TTL_SECONDS {
        return Err(SentinelError::InvalidRequest(format!(
            "ttlSeconds must be between 1 and {MAX_TTL_SECONDS} (one year), got {}",
            body.ttl_seconds
        )));
    }
    match crypto_identity::issue_capability_token(
        &body.agent_id,
        body.capabilities,
        body.ttl_seconds,
    ) {
        Some(token) => {
            // Persisted before it is handed out: a token the caller holds but
            // the store has never seen would verify nowhere.
            state.nhi_store.store_capability_token(&token).await?;
            Ok((
                StatusCode::CREATED,
                Json(serde_json::to_value(&token).unwrap_or_default()),
            )
                .into_response())
        }
        // Naming the remedy, because this 404 is reachable on the happy path:
        // an agent can have a profile and an agent-scoped key and still have no
        // NHI identity, since the identity is created lazily by its first
        // governed action. 2.1.0 makes that gap matter — `read:self` is the
        // documented answer to the reads this release closes, so "not
        // registered" is what a user hits while following the upgrade notes.
        None => Err(SentinelError::NotFound(format!(
            "No NHI identity for {}; register it with POST /v1/nhi/identities, \
             or let the agent's first governed action create it",
            body.agent_id
        ))),
    }
}

/// The inventory a revocation needs.
///
/// Minting and revoking both take an id the caller already holds, so an
/// operator could only ever withdraw a token whose id they had written down at
/// mint time: "what is currently authorized" had no answer at all, on a bearer
/// credential that grants access to another agent's governance data.
///
/// Admin-only, like the other two, and the `signature` is not in the response:
/// it is the server's own HMAC over the row, recomputed from the agent's
/// derived secret on every check, so publishing it would hand out a valid MAC
/// under that secret next to the plaintext it covers — and an inventory does
/// not need it. The row is excluded in the SQL projection rather than filtered
/// afterwards, so a later edit cannot reintroduce it by accident.
async fn list_tokens_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::storage::traits::CapabilityTokenRecord>>, SentinelError> {
    Ok(Json(state.nhi_store.list_capability_tokens().await?))
}

/// Revoke a capability token. Durable and fleet-wide, because the row is the
/// authority -- there is no in-process token cache to go stale.
///
/// This route did not exist: `revoke_token` was implemented and unreachable, so
/// a token could be minted and never withdrawn.
async fn revoke_token_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
    Path(token_id): Path<String>,
) -> Result<StatusCode, SentinelError> {
    if state.nhi_store.revoke_capability_token(&token_id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(SentinelError::NotFound(format!(
            "Capability token not found: {token_id}"
        )))
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

/// Admin-scoped: every agent's held-back actions. Its approve and reject
/// twins below were already admin-only, so this read was the asymmetric one.
async fn sandbox_pending_handler(_admin: RequireAdmin) -> Json<Vec<serde_json::Value>> {
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
) -> Result<impl IntoResponse, SentinelError> {
    match sandbox_executor::approve_sandbox(&id) {
        Some(r) => Ok((
            StatusCode::OK,
            Json(serde_json::to_value(r).unwrap_or_default()),
        )
            .into_response()),
        None => Err(SentinelError::NotFound(format!(
            "Sandbox entry not found: {id}"
        ))),
    }
}

async fn sandbox_reject_handler(
    _admin: RequireAdmin,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, SentinelError> {
    match sandbox_executor::reject_sandbox(&id) {
        Some(r) => Ok((
            StatusCode::OK,
            Json(serde_json::to_value(r).unwrap_or_default()),
        )
            .into_response()),
        None => Err(SentinelError::NotFound(format!(
            "Sandbox entry not found: {id}"
        ))),
    }
}

// ── L6: Policy Verification ──

/// Same read as `get_workspace_handler` behind an analysis pass: it loads an
/// arbitrary workspace policy and reports its shape. Gating the policy read but
/// not its verifier would have left the same disclosure one route over.
async fn verify_policy_handler(
    _admin: RequireAdmin,
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

/// Admin-scoped. The span buffer records `agent.id`, `tool.name`,
/// `governance.decision` and `risk.score` for every governed action and keeps
/// 10_000 of them newest-first, so polling this route reconstructs exactly the
/// cross-tenant firehose that `/v1/events/stream` and `/v1/audit` refuse to an
/// agent-scoped key. Closing those two and leaving this open was shutting one
/// door and leaving the next one open on the same data.
async fn telemetry_spans_handler(_admin: RequireAdmin) -> Json<Vec<serde_json::Value>> {
    let spans = otel_emitter::get_recent_spans(100);
    let json: Vec<serde_json::Value> = spans
        .into_iter()
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect();
    Json(json)
}

/// Admin-scoped, with `/v1/telemetry/spans`: the same per-agent governance
/// counters, aggregated.
async fn telemetry_metrics_handler(_admin: RequireAdmin) -> Json<Vec<serde_json::Value>> {
    let metrics = otel_emitter::get_recent_metrics(100);
    let json: Vec<serde_json::Value> = metrics
        .into_iter()
        .filter_map(|m| serde_json::to_value(m).ok())
        .collect();
    Json(json)
}

/// Admin-scoped, with `/v1/telemetry/spans`: the OTLP rendering of the same
/// buffer, 200 records at a time.
async fn telemetry_export_handler(_admin: RequireAdmin) -> Json<Vec<serde_json::Value>> {
    let records = otel_emitter::export_otlp_json(200);
    let json: Vec<serde_json::Value> = records
        .into_iter()
        .filter_map(|r| serde_json::to_value(r).ok())
        .collect();
    Json(json)
}

// ── Response Scanning ──

async fn response_scan_handler(
    auth: AuthContext,
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ResponseScanRequest>,
) -> Result<Json<ResponseScanResult>, SentinelError> {
    auth.authorize_agent_id(&payload.agent_id)?;
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

/// Admin, OR an agent reading its OWN behavioural record with a capability
/// token. Named in the `CAP_READ_SELF` doc alongside analytics and profile.
async fn get_fingerprint_handler(
    capability: CapabilityTokenHeader,
    State(state): State<Arc<AppState>>,
    request_parts: axum::http::Extensions,
    Path(agent_id): Path<String>,
) -> Result<axum::response::Response, SentinelError> {
    authorize_agent_scope(
        &state,
        &request_parts,
        &capability,
        &agent_id,
        crypto_identity::CAP_READ_SELF,
    )
    .await?;
    match state.behavioral_engine.get_fingerprint(&agent_id) {
        Some(fp) => Ok((
            StatusCode::OK,
            Json(serde_json::to_value(fp).unwrap_or_default()),
        )
            .into_response()),
        None => Err(SentinelError::NotFound(format!(
            "No behavioural fingerprint for agent: {agent_id}"
        ))),
    }
}

/// Admin-scoped: every agent's behavioural record. The per-agent read below
/// is the one an agent can reach for itself, with `read:self`.
async fn list_fingerprints_handler(
    _admin: RequireAdmin,
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

/// Admin, OR an agent reading its OWN rate-limit state with a capability
/// token. Named in the `CAP_READ_SELF` doc alongside analytics and profile.
async fn rate_limit_status_handler(
    capability: CapabilityTokenHeader,
    State(state): State<Arc<AppState>>,
    request_parts: axum::http::Extensions,
    Path(agent_id): Path<String>,
) -> Result<Json<serde_json::Value>, SentinelError> {
    authorize_agent_scope(
        &state,
        &request_parts,
        &capability,
        &agent_id,
        crypto_identity::CAP_READ_SELF,
    )
    .await?;
    let status = state.rate_limiter.status(&agent_id).await;
    Ok(Json(serde_json::to_value(status).unwrap_or_default()))
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
    // Persist it too. `save_config` shipped with a full UPSERT on both backends
    // and no caller, while `main.rs` reads the row back at boot — so a tightened
    // limit answered 200, survived until restart, and then silently reverted to
    // the defaults. On the multi-replica deployment that `values.yaml` gives as
    // the reason to choose Postgres, it bound only the replica that served the
    // POST. Best-effort: the in-memory limiter is already updated, so a storage
    // failure must not turn a successful tightening into an error response.
    if let Err(e) = state.rate_limit_store.save_config(&new_config).await {
        tracing::warn!(error = %e, "rate-limit config applied in memory but not persisted");
    }
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
) -> Result<StatusCode, SentinelError> {
    if state.threat_feed.remove_indicator(&id) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(SentinelError::NotFound(format!(
            "Threat indicator not found: {id}"
        )))
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
) -> Result<StatusCode, SentinelError> {
    if state.webhook_manager.dlq().remove(&id).await {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(SentinelError::NotFound(format!(
            "DLQ entry not found: {id}"
        )))
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
        None => Err(SentinelError::NotFound(format!(
            "Template not found: {template_id}"
        ))),
    }
}

// ── v0.4.0: Policy Rules per Workspace ──

/// Admin-scoped, with `GET /v1/workspaces/{id}`. The workspace body carries
/// the block/review thresholds; its rules are the other half of the same
/// policy, and the `POST` twin below was already admin-only.
async fn list_workspace_rules_handler(
    _admin: RequireAdmin,
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
/// Admin-scoped: per-agent spend across the fleet. The other `/v1/cost/*`
/// routes aggregate without naming an agent and stay open.
async fn cost_by_agent_handler(
    _admin: RequireAdmin,
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

#[cfg(test)]
mod csv_export_tests {
    use super::csv_field;

    #[test]
    fn ordinary_values_are_left_alone() {
        assert_eq!(csv_field("openclaw-builder-01"), "openclaw-builder-01");
        assert_eq!(csv_field("block"), "block");
        assert_eq!(csv_field(""), "");
    }

    /// The three shapes that corrupted a real export.
    #[test]
    fn commas_quotes_and_newlines_are_quoted() {
        assert_eq!(csv_field("bad,agent"), "\"bad,agent\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("two\nlines"), "\"two\nlines\"");
        assert_eq!(csv_field("cr\rlf"), "\"cr\rlf\"");
    }

    /// The exact agent id and tool name that split one audit row into two.
    #[test]
    fn the_measured_corrupting_values_round_trip_as_one_field_each() {
        let agent = csv_field("bad,agent\"id");
        let tool = csv_field("tool\"with,comma");
        assert_eq!(agent, "\"bad,agent\"\"id\"");
        assert_eq!(tool, "\"tool\"\"with,comma\"");

        // A quoted field contains no unescaped delimiter, so a parser reading
        // this row sees one field per column rather than the four the raw
        // interpolation produced.
        for field in [&agent, &tool] {
            let inner = &field[1..field.len() - 1];
            assert!(
                inner.replace("\"\"", "").find('"').is_none(),
                "every inner quote must be doubled: {field}"
            );
        }
    }
}
