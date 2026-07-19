use axum::http::StatusCode;
use axum::response::{IntoResponse, Json};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Workspace not found: {0}")]
    WorkspaceNotFound(String),

    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Authentication required")]
    AuthRequired,

    #[error("Invalid API key")]
    InvalidApiKey,

    #[error("This endpoint requires an admin-scoped API key")]
    AdminScopeRequired,

    /// The request asserted a workspace that is not the one its agent profile
    /// belongs to. Scope is derived server-side from the profile; a contradicting
    /// client value is refused rather than silently honoured, which would have
    /// evaluated the action against another workspace's thresholds, egress
    /// allowlist and tool policy, and signed the receipt with that workspace's
    /// `policy_hash`.
    #[error("Agent '{agent_id}' belongs to workspace '{expected}', but the request asserted '{claimed}'")]
    WorkspaceScopeMismatch {
        agent_id: String,
        expected: String,
        claimed: String,
    },

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Review not found: {0}")]
    ReviewNotFound(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("Proxy error: {0}")]
    Proxy(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
    message: String,
}

impl IntoResponse for SentinelError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_type) = match &self {
            SentinelError::AgentNotFound(_) => (StatusCode::NOT_FOUND, "agent_not_found"),
            SentinelError::WorkspaceNotFound(_) => (StatusCode::NOT_FOUND, "workspace_not_found"),
            SentinelError::PolicyViolation(_) => (StatusCode::FORBIDDEN, "policy_violation"),
            SentinelError::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "storage_error"),
            SentinelError::AuthRequired => (StatusCode::UNAUTHORIZED, "auth_required"),
            SentinelError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "invalid_api_key"),
            SentinelError::AdminScopeRequired => (StatusCode::FORBIDDEN, "admin_scope_required"),
            SentinelError::WorkspaceScopeMismatch { .. } => {
                (StatusCode::FORBIDDEN, "scope_mismatch")
            }
            SentinelError::InvalidRequest(_) => (StatusCode::BAD_REQUEST, "invalid_request"),
            SentinelError::ReviewNotFound(_) => (StatusCode::NOT_FOUND, "review_not_found"),
            SentinelError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
            SentinelError::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "config_error"),
            SentinelError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "io_error"),
            SentinelError::Proxy(_) => (StatusCode::INTERNAL_SERVER_ERROR, "proxy_error"),
        };

        let body = ErrorBody {
            error: error_type.to_string(),
            message: self.to_string(),
        };

        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for SentinelError {
    fn from(e: sqlx::Error) -> Self {
        SentinelError::Storage(e.to_string())
    }
}

impl From<std::io::Error> for SentinelError {
    fn from(e: std::io::Error) -> Self {
        // 1.5.2: dedicated Io variant; previously conflated with Config,
        // which made file-not-found surface as `config_error`.
        SentinelError::Io(e.to_string())
    }
}

impl From<serde_yaml::Error> for SentinelError {
    fn from(e: serde_yaml::Error) -> Self {
        SentinelError::Config(e.to_string())
    }
}
