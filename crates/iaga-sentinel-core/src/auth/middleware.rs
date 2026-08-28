use axum::{
    extract::{FromRequestParts, Request, State},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;

use crate::core::errors::SentinelError;
use crate::server::app_state::AppState;
use crate::storage::traits::KeyScope;

/// Returns true if the IAGA_SENTINEL_OPEN_MODE env var is explicitly set to "true".
pub fn is_open_mode_enabled() -> bool {
    std::env::var("IAGA_SENTINEL_OPEN_MODE")
        .map(|v| v == "true")
        .unwrap_or(false)
}

/// Identity attached to every authenticated request by [`auth_middleware`].
/// Handlers read it via the [`RequireAdmin`] extractor (or directly from
/// request extensions when they only need the key id).
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub scope: KeyScope,
    /// `None` in open mode and for keys verified through a legacy
    /// [`crate::storage::traits::ApiKeyStore`] implementation.
    pub key_id: Option<String>,
    /// Identity an agent-scoped key may assert. Admin/open-mode keys have no
    /// binding because they are explicitly allowed to act across agents.
    pub agent_id: Option<String>,
}

impl AuthContext {
    pub fn authorize_agent_id(&self, claimed: &str) -> Result<(), SentinelError> {
        if self.scope == KeyScope::Admin {
            return Ok(());
        }
        match self.agent_id.as_deref().filter(|id| !id.trim().is_empty()) {
            Some(expected) if expected == claimed => Ok(()),
            Some(expected) => Err(SentinelError::AgentScopeMismatch {
                expected: expected.to_string(),
                claimed: claimed.to_string(),
            }),
            None => Err(SentinelError::AgentKeyUnbound),
        }
    }

    /// Run the rest of the stack with this identity in the REQUEST extensions,
    /// then leave a copy in the RESPONSE extensions.
    ///
    /// The response copy exists because of the layer order in `create_router`:
    /// `request_logging_middleware` is layered onto the MERGED router while
    /// `auth_middleware` is layered onto the protected half alone, so the
    /// logger is the OUTER layer and runs FIRST inbound. At the point it could
    /// read `request.extensions()` this middleware has not run yet, and by the
    /// time this middleware inserts `AuthContext` the request has been moved
    /// into `next.run(...)`. axum copies nothing from request extensions onto
    /// the response, so the only way the access log can name the key that made
    /// a request — on the same line as method/path/status, rather than as a
    /// second, unjoinable line — is to put it there deliberately.
    ///
    /// The log names the authenticating key as a second attribution anchor next
    /// to the bound `agentId` enforced by [`Self::authorize_agent_id`].
    async fn run(self, mut request: Request, next: Next) -> Response {
        request.extensions_mut().insert(self.clone());
        let mut response = next.run(request).await;
        response.extensions_mut().insert(self);
        response
    }
}

impl<S> FromRequestParts<S> for AuthContext
where
    S: Send + Sync,
{
    type Rejection = SentinelError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthContext>()
            .cloned()
            .ok_or(SentinelError::AuthRequired)
    }
}

/// Extractor that rejects with `403 admin_scope_required` unless the request
/// authenticated with an `admin`-scoped key (or open mode, which is implicit
/// admin). Fails closed when the auth middleware did not run.
pub struct RequireAdmin;

impl<S> FromRequestParts<S> for RequireAdmin
where
    S: Send + Sync,
{
    type Rejection = SentinelError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<AuthContext>() {
            Some(ctx) if ctx.scope == KeyScope::Admin => Ok(RequireAdmin),
            // Agent-scoped key, or middleware never ran (fail closed).
            _ => Err(SentinelError::AdminScopeRequired),
        }
    }
}

/// Header carrying a capability token id, alongside the ordinary `Authorization`
/// bearer key. A separate header rather than a second bearer scheme, so the API
/// key that authenticates the CALLER and the token that authorizes the ACTION
/// stay independent and both end up in the audit trail.
pub const CAPABILITY_TOKEN_HEADER: &str = "x-iaga-capability-token";

/// The capability token id presented with this request, if any.
///
/// Deliberately just the header value: verification needs storage, which an
/// infallible `FromRequestParts` cannot reach without dragging `AppState` into
/// every extractor bound. [`authorize_agent_scope`] does the verifying.
#[derive(Debug, Clone, Default)]
pub struct CapabilityTokenHeader(pub Option<String>);

impl<S> FromRequestParts<S> for CapabilityTokenHeader
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(CapabilityTokenHeader(
            parts
                .headers
                .get(CAPABILITY_TOKEN_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
        ))
    }
}

/// Authorize a read of `agent_id`'s own governance data.
///
/// Two ways in, and the order matters for the error message:
///
///  1. an admin-scoped key (or open mode), which may read any agent;
///  2. a capability token that is bound to THIS `agent_id`, verifies against
///     that agent's derived secret, has not expired or been revoked, and
///     carries `required_capability`.
///
/// Between the two sits the key's own binding: a non-admin key must already be
/// entitled to assert `agent_id` before any token is looked at. So asking for
/// somebody else's record answers `agent_scope_mismatch` and never reaches the
/// token, while asking for your own without one answers `capability_required`.
/// Both are 403, and the distinction is deliberate — a caller must not be able
/// to probe which tokens exist for an agent that is not theirs.
///
/// The binding in (2) is the whole point: the token names one agent, so it can
/// never widen into another agent's data no matter what capabilities it lists.
///
/// This is additive. Every caller that worked before -- the console, the SDKs,
/// an operator with an admin key -- still takes path (1) unchanged; path (2)
/// only ever grants access that would otherwise have been refused.
pub async fn authorize_agent_scope(
    state: &Arc<AppState>,
    parts_extensions: &axum::http::Extensions,
    presented: &CapabilityTokenHeader,
    agent_id: &str,
    required_capability: &str,
) -> Result<(), SentinelError> {
    let ctx = parts_extensions
        .get::<AuthContext>()
        .ok_or(SentinelError::AuthRequired)?;
    if ctx.scope == KeyScope::Admin {
        return Ok(());
    }
    ctx.authorize_agent_id(agent_id)?;
    let Some(token_id) = presented.0.as_deref().filter(|s| !s.is_empty()) else {
        return Err(SentinelError::CapabilityRequired(
            required_capability.to_string(),
        ));
    };

    let token = state.nhi_store.get_capability_token(token_id).await?;
    let Some(token) = token else {
        // Same error for "no such token" as for "wrong capability": a caller
        // must not be able to probe which token ids exist.
        return Err(SentinelError::CapabilityRequired(
            required_capability.to_string(),
        ));
    };

    if token.agent_id != agent_id {
        return Err(SentinelError::CapabilityRequired(
            required_capability.to_string(),
        ));
    }
    if !crate::modules::nhi::crypto_identity::token_grants(&token, required_capability) {
        return Err(SentinelError::CapabilityRequired(
            required_capability.to_string(),
        ));
    }

    tracing::debug!(
        agent_id,
        token_id,
        capability = required_capability,
        "authorized by capability token"
    );
    Ok(())
}

/// Auth middleware: extracts the Bearer token and verifies it against stored
/// Argon2 hashes, consulting the per-instance [`crate::auth::cache::AuthCache`]
/// first so the hot path skips the DB query + Argon2 work (1.5.2).
///
/// Open mode (no auth when no keys exist) requires explicit opt-in via
/// IAGA_SENTINEL_OPEN_MODE=true. Without that env var, requests are rejected
/// with 401 if no API keys have been generated yet.
///
/// Staleness: the cached "any keys exist" flag can lag out-of-process key
/// creation/deletion by at most the cache TTL. A presented token is always
/// verified for real on cache miss, so a key created by another process works
/// immediately; set IAGA_SENTINEL_AUTH_CACHE_TTL_MS=0 to disable caching.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract the Bearer token up front (owned, so we can mutate extensions).
    let token: Option<String> = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string);

    // "Any keys configured?" — cached; one list_keys() round-trip on miss.
    let keys_exist = match state.auth_cache.keys_exist() {
        Some(v) => v,
        None => {
            let exist = !state
                .api_key_store
                .list_keys()
                .await
                .unwrap_or_default()
                .is_empty();
            state.auth_cache.set_keys_exist(exist);
            exist
        }
    };

    // No keys yet and no token presented: open mode allows (as implicit
    // admin, the historical behavior), otherwise reject.
    if !keys_exist && token.is_none() {
        if is_open_mode_enabled() {
            return Ok(AuthContext {
                scope: KeyScope::Admin,
                key_id: None,
                agent_id: None,
            }
            .run(request, next)
            .await);
        }
        tracing::warn!("no API keys configured and IAGA_SENTINEL_OPEN_MODE is not enabled, rejecting request. Run `iaga gen-key` to create your first key.");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Keys exist (or the flag is stale and a token was presented anyway):
    // a Bearer token is required from here on.
    let token = match token {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // Hot path: previously verified key, no DB query, no Argon2.
    if let Some((key_id, scope, agent_id)) = state.auth_cache.lookup(&token) {
        return Ok(AuthContext {
            scope,
            key_id,
            agent_id,
        }
        .run(request, next)
        .await);
    }

    // Cold path: verify against stored Argon2 hashes.
    match state.api_key_store.verify_raw_key_scoped(&token).await {
        Ok(Some(verified)) => {
            state.auth_cache.insert(
                &token,
                verified.key_id.clone(),
                verified.scope,
                verified.agent_id.clone(),
            );
            state.auth_cache.set_keys_exist(true);
            Ok(AuthContext {
                scope: verified.scope,
                key_id: verified.key_id,
                agent_id: verified.agent_id,
            }
            .run(request, next)
            .await)
        }
        _ => {
            // Preserve pre-1.5.2 open-mode semantics: with open mode on and
            // genuinely zero keys configured, any request is allowed even if
            // it carried a (stale/bogus) token. Fresh recheck, never cached.
            if is_open_mode_enabled() {
                let fresh_empty = state
                    .api_key_store
                    .list_keys()
                    .await
                    .map(|k| k.is_empty())
                    .unwrap_or(false);
                state.auth_cache.set_keys_exist(!fresh_empty);
                if fresh_empty {
                    return Ok(AuthContext {
                        scope: KeyScope::Admin,
                        key_id: None,
                        agent_id: None,
                    }
                    .run(request, next)
                    .await);
                }
            }
            state.auth_cache.remove(&token);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}
