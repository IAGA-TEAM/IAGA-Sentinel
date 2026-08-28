use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures_core::Stream;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::auth::middleware::RequireAdmin;
use crate::core::errors::SentinelError;
use crate::server::app_state::AppState;

/// SSE endpoint: GET /v1/events/stream
/// Streams real-time governance events to connected clients.
///
/// Admin-scoped: the stream is a firehose of every tenant's `ActionGoverned`
/// events, carrying other agents' tool names, decisions and risk scores in real
/// time. That is the same cross-tenant read `/v1/audit` already refuses to an
/// agent-scoped key, just live instead of after the fact.
///
/// The console is unaffected: it sends one bearer token for every call
/// (`dashboard.html` `fetchJson` and `startLive` share `state.token`) and its
/// refresh cycle already requires admin for `/v1/audit` and `/v1/receipts`, so
/// an operator who can load the dashboard at all can already open this stream.
pub async fn sse_handler(
    _admin: RequireAdmin,
    State(state): State<Arc<AppState>>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, SentinelError> {
    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).unwrap_or_default();
            let event_type = match &event {
                crate::events::bus::SentinelEvent::ActionGoverned { .. } => "action_governed",
                crate::events::bus::SentinelEvent::ReviewCreated { .. } => "review_created",
                crate::events::bus::SentinelEvent::ReviewResolved { .. } => "review_resolved",
            };
            Some(Ok(Event::default().event(event_type).data(json)))
        }
        // OBS-SSE-LAG-1: a lagging subscriber dropped `n` events. Surface it as
        // a `lagged` frame (+ log) instead of silently losing Blocks/Reviews.
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
            tracing::warn!(missed = n, "SSE subscriber lagged; events dropped");
            Some(Ok(Event::default()
                .event("lagged")
                .data(format!("{{\"missed\":{n}}}"))))
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
