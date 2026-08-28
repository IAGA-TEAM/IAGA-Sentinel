use std::sync::Arc;

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::sync::RwLock;

use super::bus::SentinelEvent;
use crate::core::errors::SentinelError;

type HmacSha256 = Hmac<Sha256>;

// ── Dead Letter Queue ──

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetterEntry {
    pub id: String,
    pub webhook_id: String,
    pub webhook_url: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub error: String,
    pub attempts: u32,
    pub failed_at: String,
}

pub struct DeadLetterQueue {
    entries: RwLock<Vec<DeadLetterEntry>>,
}

impl Default for DeadLetterQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadLetterQueue {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(Vec::new()),
        }
    }

    pub async fn push(&self, entry: DeadLetterEntry) {
        let mut entries = self.entries.write().await;
        // Keep max 1000 entries
        if entries.len() >= 1000 {
            entries.remove(0);
        }
        entries.push(entry);
    }

    pub async fn list(&self) -> Vec<DeadLetterEntry> {
        self.entries.read().await.clone()
    }

    pub async fn remove(&self, id: &str) -> bool {
        let mut entries = self.entries.write().await;
        let before = entries.len();
        entries.retain(|e| e.id != id);
        entries.len() < before
    }

    pub async fn take(&self, id: &str) -> Option<DeadLetterEntry> {
        let mut entries = self.entries.write().await;
        entries
            .iter()
            .position(|e| e.id == id)
            .map(|pos| entries.remove(pos))
    }
}

/// A registered webhook endpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookConfig {
    pub id: String,
    pub url: String,
    #[serde(skip_serializing)]
    pub secret: String,
    /// Filter: only send events matching these types. Empty = send all.
    #[serde(default)]
    pub event_filter: Vec<String>,
    pub created_at: String,
    pub active: bool,
}

/// Manages webhook registrations and delivery.
pub struct WebhookManager {
    hooks: RwLock<Vec<WebhookConfig>>,
    client: reqwest::Client,
    dlq: Arc<DeadLetterQueue>,
}

impl WebhookManager {
    pub fn new(dlq: Arc<DeadLetterQueue>) -> Self {
        Self {
            hooks: RwLock::new(Vec::new()),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            dlq,
        }
    }

    pub fn dlq(&self) -> &Arc<DeadLetterQueue> {
        &self.dlq
    }

    pub async fn register(
        &self,
        url: String,
        secret: String,
        event_filter: Vec<String>,
    ) -> WebhookConfig {
        let config = WebhookConfig {
            id: uuid::Uuid::new_v4().to_string(),
            url,
            secret,
            event_filter,
            created_at: Utc::now().to_rfc3339(),
            active: true,
        };
        self.hooks.write().await.push(config.clone());
        config
    }

    pub async fn unregister(&self, id: &str) -> Result<(), SentinelError> {
        let mut hooks = self.hooks.write().await;
        let before = hooks.len();
        hooks.retain(|h| h.id != id);
        if hooks.len() == before {
            return Err(SentinelError::NotFound(format!("Webhook not found: {id}")));
        }
        Ok(())
    }

    pub async fn list(&self) -> Vec<WebhookConfig> {
        self.hooks.read().await.clone()
    }

    /// Deliver an event to all matching webhooks (fire-and-forget with retries).
    pub async fn deliver(&self, event: &SentinelEvent) {
        let hooks = self.hooks.read().await.clone();
        let event_type = event_type_name(event);

        for hook in hooks {
            if !hook.active {
                continue;
            }
            if !hook.event_filter.is_empty() && !hook.event_filter.contains(&event_type.to_string())
            {
                continue;
            }

            let client = self.client.clone();
            let event = event.clone();
            let hook = hook.clone();
            let dlq = self.dlq.clone();

            // Fire-and-forget with retry, failed deliveries go to DLQ
            tokio::spawn(async move {
                deliver_with_retry(&client, &hook, &event, 3, &dlq).await;
            });
        }
    }

    /// Retry a dead-letter entry. Returns the delivery result.
    pub async fn retry_dlq_entry(&self, entry_id: &str) -> Result<(), SentinelError> {
        let entry =
            self.dlq.take(entry_id).await.ok_or_else(|| {
                SentinelError::NotFound(format!("DLQ entry not found: {entry_id}"))
            })?;

        // Find the webhook config
        let hooks = self.hooks.read().await;
        let hook = hooks.iter().find(|h| h.id == entry.webhook_id).cloned();
        drop(hooks);

        let hook = hook.ok_or_else(|| {
            SentinelError::InvalidRequest(format!(
                "Webhook {} no longer registered",
                entry.webhook_id
            ))
        })?;

        // Re-serialize event from stored payload
        let payload = serde_json::to_vec(&entry.payload).unwrap_or_default();
        let signature = sign_payload(&hook.secret, &payload);

        let result = self
            .client
            .post(&hook.url)
            .header("Content-Type", "application/json")
            .header("X-Iaga-Sentinel-Signature", &signature)
            .header("X-Iaga-Sentinel-Event", &entry.event_type)
            .body(payload)
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => Ok(()),
            Ok(resp) => Err(SentinelError::Internal(format!(
                "Retry failed with status {}",
                resp.status()
            ))),
            Err(e) => Err(SentinelError::Internal(format!("Retry failed: {e}"))),
        }
    }
}

fn event_type_name(event: &SentinelEvent) -> &'static str {
    match event {
        SentinelEvent::ActionGoverned { .. } => "action_governed",
        SentinelEvent::ReviewCreated { .. } => "review_created",
        SentinelEvent::ReviewResolved { .. } => "review_resolved",
    }
}

fn sign_payload(secret: &str, payload: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(payload);
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

async fn deliver_with_retry(
    client: &reqwest::Client,
    hook: &WebhookConfig,
    event: &SentinelEvent,
    max_retries: u32,
    dlq: &DeadLetterQueue,
) {
    let payload = match serde_json::to_vec(event) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(webhook_id = %hook.id, error = %e, "Failed to serialize webhook payload");
            return;
        }
    };

    let signature = sign_payload(&hook.secret, &payload);
    let mut last_error = String::new();

    for attempt in 0..=max_retries {
        let result = client
            .post(&hook.url)
            .header("Content-Type", "application/json")
            .header("X-Iaga-Sentinel-Signature", &signature)
            .header("X-Iaga-Sentinel-Event", event_type_name(event))
            .body(payload.clone())
            .send()
            .await;

        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(
                    webhook_id = %hook.id,
                    status = %resp.status(),
                    "Webhook delivered"
                );
                return;
            }
            Ok(resp) => {
                last_error = format!("HTTP {}", resp.status());
                tracing::warn!(
                    webhook_id = %hook.id,
                    status = %resp.status(),
                    attempt = attempt + 1,
                    "Webhook delivery failed"
                );
            }
            Err(e) => {
                last_error = e.to_string();
                tracing::warn!(
                    webhook_id = %hook.id,
                    error = %e,
                    attempt = attempt + 1,
                    "Webhook delivery error"
                );
            }
        }

        if attempt < max_retries {
            let delay = std::time::Duration::from_secs(1 << attempt);
            tokio::time::sleep(delay).await;
        }
    }

    // All retries exhausted, send to dead letter queue
    let entry = DeadLetterEntry {
        id: uuid::Uuid::new_v4().to_string(),
        webhook_id: hook.id.clone(),
        webhook_url: hook.url.clone(),
        event_type: event_type_name(event).to_string(),
        payload: serde_json::to_value(event).unwrap_or_default(),
        error: last_error,
        attempts: max_retries + 1,
        failed_at: Utc::now().to_rfc3339(),
    };
    dlq.push(entry).await;

    tracing::error!(
        webhook_id = %hook.id,
        url = %hook.url,
        "Webhook delivery failed after all retries, added to DLQ"
    );
}

/// Stand-alone event bus → webhook bridge.
/// Spawns a background task that reads from the event bus and delivers to webhooks.
pub fn spawn_webhook_worker(bus: super::bus::EventBus, manager: Arc<WebhookManager>) {
    tokio::spawn(async move {
        let mut rx = bus.subscribe();
        loop {
            match rx.recv().await {
                Ok(event) => {
                    manager.deliver(&event).await;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "Webhook worker lagged behind event bus");
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    tracing::info!("Event bus closed, webhook worker stopping");
                    break;
                }
            }
        }
    });
}
