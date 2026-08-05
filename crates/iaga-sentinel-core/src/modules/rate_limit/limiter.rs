use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::core::types::RateLimitConfig;

/// Result of a rate limit check.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: u32,
    pub reset_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u32>,
}

/// Per-key status snapshot for the status endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitStatus {
    pub agent_id: String,
    pub requests_last_minute: u32,
    pub requests_last_hour: u32,
    pub requests_last_5_seconds: u32,
    pub config: RateLimitConfig,
}

/// Is `t` inside the window of length `window` ending at `now`?
///
/// `Instant`'s epoch is implementation-defined — on Windows it is system boot.
/// When `now` is closer to that epoch than `window`, `checked_sub` returns
/// `None` because the window start is not representable. The window still
/// reaches further back than any instant that can exist, so it contains
/// EVERY recorded timestamp.
///
/// This used to be spelled `now.checked_sub(w).unwrap_or(now)` at all five call
/// sites, which reads as "the window starts now" and therefore excluded every
/// prior timestamp instead of including it. Consequences, all measured on this
/// build with host uptime under one hour: `check_rate` pruned each key's vector
/// to empty on every call, so all three counters read zero and the limiter
/// allowed everything (80/80 calls at a configured 60/min, 5/5 at 1/min);
/// `cleanup` dropped every window it touched; `status` reported zero traffic.
/// Above one hour of uptime the same binary rate-limits correctly (70/80
/// refused), which is why the three rate-limiter tests in the suite looked
/// flaky rather than failing.
fn within_window(now: Instant, window: Duration, t: Instant) -> bool {
    match now.checked_sub(window) {
        Some(cutoff) => t >= cutoff,
        None => true,
    }
}

const HOUR: Duration = Duration::from_secs(3600);
const MINUTE: Duration = Duration::from_secs(60);
const BURST: Duration = Duration::from_secs(5);

/// Sliding-window rate limiter backed by in-memory timestamp vectors.
pub struct RateLimiter {
    /// Map from key (agent_id or agent_id:tool_name) to sorted timestamps.
    windows: RwLock<HashMap<String, Vec<Instant>>>,
    config: RwLock<RateLimitConfig>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            windows: RwLock::new(HashMap::new()),
            config: RwLock::new(config),
        }
    }

    /// Build the key used for rate-limit tracking.
    fn make_key(agent_id: &str, tool_name: Option<&str>) -> String {
        match tool_name {
            Some(t) => format!("{}:{}", agent_id, t),
            None => agent_id.to_string(),
        }
    }

    /// Check whether a request is allowed and, if so, record it.
    pub async fn check_rate(&self, agent_id: &str, tool_name: Option<&str>) -> RateLimitResult {
        let config = self.config.read().await.clone();
        let key = Self::make_key(agent_id, tool_name);
        let now = Instant::now();

        let mut windows = self.windows.write().await;
        let timestamps = windows.entry(key).or_insert_with(Vec::new);

        // Prune entries older than 1 hour (the largest window we care about).
        timestamps.retain(|t| within_window(now, HOUR, *t));

        let count_minute = timestamps
            .iter()
            .filter(|t| within_window(now, MINUTE, **t))
            .count() as u32;
        let count_hour = timestamps.len() as u32;
        let count_burst = timestamps
            .iter()
            .filter(|t| within_window(now, BURST, **t))
            .count() as u32;

        // Determine which limit is hit (if any) and calculate retry_after.
        let (allowed, retry_after_secs) = if count_burst >= config.burst_limit {
            // Burst limit: retry after the oldest burst-window entry expires.
            let oldest_burst = timestamps
                .iter()
                .filter(|t| within_window(now, BURST, **t))
                .min()
                .copied()
                .unwrap_or(now);
            let wait = Duration::from_secs(5)
                .checked_sub(now.duration_since(oldest_burst))
                .unwrap_or(Duration::from_secs(1));
            (false, Some(wait.as_secs() as u32 + 1))
        } else if count_minute >= config.max_per_minute {
            let oldest_minute = timestamps
                .iter()
                .filter(|t| within_window(now, MINUTE, **t))
                .min()
                .copied()
                .unwrap_or(now);
            let wait = Duration::from_secs(60)
                .checked_sub(now.duration_since(oldest_minute))
                .unwrap_or(Duration::from_secs(1));
            (false, Some(wait.as_secs() as u32 + 1))
        } else if count_hour >= config.max_per_hour {
            let oldest_hour = timestamps.iter().min().copied().unwrap_or(now);
            let wait = Duration::from_secs(3600)
                .checked_sub(now.duration_since(oldest_hour))
                .unwrap_or(Duration::from_secs(1));
            (false, Some(wait.as_secs() as u32 + 1))
        } else {
            (true, None)
        };

        if allowed {
            timestamps.push(now);
        }

        let remaining = config.max_per_minute.saturating_sub(if allowed {
            count_minute + 1
        } else {
            count_minute
        });

        let reset_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + 60; // next minute-window reset

        RateLimitResult {
            allowed,
            remaining,
            reset_at,
            retry_after_secs,
        }
    }

    /// Does `key` belong to `agent_id`? Either the bare agent key, or one of its
    /// `agent_id:tool_name` keys.
    ///
    /// The `:` is not ambiguous here even though a tool name may contain one:
    /// the prefix is anchored at the start and the agent id is matched whole, so
    /// `a:b` never matches agent `a:b`'s sibling agent `a` — only `a`'s own
    /// tools.
    fn key_belongs_to(key: &str, agent_id: &str) -> bool {
        key == agent_id
            || (key.len() > agent_id.len()
                && key.starts_with(agent_id)
                && key.as_bytes()[agent_id.len()] == b':')
    }

    /// Return current rate-limit status for an agent (read-only, does not record).
    ///
    /// The counts are the **maximum** over the agent's per-tool windows, not the
    /// sum, because the limit is enforced per `agent_id:tool_name` key and the
    /// same struct carries the config those numbers will be read against. The
    /// max is the one that answers "is this agent about to be refused"; a sum
    /// could sit above `max_per_minute` with nothing being refused anywhere.
    ///
    /// This used to look up the bare `agent_id` key, which `check_rate` never
    /// writes: the pipeline always passes `Some(tool_name)`, so every recorded
    /// request lands under `agent_id:tool_name`. The endpoint therefore reported
    /// **zero traffic for every agent, forever**, no matter the load — measured
    /// live on 2.0.1: 12 governed calls, `requestsLastMinute: 0`, while the very
    /// next call was refused with "Rate limit exceeded". A status endpoint that
    /// always reports zero is worse than no status endpoint, because it reads as
    /// evidence that the limiter is idle.
    pub async fn status(&self, agent_id: &str) -> RateLimitStatus {
        let config = self.config.read().await.clone();
        let now = Instant::now();

        let windows = self.windows.read().await;

        let (mut req_minute, mut req_hour, mut req_burst) = (0u32, 0u32, 0u32);
        for (key, timestamps) in windows.iter() {
            if !Self::key_belongs_to(key, agent_id) {
                continue;
            }
            let count = |w: Duration| {
                timestamps
                    .iter()
                    .filter(|t| within_window(now, w, **t))
                    .count() as u32
            };
            req_minute = req_minute.max(count(MINUTE));
            req_hour = req_hour.max(count(HOUR));
            req_burst = req_burst.max(count(BURST));
        }

        RateLimitStatus {
            agent_id: agent_id.to_string(),
            requests_last_minute: req_minute,
            requests_last_hour: req_hour,
            requests_last_5_seconds: req_burst,
            config,
        }
    }

    /// Get the current config.
    pub async fn get_config(&self) -> RateLimitConfig {
        self.config.read().await.clone()
    }

    /// Update the config at runtime.
    pub async fn update_config(&self, new_config: RateLimitConfig) {
        let mut cfg = self.config.write().await;
        *cfg = new_config;
    }

    /// Prune all entries older than 1 hour to free memory.
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut windows = self.windows.write().await;

        windows.retain(|_key, timestamps| {
            timestamps.retain(|t| within_window(now, HOUR, *t));
            !timestamps.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The regression that let the limiter allow everything for the first hour
    /// of host uptime.
    ///
    /// It cannot be reproduced by calling `check_rate` on a normal machine,
    /// because whether `Instant::now()` is within an hour of its epoch is a
    /// property of the host, not of the test — which is exactly why the three
    /// end-to-end rate-limiter tests read as flaky for so long. So this drives
    /// the same branch from the other side: a window longer than any uptime
    /// makes `checked_sub` return `None` on every machine, at every uptime.
    ///
    /// The window in that case reaches back past the epoch, so it contains
    /// every instant that exists and the answer must be `true`. The old
    /// `unwrap_or(now)` answered `false`, which emptied every window.
    #[test]
    fn a_window_reaching_past_the_epoch_contains_every_timestamp() {
        let now = Instant::now();
        // Strictly before `now`, and by a margin the platform clock cannot
        // collapse: two consecutive `Instant::now()` calls compare EQUAL on
        // Windows, which made the first version of this test pass against the
        // very semantics it exists to reject.
        let earlier = now - Duration::from_secs(1);
        let unrepresentable = Duration::from_secs(u64::MAX / 2);

        assert!(
            now.checked_sub(unrepresentable).is_none(),
            "precondition: this window must be unrepresentable for the test to \
             exercise the None branch"
        );
        assert!(
            within_window(now, unrepresentable, earlier),
            "a window that starts before the epoch must contain a timestamp \
             recorded before now; returning false here disables the limiter"
        );
    }

    /// The ordinary branch still discriminates, so the fix above did not turn
    /// the limiter into an accept-all.
    #[test]
    fn a_representable_window_still_excludes_what_falls_outside_it() {
        let now = Instant::now();
        assert!(
            within_window(now, Duration::from_secs(60), now),
            "now is inside a window ending at now"
        );
        // A window of zero length ending at `now` excludes anything strictly
        // before `now`, which is the discriminating case.
        let earlier = now - Duration::from_nanos(1);
        assert!(
            !within_window(now, Duration::ZERO, earlier),
            "a timestamp older than the cutoff must fall outside the window"
        );
    }

    /// `cleanup` bounds the `windows` map by dropping keys whose entries have
    /// all aged out. It must not drop keys that are still inside their window:
    /// a cleanup that forgets live traffic hands the caller a fresh budget and
    /// disables the limiter just as effectively as never counting at all.
    ///
    /// The complementary direction — a key whose entries have all expired is
    /// removed — is not asserted here because it would mean sleeping an hour.
    /// It is covered by `within_window`'s own tests, which pin the predicate
    /// `cleanup` shares with `check_rate`.
    #[tokio::test]
    async fn cleanup_does_not_drop_live_windows() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_minute: 100,
            max_per_hour: 1000,
            burst_limit: 2,
        });
        assert!(limiter.check_rate("a", Some("t")).await.allowed);
        assert!(limiter.check_rate("a", Some("t")).await.allowed);
        assert!(
            !limiter.check_rate("a", Some("t")).await.allowed,
            "precondition: the burst limit must be exhausted before cleanup runs"
        );

        limiter.cleanup().await;

        assert!(
            !limiter.check_rate("a", Some("t")).await.allowed,
            "cleanup dropped a window seconds old against a one-hour TTL: the \
             limiter forgot a burst it had just refused"
        );
    }

    /// `status` must see the traffic `check_rate` recorded.
    ///
    /// It used to read the bare `agent_id` key while `check_rate` writes
    /// `agent_id:tool_name`, and the pipeline always supplies a tool name — so
    /// the status endpoint reported zero for every agent under any load. The
    /// assertion below is the one that fails against that version.
    #[tokio::test]
    async fn status_reports_the_traffic_that_was_actually_recorded() {
        let limiter = RateLimiter::new(RateLimitConfig {
            max_per_minute: 100,
            max_per_hour: 1000,
            burst_limit: 100,
        });
        for _ in 0..3 {
            assert!(limiter.check_rate("agent-a", Some("tool-x")).await.allowed);
        }
        // A second tool for the same agent, with MORE traffic: the reported
        // number is the max across the agent's per-tool windows, because that is
        // the one comparable to the `config` shipped in the same struct.
        for _ in 0..5 {
            assert!(limiter.check_rate("agent-a", Some("tool-y")).await.allowed);
        }
        // A different agent must not leak into the answer.
        assert!(limiter.check_rate("agent-b", Some("tool-x")).await.allowed);

        let s = limiter.status("agent-a").await;
        assert_eq!(
            s.requests_last_minute, 5,
            "status must report the busiest of the agent's per-tool windows; 0 \
             here means it is reading a key nothing ever writes"
        );
        assert_eq!(s.requests_last_hour, 5);

        let other = limiter.status("agent-b").await;
        assert_eq!(
            other.requests_last_minute, 1,
            "another agent's traffic must not be counted"
        );

        // A prefix that is not a key boundary must not match: `agent-a` and
        // `agent-ab` are different agents, not an agent and its tool.
        assert!(limiter.check_rate("agent-ab", Some("t")).await.allowed);
        assert_eq!(
            limiter.status("agent-a").await.requests_last_minute,
            5,
            "`agent-ab` is a different agent, not a tool of `agent-a`"
        );
    }
}
