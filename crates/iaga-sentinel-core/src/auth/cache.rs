//! In-memory cache for verified API keys (1.5.2).
//!
//! Before this cache, every authenticated request paid one `list_keys()`
//! round-trip plus an Argon2id verification — tens of milliseconds added to
//! the `/v1/inspect` hot path by design of the hash. The cache remembers the
//! SHA-256 of raw keys that already verified (never the raw key itself) for a
//! short TTL, so steady-state traffic authenticates with one in-memory hash
//! lookup.
//!
//! Lives in `AppState` (per server instance, not process-global): each test
//! server gets an isolated cache and there is no cross-instance state to
//! reset. Mutating handlers (key create/delete) invalidate it in-process;
//! out-of-process key creation is still picked up immediately because the
//! middleware always falls back to a real verification on cache miss. The
//! only staleness window is open-mode → first-key (the cached `keys_exist`
//! flag, ≤ TTL).
//!
//! `IAGA_SENTINEL_AUTH_CACHE_TTL_MS` tunes the TTL (default 60_000); `0`
//! disables caching entirely and restores the pre-1.5.2 verify-every-request
//! behavior.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::storage::traits::KeyScope;

const MAX_ENTRIES: usize = 1024;

#[derive(Clone)]
struct CachedKey {
    key_id: Option<String>,
    scope: KeyScope,
    agent_id: Option<String>,
    inserted_at: Instant,
}

pub struct AuthCache {
    entries: RwLock<HashMap<[u8; 32], CachedKey>>,
    /// Cached outcome of "are any API keys configured at all?" with the
    /// instant it was observed. `None` = not known / expired.
    keys_exist: RwLock<Option<(bool, Instant)>>,
    ttl: Duration,
}

impl AuthCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            keys_exist: RwLock::new(None),
            ttl,
        }
    }

    /// TTL from `IAGA_SENTINEL_AUTH_CACHE_TTL_MS` (default 60s, `0` disables).
    pub fn from_env() -> Self {
        let ttl_ms = crate::config::env::env_parse("IAGA_SENTINEL_AUTH_CACHE_TTL_MS", 60_000u64);
        Self::new(Duration::from_millis(ttl_ms))
    }

    fn enabled(&self) -> bool {
        !self.ttl.is_zero()
    }

    fn hash(raw_key: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(raw_key.as_bytes());
        let out = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        arr
    }

    /// Returns the cached identity/scope for a raw key that previously
    /// verified, or `None` (caller falls back to a real verification).
    pub fn lookup(&self, raw_key: &str) -> Option<(Option<String>, KeyScope, Option<String>)> {
        if !self.enabled() {
            return None;
        }
        let entries = self.entries.read().unwrap_or_else(|e| e.into_inner());
        let entry = entries.get(&Self::hash(raw_key))?;
        if entry.inserted_at.elapsed() > self.ttl {
            return None;
        }
        Some((entry.key_id.clone(), entry.scope, entry.agent_id.clone()))
    }

    /// Remembers a successfully verified key. Evicts the oldest entry at cap.
    pub fn insert(
        &self,
        raw_key: &str,
        key_id: Option<String>,
        scope: KeyScope,
        agent_id: Option<String>,
    ) {
        if !self.enabled() {
            return;
        }
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        if entries.len() >= MAX_ENTRIES {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, v)| v.inserted_at)
                .map(|(k, _)| *k)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(
            Self::hash(raw_key),
            CachedKey {
                key_id,
                scope,
                agent_id,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Drops the entry for a raw key (e.g. after it failed verification).
    pub fn remove(&self, raw_key: &str) {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        entries.remove(&Self::hash(raw_key));
    }

    /// Drops every cached entry that maps to `key_id` (key deletion must take
    /// effect immediately, not after the TTL).
    pub fn invalidate_key_id(&self, key_id: &str) {
        let mut entries = self.entries.write().unwrap_or_else(|e| e.into_inner());
        entries.retain(|_, v| v.key_id.as_deref() != Some(key_id));
    }

    /// Drops everything, including the `keys_exist` flag.
    pub fn clear(&self) {
        self.entries
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        *self.keys_exist.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Cached "any keys configured?" flag, `None` when unknown or expired.
    pub fn keys_exist(&self) -> Option<bool> {
        if !self.enabled() {
            return None;
        }
        let flag = self.keys_exist.read().unwrap_or_else(|e| e.into_inner());
        match *flag {
            Some((value, at)) if at.elapsed() <= self.ttl => Some(value),
            _ => None,
        }
    }

    pub fn set_keys_exist(&self, value: bool) {
        if !self.enabled() {
            return;
        }
        *self.keys_exist.write().unwrap_or_else(|e| e.into_inner()) = Some((value, Instant::now()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_roundtrip_and_invalidation() {
        let cache = AuthCache::new(Duration::from_secs(60));
        assert!(cache.lookup("iaga_abc").is_none());

        cache.insert(
            "iaga_abc",
            Some("key-1".into()),
            KeyScope::Agent,
            Some("agent-1".into()),
        );
        let (id, scope, agent_id) = cache.lookup("iaga_abc").expect("cached");
        assert_eq!(id.as_deref(), Some("key-1"));
        assert_eq!(scope, KeyScope::Agent);
        assert_eq!(agent_id.as_deref(), Some("agent-1"));

        cache.invalidate_key_id("key-1");
        assert!(cache.lookup("iaga_abc").is_none());
    }

    #[test]
    fn remove_drops_single_entry() {
        let cache = AuthCache::new(Duration::from_secs(60));
        cache.insert("iaga_a", None, KeyScope::Admin, None);
        cache.insert("iaga_b", None, KeyScope::Admin, None);
        cache.remove("iaga_a");
        assert!(cache.lookup("iaga_a").is_none());
        assert!(cache.lookup("iaga_b").is_some());
    }

    #[test]
    fn zero_ttl_disables_everything() {
        let cache = AuthCache::new(Duration::ZERO);
        cache.insert("iaga_abc", Some("key-1".into()), KeyScope::Admin, None);
        assert!(cache.lookup("iaga_abc").is_none());
        cache.set_keys_exist(true);
        assert!(cache.keys_exist().is_none());
    }

    #[test]
    fn keys_exist_flag_roundtrip_and_clear() {
        let cache = AuthCache::new(Duration::from_secs(60));
        assert_eq!(cache.keys_exist(), None);
        cache.set_keys_exist(false);
        assert_eq!(cache.keys_exist(), Some(false));
        cache.set_keys_exist(true);
        assert_eq!(cache.keys_exist(), Some(true));
        cache.clear();
        assert_eq!(cache.keys_exist(), None);
    }

    #[test]
    fn cap_evicts_oldest_entry() {
        let cache = AuthCache::new(Duration::from_secs(60));
        for i in 0..MAX_ENTRIES + 1 {
            cache.insert(&format!("iaga_{i}"), None, KeyScope::Admin, None);
        }
        let entries = cache.entries.read().unwrap();
        assert!(entries.len() <= MAX_ENTRIES);
    }
}
