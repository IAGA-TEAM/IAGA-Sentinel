//! LAYER 3, Non-Human Identity (NHI)
//!
//! Per-agent identity built on a **symmetric HMAC-SHA256 key commitment**,
//! capability tokens with expiry, and challenge-response attestation.
//!
//! **Honest scope (CRYPTO-NHI-2).** This is *not* an asymmetric PKI and the
//! `spiffe_id` is a stable name, not a verifiable SPIFFE SVID. Each agent's
//! secret is derived from a process master seed; `key_commitment` is
//! `HMAC(secret, …)` — a value a holder of the secret can recompute, **not** a
//! public key a relying party can verify on its own. Verification therefore
//! requires the secret, so only the server (which holds every secret) can
//! verify. Verifiable, relying-party-checkable asymmetric agent identity
//! (Ed25519 / EUDI-wallet-bound credentials, roadmap 4.0) is part of IAGA
//! Sentinel Enterprise, not this open build (ADR 0010).
//!
//! **Attestation.** Challenge-response: the server issues a time-limited nonce,
//! the agent authenticates it with its derived HMAC key, and the server
//! verifies. A simulated mode is preserved for backwards compatibility.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::Utc;
use hmac::{Hmac, Mac};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// ── Types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentity {
    pub agent_id: String,
    pub spiffe_id: String,
    /// Symmetric HMAC key commitment, `HMAC(secret, "public-key-derivation")`.
    /// **Not** an asymmetric public key — verifying a signature against it still
    /// requires the secret (CRYPTO-NHI-2). Accepts the old `publicKeyHex` JSON
    /// key on input for back-compat.
    #[serde(alias = "publicKeyHex")]
    pub key_commitment: String,
    pub created_at: String,
    pub attestation_status: String,
    pub trust_score: f64,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone)]
struct StoredIdentity {
    pub identity: AgentIdentity,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityToken {
    pub token_id: String,
    pub agent_id: String,
    pub capabilities: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub signature: String,
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationResult {
    pub agent_id: String,
    pub verified: bool,
    pub spiffe_id: String,
    pub trust_score: f64,
    pub reason: String,
    /// "simulated" (v0.1 compat) or "verified" (real challenge-response)
    pub mode: String,
}

// ── Challenge-Response Types ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingChallenge {
    pub challenge_id: String,
    pub agent_id: String,
    pub nonce: String,
    pub expires_at: String,
}

struct StoredChallenge {
    challenge: PendingChallenge,
    created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MutualAttestationResult {
    pub initiator: AttestationResult,
    pub responder: AttestationResult,
    pub mutual_trust: f64,
    pub session_token: Option<String>,
}

// ── Store ──

static IDENTITIES: Lazy<Mutex<HashMap<String, StoredIdentity>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static TOKENS: Lazy<Mutex<HashMap<String, CapabilityToken>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static CHALLENGES: Lazy<Mutex<HashMap<String, StoredChallenge>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// ── Key Derivation ──

/// Process-wide NHI master seed, resolved exactly ONCE (DET-NHI-4).
///
/// Previously `get_master_seed` regenerated a fresh random seed on *every* call
/// when the env was unset, so an agent's derived secret/token (and the trust
/// that feeds the signed risk score) silently changed between two
/// `register_identity` calls in the same process. Memoizing it gives a stable
/// seed for the process lifetime — still ephemeral across restarts unless the
/// env is set, which we warn about.
static MASTER_SEED: Lazy<Vec<u8>> =
    Lazy::new(|| match std::env::var("IAGA_SENTINEL_NHI_MASTER_SEED") {
        Ok(s) => {
            let bytes = s.into_bytes();
            // ERG-NHI-SEED-VALIDATION-1: a short seed is weak key material.
            // Warn (rather than hard-fail, to keep OSS dev ergonomics) so the
            // operator knows to supply >= 32 bytes of high-entropy material.
            if bytes.len() < 16 {
                tracing::warn!(
                    len = bytes.len(),
                    "IAGA_SENTINEL_NHI_MASTER_SEED is shorter than 16 bytes; \
                     use at least 32 bytes of high-entropy material"
                );
            }
            bytes
        }
        Err(_) => {
            tracing::warn!(
                "IAGA_SENTINEL_NHI_MASTER_SEED not set; using a random ephemeral seed for this \
                 process. Identities will not persist across restarts — set the env var for \
                 stable identities."
            );
            use rand::RngCore;
            let mut seed = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed);
            seed.to_vec()
        }
    });

fn get_master_seed() -> &'static [u8] {
    &MASTER_SEED
}

fn derive_keypair(agent_id: &str) -> (Vec<u8>, String) {
    // Derive deterministic secret from agent_id + the process master seed.
    let master_seed = get_master_seed();
    let mut mac = HmacSha256::new_from_slice(master_seed).expect("HMAC accepts any key size");
    mac.update(agent_id.as_bytes());
    let secret = mac.finalize().into_bytes().to_vec();

    // Key commitment = HMAC(secret, …). NOT a public key: it is a symmetric
    // digest of the secret, verifiable only by a holder of the secret
    // (CRYPTO-NHI-2). The constant string is kept for wire/format stability.
    let mut pub_mac = HmacSha256::new_from_slice(&secret).expect("HMAC accepts any key size");
    pub_mac.update(b"public-key-derivation");
    let public = pub_mac.finalize().into_bytes();
    let pub_hex = hex::encode(public);

    (secret, pub_hex)
}

fn sign(secret: &[u8], message: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

pub fn verify_signature(secret: &[u8], message: &str, signature: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(message.as_bytes());
    // Decode the hex signature and verify with constant-time comparison
    match hex::decode(signature) {
        Ok(sig_bytes) => mac.verify_slice(&sig_bytes).is_ok(),
        Err(_) => false,
    }
}

// ── SPIFFE ID ──

fn build_spiffe_id(agent_id: &str, workspace_id: Option<&str>) -> String {
    let ws = workspace_id.unwrap_or("default");
    format!("spiffe://iaga-sentinel/{}/agent/{}", ws, agent_id)
}

// ── Identity Management ──

pub fn register_identity(
    agent_id: &str,
    workspace_id: Option<&str>,
    capabilities: Vec<String>,
) -> AgentIdentity {
    let (secret, pub_hex) = derive_keypair(agent_id);
    let spiffe_id = build_spiffe_id(agent_id, workspace_id);

    let identity = AgentIdentity {
        agent_id: agent_id.to_string(),
        spiffe_id,
        key_commitment: pub_hex,
        created_at: Utc::now().to_rfc3339(),
        attestation_status: "registered".into(),
        trust_score: 0.5,
        capabilities: capabilities.clone(),
    };

    let stored = StoredIdentity {
        identity: identity.clone(),
        secret_key: secret,
    };

    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(agent_id.to_string(), stored);
    identity
}

pub fn get_identity(agent_id: &str) -> Option<AgentIdentity> {
    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(agent_id)
        .map(|s| s.identity.clone())
}

/// Get the hex-encoded secret key for an agent (used for durable persistence).
pub fn get_secret_key_hex(agent_id: &str) -> Option<String> {
    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(agent_id)
        .map(|s| hex::encode(&s.secret_key))
}

/// Hydrate an identity into the in-memory store (used on startup to load from DB).
pub fn hydrate_identity(identity: AgentIdentity, secret_key_hex: &str) {
    let secret_key = hex::decode(secret_key_hex).unwrap_or_default();
    let stored = StoredIdentity {
        identity: identity.clone(),
        secret_key,
    };
    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(identity.agent_id.clone(), stored);
}

pub fn list_identities() -> Vec<AgentIdentity> {
    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .map(|s| s.identity.clone())
        .collect()
}

// ── Attestation ──

/// Attest an agent via simulated challenge-response (v0.1 backwards compatibility).
///
/// For real attestation, use `create_challenge()` + `verify_attestation()`.
pub fn attest_agent(agent_id: &str, _challenge: &str) -> AttestationResult {
    let store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(stored) = store.get(agent_id) {
        // CRYPTO-NHI-1: the previous implementation signed the challenge with the
        // stored secret and then verified that very signature with the same
        // secret, so `verified` was ALWAYS true for any registered agent — the
        // caller proved nothing (no proof-of-possession). That false positive fed
        // `mutual_attest`, which then minted an HMAC `session_token` for anyone who
        // could merely name two registered agent ids. Simulated attestation is
        // non-authoritative by construction: it confirms the identity is
        // registered but MUST NOT claim verification. Real verification requires
        // the challenge-response flow (`create_challenge` + `verify_attestation`).
        AttestationResult {
            agent_id: agent_id.to_string(),
            verified: false,
            spiffe_id: stored.identity.spiffe_id.clone(),
            trust_score: stored.identity.trust_score,
            reason: "agent is registered but simulated attestation proves no key \
                     possession; use POST /v1/nhi/challenge then /v1/nhi/verify for \
                     real challenge-response verification"
                .into(),
            mode: "simulated".into(),
        }
    } else {
        AttestationResult {
            agent_id: agent_id.to_string(),
            verified: false,
            spiffe_id: String::new(),
            trust_score: 0.0,
            reason: "unknown agent, no identity registered".into(),
            mode: "simulated".into(),
        }
    }
}

// ── Real Challenge-Response Attestation (v0.2) ──

/// Create a time-limited challenge for an agent to sign.
/// Returns None if the agent is not registered.
pub fn create_challenge(agent_id: &str) -> Option<PendingChallenge> {
    let store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    if !store.contains_key(agent_id) {
        return None;
    }
    drop(store);

    let challenge_id = Uuid::new_v4().to_string();
    let nonce = Uuid::new_v4().to_string();
    let expires = Utc::now() + chrono::Duration::seconds(60);

    let challenge = PendingChallenge {
        challenge_id: challenge_id.clone(),
        agent_id: agent_id.to_string(),
        nonce: nonce.clone(),
        expires_at: expires.to_rfc3339(),
    };

    let stored = StoredChallenge {
        challenge: challenge.clone(),
        created_at: Utc::now().timestamp(),
    };

    CHALLENGES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(challenge_id, stored);

    Some(challenge)
}

/// Verify an agent's signature against a previously issued challenge.
///
/// The agent must sign the nonce with its HMAC-SHA256 derived key and
/// return the hex-encoded signature.
pub fn verify_attestation(
    agent_id: &str,
    challenge_id: &str,
    signature: &str,
) -> AttestationResult {
    // CRYPTO-NHI-3: hold the CHALLENGES lock across the whole check → verify →
    // consume so the challenge is single-use even under concurrent requests.
    // Peeking then releasing the lock (as before) let two threads both observe a
    // still-present challenge and each return `verified` — a replay within the
    // race window. The challenge is still consumed ONLY on a successful
    // verification, so a wrong agent/signature cannot burn a legitimate agent's
    // pending challenge (denial-of-attestation). Expired ones are reaped by
    // `prune_expired_challenges`.
    let mut challenges = CHALLENGES.lock().unwrap_or_else(|e| e.into_inner());
    let (owner, expires_at, nonce) = match challenges.get(challenge_id) {
        Some(sc) => (
            sc.challenge.agent_id.clone(),
            sc.challenge.expires_at.clone(),
            sc.challenge.nonce.clone(),
        ),
        None => {
            return AttestationResult {
                agent_id: agent_id.to_string(),
                verified: false,
                spiffe_id: String::new(),
                trust_score: 0.0,
                reason: "challenge not found or already consumed".into(),
                mode: "verified".into(),
            };
        }
    };

    // Check challenge belongs to this agent
    if owner != agent_id {
        return AttestationResult {
            agent_id: agent_id.to_string(),
            verified: false,
            spiffe_id: String::new(),
            trust_score: 0.0,
            reason: "challenge was issued for a different agent".into(),
            mode: "verified".into(),
        };
    }

    // Check expiry
    if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&expires_at) {
        if Utc::now() > expires {
            return AttestationResult {
                agent_id: agent_id.to_string(),
                verified: false,
                spiffe_id: String::new(),
                trust_score: 0.0,
                reason: "challenge expired".into(),
                mode: "verified".into(),
            };
        }
    }

    // Verify signature. IDENTITIES is locked *after* CHALLENGES; no other path
    // holds IDENTITIES while acquiring CHALLENGES, so this ordering can't deadlock.
    let identities = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    match identities.get(agent_id) {
        Some(stored) => {
            let verified = verify_signature(&stored.secret_key, &nonce, signature);
            let spiffe_id = stored.identity.spiffe_id.clone();
            let trust_score = stored.identity.trust_score;
            drop(identities);
            if verified {
                // Consume the challenge only now that it was used successfully,
                // still under the CHALLENGES lock held above → single-use, race-free.
                challenges.remove(challenge_id);
            }
            AttestationResult {
                agent_id: agent_id.to_string(),
                verified,
                spiffe_id,
                trust_score,
                reason: if verified {
                    "challenge-response verified successfully".into()
                } else {
                    "signature verification failed".into()
                },
                mode: "verified".into(),
            }
        }
        None => AttestationResult {
            agent_id: agent_id.to_string(),
            verified: false,
            spiffe_id: String::new(),
            trust_score: 0.0,
            reason: "unknown agent, no identity registered".into(),
            mode: "verified".into(),
        },
    }
}

/// Prune expired challenges. Returns the number of pruned entries.
pub fn prune_expired_challenges() -> usize {
    let now = Utc::now().timestamp();
    let mut challenges = CHALLENGES.lock().unwrap_or_else(|e| e.into_inner());
    let before = challenges.len();
    challenges.retain(|_, sc| now - sc.created_at < 60);
    before - challenges.len()
}

/// Get the secret key for an agent (for SDK use in test/dev).
/// Returns the hex-encoded HMAC key that the agent should use to sign challenges.
pub fn get_agent_secret_hex(agent_id: &str) -> Option<String> {
    let store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    store.get(agent_id).map(|s| hex::encode(&s.secret_key))
}

/// Mutual attestation over the simulated path. CRYPTO-NHI-1: because
/// `attest_agent` is non-authoritative (never returns `verified = true`), this
/// never establishes `mutual_trust` and never mints a `session_token` — closing
/// the bug where naming two registered agent ids yielded a valid HMAC token with
/// no proof of possession. Genuine mutual attestation must run the
/// challenge-response flow (`create_challenge` + `verify_attestation`) for each
/// party; that managed orchestration is intentionally left as an Enterprise
/// concern and is out of scope for this OSS helper.
pub fn mutual_attest(initiator_id: &str, responder_id: &str) -> MutualAttestationResult {
    let challenge = Uuid::new_v4().to_string();
    let init_result = attest_agent(initiator_id, &challenge);
    let resp_result = attest_agent(responder_id, &challenge);

    let mutual_trust = if init_result.verified && resp_result.verified {
        (init_result.trust_score + resp_result.trust_score) / 2.0
    } else {
        0.0
    };

    let session_token = if init_result.verified && resp_result.verified {
        let store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(init_stored) = store.get(initiator_id) {
            let token_data = format!("{}:{}:{}", initiator_id, responder_id, challenge);
            Some(sign(&init_stored.secret_key, &token_data))
        } else {
            None
        }
    } else {
        None
    };

    MutualAttestationResult {
        initiator: init_result,
        responder: resp_result,
        mutual_trust,
        session_token,
    }
}

// ── Capability Tokens ──

pub fn issue_capability_token(
    agent_id: &str,
    capabilities: Vec<String>,
    ttl_seconds: i64,
) -> Option<CapabilityToken> {
    let store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    let stored = store.get(agent_id)?;

    let now = Utc::now();
    let expires = now + chrono::Duration::seconds(ttl_seconds);
    let token_id = Uuid::new_v4().to_string();

    let payload = format!(
        "{}:{}:{}:{}",
        token_id,
        agent_id,
        capabilities.join(","),
        expires.to_rfc3339()
    );
    let signature = sign(&stored.secret_key, &payload);

    let token = CapabilityToken {
        token_id: token_id.clone(),
        agent_id: agent_id.to_string(),
        capabilities,
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        signature,
        valid: true,
    };

    drop(store);
    TOKENS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(token_id, token.clone());
    Some(token)
}

pub fn verify_capability_token(token_id: &str, required_capability: &str) -> bool {
    let tokens = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(token) = tokens.get(token_id) {
        if !token.valid {
            return false;
        }
        // Check expiry
        if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&token.expires_at) {
            if Utc::now() > expires {
                return false;
            }
        }
        // Check capability
        token
            .capabilities
            .contains(&required_capability.to_string())
            || token.capabilities.contains(&"*".to_string())
    } else {
        false
    }
}

pub fn revoke_token(token_id: &str) -> bool {
    let mut tokens = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(token) = tokens.get_mut(token_id) {
        token.valid = false;
        true
    } else {
        false
    }
}

// ── Trust Score Updates ──

/// Update trust score with a severity-aware delta.
///
/// Use `update_trust_from_decision` for the standard pipeline path.
/// This raw function is kept for direct callers.
pub fn update_trust_score(agent_id: &str, delta: f64) -> Option<f64> {
    let mut store = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(stored) = store.get_mut(agent_id) {
        stored.identity.trust_score = (stored.identity.trust_score + delta).clamp(0.0, 1.0);
        Some(stored.identity.trust_score)
    } else {
        None
    }
}

/// Severity-aware trust update based on the actual risk score.
///
/// - ALLOW:  +0.02 (was +0.01, faster recovery)
/// - BLOCK with risk < 50 (policy violation, not malicious): -0.01
/// - BLOCK with risk 50-79 (suspicious): -0.03
/// - BLOCK with risk >= 80 (clearly malicious): -0.05
/// - REVIEW: -0.005 (slight penalty, pending human judgment)
///
/// This replaces the old flat -0.05/-0.01 system that made trust
/// unrecoverable after any burst of blocks.
pub fn update_trust_from_decision(agent_id: &str, decision: &str, risk_score: u32) -> Option<f64> {
    let delta = match decision {
        "allow" => 0.02,
        "review" => -0.005,
        "block" => {
            if risk_score >= 80 {
                -0.05
            } else if risk_score >= 50 {
                -0.03
            } else {
                -0.01
            }
        }
        _ => 0.0,
    };
    update_trust_score(agent_id, delta)
}

/// Get the trust score for use in the adaptive risk scorer
pub fn get_agent_trust(agent_id: &str) -> f64 {
    IDENTITIES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(agent_id)
        .map(|s| s.identity.trust_score)
        .unwrap_or(0.5)
}

/// Clear all process-global identity state (identities, tokens, challenges).
/// The reputation signal reads `get_agent_trust`, which this resets to the
/// default for every agent. Exposed so deterministic tests can reset the
/// shared maps between runs; also useful for operational resets.
pub fn reset_state() {
    IDENTITIES.lock().unwrap_or_else(|e| e.into_inner()).clear();
    TOKENS.lock().unwrap_or_else(|e| e.into_inner()).clear();
    CHALLENGES.lock().unwrap_or_else(|e| e.into_inner()).clear();
}
