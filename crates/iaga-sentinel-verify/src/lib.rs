//! Standalone offline verifier for IAGA Sentinel signed receipt chains.
//!
//! Given an exported chain (`ChainExport`) this verifies every Ed25519
//! signature and the Merkle parent-hash links with a single public key,
//! with no database, no network, and no async runtime. It is the artifact
//! an auditor runs to confirm a receipt chain is intact and unaltered,
//! without trusting IAGA.
//!
//! The verification itself reuses `iaga_sentinel_receipts::verify_chain`,
//! the exact function the full runtime uses, so this tool and the runtime
//! cannot disagree about what a valid chain is.

use ed25519_dalek::VerifyingKey;
use iaga_sentinel_receipts::{key_id_for_verifying_key, verify_chain, ChainExport, ChainStatus};

/// Which public key the chain was verified against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySource {
    /// A key the caller pinned out of band. Trusted.
    Pinned,
    /// The key embedded in the export itself. Self-asserted, not authenticated.
    Embedded,
}

/// An error that prevents the chain from being checked at all.
#[derive(Debug)]
pub enum VerifyError {
    /// The hex public key could not be decoded into a 32-byte Ed25519 key.
    BadKey(String),
    /// `verify_chain` itself errored (for example malformed signature hex).
    Verify(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::BadKey(m) => write!(f, "invalid public key: {m}"),
            VerifyError::Verify(m) => write!(f, "verification error: {m}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Decode a hex-encoded 32-byte Ed25519 public key.
pub fn parse_key(hex_key: &str) -> Result<VerifyingKey, VerifyError> {
    let bytes =
        hex::decode(hex_key.trim()).map_err(|e| VerifyError::BadKey(format!("not hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyError::BadKey(format!("expected 32 bytes, got {}", bytes.len())))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| VerifyError::BadKey(e.to_string()))
}

/// Verify an exported receipt chain. If `pinned_key_hex` is provided the
/// chain is checked against that trusted key; otherwise it falls back to the
/// key embedded in the export, which is self-asserted.
pub fn verify_export(
    export: &ChainExport,
    pinned_key_hex: Option<&str>,
) -> Result<(ChainStatus, KeySource), VerifyError> {
    let (key_hex, source) = match pinned_key_hex {
        Some(k) => (k, KeySource::Pinned),
        None => (export.signer_verifying_key.as_str(), KeySource::Embedded),
    };
    let vk = parse_key(key_hex)?;

    // PROOF-VERIFY-SIGNERID: bind the human-readable `signer=` label (and every
    // receipt's claimed signer) to the key that actually verifies the chain. The
    // signature covers `signer_key_id`, so a chain can be self-consistently signed
    // by one key while advertising a *different* `signer_key_id` (e.g. a victim's).
    // Without this check `CHAIN OK signer=<id>` would print an unauthenticated,
    // attacker-chosen identity. A mismatch is a verification failure (Broken), not
    // an IO error.
    let key_id = key_id_for_verifying_key(&vk);
    if export.signer_key_id != key_id {
        return Ok((
            ChainStatus::Broken {
                seq: 0,
                reason: format!(
                    "signer_key_id mismatch: export claims {} but the verifying key is {key_id}",
                    export.signer_key_id
                ),
            },
            source,
        ));
    }
    for r in &export.receipts {
        if r.body.signer_key_id != key_id {
            return Ok((
                ChainStatus::Broken {
                    seq: r.body.seq,
                    reason: format!(
                        "receipt seq {} claims signer {} but the verifying key is {key_id}",
                        r.body.seq, r.body.signer_key_id
                    ),
                },
                source,
            ));
        }
        // The envelope's `run_id` is not covered by any signature, so a chain of
        // genuinely signed receipts can be relabelled to a run that never
        // happened and still verify. The Python and Node verifiers have always
        // rejected that; this one did not, which broke the conformance promise
        // that all three reach the same verdict with the same exit code. Same
        // wording as theirs, deliberately.
        if r.body.run_id != export.run_id {
            return Ok((
                ChainStatus::Broken {
                    seq: r.body.seq,
                    reason: format!(
                        "run_id mismatch: expected {} got {}",
                        export.run_id, r.body.run_id
                    ),
                },
                source,
            ));
        }
    }

    let status =
        verify_chain(&export.receipts, &vk).map_err(|e| VerifyError::Verify(e.to_string()))?;
    Ok((status, source))
}
