use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use uuid::Uuid;

/// Generate a new API key pair: (raw_key, key_hash)
/// The raw_key is returned to the user once; the Argon2id hash is stored.
pub fn generate_api_key() -> (String, String) {
    let raw = format!("iaga_{}", Uuid::new_v4().to_string().replace('-', ""));
    let hash = hash_key(&raw);
    (raw, hash)
}

/// Hash an API key with Argon2id for storage/lookup.
pub fn hash_key(raw_key: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(raw_key.as_bytes(), &salt)
        .expect("failed to hash API key")
        .to_string()
}

/// Verify a raw API key against a stored Argon2id hash.
pub fn verify_key(raw_key: &str, stored_hash: &str) -> bool {
    let parsed = match PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(raw_key.as_bytes(), &parsed)
        .is_ok()
}

/// Env var carrying an operator-supplied admin key to register at startup.
///
/// Deliberately NOT `IAGA_SENTINEL_API_KEY`: that name is already the *client*
/// bearer token in the Letta and VoltAgent plug-ins, so reusing it would mean a
/// developer with the client key exported could no longer start the server, and
/// a shared `.env` would silently mint a server-side admin credential.
pub const BOOTSTRAP_ENV: &str = "IAGA_SENTINEL_BOOTSTRAP_API_KEY";

/// Minimum length for a bootstrap key. Short enough not to fight the operator,
/// long enough that a typo or a placeholder does not become a live admin
/// credential.
const MIN_BOOTSTRAP_LEN: usize = 16;

/// Validate an operator-supplied bootstrap key.
///
/// The value is checked **as given** — no trimming. Trimming would silently
/// register a different credential than the one the operator's clients send
/// (a `kubectl create secret --from-file` trailing newline is the common case),
/// and the mismatch would then surface as an unexplained 401.
pub fn validate_bootstrap_key(raw: &str) -> Result<(), String> {
    if raw.len() < MIN_BOOTSTRAP_LEN {
        return Err(format!(
            "must be at least {MIN_BOOTSTRAP_LEN} characters, got {}",
            raw.len()
        ));
    }
    if !raw.chars().all(|c| c.is_ascii_graphic()) {
        return Err(
            "must contain only printable ASCII with no spaces or newlines \
             (a trailing newline from `--from-file` is the usual cause)"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_key_validation_rejects_what_would_silently_break_auth() {
        assert!(validate_bootstrap_key("iaga_bootstrap_key_0123").is_ok());

        // Too short: a placeholder must not become a live admin credential.
        assert!(validate_bootstrap_key("short").is_err());
        assert!(validate_bootstrap_key("").is_err());

        // A trailing newline is rejected rather than trimmed, so the key that
        // gets registered is always the key the operator's clients send.
        assert!(validate_bootstrap_key("iaga_bootstrap_key_0123\n").is_err());
        assert!(validate_bootstrap_key("iaga bootstrap key 0123").is_err());

        // Non-ASCII must not panic on the key_prefix slice downstream.
        assert!(validate_bootstrap_key("iaga_bootstrap_kéy_0123").is_err());
    }
}
