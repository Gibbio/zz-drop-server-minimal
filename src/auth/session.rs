use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Length in bytes of an opaque session token before base64 encoding.
/// 32 bytes = 256 bits of entropy from `getrandom`.
pub const SESSION_TOKEN_BYTES: usize = 32;

/// Session lifetime. After this many seconds the row in `sessions` is
/// no longer valid. We don't auto-rotate; the client logs in again.
pub const SESSION_TTL_SECS: u64 = 7 * 24 * 60 * 60; // 7 days

/// Lifetime of a TOTP login challenge. Five minutes is enough for the
/// user to fish out their authenticator app; not so long that a stolen
/// challenge stays useful.
pub const TOTP_CHALLENGE_TTL_SECS: u64 = 5 * 60;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("rng failure")]
    Rng,
}

/// Mint a fresh opaque token. Returns the URL-safe base64 string the
/// server hands back to the client. Use [`hash_token`] to derive the
/// digest stored in the DB.
pub fn mint_token() -> Result<String, SessionError> {
    let mut buf = [0u8; SESSION_TOKEN_BYTES];
    getrandom::getrandom(&mut buf).map_err(|_| SessionError::Rng)?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// SHA-256 the token before storing it. We deliberately avoid Argon2id
/// here: tokens are 256 bits of uniform random, so a fast hash is
/// enough and the verification path needs to be cheap.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trip_unique() {
        let a = mint_token().unwrap();
        let b = mint_token().unwrap();
        assert_ne!(a, b, "tokens are not unique");
        assert!(a.len() >= 40, "base64 of 32 bytes is ~43 chars");
    }

    #[test]
    fn hash_token_is_deterministic() {
        let t = "abc";
        assert_eq!(hash_token(t), hash_token(t));
    }

    #[test]
    fn hash_token_differs_per_input() {
        assert_ne!(hash_token("a"), hash_token("b"));
    }
}
