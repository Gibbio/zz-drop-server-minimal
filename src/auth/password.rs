use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use argon2::{Argon2, Algorithm, Params, Version};
use thiserror::Error;

/// Server-enforced minimum length for account passwords. Matches the
/// OpenAPI `RegisterRequest.password.minLength = 16`.
pub const MIN_PASSWORD_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("password too short")]
    TooShort,
    #[error("hash error")]
    Hash,
    #[error("verify error")]
    Verify,
}

/// Argon2id parameters for account passwords. Conservative production
/// defaults: 64 MiB / 3 iterations / 1 lane, ~150 ms on a modern CPU.
fn argon2() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64 * 1024, 3, 1, None).expect("static argon2 params are valid"),
    )
}

/// Hash an account password. Rejects passwords shorter than
/// [`MIN_PASSWORD_LEN`] before hashing so we never compute Argon2id on
/// obviously-bad input.
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(PasswordError::TooShort);
    }
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| PasswordError::Hash)
}

/// Constant-time verify of `password` against the stored PHC string.
/// Returns `Ok(false)` for "wrong password", `Err` only for malformed
/// stored hash.
pub fn verify_password(password: &str, stored_hash: &str) -> Result<bool, PasswordError> {
    let parsed = PasswordHash::new(stored_hash).map_err(|_| PasswordError::Verify)?;
    Ok(argon2()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_strong_password() {
        let h = hash_password("correct-horse-battery-staple-9!").unwrap();
        assert!(verify_password("correct-horse-battery-staple-9!", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn rejects_short_password() {
        assert!(matches!(
            hash_password("short"),
            Err(PasswordError::TooShort)
        ));
    }

    #[test]
    fn boundary_at_exactly_16_chars() {
        let p = "x".repeat(MIN_PASSWORD_LEN);
        assert!(hash_password(&p).is_ok());
    }

    #[test]
    fn debug_does_not_leak_password() {
        let h = hash_password("correct-horse-battery-staple-9!").unwrap();
        // The PHC string contains the salt + digest but NOT the plaintext.
        assert!(!h.contains("correct-horse"));
    }
}
