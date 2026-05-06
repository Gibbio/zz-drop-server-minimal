use argon2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng,
};
use argon2::{Algorithm, Argon2, Params, Version};
use thiserror::Error;

/// 10 codes issued at enrollment, per the security model.
pub const CODE_COUNT: usize = 10;

/// 10 chars from the unambiguous Base32-Crockford alphabet (no I/L/O/U).
/// 50 bits of entropy per code — enough that 10 codes shown once + the
/// password is acceptable account-recovery security.
pub const CODE_LEN: usize = 10;
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // 32 chars

#[derive(Debug, Error)]
pub enum RecoveryCodeError {
    #[error("rng failure")]
    Rng,
    #[error("hash error")]
    Hash,
    #[error("verify error")]
    Verify,
}

/// Generate a fresh batch of [`CODE_COUNT`] plain-text recovery codes.
/// The plaintexts must be shown once to the user and then forgotten by
/// the server (only the Argon2id hashes are stored).
pub fn generate_codes() -> Result<[String; CODE_COUNT], RecoveryCodeError> {
    let mut codes: [String; CODE_COUNT] = std::array::from_fn(|_| String::new());
    for slot in codes.iter_mut() {
        *slot = generate_code()?;
    }
    Ok(codes)
}

fn generate_code() -> Result<String, RecoveryCodeError> {
    let mut bytes = [0u8; CODE_LEN];
    getrandom::getrandom(&mut bytes).map_err(|_| RecoveryCodeError::Rng)?;
    let s: String = bytes
        .iter()
        .map(|b| char::from(ALPHABET[(*b as usize) % ALPHABET.len()]))
        .collect();
    Ok(s)
}

/// Argon2id parameters for recovery codes. Lighter than the password
/// hasher (codes are uniform random, so memory-hardness has little
/// added benefit and we want fast verification on login).
fn argon2() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(16 * 1024, 2, 1, None).expect("static argon2 params are valid"),
    )
}

pub fn hash_code(code: &str) -> Result<String, RecoveryCodeError> {
    let salt = SaltString::generate(&mut OsRng);
    argon2()
        .hash_password(code.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| RecoveryCodeError::Hash)
}

pub fn verify_code(code: &str, stored_hash: &str) -> Result<bool, RecoveryCodeError> {
    let parsed =
        PasswordHash::new(stored_hash).map_err(|_| RecoveryCodeError::Verify)?;
    Ok(argon2()
        .verify_password(code.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_has_ten_unique_codes() {
        let codes = generate_codes().unwrap();
        let mut set = std::collections::HashSet::new();
        for c in &codes {
            assert_eq!(c.len(), CODE_LEN);
            assert!(set.insert(c.clone()), "duplicate generated: {c}");
        }
        assert_eq!(set.len(), CODE_COUNT);
    }

    #[test]
    fn round_trip_hash_verify() {
        let code = generate_code().unwrap();
        let h = hash_code(&code).unwrap();
        assert!(verify_code(&code, &h).unwrap());
        assert!(!verify_code("ZZZZZZZZZZ", &h).unwrap());
    }
}
