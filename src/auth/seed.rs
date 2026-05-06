use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use thiserror::Error;

/// Length of the TOTP shared seed in bytes. RFC 4226 §4 recommends
/// at least 128 bits; we use 160 (20 bytes) so the base32 representation
/// is a pleasant 32 characters and matches the HOTP/TOTP test vectors.
pub const TOTP_SEED_BYTES: usize = 20;

/// Length of the master key used to encrypt TOTP seeds at rest.
/// XChaCha20-Poly1305 takes a 32-byte key.
pub const MASTER_KEY_BYTES: usize = 32;

/// Length of the XChaCha20 nonce. 24 bytes; safe to use random nonces.
pub const NONCE_BYTES: usize = 24;

#[derive(Debug, Error)]
pub enum SeedError {
    #[error("rng failure")]
    Rng,
    #[error("encrypt error")]
    Encrypt,
    #[error("decrypt error")]
    Decrypt,
    #[error("bad master key length")]
    BadKey,
    #[error("bad ciphertext encoding")]
    Encoding,
}

/// Generate a fresh TOTP shared seed. 20 random bytes from the OS RNG.
pub fn generate_seed() -> Result<[u8; TOTP_SEED_BYTES], SeedError> {
    let mut buf = [0u8; TOTP_SEED_BYTES];
    getrandom::getrandom(&mut buf).map_err(|_| SeedError::Rng)?;
    Ok(buf)
}

/// Encrypt a TOTP seed for storage. Returns `(ciphertext_b64, nonce_b64)`.
/// Each enrollment gets a fresh random nonce; we never reuse one for
/// the same key.
pub fn encrypt_seed(seed: &[u8], master_key: &[u8]) -> Result<(String, String), SeedError> {
    if master_key.len() != MASTER_KEY_BYTES {
        return Err(SeedError::BadKey);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(master_key).map_err(|_| SeedError::BadKey)?;
    let mut nonce_bytes = [0u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce_bytes).map_err(|_| SeedError::Rng)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, seed).map_err(|_| SeedError::Encrypt)?;
    Ok((B64.encode(&ct), B64.encode(nonce_bytes)))
}

/// Decrypt a TOTP seed fetched from the DB.
pub fn decrypt_seed(
    ciphertext_b64: &str,
    nonce_b64: &str,
    master_key: &[u8],
) -> Result<Vec<u8>, SeedError> {
    if master_key.len() != MASTER_KEY_BYTES {
        return Err(SeedError::BadKey);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(master_key).map_err(|_| SeedError::BadKey)?;
    let ct = B64.decode(ciphertext_b64).map_err(|_| SeedError::Encoding)?;
    let n = B64.decode(nonce_b64).map_err(|_| SeedError::Encoding)?;
    if n.len() != NONCE_BYTES {
        return Err(SeedError::Encoding);
    }
    let nonce = XNonce::from_slice(&n);
    cipher.decrypt(nonce, ct.as_slice()).map_err(|_| SeedError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_master() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        k
    }

    #[test]
    fn round_trip() {
        let seed = generate_seed().unwrap();
        let (ct, n) = encrypt_seed(&seed, &fixed_master()).unwrap();
        let back = decrypt_seed(&ct, &n, &fixed_master()).unwrap();
        assert_eq!(back, seed);
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let seed = generate_seed().unwrap();
        let (ct, n) = encrypt_seed(&seed, &fixed_master()).unwrap();
        let mut other = fixed_master();
        other[0] ^= 0xFF;
        assert!(matches!(
            decrypt_seed(&ct, &n, &other),
            Err(SeedError::Decrypt)
        ));
    }

    #[test]
    fn nonces_are_unique() {
        let seed = generate_seed().unwrap();
        let (_, n1) = encrypt_seed(&seed, &fixed_master()).unwrap();
        let (_, n2) = encrypt_seed(&seed, &fixed_master()).unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn rejects_short_master_key() {
        let seed = generate_seed().unwrap();
        assert!(matches!(
            encrypt_seed(&seed, &[0u8; 16]),
            Err(SeedError::BadKey)
        ));
    }
}
