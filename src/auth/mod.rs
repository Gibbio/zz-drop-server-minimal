//! Account auth subsystem: password hashing, session tokens, optional
//! TOTP 2FA, and recovery codes.
//!
//! Security invariants enforced here:
//!
//! - Account passwords: minimum 16 characters, hashed with Argon2id.
//! - Session tokens: 32 random bytes, hashed before storage.
//! - TOTP: RFC 6238 (HMAC-SHA1, 6 digits, 30 s, drift ±1). Shared seed
//!   encrypted at rest with a server-side master key.
//! - Recovery codes: 10 single-use codes per account, plain text shown
//!   once at enrollment, stored as Argon2id hashes.
//! - Errors are deliberately uninformative to the client (we don't
//!   distinguish "wrong password" from "no such user").
//! - Nothing here ever logs a password, a TOTP code, a recovery code,
//!   a token, a seed, or a hash.

pub mod password;
pub mod recovery_codes;
pub mod seed;
pub mod session;
pub mod totp;
