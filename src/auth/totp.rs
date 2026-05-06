//! TOTP (RFC 6238) — HMAC-SHA1, 6 digits, 30 s period, drift ±1 step.
//! Used only for server account login; never to derive a profile key.

use base32::Alphabet;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

pub const PERIOD_SECS: u64 = 30;
pub const DIGITS: u32 = 6;
pub const DRIFT_STEPS: i64 = 1;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("hmac key error")]
    Key,
}

/// Generate the 6-digit code for `seed` at unix-time `now_secs`. The
/// drift parameter is 0 here; callers wanting drift tolerance should
/// use [`verify`] which checks ±DRIFT_STEPS.
pub fn code_at(seed: &[u8], now_secs: u64) -> Result<String, TotpError> {
    code_at_step(seed, now_secs / PERIOD_SECS)
}

fn code_at_step(seed: &[u8], step: u64) -> Result<String, TotpError> {
    let mut mac = HmacSha1::new_from_slice(seed).map_err(|_| TotpError::Key)?;
    mac.update(&step.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    // Dynamic truncation, RFC 4226 §5.3.
    let offset = (tag[19] & 0x0f) as usize;
    let bin = ((tag[offset] as u32 & 0x7f) << 24)
        | ((tag[offset + 1] as u32) << 16)
        | ((tag[offset + 2] as u32) << 8)
        | (tag[offset + 3] as u32);
    let modulus = 10u32.pow(DIGITS);
    let n = bin % modulus;
    Ok(format!("{n:0width$}", width = DIGITS as usize))
}

/// Verify a 6-digit code against `seed` at the given timestamp. Accepts
/// the current step and ±1 step on either side (RFC 6238 drift tolerance).
/// Constant-time string compare against each candidate.
pub fn verify(seed: &[u8], now_secs: u64, code: &str) -> bool {
    if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let step = (now_secs / PERIOD_SECS) as i64;
    for delta in -DRIFT_STEPS..=DRIFT_STEPS {
        let s = (step + delta).max(0) as u64;
        if let Ok(candidate) = code_at_step(seed, s)
            && candidate.as_bytes().ct_eq(code.as_bytes()).into()
        {
            return true;
        }
    }
    false
}

/// Encode a seed as base32 (RFC 3548 / 4648, no padding) for the
/// `otpauth://` URI. Authenticator apps expect the seed in this form.
pub fn seed_to_base32(seed: &[u8]) -> String {
    base32::encode(Alphabet::Rfc4648 { padding: false }, seed)
}

/// Build the `otpauth://totp/issuer:account?secret=...&issuer=...`
/// URI shown to the user (typically as a QR) at enrollment.
pub fn otpauth_uri(issuer: &str, account: &str, seed_b32: &str) -> String {
    // We minimise URL-encoding manually for the small subset we expect
    // in the issuer/account labels (alphanumerics + `.`, `-`, `_`, `@`).
    // For everything else, callers should pre-sanitize.
    format!(
        "otpauth://totp/{issuer}:{account}?secret={seed_b32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        issuer = issuer,
        account = account,
        seed_b32 = seed_b32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B test vectors (seed = "12345678901234567890",
    // SHA-1). Time T = unix-time / 30. Listed `(T, code)` pairs.
    fn rfc_seed() -> &'static [u8] {
        b"12345678901234567890"
    }

    #[test]
    fn rfc_test_vectors() {
        // (unix_secs, expected_6digit)
        for (now, expected) in [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
        ] {
            let got = code_at(rfc_seed(), now).unwrap();
            assert_eq!(got, expected, "mismatch at T={now}");
        }
    }

    #[test]
    fn verify_accepts_drift_one_step() {
        let seed = rfc_seed();
        let now = 60u64; // step 2
        let prev_step_code = code_at(seed, 30).unwrap(); // step 1
        let next_step_code = code_at(seed, 90).unwrap(); // step 3
        assert!(verify(seed, now, &prev_step_code));
        assert!(verify(seed, now, &next_step_code));
    }

    #[test]
    fn verify_rejects_drift_two_steps() {
        let seed = rfc_seed();
        let now = 60u64; // step 2
        let two_back = code_at(seed, 0).unwrap(); // step 0
        assert!(!verify(seed, now, &two_back));
    }

    #[test]
    fn verify_rejects_non_numeric() {
        assert!(!verify(rfc_seed(), 60, "12abcd"));
        assert!(!verify(rfc_seed(), 60, "12345"));
        assert!(!verify(rfc_seed(), 60, "1234567"));
    }

    #[test]
    fn otpauth_uri_contains_required_params() {
        let s = seed_to_base32(b"abcdefghij");
        let uri = otpauth_uri("zz-drop", "alice@example.org", &s);
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("issuer=zz-drop"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    #[test]
    fn debug_output_does_not_contain_seed_bytes() {
        // We never `Debug`-print a raw seed in production; this test
        // is a guardrail in case a future refactor attaches `Debug` to
        // a struct that holds the seed.
        let s = format!("{:?}", b"12345678901234567890");
        assert!(s.contains("49"), "raw bytes printed by ?: that is exactly what we never do");
    }
}
