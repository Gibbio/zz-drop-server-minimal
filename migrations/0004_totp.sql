-- TOTP 2FA + recovery codes. Optional per account; default off.
-- Per the SECURITY_MODEL: the shared seed is stored encrypted at rest
-- and recovery codes are stored as Argon2id hashes. Neither value is
-- ever sent to a CLI/TUI client. Neither is part of profile.zz.

-- One row per account once TOTP is enabled. Absence of a row = TOTP off.
-- `seed_ciphertext` is the AEAD-encrypted shared seed (encryption keyed
-- off a server-side master key — outside this migration's scope).
-- `enrolled_at` is the timestamp of successful first verification.
-- `pending_until` lets enrollment be in two phases: row inserted at
-- /enroll, then activated at /verify.
CREATE TABLE totp_secrets (
    user_id         INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    seed_ciphertext TEXT NOT NULL,
    seed_nonce      TEXT NOT NULL,
    pending_until   INTEGER,      -- unix seconds; non-null while enrollment is unconfirmed
    enrolled_at     INTEGER,      -- unix seconds; non-null once activated
    created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

-- Single-use recovery codes. We store only Argon2id hashes; the
-- plaintext is shown to the user once at enrollment. `consumed_at`
-- timestamps single-use semantics.
CREATE TABLE totp_recovery_codes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash       TEXT NOT NULL,
    consumed_at     INTEGER,      -- unix seconds; null until consumed
    created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX totp_recovery_user_idx ON totp_recovery_codes (user_id);

-- Two-step login challenge. After password is verified but TOTP is on,
-- the server returns a short-lived challenge. The TOTP step exchanges
-- the challenge + a 6-digit code (or recovery code) for a session.
-- Challenges are ephemeral — no IPs, no user-agents.
CREATE TABLE totp_challenges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    challenge_hash  TEXT NOT NULL,
    expires_at      INTEGER NOT NULL,
    created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX totp_challenges_expires_idx ON totp_challenges (expires_at);
