-- Opaque session tokens for the bearer-auth flow. The token itself is
-- never persisted — only its Argon2id-hashed digest. Compromise of the
-- DB therefore does not yield active sessions.
--
-- We do NOT store IP addresses or user-agents (security model: no
-- persistent IP/user-agent logs associated with profiles or accounts).

CREATE TABLE sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash      TEXT NOT NULL,
    -- Unix seconds. INTEGER (not ISO string) so comparisons against
    -- "now" are pure integer arithmetic with no parsing.
    created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    expires_at      INTEGER NOT NULL
);

CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
