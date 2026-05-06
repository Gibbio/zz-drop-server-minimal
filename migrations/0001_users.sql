-- Users + email preferences. The encrypted profile blob lives in a
-- separate table (TASK 19); this migration is purely about identity.
--
-- We never store: provider URLs, app passwords, TOTP seeds, decrypted
-- profile data. See SECURITY_MODEL.md.

CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT NOT NULL,
    -- Email preferences. `security_events` is non-disableable per
    -- the API contract; we keep the column for symmetry but enforce
    -- TRUE at the application layer.
    pref_security_events    INTEGER NOT NULL DEFAULT 1 CHECK (pref_security_events = 1),
    pref_profile_activity   INTEGER NOT NULL DEFAULT 1,
    pref_product_updates    INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX users_email_idx ON users (email);
