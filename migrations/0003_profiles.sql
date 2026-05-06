-- Profile aliases + encrypted blob storage. The server only ever sees
-- the opaque encrypted blob — never decrypted profile data, provider
-- credentials, server URLs, or anything else from the client.
--
-- One row per (user, alias). Alias is globally unique (not just per-
-- user) per the spec: a global namespace lets `zz z <alias>` succeed
-- without first knowing the owner's email.

CREATE TABLE profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    alias           TEXT NOT NULL UNIQUE COLLATE NOCASE,
    blob            BLOB,                  -- null until first PUT
    blob_size       INTEGER NOT NULL DEFAULT 0,
    -- Monotonic version. Incremented on every successful PUT. Clients
    -- must pass `expected_version=N` matching the current value (or 0
    -- for the first upload) — anything else is a 409 version_conflict.
    blob_version    INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    updated_at      INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER))
);

CREATE INDEX profiles_user_idx ON profiles (user_id);
