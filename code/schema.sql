-- TDX Confidential File Sharing
-- Metadata schema for the EXTERNAL (untrusted) PostgreSQL store, per decision D1.
-- SECURITY NOTE: constraints below are developer conveniences only. The database is
-- untrusted; an attacker with write access can forge or drop anything here. All security
-- properties come from TEE-side checks: AAD binding on wrapped keys, HMACs on ACL rows,
-- the hash-chained audit log, and the D3 Key Vault rollback anchor.

CREATE TABLE IF NOT EXISTS users (
    user_id     UUID PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    pw_hash     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_keys (
    user_id     UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    wrapped_kek BYTEA NOT NULL,
    nonce       BYTEA NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS files (
    file_id        UUID PRIMARY KEY,
    owner_id       UUID NOT NULL REFERENCES users(user_id),
    filename_enc   BYTEA NOT NULL,
    filename_nonce BYTEA NOT NULL,
    size_bytes     BIGINT NOT NULL,
    blob_path      TEXT NOT NULL,
    version        INTEGER NOT NULL DEFAULT 1,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS file_keys (
    file_id     UUID NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    wrapped_dek BYTEA NOT NULL,
    nonce       BYTEA NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, user_id)
);

CREATE TABLE IF NOT EXISTS acl (
    file_id     UUID NOT NULL,
    user_id     UUID NOT NULL,
    permission  TEXT NOT NULL,
    version     INTEGER NOT NULL DEFAULT 1,
    mac         BYTEA NOT NULL,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (file_id, user_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq         BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id     UUID,
    action      TEXT NOT NULL,
    file_id     UUID,
    detail      TEXT,
    prev_hash   BYTEA NOT NULL,
    entry_hash  BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_file_keys_user ON file_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_acl_user       ON acl(user_id);
CREATE INDEX IF NOT EXISTS idx_files_owner    ON files(owner_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log(ts);
