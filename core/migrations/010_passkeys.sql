-- Migration: Add WebAuthn passkey support
-- Description: Store passkeys (software authenticator credentials) as first-class
--              identity-scoped items. The private key is encrypted with a per-item
--              key wrapped by the master key (see docs/KEY_HIERARCHY.md).

CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY NOT NULL,
    identity_id TEXT NOT NULL,
    rp_id TEXT NOT NULL CHECK(length(trim(rp_id)) > 0),
    rp_name TEXT,
    user_handle BLOB NOT NULL,
    user_name TEXT,
    user_display_name TEXT,
    credential_id BLOB NOT NULL,
    encrypted_private_key BLOB NOT NULL,
    wrapped_item_key BLOB NOT NULL,
    public_key_cose BLOB NOT NULL,
    alg INTEGER NOT NULL DEFAULT -7,
    sign_count INTEGER NOT NULL DEFAULT 0,
    uv_initialized INTEGER NOT NULL DEFAULT 0,
    export_allowed INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER,
    tags TEXT NOT NULL DEFAULT '[]',
    FOREIGN KEY (identity_id) REFERENCES identities(id) ON DELETE CASCADE,
    UNIQUE(identity_id, credential_id)
);

CREATE INDEX IF NOT EXISTS idx_passkeys_identity_id ON passkeys(identity_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_rp_id ON passkeys(rp_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys(credential_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_created_at ON passkeys(created_at DESC);
