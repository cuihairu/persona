-- Migration 016: passkeys.credential_id 收紧为全库唯一。
-- 设计稿（docs/PASSKEYS_DESIGN.md §5）："credential_id 加唯一索引（同一库内不重复）"。
-- 010 建表时误写成 UNIQUE(identity_id, credential_id)，同一 credential_id 仍可
-- 挂到两个身份下（例如同一条 passkey 被导入两次落到不同身份）——签名归属与
-- 断言查找都会含糊。SQLite 改不了表约束，按标准重建流程：建新表 → 拷贝 →
-- 换名 → 重建索引。本表是 FK 叶子（无子表引用），行数据原样迁移；
-- credential_id 为随机 32 字节，现存数据实际不会撞 UNIQUE。

CREATE TABLE passkeys_unique (
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
    UNIQUE(credential_id)
);

INSERT INTO passkeys_unique (
    id, identity_id, rp_id, rp_name, user_handle, user_name, user_display_name,
    credential_id, encrypted_private_key, wrapped_item_key, public_key_cose,
    alg, sign_count, uv_initialized, export_allowed, created_at, last_used_at, tags
) SELECT
    id, identity_id, rp_id, rp_name, user_handle, user_name, user_display_name,
    credential_id, encrypted_private_key, wrapped_item_key, public_key_cose,
    alg, sign_count, uv_initialized, export_allowed, created_at, last_used_at, tags
FROM passkeys;

DROP TABLE passkeys;
ALTER TABLE passkeys_unique RENAME TO passkeys;

CREATE INDEX IF NOT EXISTS idx_passkeys_identity_id ON passkeys(identity_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_rp_id ON passkeys(rp_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_credential_id ON passkeys(credential_id);
CREATE INDEX IF NOT EXISTS idx_passkeys_created_at ON passkeys(created_at DESC);
