-- 账号体系（M2 账号体系：注册/登录、通行密钥优先+SRP 密码兜底、设备管理、恢复）。
-- 零知识原则：主密码/主密钥不出设备，服务器只存公开验证材料。
-- 通行密钥：存 credential_id + 公钥（webauthn-rs PasskeyAuthentication）；
-- SRP 密码兜底：复用 auth_devices 表结构（salt + verifier），以 account_id 做前缀键区分。
-- 恢复码：存 Argon2id hash（同核心口令 hash 算法），一次性使用后作废。

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,                          -- server 分配 UUID v4
    username TEXT NOT NULL UNIQUE,                -- 用户名/邮箱（唯一标识，登录用）
    display_name TEXT,                            -- 显示名
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    -- 账号状态：active / locked / pending_recovery
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'locked', 'pending_recovery')),
    -- 最后登录时间（审计用）
    last_login_at TEXT,
    -- 版本号（乐观锁，防并发修改竞态）
    version INTEGER NOT NULL DEFAULT 1
);

-- 通行密钥凭据表（每账号多条，WebAuthn 凭据）
-- 复用 core 的 PasskeyAuthentication 数据结构字段
CREATE TABLE IF NOT EXISTS account_passkeys (
    id TEXT PRIMARY KEY,                          -- credential_id (base64url)
    account_id TEXT NOT NULL,
    public_key BLOB NOT NULL,                     -- COSE 公钥（SPKI/DER 或 raw）
    aaguid BLOB,                                  -- 16 字节 AAGUID（可空）
    sign_count INTEGER NOT NULL DEFAULT 0,        -- 签名计数器（重放防护）
    backed_up INTEGER NOT NULL DEFAULT 0,         -- 是否已备份到云同步器
    transports TEXT,                              -- 逗号分隔：usb/nfc/ble/internal/hybrid
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_account_passkeys_account ON account_passkeys(account_id);

-- SRP 密码兜底：按账号隔离（复用 auth_devices 结构，加 account_id 前缀）
-- 设备名 = account_id:device_name，保证跨账号隔离
CREATE TABLE IF NOT EXISTS account_srp_credentials (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_name TEXT NOT NULL,                    -- 账号内设备名
    salt BLOB NOT NULL,                           -- SRP salt
    verifier BLOB NOT NULL,                       -- SRP verifier (v = g^x mod N)
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT,
    UNIQUE(account_id, device_name)
);

CREATE INDEX IF NOT EXISTS idx_account_srp_account ON account_srp_credentials(account_id);

-- 恢复码（一次性，Argon2id hash，用完即弃）
-- 用户生成一组（如 8 个），每个独立验证、一次性消费
CREATE TABLE IF NOT EXISTS account_recovery_codes (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,                      -- Argon2id PHC 串
    used_at TEXT,                                 -- null = 未用，非 null = 已消费
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_account_recovery_account ON account_recovery_codes(account_id);
CREATE INDEX IF NOT EXISTS idx_account_recovery_unused ON account_recovery_codes(account_id, used_at) WHERE used_at IS NULL;

-- 账号级设备授权表（扩展 sync_devices 到账号作用域）
-- 关联 account_id + device_id，记录授权状态、授权方、授权时间
CREATE TABLE IF NOT EXISTS account_devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_id TEXT NOT NULL,                      -- sync_devices.id
    device_name TEXT NOT NULL,                    -- 冗存设备名（便于列表不 JOIN）
    public_key BLOB NOT NULL,                     -- 冗存公钥（同步时直接读）
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'authorized', 'revoked')),
    authorized_by TEXT,                           -- 授权方设备名
    authorized_at TEXT,
    revoked_at TEXT,
    revoked_by TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES sync_devices(id) ON DELETE CASCADE,
    UNIQUE(account_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_account_devices_account ON account_devices(account_id);
CREATE INDEX IF NOT EXISTS idx_account_devices_status ON account_devices(account_id, status);

-- 登录会话（短期，用于已登录态管理、设备信任）
-- 与 SRP 短期令牌分离：这是账号级会话，不直接用于 sync API Bearer
CREATE TABLE IF NOT EXISTS account_sessions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    device_id TEXT,                               -- 关联设备（可空，首次登录前无设备）
    session_token TEXT NOT NULL UNIQUE,           -- 随机 ≥256-bit base64url
    expires_at TEXT NOT NULL,                     -- RFC3339
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_activity_at TEXT,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_account_sessions_account ON account_sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_account_sessions_token ON account_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_account_sessions_expires ON account_sessions(expires_at);