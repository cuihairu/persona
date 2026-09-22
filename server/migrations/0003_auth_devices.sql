-- SRP 设备认证（E2EE 同步轨道阶段 1）：每台设备一个 SRP 账户。
-- 服务器只存 salt 与 SRP verifier（v = g^x mod N）——永不存密码或
-- Argon2 派生值；verifier 泄露后的离线爆破成本 ≈ 客户端 Argon2 参数。
CREATE TABLE auth_devices (
    id TEXT PRIMARY KEY,
    device_name TEXT NOT NULL UNIQUE,
    salt BLOB NOT NULL,
    verifier BLOB NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
