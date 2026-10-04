-- 同步组动态密码配对中转（S1，docs/sync-group-mode.md）。
-- 无账号信箱：session_id 即能力标识；中转不解释 payload（客户端
-- core::sync::pairing::PairingMessage 的 JSON 字节，只见 SRP 公开消息与
-- AEAD 密文信封——零知识）。TTL / 单方向队列上限 / payload 上限由 API 层
-- 强制；过期与废弃 session 由写入路径惰性清理。
-- direction: to_host = guest→host，to_guest = host→guest。

CREATE TABLE IF NOT EXISTS pairing_sessions (
    id TEXT PRIMARY KEY,                          -- server 分配 UUID v4（能力标识）
    salt BLOB NOT NULL,                           -- 配对 KDF salt（host 生成，经此分发）
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed_at TEXT                              -- 任一端 DELETE 后标记（行随惰性清理删除）
);

CREATE TABLE IF NOT EXISTS pairing_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES pairing_sessions(id) ON DELETE CASCADE,
    direction TEXT NOT NULL CHECK (direction IN ('to_host', 'to_guest')),
    payload BLOB NOT NULL,                        -- 客户端消息 JSON（b64 解出前/后均可，本层不解释）
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pairing_messages_session
    ON pairing_messages(session_id, direction, id);
