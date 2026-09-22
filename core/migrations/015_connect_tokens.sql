-- Migration 015: Connect automation tokens (CONNECT_AUTOMATION_DESIGN DR-2).
-- token 明文只在创建时展示一次；库里只存 SHA-256 哈希（UNIQUE，查表校验）
-- 与前 8 字节指纹（列表识别/吊销/审计，不泄露 token 本体）。
-- 随库走（备份覆盖/换机迁移），但不进同步轨道——per-device 本地资产
-- （设计稿 §9-4）。scope 以 JSON 存放（三维：identities/item_types/verbs）。

CREATE TABLE IF NOT EXISTS connect_tokens (
    id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    fingerprint TEXT NOT NULL,
    scope TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_connect_tokens_hash ON connect_tokens(hash);
