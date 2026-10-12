-- Migration 020: context-aware suggestion, stage 2 — local learning history.
-- (CONTEXT_AWARE_DESIGN §4.1/§8 阶段 2, core/src/storage/context_learn_repository.rs)
-- 本地表，设计红线：学习记录不进同步、不上服务器（sync oplog 不覆盖本表）。
-- cwd 存哈希不存原文：目录路径不落明文，分组建议只用等值匹配。
-- 开关同库存放（context_settings），默认关——未显式 `persona context learn on`
-- 前本表为空，suggest 行为与阶段 1 完全一致。

CREATE TABLE IF NOT EXISTS context_learn (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_name TEXT NOT NULL,
    cwd_hash TEXT NOT NULL,
    host TEXT,
    ts TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_context_learn_lookup
    ON context_learn(cwd_hash, identity_name);

CREATE TABLE IF NOT EXISTS context_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
