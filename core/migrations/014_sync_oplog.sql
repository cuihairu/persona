-- Migration 014: local E2EE sync oplog + sync device state.
-- (E2EE_SYNC_DESIGN 阶段 2，core/src/sync/oplog.rs)
-- 本地表只存密文载荷（ciphertext / wrapped_item_key），与服务器 oplog 同构：
-- append-only，主位/冲突副本由 item_view 推导（见 sync/oplog.rs 模块文档），
-- 不落 conflict_of 快照列。
-- change_history 仍是本地明文审计，永不进本表（§8 边界）。

CREATE TABLE IF NOT EXISTS sync_oplog (
    op_id TEXT PRIMARY KEY,
    item_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    op TEXT NOT NULL CHECK (op IN ('put', 'delete')),
    lamport INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    timestamp TEXT,
    ciphertext BLOB,
    wrapped_item_key BLOB,
    origin TEXT NOT NULL DEFAULT 'local' CHECK (origin IN ('local', 'remote')),
    push_state TEXT NOT NULL DEFAULT 'pending' CHECK (push_state IN ('pending', 'acked'))
);

CREATE INDEX IF NOT EXISTS idx_sync_oplog_item ON sync_oplog(item_id);
CREATE INDEX IF NOT EXISTS idx_sync_oplog_push_queue
    ON sync_oplog(lamport, device_id, op_id)
    WHERE origin = 'local' AND push_state = 'pending';

CREATE TABLE IF NOT EXISTS sync_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    local_lamport INTEGER NOT NULL DEFAULT 0,
    device_id TEXT,
    last_pull_cursor TEXT
);
