-- server 侧保留策略（E2EE_SYNC_DESIGN §11 开放问题 3 收口）：
-- sync_oplog 按 received_at 滚动清理需要时间索引（表无此列索引时
-- DELETE 退化为全表扫描）。events 侧 idx_audit_events_received_at
-- 已在 0001 就位。

CREATE INDEX IF NOT EXISTS idx_sync_oplog_received_at
    ON sync_oplog(received_at);
