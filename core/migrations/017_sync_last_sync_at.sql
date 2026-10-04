-- 同步状态显示（sync-group-mode §二.5.5）：最近一次成功同步周期的时间。
-- pull/pull+push 跑完（非 travel 拒绝、无错误）即记，NULL = 从未同步。
ALTER TABLE sync_state ADD COLUMN last_sync_at TEXT;
