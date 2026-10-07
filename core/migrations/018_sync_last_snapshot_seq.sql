-- S2 库级快照（E2EE_SYNC_DESIGN §5「触发时机」）：本机最近一次快照的
-- 覆盖位点。上传成功与 bootstrap 装包成功都记（MAX 语义只进不退）——
-- 触发条件 `head_seq − last_snapshot_seq > UPLOAD_THRESHOLD_OPS` 靠它防
-- 频繁重打包。0 = 从未有过快照（与「空组 head=0」同口径，新库自然等满
-- 阈值才首次打包）。
ALTER TABLE sync_state ADD COLUMN last_snapshot_seq INTEGER NOT NULL DEFAULT 0;
