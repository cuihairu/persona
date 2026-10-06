-- S2 库级快照（E2EE_SYNC_DESIGN §5「库级快照与指令压缩」，2026-10-07 设计定稿）。
-- 单快照语义：只留最新一份（id = 1，PUT upsert 覆盖）。seq = 客户端声明的
-- 覆盖位点（先 pull 到 head 再 push ack 的 seq——快照声称包含 seq ≤ S 的
-- 全部效果；谎报 S 属组内恶意设备既有威胁面，不新增防线）。快照包是
-- group key 整包加密的密文，服务器盲存零知识。
-- 上传事务内删 seq <= 快照点的 ops：与按天 retention（enforce_oplog_retention）
-- 同向的压缩——「缩水子集也收敛」宽容口径不变，快照补的是空库新设备被
-- retention 删段后无本地事实源可补的真丢数据洞。

CREATE TABLE IF NOT EXISTS sync_snapshots (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seq INTEGER NOT NULL CHECK (seq >= 0),
    device_id TEXT NOT NULL,           -- 打包设备自报，仅展示（与 oplog 同口径）
    ciphertext BLOB NOT NULL,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
