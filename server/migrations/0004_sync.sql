-- E2EE 同步：设备登记 / group key 信封 / oplog 中继（阶段 2 批 3，
-- E2EE_SYNC_DESIGN §5/§6，server/src/api/sync.rs）。
-- 服务器定位 = 纯中继 + 密文保管：信封与 oplog 载荷全部是密文字节，
-- 服务器盲存不解释；不做任何 LWW 胜负判定（DR-4）。
-- server 侧连接池 foreign_keys=false（state.rs 惯例），跨表关联为逻辑关联。

CREATE TABLE sync_devices (
    id TEXT PRIMARY KEY,
    device_name TEXT NOT NULL UNIQUE,
    public_key BLOB NOT NULL,          -- X25519 公钥（32B，DR-1）
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 每设备一个 group key 信封（persona-dev-env-1，80B）。「有信封 = 已授权」
-- 由信封存在性表达（§6）；重包（轮换/换钥）= 同 device_id UPSERT 覆盖。
CREATE TABLE sync_group_keys (
    device_id TEXT PRIMARY KEY,
    envelope BLOB NOT NULL,
    sealed_by TEXT NOT NULL,           -- 上传方设备名（审计用，非裁决依据）
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 服务器侧 oplog：到达顺序追加（seq），按 op_id 幂等（UNIQUE + INSERT OR
-- IGNORE）。不排序、不合并、不裁决冲突——pull 按 seq 增量转发。
CREATE TABLE sync_oplog (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id TEXT NOT NULL UNIQUE,
    item_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    op TEXT NOT NULL CHECK (op IN ('put', 'delete')),
    lamport INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    timestamp TEXT,                    -- 客户端自报，仅展示，不参与任何排序
    ciphertext BLOB,                   -- put 必有；delete（tombstone）为 NULL
    wrapped_item_key BLOB,             -- 同上
    received_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_sync_oplog_seq ON sync_oplog(seq);
CREATE INDEX idx_sync_oplog_item ON sync_oplog(item_id);
