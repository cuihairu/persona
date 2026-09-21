-- 整库加密备份的保管元数据（同步第一阶段）。
-- 文件本体在磁盘 {backup_dir}/{id}.persenc：客户端侧 VACUUM INTO 快照
-- gzip 后按 PERSENC1 加密的密文，服务器不可解；本表只存元数据，协议上
-- 不承载明文 secret 或密钥材料（见 docs/THREAT_MODEL.md 备份保管端点）。
CREATE TABLE IF NOT EXISTS backups (
    id            TEXT PRIMARY KEY,          -- server 分配 UUID v4
    device_name   TEXT NOT NULL,             -- 由命中的设备令牌推导，客户端不可自报
    size_bytes    INTEGER NOT NULL,          -- 密文字节数
    sha256        TEXT NOT NULL,             -- 密文 hex 摘要（下载 ETag 与同设备去重键）
    content_path  TEXT NOT NULL UNIQUE,      -- 备份目录内相对文件名 "{id}.persenc"
    created_at    TEXT NOT NULL,             -- RFC3339，server 时钟
    created_at_ms INTEGER NOT NULL           -- created_at 毫秒精度，游标/排序键
);

-- 倒序分页（新→旧）：按 (created_at_ms, id) 稳定游标
CREATE INDEX IF NOT EXISTS idx_backups_order ON backups(created_at_ms DESC, id DESC);
