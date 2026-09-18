-- persona-server 独立事件存储。
-- 与 core 身份库 schema 无关：本表只承载客户端上报的审计事件摘要
-- （action、资源类型、可选 ID、时间戳、成功标记），协议上不承载
-- 明文 secret 或密钥材料（见 docs/THREAT_MODEL.md 可选服务端边界）。
CREATE TABLE IF NOT EXISTS audit_events (
    id               TEXT PRIMARY KEY,          -- server 分配 UUID v4
    client_event_id  TEXT,                      -- 客户端幂等键（可空）
    user_id          TEXT,
    identity_id      TEXT,                      -- UUID 字符串
    credential_id    TEXT,                      -- UUID 字符串
    session_id       TEXT,
    action           TEXT NOT NULL,             -- core AuditAction 的 snake_case 串
    resource_type    TEXT NOT NULL,             -- core ResourceType 的 snake_case 串
    resource_id      TEXT,
    ip_address       TEXT,                      -- 客户端自报，不可信
    user_agent       TEXT,                      -- 客户端自报，不可信
    success          INTEGER NOT NULL CHECK (success IN (0, 1)),
    error_message    TEXT,
    metadata         TEXT NOT NULL DEFAULT '{}',
    client_timestamp TEXT NOT NULL,             -- RFC3339，客户端时钟（仅参考）
    received_at      TEXT NOT NULL,             -- RFC3339，server 时钟
    received_at_ms   INTEGER NOT NULL           -- received_at 毫秒精度，游标/排序键
);

-- SIEM 拉取：按 (received_at_ms, id) 稳定游标翻页
CREATE INDEX IF NOT EXISTS idx_audit_events_order ON audit_events(received_at_ms, id);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_events_received_at ON audit_events(received_at);

-- 幂等去重：仅对非空 client_event_id 唯一；
-- 配合 INSERT ... ON CONFLICT(client_event_id) WHERE client_event_id IS NOT NULL DO NOTHING
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_events_client_event_id
    ON audit_events(client_event_id) WHERE client_event_id IS NOT NULL;
