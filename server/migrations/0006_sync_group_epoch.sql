-- 并发轮换互斥（E2EE_SYNC_DESIGN §11 开放问题 2 收口）：
-- group key 轮换 = 「全组信封族重写 + 全量重包」的多笔写入，两台设备
-- 并发执行会互相覆盖信封、把对方的重包 op 变成全组解不开的孤儿。
-- epoch 是全组轮换代数：rotate-begin 以乐观锁（if_epoch CAS）抢占——
-- 抢到的设备获得互斥窗口写信封，抢不到的收到 409 fail-closed 中止。
-- 只防诚实客户端的意外并发（写入真实性边界不变，见 THREAT_MODEL）。

CREATE TABLE IF NOT EXISTS sync_group_epoch (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    epoch INTEGER NOT NULL DEFAULT 0
);

-- 单行表懒初始化（PUT/POST 路径 INSERT OR IGNORE，避免依赖迁移时点）。
INSERT OR IGNORE INTO sync_group_epoch (id, epoch) VALUES (1, 0);
