-- Migration 021: persist the PBKDF2 iteration count used for master-key
-- derivation (docs/review/2026-10-16-kdf-decision.md, 已代决).
--
-- 为什么必须持久化：迭代数是派生主密钥的输入之一，改了迭代数、同一口令派生
-- 出的密钥就完全不同。常量此前写死在调用点（100k），就地改常量会让所有既有
-- 库的主密钥对不上、item key 包裹层整体解不开——数据级事故。
--
-- 存量行的取值：DEFAULT 必须是**升级前的旧口径 100000**。这样：
--   * 迁移前创建的库 → 读回 100000 → 解锁时按旧迭代数派生 → 旧包裹层解得开；
--   * 解锁成功后若旧值低于现行下限（600000），service 在内存里惰性
--     re-wrap（re-wrap 用新迭代数派生的密钥，口令与 salt 都不变）并把本列
--     推进到 600000，下次解锁直接走新口径。
--   * 新建库 → INSERT 显式写 600000。
-- 新库不会读到 DEFAULT，所以 DEFAULT 只对历史行有意义。

ALTER TABLE user_auth ADD COLUMN kdf_iterations INTEGER NOT NULL DEFAULT 100000;
