# KDF 参数决策（2026-10-16，已代决）

> 承接 `docs/review/2026-10-12-kdf-parameter-review.md` 的三个待拍板决策点。
> 本次巡检用户已授权代决（卡在待拍板/设计选择/需求取舍/排期的条目按推荐
> 方案直接执行），故不再等拍板；用户对任一项事后均可推翻——推翻方式见末尾。

## 决策 ①：PBKDF2 主密钥派生 100k → 600k（已代决：升）

- **理由**：OWASP Password Storage Cheat Sheet 现行建议 PBKDF2-HMAC-SHA256
  为 600,000 次；100k 是 2023 年前的旧口径，等于安全余量打了六折。同类
  产品（1Password）使用 650k。
- **对价**：解锁派生延迟约 ×6（数十毫秒 → 0.2–0.4s 量级）。主密钥派生只在
  解锁与改密时发生，不在每次操作路径上；桌面/CLI 均可接受。
- **落点**：`core/src/crypto/keys.rs`
  `MASTER_KEY_PBKDF2_ITERATIONS = 600_000`，
  `LEGACY_MASTER_KEY_PBKDF2_ITERATIONS = 100_000`。

## 决策 ②：惰性升级（已代决：下次解锁顺带 re-wrap，不做显式迁移命令）

**为什么必须持久化迭代数**：迭代数是派生输入。旧实现把 100k 写死在调用点，
就地改常量会让所有既有库派生出完全不同的主密钥，`wrapped_item_key` 包裹层
整体解不开——数据级事故。故新增 `user_auth.kdf_iterations`（migration 021），
记录每个库实际生效的迭代数。

**迁移形态**：不新增 CLI 子命令，也不做独立的数据迁移任务。解锁时按
「口令已校验、迭代数低于现行下限」判定，在同一次事务里完成
旧参数派生 → 重包全部 item key / passkey 包裹层 → 本列推进到 600k。理由：

1. 与 `KEY_HIERARCHY.md` 既定原则一致（变更走 re-wrap/re-encrypt 迁移，不
   原地改），且 legacy 行在下次写入/解锁时自然升级；
2. 不需要用户执行任何动作，不存在「升级了但忘了跑迁移命令」的半吊子状态；
3. 事务原子：迭代数与重包同事务提交，不存在「已重包但计数仍旧」的撕裂态。

**边界条件（有意为之，不是遗漏）**：

- **口令与 salt 都不变**：口令验证走 Argon2id（`verify_master_password`），
  与 PBKDF2 迭代数完全无关；盐值按既有「跨口令变更保持稳定」原则不动。所以
  用户无需重设密码、无需记新口令。
- **旅行模式下暂缓**：travel sidecar 里的 key 由旧主密钥包裹，本次重包只覆盖
  在线库。`change_master_password` 对此直接拒绝；本升级选择**暂缓而非拒绝**
  （解锁必须照常可用），升级顺延到退出旅行模式后的下一次解锁。
- **失败即锁死在旧口径**：重包中途失败则事务回滚，迭代数保持旧值，下次解锁
  重试。计数与实际包裹层永不分离——若未来出现非事务写入破坏该不变量，
  解锁会显式报加密错误而非返回错误明文（有测试钉住）。

## 决策 ③：Argon2id 参数不上浮（已代决：维持下限）

口令验证哈希、SRP 预哈希、配对短码、钱包 keystore 均恰在 OWASP 下限
m=19 MiB/t=2/p=1（PERSENC1 已在 m=64 MiB/t=3/p=1），机制上合规、无违规项。
本轮不上浮的理由：下限即 OWASP 的「可接受」档，且 Argon2id 参数变更需要
独立的重哈希链路（哈希格式带参数、需逐口令重算），与 PBKDF2 惰性升级不同质，
合并推进的收益低于新增风险。按季度节奏 2027-01 复核；若届时 OWASP 下限上移
再单独立项。

## 实施与验证

- 迁移：`core/migrations/021_user_auth_kdf_iterations.sql`
  （`DEFAULT 100000`——只对新库无意义、对历史行是正确性关键）。
- 存储往返：`core/src/storage/user_auth.rs`（SELECT ×2 / INSERT / UPDATE /
  行映射），`UserAuth::new()` 写下限值，serde 缺字段回落到 legacy 值。
- 升级路径：`core/src/service.rs` `derive_verified_master_key`（唯一收敛的
  解锁入口 `authenticate_user` 调用）；`change_master_password` 与
  `derive_master_key_for_wrap` 同步切到「存值派生 / 下限派生」拆分口径。
- 回归测试（`cargo test -p persona-core` 1168 passed / 0 failed）：
  legacy 库解锁自动升级且口令、salt、凭据明文均不变；升级后二次解锁无重包；
  新建库带 600k；legacy 库改密同时轮换与升级；计数跨进程重启存活；
  撕裂态解锁 fail-closed；迭代数改变派生密钥；存储往返与列默认值。

## 推翻方式

- 想回退 ① 与 ②：把 `MASTER_KEY_PBKDF2_ITERATIONS` 改回 `100_000` 即可——
  已升级到 600k 的库会按 `derive_verified_master_key` 的下限短路分支回退到
  常量口径，但那些库的包裹层已重包到 600k，回退会让它们解不开。**因此回退
  必须连同 migration 022（把存值重新写回 100k 并反向重包）一起做**，不能只
  改常量。
- 想推进 ③：在 `core/src/crypto/hashing.rs` 与 SRP/配对/钱包各处把参数改到
  目标值，并给存量哈希加重哈希链路（哈希格式已带参数，逐口令重算）。
