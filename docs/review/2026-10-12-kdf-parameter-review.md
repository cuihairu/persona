# KDF 参数季度评审（2026-10-12）

> 依据 `KEY_HIERARCHY.md`「PBKDF2 iteration count and Argon2 parameters
> revisited quarterly」与 `THREAT_MODEL.md`「重新评估 KDF 参数」的既定要求
> 落的首次有记录评审。口径基准：OWASP Password Storage Cheat Sheet
> （cheatsheetseries.owasp.org，2026-10-12 访问，其数值注记 2022-12 基于
> RTX 4000 GPU 实测）：PBKDF2-HMAC-SHA256 建议 **600,000** 次；Argon2id
> **下限 m=19 MiB / t=2 / p=1**；PBKDF2 仅在 FIPS-140 硬约束时选型。

## 评审结论速览

| 路径 | 算法与参数 | OWASP 口径 | 结论 |
| --- | --- | --- | --- |
| 主密钥派生（本地解锁，`core/src/auth/authentication.rs:203`） | PBKDF2-HMAC-SHA256 **100,000** 次 | 600,000 次 | ⚠️ **低于建议 6 倍**——提案升 600k，需用户拍板（见下） |
| 口令验证哈希（`core/src/crypto/hashing.rs`） | Argon2id PHC 串（存量 v19 m=19456,t=2,p=1） | 下限 19 MiB/t=2/p=1 | ✅ 恰在下限；维持，下季度复核 |
| SRP 登录预哈希（`core/src/auth/srp.rs:119`） | Argon2id crate 默认（m≈19 MiB/t=2/p=1） | 下限 | ✅ 恰在下限；维持 |
| 同步组配对短码 KDF（`core/src/sync/pairing.rs:107`） | Argon2id crate 默认 | 下限 | ✅ 维持（短码本身 9 位单次使用，主闸不在 KDF） |
| 导出/备份加密 PERSENC1（`core/src/backup/file_crypto.rs`） | Argon2id m=64 MiB/t=3/p=1 | 下限以上 | ✅ 维持 |
| 钱包 keystore（`core/src/crypto/encryption.rs`） | Argon2 默认 m≈19 MiB/t=2/p=1 | 下限 | ✅ 维持（钱包轨整体冻结中） |

## 发现与提案

### PBKDF2 100k → 600k（提案，不代拍）

- **现状**：主密钥派生用 PBKDF2-HMAC-SHA256 100k（`derive_key_pbkdf2`，
  迭代数是调用点常量）。100k 是 2023 年前的旧口径；OWASP 现行建议 600k
  （1Password 同类产品使用 PBKDF2 650k）。
- **影响面**：每个既有工作区的解锁派生路径。**不能就地改常量**——迭代数
  变更后旧库按新迭代数派生会对不上，必须走 re-wrap 迁移：派生校验成功后
  用旧参数解主密钥 → 新参数重派生 → 重包 item key 包裹层（或引入带迭代数
  的 v2 头格式，逐库在下次解锁时惰性升级），与 `KEY_HIERARCHY.md`「changes
  applied via re-wrap/re-encrypt migrations rather than in place」一致。
- **UX 对价**：解锁延迟约 ×6（当前数十毫秒级 → 预计 0.2–0.4s 级；实施时
  需实机测量并在迁移前给用户预期说明）。
- **决策点（等用户拍板）**：① 是否升 600k；② 惰性升级（下次解锁顺带
  re-wrap）还是显式迁移命令；③ 是否同批把口令验证哈希/SRP 预哈希从
  Argon2id 下限参数上浮（如 m=64 MiB）。
- **拍板前不动代码**：本评审只登记，不实现迁移。

### Argon2id 全部处于 OWASP 下限

机制上合规（下限即「可接受」），但无余量。升级同样需要迁移/重哈希链路，
与 PBKDF2 提案合并拍板更经济。下季度复核前维持。

## 复核节奏

- 下次评审窗口：2027-01（季度）；触发提前评审的条件：OWASP 数值更新、
  新增 KDF 使用点、或接入 FIPS 约束场景。
- 本文档落地后，`KEY_HIERARCHY.md` 的「re-reviewed quarterly」注记追加
  本次评审指针。
