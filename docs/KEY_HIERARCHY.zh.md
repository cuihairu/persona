> [English](KEY_HIERARCHY.md) | **中文**

# 密钥层级

Persona 为每个存储的条目使用独立的随机 item key 进行加密，并用从用户密码派生的主密钥包裹该 item key。这最小化了爆炸半径：单个 item key 泄露无法解密其他任何秘密。

## 流程

1. 通过 PBKDF2（600k 次迭代；本库实际生效的迭代数记录在 `user_auth.kdf_iterations`）从主密码 + 每用户 salt 派生**主密钥**。
2. 创建秘密时，生成一个全新的 32 字节 **item key**。
3. 使用 item key 以 AES-256-GCM 加密载荷。
4. 在主密钥下以 AES-256-GCM 加密 item key，完成包裹。
5. 将 `ciphertext` 与 `wrapped_item_key` 一并持久化到存储。
6. 读取时，用主密钥解包 item key，再解密载荷。

## 代码库中的 KDF 路径

Persona 当前有六条不同的基于密码的 KDF 路径。它们服务于不同用途，不可混用：

| 路径                            | 算法                 | 参数                                                                                   | 使用方                                                                                                                                           |
| ------------------------------- | -------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| 主密钥派生（本地保险库解锁）    | PBKDF2-HMAC-SHA256   | 600,000 次迭代，按库持久化在 `user_auth.kdf_iterations`（migration 021）。该列之前的库读回 100,000，并在下一次解锁时惰性 re-wrap 到现行下限——迭代数是派生输入，必须随库存储而非原地改常量 | `core/src/crypto/keys.rs`（`MASTER_KEY_PBKDF2_ITERATIONS` / `LEGACY_MASTER_KEY_PBKDF2_ITERATIONS`）、`core/src/auth/authentication.rs`（`MasterKeyService::derive_master_key` / `derive_master_key_with_iterations`；包裹 item key）、`core/src/service.rs`（`derive_verified_master_key`）。仅本地——远程认证是下方的 SRP/Argon2id 行，不是 PBKDF2 |
| 导出/备份加密（PERSENC1）       | Argon2id             | m=64 MiB / t=3 / p=1（自定义 `KdfParams::default`）                                    | `core/src/backup/file_crypto.rs`（CLI `--encrypt` 导出、加密保险库备份、travel sidecar——均共享 PERSENC1 格式）                                   |
| 密码哈希校验                    | Argon2（PHC string） | crate 默认参数                                                                         | `core/src/crypto/hashing.rs`                                                                                                                     |
| SRP 登录预 hash（远程设备认证） | Argon2id             | crate 默认参数（m≈19 MiB / t=2 / p=1）；域分隔 salt `persona-srp-v1` ‖ 服务器签发 salt | `core/src/auth/srp.rs`（`derive_srp_secret`——派生作为"密码"喂入 SRP-6a 协议的字节）                                                              |
| 同步组配对短码 KDF              | Argon2id             | crate 默认参数；域分隔 salt `persona-pairing-v1` ‖ 配对 salt                           | `core/src/sync/pairing.rs`（`derive_pairing_secret`——配对短码 → SRP "密码"角色）                                                                 |
| 钱包 keystore 加密              | Argon2id             | crate 默认参数（m≈19 MiB / t=2 / p=1），每密钥随机 salt                                | `core/src/crypto/wallet_encryption.rs`（经 `crypto/encryption.rs` 的 `derive_key_from_password`——包裹钱包私钥）                                  |

注意：钱包 keystore 行（最后一行）与上面的 PERSENC1 是**独立**路径——算法相同，用途与 salt 域不同。两者不可混用。

PBKDF2 迭代次数与 Argon2 参数必须每季度复审（见 `THREAT_MODEL.md`）。提升参数时，应以 re-wrap/re-encrypt 迁移方式应用变更，而非原地修改，使现有行保持可读、legacy 行在下次写入时升级。主密钥迭代数之所以按库持久化，正是出于这个原因：迭代数是派生输入，必须随其包裹的库一起走。

> **最近评审：2026-10-12**（`docs/review/2026-10-12-kdf-parameter-review.md`）：各 Argon2id 路径恰在 OWASP 下限、PERSENC1 在下限以上——均维持；**PBKDF2-HMAC-SHA256 100k 低于 OWASP 现行建议（600k）**，升级走 re-wrap 迁移的提案已登记、等用户拍板，拍板前参数不动。
>
> **最近决策：2026-10-16（已代决）**（`docs/review/2026-10-16-kdf-decision.md`）：① PBKDF2 升 600k；② 惰性升级——下次解锁在同一次事务里 re-wrap 并把 `user_auth.kdf_iterations` 推进到 600k，不做显式迁移命令（旅行模式下暂缓而非拒绝）；③ Argon2id 维持 OWASP 下限、2027-01 季度复核。用户对任一项事后均可推翻。

## Legacy 兼容

缺少 `wrapped_item_key` 的旧行视为 legacy，将直接用主密钥解密。新写入始终使用 per-item key。
