> [English](WALLET_DESIGN.md) | **中文**

# 钱包密钥层级与签名 — 设计

> 状态：**现状盘点 + 定案**（2026-10-13，M5 钱包毕业轨道）。本文回答四件事：
> 密钥层级（seed ↔ master key 包装）、口令变更的 re-wrap 语义、分身与钱包的
> 绑定模型、签名确认的 UX 与后端策略；威胁模型扩展见
> [THREAT_MODEL.md「钱包（实验轨道）」节](THREAT_MODEL.md)。关联：
> [ROADMAP M5](ROADMAP.md#milestone-5-wallet-graduation-deferred-until-milestone-4-experimental-today)、
> [KEY_HIERARCHY.md](KEY_HIERARCHY.md)（分身保险库层级——钱包是其中注明的
> 独立第六条 KDF 路径）。

**本文与代码的边界**：§1/§2 是现状盘点（已在库中实现）；§2.1/§3/§4/§5 是
**定案**——其中 §3 的 `persona wallet passwd` 与 `EncryptedMnemonic` 重包
**已落地（2026-10-13）**，§5 第 3 条（后端防投毒强制）与桌面 keystore 臂
也已落地（2026-10-13）；§2.1 的 version=2 惰性重包迁移仍待做。定案不
代表已实现，读法以本节标记为准。

## 1. 现状代码地图（盘点，2026-10-13）

| 层             | 位置                                                                                                        | 要点                                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| BIP39 助记词   | `core/src/crypto/wallet_crypto.rs` `SecureMnemonic`（bip39 3.0）                                            | 12–24 词，`to_seed(passphrase)` = BIP39 64 字节 seed                                                                 |
| secp256k1 主钥 | `MasterKey`（bip32 0.6 `XPrv`）                                                                             | `from_seed` → `derive_path` → `to_xpub`；**序列化即 base58 xprv/xpub 字符串**                                        |
| Solana 主钥    | `Ed25519Key`（SLIP-0010 ed25519，自研，仅硬化派生）                                                         | HMAC-SHA512 链；持久化 `(secret, chain_code)` 64 字节；drop 时 zeroize                                               |
| 单钥包装       | `EncryptedWalletKey {version:1, encrypted_data, salt, nonce}`                                               | Argon2id（argon2 crate 默认 m≈19MiB/t=2/p=1，参数不落盘）+ AES-256-GCM（`crypto/encryption.rs`）                     |
| 助记词包装     | `EncryptedMnemonic {version:1, encrypted_phrase, salt, nonce}`                                              | 同上                                                                                                                 |
| keystore v3    | `crypto/wallet_encryption.rs`                                                                               | scrypt(n=2^18,r=8,p=1)/pbkdf2 + AES-128-CTR + keccak MAC；导入 256MiB 内存上限、常数时间 MAC 比较；geth 规范向量锁定 |
| 派生路径       | `recommended_derivation_path`（BTC `m/44'/0'/{a}'/0`、ETH `m/44'/60'/{a}'/0`、Solana `m/44'/501'/{a}'/0'`） | BIP-84/86 目前只是 `BipVersion` 类型与 path builder（测试向量覆盖），**未进默认流程**；BTC 地址生成现仅 P2WPKH       |
| 签名           | `crypto/transaction_signing.rs`                                                                             | ETH EIP-155/1559（alloy）、BTC BIP-143 P2WPKH（rust-bitcoin）、Solana ed25519（调用方供序列化消息）                  |
| PSBT           | `crypto/transaction_psbt.rs`                                                                                | BIP-174 单签 P2WPKH export/sign/finalize（finalize 自写）；CLI `wallet export-psbt/sign-psbt/finalize-psbt`          |

## 2. 密钥层级（定案）

```
BIP39 助记词 ──(BIP39 seed, 可选 passphrase)──▶ 64 字节 seed
      │                                            │
      │ wrap: EncryptedMnemonic                    │ wrap: EncryptedWalletKey
      │ （Argon2id + AES-256-GCM，钱包口令）        │ （同上；HD 钱包容纳 xprv 串）
      ▼                                            ▼
  恢复/迁移面                                MasterKey (bip32 XPrv)
                                                   │ derive_path
                                                   ▼
                                        DerivedKey → 地址 / 签名钥
```

- **seed ↔ master key 的关系是派生而非包装**：master key 从 seed 派生
  （BIP32），存储面包装的是「xprv 序列化串」（HD）或「单钥」（single），
  助记词单独包装一份用于恢复/导出。两个包装用同一钱包口令、同一
  Argon2id+AES-256-GCM 管线（fresh salt/nonce 各自独立）。
- **理由**：不把助记词当作唯一事实源重新派生每一次签名（解锁成本），
  也不把 xprv 当唯一事实源（丢助记词无法恢复）——两者都存、都能独立
  解锁使用，任一损坏另一份仍可恢复全部地址。
- **keystore v3 是互操作出口/入口**，不是存储格式：导出时从解密后的
  私钥再包一层 scrypt/pbkdf2（geth 生态标准），导入时解出私钥后立刻
  走 `import_from_private_key` 的存储包装。两套 KDF 语义不同（生态互操作
  vs 本机存储），刻意不统一。

### 2.1 存储参数的演进约束

`EncryptedWalletKey.version = 1`，KDF 参数取 crate 默认且不落盘——参数
升级（如对齐 OWASP Argon2 推荐值）必须：新增 `version = 2` + 落盘参数 +
惰性重包（读到 v1 就用旧参数解、新参数重包回写），与 KEY_HIERARCHY.md
的 re-wrap 迁移规则同构。禁止原地改默认参数（会让旧数据解不开）。

## 3. 口令变更与 re-wrap（定案）

现状（2026-10-13 盘点）：

- `change_wallet_password(encrypted_key, old, new)` 存在（解旧密→新
  salt/nonce 重包）；对称的 `change_mnemonic_password` 已补（2026-10-13），
  两者由 CLI `persona wallet passwd` 作为生产调用方串起。
- 主密码轮换 `change_master_password → rewrap_all_item_keys` 只覆盖
  credentials/passkeys 的 item key；`crypto_wallets` 表的包装物
  **刻意不动**：钱包口令是独立于主密码的第二要素，主密码泄露不应
  直接等于资金材料泄露（爆炸半径隔离，与 1Password 的 wallet password
  独立语义一致）。这是设计决定，不是缺口。

定案：

1. **钱包口令保持独立于主密码**（签名/导出时输入；`validate_wallet_password`
   试解密校验）。
2. **新增 `persona wallet passwd`**（**已实现 2026-10-13**）：一个操作里
   同时 re-wrap `encrypted_private_key` 与 `encrypted_mnemonic`——复用
   `change_wallet_password` 并为 `EncryptedMnemonic` 补对称的
   `change_mnemonic_password`（均 fresh salt/nonce）。写回顺序：先解旧密
   重包两份材料（任一步失败即中止，原行不动，不产生半写），成功后才
   `repo.update` 写回。旧口令与签名同源（交互走 prompt，非交互
   `PERSONA_WALLET_PASSWORD`）；新口令仅交互输入（与 `persona passwd`
   同规：无环境变量覆盖，陈旧环境变量不能静默轮换口令），带确认
   prompt、须异于旧口令且 ≥8 字符；watch-only 钱包拒绝（无材料可重包）。
3. **不随主密码轮换**：`change_master_password` 对 `crypto_wallets`
   不动作继续成立；文档在此与 THREAT_MODEL 钱包节同时声明。

## 4. 分身绑定模型（定案）

- `CryptoWallet.identity_id` 外键指向 `identities` 行：钱包属于一个分身，
  不属于工作区；列钱包按分身过滤，`watch_only` 钱包同样落在此模型
  （无 `encrypted_private_key`，仅 xpub）。
- **激活语义沿用现状**：`persona switch` 只切分身指针，不解锁钱包、
  不改钱包可见性；签名始终需要钱包口令（或桌面 item password 二要素
  `wallet_set_item_password`）。
- **上下文建议轨道不作用于钱包**（v1）：suggest 的候选是分身，不是
  钱包；钱包选择永远是显式动作（`--wallet` / 桌面下拉）。
- 同一分身可挂多链多钱包；删除分身时钱包行级联（现状
  `wallet_repository` 语义保持）。

## 5. 签名确认 UX 与后端策略（定案）

不变量（后端强制，UI 只是展示层）：

1. **先验证后持久化**：ETH/Solana 签名后本地验证
   （`verify_ethereum_transaction` / `verify_solana_transaction`，含
   recover-to-address 比对），失败一律不落库；BTC 组装失败降级为
   仅审计记录（`audit:<sha256>`），绝不产出可广播假象。
2. **确认面板必列**：from（签名地址全文）、to（全文 + EIP-55 校验和）、
   金额 + 精度、费用（gas × price 或 fee rate）、chain id（EVM）、
   网络。缺任何一项不允许提交签名。
3. **防投毒启发式后端化**（**已实现 2026-10-13**）：core
   `crypto/address_poisoning.rs` 的 `detect_address_poisoning`（首 6 + 末 6
   字符相同、中段不同，大小写不敏感，按字符切分永不 panic）+
   `enforce_poisoning_check`（命中且未确认即拒签）在后端签名入口强制：
   CLI `create-transaction --sign` 检查在口令 prompt 之前，命中需显式
   `--confirm-poisoning-check`；桌面 `wallet_sign_transaction` 同样强制，
   确认弹窗展示告警后用户二次确认才带 `confirm_poisoning_check` ack
   （serde default false，旧前端缺字段按未确认拒绝）。已知地址集合 =
   钱包全部地址（本实现口径）；「+ 用户标记」仍开放。
4. **口令不离面板**：桌面口令在 modal 内输入、`finally` 清理；CLI 走
   标准口令 prompt；两者都不落日志（脱敏策略已有测试）。
5. **审计**：每次签名记录 digest 级摘要（to/amount/fee/chain id hash），
   与 SSH 签名同粒度。

CLI 与桌面共用 `signing_key_for_address → sign_transaction → verify →
persist` 链；策略差异只在确认形式（桌面 modal vs CLI 提示），验证与
审计不变量两端一致。

## 6. 威胁模型扩展

见 [THREAT_MODEL.md](THREAT_MODEL.md)「钱包（实验轨道）」节：钱包密钥
列为最高级资产、导出面（keystore/WIF/明文 JSON）单独列边界、实验性
声明与升级路径。本文 §2.1/§3 与该节互相引用。

## 7. 开放问题（需拍板，不在本轮做）

- **硬件钱包**（Ledger/Trezor）：`WalletType::Hardware` 类型已预留；
  是否进主线待用户裁定（ROADMAP M5 open question）。
- **PSBT 工作流**：**单签切片已落地（2026-10-13）**——`export-psbt` /
  `sign-psbt` / `finalize-psbt`（BIP-174，单签 P2WPKH，core
  `crypto/transaction_psbt.rs`；finalize 自写，rust-bitcoin 无 finalizer；
  直签与 PSBT 路径产物字节级一致由回归锚锁定）。仍开放：多方
  `Psbt::combine` 合签、桌面 UI 臂。
- **桌面端 keystore 臂**：~~`import_wallet_from_request`/`export_wallet_from_request`
  尚无 keystore 分支~~ **已补齐（2026-10-13）**：桌面 `wallet import/export`
  均支持 `keystore`（导出 geth 默认参数；导入解出私钥后走存储包装），
  WalletPanel 表单与格式下拉同步。
- BIP-84/86 地址形态进默认流程（现仅 P2WPKH）。

## 8. 测试盘点（回归锚点）

- geth keystore 规范向量（scrypt n=2^18/r=1/p=8 官方测试向量，密文/
  MAC/地址三重断言）+ OpenSSL 跨语言 KDF 钉版（scrypt/pbkdf2 各一）。
- EIP-155 签名规范向量、BIP-143 P2WPKH 逐字节向量、SLIP-0010 ed25519
  官方向量、BIP-84/86 path builder 向量（builder 层）。
- 口令变更：`test_password_change`（旧密失效、新密可用、密文独立）；
  `mnemonic_password_change_rewraps_with_fresh_salt`（对称语义 + fresh
  salt/nonce + 错旧口令拒绝）；CLI `persona wallet passwd` 集成 4 例
  （双 blob 轮换后新口令可解/旧口令失效且 salt/nonce 已换、错旧口令
  报错且原行不动、watch_only 拒绝、同口令/弱口令拒绝）。
- PSBT：`psbt_roundtrip_matches_direct_signing`（直签 vs
  export→sign→finalize 字节级一致，RFC-6979 确定性锚）；export 确定性/
  可反序列化/字段完备 + txid 不变量；signed 逐输入 partial_sigs 形状 +
  幂等重签；异钥拒绝（sign）；未签/异钥签名集拒绝（finalize）；magic
  校验 + inputs metadata 契约复用；CLI 集成 3 例（roundtrip wiring、
  防投毒/网络门、watch-only·异钥·坏 base64 拒绝）。
- 篡改路径：keystore 密文篡改 MAC 拒绝、超大 scrypt work factor 拒绝、
  不支持 KDF/cipher/prf 拒绝。
- 防投毒：core 启发式 7 例（命中/同址豁免/部分匹配拒绝/base58 保守/
  大小写不敏感/非 ASCII 不 panic/确认放行）+ CLI 集成（未确认拒绝、
  确认后放行）+ 桌面命令层（缺 ack 拒签不落库、带 ack 正常签名落库）
  - 弹窗 jest（干净地址 ack=false、仿冒地址 ack=true）。
