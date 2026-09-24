# E2EE 同步设计稿（阶段 0）

> 状态：**设计稿，未实现**。本文是 TODO「第 3 步」（Connect endpoint + E2EE sync +
> SRP 设备认证）的开工文档：把四个必须先拍板的设计决策定下来，并给出实施阶段
> 映射与威胁模型登记骨架。实现按 §10 的阶段逐个落地，每阶段独立 PR 粒度。
>
> 相关文档：[`ROADMAP.md`](./ROADMAP.md) Milestone 6、[`REMOTE_AUTH.md`](./REMOTE_AUTH.md)
> （既有 SRP 抽象与 mock）、[`STORAGE_AND_SYNC.md`](./STORAGE_AND_SYNC.md)（用户视角
> 的现状）、[`THREAT_MODEL.md`](./THREAT_MODEL.md)（「备份保管端点」与「Travel Mode」
> 的诚实边界先例）。

## 1. 目标与非目标

**目标**

1. 多台设备对**同一 Persona 工作区**做凭据级增量同步；服务器只见密文与最小元数据。
2. 同步层与主密码**解耦**：换主密码是纯本地操作，不触发全网重包。
3. 设备加入/移除有明确流程；移除的爆炸半径诚实登记（见 §9）。
4. 复用既有资产：per-item key 信封结构、server 骨架、`RemoteAuthProvider` 抽象、
   fail-closed 惯例、备份保管链（不打断它）。

**非目标（第一阶段明确不做）**

- **CRDT / 字段级合并**：凭据是原子整体，冲突保双版本供用户裁决（§7）。
- **防恶意/被攻破服务器的篡改与回滚**：与备份保管同一边界——客户端不做新鲜度
  校验，不宣称防服务器操作者。
- **设备私钥签名 oplog**（防服务器伪造历史）：远期项，见 §11。
- **附件文件体同步**：v1 只同步库内行数据；附件走既有备份通道（其 v1 边界一致）。
- **移动端**：desktop 与 CLI 先行，mobile FFI 不动。

## 2. 信任模型

- **信任根 = 主密码 + 每设备私钥**。解锁本地库靠主密码；解开同步密文靠设备私钥
  （拆 group key 信封）→ group key → item key。二者独立存放、独立轮换。
- **服务器定位 = 纯中继 + 密文保管**。它存储 oplog、设备公钥、信封，但不持有
  任何能解密同步数据的密钥；不承担合并裁决（裁决在客户端，§7）。
- **服务端可见面**（完整清单见 §9）：密文载荷、item 的 UUID、类型枚举、Lamport
  计数、时间戳、设备公钥、信封尺寸。**无任何明文名称/URL/用户名**——同步条目把
  元数据也封进密文区，可见面严格小于本地 SQLite（后者元数据列是明文，
  STORAGE_AND_SYNC 已如实说明）。

## 3. 决策记录

### DR-1 设备密钥：独立生成，存 OS keyring（否决：主密码派生）

每台设备在**加入同步时生成一次性 X25519 密钥对**：私钥 32 字节随机数存 OS
keyring（service 名 `persona-device`，与既有 `persona-biometric`/`persona-sync`
并列）；公钥随设备注册上服务器。

- **为何不派生自主密码**：派生意味着换主密码 = 每台设备的公钥全变 = 全部信封
  重包 + 全设备重注册——把「换密码」从本地操作升级成全网迁移。设备身份密钥是
  长期凭证，不应与可更换的认证口令耦合（1Password 的账户密码与设备 Secret Key
  分离是同款思路）。
- **keyring 缺失的 fallback**（headless CLI/容器）：经显式 `--device-key-file`
  落盘 0600 文件，命令输出红色警告「该文件等同设备私钥，泄露即设备被冒用」。
  无 keyring 又不给文件参数 = 同步功能不可用（fail-closed，不静默生成临时密钥）。
- **密钥丢失** = 该设备身份作废：重新走加入流程即可，不牵连其他设备。
- **算法与依赖**：`x25519-dalek`（dalek 家族，公开审视充分）+ `hkdf`（RustCrypto，
  与已有 `sha2` 配套）+ 既有 `aes-gcm`。信封格式（`persona-dev-env-1`）：
  `ephemeral_pub(32) ‖ AES-256-GCM(key = HKDF-SHA256(x25519(eph, device_pub),
info="persona-dev-env-1"), plaintext = group key)`。组合层自写约 30 行，
  round-trip + 篡改 + 跨设备失败路径测试覆盖；不为此引入 HPKE 重依赖（远期可选）。

### DR-2 设备认证：SRP-6a + RFC 5054 4096-bit group 起步（OPAQUE 列远期升级）

实化 `core/src/auth/remote.rs` 的 `RemoteAuthProvider`（现为 129 行纯 mock）：

- **协议**：SRP-6a，RFC 5054 4096-bit group（有官方测试向量，跨实现互通）。
  数学走 RustCrypto `srp` 0.6（`core/src/auth/srp.rs` 封装），握手哈希 SHA-256；
  实现正确性由 RFC 5054 附录 B 官方向量（1024-bit/SHA-1 interop 向量）锁定。
- **防 verifier 泄露离线爆破**：客户端先对「主密码 ‖ 域分隔盐
  （`persona-srp-v1` ‖ 服务器 salt）」做 Argon2id（Argon2id v19，m=19 MiB、
  t=2、p=1——与本地库解锁 KDF 同参数，即 argon2 crate 默认；较备份文件
  KDF 的 64 MiB/t3 轻，因登录路径高频执行）得到 SRP 私钥 x——服务器存的是
  SRP verifier，泄露后离线猜解的成本 ≈ Argon2 成本，与本地密码验证同级。
- **会话**：SRP 握手成功 → 双方派生会话密钥 → 客户端用它换取短期 access token
  （TTL 分钟级），后续请求 `Authorization: Bearer`。锁户对齐本机 5 次语义。
- **兼容硬约束**：既有 `PERSONA_SERVER_TOKENS` Bearer 路径**保留共存**——备份链
  （push 无需解锁主密码）与事件上报不打断；SRP 是同步端点的认证方式，不是
  全端点的前置改造。
- **crate 现状（2026-09 调研，选型依据）**：RustCrypto `srp` 0.6 可用但维护缓慢
  （PAKEs 仓库标注 "USE AT YOUR OWN RISK"，0.7 停在 rc）；活跃替代有 `srp6-rs`。
  应对：实现走 `RemoteAuthProvider` seam、锁定具体 crate 版本 + **RFC 5054 官方
  测试向量做回归**，换实现不动调用方。**OPAQUE（`opaque-ke` 4.x，RFC 9807 已
  定稿、防服务器模拟攻击且 verifier 不可离线爆破）列为远期升级**——实现重、
  依赖链深，等同步链路稳定后评估；seam 层已为此留位。

### DR-3 信封方向：组密钥层级（否决：逐 item 逐设备收件人列表）

- **同步组密钥（group key）**：随机 256 位，工作区一份，**永不明文离开设备**——
  在服务器上只以「设备信封」形态存在（每台设备一个，用该设备 X25519 公钥包裹，
  DR-1 格式）。
- **同步条目**：`{密文载荷（item key 加密）, item key 信封（group key 包裹）}`。
  与本地行的唯一差别是包裹密钥：本地 `wrapped_item_key` 是 master key 包的
  （`key_hierarchy.rs`），传输版是 group key 包的——**同步格式因此与主密码彻底
  解耦**（换主密码只影响本地包裹，DR-1 的派生方案若被采纳则无此优点）。
- **新设备加入 = O(1) 重包**：任一现有设备拆出 group key → 用新设备公钥包一个
  新信封上传。否决逐 item 收件人列表（N 设备 × 全部 item 的信封膨胀）的原因
  在此——1Password 的 vault key 层级是同款结构。
- **设备移除的诚实边界**：被移除设备已知道 group key，**已同步历史的密钥不可
  追溯撤销**。真正的移除 = 手动触发「安全轮换」（rotate group key + 全量重包 +
  各设备重新拉取），已于 2026-09 阶段 3d 落地（`SyncSession::rotate_group_key`：
  先以服务器 epoch 乐观锁抢占互斥（rotate-begin，2026-09-24，见 §11-2）→
  drain 旧组密文上线 → 为每个仍授权设备重封新信封 → 全量重包推空；
  桌面「轮换组密钥」入口 + 诚实边界确认文案）。吊销与轮换分离：第一阶段
  只做「吊销该设备的认证与访问」，轮换是事后手动的一步。

### DR-4 冲突解决：LWW + 客户端 Lamport 时钟（否决：服务器裁决 / CRDT）

- **全序**：每条 item 携带 `(lamport: u64, device_id: u128)`。本地写 = 本机
  lamport + 1；pull 时本机 lamport = max(本机, 收到值)。比较：lamport 大者赢；
  相等则 device_id 字典序定胜负——**两端独立计算结果必然一致**。
- **时钟来源**：只信客户端 Lamport 计数，不信任何服务器/墙钟；时间戳仅展示。
- **真冲突**：同一 item 两个版本 lamport 相同且来自不同设备（离线双编辑典型
  形态）→ **保双版本**：胜者占主位，负者以「冲突副本」入同 item 的冲突区
  （`conflict_of` 字段），用户在 UI 裁决合并或取舍（裁决 UI 属阶段 3；阶段 2
  core 层先保证双版本不丢、不静默覆盖）。
- **删除 = tombstone**：删除记墓碑条目（含 lamport），防止离线删除被旧版本
  复活；墓碑按保留策略惰性清理。
- **服务器角色**：只存 oplog、按游标转发，**不做任何胜负判定**——与「服务器
  不可信」一致；让服务器裁决意味着把合并语义交给一个我们拒绝信任其诚实的组件。

## 4. 密钥层级（全图）

```
主密码 ──Argon2id──> master key ──包──> item key ──加密──> 本地载荷与元数据   （本地存储，现状不变）
                     (验证: Argon2 哈希)    │
                                            └──加密──> 附件文件体            （现状不变）
group key（随机 256b，不落盘不明文上服务器）
  ├──包──> item key（同步传输格式）
  └──被每设备 X25519 公钥包──> device envelope（服务器存这个）
设备私钥（X25519，随机生成，keyring persona-device / 0600 文件 fallback）
主密码 ──Argon2id──> SRP x ──SRP-6a 握手──> 短期 access token              （认证层，DR-2）
```

## 5. 同步协议

**oplog 条目**（服务器逐条存储，独立于 change_history——那是本地审计，含明文
元数据，永不直接上同步通道）：

```
SyncOp {
  op_id: uuid,          // 幂等去重键
  item_id: uuid,
  kind: enum,           // credential | identity | passkey | …
  op: put | delete,     // delete 时 payload 为空（tombstone）
  lamport: u64,
  device_id: uuid,
  timestamp: rfc3339,   // 仅展示，不参与排序
  payload: Option<{ ciphertext: bytes, wrapped_item_key: bytes }>,  // 全密文
}
```

**端点**（挂现有 axum server，`/api/v1/sync/*`，认证 = DR-2 的 SRP 会话 token）：

| 端点                       | 方法                | 用途                                               |
| -------------------------- | ------------------- | -------------------------------------------------- |
| `/sync/devices`            | POST / GET / DELETE | 注册（公钥+设备名）/ 列出 / 吊销                   |
| `/sync/group-keys`         | GET / PUT           | 取全部设备信封 / 上传本设备的 group key 信封       |
| `/sync/oplog`              | POST                | push 本地新 oplog 段（≤500 条/批，沿 events 惯例） |
| `/sync/oplog?since=cursor` | GET                 | pull 增量（游标分页）                              |

**推送/拉取语义**：push 按 `op_id` 幂等；pull 从 since 游标起增量。服务端按到达
顺序追加存储，不排序、不合并（DR-4）。配额/上限沿用 server 既有 1 MiB/批、
解压 10 MiB 防线。

**捕获点**：在 service 层写路径（与 change_history 相同的调用点）同步生成
oplog——元数据明文只留在本地 change_history，oplog 只持有 §5 的密文结构。

## 6. 设备生命周期

- **注册**：生成 X25519 对（DR-1）→ SRP 登录 → `POST /sync/devices`（公钥 +
  设备名）。新设备此时**还读不到 group key**——处于「待授权」。
- **自举**（2026-09 阶段 3c 补）：全新服务器上不存在「既有设备」可代为
  授权——第一台设备 join 时若 `GET /sync/group-keys` 为空，本机生成
  group key 并自封信封上传（`bootstrap_group_if_empty`）。令牌持有者
  本来就能读全部密文，自建组不放大信任面。已知边界：两台设备在彼此
  可见前先后见到空组会各自建组，重复一侧 leave 重走即可。
- **授权**：任一既有设备拆出 group key，为新设备包信封并上传（桌面给设备管理
  页一行确认；CLI 给 `persona sync authorize` 类命令）。未授权设备 pull 不到
  group key，也解不开任何条目——fail-closed。
- **吊销**：设备管理页/CLI 删除该设备：服务器删其公钥与信封，级联删除
  同名 SRP 登记并**即刻吊销**其已签发的短期令牌与未决握手（2026-09 吊销
  闭环——被吊销设备无法用既有凭证继续认证/推送，而非等 TTL 自然过期）。
  前向边界见 DR-3（诚实提示文案照 THREAT_MODEL 风格；历史密文由
  「轮换组密钥」闭环）。
- **恢复**：设备丢失 = 在别处吊销它 + 本机重新走注册授权。主密码不参与设备
  密钥的恢复（无托管原则一致）。

## 7. 冲突解决（操作序）

pull 应用顺序：按 (lamport, device_id) 降序入库；同 item 遇到 lamport 相等但
device 不同的第二条 → 降级为冲突副本（`conflict_of` 指向主位），UI 展示双版本。
合并动作 = 用户在副本上选择字段后「采纳」，产生新 lamport 的 put。**不丢数据、
不静默覆盖**是底线；全自动合并明确不做（§1 非目标）。

## 8. 与既有系统的边界

| 既有资产                                                      | 关系                                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 备份链（`/api/v1/backups`、PERSENC1）                         | **不动**。备份是整库快照，同步是凭据级增量；token 共存（DR-2）。恢复整库备份后，本机以 Lamport 重新对齐（备份点之后的远端 oplog 重放）                                                                                                                                                     |
| `change_history`                                              | 本地审计，含明文元数据，**不上同步通道**；oplog 是独立写入（§5 捕获点）                                                                                                                                                                                                                    |
| 审计事件上报（WireEvent）                                     | 元数据级、本来就不含载荷，与同步无耦合，各走各的                                                                                                                                                                                                                                           |
| **Travel Mode**                                               | **同步在 travel 激活期间必须整体暂停（push 与 pull 双停）**：enter 事务的批量删除若进 oplog，会把 tombstone 推到其他设备毁库；pull 则可能把被移出身份写回主库，直接违反「主库零痕迹」。exit 恢复后需手动/提示恢复同步。此交互列入 §11 首位开放问题，阶段 2 实现时落地为 push/pull 的前置闸 |
| 桌面 keyring 双 service（`persona-biometric`/`persona-sync`） | 新增 `persona-device`（DR-1），三 service 并列，语义同款：真值在 keyring，库里只留占位                                                                                                                                                                                                     |

## 9. 服务端可见面与威胁模型登记骨架

`THREAT_MODEL.md`「E2EE 同步中继」章已按本骨架写实（2026-09，阶段 2 批 1–4
落地）。骨架存档：

- **信任根**：主密码 + 设备私钥（§2）。
- **服务端定位与可见面**：纯中继；可见 = 密文、item UUID、kind、lamport、
  时间戳、设备公钥、信封（含尺寸侧信道——诚实登记：条目大小可被服务器观察）。
- **不宣称**：防服务器篡改/回滚/扣留（与备份保管同款）；设备移除的前向安全
  （DR-3）；防恶意服务器无限灌 oplog（配额缓解，不根除）。
- **设备被攻破的爆炸半径**：该设备私钥 → group key → **全部同步数据**（与
  「本机被攻破 = 本库全失」同级，不因同步而放大额外资产——每台设备本来就能
  解全库）。

## 10. 实施阶段映射

| 阶段      | 内容                                                                                                                              | 验收要点                                                                                                       | 威胁模型登记                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------- | --------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0（本文） | 设计稿                                                                                                                            | 四决策定稿 + 用户确认                                                                                          | 骨架（§9）                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 1         | SRP 设备认证：实化 `RemoteAuthProvider`、server 存 verifier（非密码哈希）、SRP 会话换短期 token、与 TOKENS Bearer 共存、锁户 5 次 | RFC 5054 测试向量回归；备份链回归（token 共存不打断）；跨端（CLI↔server）握手集成测试                         | **全流程已落地 2026-09**：服务端 `server/src/api/auth.rs` + 客户端 `core/src/auth/remote_http.rs`（feature `remote-auth`；mock trait 留作 UI seam，真实客户端为独立类型，见 REMOTE_AUTH「Real implementation」）；跨端集成测试 `http_provider_full_round_trip_over_real_tcp`（真 TCP 全流程 + SRP token 过 require_bearer）；THREAT_MODEL「SRP 设备认证端点」章                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| 2         | E2EE sync 核心：device envelope（DR-1 格式）、group key 层级、oplog push/pull、LWW+冲突双版本、travel 闸                          | 服务端只见密文的断言测试；断网/重放/乱序容错；换主密码后同步零影响；两端收敛测试（含双端离线编辑冲突保双版本） | **核心已落地 2026-09（批 1–4）**：密码层 `core/src/sync/{keys,envelope}.rs`（group key/设备密钥对/`persona-dev-env-1` 信封）、oplog + LWW/冲突双版本 `core/src/sync/oplog.rs`（DR-4；`conflict_of` 偏差——冲突区由 `item_view` 从 op 集合推导，不落快照列，append-only 免维护）、本地同步存储 `core/src/storage/sync_repository.rs`（014 迁移：oplog/push 队列/游标/时钟）、服务端中继 `server/src/api/sync.rs` + 0004 迁移（设备/信封/oplog 表，`/api/v1/sync/*`）、客户端引擎 `core/src/sync/engine.rs`（push/pull 周期 + Lamport 时钟 + travel 闸）与 `sync/remote.rs`（HTTP wire，cfg `remote-auth`）。验收对应：服务端只见密文（`server_stores_only_ciphertext`）；重放幂等（op_id 双端去重 + INSERT OR IGNORE）；乱序容错（LWW 全序回放顺序无关，`batch_is_order_independent`）；换主密码零影响（引擎全链路无主密码参数，状态全在库，重建实例续用——收敛测试内构造性证明）；两端收敛（`two_devices_converge_over_real_tcp_conflict_keeps_both_versions`：真 TCP，双端同 lamport 离线编辑 → 收敛同一主位 + 双版本密文都在）；travel 闸（`travel_gate_stops_push_and_pull_both`）。THREAT_MODEL「E2EE 同步中继」章 |
| 3         | 端到端接线：desktop 设备管理页 + 冲突裁决 UI + `STORAGE_AND_SYNC.md`「当前没有凭据级实时同步」整节重写                            | 双设备真机同步演示脚本；吊销流程 UI 走查；文档与实现一致                                                       | 复查 §9 清单与实现相符                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 4         | Connect endpoint：本机 127.0.0.1 HTTP API + scope token（形态 A），默认关闭 fail-closed                                           | 越权/越 scope 拒绝测试；默认关闭断言                                                                           | 新章「自动化端点」                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |

规模预估：10–12 个会话量级，每阶段独立 PR。

## 11. 开放问题

1. **Travel Mode × 同步**（§8）：暂停是够用的答案吗？enter 前是否强制一次
   最终 flush？多设备同时 travel 的语义（两台各自移出不同身份再恢复）？
2. **安全轮换**——**v1 已落地**（2026-09 阶段 3d）：`SyncSession::rotate_group_key`
   （换信封 + 全量重包，§11 语义的字面实现）+ 桌面「轮换组密钥」入口。
   诚实边界已登记于 DR-3 与用户文档：窗口内未推送改动、未裁决冲突副本清出
   视图。**并发轮换已收口**（2026-09-24）：`POST /sync/group-key/rotate-begin`
   以 epoch 乐观锁为「写信封族 + 全量重包」抢占互斥——CAS 命中（epoch ==
   if_epoch）则 epoch +1 并获得写信封窗口，未命中返回 409（客户端映射
   `PersonaError::ConcurrentConflict`，desktop 错误码 `CONCURRENT_CONFLICT`），
   后到者未写信封未重包、干净中止，重读状态后重试即可。epoch 随
   GroupKeysResponse 下发（serde default 0 兼容老服务器——从未轮换语义
   一致，最多多一次误报 409 后重读，方向安全）。**只防诚实客户端的意外
   并发，不防恶意绕过 begin 直接写信封**（写入真实性属开放问题 6 远期
   边界）。**仍开放**：轮换中途崩溃的续跑/恢复（当前重试即重跑，幂等面 =
   信封 upsert + 重包以主库为准；begin 后崩溃留下的信封混合态，重试以新
   epoch 重跑 begin 后整体重写，自愈）。
3. **oplog 增长与墓碑保留策略**——**客户端半边已落地**（2026-09-24）：
   `SyncSession::gc_oplog`（每个同步周期尾部自动运行）按安全谓词清理已消费
   的历史：保护集 = push 未 ack 的 op（推数窗口）、未裁决冲突副本、主位 put；
   可清集 = acked 的旧版本 + ack 且超过 tombstone 保留窗口（默认 30 天，
   `default_tombstone_retention`；timestamp 缺失保守不清）的主位墓碑。裁决
   采纳以更大 lamport 重新入账，败方自动落出副本集、无需 GC 特判；被清 op
   在游标重置重拉时按 op*id 幂等重建，视图不变（谓词矩阵见 runtime 测试）。
   ——**server 半边同日落地**（2026-09-24）：
   `PERSONA_SERVER_OPS_RETENTION_DAYS` / `PERSONA_SERVER_EVENTS_RETENTION_DAYS`
   （0 = 不清理，默认保持纯中继现状；push/ingest 写路径滚动执行，
   `persona*{sync_ops,events}\_pruned_total` 计数）。oplog 窗口语义 =
   放弃向「离线超过窗口」的设备补发历史的责任：游标重置重拉拿到缩水
   子集（LWW 对子集仍收敛），缺失部分靠各端本地事实源 + 重推幂等重建
   （INSERT OR IGNORE 原样回填）补齐——**窗口须 ≥ 最慢设备的离线周期**；
   events 窗口按部署方 SIEM 摘取周期定。**开放问题 3 至此两端收口**，
   剩余为运维参数调优而非机制缺口。
4. **附件同步**：v2 议题——文件体走 oplog（信封化分块）还是保持备份通道，等
   v1 落地后按真实需求定。
5. **OPAQUE 升级路径**（DR-2）：`opaque-ke` 4.x/RFC 9807 成熟度已足够，若同步
   上线后出现 verifier 泄露场景的真实担忧，按 seam 迁移。
6. **设备私钥签名 oplog**（防服务器伪造/回滚历史）：需要 Ed25519 第二密钥，
   远期随「安全轮换」一并评估。
