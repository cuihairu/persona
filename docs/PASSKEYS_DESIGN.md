# Persona Passkeys (WebAuthn) 设计

状态：设计稿（待评审） · 日期：2026-09-13 · 对应路线图：Milestone 4「1Password Parity」

## 1. 背景与目标

Passkey 是 WebAuthn/FIDO2 的可发现凭据（discoverable credential）：每个 relying party（RP，即网站）一对 ES256 密钥，私钥不出验证器。1Password/Bitwarden 的做法是把自己实现为**软件验证器**：私钥加密存在密码库里，随库同步，浏览器侧拦截 `navigator.credentials` 并用库中私钥完成注册/断言。

Persona 的目标：把 passkey 作为一种身份材料（identity material），与密码、TOTP、SSH key 同等对待——身份域隔离、per-item key 加密、可审计、浏览器无感填充。

v1 覆盖：
- 存储模型 + CLI 全生命周期（create/list/show/remove、自检 sign/verify）
- 浏览器扩展拦截 WebAuthn 注册/认证流程，经桥接协议在 core 完成签名
- 与 webauthn.io 等真实站点互通

## 2. 非目标（v1）

- **不做 OS 级 passkey provider**（macOS Credential Provider / Windows passkey plugin）——这是 Phase 4，需要原生壳工程
- 不支持 conditional mediation（浏览器自动填充 UI 对扩展不可见，v1 用显式选择 UI）
- 不做跨设备混合传输（caBLE/hybrid）：Persona 是本机软件验证器，无需跨设备
- 不实现 CTAP2 USB/NFC/BLE 传输层：不扮演硬件 key
- 不做 attestation（att fmt = `none`；`packed` self-attestation 留作可选）
- 不承诺 passkey 跨管理器导出：FIDO 凭据交换协议（CXF）尚未定稿，设计保留字段但暂不实现

## 3. WebAuthn 最小知识集（与实现直接相关的部分)

一个 passkey 由这些字节组成，全部有规范定义、全部可测：

| 成分 | 说明 |
| --- | --- |
| 密钥对 | ES256（ECDSA P-256 + SHA-256），WebAuthn 强制算法；签名 DER 编码 |
| `credential_id` | 全局唯一字节串，软件验证器用随机 32 字节即可 |
| `user_handle` | RP 侧用户标识（RP 生成，注册时透传存储） |
| COSE_Key | 公钥的 COSE/CBOR 编码（EC2 + P-256 + ES256 → alg -7） |
| authenticator data | `rpIdHash(32) ‖ flags(1) ‖ signCount(4) [+ attestedCredentialData + extensions]`；flags 含 UP/UV/AT |
| client data | `{"type":"webauthn.create"/"webauthn.get","challenge":…,"origin":…}` 的 JSON 字节 |
| 注册产物 | attestation object（fmt `none`：`{fmt, attStmt:{}, authData}`）+ clientDataJSON |
| 断言产物 | `credentialId + authenticatorData + signature(authenticatorData ‖ SHA256(clientDataJSON))` |

RP 侧校验与我们相关的规则：
- `rpIdHash` 必须等于 SHA-256(rp_id)
- origin 的 effective domain 必须与 rp_id 一致（或 rp_id 是其 registrable suffix）——**这是防钓鱼的核心校验，core 必须执行**
- signCount：软件验证器普遍恒 0（1Password/Bitwarden 同样如此），意味着无克隆检测——见威胁模型

## 4. 总体架构与信任边界

```
浏览器页面                    扩展（不持任何密钥）                core / persona bridge
┌─────────────┐   main-world 拦截   ┌──────────────┐  Native Messaging  ┌─────────────────────┐
│ navigator.  │ ──────────────────▶ │ content/     │ ─────────────────▶ │ 校验 origin↔rp_id   │
│ credentials │   请求参数+origin    │ background   │  配对+HMAC+gesture │ 解锁态签名（ES256）  │
└─────────────┘ ◀────────────────── └──────────────┘ ◀───────────────── │ per-item key 解封    │
   attestation/                     选择 UI                               │ 审计 + 计数          │
   assertion 返回页面                                                      └─────────────────────┘
```

关键决策：**私钥只存在于 core 进程内存（解锁态），扩展永远只搬运请求参数与签名结果**。这与现有 `request_fill`（扩展拿填充值）不同——passkey 连敏感值都不给扩展，只给非敏感的公钥产物。

信任边界沿用 `BRIDGE_PROTOCOL.md`：配对 + HMAC + 短期会话 + origin 绑定 + user gesture；新增 core 侧 origin↔rp_id 校验作为最后一道防线（扩展被攻破也不能为错域签名）。

## 5. 数据模型与存储

新的一等模型 `PasskeyItem`（与 `Credential` 平级，身份域隔离，走现有 per-item key 包裹层级）：

```rust
pub struct PasskeyItem {
    pub id: Uuid,
    pub identity_id: Uuid,          // 身份域
    pub rp_id: String,              // "github.com"
    pub rp_name: Option<String>,    // 注册时 RP 可读名
    pub user_handle: Vec<u8>,       // RP 生成，原样存储
    pub user_name: Option<String>,  // 登录名（展示用）
    pub user_display_name: Option<String>,
    pub credential_id: Vec<u8>,     // 32 字节随机
    pub private_key: SecretVec<u8>, // P-256 标量（32B），由 item key 加密落盘
    pub public_key_cose: Vec<u8>,   // COSE_Key 原始字节（展示/导出/自检）
    pub alg: i64,                   // -7 (ES256)；v1 唯一
    pub sign_count: u32,            // 恒 0（软件验证器惯例）
    pub uv_initialized: bool,       // 创建时是否做过 UV
    pub export_allowed: bool,       // 默认 true；false 则导出/备份跳过并告警
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub tags: Vec<String>,
}
```

- 落盘：`private_key` 与 `user_handle` 等敏感字段整体作为 payload，由随机 item key 加密（AES-256-GCM），item key 由主密钥包裹——与 `KEY_HIERARCHY.md` 完全一致，无需新加密路径
- `credential_id` 加唯一索引（同一库内不重复；与 RP 侧无全局注册）
- 同一 identity + 同一 rp_id + 同一 user_name 允许多条（站点本身支持多 passkey），选择 UI 去重展示
- 条目历史（item versioning）自动覆盖：私钥轮换/字段变更进历史

`CredentialType` **不**新增 `Passkey` 变体：passkey 是独立模型，避免 `Credential` 的 secret 字段语义被稀释；列表/搜索/TUI 层把它呈现为一种条目类型即可。

## 6. 密码学与依赖选型

遵循「优先审计过的库」：

| 需求 | 选型 | 说明 |
| --- | --- | --- |
| P-256 密钥生成/ECDSA/DER | `p256`（RustCrypto, ecdsa feature） | 与 k256 同族同维护方 |
| COSE/CBOR 编解码 | `coset`（Google 维护，Fuchsia 在用，基于 ciborium） | COSE_Key、COSE_Algorithm 常量齐全；不用手写 CBOR |
| SHA-256 | 复用 `sha2` | rpIdHash、client data hash |

自研部分只剩「authenticator data / attestation object 的拼装」这一小段规范固定的字节组装（~百行），并用 RP 侧库做回归验证（见 §12）——与钱包迁移同一策略：协议编解码用库，标准向量兜底。

私钥在内存中的形态：`p256::SecretKey`，落盘前后走 `zeroize` 路径（与现有 secret 处理一致）。

## 7. 桥接协议 v2

在 v1 基础上新增三个消息（全部要求 `auth` HMAC + `origin` + `user_gesture`），`hello` 能力表追加 `passkey_create`、`passkey_assert`、`passkey_list`：

### 7.1 passkey_list — 列出某 RP 的 passkey（选择 UI 数据源）

```json
{ "type": "passkey_list", "origin": "https://github.com",
  "payload": { "rp_id": "github.com" } }
```
core 校验 rp_id 与 origin 匹配后，返回非敏感摘要：`[{id, rp_id, user_name, user_display_name, created_at}]`。**不返回 credential_id 之外的字节**。

### 7.2 passkey_create — 注册（attestation）

```json
{ "type": "passkey_create", "origin": "https://github.com", "user_gesture": true,
  "payload": {
    "request_json": { /* PublicKeyCredentialCreationOptions 的 JSON 形态 */ },
    "client_data_json_b64": "…",   // 浏览器产出的原始字节，core 只做哈希，不重组
    "require_resident_key": true
  } }
```

core 侧流程：
1. 解析 options：取 `rp.id`（缺省用 origin 的 effective domain）、`user.id`（user_handle）、`user.name`、`pubKeyCredParams`（只接受 ES256；不含则拒绝）
2. **origin 校验**：`client_data_json` 内的 `origin` 必须与请求 `origin` 一致，且 effective domain 与 rp_id 满足 registrable-suffix 关系
3. **challenge 不解释**：原样保留在 client_data_json 里，只对完整字节取 SHA-256
4. 生成密钥对 + credential_id（随机 32B）→ 组装 authenticator data（rpIdHash、UP|UV|AT、signCount=0、AAGUID、credential_id、COSE 公钥）→ `{fmt:"none", attStmt:{}, authData}`
5. 落库 `PasskeyItem`（先解锁 + 敏感操作再认证/生物识别闸门），返回 attestation 响应

### 7.3 passkey_assert — 认证（assertion）

```json
{ "type": "passkey_assert", "origin": "https://github.com", "user_gesture": true,
  "payload": {
    "item_id": "uuid",             // 用户在 UI 选中后传入；缺省时 core 拒绝（不允许静默选钥）
    "client_data_json_b64": "…"
  } }
```

core 侧流程：同 7.3 的 origin↔rp_id 校验 → 组装 `authenticator_data`（UP|UV，signCount=0，无 AT）→ `signature = ES256_sign(priv, auth_data ‖ SHA256(client_data_json))`（DER；签名对象顺序遵循 WebAuthn 标准 §6.5.6：authenticatorData 在前，clientDataHash 在后）→ 返回 `{credential_id_b64, authenticator_data_b64, signature_der_b64}` → 审计 `passkey_asserted{rp_id, origin, item_id, result}`。

### 7.4 版本兼容

`protocol_version` 升 2；v1 扩展收到未知消息返回既有 `unknown_type` 错误码，向后兼容。协议文档增补三节 + 错误码：`passkey_rp_mismatch`、`passkey_alg_unsupported`、`passkey_item_not_found`、`passkey_origin_mismatch`。

## 8. 浏览器扩展集成

### 8.1 拦截方式（Bitwarden 同款，Chromium 已验证可行）

- content script 以 `world: "MAIN"`（MV3 支持）注入一段小脚本，替换 `navigator.credentials.create/get`：先取页面参数与调用栈 origin，转发 background 汇集 `user_gesture`（注入时同步取 `navigator.userActivation.isActive`）
- 替换函数保留原函数引用：passkey 未命中或用户取消时**回退调用原生实现**，绝不阻塞站点原生流程
- conditional mediation（`mediation: "conditional"`）请求 v1 不拦截，直接回退原生

### 8.2 选择 UI

- `passkey_create`：确认弹窗展示「为 <rp_id>（<origin>）创建 passkey，账号 <user_name>」，确认后才发桥接请求
- `passkey_assert`：`passkey_list` 拉取候选 → 弹窗列出（用户名 + 创建时间 + 身份名）→ 用户点选 → `passkey_assert`。**无候选时不弹窗、不请求**；单候选也必须显式点击（1Password 行为，防静默签名）
- 弹窗 UI 复用扩展现有 popup/确认样式；域名展示完整 origin，rp_id 与 origin 不一致的场景（合法子域）标注解释文案

### 8.3 平台限制说明（写进用户文档）

Safari 不支持 main-world 注入拦截 WebAuthn——Safari host shell 下的 passkey 依赖 Phase 4 OS provider。Chromium（Chrome/Edge/Brave）v1 全覆盖。

## 9. 安全设计

- **origin↔rp_id 校验在 core 强制执行**（§7.2），扩展侧校验只是 UX 前置；这是扩展被攻破后的最后防线
- **UV 旗标映射**：`uv` flag 只有在本次操作实际通过本地认证（主密码再认证或生物识别闸门）时才置位；未置位而 RP 要求 UV 时，先触发再认证再签
- **user presence（UP）**：由 user gesture 保证；桥接请求缺 `user_gesture: true` 一律拒绝
- **静默签名禁止**：无选择 UI 点击不发 assert；审计可区分「用户点选」与「自动」
- **AAGUID**：固定一个 Persona 专属 UUID（代码常量，随机生成一次后固化），RP 侧可识别 Persona 但不做 attestation 断言
- **挑战/计数**：challenge 不解析；signCount 恒 0 并在条目详情向用户说明「软件 passkey 无克隆检测」
- **审计**：`passkey_created` / `passkey_asserted` / `passkey_exported` 事件，记录 rp_id、origin、item_id、结果与 client_data 的 SHA-256 摘要（不记 challenge 原文与签名）
- **导出**：`export_allowed=false` 的条目在导出/备份中跳过并产生告警事件；默认 true（与 1Password 一致，passkey 必须可随库迁移）

## 10. 威胁模型增补（并入 THREAT_MODEL.md）

| 威胁 | 控制 |
| --- | --- |
| 钓鱼站用合法 rp_id 发起断言（同域恶意页） | 选择 UI 显示完整 origin + 用户显式点击；审计留痕；与密码填充同源策略一致 |
| 扩展被攻破，替任意域请求签名 | core 侧 origin↔rp_id 校验 + HMAC 配对绑定扩展实例 + user gesture + 桌面确认策略（`confirm_on_fill` 同级） |
| 页面以 hidden iframe 触发 WebAuthn | 拦截层拒绝 cross-origin iframe 上下文（WebAuthn 规范本身禁止，拦截层双保险） |
| 解锁态自动化脚本借用桥接静默签名 | 与 SSH agent 同思路：passkey assert 走敏感操作再认证/生物识别闸门，可策略强制 |
| 导出备份泄露 passkey 私钥 | 与库同级加密（Argon2id 备份加密）；`export_allowed=false` 跳过；导出事件审计 |
| signCount=0 无克隆检测 | 接受的限制（业界软件 passkey 现状），条目详情明示用户 |

## 11. 导入导出

- 库导出（JSON/YAML）：passkey 条目按 §9 规则参与导出；加密备份沿用 Argon2id 路径
- 从其他管理器导入：1Password/Bitwarden 的导出格式均含 passkey 私钥字段（1PUX 的 `truncatedUpdateToken`…各不相同），v1 只做**1Password 1PUX 只读导入**中 passkey 字段的解析（能拿到私钥的才导入，平台锁定的跳过并报告）
- 跨管理器标准交换（CXF）：留 `foreign_key_ref` 字段空间，待 FIDO 定稿再实现

## 12. 测试与互操作验证

- **单元/规范向量**：COSE_Key 编码、authenticator data 字节布局、`none` attestation object、DER 签名、rpIdHash、registrable-suffix 匹配表（含 `github.com` vs `www.github.com` vs `evil-github.com` 反例）
- **RP 侧回归**：dev-dependency 引 `webauthn-rs`（成熟的 relying party 实现），用 core 产物走完整 RP 校验（attestation verify + assertion verify）——与钱包用官方向量兜底同一哲学：我们的 authenticator 侧代码小，用对方实现当裁判
- **桥接协议**：三个新消息的正反用例（缺 origin/缺 gesture/rp 不匹配/未配对/算法不支持）
- **fuzz**：`client_data_json` 与 options JSON 解析进 fuzz 清单（`webauthn.create` 畸形输入）
- **人工互操作**：webauthn.io（注册+登录）、webauthn.bin.coffee、GitHub passkey 登录；Chromium + Edge 各过一遍
- **审计抽查**：按 THREAT_MODEL 季度流程核对无明文 challenge/签名入日志

## 13. 分阶段落地

| 阶段 | 内容 | 验收 |
| --- | --- | --- |
| P1 core | 模型/存储/迁移、`p256`+`coset` 接入、CLI（`persona passkey create/list/show/remove`、`--self-test` 本地注册+断言自检）、导出导入、审计 | workspace 测试 + webauthn-rs RP 校验全绿 |
| P2 浏览器 | 桥接 v2 三消息、扩展 main-world 拦截、选择/确认 UI、回退原生 | webauthn.io + GitHub 真站互通 |
| P3 桌面与策略 | 桌面 passkey 列表/详情、再认证与生物识别闸门接线、域策略联动 | 桌面端全流程 |
| P4 远期 | OS passkey provider（macOS/Windows）、conditional mediation、1PUX 导入、CXF | 各平台原生 UI 出 Persona 条目 |

## 14. 开放问题

1. **多身份命中同一 rp_id**：选择 UI 是否要按 active identity 过滤后再列（与密码建议的「活动身份优先」策略对齐）？倾向：默认过滤到 active identity，提供「显示其他身份」展开
2. **私钥备份格式**：导出用自定义 JSON（v1）还是同时给一个 PKCS#12 类标准容器？（CXF 定稿前无标准，v1 自定义 + schema 文档化）
3. **P3 之后再评估**是否把 `confirm_on_passkey_assert` 做成独立策略键（当前复用 `confirm_on_fill`）
