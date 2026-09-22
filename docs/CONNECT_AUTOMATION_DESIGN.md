# Connect 本机自动化端点设计稿（阶段 0）

> 状态：**设计稿，未实现**。本文是 TODO「Connect-like local-first secrets
> automation endpoint」（ROADMAP Milestone 6）的开工文档，对标 1Password
> Secrets Automation / Connect server 在 Persona 本地优先架构下的形态：
> 把必须先拍板的设计决策定下来，并给出实施阶段映射与威胁模型登记骨架。
> 实现按 §8 的阶段逐个落地，每阶段独立 PR 粒度。
>
> 相关文档：[`ROADMAP.md`](./ROADMAP.md) Milestone 6、[`E2EE_SYNC_DESIGN.md`](./E2EE_SYNC_DESIGN.md)
> （同轨道姊妹稿——本端点**不依赖**同步轨道，可独立落地）、
> [`THREAT_MODEL.md`](./THREAT_MODEL.md)、[`BOUNDARY.md`](../BOUNDARY.md)
> （automation-friendly access 在边界内）。

## 1. 目标与非目标

**目标**

1. 让本机脚本/CI/SDK 在**不接触主密码**的前提下按授权范围读取凭据与 TOTP
   ——自动化消费者拿 token，不拿解锁口令。
2. 默认零暴露：功能不开就**根本不监听端口**（不是 403，是不 bind）。
3. 复用既有资产：`PersonaService` 解锁态、audit log、设置持久化模式、
   server 端 axum 分层先例、passkey 桌面审批的本机 IPC 先例。
4. 授权可细分、可吊销、可审计——token 泄露的爆炸半径被 scope 圈住。

**非目标（第一阶段明确不做）**

- **写路径**：自动化不改库（创建/更新/删除不做）。1P Connect 同样以读取
  为主；自动化写库的审计归属、冲突面、误操作半径是独立议题（§9）。
- **passkey / 钱包 / SSH key 私钥面**：scope 默认排除敏感类型；passkey
  attest 从桌面审批链走，不走 token 端点。
- **远程/LAN 形态**：只服务 127.0.0.1。容器化独立 Connect server、经
  Persona Server 中转的远程自动化（1P 的部署形态）不做——E2EE 同步轨道
  稳定后再评估。
- **搜索/富查询**：起步只给确定性取回（按 id / 按 title 精确匹配 +
  identity/type 过滤），不做全文检索面。

## 2. 信任模型

- **信任根 = 主密码解锁态 + connect token**。端点只在库已解锁时返回数据；
  token 决定「能看哪个身份下的哪些类型」。二者缺一即拒绝。
- **消费者定位 = 本机半可信进程**。127.0.0.1 上没有陌生调用方，但有浏览器
  渲染的恶意网页（§5 三防线）与本机其他用户的进程（token 必需 + OS 层
  边界，不额外宣称多用户隔离——与 THREAT_MODEL 现有口径一致）。
- **端点可见面**：token 授权范围内条目的字段明文（这正是功能目的）+ 最小
  元数据。超出 scope 的条目对消费者**不存在**（404 与 403 不区分，避免
  探测）。health 端点零信息（不报解锁态、不报库存在性）。

## 3. 决策记录

### DR-1 部署形态：宿主进程内嵌监听（否决：独立常驻进程 / 容器）

HTTP 服务嵌入**已解锁的宿主进程**，core 出框架无关服务层，两个宿主复用：

- **A1 桌面内嵌（先行）**：desktop 的 tokio runtime 里起 axum listener。
  密钥不新增进程边界；桌面退出 = 自动化自然停止（诚实语义：自动化跟着
  解锁会话走）。
- **A2 CLI `persona connect serve`（后续）**：headless 服务器/CI 长会话
  用同一 core 服务层 + 同一 token 存储（工作区库内），前台进程 + Ctrl-C
  退出，不做 daemon 化（systemd 用户单元由用户自配，文档给示例）。
- **否决独立进程/容器**：1P Connect 容器形态服务于「服务器托管、多消费
  者远程访问」——与本地优先边界相反；独立本地常驻进程则引入密钥跨进程
  传递（违背「解锁态在宿主进程内」的单一边界）与第二份生命周期管理。
- **依赖**：axum 0.7（与 server 同版本，workspace 先例；desktop 独立
  workspace 需自行声明）+ 既有 tokio。bind 地址硬编码 `127.0.0.1`，
  端口默认 `0`（OS 分配）+ 显式配置项；**拒绝任何非 loopback 配置**
  （fail-closed，配置了就启动失败并报错，不静默回退）。

### DR-2 认证与授权：scope token（一次性显示、只存哈希、三维 scope）

- **token 形态**：`pconn_` 前缀 + 32 字节随机（base64url）。创建时一次性
  展示明文（桌面设置页复制按钮 / CLI stdout），存储只存 SHA-256 哈希 +
  前 8 字节指纹（供列表识别与吊销，不泄露 token 本体）。
- **scope 三维**：
  - `identities`: 允许的身份 UUID 列表（空 = 全部——显式选择，UI 需
    二次确认措辞「该 token 可读取所有身份」）；
  - `item_types`: 允许的凭据类型（如 `password`/`totp`/`note`/`address`；
    passkey/wallet/ssh 恒不可授权，不在合法枚举里）；
  - `verbs`: `read`（起步唯一合法值；未来写路径再加枚举）。
- **存放**：工作区库内新表 `connect_tokens`（id、hash、fingerprint、
  scope JSON、created_at、last_used_at、revoked_at、label）。随库走 =
  备份覆盖它、换机迁移它，与「库是第一事实源」一致；**不进同步轨道**
  （v1 不同步；若未来同步，token 也必须是 per-device 的本地资产，登记
  为同步设计的开放问题输入）。
- **校验**：SHA-256 后常量时间比较；每请求计 `last_used_at`（节流批量
  写）。吊销即时生效（查表判定，无缓存窗口——v1 不做 token 缓存，
  性能不够再议）。
- **1P 对齐**：1P Connect token 按 vault 授权、服务端校验、可吊销——
  Persona 的「身份」替代「vault」作为授权粒度，与 IdentitySwitcher 的
  产品语义一致。

### DR-3 端点面：最小只读 + TOTP resolve

`/api/v1/connect/*`，全部要求 `Authorization: Bearer pconn_…`（health 除外）：

| 端点                       | 方法 | 语义                                                                                              |
| -------------------------- | ---- | ------------------------------------------------------------------------------------------------- |
| `/connect/health`          | GET  | `{ "service": "persona-connect", "version": … }`，零库信息，免认证                                |
| `/connect/identities`      | GET  | scope 内身份列表（id + 名称）                                                                     |
| `/connect/items`           | GET  | scope 内条目元数据（id、title、type、urls、updated_at）；`?identity=`/`?type=`/`?title=` 精确过滤 |
| `/connect/items/{id}`      | GET  | 单条全字段（解密后 JSON；scope 外返回 404）                                                       |
| `/connect/items/{id}/totp` | POST | 当前 TOTP 码 + 剩余秒（复用 CLI/desktop 的 TOTP 解析路径）                                        |

- **响应包络**：沿用 server 惯例 `{"ok":true,"data":…}` / `{"ok":false,
"error":{…}}`，错误码与 desktop `ApiResponse` 对齐，消费者错误处理
  只学一套。
- **限额**：每 token 每分钟 120 请求（内存计数，超限 429）——防失控
  轮询循环拖垮宿主；上限写死，不做配置（配置面越大误用面越大）。
- **审计**：每次鉴权成功/失败进 audit log（token 指纹、端点、来源
  PID 不可得则不记——诚实登记：127.0.0.1 上拿不到可靠调用方身份）。

### DR-4 本机暴露面加固：默认关闭 + 三防线防浏览器侧攻击

本机 HTTP 端点的真实威胁不是「远程攻击者」，是**浏览器里的恶意网页**
（DNS rebinding、CSRF 式 fetch、内网探测）。三道防线缺一不可：

1. **Host 头白名单**：只接受 `127.0.0.1:{port}` / `localhost:{port}`
   （rebinding 攻击的 `evil.com`→`127.0.0.1` 解析会带恶意 Origin/Host，
   Host 不符直接 421 拒绝）。
2. **CORS 全关**：不返回任何 `Access-Control-Allow-*` 头；`Origin` 头
   出现即 403（本机 API 没有合法浏览器跨源消费者）。预检请求一律拒绝。
3. **token 必需**：无匿名面（health 除外，health 零信息）。

外加：

- **默认关闭**：设置不开启 = 不创建 listener。开关文案按 THREAT_MODEL
  风格如实说明「开启后本机进程可按 token 授权读取凭据」。
- **锁定门禁**：库未解锁（含自动锁/手动锁/travel enter 后）= 全数据
  端点 503 + `error: "vault_locked"`；解锁即恢复。token 有效但库锁定
  时**不消耗** 429 限额（锁屏自动化重试风暴不锁死 token）。
- **响应头**：`Cache-Control: no-store`（TOTP 码与字段明文不进任何
  中间缓存）、`Content-Type` 严格 `application/json`。

### DR-5 token 管理面：桌面设置页先行，CLI 同批跟进

- 桌面：设置页新增 Automation 区（token 列表：label/指纹/scope/last_used/
  吊销；创建弹窗：scope 选择 + 一次性明文展示 + 「关闭后无法再次查看」
  警示）。创建/吊销走 reauth 门禁（与敏感设置同语义）。
- CLI：`persona connect token create/list/revoke` + `persona connect serve`
  （A2 阶段）。非交互 CI 模式沿用 `--passphrase-env` 惯例。
- 无「编辑 scope」——改权限 = 建新 token 吊销旧 token（审计清晰，避免
  「token 权限悄悄变大」）。

## 4. 数据流（解锁态一次，token 校验每请求）

```
脚本/SDK ──Bearer pconn_…──> 127.0.0.1:port (axum, 宿主进程内)
    │ 1. Host/Origin/限流 检查（DR-4）
    │ 2. token 哈希比对 + scope 解析（DR-2，查库）
    │ 3. 锁定门禁：PersonaService 未解锁 → 503（DR-4）
    │ 4. scope 过滤：identity ∈ scope ∧ type ∈ scope（DR-2）
    └ 5. PersonaService 读取/解密 → JSON（no-store）
             audit：token 指纹 + 端点 + 结果
```

明文字段只存在于宿主进程内存与响应体；消费者侧（脚本环境变量、CI 日志）
的安全是**消费者责任**，文档如实警示「响应含明文，勿落日志」。

## 5. 与既有系统的边界

| 既有资产                        | 关系                                                                                                                               |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `PersonaService` 解锁态         | 唯一数据面；端点不做自己的缓存（DR-3 限额计数除外，非数据）                                                                        |
| desktop 设置/feature flags      | 开关持久化同模式；automation 开关是第 N 个 feature flag + token 表                                                                 |
| passkey 桌面审批（Unix socket） | 先例参照（本机 IPC + GUI 审批）；connect 不复用 socket（HTTP 面向任意语言消费者），审批链**不接** token 端点                       |
| audit log                       | 新 `AuditAction::ConnectTokenCreated/Revoked/Used`(命名实现时定)；Used 走节流防刷屏（如每 token 每分钟一条聚合）                   |
| 备份链                          | `connect_tokens` 表随 VACUUM INTO 快照走（scope/哈希是库数据）；恢复备份 = token 集合回到备份时点，明文 token 本来就不在任何备份里 |
| server / 同步轨道               | 无耦合；connect 是纯本机面。server 的 Bearer/SRP 体系不复用（不同信任域：远程设备 vs 本机消费者）                                  |
| Travel Mode                     | travel 激活期间端点随锁定门禁自然 503；被移出身份在 scope 内的 token 请求返回 404（条目不存在），不暴露 travel 状态                |

## 6. 威胁模型登记骨架（实现时在 THREAT_MODEL.md 写实）

- **信任根与可见面**：§2。
- **不宣称**：防本机恶意进程（token 在其环境变量/参数里同样可见——与
  1P CLI 同边界）；防宿主进程被攻破（自动化不扩大也不缩小该边界）；
  多用户 OS 隔离。
- **恶意网页**：DR-4 三防线 + 已知残面（token 若被配置进浏览器扩展可
  及的存储则防线无效——文档禁止此用法）。
- **token 泄露爆炸半径**：scope 圈定的只读面 + 吊销 + audit 可见；
  无写路径 = 无篡改半径。
- **DoS**：429 限额保护宿主；listener 占用端口面极小（loopback 单口）。

## 7. 测试要点（验收预登记）

- fail-closed 断言：默认配置下无端口监听；非 loopback bind 配置启动失败。
- 三防线：恶意 Host/带 Origin/无 token/错 token/越 scope 各拒绝路径；
  scope 外条目 404 与 403 同形。
- 锁定语义：锁定 503、解锁恢复、锁定期间不计限额。
- token 生命周期：创建一次性展示、哈希存储断言（库里无明文）、吊销即时、
  last_used 更新。
- TOTP 端点与 CLI/desktop 解析路径一致性。
- 429 限流边界；health 零信息断言。

## 8. 实施阶段映射

| 阶段      | 内容                                                                                             | 验收要点                                                    | 威胁模型登记                     |
| --------- | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- | -------------------------------- |
| 0（本文） | 设计稿                                                                                           | 决策拍板 + 用户确认                                         | 骨架（§6）                       |
| 1         | core `connect` 服务层：token 表迁移 + 管理 API + scope 过滤 + 锁定门禁编排（框架无关，纯函数化） | core 测试：token 生命周期/scope 过滤/404 同形               | —                                |
| 2         | desktop 内嵌 axum（DR-1 A1）+ 三防线 + 限额 + 设置页 token 管理 UI                               | DR-4 全拒绝路径测试；`cargo test -p persona-desktop` + jest | 「Connect 本机自动化端点」章写实 |
| 3         | CLI `persona connect token …` + `serve`（DR-1 A2）                                               | CLI 集成测试（ScriptedUi 缝）；跨宿主同 token 存储互通      | 复查与实现相符                   |
| 4         | 文档收口：STORAGE_AND_SYNC 增 automation 节 + README 快速上手（curl 示例）                       | 文档与实现一致                                              | —                                |

规模预估：3–4 个会话量级；阶段 1–2 是主面。

## 9. 开放问题

1. **写路径**（create/update via token）：1P 用 SDK+CLI 承担写；Persona
   是否走同路（token 只读、写走 CLI 交互）还是开放写 scope？等真实
   automation 需求出现再拍。
2. **SDK 形态**：shell 函数（`persona connect env` 注入 env var）vs
   正式 SDK 包；倾向前者（零依赖、与 CI env 模式一致）。
3. **desktop 生命周期细节**：锁屏时 listener 保持（快恢复）还是关闭
   （最小暴露面）？本稿按「保持 + 503」设计，实现阶段可用真实功耗/
   安全评估翻案。
4. **token 表与同步轨道**：若未来 E2EE 同步落地，token 是否纳入同步
   （倾向否——per-device 本地资产），作为 E2EE_SYNC_DESIGN §11 的新
   输入登记。
5. **indirect 授权 UI**：token 创建后是否要求「首次使用需在桌面弹窗
   确认一次」（1P 无此步；Persona 的 GUI 审批先例支持做）——防 token
   创建即被盗用的空窗，成本是自动化首次接入了人工步骤。
