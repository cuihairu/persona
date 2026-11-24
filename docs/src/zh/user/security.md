# 安全设计

**一句话**：persona 是本地优先、零知识的身份材料管理器——凭据明文只存在
你的设备上（AES-256-GCM 加密），可选服务器只能碰密文或摘要，永不解密；
当前 **OS 用户账户是主要本地边界**，边界之外的风险当面告诉你，不打包票。

这页是**用户视角的安全方案整合**：保护什么、边界在哪、威胁怎么防、凭据
从存储到使用的生命周期各有什么控制。完整威胁模型与工程细节见文末「深读」。

## 保护什么（资产）

| 资产                     | 风险                                     |
| ------------------------ | ---------------------------------------- |
| 主密码与派生主密钥       | 泄露后可解密整个本地工作区               |
| 单项凭据密钥（item key） | 单项明文泄露或横向扩大                   |
| 凭据明文                 | 密码、API Key、TOTP、SSH 私钥外泄 / 滥用 |
| 工作区数据库             | 离线暴力破解、篡改、回滚                 |
| 浏览器桥接会话           | 恶意扩展请求填充或复制                   |
| SSH Agent socket/pipe    | 未授权签名、agent 转发滥用               |
| 审计日志                 | 篡改、删除、敏感字段误写入               |
| 备份 / 导出文件          | 备份泄露、弱口令                         |
| 钱包密钥（实验轨道）     | 不可逆丢失、投毒地址——不享受主线安全承诺 |

## 信任边界

1. **本地用户边界**：当前 OS 用户账户是主要安全边界；persona 不防已完全
   控制该账户的恶意软件、内核或调试器。
2. **解锁边界**：解锁后的主密钥只存在于短期内存，锁定即清理。
3. **浏览器桥接边界**：扩展经 Native Messaging 调用，敏感操作必须过配对、
   HMAC、短期 session、origin 绑定与 user gesture。
4. **SSH Agent 边界**：只暴露公钥列表与签名能力，私钥不可导出。
5. **可选服务端边界**：server/sync 只处理密文、事件摘要或同步元数据，
   **不得成为明文解密方**；未配置令牌即整体禁用（fail-closed）。
6. **自动化边界**：非交互模式允许环境变量注入主密码（适合 CI），调用方
   负责隔离与清理。

## 主要威胁与控制（STRIDE 摘要）

| 类别                   | 代表威胁                 | 已有控制                                             |
| ---------------------- | ------------------------ | ---------------------------------------------------- |
| 仿冒（Spoofing）       | 恶意扩展伪装已配对客户端 | 配对码 + 短期 session + HMAC-SHA256 请求认证         |
| 仿冒（Spoofing）       | SSH 目标主机被冒充       | known_hosts 强制模式、未知主机确认、每主机策略       |
| 篡改（Tampering）      | 本地库或配置被离线篡改   | AES-GCM 认证加密；导入与桥协议有解析测试与 fuzz 面   |
| 抵赖（Repudiation）    | 否认敏感操作             | 审计记录身份 CRUD、解密、导出、SSH 签名摘要          |
| 信息泄露（Disclosure） | 工作区文件被拖库离线爆破 | Argon2id/PBKDF2 派生、单项 item key 包裹             |
| 信息泄露（Disclosure） | 浏览器后台页悄悄读密码   | user gesture、origin 绑定、活动身份过滤              |
| 信息泄露（Disclosure） | 日志泄露 secret / token  | 日志脱敏策略 + 单元测试覆盖常见 secret 形式          |
| 拒绝服务（DoS）        | Agent 被频繁请求签名     | 全局最小间隔、每小时 / 每日限制、每密钥 / 每主机策略 |
| 提权（Elevation）      | 低信任脚本借用解锁态     | 自动锁、敏感操作再认证、非交互模式显式环境开关       |

## 分层防护

| 层         | 职责                                         | 关键控制                                                |
| ---------- | -------------------------------------------- | ------------------------------------------------------- |
| 客户端入口 | CLI / 桌面 / 扩展 / SSH Agent 只做交互与路由 | 不绕过 core 读写敏感明文                                |
| Core 服务  | 身份、凭据、解锁、审计、策略的唯一入口       | 自动锁、敏感操作再认证、本地审计日志                    |
| 加密层     | 主密钥派生、item key 包裹、加解密            | 每凭据独立 item key；AES-256-GCM 认证加密防篡改         |
| 存储层     | SQLite、附件、迁移、配置                     | 迁移向后兼容、`wrapped_item_key` 兼容、明文元数据最小化 |
| 外部接口   | Native Messaging、SSH Agent、可选 server     | 配对 / HMAC、origin 绑定、known_hosts、只出密文或摘要   |
| 供应链     | 依赖、许可证、构建产物                       | cargo-deny / cargo-audit / pnpm audit 进 CI；锁文件入库 |

## 凭据生命周期

**存储**：新写入的凭据用随机 item key 加密明文，item key 再由主密码派生的
master key 包裹（`wrapped_item_key`）——单项密钥泄露不横向扩大。附件复用
所属凭据的 item key 封存，主密码轮换只重包 wrapped key、附件无需重写。

**解锁与会话**：主密码解锁（PBKDF2 路径，迭代数按库持久化）；支持自动锁、
敏感操作（查看 / 复制 / 填充 / TOTP）再认证、生物识别解锁。生物识别把
「知道主密码」降级为「能过 OS 用户认证」：主密码托管进 OS 钥匙串（Linux
secret-service / macOS Keychain / Windows Credential Manager），可选升级
为硬件包裹档（BIOWRAP1——keyring 里只存被平台硬件密钥包裹的密文，同用户
恶意进程拿到也解不开）。**诚实登记**：同 OS 用户的任意进程原则上可读
OS 钥匙串（Windows 无 per-entry ACL），这是 1Password 同款直存设计的固有
代价，对抗它需要专用硬件边界。

**浏览器填充**：扩展与宿主经 Native Messaging 配对后才可用；请求带
HMAC-SHA256 认证、短期 session、重放窗口；凭据带 URL 时做 **origin 绑定**
（不匹配的页面拿不到）；敏感操作要求 user gesture——后台页面不能静默读
密码。**没有 URL 的凭据无法严格绑定来源**，高价值凭据务必设 URL。

**SSH Agent**：只提供公钥列表与签名，私钥默认不可导出；策略支持 deny-all、
known_hosts 校验、速率限制、每密钥 / 每主机 allow/deny、签名确认与生物识别
优先。

**审计与脱敏**：身份操作、凭据解密、导出、SSH 签名写入本地审计日志；签名
只记 digest；日志脱敏策略覆盖常见 secret / token / 验证码形式并有测试锁定。
审计日志强调可追踪性，当前不是防篡改账本。

**备份**：整库导出为 PERSENC1 加密文件（Argon2id + AES-256-GCM）；服务器
保管的备份同样只存密文，恢复需要**备份口令 + 主密码双要素**——任一口令
丢失即不可恢复（无托管、无重置）。

## 供应链安全

persona 对自己的依赖链做持续检查，细节与操作手册见
[供应链安全检查指南](https://github.com/cuihairu/persona/blob/main/docs/SUPPLY_CHAIN_SECURITY.zh.md)：

- **CI 门禁**：`cargo deny check`（RustSec 漏洞 + 许可证 allowlist + 禁用
  依赖 + 来源检查）与 `cargo audit` 每个 push / PR 必跑；JS/TS 侧 pnpm
  audit 报告中等以上漏洞。
- **许可证**：deny.toml allowlist（MIT / Apache-2.0 / BSD / ISC 等宽松许可），
  未列入即拒绝。
- **锁文件**：Cargo.lock 与 pnpm-lock.yaml 提交入库（docs 子站独立 npm），
  构建可复现；镜像基础层按 digest 钉死（
  [可复现构建](https://github.com/cuihairu/persona/blob/main/docs/REPRODUCIBLE_BUILDS.md)）。
- **复审节奏**：RustSec 与 npm audit 每月复查；KDF 参数、备份加密、威胁
  模型每季度复审；deny.toml 豁免必须在 PR 说明理由。

## 明确不做什么（非目标）

- 不防已完全控制当前 OS 会话的恶意内核、调试器或系统级恶意软件。
- 不承诺未解锁且主密码丢失时恢复明文数据。
- 可选 server/sync 不是信任根；本地库是第一事实源。
- 钱包能力是实验轨道，不享受主线安全承诺，不可用于生产级资金安全。

## 报告漏洞

**请勿用公开 issue 报告安全漏洞。** 正式 SECURITY.md 与安全联络邮箱待补
（占位：chuihairu@gmail.com，mailto 通道建立后本节更新）。

## 深读

- [威胁模型与周期性安全审查](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.zh.md)
  ——资产、边界、STRIDE 全表、逐端点威胁登记
- [供应链安全检查指南](https://github.com/cuihairu/persona/blob/main/docs/SUPPLY_CHAIN_SECURITY.zh.md)
  ——工具链、许可证策略、漏洞处理流程
- [Key Hierarchy](https://github.com/cuihairu/persona/blob/main/docs/KEY_HIERARCHY.zh.md)
  ——密钥派生与包裹层级
- [E2EE 同步设计稿](https://github.com/cuihairu/persona/blob/main/docs/E2EE_SYNC_DESIGN.zh.md)
  ——同步链路的密钥与威胁登记

## 相关页面

- [同步方案](./sync) —— 同步的端到端加密如何工作
- [安全需求](../analysis/security-requirements) —— 需求侧的安全约束
- [安全特性](../overview/security) / [系统设计·安全设计](../design/security)
