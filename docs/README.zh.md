> [English](https://github.com/cuihairu/persona/blob/main/docs/README.md) | **中文**

# Persona 项目文档

**掌控你的数字身份。一键自由切换。**

本目录是 Persona 的设计与安全文档入口。里程碑视图见 [ROADMAP](https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md)，每日任务见根目录 [TODO](https://github.com/cuihairu/persona/blob/main/todo.md)。

## 产品与边界

- [BOUNDARY](https://github.com/cuihairu/persona/blob/main/BOUNDARY.md) – 产品边界：Principal / Identity / 身份材料的定义，钱包的定位（deferred：先补齐 1Password 级密码功能，再做钱包）
- [ROADMAP](https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md) – 里程碑视图与优先级政策
- [MONOREPO](https://github.com/cuihairu/persona/blob/main/docs/MONOREPO.md) – monorepo 结构与工具链

## 对标与差距

- [ONEPASSWORD_FEATURES](https://github.com/cuihairu/persona/blob/main/docs/ONEPASSWORD_FEATURES.md) – 1Password 功能全集（对标清单）
- [FEATURE_GAP_ANALYSIS](https://github.com/cuihairu/persona/blob/main/docs/FEATURE_GAP_ANALYSIS.md) – Persona vs 1Password 现状对比
- [审计-文档一致性](./审计-文档一致性.md) – 文档-源码一致性审计表（三类差异分桶，67 项，2026-10-13；英文版：[DOC_SOURCE_CONSISTENCY_AUDIT](https://github.com/cuihairu/persona/blob/main/docs/DOC_SOURCE_CONSISTENCY_AUDIT.md)）

## 架构

- [STORAGE_AND_SYNC](https://github.com/cuihairu/persona/blob/main/docs/STORAGE_AND_SYNC.md) – 存储与同步模式用户指南（纯本地 / 自托管 Persona Server / 端到端加密凭据同步（含双设备演示脚本）/ 网盘冷备；备份恢复实操与故障后果）
- [CLIENT_COMMUNICATION_ARCHITECTURE](https://github.com/cuihairu/persona/blob/main/docs/CLIENT_COMMUNICATION_ARCHITECTURE.md) – 统一客户端通信架构（CLI/桌面/浏览器/Agent 共用同一本地服务/IPC 协议）
- [LOCAL_SERVICE](https://github.com/cuihairu/persona/blob/main/docs/LOCAL_SERVICE.md) – 本地服务、IPC 传输（Unix Socket 优先）与三种存储/同步模式（纯本地 / 自托管云 / Persona 服务器辅助）
- [BRIDGE_PROTOCOL](https://github.com/cuihairu/persona/blob/main/docs/BRIDGE_PROTOCOL.md) – 浏览器扩展 Native Messaging 协议
- [NON_INTERACTIVE_MODE](https://github.com/cuihairu/persona/blob/main/docs/NON_INTERACTIVE_MODE.md) – CI/CD 非交互模式指南
- [REMOTE_AUTH](https://github.com/cuihairu/persona/blob/main/docs/REMOTE_AUTH.md) – 远程认证抽象
- [KEY_HIERARCHY](https://github.com/cuihairu/persona/blob/main/docs/KEY_HIERARCHY.md) – 密钥层级与 KDF 路径
- [E2EE_SYNC_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/E2EE_SYNC_DESIGN.md) – E2EE 同步设计稿（阶段 1–4 已落地：设备密钥/SRP 选型/组密钥信封/冲突解决四决策，状态与证据见文内 §10）
- [sync-group-mode](https://github.com/cuihairu/persona/blob/main/docs/sync-group-mode.md) – 跨设备同步（默认同步方式）：动态密码+PAKE 零账号配对；实现状态随批次标注（S1 协议+中转已实现，桌面接线/S2+ 未实现）
- [SELF_HOST_SERVER](https://github.com/cuihairu/persona/blob/main/docs/SELF_HOST_SERVER.md) – 自建服务端（部署、环境变量、API 端点）
- [CONNECT_AUTOMATION_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/CONNECT_AUTOMATION_DESIGN.md) – 本机 Connect 自动化端点设计（127.0.0.1 HTTP + scope token）
- [CONTEXT_AWARE_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/CONTEXT_AWARE_DESIGN.md) – 上下文感知（按环境推荐身份）设计

## 安全

- [THREAT_MODEL](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md) – 威胁模型与周期性安全审查
- [SSH_AGENT_FEATURES](https://github.com/cuihairu/persona/blob/main/docs/SSH_AGENT_FEATURES.md) – SSH Agent 完整文档
- [BIOMETRIC_HOOKS](https://github.com/cuihairu/persona/blob/main/docs/BIOMETRIC_HOOKS.md) – 生物识别解锁抽象
- [biometric-unlock-design](https://github.com/cuihairu/persona/blob/main/docs/biometric-unlock-design.md) – 生物识别解锁设计稿
- [PASSKEYS_DESIGN](https://github.com/cuihairu/persona/blob/main/docs/PASSKEYS_DESIGN.md) – Passkey（WebAuthn）设计稿
- [PASSKEY_GATE_AUDIT](https://github.com/cuihairu/persona/blob/main/docs/PASSKEY_GATE_AUDIT.md) – Passkey 门禁审计
- [SUPPLY_CHAIN_SECURITY](https://github.com/cuihairu/persona/blob/main/docs/SUPPLY_CHAIN_SECURITY.md) – 供应链安全检查

## 构建与发布

- [REPRODUCIBLE_BUILDS](https://github.com/cuihairu/persona/blob/main/docs/REPRODUCIBLE_BUILDS.md) – 可复现构建（工具链钉版）
- [WINDOWS_INSTALLER](https://github.com/cuihairu/persona/blob/main/docs/WINDOWS_INSTALLER.md) – Windows 安装器
- [CONTRIBUTING](https://github.com/cuihairu/persona/blob/main/docs/CONTRIBUTING.md) – 贡献指南（Conventional Commits、PR 要求）
- [UNINSTALL](https://github.com/cuihairu/persona/blob/main/docs/UNINSTALL.md) – 卸载与数据保留（卸载不删数据，重装接续；显式 purge 步骤）

## 品牌

- [branding](./branding/README.md) – logo、字标、配色与使用规范

---

_早期场景分析文档（scenarios-analysis / security-requirements）已不再单独维护，其内容并入 [BOUNDARY](https://github.com/cuihairu/persona/blob/main/BOUNDARY.md) 与 [THREAT_MODEL](https://github.com/cuihairu/persona/blob/main/docs/THREAT_MODEL.md)。_
