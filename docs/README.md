# Persona 项目文档

**Master your digital identity. Switch freely with one click.**

本目录是 Persona 的设计与安全文档入口。里程碑视图见 [ROADMAP](./ROADMAP.md)，每日任务见根目录 [TODO](../TODO.md)。

## 产品与边界

- [BOUNDARY](../BOUNDARY.md) – 产品边界：Principal / Identity / 身份材料的定义，钱包的定位（deferred：先补齐 1Password 级密码功能，再做钱包）
- [ROADMAP](./ROADMAP.md) – 里程碑视图与优先级政策
- [MONOREPO](./MONOREPO.md) – monorepo 结构与工具链

## 对标与差距

- [ONEPASSWORD_FEATURES](./ONEPASSWORD_FEATURES.md) – 1Password 功能全集（对标清单）
- [FEATURE_GAP_ANALYSIS](./FEATURE_GAP_ANALYSIS.md) – Persona vs 1Password 现状对比

## 架构

- [CLIENT_COMMUNICATION_ARCHITECTURE](./CLIENT_COMMUNICATION_ARCHITECTURE.md) – 统一客户端通信架构（CLI/桌面/浏览器/Agent 共用同一本地服务/IPC 协议）
- [LOCAL_SERVICE](./LOCAL_SERVICE.md) – 本地服务、IPC 传输（Unix Socket 优先）与三种存储/同步模式（纯本地 / 自托管云 / Persona 服务器辅助）
- [BRIDGE_PROTOCOL](./BRIDGE_PROTOCOL.md) – 浏览器扩展 Native Messaging 协议
- [NON_INTERACTIVE_MODE](./NON_INTERACTIVE_MODE.md) – CI/CD 非交互模式指南
- [REMOTE_AUTH](./REMOTE_AUTH.md) – 远程认证抽象
- [KEY_HIERARCHY](./KEY_HIERARCHY.md) – 密钥层级与 KDF 路径

## 安全

- [THREAT_MODEL](./THREAT_MODEL.md) – 威胁模型与周期性安全审查
- [SSH_AGENT_FEATURES](./SSH_AGENT_FEATURES.md) – SSH Agent 完整文档
- [BIOMETRIC_HOOKS](./BIOMETRIC_HOOKS.md) – 生物识别解锁抽象
- [SUPPLY_CHAIN_SECURITY](./SUPPLY_CHAIN_SECURITY.md) – 供应链安全检查

## 品牌

- [branding](./branding/README.md) – logo、字标、配色与使用规范

---

*早期场景分析文档（scenarios-analysis / security-requirements）已不再单独维护，其内容并入 [BOUNDARY](../BOUNDARY.md) 与 [THREAT_MODEL](./THREAT_MODEL.md)。*
