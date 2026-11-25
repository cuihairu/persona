# 工程参考

维护在仓库根（`docs/*.md`）的设计文档、运行手册与特性规格。它们以**单一
来源**挂进站点——你在站点里读到的文件和 GitHub 仓库里的文件是同一批文件
（只改一处，两边同步可见）。

## 核心设计文档

| 文档                                     | 内容                               |
| ---------------------------------------- | ---------------------------------- |
| [威胁模型](./THREAT_MODEL.zh)            | 资产、信任边界、STRIDE、周期性复审 |
| [E2EE 同步设计](./E2EE_SYNC_DESIGN.zh)   | 同步协议、密钥层级、快照压缩       |
| [供应链安全](./SUPPLY_CHAIN_SECURITY.zh) | 依赖审计、许可证策略、CI 门禁      |
| [密钥层级](./KEY_HIERARCHY.zh)           | 主密钥派生与 item key 包裹         |
| [可复现构建](./REPRODUCIBLE_BUILDS.zh)   | digest 钉死镜像、可验证产物        |
| [存储与同步](./STORAGE_AND_SYNC.zh)      | 本地存储内部与同步状态             |
| [路线图](./ROADMAP.zh)                   | 里程碑与详细计划                   |

## 更多参考文档

[钱包设计](./WALLET_DESIGN.zh) · [自托管服务器](./SELF_HOST_SERVER.zh) ·
[桥协议](./BRIDGE_PROTOCOL.zh) · [SSH Agent 功能](./SSH_AGENT_FEATURES.zh) ·
[上下文感知设计](./CONTEXT_AWARE_DESIGN.zh) · [Connect 自动化](./CONNECT_AUTOMATION_DESIGN.zh) ·
[本地服务](./LOCAL_SERVICE.zh) · [Monorepo](./MONOREPO.zh) ·
[外部集成](./EXTERNAL_INTEGRATION.zh) · [远程认证](./REMOTE_AUTH.zh) ·
[非交互模式](./NON_INTERACTIVE_MODE.zh) · [客户端通信架构](./CLIENT_COMMUNICATION_ARCHITECTURE.zh) ·
[同步组模式](./sync-group-mode.zh) · [云盘同步](./CLOUD_DRIVE_SYNC.zh) ·
[边界声明](https://github.com/cuihairu/persona/blob/main/BOUNDARY.md)（仓库根）

时间点的审计与评审记录在 GitHub 的
[docs/review](https://github.com/cuihairu/persona/tree/main/docs/review)。
