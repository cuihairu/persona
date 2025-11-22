# Persona（数钥）- 数字身份与开发者密钥管理

中文名：数钥（读音：shù yào）  
理由：简洁有记忆点，直观传达“数字 + 密钥/要点”的产品内涵，贴合密码/身份/开发者密钥场景。建议品牌对外统一用法为“Persona（数钥）”或“数钥 Persona”。

Master your digital identity. Switch freely with one click.

## 🎯 项目概述

Persona 是一个安全、便捷的数字身份与凭据管理系统，重点强化开发者场景（SSH Agent、API Key、服务器配置），同时覆盖通用密码与数字钱包。采用零知识架构与端到端加密，数据仅由本地设备加解密。

### 核心功能
- 🔐 密码与身份：账户密码、身份档案、标签与自定义属性
- 🔑 开发者场景：SSH 密钥存储与签名（内置 SSH Agent）、API Key/服务器配置
- 💰 数字钱包：助记词/私钥管理（后续提供多链派生/签名）
- 🗄️ 导入/导出：JSON/YAML/CSV；支持 gzip 压缩与口令加密（Argon2id + AES‑GCM）
- 🧾 审计日志：关键操作与签名审计（含摘要）

## 🏗️ 技术架构

### Monorepo 结构
```
persona/
├── core/               # Rust 核心库：模型、加密、存储、服务层
├── cli/                # Persona CLI：init/add/list/show/switch/export/import/ssh/...
├── agents/ssh-agent/   # 内置 SSH Agent（UNIX socket，ed25519）
├── desktop/            # Tauri + React 桌面应用（原型）
├── mobile/             # 移动端占位
├── server/             # 可选同步/自动化（原型）
└── docs/               # 文档与路线图
```

### 技术栈
- 核心库：Rust（安全/高性能），sqlx + SQLite
- 加解密：Argon2id 密钥派生，AES‑256‑GCM 对称加密
- 桌面端：Tauri + React + TypeScript（原型）
- 服务器：Rust + Axum（可选）

## 🔒 安全特性

- **零知识架构**: 服务器无法解密用户数据
- **端到端加密**: AES-256-GCM + Argon2id
- **本地优先**: 所有敏感数据在本地加解密
- **签名审计**: SSH 签名写入摘要（sha256）与上下文元数据
- **策略控制**: SSH Agent 支持频率限制与交互确认；可选 known_hosts 校验

## 🚀 快速开始

### 环境要求
- Rust 1.75+
- Node.js 18+

### 构建与安装（CLI + Agent）
```bash
# 克隆项目
git clone https://github.com/your-username/persona.git
cd persona

# 构建 CLI 与 Agent
cargo build --workspace

# 可选：运行 CI 本地检查
make ci
```

### JS/桌面端依赖（pnpm）
```bash
# 安装 workspace 依赖（desktop + browser extension）
pnpm install

# 运行桌面端开发模式
pnpm --filter desktop run dev

# 构建浏览器扩展
pnpm --filter persona-chromium-extension run build
```

### 初始化工作区与基础操作
```bash
# 初始化工作区（未加密）
persona init --path ~/PersonaDemo --yes

# 初始化工作区（加密，设置主密码）
persona init --path ~/PersonaSecure --yes --encrypted --master-password "your_password"

# 新增/查看/列表（身份）
persona add
persona show <name>
persona list

# 切换激活身份（Workspace v2 已持久化）
persona switch <name>

# 迁移（确保 schema 最新且写入 workspace 记录）
persona migrate

# 凭据管理（密码/API Key 等）
persona credential add --identity alice --name "GitHub" --credential-type password --prompt-secret
persona credential list --identity alice --format table
persona credential show --id <UUID> --reveal
persona credential remove --id <UUID>

# TOTP（二步验证）管理
persona totp setup --identity alice --qr ~/Downloads/github.png
persona totp code --id <UUID>
persona totp code --id <UUID> --watch
```

### 导出/导入（压缩 + 加密）
```bash
# 导出为 JSON，包含敏感数据（需解锁）
persona export --include-sensitive --output backup.json

# 启用 gzip 压缩与口令加密
persona export --format yaml --compression 9 --encrypt --output backup.yaml

# 导入（支持 .json/.yaml/.csv；--decrypt 交互输入口令）
persona import backup.enc --decrypt --mode merge --backup
```

### SSH Agent（开发者增强）
```bash
# 生成 SSH 密钥（ed25519），存入 vault
persona ssh generate --identity <name> --name "GitHub Key"

# 启动内置 Agent，并打印导出命令
persona ssh start-agent --print-export
export SSH_AUTH_SOCK=...   # 复制到当前 shell

# 传递目标主机并执行命令（启用 known_hosts 策略时推荐）
persona ssh run --host github.com -- ssh -T git@github.com

# Agent 策略（可选）
export PERSONA_AGENT_REQUIRE_CONFIRM=1          # 每次签名前确认
export PERSONA_AGENT_MIN_INTERVAL_MS=1000       # 频率限制（毫秒）
export PERSONA_AGENT_ENFORCE_KNOWN_HOSTS=1      # 启用 known_hosts 检查
export PERSONA_AGENT_CONFIRM_ON_UNKNOWN=1       # 非 known_hosts 主机时询问确认

# 状态与停止
persona ssh agent-status
persona ssh stop-agent
```

## 📖 文档

- [ONEPASSWORD_FEATURES](./docs/ONEPASSWORD_FEATURES.md) - 1Password 功能清单参考
- [FEATURE_GAP_ANALYSIS](./docs/FEATURE_GAP_ANALYSIS.md) - Persona vs 1Password 差距分析
- [MONOREPO](./docs/MONOREPO.md) - Monorepo 说明
- [ROADMAP](./docs/ROADMAP.md) - 路线图与详细 TODO
- [TODO](./TODO.md) - 任务清单（每日维护）
- [品牌素材](./docs/branding/README.md) - Logo/文字标/配色与规范

## 🛣️ 开发路线图

- [x] Monorepo 与核心库搭建，CLI 连接数据库全链路
- [x] Workspace v2（path/active_identity/settings）与迁移命令
- [x] 导出/导入（gzip + 加密），审计日志完善
- [x] SSH Agent MVP（UNIX socket / ed25519），CLI 管理命令
- [ ] SSH Agent 策略完善（known_hosts 完整解析、白名单/黑名单、Windows 支持）
- [ ] 数字钱包（模型/派生/签名）
- [ ] 桌面应用数据接线与 UI 打磨
- [ ] 可选同步/自动化服务（本地优先）

## 🤝 贡献指南

- 阅读 [`docs/CONTRIBUTING.md`](./docs/CONTRIBUTING.md) 了解 Conventional Commits 规范与 PR 要求。
- Fork 项目并创建功能分支（例如 `git checkout -b feat/cli-edit`）。
- 按 [Conventional Commits](https://www.conventionalcommits.org) 格式撰写 PR/commit 标题，例如 `feat(cli): add credential filters`。
- 推送分支并创建 Pull Request，确保通过 `make lint-all` 与 `make test-all`。

## 📄 许可证

本项目采用 MIT 许可证 - 查看 [LICENSE](LICENSE) 文件了解详情。

## 🔗 相关链接

- [问题反馈](https://github.com/your-username/persona/issues)

---

安全提醒：本项目仍处于快速迭代阶段，接口与数据格式可能变动；请谨慎用于生产数据。
Master your digital identity. Switch freely with one click.
