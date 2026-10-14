> [English](MONOREPO.md) | **中文**

# Persona 单体仓库

Persona 采用多语言单体仓库（polyglot monorepo）组织：Rust 工作区承载 core/CLI/server/agents，JS 工作区承载桌面端（Tauri+React），以及共享文档。

结构

- core（Rust crate）– 加密、存储、服务层
- cli（Rust crate）– 面向用户的 CLI
- server（Rust crate）– 可选的同步/事件 API（Axum）
- agents/ssh-agent（Rust crate）– SSH Agent 守护进程（开发者功能）
- connect-server（Rust crate）– 内嵌于宿主应用的本地自动化端点
- desktop（Tauri+React 应用）– 跨平台桌面 UI
- mobile – 原生客户端（iOS、Android、HarmonyOS），共享 `mobile/rust` 桥（Bridge） crate；不使用 Flutter 或其他跨平台 UI 层（见 `mobile/README.md`）
- docs – 规格说明、路线图和设计文档（加密细节见 `docs/KEY_HIERARCHY.md`，SRP 认证见 `docs/REMOTE_AUTH.md`，另有 `docs/BIOMETRIC_HOOKS.md`）

工具链

- Rust：Cargo 工作区（根 Cargo.toml；成员：`core`、`cli`、`server`、`agents/ssh-agent`、`connect-server`、`mobile/rust`）
- JS：pnpm 工作区（根 package.json；`desktop`、`browser/chromium-extension`、`website`）
- Makefile：面向常见开发流程的便捷 target

构建

- Rust：`cargo build --workspace`
- JS 工作区：`pnpm install`
- Desktop：`pnpm --filter persona-desktop run dev`

测试

- 运行 CLI 集成测试前，请先构建整个工作区：
  `cargo test -p persona-cli` 不会重新构建 `persona-ssh-agent`，而
  SSH agent 测试会启动 `target/debug/persona` 旁边的同级二进制。
  陈旧的 agent（在较新的迁移落地之前构建）在全新数据库上会因令人困惑的
  `migration N was previously applied but is missing in the resolved
migrations` 错误而失败。

贡献指南

- 遵循 Rust 2021 edition 风格；运行 `cargo fmt && cargo clippy`
- desktop/browser 通过 pnpm 运行 ESLint + Jest；PR 必须包含核心逻辑的测试
