# Persona 项目结构说明

## Monorepo 架构

本项目采用 **Monorepo** 架构，将所有相关代码统一管理在一个仓库中，便于代码共享、依赖管理和版本控制。

```
persona/
├── docs/                  # 项目文档站（VitePress）与设计文档
├── core/                  # Rust 核心库（加密、存储、认证、同步协议）
├── cli/                   # 命令行客户端（复用 core）
├── desktop/               # 桌面应用（Tauri + React，独立 cargo workspace）
├── server/                # 可选同步服务器（Rust + Axum）
├── connect-server/        # Connect 本机自动化端点（secrets automation）
├── agents/                # 代理进程（ssh-agent 等）
├── browser-extension/     # 浏览器扩展
├── mobile/                # 移动端（原生 App，规划中，见下文）
├── website/               # 项目官网
├── scripts/               # 构建/开发脚本
├── docker/                # 容器化部署
├── Cargo.toml             # Rust workspace 配置
└── README.md              # 项目说明
```

## 架构设计

### 分层架构

```
┌─────────────────────────────────────┐
│           用户界面层                 │
│  Desktop (Tauri+React) / CLI        │
│  Mobile (原生 Swift / Kotlin)       │
├─────────────────────────────────────┤
│           业务逻辑层                 │
│         Core Library (Rust)         │
│  ┌─────────┬─────────┬─────────┐    │
│  │ Crypto  │ Storage │  Auth   │    │
│  └─────────┴─────────┴─────────┘    │
├─────────────────────────────────────┤
│           数据存储层                 │
│    SQLCipher + 文件系统加密         │
├─────────────────────────────────────┤
│           系统接口层                 │
│   操作系统API + 硬件安全模块        │
└─────────────────────────────────────┘
```

### 技术栈组合

#### Core Library (Rust)

- **职责**: 核心加密、存储、认证逻辑
- **优势**: 内存安全、高性能、跨平台
- **依赖**: ring, argon2, aes-gcm, rusqlite

#### Desktop App (Tauri + React)

- **职责**: 桌面端用户界面
- **优势**: 轻量级、安全、现代 UI
- **依赖**: React, TypeScript, Tailwind CSS

#### Mobile App（原生，规划中）

- **职责**: 移动端用户界面
- **技术决策**: iOS、Android、HarmonyOS 各自用**平台原生技术**
  开发——iOS Swift/SwiftUI（LocalAuthentication + CryptoKit Secure
  Enclave）、Android Kotlin/Jetpack Compose（BiometricPrompt +
  Android Keystore）、HarmonyOS ArkTS/ArkUI（userIAM userAuth +
  HUKS）。不经 Flutter/Rust FFI 中转：生物识别与密钥存储是深度平台
  特性，原生 API 才能拿到完整语义，中转层只会损耗语义并增加攻击面。
  详见 `docs/biometric-unlock-design.md` §7.2。

#### Sync Server (Rust + Axum)

- **职责**: 可选的端到端加密同步
- **优势**: 零知识架构、高性能
- **依赖**: axum, sqlx, tokio

## 数据流设计

### 本地数据流

```
用户输入 → UI层 → Core库 → 加密存储 → 本地数据库
```

### 跨设备同步流

```
设备A → 端到端加密 → 同步服务器 → 端到端解密 → 设备B
```

### 安全边界

- **UI层**: 用户交互，不处理敏感数据
- **Core层**: 所有加密操作，敏感数据处理
- **存储层**: 加密数据持久化
- **网络层**: 仅传输加密数据

## 开发工作流

### 构建命令

```bash
# 构建核心库
cargo build -p persona-core

# 开发桌面应用
pnpm --filter desktop run tauri:dev

# 运行服务器
cargo run -p persona-server

# 运行所有测试
cargo test --workspace
```

### 依赖管理

- **Rust**: Cargo workspace 统一管理
- **Node.js**: pnpm workspace（根 package.json + pnpm-workspace.yaml）

### 代码共享策略

- **核心逻辑**: Rust core 库
- **数据模型**: core models（同步信封协议跨端一致）
- **UI 组件**: 各平台独立实现（桌面 React / 移动端原生）

## 安全考虑

### 代码隔离

- **敏感操作**: 仅在 core 库中实现
- **UI层**: 不直接处理密钥和敏感数据
- **网络层**: 仅传输加密数据

### 构建安全

- **依赖锁定**: Cargo.lock, pnpm-lock.yaml
- **安全审计**: cargo audit, pnpm audit
- **代码签名**: 发布版本数字签名

### 运行时安全

- **内存保护**: zeroize 清理敏感数据
- **进程隔离**: 各组件独立进程
- **权限最小化**: 仅申请必要权限

## 部署策略

### 桌面应用

- **打包**: Tauri bundle
- **分发**: GitHub Releases + 应用商店
- **更新**: 内置自动更新

### 移动应用

- **打包**: Xcode / Android Studio 原生构建
- **分发**: App Store + Google Play
- **更新**: 应用商店机制

### 服务器

- **容器化**: Docker 部署
- **云平台**: 支持主流云服务
- **监控**: 日志和性能监控

## 开发路线图

当前状态以仓库 `TODO.md` 为准（逐项含完成日期与验证方式），此处只保留
阶段划分：

1. **桌面版**（已完成并持续迭代）：vault、加密存储、同步、SSH agent、
   passkey、生物识别门禁与硬件绑定包裹层等
2. **服务器与自动化**：自托管同步服务器、Connect secrets automation
3. **移动端**：iOS / Android 原生应用（含平台生物识别解锁，见上文
   技术决策）
4. **企业功能**：团队共享、企业策略、审计报表

这种 Monorepo 结构的优势：

1. **统一管理**: 所有代码在一个仓库中
2. **代码共享**: Core 库被多个客户端复用
3. **版本同步**: 避免版本不一致问题
4. **简化 CI/CD**: 统一的构建和部署流程
5. **便于重构**: 跨项目重构更容易
