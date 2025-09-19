# Persona 项目结构说明

## 📁 Monorepo 架构

本项目采用 **Monorepo** 架构，将所有相关代码统一管理在一个仓库中，便于代码共享、依赖管理和版本控制。

```
persona/
├── 📋 docs/                    # 项目文档
│   ├── README.md               # 文档导航
│   ├── scenarios-analysis.md   # 场景分析
│   ├── security-requirements.md # 安全需求
│   └── project-structure.md    # 项目结构说明
│
├── 🦀 core/                    # Rust 核心库
│   ├── src/
│   │   ├── crypto/             # 加密模块
│   │   ├── storage/            # 存储模块
│   │   ├── auth/               # 认证模块
│   │   ├── models/             # 数据模型
│   │   └── lib.rs              # 库入口
│   ├── tests/                  # 单元测试
│   └── Cargo.toml              # Rust 配置
│
├── 🖥️ desktop/                 # 桌面应用 (Tauri + React)
│   ├── src/                    # React 前端代码
│   ├── src-tauri/              # Tauri 后端代码
│   │   └── src/
│   ├── package.json            # Node.js 依赖
│   └── tauri.conf.json         # Tauri 配置
│
├── 📱 mobile/                  # 移动应用 (Flutter)
│   ├── lib/                    # Dart 代码
│   ├── android/                # Android 特定代码
│   ├── ios/                    # iOS 特定代码
│   ├── rust/                   # Rust FFI 桥接
│   └── pubspec.yaml            # Flutter 配置
│
├── 🌐 server/                  # 可选同步服务器
│   ├── src/                    # Rust 服务器代码
│   ├── migrations/             # 数据库迁移
│   └── Cargo.toml              # Rust 配置
│
├── 🔗 shared/                  # 共享资源
│   ├── schemas/                # 数据模式定义
│   ├── proto/                  # Protocol Buffers
│   └── assets/                 # 共享资源文件
│
├── 🛠️ tools/                   # 开发工具
│   ├── scripts/                # 构建脚本
│   └── generators/             # 代码生成器
│
├── Cargo.toml                  # Rust Workspace 配置
├── .gitignore                  # Git 忽略文件
├── LICENSE                     # 开源许可证
└── README.md                   # 项目说明
```

## 🏗️ 架构设计

### 分层架构
```
┌─────────────────────────────────────┐
│           用户界面层                 │
│  Desktop (Tauri+React)              │
│  Mobile (Flutter)                   │
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

#### 🦀 Core Library (Rust)
- **职责**: 核心加密、存储、认证逻辑
- **优势**: 内存安全、高性能、跨平台
- **依赖**: ring, argon2, aes-gcm, rusqlite

#### 🖥️ Desktop App (Tauri + React)
- **职责**: 桌面端用户界面
- **优势**: 轻量级、安全、现代UI
- **依赖**: React, TypeScript, Tailwind CSS

#### 📱 Mobile App (Flutter)
- **职责**: 移动端用户界面
- **优势**: 跨平台、原生性能、丰富UI
- **依赖**: Flutter, Dart, flutter_rust_bridge

#### 🌐 Sync Server (Rust + Axum)
- **职责**: 可选的端到端加密同步
- **优势**: 零知识架构、高性能
- **依赖**: axum, sqlx, tokio

## 🔄 数据流设计

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

## 🛠️ 开发工作流

### 构建命令
```bash
# 构建核心库
cargo build -p persona-core

# 开发桌面应用
cd desktop && npm run tauri:dev

# 开发移动应用
cd mobile && flutter run

# 运行服务器
cargo run -p persona-server

# 运行所有测试
cargo test --workspace
```

### 依赖管理
- **Rust**: Cargo workspace 统一管理
- **Node.js**: desktop/package.json
- **Flutter**: mobile/pubspec.yaml

### 代码共享策略
- **核心逻辑**: Rust core 库
- **数据模型**: shared/schemas
- **UI组件**: 各平台独立实现
- **配置文件**: 统一格式，分平台存储

## 🔒 安全考虑

### 代码隔离
- **敏感操作**: 仅在 core 库中实现
- **UI层**: 不直接处理密钥和敏感数据
- **网络层**: 仅传输加密数据

### 构建安全
- **依赖锁定**: Cargo.lock, package-lock.json
- **安全审计**: cargo audit, npm audit
- **代码签名**: 发布版本数字签名

### 运行时安全
- **内存保护**: zeroize 清理敏感数据
- **进程隔离**: 各组件独立进程
- **权限最小化**: 仅申请必要权限

## 📦 部署策略

### 桌面应用
- **打包**: Tauri bundle
- **分发**: GitHub Releases + 应用商店
- **更新**: 内置自动更新

### 移动应用
- **打包**: Flutter build
- **分发**: App Store + Google Play
- **更新**: 应用商店机制

### 服务器
- **容器化**: Docker 部署
- **云平台**: 支持主流云服务
- **监控**: 日志和性能监控

## 🚀 开发路线图

### Phase 1: MVP (核心功能)
- ✅ 项目结构搭建
- 🔄 Core 库基础实现
- 🔄 桌面端基础UI
- 🔄 本地加密存储

### Phase 2: 完整桌面版
- 📋 完整功能实现
- 📋 用户体验优化
- 📋 安全测试

### Phase 3: 移动端
- 📋 Flutter 应用开发
- 📋 生物识别集成
- 📋 跨平台同步

### Phase 4: 企业功能
- 📋 团队共享功能
- 📋 企业策略管理
- 📋 审计日志系统

这种 Monorepo 结构的优势：
1. **统一管理**: 所有代码在一个仓库中
2. **代码共享**: Core 库被多个客户端复用
3. **版本同步**: 避免版本不一致问题
4. **简化CI/CD**: 统一的构建和部署流程
5. **便于重构**: 跨项目重构更容易