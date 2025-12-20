# Persona 数字身份管理系统

> **Master your digital identity. Switch freely with one click.**

欢迎来到 Persona 数字身份管理系统的官方文档！

## 🎯 项目愿景

在数字化时代，我们每个人都拥有多重数字身份——工作身份、社交身份、学习身份、娱乐身份等。Persona 致力于帮助用户安全、便捷地管理这些多重数字身份，实现"一键切换，自由掌控"的理想体验。

## ✨ 核心特性

### 🔐 安全至上
- **零知识架构**：所有敏感数据本地加密，服务器无法访问用户隐私
- **分层加密**：采用多层加密策略，确保数据安全
- **硬件安全**：支持 TPM、Secure Enclave 等硬件安全模块
- **生物识别**：指纹、面部识别等多因素认证

### 🚀 极致体验
- **一键切换**：快速在不同数字身份间切换
- **智能同步**：跨设备无缝同步身份数据
- **离线优先**：核心功能支持离线使用
- **现代界面**：简洁直观的用户界面设计

### 🌐 跨平台支持
- **桌面应用**：基于 Tauri 的原生桌面应用
- **移动应用**：Flutter 开发的 iOS/Android 应用
- **Web 扩展**：浏览器扩展支持
- **API 接口**：开放的 API 供第三方集成

## 🏗️ 技术架构

Persona 采用现代化的技术栈，确保性能、安全性和可维护性：

- **后端核心**：Rust - 内存安全、高性能
- **桌面前端**：Tauri + React - 轻量级、原生体验
- **移动端**：Flutter - 跨平台、一致体验
- **数据库**：SQLite + 加密 - 本地存储、隐私保护
- **同步服务**：可选的端到端加密同步

## 📚 文档导航

### 🔍 了解项目
- [项目简介](./overview/introduction.md) - 深入了解 Persona 的设计理念
- [核心功能](./overview/features.md) - 详细功能特性介绍
- [技术架构](./overview/architecture.md) - 系统架构设计
- [安全特性](./overview/security.md) - 安全机制详解

### 📋 需求分析
- [场景分析](./analysis/scenarios.md) - 用户使用场景分析
- [安全需求](./analysis/security-requirements.md) - 安全需求规范
- [用户需求](./analysis/user-requirements.md) - 用户需求分析
- [技术需求](./analysis/technical-requirements.md) - 技术需求规范

### 🎨 系统设计
- [整体架构](./design/architecture.md) - 系统架构设计
- [数据模型](./design/data-model.md) - 数据结构设计
- [API 设计](./design/api.md) - 接口设计规范
- [安全设计](./design/security.md) - 安全架构设计
- [UI/UX 设计](./design/ui-ux.md) - 用户界面设计

### 👨‍💻 开发指南
- [环境搭建](./development/setup.md) - 开发环境配置
- [项目结构](./development/structure.md) - 代码结构说明
- [编码规范](./development/coding-standards.md) - 代码规范指南
- [测试指南](./development/testing.md) - 测试策略和方法
- [部署指南](./development/deployment.md) - 部署和发布流程

### 📖 用户手册
- [快速开始](./user/quick-start.md) - 快速上手指南
- [桌面应用](./user/desktop.md) - 桌面版使用说明
- [移动应用](./user/mobile.md) - 移动版使用说明
- [常见问题](./user/faq.md) - 常见问题解答
- [故障排除](./user/troubleshooting.md) - 问题诊断和解决

## 🚀 快速开始

### 环境要求

- **Rust**: 1.70+
- **Node.js**: 18+
- **Flutter**: 3.10+
- **操作系统**: Windows 10+, macOS 10.15+, Linux

### 构建项目

```bash
# 克隆项目
git clone https://github.com/cuihairu/persona.git
cd persona

# 构建核心库
cargo build --release

# 构建桌面应用
pnpm install
pnpm --filter desktop run tauri build

# 构建移动应用
cd ../mobile
flutter pub get
flutter build apk  # Android
flutter build ios  # iOS
```

## 🤝 参与贡献

我们欢迎所有形式的贡献！请查看 [贡献指南](./contributing/how-to-contribute.md) 了解如何参与项目开发。

### 贡献方式

- 🐛 **报告问题**：发现 bug 或提出改进建议
- 💡 **功能建议**：提出新功能想法
- 📝 **文档改进**：完善文档内容
- 💻 **代码贡献**：提交代码修复或新功能
- 🌍 **国际化**：帮助翻译界面和文档

## 📄 许可证

本项目采用 [MIT 许可证](../LICENSE) 开源。

## 🔗 相关链接

- [GitHub 仓库](https://github.com/cuihairu/persona)
- [问题追踪](https://github.com/cuihairu/persona/issues)
- [讨论区](https://github.com/cuihairu/persona/discussions)
- [发布页面](https://github.com/cuihairu/persona/releases)

## ⚠️ 安全提醒

Persona 是一个安全敏感的应用程序。在使用过程中，请：

- 定期备份您的身份数据
- 使用强密码和多因素认证
- 保持软件更新到最新版本
- 不要在不受信任的设备上使用
- 如发现安全问题，请通过安全邮箱联系我们

---

**让我们一起构建更安全、更便捷的数字身份管理系统！** 🚀
