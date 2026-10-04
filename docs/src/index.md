---
layout: home

hero:
  name: Persona 数钥
  text: 多分身数字身份运行时
  tagline: Master your digital identity. Switch freely with one click.
  image:
    src: /persona-logo.svg
    alt: Persona logo
  actions:
    - theme: brand
      text: 快速开始
      link: /user/quick-start
    - theme: alt
      text: 查看架构
      link: /overview/architecture
    - theme: alt
      text: GitHub
      link: https://github.com/cuihairu/persona

features:
  - title: 本地优先与端到端加密
    details: 敏感身份材料只在本地解密；服务器只见密文与元数据，无法解密任何凭据。
  - title: 多分身上下文
    details: 将工作、个人、开发、SSH、浏览器等身份材料按场景隔离和切换。
  - title: 跨端统一边界
    details: CLI、桌面端、浏览器扩展和 SSH Agent 共用同一套本地服务与策略。
---

## 界面预览

<UiCarousel />

桌面明暗主题、侧栏细节与移动端界面轮播展示，更多截图与素材出处见
[界面预览](/previews/ui)、[素材盘点](/previews/assets)。

## 从这里开始

- [快速开始](/user/quick-start) 构建桌面应用或 CLI，创建你的第一个加密密码库。
- [项目简介](/overview/introduction) 了解 Persona 的问题边界和设计理念。
- [核心概念](/concepts/index) 分身、上下文、材料、策略、动作——Persona 的理论基础。
- [技术架构](/overview/architecture) 看分层结构与端到端加密同步的设计。
- [安全设计](/design/security) 密钥层级、威胁模型与安全边界。
- [项目结构](/development/structure) 配置本地开发与浏览 monorepo 布局。
- [工程文档](https://github.com/cuihairu/persona/tree/main/docs) E2EE 同步设计、威胁模型、可复现构建等深度文档。
