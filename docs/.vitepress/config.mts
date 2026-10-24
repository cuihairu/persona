import { withMermaid } from "vitepress-plugin-mermaid";
import { defineConfig } from "vitepress";

const base = process.env.VITEPRESS_BASE ?? "/persona/";

// 双 locale：en 为根（默认），zh 挂 /zh/。两侧 sidebar/nav 各自维护，
// 页面一一配对（docs/src/<path>.md ↔ docs/src/zh/<path>.md）；被取代的
// 历史页（analysis/*）中文侧只留同款 superseded 横幅，不硬造翻译。
// 侧边栏只挂有实内容的页面：占位白页（仅一行标题）已删除，板块有稳定
// 内容后再挂回——空板块不如不挂。根目录 docs/*.md 工程文档（E2EE 同步
// 设计、威胁模型、可复现构建等）经 GitHub 链接在 nav「路线图」同款方式
// 可达，不在此重复。
const sidebarZh = [
  {
    text: "项目概述",
    items: [
      { text: "项目简介", link: "/zh/overview/introduction" },
      { text: "核心功能", link: "/zh/overview/features" },
      { text: "技术架构", link: "/zh/overview/architecture" },
      { text: "安全特性", link: "/zh/overview/security" },
    ],
  },
  {
    text: "核心概念",
    items: [
      { text: "概念总览", link: "/zh/concepts/index" },
      { text: "分身（Identity）", link: "/zh/concepts/identity" },
      { text: "上下文（Context）", link: "/zh/concepts/context" },
      { text: "身份材料（Material）", link: "/zh/concepts/material" },
      { text: "策略（Policy）", link: "/zh/concepts/policy" },
      { text: "动作（Action）", link: "/zh/concepts/action" },
      { text: "主体（Principal，预留）", link: "/zh/concepts/principal" },
    ],
  },
  {
    text: "界面预览",
    items: [
      { text: "界面一览", link: "/zh/previews/ui" },
      { text: "素材盘点", link: "/zh/previews/assets" },
    ],
  },
  {
    text: "API 文档",
    items: [
      { text: "认证 API", link: "/zh/api/authentication" },
      { text: "同步 API", link: "/zh/api/sync" },
    ],
  },
  {
    text: "用户手册",
    items: [
      { text: "快速开始", link: "/zh/user/quick-start" },
      { text: "身份（Identity）", link: "/zh/user/identity" },
      { text: "桌面应用", link: "/zh/user/desktop" },
      { text: "常见问题", link: "/zh/user/faq" },
      { text: "故障排除", link: "/zh/user/troubleshooting" },
    ],
  },
  {
    text: "需求分析",
    items: [
      { text: "场景分析", link: "/zh/analysis/scenarios" },
      { text: "安全需求", link: "/zh/analysis/security-requirements" },
    ],
  },
  {
    text: "系统设计",
    items: [
      { text: "产品定位与总体架构", link: "/zh/design/product" },
      { text: "整体架构", link: "/zh/design/architecture" },
      { text: "安全设计", link: "/zh/design/security" },
      { text: "Principal 与 Action 授权", link: "/zh/design/principal-action" },
      { text: "跨进程会话与授权中心", link: "/zh/design/session-center" },
    ],
  },
  {
    text: "开发指南",
    items: [
      { text: "环境搭建", link: "/zh/development/setup" },
      { text: "项目结构", link: "/zh/development/structure" },
    ],
  },
];

const sidebar = [
  {
    text: "Overview",
    items: [
      { text: "Introduction", link: "/overview/introduction" },
      { text: "Features", link: "/overview/features" },
      { text: "Architecture", link: "/overview/architecture" },
      { text: "Security", link: "/overview/security" },
    ],
  },
  {
    text: "Core Concepts",
    items: [
      { text: "Concepts Overview", link: "/concepts/index" },
      { text: "Identity", link: "/concepts/identity" },
      { text: "Context", link: "/concepts/context" },
      { text: "Identity Material", link: "/concepts/material" },
      { text: "Policy", link: "/concepts/policy" },
      { text: "Action", link: "/concepts/action" },
      { text: "Principal (reserved)", link: "/concepts/principal" },
    ],
  },
  {
    text: "UI Previews",
    items: [
      { text: "UI Tour", link: "/previews/ui" },
      { text: "Asset Inventory", link: "/previews/assets" },
    ],
  },
  {
    text: "API Reference",
    items: [
      { text: "Authentication API", link: "/api/authentication" },
      { text: "Sync API", link: "/api/sync" },
    ],
  },
  {
    text: "User Guide",
    items: [
      { text: "Quick Start", link: "/user/quick-start" },
      { text: "Identity", link: "/user/identity" },
      { text: "Desktop App", link: "/user/desktop" },
      { text: "FAQ", link: "/user/faq" },
      { text: "Troubleshooting", link: "/user/troubleshooting" },
    ],
  },
  {
    text: "Requirements Analysis",
    items: [
      { text: "Scenario Analysis", link: "/analysis/scenarios" },
      {
        text: "Security Requirements",
        link: "/analysis/security-requirements",
      },
    ],
  },
  {
    text: "System Design",
    items: [
      {
        text: "Product Positioning & Overall Architecture",
        link: "/design/product",
      },
      { text: "Architecture", link: "/design/architecture" },
      { text: "Security Design", link: "/design/security" },
      {
        text: "Principal & Action Authorization",
        link: "/design/principal-action",
      },
      { text: "Cross-Process Session Center", link: "/design/session-center" },
    ],
  },
  {
    text: "Development Guide",
    items: [
      { text: "Setup", link: "/development/setup" },
      { text: "Project Structure", link: "/development/structure" },
    ],
  },
];

export default withMermaid(
  defineConfig({
    vite: { build: { target: "esnext" } },
    base,
    title: "Persona",
    description: "Master your digital identity. Switch freely with one click.",
    srcDir: "src",
    cleanUrls: true,
    lastUpdated: true,
    head: [
      ["link", { rel: "icon", href: `${base}persona-logo.svg` }],
      ["meta", { name: "theme-color", content: "#FE7336" }],
    ],
    markdown: {
      theme: {
        light: "github-light",
        dark: "github-dark",
      },
    },
    locales: {
      root: {
        lang: "en-US",
        label: "English",
        title: "Persona",
        description:
          "Master your digital identity. Switch freely with one click.",
        themeConfig: {
          logo: "/persona-logo.svg",
          siteTitle: "Persona",
          nav: [
            { text: "Guide", link: "/overview/introduction" },
            { text: "UI", link: "/previews/ui" },
            { text: "Develop", link: "/development/structure" },
            { text: "API", link: "/api/sync" },
            { text: "中文", link: "/zh/" },
            {
              text: "Engineering Docs",
              link: "https://github.com/cuihairu/persona/tree/main/docs",
            },
            {
              text: "Roadmap",
              link: "https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md",
            },
          ],
          sidebar,
          outline: {
            level: [2, 3],
            label: "On this page",
          },
          search: {
            provider: "local",
          },
          socialLinks: [
            { icon: "github", link: "https://github.com/cuihairu/persona" },
          ],
          editLink: {
            pattern:
              "https://github.com/cuihairu/persona/edit/main/docs/src/:path",
            text: "Edit this page on GitHub",
          },
          lastUpdated: {
            text: "Last updated",
            formatOptions: {
              dateStyle: "medium",
              timeStyle: "short",
            },
          },
          docFooter: {
            prev: "Previous page",
            next: "Next page",
          },
          footer: {
            message: "Released under the MIT License.",
            copyright: "Copyright © 2026 Persona Team",
          },
          returnToTopLabel: "Back to top",
          sidebarMenuLabel: "Menu",
          darkModeSwitchLabel: "Appearance",
          lightModeSwitchTitle: "Switch to light mode",
          darkModeSwitchTitle: "Switch to dark mode",
        },
      },
      zh: {
        lang: "zh-CN",
        label: "简体中文",
        link: "/zh/",
        title: "Persona 数钥",
        description: "掌控你的数字身份。一键自由切换。",
        themeConfig: {
          logo: "/persona-logo.svg",
          siteTitle: "Persona 数钥",
          nav: [
            { text: "指南", link: "/zh/overview/introduction" },
            { text: "界面", link: "/zh/previews/ui" },
            { text: "开发", link: "/zh/development/structure" },
            { text: "API", link: "/zh/api/sync" },
            { text: "English", link: "/" },
            {
              text: "工程文档",
              link: "https://github.com/cuihairu/persona/tree/main/docs",
            },
            {
              text: "路线图",
              link: "https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md",
            },
          ],
          sidebar: sidebarZh,
          outline: {
            level: [2, 3],
            label: "本页目录",
          },
          search: {
            provider: "local",
            options: {
              translations: {
                button: {
                  buttonText: "搜索文档",
                  buttonAriaLabel: "搜索文档",
                },
                modal: {
                  displayDetails: "显示详情",
                  resetButtonTitle: "清除搜索条件",
                  backButtonTitle: "关闭搜索",
                  noResultsText: "未找到结果",
                  footer: {
                    selectText: "选择",
                    selectKeyAriaLabel: "回车",
                    navigateText: "切换",
                    navigateUpKeyAriaLabel: "上箭头",
                    navigateDownKeyAriaLabel: "下箭头",
                    closeText: "关闭",
                    closeKeyAriaLabel: "Esc",
                  },
                },
              },
            },
          },
          editLink: {
            pattern:
              "https://github.com/cuihairu/persona/edit/main/docs/src/:path",
            text: "在 GitHub 上编辑此页",
          },
          lastUpdated: {
            text: "最后更新",
            formatOptions: {
              dateStyle: "medium",
              timeStyle: "short",
            },
          },
          docFooter: {
            prev: "上一页",
            next: "下一页",
          },
          footer: {
            message: "Released under the MIT License.",
            copyright: "Copyright © 2026 Persona Team",
          },
          returnToTopLabel: "返回顶部",
          sidebarMenuLabel: "菜单",
          darkModeSwitchLabel: "外观",
          lightModeSwitchTitle: "切换到浅色模式",
          darkModeSwitchTitle: "切换到深色模式",
        },
      },
    },
  }),
);
