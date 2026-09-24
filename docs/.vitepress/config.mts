import { defineConfig } from "vitepress";

const base = process.env.VITEPRESS_BASE ?? "/persona/";

// 侧边栏只挂有实内容的页面：占位白页（仅一行标题）已删除，板块有稳定
// 内容后再挂回——空板块不如不挂。根目录 docs/*.md 工程文档（E2EE 同步
// 设计、威胁模型、可复现构建等）经 GitHub 链接在 nav「路线图」同款方式
// 可达，不在此重复。
const sidebar = [
  {
    text: "项目概述",
    items: [
      { text: "项目简介", link: "/overview/introduction" },
      { text: "核心功能", link: "/overview/features" },
      { text: "技术架构", link: "/overview/architecture" },
      { text: "安全特性", link: "/overview/security" },
    ],
  },
  {
    text: "用户手册",
    items: [{ text: "快速开始", link: "/user/quick-start" }],
  },
  {
    text: "需求分析",
    items: [
      { text: "场景分析", link: "/analysis/scenarios" },
      { text: "安全需求", link: "/analysis/security-requirements" },
    ],
  },
  {
    text: "系统设计",
    items: [
      { text: "整体架构", link: "/design/architecture" },
      { text: "安全设计", link: "/design/security" },
    ],
  },
  {
    text: "开发指南",
    items: [
      { text: "环境搭建", link: "/development/setup" },
      { text: "项目结构", link: "/development/structure" },
    ],
  },
];

export default defineConfig({
  lang: "zh-CN",
  title: "Persona",
  description: "Master your digital identity. Switch freely with one click.",
  base,
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
  themeConfig: {
    logo: "/persona-logo.svg",
    siteTitle: "Persona 数钥",
    nav: [
      { text: "指南", link: "/overview/introduction" },
      { text: "开发", link: "/development/structure" },
      {
        text: "工程文档",
        link: "https://github.com/cuihairu/persona/tree/main/docs",
      },
      {
        text: "路线图",
        link: "https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md",
      },
    ],
    sidebar,
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
    socialLinks: [
      { icon: "github", link: "https://github.com/cuihairu/persona" },
    ],
    editLink: {
      pattern: "https://github.com/cuihairu/persona/edit/main/docs/src/:path",
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
});
