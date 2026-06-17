import { defineConfig } from 'vitepress'

const base = process.env.VITEPRESS_BASE ?? '/persona/'

const sidebar = [
  {
    text: '项目概述',
    items: [
      { text: '项目简介', link: '/overview/introduction' },
      { text: '核心功能', link: '/overview/features' },
      { text: '技术架构', link: '/overview/architecture' },
      { text: '安全特性', link: '/overview/security' }
    ]
  },
  {
    text: '需求分析',
    items: [
      { text: '场景分析', link: '/analysis/scenarios' },
      { text: '安全需求', link: '/analysis/security-requirements' },
      { text: '用户需求', link: '/analysis/user-requirements' },
      { text: '技术需求', link: '/analysis/technical-requirements' }
    ]
  },
  {
    text: '系统设计',
    items: [
      { text: '整体架构', link: '/design/architecture' },
      { text: '数据模型', link: '/design/data-model' },
      { text: 'API 设计', link: '/design/api' },
      { text: '安全设计', link: '/design/security' },
      { text: 'UI/UX 设计', link: '/design/ui-ux' }
    ]
  },
  {
    text: '开发指南',
    items: [
      { text: '环境搭建', link: '/development/setup' },
      { text: '项目结构', link: '/development/structure' },
      { text: '编码规范', link: '/development/coding-standards' },
      { text: '测试指南', link: '/development/testing' },
      { text: '部署指南', link: '/development/deployment' }
    ]
  },
  {
    text: 'API 文档',
    items: [
      { text: '认证 API', link: '/api/authentication' },
      { text: '身份管理 API', link: '/api/identity' },
      { text: '数据同步 API', link: '/api/sync' },
      { text: '安全 API', link: '/api/security' }
    ]
  },
  {
    text: '用户手册',
    items: [
      { text: '快速开始', link: '/user/quick-start' },
      { text: '桌面应用', link: '/user/desktop' },
      { text: '移动应用', link: '/user/mobile' },
      { text: '常见问题', link: '/user/faq' },
      { text: '故障排除', link: '/user/troubleshooting' }
    ]
  },
  {
    text: '贡献指南',
    items: [
      { text: '如何贡献', link: '/contributing/how-to-contribute' },
      { text: '代码审查', link: '/contributing/code-review' },
      { text: '发布流程', link: '/contributing/release-process' }
    ]
  },
  {
    text: '附录',
    items: [{ text: '附录', link: '/appendix/' }]
  }
]

export default defineConfig({
  lang: 'zh-CN',
  title: 'Persona',
  description: 'Master your digital identity. Switch freely with one click.',
  base,
  srcDir: 'src',
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ['link', { rel: 'icon', href: `${base}persona-logo.svg` }],
    ['meta', { name: 'theme-color', content: '#FE7336' }]
  ],
  markdown: {
    theme: {
      light: 'github-light',
      dark: 'github-dark'
    }
  },
  themeConfig: {
    logo: '/persona-logo.svg',
    siteTitle: 'Persona 数钥',
    nav: [
      { text: '指南', link: '/overview/introduction' },
      { text: '开发', link: '/development/setup' },
      { text: 'API', link: '/api/authentication' },
      { text: '路线图', link: 'https://github.com/cuihairu/persona/blob/main/docs/ROADMAP.md' }
    ],
    sidebar,
    outline: {
      level: [2, 3],
      label: '本页目录'
    },
    search: {
      provider: 'local',
      options: {
        translations: {
          button: {
            buttonText: '搜索文档',
            buttonAriaLabel: '搜索文档'
          },
          modal: {
            displayDetails: '显示详情',
            resetButtonTitle: '清除搜索条件',
            backButtonTitle: '关闭搜索',
            noResultsText: '未找到结果',
            footer: {
              selectText: '选择',
              selectKeyAriaLabel: '回车',
              navigateText: '切换',
              navigateUpKeyAriaLabel: '上箭头',
              navigateDownKeyAriaLabel: '下箭头',
              closeText: '关闭',
              closeKeyAriaLabel: 'Esc'
            }
          }
        }
      }
    },
    socialLinks: [
      { icon: 'github', link: 'https://github.com/cuihairu/persona' }
    ],
    editLink: {
      pattern: 'https://github.com/cuihairu/persona/edit/main/docs/src/:path',
      text: '在 GitHub 上编辑此页'
    },
    lastUpdated: {
      text: '最后更新',
      formatOptions: {
        dateStyle: 'medium',
        timeStyle: 'short'
      }
    },
    docFooter: {
      prev: '上一页',
      next: '下一页'
    },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 Persona Team'
    },
    returnToTopLabel: '返回顶部',
    sidebarMenuLabel: '菜单',
    darkModeSwitchLabel: '外观',
    lightModeSwitchTitle: '切换到浅色模式',
    darkModeSwitchTitle: '切换到深色模式'
  }
})
