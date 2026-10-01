# 仓库设计原型/界面素材盘点

## 已入库的设计资产（出处）

| 文件 | 位置（tracked） | 首次入库 commit | 日期 | 说明 |
|---|---|---|---|---|
| light-full.png | docs/branding/ui/light-full.png、docs/src/public/ui/light-full.png | bae6a51（README 段） / 70331ce（站点副本） | 2026-09-30 | 亮色主题全窗（三栏布局） |
| dark-full.png | docs/branding/ui/dark-full.png、docs/src/public/ui/dark-full.png | bae6a51 / 70331ce | 2026-09-30 | 暗色主题全窗 |
| light-sidebar.png | docs/branding/ui/light-sidebar.png、docs/src/public/ui/light-sidebar.png | bae6a51 / 70331ce | 2026-09-30 | 亮色侧栏特写（1Password 风格分组） |
| dark-sidebar.png | docs/branding/ui/dark-sidebar.png、docs/src/public/ui/dark-sidebar.png | bae6a51 / 70331ce | 2026-09-30 | 暗色侧栏特写 |
| sidebar-before-redesign.png | docs/branding/ui/sidebar-before-redesign.png、docs/src/public/ui/sidebar-before-redesign.png | bae6a51 / 70331ce | 2026-09-30 | 侧栏重设计前对比 |
| persona-logo.svg | docs/src/public/persona-logo.svg、docs/branding/logo.svg（SVG 源） | 1c85352（初始品牌提交） | 2026-09-25 | 主 Logo（矢量） |
| wordmark-horizontal.svg | docs/branding/wordmark-horizontal.svg | 1c85352 | 2026-09-25 | 横排字标（Persona 数钥） |

**说明**：站点 VitePress 用 `/ui/*.png`（public 副本），README/品牌目录各保留一份源，均已 git 跟踪。未发现 `docs/design/`、`ui_sandbox_out/` 或其他原型文件（.fig/.sketch/.xd/.ai/.psd）。

## 原型缺口清单（等用户交付素材）

docs/src/previews/ui.md 已列入下表。**严禁自行生成或替换任何 SVG/设计资产**。

| 视图 | 缺失原因 | 建议交付形式 |
|---|---|---|
| SSH Agent 面板 | 仓库无对应设计原型/截图 | PNG/JPG（明暗双主题，含托管密钥列表、agent 启停态、签名审批弹窗） |
| 设置 · 安全中心 | 同上 | PNG/JPG（修改主密码、生物识别解锁、自动锁定、旅行模式） |
| 设置 · 同步设备 | 同上 | PNG/JPG（设备登记/授权/吊销、冲突裁决队列） |
| 条目详情 · 密文揭示 | 同上 | PNG/JPG（掩显→再认证→明文揭示流程，保留操作细节） |
| 新建 / 编辑凭据弹窗 | 同上 | PNG/JPG（分类字段、密码生成器、表单校验错误态） |
| 统计 / 安全瞭望 | 同上 | PNG/JPG（库内元数据、弱口令/重用检测） |
| 快速访问 | 同上 | PNG/JPG（全局热键唤起的速查面板） |
| CLI 终端会话 | 同上 | PNG/JPG（persona CLI 关键命令终端记录，浅色/深色择一或双份） |
| 浏览器扩展 | 同上 | PNG/JPG（填充建议弹层、身份切换） |
| 移动端（Android / iOS / 鸿蒙） | 同上 | PNG/JPG（三端原生界面，关键视图） |

## 补充说明

- 运行时走查产出（`~/.cache/persona-ui-shots/shots-walk1002f/` 共 17 张）**属于自动化截图，不是设计原型资产**，不应入库到 docs 的设计素材集中。
- Dependabot：仓库 `.github/` 下**无** `dependabot.yml`（也无 `.yaml`/变体），远端 main 历史中从未存在该文件。GitHub 仓库的 Dependabot 告警（304 处 fixed、2 dismissed）来自本仓库依赖生态的历史扫描与现有依赖更新追踪；**配置文件不存在 = 未启用 version-updates 配置文件**。这属于仓库当前配置状态（未配配置文件）。PR 历史显示 Dependabot 曾自动创建 PR（#21 等）处理安全更新——说明平台级 Dependabot 已在工作（基于默认行为或组织策略），但仓库级自定义 `dependabot.yml` 并未配置。按「顺手确认 Dependabot 配置已生效」的要求：**仓库级 dependabot.yml 不存在，平台级 Dependabot 对本仓库依然在生效（alerts 大部分 fixed，近期有自动 PR #21 merged 2026-09-30）。如需显式配置（schedule/groups/ignore/assignees 等）需补 `.github/dependabot.yml`；当前未配置文件不等同失效。**
- docs 锁文件：`docs/package-lock.json` 存在（npm），`docs/pnpm-lock.yaml` 在历史曾存在（62940e8 引入 mermaid 时可能用过 pnpm，后续未入库且 CI 已有守卫 `docs.yml` 禁止 docs 出现 pnpm-lock.yaml/yarn.lock）。当前工作区 docs 下无第二份锁文件，CI 门禁有效。
