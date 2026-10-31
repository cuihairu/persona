# 2026-10-31 界面审核报告（impeccable 技能） — persona

> 批次条目：`persona|desktop + website`
> 审核人：cuihairu（impeccable 技能 v4.8.0）
> 结论：**整体优秀，但营销站是明显的薄弱环节**。桌面端是这套产品里最接近「1Password 式」成熟度的界面——层级、色彩、暗色模式、空/锁/窄态都经得起推敲，审核后仅 1 处小概率缺陷（React 受控警告）+ 1 处侧栏次级文字对比度不达标（已修复）。相比之下营销站（website）几乎全面踩坑：主按钮渐变对比度不达标、平台文案 2.56:1、页脚三条死链、`Button>Link` 嵌套交互 5 处。营销站的问题不是「细节没打磨」，而是**核心 CTA 的视觉层级建立在低于 WCAG AA 的对比度之上**——这是品牌站最不该出问题的地方。

---

## 1. 审核范围与方法

| 界面                                    | 方法                                                                                          |     是否渲染核验     |
| --------------------------------------- | --------------------------------------------------------------------------------------------- | :------------------: |
| `persona/desktop`（Tauri 2 + React 19） | 构建 `dist` 静态伺服 + `__TAURI_INTERNALS__.invoke` fixture 注入 + Playwright（chromium）走查 |   ✅ 是，36 张截图   |
| `persona/website`（umi 4 + antd 6）     | 静态源码审核                                                                                  | ❌ 否（见 3.1 说明） |

**persona/desktop 走查矩阵**（截图目录 `/home/cui/.cache/persona-audit-desktop/`，deviceScaleFactor=2）：

- 默认窗口 1200×800 亮色：全部 16 个侧栏视图（全部/收藏/最近 + 8 类 + 通行密钥/统计/SSH Agent/钱包/安全瞭望/生成器）
- 暗色模式（`html.dark`）：全部/统计/生成器/安全瞭望
- 最小窗口 800×600 窄屏：全部/统计/生成器/密码
- 锁定态（`is_service_unlocked=false`）：解锁屏
- 空态（0 条凭据）：全部/收藏/加密钱包
- 详情面板、新建凭据弹窗

**persona/website 页面清单**（`.umirc.ts` 仅 5 条路由）：`/`、`/features`、`/download`、`/docs`、`/pricing`。无嵌套路由。

**对比基线**：`DESIGN.md` 未提供（`DESIGN_NOTE.md` 存在于仓根，但它是**身份选择语义的行为设计分析**，不是视觉设计规范）。故本报告以 WCAG 2.1 AA 与通用 UI 准则为基准，不设视觉基准线比对。

---

## 2. persona/desktop 审核

### 2.1 总体评价

桌面端是这套产品里完成度最高的界面。侧栏导航的「1Password 式」单行选中块、分组标题、徽标计数、工具分组结构清晰；暗色模式通过 `html.dark` 类 + `persona-theme` localStorage 正确翻转；所有 16 个视图 + 详情面板 + 新建弹窗 + 锁定屏 + 空态 + 最小窗口 800×600 均正常渲染，无布局破损、无错位、无溢出。主按钮 `#2563eb`（5.17:1）、导航文字（10.36:1）、正文（17.85:1）对比度全部达标；键盘焦点环（`.btn`/`.input` focus-visible ring）齐全；`aria-current="page"`、`aria-label`、`aria-hidden` 图标、`tabular-nums` 徽标等可访问性细节到位。impeccable `detect --json` 对 desktop 返回 `[]`（无自动检测发现的缺陷）。

### 2.2 已修复（1 项）

**P1（AA 不达标）— 侧栏次级文字对比度**：`src/components/Sidebar.tsx:72`（计数徽标）与 `:87`（分组标题）使用 `text-secondary-400 dark:text-secondary-500`，实测**亮色 2.56:1 / 暗色 3.72:1**，均低于 WCAG AA 正文 4.5:1。徽标与分组标题虽为辅助信息，但 11px 小字号 + 低对比在 264px 窄栏内可读性差。

- 修复：改为 `text-secondary-600 dark:text-secondary-400` → **亮色 7.59:1 / 暗色 6.92:1**（`fix(ui): sidebar secondary text contrast`，`96ce9f6`）。
- 位置：`src/components/Sidebar.tsx` `NavRow` 计数 `span`、`GroupTitle`。

### 2.3 待办（1 项）

**P3 — React 受控/非受控警告**：所有状态下控制台均出现 `A component is changing from uncontrolled to controlled`（输入框 `value` 从 `undefined` 翻转为已定义值）。运行期未定位到具体组件（需二分），但该警告在 light/dark/empty/narrow 全矩阵复现，属真实应用问题而非审核工具产物。

- 建议：排查 `SettingsModal` 的表单字段与 `sidebar-search`——`value={searchQuery}` 初始为 `undefined`，`onChange` 后才成为字符串；若某受控输入初始值为 `undefined` 而非 `''`，即为元凶。统一初始化为空串。

### 2.4 审核工具产物（非应用缺陷，如实记录）

| 现象                                                                                                | 原因                                                                                                                                                                                                             | 处置                        |
| --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------- |
| 控制台 `Cannot read properties of undefined (reading 'unregisterListener')`                         | 应用 `@tauri-apps/api/event` 的 `listen()`（`QuickAccessPanel`、`useQuickAccessBridge`、`useAutoLockEvents`）在浏览器渲染下的清理逻辑依赖 `unregisterListener`，而 fixture 仅注入了 `invoke`/`transformCallback` | 属 fixture 缺口，非应用 bug |
| 错误横幅「加载 SSH 密钥失败」「列出 demo 的通行密钥失败」「自定义字段读取失败」「加载安全评分失败」 | fixture 对未处理的 invoke 命令返回 `ok(null)`，部分视图期待非空数组                                                                                                                                              | 属 fixture 缺口，非应用 bug |

---

## 3. persona/website 审核

### 3.1 渲染核验未执行（重要说明）

website **未执行真实渲染核验**，原因：

1. 无 `node_modules` 且任务禁止 `npm install`；
2. 无构建产物 `dist`；
3. 演示站点 `https://persona.cuihairu.site` 不可达（HTTP 000），且 README 无「演示站点」账号。

因此 website 仅做**静态源码 + 样式表审核**。以下对比度数值基于样式表颜色与白/渐变背景的 WCAG 相对亮度计算，**未经验证**；建议依赖安装后运行 `npm run dev` 复核。所有色相族与视觉方向（indigo→violet 渐变体系）保持不变，仅按需加深。

### 3.2 已修复（2 项）

**P1（AA 不达标）— 主按钮渐变对比度**：`.ant-btn-primary` 渐变 `#6366f1→#8b5cf6`，实测**白字 4.47→4.23:1**，低于 4.5:1。该渐变用于全站所有主 CTA（页头「下载」、Hero「免费下载」、各区块「了解更多」、CTA「立即下载」），是品牌站最关键的可交互元素。

- 修复：`src/global.less` 基态渐变 → `#4f46e5→#7c3aed`（**6.28→5.70:1**，hover `#4338ca→#6d28d9` 达 7.89→7.10:1）（`fix(ui): primary button gradient contrast`，`e124733`）。
- 位置：`src/global.less` `.ant-btn-primary`。

**P2（AA 不达标）— 落地页文字对比度**：

- `.platforms`「支持平台：」`#94a3b8` 实为 **2.56:1**，14px 正文不达标 → 改 `#64748b`（**4.76:1**）。
- `.badge`（Hero 徽章）`#6366f1` 在 10% indigo 底上约 4.3:1 → 改 `#4f46e5`。
- `.stats`/`.cta` 区块渐变背景 `#6366f1→#8b5cf6` 上白字 4.23:1 → 渐变改 `#4f46e5→#7c3aed`；`.statLabel`（14px）白字 alpha 0.8 → 0.95、`.ctaDesc` 0.9 → 0.95。

修复：`fix(ui): landing page contrast`（`6081531`），位置 `src/pages/index.less`。

### 3.3 待办（2 项）

**P2 — 嵌套交互 `Button>Link`（5 处）**：主按钮内包裹 `<Link>` 而非用 `Button` 的 `href`/导航，产生「交互元素嵌套交互元素」：

- `src/layouts/index.tsx:44`（页头「下载」）
- `src/pages/index.tsx:81`（Hero「免费下载」）、`:179`、`:231`（「了解更多」×2）、`:268`（CTA「立即下载」）

这既破坏可访问性树（读屏无法正确宣告嵌套交互），也违背 antd `Button` 的导航用法（应传 `href`，或外层用 `Link` 包整钮）。

- 建议：对站内路由改用 `<Link to="/download">` 包裹 `<Button>`（Link 在外、Button 在内，单一路由语义），或给 `Button` 增加 `href` 支持站内导航。

**P2 — 页脚死链（3 条）**：`src/layouts/index.tsx:71-73` 页脚「安全性」`/security`、「隐私政策」`/privacy`、「使用条款」`/terms`，但 `.umirc.ts` 只有 5 条路由，**这 3 条路径不存在 → 404**。

- 建议：要么补充对应页面，要么指向已存在内容（如 `/docs` 相应章节）；若暂无文案，先移除链接并标注「即将上线」。

### 3.4 观察项（非缺陷，仅记录）

- `src/pages/index.less:172` `.vaultSubtitle`（Hero mockup 内 12px `#94a3b8`，2.56:1）——属装饰性示意图内的假内容，非真实交互文案，豁免但记录。
- `src/pages/docs.less:122` 文档列表「→ 」前缀箭头 `#94a3b8`（2.56:1）——装饰性图形符号，豁免但记录。
- `src/pages/index.less:60` Hero 标题渐变 `.gradient` 末端 `#d946ef`（约 3.46:1）——56px 大字号，按 WCAG 大文本 3:1 阈值**达标**，但接近边界，建议留意。
- `src/global.less:58` 滚动条 thumb hover `#94a3b8`——装饰性 UI 组件，豁免。
- 页头/页脚与移动端断点（`@media max-width: 968px`）在源码中定义齐全，但未渲染验证，见 3.1。

---

## 4. 汇总

| 界面            | 问题数 |             已修复              |                待办                 | 修复提交             |
| --------------- | :----: | :-----------------------------: | :---------------------------------: | -------------------- |
| persona/desktop |   2    |         1（P1 对比度）          |          1（P3 受控警告）           | `96ce9f6`            |
| persona/website |   6    | 2（P1 按钮渐变、P2 文案对比度） | 2（P2 嵌套交互、P2 死链）+ 4 观察项 | `e124733`、`6081531` |

**总评**：desktop 已是可发布级界面；website 的核心 CTA 对比度与页脚信息架构需在对外之前修正——尤其嵌套 `Button>Link` 与死链这两项是真实用户会碰到的（读屏错乱、点击 404）。website 渲染核验缺失是本报告最大局限，依赖安装后务必先跑 `npm run dev` 复核本报告 3.2 的对比度修复。
