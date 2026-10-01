# 素材盘点与缺口清单

本页供设计与文档维护用：记录**已入库设计素材的出处与变更史**，以及
**尚缺素材的视图清单**（等素材交付后补入）。

::: danger 素材红线
严禁自行生成、重绘或替换任何 SVG / 设计资产。缺口清单里的视图一律等
设计侧交付；自动化走查截图不是设计原型，不进素材集。
:::

## 已入库素材（出处）

| 素材                        | 位置（均 tracked）                          | 首次入库              | 最近变更                                  | 尺寸      | 说明                            |
| --------------------------- | ------------------------------------------- | --------------------- | ----------------------------------------- | --------- | ------------------------------- |
| light-full.png              | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51（2026-09-30） | 同首次入库                                | 3200×2000 | 亮色主题全窗（三栏布局）        |
| dark-full.png               | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51（2026-09-30） | 同首次入库                                | 3200×2000 | 暗色主题全窗                    |
| light-sidebar.png           | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51（2026-09-30） | 同首次入库                                | 528×2000  | 亮色侧栏特写（分组导航）        |
| dark-sidebar.png            | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51（2026-09-30） | 同首次入库                                | 528×2000  | 暗色侧栏特写                    |
| sidebar-before-redesign.png | `docs/branding/ui/` + `docs/src/public/ui/` | bae6a51（2026-09-30） | 同首次入库                                | 512×2000  | 侧栏重设计前形态（对比用）      |
| persona-logo.svg            | `docs/src/public/persona-logo.svg`          | 1c85352（2026-09-25） | 47e008a（2026-09-26）用户提供的取景框图标 | —         | 站点 favicon / 导航 / 首页 hero |
| logo.svg                    | `docs/branding/logo.svg`                    | 1c85352（2026-09-25） | 47e008a（2026-09-26）同上                 | —         | 品牌目录 Logo 源                |
| wordmark-horizontal.svg     | `docs/branding/wordmark-horizontal.svg`     | 1c85352（2026-09-25） | 未再变更                                  | —         | 横排字标（Persona 数钥）        |

读历史时注意两处容易误判的地方：

- `1c85352` 的 commit subject 是一次 CI 修复（Windows 测试分步定位挂死），
  三个 SVG 是搭车入库的，并非品牌提交。
- 五张 PNG 在 `docs/branding/ui/`（源）与 `docs/src/public/ui/`（站点副本）
  各存一份，两份**字节一致**（sha256 相同），改图时两边都要同步，否则站点
  与品牌目录会漂移。

::: tip 素材规范
新增 PNG/JPG 素材：放进 `docs/branding/ui/`，同步副本到
`docs/src/public/ui/`，然后在[界面一览](/previews/ui)与本页各加一行图注。
站点通过 `/ui/*.png` 引用（`base: /persona/` 自动加前缀）。
:::

## 原型缺口清单（等素材交付）

以下关键视图在仓库里既无设计原型文件（`.fig`/`.sketch`/`.xd`/`.ai`/`.psd`）
也无对应截图，等设计侧交付后补入：

| 视图                           | 现状                  | 建议交付形式                                                   |
| ------------------------------ | --------------------- | -------------------------------------------------------------- |
| SSH Agent 面板                 | 仓库无对应原型 / 截图 | PNG/JPG（明暗双主题：托管密钥列表、agent 启停、签名审批弹窗）  |
| 设置 · 安全中心                | 同上                  | PNG/JPG（修改主密码、生物识别解锁、自动锁定、旅行模式）        |
| 设置 · 同步设备                | 同上                  | PNG/JPG（设备登记 / 授权 / 吊销、冲突裁决队列）                |
| 条目详情 · 密文揭示            | 同上                  | PNG/JPG（掩显 → 再认证 → 明文揭示流程，保留操作细节）          |
| 新建 / 编辑凭据弹窗            | 同上                  | PNG/JPG（分类字段、密码生成器、表单校验错误态）                |
| 统计 / 安全瞭望                | 同上                  | PNG/JPG（库内元数据、弱口令 / 重用检测）                       |
| 快速访问                       | 同上                  | PNG/JPG（全局热键唤起的速查面板）                              |
| CLI 终端会话                   | 同上                  | PNG/JPG（persona CLI 关键命令终端记录，浅色 / 深色择一或双份） |
| 浏览器扩展                     | 同上                  | PNG/JPG（填充建议弹层、身份切换）                              |
| 移动端（Android / iOS / 鸿蒙） | 同上                  | PNG/JPG（三端原生界面，关键视图）                              |

`docs/src/design/` 目录存在但只有文字设计文档（`architecture.md`、
`security.md`），不是原型图资产；`docs/` 根下另有二十余份设计/协议类
Markdown（`E2EE_SYNC_DESIGN.md`、`PASSKEYS_DESIGN.md`、
`THREAT_MODEL.md` 等），同样都不是原型图。

## 走查截图的定位

运行时走查（`~/.cache/persona-ui-shots/` 下的 `shots-walk*/`）产出的是
**自动化回归截图**，用于验证交互链路是否走通，**不是设计原型**，不并入
`docs/` 素材集。

## 依赖更新轨道（Dependabot）

- 仓库级 `.github/dependabot.yml` 已随 `7b1c08a`（2026-10-02）推到默认
  分支，共 4 条 entry：npm `/`、npm `/docs`、cargo `/`、github-actions `/`，
  全部 weekly，dev 依赖分组，PR 前缀 `build` / `ci`（dependabot 默认的
  `Bump …` 标题过不了本仓 `conventional-commits.yml` 的 semantic 检查，
  故必须显式指定）。
- **已实证生效**：配置落地 3 分钟后即产出 PR #22–#32——cargo 10 条
  （`argon2`、`sha2`、`ed25519-dalek`、`tokio-util`、`dirs` 等）与
  actions 1 条（`ci: bump dtolnay/rust-toolchain`），标题带上了
  `build:` / `ci:` 前缀。一条 cargo entry 覆盖整个 workspace，成员 crate
  的 `Cargo.toml` 会一并出现在 PR 里。
- **npm 轨道已实证生效**：配置落地 19 分钟后产出 PR #33–#41——含
  dev-deps 分组聚合 PR（一次 19 个更新，改 `desktop` /
  `website` / `browser/chromium-extension` 三处 `package.json` + 根
  `pnpm-lock.yaml`）与单包 PR（`zod`、`react-hot-toast`、
  `tauri-apps/api` 等）。这推翻了落地初期的疑虑：根 `package.json` 虽
  自身 0 依赖，但 pnpm workspace 成员（desktop 41 / website 9 /
  chromium-extension 7）被根条目整体覆盖，锁文件也同步更新，无需按包
  补 `directory`（那反而会踩 dependabot-core #11135 的 pnpm 根锁
  不同步问题）。独立 npm 锁文件的 `/docs` entry 当时尚未产出 PR
  （`vue` 3.5.38→3.5.43、`rimraf` 6.0.1→6.1.3 有范围内更新），单独
  entry 排队靠后，下轮周更再核。
- 平台级安全更新（`automated-security-fixes`）是仓库设置侧的独立轨道，
  不受本文件影响，保持默认。

## docs 锁文件口径

`docs/` 由 npm 安装（`npm ci` + `package-lock.json`），且必须**独立安装**
（`--ignore-workspace`）：从根 workspace 装会命中根的 esbuild override，
把文档站构建毒化。`docs.yml` 里有守卫步骤，一旦 `docs/` 下出现
`pnpm-lock.yaml` 或 `yarn.lock` 就直接失败——第二份锁文件必然漂移。
