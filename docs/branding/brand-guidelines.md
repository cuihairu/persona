# 品牌使用说明（Brand Guidelines）

名称与读法
- 对外名称：Persona（数钥）
- 中文读音：shù yào
- 场景建议：正式文案与产品页可用“Persona（数钥）”，开发者文档与命令行维持英文 Persona 一致性。

Logo 与留白
- 主 Logo 文件：`docs/branding/logo.svg`
- 最小尺寸：24×24 px（屏幕）、12 mm（印刷）
- 留白：四周至少等于图标圆环线宽
- 禁止：拉伸变形、低对比度叠底、强饱和背景撞色

横排文字标（Wordmark）
- 文件：`docs/branding/wordmark-horizontal.svg`
- 推荐用于页眉/导航/欢迎页；缩放时保持等比

颜色
- 见 `docs/branding/color-palette.md`
- 渐变主色：`#4C6FFF` → `#00D1B2`
- 深浅模式自适应，注意文字和背景对比度

图标导出建议
- 应用图标：从 `logo.svg` 导出多尺寸 PNG/ICO（16/32/48/64/128/256/512）
- 桌面 App（Tauri）：放置于 `desktop/src/assets/brand/`，并在打包配置中引用
- Favicon：导出 32×32/48×48，同时保留 SVG 版本以支持高清缩放

命名与路径稳定性
- 生产前视需要替换视觉方案，但建议保持相同文件路径，以免影响引用

