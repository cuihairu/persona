# Passkey Gate Audit（批 E 核查）

核查日期：2026-10-04。范围：浏览器插件轨的 passkey/WebAuthn 能力（TODO 批 E：
「Passkey 补缺口核查 + 端到端测试」），对照 [PASSKEYS_DESIGN.md](PASSKEYS_DESIGN.md)
的 P1–P4 阶段与桥协议 v2/v3 落地情况。分工口径：E1/E3 的代码与测试由扩展轨
（批 A–D）交付，本审计负责**逐项核实 + 裁定 + 登记残留**。

## 结论速览

| 任务 | 判定 | 证据 |
| --- | --- | --- |
| E1 扩展侧 passkey 创建/断言双闸门回归 | ✅ 已覆盖 | 见 §1 |
| E2 OS passkey provider（v3）真机验收 | ⏸ 顺延（真机前提） | 见 §2 |
| E3 跨源 iframe passkey hook 行为 | ✅ 设计裁定：不注入 | 见 §3 |

净结论：v2/v3 协议、core 校验、双闸门、审计元数据无不预期缺口；残留都是
真机/平台前提（E2、P4.2/P4.3）或显式非目标（§4）。

## 1. E1：手势闸门 + 桌面审批双闸门回归 — 已覆盖

- 扩展消息层：`passkey_list` / `passkey_create` / `passkey_assert` 均为
  authed 消息（配对 + session HMAC）；`passkeyCreate`/`passkeyAssert` 原样
  转发页面报告的 `user_gesture`（`nativeBridge.ts`），测试覆盖
  `user_gesture=true/false` 两条路径与断言选择条目（`nativeBridge.test.ts`）。
- 内容层：确认 UI 在 `persona_passkey_create/list/assert` 消息后触发
  （`content.ts`），手势来自真实点击。
- core 侧：桥协议用例（cli bridge 测试）+ 桌面审批白名单用例
  （`desktop/src-tauri/src/passkey_bridge.rs` 的 op 与解析测试，含
  `parse_query` 拒绝非法 op）。`passkey_create`/`passkey_assert` 均经
  `desktop_approval_gate` 与 active identity 检查。
- 审计：`passkey_asserted` 携带 `via=extension|os_provider` 元数据
  （P4.4，协议测试已锁）。

复核方式：`browser/chromium-extension` 内 `npx jest`（11 套件 135 例全绿）
+ `npx tsc --noEmit`；扩展测试含 manifest 契约测试（webauthnHook 仅顶层、
content.js 全 frame、ISOLATED world）。

## 2. E2：OS passkey provider 真机验收 — 顺延（登记）

与 `FEATURE_GAP_ANALYSIS.md` #23/#24 同一类前提缺失：OS provider 需要
macOS（Signing & WebAuthn entitlement 签名）与 Windows（Hello 插件）实机
+ 签名环境；本仓库 CI 仅 Linux，只能跑协议与 core 回归（P4.1/P4.4 已在此
闭环）。顺延登记，重启条件：拿到 macOS/Windows 实机 + Developer ID
签名环境（对照 PASSKEYS_DESIGN §13.1 的 P4.2/P4.3 验收）。

## 3. E3：跨源 iframe passkey — 设计裁定：不注入

`all_frames: true` 只作用于 ISOLATED world 的 `content.js`；MAIN world 的
`webauthnHook.ts` **保持 top frame only**。裁定依据：

1. 给每个第三方 iframe 都包一层 `navigator.credentials` 侵入面太大，
   且跨源 iframe 的 passkey 请求本来就应该走浏览器原生流程（用户已有
   OS/浏览器 passkey 时的最优路径）；
2. 同源 iframe（oauth 弹层内嵌登录等）由 content.js 的逐 frame 自填
   机制覆盖（批 B），不走 WebAuthn hook；
3. v3 provider 路径（P4.1）不经过 content-script hook，与 iframe 无关。

该裁定由 manifest 契约测试**锁定**（防回归：`manifest.test.ts` 断言
webauthnHook 不入 iframe）。iframe 段落在 README 有对应设计说明。

## 4. 残留缺口（均登记，不属本批）

| 项 | 状态 | 归属 |
| --- | --- | --- |
| P4.2 macOS provider / P4.3 Windows Hello 插件 | 真机前提 | 顺延（同 E2） |
| 开放问题 1：多身份命中同一 rp_id 的选择 UI 过滤 | 倾向 active identity 过滤 + 「显示其他身份」展开 | PASSKEYS_DESIGN §14 待决 |
| 开放问题 2：私钥备份格式（自定义 JSON vs PKCS#12 类） | 标准（CXF）定稿前维持 v1 自定义 + schema 文档 | 同上 |
| 开放问题 3：`confirm_on_passkey_assert` 独立策略键 | 当前复用 `confirm_on_fill`，P3 后评估 | 同上 |
| P4.5 CXF 字段预留 | `foreign_key_ref` 已预留，不实现 | 跟踪项 |
| 扩展 passkey 真站互操作（webauthn.io/GitHub） | 无浏览器 E2E 基建，同批 B 实机勾稽待补 | 与 E2 一并重启 |

## 5. 建议的后续动作（不阻塞收口）

1. 选一个真站回归工具（Playwright 冒烟）时，把 webauthn.io 注册/断言
   定为扩展轨首位用例（同时覆盖批 B 的 GitHub 多步登录勾稽）；
2. 开放问题 1 随桌面 passkey 管理页迭代裁决（P3 已在）；
3. E2 重启前不新增 OS provider 代码承诺。