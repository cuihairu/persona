# Persona Safari Extension Skeleton

This directory captures the files that will back the Safari Web Extension build. The design mirrors the
Chromium extension so we can share JavaScript/TypeScript sources and then wrap them with a macOS host app
via Xcode's “Safari Web Extension” template.

## Layout

- `Shared/manifest.json` – WebExtension manifest, kept intentionally close to the Chromium variant
  （M5 批5a 起与 chromium `public/manifest.json` v0.2.0 同步：nativeMessaging、
  optional_host_permissions、webauthnHook MAIN-world 注入、commands 全对齐，仅多
  `safari_web_extension` 节）。
- `Sources/PersonaSafariExtensionApp` – SwiftUI host app stub that enables distribution through the Mac App Store.
- `Sources/PersonaSafariExtensionExtension` – Swift bridge that receives messages from Safari and can talk to the host.

Run `xcrun safari-web-extension-converter ../chromium-extension/public` after the Chromium build to populate the
`Shared` folder with the latest JS bundles. The generated Xcode project can live in this directory as well.

## JS 侧同份（M5 批5a，已在 chromium-extension 落地）

桥协议报文本身不分叉——chromium 与 Safari 走同一份 TS 源码（`chromium-extension/src`），
只有传输入口分叉：

- **chromium**：`chrome.runtime.sendNativeMessage('com.persona.native', …)` → NMH stdio，
  每请求一个 `persona bridge` 进程。
- **Safari**：`browser.runtime.sendNativeMessage(<app bundle id>, …)` → 宿主 app 的
  `SafariWebExtensionHandler`，由宿主进程代为拉起 `persona bridge`——同样是一请求一响应
  的 JSON 报文、一请求一进程语义，桥协议层零改动。

`nativeBridge.ts` 的适配点（已实现并有测试锚定）：

1. 全局对象 `browser`（Safari/标准）优先、`chrome`（chromium）兜底——native messaging
   与 `storage.local` 两处入口统一走该选择器。
2. `setNativeHost(bundleId)`：Safari 宿主包名与 chromium NMH 名不同，扩展入口按平台注入；
   传 `null` 恢复默认 `com.persona.native`。
3. 无任何 WebExtension 全局时 `sendNativeMessage` 如实回 `native_messaging_unavailable`。

## Swift 侧（待 macOS 实机，挂起）

`SafariWebExtensionHandler` 需要实现桥协议 v7 的宿主端：收到报文 → 以相同 argv 拉起
`persona bridge` → 回传响应 JSON。工作项：

1. Wire the Swift host app to bootstrap the shared WebExtension bundle.
2. Bridge messages between Safari JS runtime and the Persona desktop agent via XPC/CLI
   （即上文的 `persona bridge` 子进程封装）。
3. Harden entitlements and signing for distribution.

以上全部依赖 macOS/Xcode 工具链，在 Linux 上无法编译验证——不计入“已实现”，
待实机批次推进（与 P4.2/P4.3、iOS/鸿蒙同批）。
