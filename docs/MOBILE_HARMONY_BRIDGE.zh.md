# 手机鸿蒙桥设计（P2 设计先行）

> [English](https://github.com/cuihairu/persona/blob/main/docs/MOBILE_HARMONY_BRIDGE.md) | [中文](https://github.com/cuihairu/persona/blob/main/docs/MOBILE_HARMONY_BRIDGE.zh.md)

PERSONA-MOBILE-002 P2：ArkTS UI 骨架与 `PersonaBridge.ets` stub 已存在（`mobile/harmony/`），
缺的是 napi 包装层。本文档在动手前固定设计。状态：**仅设计——当前舰队任何机器都没有
DevEco/OpenHarmony SDK，实现等该环境到位。**

## 决策：基于既有 C ABI 的裸 N-API shim（不用 napi-rs）

三端必须共用同一套 native 契约，而契约已经存在：`mobile/rust/src/lib.rs` +
`mobile/rust/src/remote.rs` 导出平台无关的 `extern "C"` 函数（生命周期 `PersonaResult` +
业务层 `{"ok",...}` JSON 信封；Android 的 JNI 层只是转发；iOS 直接链静态库）。

| 方案                           | Rust 侧                     | 新依赖                             | ABI 一致性                                                |
| ------------------------------ | --------------------------- | ---------------------------------- | --------------------------------------------------------- |
| **A. napi-rs（ohos 后端）**    | 每个函数 `#[napi]` 重包一层 | 重 proc-macro 链进入 `mobile/rust` | 多出第二层重包装，易与 iOS/Android 漂移                   |
| **B. 裸 N-API C shim（选定）** | 零改动                      | 仅 DevEco 模板自带的 `cpp/` 目录   | shim 转发*同一批* extern "C" 符号，与 jni_android.rs 同构 |

方案 B 让 `mobile/rust` 保持零 napi 依赖，鸿蒙层成为 `jni_android.rs` 的兄弟层（薄转发、
信封语义完全一致）。shim 是机械式的：每个函数——解析 N-API 字符串入参、调 C 函数、把返回
的 JSON 堆字符串包成 `napi_value`、`persona_free_string`、返回。

## 接线方案

1. **Rust 静态产物**：按 OHOS target 构建（`aarch64-unknown-linux-ohos` 真机、
   `x86_64-unknown-linux-ohos` 模拟器；两者均 Tier 2，Linux 上 `rustup target add` 即可）。
   OHOS SDK 的 native 工具链（NDK clang 包装）提供 `CC_aarch64_unknown_linux_ohos` 等变量。
   产物落 `entry/libs/<abi>/libpersona_mobile.so`。
2. **C shim**（`entry/src/main/cpp/napi_init.cpp` + `CMakeLists.txt`，DevEco 默认模板）：
   声明 C ABI（与 `include/Persona.h` 同签名），经 CMake `IMPORTED` target 按 ABI 链接
   预构建 `.so`，注册一个 napi 模块（`persona_mobile`），导出：`personaInit`、
   `personaVersion`、`personaServiceInit`、`personaServiceUnlock`、`personaServiceLock`、
   `personaServiceIsUnlocked`、`personaShutdown`、`personaCredentialSearch`、
   `personaRemoteRegisterDevice`、`personaRemoteLogin`、`personaRemoteDevices`、
   `personaFreeString`。全部 JSON 信封透传；C 侧不重解析信封。
3. **ArkTS**：`PersonaBridge.ets` 把 `NOT_WIRED` stub 换成真调用
   （`import personaNapi from 'libentry.so'`）；新增 `parseBusiness`（与 Kotlin 版同构）与
   三个远程方法；`types/libentry/index.d.ts` 声明模块面。签名与今天的 stub 完全一致。
4. **线程**：C 函数阻塞在原生 tokio runtime 上。第一版用同步 napi 调用 + ArkTS `taskpool`
   驱动（即 Android 的「绝不占 UI 线程」模式）。若出现时延，再在 shim 内升级
   `napi_create_async_work`——ArkTS 面不变。
5. **UI**：`Index.ets` 补齐 Android 已交付的三屏（init/解锁生命周期、凭据列表、
   登录感知设置区：注册/SRP 登录/刷新清单）。设备名默认 `ohos-<deviceName>`，同一
   `[A-Za-z0-9._-]` 白名单清洗，48 字符。

## DEVALERT 联动

鸿蒙侧零特例：`persona_remote_register_device` / `persona_remote_login` /
`persona_remote_devices` 就是 Android 模拟器 E2E 已端到端验证过的同一批共享 C ABI 函数
（herald `[warning] New device login: …`）。指纹上报即 SRP 登录本身，所有平台一致。

## 构建与验证链

- **现有 Linux 舰队机可做**：两个 ohos target 的 rust 交叉构建 + `cargo test -p
persona-mobile`（宿主机）+ shim 无关单测。CI 可仿照 Android job 并列接入。
- **需 DevEco Studio（仅 Windows/macOS）**：`hvigorw assembleHap`、模拟器、`hdc install`
  与真机走查。验收配方同 Android P0 轮：init → 解锁 → 锁定 → 再解锁 → 凭据列表 →
  注册 → SRP 登录 → 设备清单，再用第二台设备登录触发 herald NOTICE。

## 开放问题

1. **napi 模块命名**：`libentry.so`（DevEco 模板默认）vs
   `libpersona_mobile_napi.so`（README 早前措辞）。倾向模板默认，保持 DevEco import
   路径原装；README 措辞在实现时更新。
2. **OHOS SDK 可得性**：当前舰队没有；rust 交叉构建腿在任意机器部署 SDK native 工具链
   后即可启动。
3. **签名级密钥库**：OHOS HUKS 后续可承载主密码解锁（对标 iOS Keychain / Android
   Keystore）——不在首个接线构建范围内；先记下，因为桌面生物识别 trait
   （`BiometricProvider`）就是未来 `HuksProvider` 要插的同一条缝。
