# persona mobile — 三端原生

iOS（Swift）/ Android（Kotlin）/ 鸿蒙（ArkTS）三端**原生**开发。**禁 Flutter 及一切跨平台 UI 中转层**；三端各自实现原生 UI，经平台标准 native 绑定共用同一套 Rust 桥（`rust/`）：

| 端 | UI | native 绑定 | 产物 |
|---|---|---|---|
| Android | Kotlin（View 体系） | JNI（`rust/src/jni_android.rs`，Android 平台标准机制） | `cdylib` → `libpersona_mobile.so` |
| iOS | Swift（SwiftUI） | C ABI（`staticlib` 直接链接） | `libpersona_mobile.a` |
| 鸿蒙 | ArkTS | NAPI（`libpersona_mobile_napi.so` 包装层） | `.so`（napi 模块） |

## 桥语义（三端一致）

- 入参：UTF-8 字符串（主密码、vault 路径、JSON 配置）。
- 出参：除 `persona_init`（int）、`persona_version`（字符串）、`persona_service_is_unlocked`（bool）外，一律 JSON `{"success":bool,"error":string|null}`。
- 生命周期：`service_init`（打开 vault → 迁移 → 首次建户或认证，成功即解锁）→ `service_unlock` / `service_lock` / `service_is_unlocked` → `shutdown`。
- 同步上报：`configure_sync`（config 一半即 fail-closed，url+token 都非空才启用）。

## 各端构建

### Android

```bash
cargo ndk -t arm64-v8a build -p persona-mobile --release   # libpersona_mobile.so
cp target/aarch64-linux-android/release/libpersona_mobile.so \
   mobile/android/app/src/main/jniLibs/arm64-v8a/
cd mobile/android && ./gradlew :app:assembleRelease
```

CI：`desktop-build.yml` android job（cargo ndk → jniLibs → gradle assembleRelease，arm64-v8a 单 ABI）。

### iOS

需 macOS + Xcode（Linux 无法构建验证）：

```bash
rustup target add aarch64-apple-ios
cargo build -p persona-mobile --release --target aarch64-apple-ios   # staticlib
cd mobile/ios && xcodegen gen   # 由 project.yml 生成 Xcode 工程
open Persona.xcodeproj
```

### 鸿蒙

需 DevEco Studio / 命令行工具链（hvigor）。ArkTS 工程在 `harmony/`（`hvigorw assembleHap` 构建）。
**接线状态**：UI 骨架与桥接口边界已就位；napi 包装层（Rust 侧 napi-rs ohos 后端 →
`libpersona_mobile_napi.so`）待接，`PersonaBridge.ets` stub 按同签名返回桥未接入错误——
真机验收需鸿蒙实机/模拟器 + napi 层落地。

## 历史

2026-10-02 起 Flutter 壳整体移除（唯一提交过的是壳 + 每日 APK 链路，无业务功能），原生三端自此为唯一移动路线。
