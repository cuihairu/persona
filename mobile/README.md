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
- 业务层（`{"ok":bool,"error"?,"data"?}` 信封，与生命周期层的 `success` 键名不同，用 `parseBusiness` 解析）：
  `persona_credential_search`（凭据全文检索，仅元数据）。
- 远程登录感知层（同样 `{"ok",...}` 信封，PERSONA-MOBILE-002 / DEVALERT-001 联动；远程函数不触碰本地 vault 服务）：
  - `persona_remote_register_device(base_url, bearer, device_name, password)` — 引导令牌注册 SRP 设备；
  - `persona_remote_login(base_url, device_name, password)` — SRP 登录，**登录本身即设备指纹上报**（设备名 + 对端 IP + 时间落服务器台账）；`data` 含 `token`（15 分钟 TTL，仅内存持有）/`expires_in_secs`/`session_key_fingerprint`（裸 session_key 不过桥）；
  - `persona_remote_devices(base_url, token)` — 设备清单（服务器 JSON 原样透传在 `data`）。

## 与 desktop 的功能基线（PERSONA-MOBILE-002，2026-11-28）

| 功能 | desktop | Android | iOS | 鸿蒙 |
|---|---|---|---|---|
| vault 初始化/解锁/锁定 | ✅ | ✅（模拟器实测） | ✅（桥同语义） | ❌ stub |
| 凭据列表（元数据浏览） | ✅ | ✅（仅 search+列表，无增删改 UI） | ⚠️ 桥就位、UI 简版 | ❌ |
| 凭据增删改/密码生成 | ✅ | ❌（business FFI 未暴露） | ❌ | ❌ |
| 服务器登录感知（注册/SRP 登录/设备清单） | ✅（CLI/服务器侧） | ✅（模拟器实测，herald 告警闭环） | ⚠️ 桥+UI 已就位（`Persona.h`/`PersonaBridge.swift`/`ContentView.swift`，待 macOS 构建验收） | ❌ |
| 同步上报（configure_sync） | ✅ | ✅（桥就位） | ✅ | ❌ |
| 自动锁定/超时策略 | ✅ | ❌ | ❌ | ❌ |

iOS 构建走 imac（P1）；鸿蒙 napi 层 P2 设计先行。

## 各端构建

### Android

```bash
export ANDROID_NDK_HOME=/home/cui/android-sdk/ndk/28.2.13676358   # cargo ndk 需要
cargo ndk -t arm64-v8a -t x86_64 build -p persona-mobile --release
cp target/aarch64-linux-android/release/libpersona_mobile.so \
   mobile/android/app/src/main/jniLibs/arm64-v8a/
cp target/x86_64-linux-android/release/libpersona_mobile.so \
   mobile/android/app/src/main/jniLibs/x86_64/        # x86_64 供模拟器实测
cd mobile/android && ./gradlew :app:assembleDebug
# 模拟器 E2E（2026-11-28 实测配方）：AVD 无设备配置直建；宿主机服务从模拟器
# 内以 10.0.2.2 访问；软键盘会顶滚 ScrollView，逐字段 dump 后再取坐标点击；
# 全新服务器上第一台设备按设计不告警（视为操作者本人），第二台新设备触发
# [warning] New device login。
```

CI：`desktop-build.yml` android job（cargo ndk → jniLibs → gradle assembleRelease，abiFilters arm64-v8a + x86_64，CI 仅产出 arm64）。

### iOS

需 macOS + Xcode（Linux 无法构建验证；**注意 imac 是 Windows+WSL2 主机，不能构建 iOS**——
需真正的 macOS 环境。Swift 桥/UI/信封测试已就位，静态库链接与 `xcodebuild test`
验收待 macOS 硬件）：

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
