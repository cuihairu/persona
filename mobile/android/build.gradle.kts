// 移动端三原生之一的 Android 工程（Kotlin + 平台标准 JNI 绑定
// libpersona_mobile.so，Rust 侧见 mobile/rust）。禁 Flutter/跨平台中转。
plugins {
    id("com.android.application") version "8.13.0" apply false
    id("org.jetbrains.kotlin.android") version "2.2.20" apply false
}
