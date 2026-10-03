package com.persona.mobile

/**
 * libpersona_mobile.so 的 JNI 桥：native 符号在 Rust 侧
 * `mobile/rust/src/jni_android.rs`（Java_com_persona_mobile_PersonaBridge_*），
 * 语义与 iOS / 鸿蒙共用同一套 C ABI 桥。
 *
 * 出参约定：除 [personaInit]/[personaServiceIsUnlocked] 外均为 JSON 字符串
 * `{"success":bool,"error":string|null}`，用 org.json 解析。
 *
 * null 安全（2026-10-03 走查实锤修复）：JNI 层任何失败（含 Rust panic 被
 * catch_unwind 收编前的极端路径、JVM 损坏的降级层）都可能以 null 返回，
 * Kotlin 侧一律声明为可空、[parseResult] 先判 null——null 不是可解析的
 * 结果，当作失败处理而不是让 NullPointerException 崩掉首屏。
 */
object PersonaBridge {
    init {
        System.loadLibrary("persona_mobile")
    }

    /** 0 = 成功 */
    external fun personaInit(): Int

    /** 运行时未起/JVM 异常时可能为 null（展示层兜底"未知"） */
    external fun personaVersion(): String?

    /** 打开 vault → 迁移 → 首次建户或认证（成功即解锁态） */
    external fun personaServiceInit(dbPath: String, masterPassword: String): String?

    /** 用主密码解锁既有会话 */
    external fun personaServiceUnlock(masterPassword: String): String?

    external fun personaServiceLock(): String?

    external fun personaServiceIsUnlocked(): Boolean

    external fun personaShutdown(): String?

    /** JSON 出参的轻量解包：null / 非 JSON / 非对象一律落失败臂，不抛异常 */
    fun parseResult(json: String?): Pair<Boolean, String?> {
        if (json == null) return false to "Native bridge returned null"
        return runCatching {
            val obj = org.json.JSONObject(json)
            obj.optBoolean("success") to obj.optString("error", "").ifEmpty { null }
        }.getOrElse { false to "Unexpected native response" }
    }
}
