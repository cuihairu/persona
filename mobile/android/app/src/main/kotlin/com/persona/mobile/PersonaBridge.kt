package com.persona.mobile

/**
 * libpersona_mobile.so 的 JNI 桥：native 符号在 Rust 侧
 * `mobile/rust/src/jni_android.rs`（Java_com_persona_mobile_PersonaBridge_*），
 * 语义与 iOS / 鸿蒙共用同一套 C ABI 桥。
 *
 * 出参约定：除 [personaInit]/[personaVersion]/[personaServiceIsUnlocked] 外
 * 均为 JSON 字符串 `{"success":bool,"error":string|null}`，用 org.json 解析。
 */
object PersonaBridge {
    init {
        System.loadLibrary("persona_mobile")
    }

    /** 0 = 成功 */
    external fun personaInit(): Int

    external fun personaVersion(): String

    /** 打开 vault → 迁移 → 首次建户或认证（成功即解锁态） */
    external fun personaServiceInit(dbPath: String, masterPassword: String): String

    /** 用主密码解锁既有会话 */
    external fun personaServiceUnlock(masterPassword: String): String

    external fun personaServiceLock(): String

    external fun personaServiceIsUnlocked(): Boolean

    external fun personaShutdown(): String

    /** JSON 出参的轻量解包：(success, error) */
    fun parseResult(json: String): Pair<Boolean, String?> {
        val obj = org.json.JSONObject(json)
        return obj.optBoolean("success") to obj.optString("error", "").ifEmpty { null }
    }
}
