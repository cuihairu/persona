package com.persona.mobile

/**
 * JNI bridge for libpersona_mobile.so: the native symbols live on the Rust
 * side in `mobile/rust/src/jni_android.rs`
 * (Java_com_persona_mobile_PersonaBridge_*), sharing the same C ABI bridge
 * semantics as iOS / HarmonyOS.
 *
 * Out parameter convention: everything except [personaInit]/[personaServiceIsUnlocked]
 * is a JSON string `{"success":bool,"error":string|null}`, parsed with org.json.
 *
 * Null safety (fix confirmed during the 2026-10-03 walkthrough): any failure at
 * the JNI layer (including the extreme path before catch_unwind absorbs a Rust
 * panic, and the degraded layer for a corrupted JVM) may return null, so the
 * Kotlin side declares everything nullable and [parseResult] checks for null
 * first — null is not a parseable result, so treat it as failure rather than
 * letting a NullPointerException blow up the first screen.
 */
object PersonaBridge {
    init {
        System.loadLibrary("persona_mobile")
    }

    /** 0 = success */
    external fun personaInit(): Int

    /** May be null when the runtime has not started / a JVM exception occurred (the display layer falls back to "unknown") */
    external fun personaVersion(): String?

    /** Open vault -> migrate -> create the account or authenticate on first run (success means unlocked) */
    external fun personaServiceInit(dbPath: String, masterPassword: String): String?

    /** Unlock an existing session with the master password */
    external fun personaServiceUnlock(masterPassword: String): String?

    external fun personaServiceLock(): String?

    external fun personaServiceIsUnlocked(): Boolean

    external fun personaShutdown(): String?

    // ---- Business FFI (the business layer, out envelope {"ok":bool,"error"?,"data"?} —
    // a different key name from the lifecycle layer's success above, so parse it with
    // parseBusiness) ----

    /** Full-text credential search (metadata only, payloads are not decrypted; empty string = all). May be null (both JVM layers down) */
    external fun personaCredentialSearch(query: String): String?

    // ---- Remote auth FFI (business envelope, parse with parseBusiness) — the
    // mobile side of the server's login-awareness surface: `deviceName` is the
    // fingerprint the server ledger keys on, so the default should identify
    // this phone (e.g. "android-<model>"). ----

    /** Bootstrap SRP registration (needs the server's bootstrap Bearer); the password chosen here is the login password */
    external fun personaRemoteRegisterDevice(
        baseUrl: String,
        bearer: String,
        deviceName: String,
        password: String,
    ): String?

    /** SRP login: reports this device's fingerprint to the server ledger and returns the short-lived Bearer token */
    external fun personaRemoteLogin(baseUrl: String, deviceName: String, password: String): String?

    /** Login-awareness device registry (server JSON passed through verbatim inside data) */
    external fun personaRemoteDevices(baseUrl: String, token: String): String?

    /** Lightweight unwrap of the business envelope: returns (ok, error, the whole response object); null / non-JSON always lands in the failure arm */
    fun parseBusiness(json: String?): Triple<Boolean, String?, org.json.JSONObject?> {
        if (json == null) return Triple(false, "Native bridge returned null", null)
        return runCatching {
            val obj = org.json.JSONObject(json)
            Triple(obj.optBoolean("ok"), obj.optString("error", "").ifEmpty { null }, obj)
        }.getOrElse { Triple(false, "Unexpected native response", null) }
    }

    /** Lightweight unwrap of a JSON out parameter: null / non-JSON / non-object always land in the failure arm, with no exception thrown */
    fun parseResult(json: String?): Pair<Boolean, String?> {
        if (json == null) return false to "Native bridge returned null"
        return runCatching {
            val obj = org.json.JSONObject(json)
            obj.optBoolean("success") to obj.optString("error", "").ifEmpty { null }
        }.getOrElse { false to "Unexpected native response" }
    }
}
