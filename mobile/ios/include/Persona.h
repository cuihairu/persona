/*
 * persona-mobile C ABI 声明（与 mobile/rust/src/lib.rs 的 #[no_mangle]
 * 导出一一对应）。Swift 经 PersonaFFI modulemap 引入；链接静态库
 * libpersona_mobile.a（cargo build --target aarch64-apple-ios 产物）。
 */
#ifndef PERSONA_H
#define PERSONA_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int32_t persona_init(void);

/* 返回本库分配的 C 字符串，用 persona_free_string 归还 */
const char *persona_version(void);

void persona_free_string(char *s);

typedef struct {
    bool success;
    char *error_message; /* 失败时非空，persona_free_result 归还 */
} PersonaResult;

void persona_free_result(PersonaResult result);

/* 打开 vault → 迁移 → 首次建户或认证；成功即解锁态 */
PersonaResult persona_service_init(const char *db_path, const char *master_password);

PersonaResult persona_service_unlock(const char *master_password);

PersonaResult persona_service_lock(void);

bool persona_service_is_unlocked(void);

PersonaResult persona_shutdown(void);

/* ---- Remote auth FFI (PERSONA-MOBILE-002): business envelope
 * {"ok":bool,"error"?,"data"?} — a different key name from the lifecycle
 * layer's "success", parse accordingly.
 * Each call returns a heap JSON string owned by the caller (release with
 * persona_free_string; may be NULL when serialization fails). Remote calls
 * block on an internal tokio runtime — never invoke them on the UI thread.
 * They never touch the local vault service. */

/* Bootstrap SRP registration (needs the server's bootstrap Bearer); the
 * password chosen here is the login password. data: {"device": ...}. */
const char *persona_remote_register_device(const char *base_url, const char *bearer,
                                           const char *device_name, const char *password);

/* SRP login: reports this device's fingerprint to the server ledger
 * (PERSONA-DEVALERT-001). data: {"device","token" (15-min TTL),
 * "expires_in_secs","session_key_fingerprint"} — the raw session key never
 * crosses the bridge. */
const char *persona_remote_login(const char *base_url, const char *device_name,
                                 const char *password);

/* Login-awareness device registry (server JSON passed through verbatim
 * inside data). */
const char *persona_remote_devices(const char *base_url, const char *token);

#ifdef __cplusplus
}
#endif

#endif /* PERSONA_H */
