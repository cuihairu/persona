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

#ifdef __cplusplus
}
#endif

#endif /* PERSONA_H */
