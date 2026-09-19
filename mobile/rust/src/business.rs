//! 业务 FFI：身份 / 凭据 / TOTP CRUD。
//!
//! 与生命周期 FFI（lib.rs）互补：data-returning 入口统一 JSON-in/JSON-out
//! ——入参是 UTF-8 JSON 字符串指针，出参是单个 JSON 字符串指针
//! （`{"ok":true,"data":…}` / `{"ok":false,"error":"…"}`），由调用方用
//! `persona_free_string` 归还。ABI 只依赖字符指针，Dart 侧一次
//! `jsonDecode` 即得结果，错误不经异常跨边界。
//!
//! 锁定语义继承 core：全部入口经 `ensure_unlocked`；解密读（凭据数据/
//! TOTP）经 `ensure_sensitive_operation_allowed`（mobile 无因子流程，
//! REAUTH 语义等同普通解锁校验）。锁定态/未初始化态统一走错误包络。

use std::ffi::CString;
use std::os::raw::c_char;

use persona_core::{
    CredentialData, CredentialType, Identity, IdentityType, PersonaService, SecurityLevel,
};
use serde_json::json;
use uuid::Uuid;

use crate::{runtime, state};

// ---------------------------------------------------------------------------
// JSON 包络助手
// ---------------------------------------------------------------------------

fn to_c_char(value: &serde_json::Value) -> *mut c_char {
    // serde_json 序列化不会产生裸 NUL（转义为 \u0000），CString::new 恒成功；
    // 空指针臂仅为类型完备性保留
    match CString::new(value.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

fn ok_envelope<T: serde::Serialize>(data: &T) -> *mut c_char {
    to_c_char(&json!({ "ok": true, "data": data }))
}

fn err_envelope(message: &str) -> *mut c_char {
    to_c_char(&json!({ "ok": false, "error": message }))
}

/// 借用并解析 JSON 入参。
///
/// # Safety
/// `payload` 必须是有效的 null 结尾 UTF-8 JSON 字符串指针（或 null——返回 Err 而非 UB）。
unsafe fn parse_payload<T: serde::de::DeserializeOwned>(
    payload: *const c_char,
) -> Result<T, String> {
    // ptr_to_str 拦截 null/非 UTF-8（返回 Err 而非 UB）
    let raw = crate::ptr_to_str(payload)?;
    serde_json::from_str(raw).map_err(|e| format!("Invalid JSON payload: {}", e))
}

/// # Safety
/// `ptr` 必须是有效的 null 结尾 UTF-8 字符串指针（或 null）。
unsafe fn parse_uuid(ptr: *const c_char) -> Result<Uuid, String> {
    let raw = crate::ptr_to_str(ptr)?;
    Uuid::parse_str(raw).map_err(|_| "Invalid UUID format".to_string())
}

/// 解锁态 service 守卫（None = 未初始化）。Guard 持有跨 await 的槽位锁，
/// 业务调用天然串行（与 desktop AppState 同型）。
async fn service_guard() -> Result<tokio::sync::MutexGuard<'static, Option<PersonaService>>, String>
{
    let guard = state::service_slot().lock().await;
    if guard.is_none() {
        return Err("Service not initialized".to_string());
    }
    Ok(guard)
}

// ---------------------------------------------------------------------------
// 身份
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct CreateIdentityPayload {
    name: String,
    /// 预设枚举名（Personal/Work/Social/Financial/Gaming）或任意自定义名（落 Custom）
    identity_type: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
}

/// 创建身份。identity_type 未匹配预设枚举时落 Custom（与 core FromStr 一致）。
///
/// # Safety
/// `payload` 必须是有效的 null 结尾 UTF-8 JSON 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_identity_create(payload: *const c_char) -> *mut c_char {
    let parsed = unsafe { parse_payload::<CreateIdentityPayload>(payload) };
    let payload = match parsed {
        Ok(p) => p,
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        let service = guard.as_ref().expect("service_guard ensures Some");
        let identity_type = payload
            .identity_type
            .parse::<IdentityType>()
            .unwrap_or_else(|_| IdentityType::Custom(payload.identity_type.clone()));
        let mut identity = Identity::new(payload.name, identity_type);
        identity.description = payload.description;
        identity.email = payload.email;
        identity.phone = payload.phone;
        match service.create_identity_full(identity).await {
            Ok(created) => ok_envelope(&created),
            Err(e) => err_envelope(&format!("Failed to create identity: {}", e)),
        }
    })
}

/// 列出全部身份。
#[no_mangle]
pub extern "C" fn persona_identity_list() -> *mut c_char {
    runtime::block_on(async {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        match guard
            .as_ref()
            .expect("service_guard ensures Some")
            .get_identities()
            .await
        {
            Ok(list) => ok_envelope(&list),
            Err(e) => err_envelope(&format!("Failed to list identities: {}", e)),
        }
    })
}

/// 按 UUID 取单个身份（不存在时 data 为 null）。
///
/// # Safety
/// `id` 必须是有效的 null 结尾 UTF-8 UUID 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_identity_get(id: *const c_char) -> *mut c_char {
    let id = match unsafe { parse_uuid(id) } {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        match guard
            .as_ref()
            .expect("service_guard ensures Some")
            .get_identity(&id)
            .await
        {
            Ok(found) => ok_envelope(&found),
            Err(e) => err_envelope(&format!("Failed to get identity: {}", e)),
        }
    })
}

/// 更新身份：入参是完整 Identity JSON（含 id；建议经 persona_identity_get
/// 取回后改字段回传）。updated_at 由本入口盖为当前时间。
///
/// # Safety
/// `payload` 必须是有效的 null 结尾 UTF-8 JSON 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_identity_update(payload: *const c_char) -> *mut c_char {
    let parsed = unsafe { parse_payload::<Identity>(payload) };
    let mut identity = match parsed {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    identity.touch();
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        match guard
            .as_ref()
            .expect("service_guard ensures Some")
            .update_identity(&identity)
            .await
        {
            Ok(updated) => ok_envelope(&updated),
            Err(e) => err_envelope(&format!("Failed to update identity: {}", e)),
        }
    })
}

/// 删除身份（data 为是否删除的布尔）。
///
/// # Safety
/// `id` 必须是有效的 null 结尾 UTF-8 UUID 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_identity_delete(id: *const c_char) -> *mut c_char {
    let id = match unsafe { parse_uuid(id) } {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        match guard
            .as_ref()
            .expect("service_guard ensures Some")
            .delete_identity(&id)
            .await
        {
            Ok(deleted) => ok_envelope(&deleted),
            Err(e) => err_envelope(&format!("Failed to delete identity: {}", e)),
        }
    })
}

// ---------------------------------------------------------------------------
// 凭据
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct CreateCredentialPayload {
    identity_id: Uuid,
    name: String,
    credential_type: CredentialType,
    security_level: SecurityLevel,
    /// 外部标签枚举：{"Password": {...}} / {"TwoFactor": {...}} / …
    credential_data: CredentialData,
}

/// 创建凭据（明文负载在此封 encryption envelope，密钥不出 Rust 侧）。
///
/// # Safety
/// `payload` 必须是有效的 null 结尾 UTF-8 JSON 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_credential_create(payload: *const c_char) -> *mut c_char {
    let parsed = unsafe { parse_payload::<CreateCredentialPayload>(payload) };
    let payload = match parsed {
        Ok(p) => p,
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        let service = guard.as_ref().expect("service_guard ensures Some");
        match service
            .create_credential(
                payload.identity_id,
                payload.name,
                payload.credential_type,
                payload.security_level,
                &payload.credential_data,
            )
            .await
        {
            Ok(created) => ok_envelope(&created),
            Err(e) => err_envelope(&format!("Failed to create credential: {}", e)),
        }
    })
}

/// 列出某身份的全部凭据（仅元数据，不含解密负载）。
///
/// # Safety
/// `identity_id` 必须是有效的 null 结尾 UTF-8 UUID 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_credential_list(identity_id: *const c_char) -> *mut c_char {
    let id = match unsafe { parse_uuid(identity_id) } {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        match guard
            .as_ref()
            .expect("service_guard ensures Some")
            .get_credentials_for_identity(&id)
            .await
        {
            Ok(list) => ok_envelope(&list),
            Err(e) => err_envelope(&format!("Failed to list credentials: {}", e)),
        }
    })
}

/// 解密并返回凭据负载（外部标签 JSON；敏感操作，走 REAUTH 门禁）。
/// 不存在时错误包络 "Credential not found"。
///
/// # Safety
/// `credential_id` 必须是有效的 null 结尾 UTF-8 UUID 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_credential_data(credential_id: *const c_char) -> *mut c_char {
    let id = match unsafe { parse_uuid(credential_id) } {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        let service = guard.as_ref().expect("service_guard ensures Some");
        let data = match service.get_credential_data(&id).await {
            Ok(d) => d,
            Err(e) => return err_envelope(&format!("Failed to get credential data: {}", e)),
        };
        match data {
            Some(d) => ok_envelope(&d),
            None => err_envelope("Credential not found"),
        }
    })
}

/// 删除凭据（data 为是否删除的布尔）。
///
/// # Safety
/// `credential_id` 必须是有效的 null 结尾 UTF-8 UUID 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_credential_delete(credential_id: *const c_char) -> *mut c_char {
    let id = match unsafe { parse_uuid(credential_id) } {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        match guard
            .as_ref()
            .expect("service_guard ensures Some")
            .delete_credential(&id)
            .await
        {
            Ok(deleted) => ok_envelope(&deleted),
            Err(e) => err_envelope(&format!("Failed to delete credential: {}", e)),
        }
    })
}

/// 全文搜索凭据（名称/用户名/URL 等元数据；不解密负载）。
///
/// # Safety
/// `query` 必须是有效的 null 结尾 UTF-8 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_credential_search(query: *const c_char) -> *mut c_char {
    // ptr_to_str 拦截 null/非 UTF-8（返回 Err 而非 UB）
    let query = match crate::ptr_to_str(query) {
        Ok(v) => v.to_string(),
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        match guard
            .as_ref()
            .expect("service_guard ensures Some")
            .search_credentials(&query)
            .await
        {
            Ok(list) => ok_envelope(&list),
            Err(e) => err_envelope(&format!("Failed to search credentials: {}", e)),
        }
    })
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct TotpCodeResponse {
    code: String,
    remaining_seconds: u32,
    period: u32,
    digits: u8,
    algorithm: String,
    issuer: String,
    account_name: String,
}

/// 为 TwoFactor 凭据生成当前 TOTP 码（协议逻辑在 core；不回传密钥）。
///
/// # Safety
/// `credential_id` 必须是有效的 null 结尾 UTF-8 UUID 字符串指针。
#[no_mangle]
pub unsafe extern "C" fn persona_totp_code(credential_id: *const c_char) -> *mut c_char {
    let id = match unsafe { parse_uuid(credential_id) } {
        Ok(v) => v,
        Err(e) => return err_envelope(&e),
    };
    runtime::block_on(async move {
        let guard = match service_guard().await {
            Ok(g) => g,
            Err(e) => return err_envelope(&e),
        };
        let service = guard.as_ref().expect("service_guard ensures Some");
        let data = match service.get_credential_data(&id).await {
            Ok(d) => d,
            Err(e) => return err_envelope(&format!("Failed to get credential data: {}", e)),
        };
        match data {
            Some(CredentialData::TwoFactor(tf)) => {
                match persona_core::crypto::totp::totp_now(&tf) {
                    Ok(generated) => ok_envelope(&TotpCodeResponse {
                        code: generated.code,
                        remaining_seconds: generated.remaining_seconds,
                        period: tf.period.max(1),
                        digits: tf.digits.clamp(4, 10),
                        algorithm: tf.algorithm,
                        issuer: tf.issuer,
                        account_name: tf.account_name,
                    }),
                    Err(e) => err_envelope(&format!("Failed to generate TOTP code: {}", e)),
                }
            }
            // 游戏令牌经 core 统一调度器（Steam Guard 离线可算；绑定型
            // provider 在此报错而不是生成错误码）
            Some(CredentialData::GameToken(gt)) => {
                match persona_core::crypto::game_token::generate_game_token_code_now(&gt) {
                    Ok(generated) => ok_envelope(&TotpCodeResponse {
                        code: generated.code,
                        remaining_seconds: generated.remaining_seconds,
                        period: generated.period,
                        digits: persona_core::crypto::STEAM_GUARD_DIGITS as u8,
                        algorithm: gt.provider.to_ascii_uppercase(),
                        issuer: gt.issuer,
                        account_name: gt.account_name,
                    }),
                    Err(e) => err_envelope(&format!("Failed to generate game token code: {}", e)),
                }
            }
            Some(_) => err_envelope("Credential is not a TwoFactor entry"),
            None => err_envelope("Credential not found"),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{cstr, reset_state, temp_db_path, test_lock};
    use std::ffi::CStr;

    /// 就绪的解锁态 service（临时库 + 建户）。
    fn init_unlocked(tag: &str) -> String {
        let db_path = temp_db_path(tag);
        let db = cstr(&db_path);
        let pw = cstr("master-pin");
        let result = unsafe { crate::persona_service_init(db.as_ptr(), pw.as_ptr()) };
        assert!(result.success, "init failed for {}", tag);
        unsafe { crate::persona_free_result(result) };
        db_path
    }

    fn take_json(ptr: *mut c_char) -> serde_json::Value {
        assert!(!ptr.is_null(), "envelope pointer must not be null");
        // SAFETY: 指针来自本库的 into_raw，读出后立即归还
        let text = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        unsafe { crate::persona_free_string(ptr) };
        serde_json::from_str(&text).expect("envelope is valid JSON")
    }

    fn expect_ok(ptr: *mut c_char) -> serde_json::Value {
        let value = take_json(ptr);
        assert_eq!(value["ok"], json!(true), "expected ok envelope: {}", value);
        value
    }

    fn expect_err(ptr: *mut c_char) -> String {
        let value = take_json(ptr);
        assert_eq!(
            value["ok"],
            json!(false),
            "expected error envelope: {}",
            value
        );
        value["error"].as_str().unwrap().to_string()
    }

    fn call_list_identities() -> *mut c_char {
        persona_identity_list()
    }

    #[test]
    fn business_entries_require_initialized_service() {
        let _guard = test_lock();
        reset_state();

        let id = cstr("00000000-0000-0000-0000-000000000001");
        // 合法负载（入参解析通过）→ 才轮到 service 未初始化检查
        let payload = cstr(r#"{"name":"x","identity_type":"Personal"}"#);
        assert_eq!(
            expect_err(call_list_identities()),
            "Service not initialized"
        );
        assert_eq!(
            expect_err(unsafe { persona_identity_get(id.as_ptr()) }),
            "Service not initialized"
        );
        assert_eq!(
            expect_err(unsafe { persona_identity_create(payload.as_ptr()) }),
            "Service not initialized"
        );
        assert_eq!(
            expect_err(unsafe { persona_credential_search(cstr("x").as_ptr()) }),
            "Service not initialized"
        );
        assert_eq!(
            expect_err(unsafe { persona_totp_code(id.as_ptr()) }),
            "Service not initialized"
        );

        // 坏 UUID / 坏 JSON 在未初始化检查之前先被拦截（入参解析先行）
        let bad_uuid = cstr("not-a-uuid");
        assert_eq!(
            expect_err(unsafe { persona_identity_get(bad_uuid.as_ptr()) }),
            "Invalid UUID format"
        );
        let bad_json = cstr("{oops");
        let message = expect_err(unsafe { persona_identity_create(bad_json.as_ptr()) });
        assert!(
            message.starts_with("Invalid JSON payload"),
            "unexpected: {}",
            message
        );
        // null 指针防线：ptr_to_str 的 null 分支
        assert_eq!(
            expect_err(unsafe { persona_identity_create(std::ptr::null()) }),
            "null argument"
        );
    }

    #[test]
    fn identity_crud_round_trip() {
        let _guard = test_lock();
        reset_state();
        init_unlocked("biz-identity");

        // create：预设类型 + 可选元数据
        let created = expect_ok(unsafe {
            persona_identity_create(
                cstr(
                    r#"{"name":"Work Phone","identity_type":"Work","description":"day job",
                    "email":"ops@persona.dev","phone":"+8613800000000"}"#,
                )
                .as_ptr(),
            )
        });
        let identity_id = created["data"]["id"].as_str().unwrap().to_string();
        assert_eq!(created["data"]["identity_type"], json!("Work"));
        assert_eq!(created["data"]["email"], json!("ops@persona.dev"));

        // create：未匹配的 identity_type 落 Custom
        let custom = expect_ok(unsafe {
            persona_identity_create(cstr(r#"{"name":"Alias","identity_type":"Stage"}"#).as_ptr())
        });
        assert_eq!(custom["data"]["identity_type"], json!({"Custom":"Stage"}));

        // list：新库只有这两条
        let list = expect_ok(call_list_identities());
        assert_eq!(list["data"].as_array().unwrap().len(), 2);

        // get：合法 UUID 命中；非法 UUID 报格式错误
        let got = expect_ok(unsafe { persona_identity_get(cstr(&identity_id).as_ptr()) });
        assert_eq!(got["data"]["name"], json!("Work Phone"));
        let bad_uuid = cstr("zzz");
        assert_eq!(
            expect_err(unsafe { persona_identity_get(bad_uuid.as_ptr()) }),
            "Invalid UUID format"
        );

        // update：get 回传对象改字段后整体提交
        let mut updated = got["data"].clone();
        updated["name"] = json!("Work Phone Renamed");
        let updated_json = cstr(&updated.to_string());
        let update_result = expect_ok(unsafe { persona_identity_update(updated_json.as_ptr()) });
        assert_eq!(update_result["data"]["name"], json!("Work Phone Renamed"));
        let reread = expect_ok(unsafe { persona_identity_get(cstr(&identity_id).as_ptr()) });
        assert_eq!(reread["data"]["name"], json!("Work Phone Renamed"));

        // delete：真删（true）+ 复删（false）
        let deleted = expect_ok(unsafe { persona_identity_delete(cstr(&identity_id).as_ptr()) });
        assert_eq!(deleted["data"], json!(true));
        let deleted_again =
            expect_ok(unsafe { persona_identity_delete(cstr(&identity_id).as_ptr()) });
        assert_eq!(deleted_again["data"], json!(false));

        assert_ok_shutdown();
    }

    #[test]
    fn credential_round_trip_with_decryption() {
        let _guard = test_lock();
        reset_state();
        init_unlocked("biz-credential");

        let identity = expect_ok(unsafe {
            persona_identity_create(cstr(r#"{"name":"Dev","identity_type":"Personal"}"#).as_ptr())
        });
        let identity_id = identity["data"]["id"].as_str().unwrap().to_string();

        // create：密码凭据（明文进 envelope 加密，密钥不出 Rust 侧）
        let payload = format!(
            r#"{{"identity_id":"{}","name":"GitHub","credential_type":"Password",
                "security_level":"High",
                "credential_data":{{"Password":{{"password":"hunter2",
                "email":"me@persona.dev","security_questions":[]}}}}}}"#,
            identity_id
        );
        let created = expect_ok(unsafe { persona_credential_create(cstr(&payload).as_ptr()) });
        let credential_id = created["data"]["id"].as_str().unwrap().to_string();
        assert_eq!(created["data"]["name"], json!("GitHub"));

        // list：元数据可见；密文字段在列（Credential 序列化含 encrypted_data），
        // 但绝不能泄露明文
        let list = expect_ok(unsafe { persona_credential_list(cstr(&identity_id).as_ptr()) });
        assert_eq!(list["data"].as_array().unwrap().len(), 1);
        let list_text = list.to_string();
        assert!(
            !list_text.contains("hunter2"),
            "ciphertext listing must not leak plaintext: {}",
            list_text
        );

        // data：解密回读与写入一致（加密往返证明）
        let data = expect_ok(unsafe { persona_credential_data(cstr(&credential_id).as_ptr()) });
        assert_eq!(data["data"]["Password"]["password"], json!("hunter2"));
        assert_eq!(data["data"]["Password"]["email"], json!("me@persona.dev"));

        // search：按名称元数据命中
        let hits = expect_ok(unsafe { persona_credential_search(cstr("Git").as_ptr()) });
        assert_eq!(hits["data"].as_array().unwrap().len(), 1);

        // 非 TwoFactor 凭据取 TOTP → 类型错误包络
        assert_eq!(
            expect_err(unsafe { persona_totp_code(cstr(&credential_id).as_ptr()) }),
            "Credential is not a TwoFactor entry"
        );

        // delete 后再读 → "Credential not found"
        let deleted =
            expect_ok(unsafe { persona_credential_delete(cstr(&credential_id).as_ptr()) });
        assert_eq!(deleted["data"], json!(true));
        assert_eq!(
            expect_err(unsafe { persona_credential_data(cstr(&credential_id).as_ptr()) }),
            "Credential not found"
        );

        assert_ok_shutdown();
    }

    #[test]
    fn totp_code_returns_structured_payload() {
        let _guard = test_lock();
        reset_state();
        init_unlocked("biz-totp");

        let identity = expect_ok(unsafe {
            persona_identity_create(cstr(r#"{"name":"Ops","identity_type":"Work"}"#).as_ptr())
        });
        let identity_id = identity["data"]["id"].as_str().unwrap().to_string();
        let payload = format!(
            r#"{{"identity_id":"{}","name":"Admin 2FA","credential_type":"TwoFactor",
                "security_level":"Critical",
                "credential_data":{{"TwoFactor":{{"secret_key":"JBSWY3DPEHPK3PXP",
                "issuer":"Persona","account_name":"ops@persona.dev",
                "algorithm":"SHA1","digits":6,"period":30}}}}}}"#,
            identity_id
        );
        let created = expect_ok(unsafe { persona_credential_create(cstr(&payload).as_ptr()) });
        let credential_id = created["data"]["id"].as_str().unwrap().to_string();

        let code =
            expect_ok(unsafe { persona_totp_code(cstr(&credential_id).as_ptr()) })["data"].clone();
        let digits = code["digits"].as_u64().unwrap() as usize;
        assert_eq!(digits, 6);
        let generated = code["code"].as_str().unwrap();
        assert_eq!(generated.len(), digits);
        assert!(generated.bytes().all(|b| b.is_ascii_digit()));
        let remaining = code["remaining_seconds"].as_u64().unwrap();
        assert!(
            (1..=30).contains(&remaining),
            "remaining out of range: {}",
            remaining
        );
        assert_eq!(code["period"], json!(30));
        assert_eq!(code["issuer"], json!("Persona"));
        assert_eq!(code["account_name"], json!("ops@persona.dev"));

        assert_ok_shutdown();
    }

    #[test]
    fn totp_code_supports_game_token_provider() {
        let _guard = test_lock();
        reset_state();
        init_unlocked("biz-gametoken");

        let identity = expect_ok(unsafe {
            persona_identity_create(
                cstr(r#"{"name":"Player","identity_type":"Personal"}"#).as_ptr(),
            )
        });
        let identity_id = identity["data"]["id"].as_str().unwrap().to_string();

        // Steam Guard 令牌：base64 shared_secret，provider=steam_guard
        let payload = format!(
            r#"{{"identity_id":"{}","name":"Steam Guard","credential_type":"TwoFactor",
                "security_level":"High",
                "credential_data":{{"GameToken":{{"provider":"steam_guard",
                "secret_key":"MDEyMzQ1Njc4OWFiY2RlZmdoaWo=",
                "issuer":"Steam","account_name":"player_one","url":null}}}}}}"#,
            identity_id
        );
        let created = expect_ok(unsafe { persona_credential_create(cstr(&payload).as_ptr()) });
        let credential_id = created["data"]["id"].as_str().unwrap().to_string();

        let code =
            expect_ok(unsafe { persona_totp_code(cstr(&credential_id).as_ptr()) })["data"].clone();
        let generated = code["code"].as_str().unwrap();
        assert_eq!(generated.len(), 5, "steam guard code is five chars");
        assert!(
            generated
                .bytes()
                .all(|b| b"23456789BCDFGHJKMNPQRTVWXY".contains(&b)),
            "code {generated} outside the Steam alphabet"
        );
        let remaining = code["remaining_seconds"].as_u64().unwrap();
        assert!((1..=30).contains(&remaining));
        assert_eq!(code["period"], json!(30));
        assert_eq!(code["digits"], json!(5));
        assert_eq!(code["algorithm"], json!("STEAM_GUARD"));
        assert_eq!(code["issuer"], json!("Steam"));
        assert_eq!(code["account_name"], json!("player_one"));

        // 未知 provider（绑定型，如未来的腾讯安全中心）→ 报错而不是伪造码
        let bound_payload = format!(
            r#"{{"identity_id":"{}","name":"Bound token","credential_type":"TwoFactor",
                "security_level":"High",
                "credential_data":{{"GameToken":{{"provider":"tencent_security",
                "secret_key":"MDEyMzQ1Njc4OWFiY2RlZmdoaWo=",
                "issuer":"Tencent","account_name":"player_one","url":null}}}}}}"#,
            identity_id
        );
        let bound = expect_ok(unsafe { persona_credential_create(cstr(&bound_payload).as_ptr()) });
        let bound_id = bound["data"]["id"].as_str().unwrap().to_string();
        let err = expect_err(unsafe { persona_totp_code(cstr(&bound_id).as_ptr()) });
        assert!(
            err.contains("Unsupported game token provider"),
            "unexpected error: {}",
            err
        );

        assert_ok_shutdown();
    }

    #[test]
    fn locked_service_rejects_business_calls() {
        let _guard = test_lock();
        reset_state();
        init_unlocked("biz-locked");

        assert!(crate::persona_service_lock().success);
        let message = expect_err(call_list_identities());
        assert!(
            message.to_lowercase().contains("lock"),
            "unexpected error: {}",
            message
        );

        // 解锁恢复后可继续
        assert!(unsafe { crate::persona_service_unlock(cstr("master-pin").as_ptr()) }.success);
        expect_ok(call_list_identities());

        assert_ok_shutdown();
    }

    fn assert_ok_shutdown() {
        let result = crate::persona_shutdown();
        assert!(result.success);
        unsafe { crate::persona_free_result(result) };
    }
}
