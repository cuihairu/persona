//! sync token 的字段级加密存储抽象。
//!
//! 上报令牌（`settings.sync.server_token` 的真值）不进 vault settings
//! JSON——那里只存空串占位。生产实现写 OS keyring（keyring crate，
//! Linux secret-service / macOS Keychain / Windows Credential Manager），
//! 键为 vault db_path；测试用 [`InMemoryTokenStore`]（CI/headless 没有
//! secret service）。keyring 不可用时调用方 fail-closed：上报不启用、
//! 保存被拒绝——绝不退回明文存储。

use std::collections::HashMap;
use std::sync::Mutex;

/// sync token 条目的 keyring service 名（seahorse/Keychain 里按它展示）
pub const SYNC_SERVICE: &str = "persona-sync";

/// biometric 托管主密码条目的 keyring service 名（与 sync 隔离的独立
/// service；条目存在与否 = biometric unlock 是否启用，单一真相源）
pub const BIOMETRIC_SERVICE: &str = "persona-biometric";

/// 硬件绑定 biometric（biometric_wrap 模块）包裹 blob 的 keyring service
/// 名。blob 是密文（主密钥被平台硬件密钥包裹），与门禁层密码条目互斥
/// ——两类条目同时存在时以 wrap 条目优先（unlock 链按它分流）。
pub const BIOMETRIC_WRAP_SERVICE: &str = "persona-biometric-wrap";

/// E2EE sync 设备身份条目的 keyring service 名（core/src/sync/mod.rs 文档
/// 口径：设备私钥持久化由宿主负责）。值 = `DeviceIdentity::to_stored_json`，
/// 键同 token_store = vault db_path（拷机后自然失效，需重新 join）。
pub const DEVICE_SERVICE: &str = "persona-device";

/// 同步服务器上报令牌的存取接口。
///
/// 键为 vault db_path：一个 vault 一枚令牌，vault 文件拷到别的机器
/// 后 keyring 里没有对应条目，上报自然不启用（需重输入，安全默认）。
pub trait TokenStore: Send + Sync + 'static {
    /// 写入/覆盖令牌。Err = OS keyring 不可用或操作失败（fail-closed）。
    fn set(&self, db_path: &str, token: &str) -> Result<(), String>;
    /// 读取令牌；`Ok(None)` = 未存储。
    fn get(&self, db_path: &str) -> Result<Option<String>, String>;
    /// 删除令牌；条目不存在视为成功（幂等）。
    fn delete(&self, db_path: &str) -> Result<(), String>;
}

/// 生产实现：OS keyring（经 keyring crate 的平台后端）。
///
/// service 名参数化（sync token / biometric 托管密码各一个 service）。
/// 构造无 I/O——真正的 keyring 访问发生在每个方法调用时，失败以
/// `Result` 返回而非 panic（headless/无 secret service 环境安全降级）。
pub struct OsKeyringTokenStore(&'static str);

impl OsKeyringTokenStore {
    /// 指定 keyring service 的存储（条目键 = vault db_path）
    pub fn new(service: &'static str) -> Self {
        Self(service)
    }
}

impl Default for OsKeyringTokenStore {
    fn default() -> Self {
        Self(SYNC_SERVICE)
    }
}

impl TokenStore for OsKeyringTokenStore {
    fn set(&self, db_path: &str, token: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(self.0, db_path)
            .map_err(|e| format!("OS keyring unavailable: {}", e))?;
        entry
            .set_password(token)
            .map_err(|e| format!("OS keyring write failed: {}", e))
    }

    fn get(&self, db_path: &str) -> Result<Option<String>, String> {
        let entry = keyring::Entry::new(self.0, db_path)
            .map_err(|e| format!("OS keyring unavailable: {}", e))?;
        match entry.get_password() {
            Ok(token) => Ok(Some(token)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(format!("OS keyring read failed: {}", e)),
        }
    }

    fn delete(&self, db_path: &str) -> Result<(), String> {
        let entry = keyring::Entry::new(self.0, db_path)
            .map_err(|e| format!("OS keyring unavailable: {}", e))?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            // 条目本就不存在 = 已是目标状态（幂等删除）
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(format!("OS keyring delete failed: {}", e)),
        }
    }
}

/// 测试实现：进程内 HashMap（CI/headless 没有 secret service）。
#[derive(Default)]
pub struct InMemoryTokenStore(Mutex<HashMap<String, String>>);

impl TokenStore for InMemoryTokenStore {
    fn set(&self, db_path: &str, token: &str) -> Result<(), String> {
        self.0
            .lock()
            .expect("token store mutex poisoned")
            .insert(db_path.to_string(), token.to_string());
        Ok(())
    }

    fn get(&self, db_path: &str) -> Result<Option<String>, String> {
        Ok(self
            .0
            .lock()
            .expect("token store mutex poisoned")
            .get(db_path)
            .cloned())
    }

    fn delete(&self, db_path: &str) -> Result<(), String> {
        self.0
            .lock()
            .expect("token store mutex poisoned")
            .remove(db_path);
        Ok(())
    }
}
