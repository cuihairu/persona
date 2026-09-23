//! 设备身份的宿主持久化记录（E2EE_SYNC_DESIGN DR-1/DR-3）。
//!
//! 设备私钥由宿主落 OS keyring（service `persona-device`，desktop）或
//! 0600 文件（headless `--device-key-file`，CLI）——core 不依赖 keyring，
//! 只定义记录格式：一个 JSON 文本，私钥 b64 编码。desktop 与 CLI 共用
//! 同一格式；记录文本落哪、怎么保护随宿主（core 文档口径：持久化由
//! 宿主负责）。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use uuid::Uuid;

use super::keys::DeviceKeyPair;
use crate::{PersonaError, Result};

/// 一台设备加入同步后的身份：服务器分配的 `device_id`、登记名、密钥对。
/// 私钥字节只在 [`DeviceKeyPair`] 内（Drop 时清零），本结构不额外复制。
pub struct DeviceIdentity {
    pub device_id: Uuid,
    pub device_name: String,
    pub key_pair: DeviceKeyPair,
}

impl DeviceIdentity {
    /// 生成新设备身份（随机 X25519 密钥对；device_id 由服务器登记时分配，
    /// 登记后用 [`Self::with_device_id`] 回填）。
    pub fn generate(device_name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            device_id: Uuid::nil(),
            device_name: device_name.into(),
            key_pair: DeviceKeyPair::generate()?,
        })
    }

    /// 登记成功后回填服务器分配的 device_id。
    pub fn with_device_id(mut self, device_id: Uuid) -> Self {
        self.device_id = device_id;
        self
    }

    /// 存储文本（一个 JSON：b64 私钥）。宿主落 keyring/文件时写的就是
    /// 这个字符串——格式稳定，跨端（desktop/CLI）可互换。
    pub fn to_stored_json(&self) -> String {
        serde_json::json!({
            "device_id": self.device_id.to_string(),
            "device_name": self.device_name,
            "secret_key": B64.encode(self.key_pair.secret_bytes()),
        })
        .to_string()
    }

    /// 从存储文本恢复。任何一处不可解析（坏 JSON / 坏 UUID / 坏 b64 /
    /// 长度不对）一律 Err——fail-closed：记录损坏宁可让用户重新 join，
    /// 不猜、不带病运行。
    pub fn from_stored_json(raw: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|_| PersonaError::InvalidInput("malformed device record JSON".to_string()))?;
        let device_id = Uuid::parse_str(
            value
                .get("device_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    PersonaError::InvalidInput("device record missing device_id".to_string())
                })?,
        )
        .map_err(|_| PersonaError::InvalidInput("malformed device_id in record".to_string()))?;
        let device_name = value
            .get("device_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PersonaError::InvalidInput("device record missing device_name".to_string())
            })?
            .to_string();
        let secret_b64 = value
            .get("secret_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PersonaError::InvalidInput("device record missing secret_key".to_string())
            })?;
        let secret: [u8; 32] = B64
            .decode(secret_b64)
            .map_err(|_| PersonaError::InvalidInput("malformed secret_key base64".to_string()))?
            .try_into()
            .map_err(|_| PersonaError::InvalidInput("secret_key must be 32 bytes".to_string()))?;
        Ok(Self {
            device_id,
            device_name,
            key_pair: DeviceKeyPair::from_secret(secret),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_json_round_trips_identity() {
        let identity = DeviceIdentity::generate("laptop")
            .unwrap()
            .with_device_id(Uuid::new_v4());
        let restored = DeviceIdentity::from_stored_json(&identity.to_stored_json()).unwrap();
        assert_eq!(restored.device_id, identity.device_id);
        assert_eq!(restored.device_name, "laptop");
        assert_eq!(
            restored.key_pair.public_bytes(),
            identity.key_pair.public_bytes()
        );
    }

    #[test]
    fn generate_produces_distinct_keypairs() {
        let a = DeviceIdentity::generate("a").unwrap();
        let b = DeviceIdentity::generate("b").unwrap();
        assert_ne!(a.key_pair.public_bytes(), b.key_pair.public_bytes());
    }

    #[test]
    fn stored_json_rejects_malformed_records() {
        assert!(DeviceIdentity::from_stored_json("not json").is_err());
        // 缺字段
        assert!(DeviceIdentity::from_stored_json("{\"device_id\":\"x\"}").is_err());
        // 坏 UUID
        assert!(DeviceIdentity::from_stored_json(
            "{\"device_id\":\"nope\",\"device_name\":\"d\",\"secret_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}"
        )
        .is_err());
        // 私钥长度不对（31B / 33B）
        for bad_len in [&[0u8; 31][..], &[0u8; 33][..]] {
            let record = serde_json::json!({
                "device_id": "00000000-0000-0000-0000-000000000000",
                "device_name": "d",
                "secret_key": B64.encode(bad_len),
            });
            assert!(DeviceIdentity::from_stored_json(&record.to_string()).is_err());
        }
    }

    /// 三个字段逐个整条缺失（不是坏值）各有专属报错，fail-closed 不猜。
    #[test]
    fn stored_json_rejects_missing_fields_individually() {
        let id = "00000000-0000-0000-0000-000000000000";
        let must_reject = |raw: String, needle: &str| match DeviceIdentity::from_stored_json(&raw) {
            Err(e) => assert!(e.to_string().contains(needle), "{e}"),
            Ok(_) => panic!("record must be rejected: missing {needle}"),
        };
        must_reject("{}".to_string(), "missing device_id");
        must_reject(format!(r#"{{"device_id":"{id}"}}"#), "missing device_name");
        must_reject(
            format!(r#"{{"device_id":"{id}","device_name":"d"}}"#),
            "missing secret_key",
        );
    }
}
