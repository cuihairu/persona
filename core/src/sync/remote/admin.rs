//! 设备与组密钥信封管理面：[`SyncAdminApi`] 接 `/devices` +
//! `/group-keys`（§6 设备生命周期），`SyncDevice`/`SyncGroupKeyEntry` 为
//! server 行的客户端视图。

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use uuid::Uuid;

use super::http::SyncHttp;
use crate::{PersonaError, Result};

/// 已登记设备（server `sync_devices` 行的客户端视图）。`public_key` 已解
/// base64——坏值让本层报错，不让调用方处理编码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncDevice {
    pub id: Uuid,
    pub device_name: String,
    pub public_key: [u8; 32],
    pub created_at: String,
    /// 设备主人的自由备注（S4）：只有设备本人能写，全员可读。
    pub remark: String,
}

/// group key 信封条目（server `sync_group_keys` 行的客户端视图）。
/// 信封字节保持原样（`envelope::open_group_key` 的输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncGroupKeyEntry {
    pub device_id: Uuid,
    pub envelope: Vec<u8>,
    pub sealed_by: String,
    pub created_at: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireDeviceInfo {
    id: String,
    device_name: String,
    public_key: String,
    created_at: String,
    /// remark 列是后来加的（0011 迁移）——老服务器不下发，default 补空串。
    #[serde(default)]
    remark: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireDeviceList {
    devices: Vec<WireDeviceInfo>,
}

#[derive(Debug, serde::Deserialize)]
struct WireGroupKeyEntry {
    device_id: String,
    envelope: String,
    sealed_by: String,
    created_at: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireGroupKeys {
    keys: Vec<WireGroupKeyEntry>,
    #[serde(default)]
    epoch: u64,
}

#[derive(Debug, serde::Serialize)]
struct WireRotateBegin {
    if_epoch: u64,
}

#[derive(Debug, serde::Deserialize)]
struct WireRotateBeginResponse {
    epoch: u64,
}

#[derive(Debug, serde::Serialize)]
struct WireRegisterDevice<'a> {
    device_name: &'a str,
    public_key: String,
}

#[derive(Debug, serde::Deserialize)]
struct WireRegisterDeviceResponse {
    device_id: String,
}

#[derive(Debug, serde::Serialize)]
struct WirePutGroupKey<'a> {
    device_id: String,
    envelope: &'a str,
}

#[derive(Debug, serde::Serialize)]
struct WirePutRemark<'a> {
    remark: &'a str,
}

/// 服务器还回显 device_name（恒等于令牌归属名，调用方已知），不取。
#[derive(Debug, serde::Deserialize)]
struct WireRemarkResponse {
    remark: String,
}

fn decode_b32(s: &str, what: &str) -> Result<[u8; 32]> {
    let bytes = B64
        .decode(s)
        .map_err(|_| PersonaError::Io(format!("malformed {what} in sync response (bad base64)")))?;
    let key: [u8; 32] = bytes.try_into().map_err(|_: Vec<u8>| {
        PersonaError::Io(format!("malformed {what} in sync response (bad length)"))
    })?;
    Ok(key)
}

/// `/api/v1/sync/devices` + `/api/v1/sync/group-keys` 的管理客户端——
/// 注册/列出/吊销设备、收发 group key 信封（DR-1/DR-3）。授权流在调用方
/// 组装：拆自己可开的信封得 group key → 用新设备公钥包新信封上传。
#[derive(Clone)]
pub struct SyncAdminApi {
    http: SyncHttp,
}

impl SyncAdminApi {
    pub fn new(base_url: impl Into<String>, token: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: SyncHttp::new(base_url, token)?,
        })
    }

    /// 登记设备（公钥 + 设备名），返回服务器分配的 device_id。
    /// 重名 409（公钥不可被静默替换）——错误串含服务器 message。
    pub async fn register_device(&self, device_name: &str, public_key: &[u8; 32]) -> Result<Uuid> {
        let resp = self
            .http
            .request(reqwest::Method::POST, "/devices")
            .json(&WireRegisterDevice {
                device_name,
                public_key: B64.encode(public_key),
            })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync register request failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "register device").await?;
        let body: WireRegisterDeviceResponse = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync register response".to_string()))?;
        let device_id = Uuid::parse_str(&body.device_id).map_err(|_| {
            PersonaError::Io("malformed device_id in sync register response".to_string())
        })?;
        Ok(device_id)
    }

    /// 列出全部已登记设备（含待授权的——信封未上传的设备）。
    pub async fn list_devices(&self) -> Result<Vec<SyncDevice>> {
        let resp = self
            .http
            .request(reqwest::Method::GET, "/devices")
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync list devices failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "list devices").await?;
        let body: WireDeviceList = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync device list".to_string()))?;
        let mut devices = Vec::with_capacity(body.devices.len());
        for wire in body.devices {
            let id = Uuid::parse_str(&wire.id).map_err(|_| {
                PersonaError::Io("malformed device id in sync device list".to_string())
            })?;
            let public_key = decode_b32(&wire.public_key, "device public_key")?;
            devices.push(SyncDevice {
                id,
                device_name: wire.device_name,
                public_key,
                created_at: wire.created_at,
                remark: wire.remark,
            });
        }
        Ok(devices)
    }

    /// 吊销设备（删登记与其信封；幂等，204）。已知的 group key 不可追溯
    /// 撤销（DR-3 诚实边界）——提示文案归调用方。
    pub async fn delete_device(&self, device_id: Uuid) -> Result<()> {
        let resp = self
            .http
            .request(reqwest::Method::DELETE, &format!("/devices/{device_id}"))
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync revoke device failed: {e}")))?;
        SyncHttp::ensure_success(resp, "revoke device").await?;
        Ok(())
    }

    /// 设置**本设备**的自由备注（S4：令牌归属即设备身份，无跨设备路径；
    /// 服务端按令牌归属的 device_name 定位行）。空串/纯空白 = 清除。
    /// 返回服务端规整后的备注（trim 过）。
    pub async fn set_device_remark(&self, remark: &str) -> Result<String> {
        let resp = self
            .http
            .request(reqwest::Method::PUT, "/devices/remark")
            .json(&WirePutRemark { remark })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync set device remark failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "set device remark").await?;
        let body: WireRemarkResponse = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync remark response".to_string()))?;
        Ok(body.remark)
    }

    /// 取全部设备信封。调用方只认自己 device_id 的那条；未授权设备拿到
    /// 别人的信封也拆不开（fail-closed）。
    pub async fn group_keys(&self) -> Result<Vec<SyncGroupKeyEntry>> {
        Ok(self.group_keys_with_epoch().await?.0)
    }

    /// [`Self::group_keys`] + 全组轮换代数（rotate-begin 乐观锁的基线）。
    /// 老服务器无 epoch 字段时 serde default 到 0——与「从未轮换过」一致，
    /// begin 时若服务器实际有表则自然 409 提示重读，方向安全。
    pub async fn group_keys_with_epoch(&self) -> Result<(Vec<SyncGroupKeyEntry>, u64)> {
        let resp = self
            .http
            .request(reqwest::Method::GET, "/group-keys")
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync get group keys failed: {e}")))?;
        let resp = SyncHttp::ensure_success(resp, "get group keys").await?;
        let body: WireGroupKeys = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed sync group keys".to_string()))?;
        let mut keys = Vec::with_capacity(body.keys.len());
        for wire in body.keys {
            let device_id = Uuid::parse_str(&wire.device_id).map_err(|_| {
                PersonaError::Io("malformed device_id in sync group keys".to_string())
            })?;
            let envelope = B64.decode(&wire.envelope).map_err(|_| {
                PersonaError::Io("malformed envelope in sync group keys (bad base64)".to_string())
            })?;
            keys.push(SyncGroupKeyEntry {
                device_id,
                envelope,
                sealed_by: wire.sealed_by,
                created_at: wire.created_at,
            });
        }
        Ok((keys, body.epoch))
    }

    /// 轮换互斥点（E2EE_SYNC_DESIGN §11 开放问题 2）：epoch 乐观锁抢占。
    /// 返回抢占后的新代数；另一台设备已并发轮换时 409 →
    /// [`PersonaError::ConcurrentConflict`]（调用方 fail-closed 中止，
    /// 未写任何信封、未重包，重读状态后可重试）。
    pub async fn begin_group_rotation(&self, if_epoch: u64) -> Result<u64> {
        let resp = self
            .http
            .request(reqwest::Method::POST, "/group-key/rotate-begin")
            .json(&WireRotateBegin { if_epoch })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync rotate begin failed: {e}")))?;
        if resp.status() == reqwest::StatusCode::CONFLICT {
            return Err(PersonaError::ConcurrentConflict(
                "group key rotation lost the race: another device rotated concurrently; \
                 re-sync and retry"
                    .to_string(),
            )
            .into());
        }
        let resp = SyncHttp::ensure_success(resp, "rotate begin").await?;
        let body: WireRotateBeginResponse = resp
            .json()
            .await
            .map_err(|_| PersonaError::Io("malformed rotate begin response".to_string()))?;
        Ok(body.epoch)
    }

    /// 首设备自举（空组建组）：服务器上尚无任何 group key 信封时，本机生成
    /// group key 并用自己的公钥封唯一信封上传。全新服务器上不存在「既有
    /// 设备」可代为授权——令牌持有者本来就能读到全部密文，首台设备自建组
    /// 不放大信任面。返回 `true` = 本机完成自举（即已授权）；`false` = 组
    /// 非空，走既有流程等他机授权。
    ///
    /// 已知边界：两台设备在彼此可见前先后见到空组会各自建组（并发自举），
    /// 各自只能拆开自己的信封、对方条目解不开按容错跳过——事后在重复的
    /// 一侧 leave 重走即可。全员离开后组回到空态，下一个加入者自举出
    /// **新**组密钥：服务器残留的旧组密文解不开、按容错逐条跳过（不废
    /// 整轮），不回读旧数据。
    pub async fn bootstrap_group_if_empty(
        &self,
        device_id: Uuid,
        device_public: &[u8; 32],
    ) -> Result<bool> {
        if !self.group_keys().await?.is_empty() {
            return Ok(false);
        }
        let group = crate::sync::keys::GroupKey::generate()?;
        let envelope = crate::sync::envelope::seal_group_key(group.as_bytes(), device_public)?;
        self.put_group_key(device_id, &envelope).await?;
        Ok(true)
    }

    /// 为设备上传 group key 信封（授权动作）。信封必须已登记设备的公钥封出
    /// （服务器校验 80 字节 + 设备存在；挂幽灵设备 fail-closed）。
    pub async fn put_group_key(&self, device_id: Uuid, envelope: &[u8]) -> Result<()> {
        let resp = self
            .http
            .request(reqwest::Method::PUT, "/group-keys")
            .json(&WirePutGroupKey {
                device_id: device_id.to_string(),
                envelope: &B64.encode(envelope),
            })
            .send()
            .await
            .map_err(|e| PersonaError::Io(format!("sync put group key failed: {e}")))?;
        SyncHttp::ensure_success(resp, "put group key").await?;
        Ok(())
    }
}
