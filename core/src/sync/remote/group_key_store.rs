//! 组密钥信封交换的传输抽象（E2EE_SYNC_DESIGN §6 设备生命周期）。
//!
//! [`SyncSession`] 装配需要「取全部信封 → 拆本机那份得 group key」。HTTP
//! 传输经 [`SyncAdminApi`]（服务器 `/group-keys`），云盘传输经
//! [`super::cloud::CloudGroupKeyStore`]（云盘目录 `env-<device>.bin`）。
//! 把信封交换抽成 trait，让会话装配不依赖具体传输——指令流（oplog）与
//! 库级快照走 [`SyncRemote`]，这里只管「设备登记 + 信封收发」。

use async_trait::async_trait;
use uuid::Uuid;

use super::admin::SyncGroupKeyEntry;
use crate::sync::device::DeviceIdentity;
use crate::Result;

/// 组密钥信封交换的最小接口。实现方决定信封存哪（服务器行 / 云盘文件），
/// 但语义与 [`SyncAdminApi`] 完全一致：登记设备、上传单设备信封、列出
/// 全部信封、空组时自举。
///
/// 与 [`SyncRemote`] 的分工：指令流与快照走 `SyncRemote`（传输层），
/// 设备登记与信封交换走本 trait（管理面）——两种传输（HTTP/云盘）都要
/// 管理面才能让设备拿到 group key，指令流与信封是两个正交的传输面。
#[async_trait]
pub trait GroupKeyStore: Send + Sync {
    /// 登记设备（公钥 + 设备名）。幂等性由实现决定（HTTP 重名 409，
    /// 云盘同 device_id 去重）。
    async fn register_device(&self, identity: &DeviceIdentity) -> Result<()>;
    /// 上传单设备信封（授权动作）。设备必须已登记，未登记失败（fail-closed）。
    async fn put_group_key(&self, device_id: Uuid, envelope: &[u8]) -> Result<()>;
    /// 列出全部已上传信封。
    async fn group_keys(&self) -> Result<Vec<SyncGroupKeyEntry>>;
    /// 空组时自举出新组密钥并密封给自己，返回是否发生了自举。
    async fn bootstrap_group_if_empty(
        &self,
        device_id: Uuid,
        device_public: &[u8; 32],
    ) -> Result<bool>;
}

/// HTTP 传输的信封交换：包装 [`SyncAdminApi`]，零行为变化（只改调用面，
/// 服务器路由/协议不动）。
pub struct HttpGroupKeyStore {
    admin: super::SyncAdminApi,
}

impl HttpGroupKeyStore {
    pub fn new(admin: super::SyncAdminApi) -> Self {
        Self { admin }
    }
}

#[async_trait]
impl GroupKeyStore for HttpGroupKeyStore {
    async fn register_device(&self, identity: &DeviceIdentity) -> Result<()> {
        self.admin
            .register_device(&identity.device_name, identity.key_pair.public_bytes())
            .await
            .map(|_| ())
    }

    async fn put_group_key(&self, device_id: Uuid, envelope: &[u8]) -> Result<()> {
        self.admin.put_group_key(device_id, envelope).await
    }

    async fn group_keys(&self) -> Result<Vec<SyncGroupKeyEntry>> {
        self.admin.group_keys().await
    }

    async fn bootstrap_group_if_empty(
        &self,
        device_id: Uuid,
        device_public: &[u8; 32],
    ) -> Result<bool> {
        self.admin
            .bootstrap_group_if_empty(device_id, device_public)
            .await
    }
}
