//! Transport abstraction for group key envelope exchange (E2EE_SYNC_DESIGN §6 device lifecycle).
//!
//! Assembling a [`SyncSession`] requires "fetch all envelopes → unwrap the local one to get the group key".
//! The HTTP transport goes through [`SyncAdminApi`] (server `/group-keys`); the cloud-drive transport goes
//! through [`super::cloud::CloudGroupKeyStore`] (cloud-drive directory `env-<device>.bin`).
//! Extracting envelope exchange into a trait keeps session assembly independent of the concrete transport —
//! the instruction stream (oplog) and vault-level snapshots travel via [`SyncRemote`], and this trait only
//! handles "device registration + envelope send/receive".

use async_trait::async_trait;
use uuid::Uuid;

use super::admin::SyncGroupKeyEntry;
use crate::sync::device::DeviceIdentity;
use crate::Result;

/// Minimal interface for group key envelope exchange. The implementation decides where envelopes are stored
/// (server rows / cloud-drive files), but the semantics match [`SyncAdminApi`] exactly: register a device,
/// upload a per-device envelope, list all envelopes, and bootstrap an empty group.
///
/// Division of labor with [`SyncRemote`]: the instruction stream and snapshots travel via `SyncRemote`
/// (the transport plane), while device registration and envelope exchange go through this trait (the
/// management plane) — both transports (HTTP/cloud drive) need the management plane for a device to
/// obtain the group key; the instruction stream and the envelopes are two orthogonal transport planes.
#[async_trait]
pub trait GroupKeyStore: Send + Sync {
    /// Registers a device (public key + device name). Idempotency is decided by the implementation
    /// (HTTP returns 409 on duplicate name, the cloud drive dedupes by device_id).
    async fn register_device(&self, identity: &DeviceIdentity) -> Result<()>;
    /// Uploads a per-device envelope (an authorized action). The device must already be registered; otherwise the call fails (fail-closed).
    async fn put_group_key(&self, device_id: Uuid, envelope: &[u8]) -> Result<()>;
    /// Lists all uploaded envelopes.
    async fn group_keys(&self) -> Result<Vec<SyncGroupKeyEntry>>;
    /// Bootstraps a new group key for an empty group and seals it to itself; returns whether a bootstrap occurred.
    async fn bootstrap_group_if_empty(
        &self,
        device_id: Uuid,
        device_public: &[u8; 32],
    ) -> Result<bool>;
}

/// Envelope exchange over the HTTP transport: wraps [`SyncAdminApi`] with zero behavior change (only the call
/// surface changes; server routes/protocol untouched).
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
