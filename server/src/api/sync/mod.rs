//! `/api/v1/sync/*`：E2EE 同步中继（阶段 2 批 3，E2EE_SYNC_DESIGN §5/§6）。
//!
//! 服务器定位 = **纯中继 + 密文保管**：oplog 载荷与 group key 信封全部是
//! 密文字节，服务器盲存、按到达顺序追加、按游标转发——**不做任何胜负
//! 判定或合并**（DR-4：让服务器裁决等于把合并语义交给一个我们拒绝信任
//! 其诚实的组件）。真实性边界：本阶段不校验 op.device_id 与认证身份的
//! 对应（静态 token 与 SRP token 混用，无统一映射），写入真实性由
//! Bearer 认证 + 远期「设备私钥签名 oplog」（§11）承担；THREAT_MODEL
//! 已登记「恶意客户端无法靠服务器根除」。
//!
//! 认证：整个子路由挂 `require_bearer`——静态令牌与 SRP 短期令牌自然
//! 兼容（auth.rs 的同一中间件）。
//!
//! fail-closed 的授权语义：「有信封 = 已授权」。未授权设备 GET 拿得到
//! 别人的信封，但拆不开（X25519：无对应私钥，tag 校验必失败）——拿不到
//! group key 也解不开任何条目，由密码学而非服务器 ACL 保证。

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::{decode_cursor, encode_cursor, ApiError, ErrorItem};
use crate::auth::DeviceName;
use crate::AppState;

/// push 单批条数上限（沿 events 的 500 条惯例，设计稿 §5）。
pub(crate) const MAX_BATCH_OPS: usize = 500;
/// 单条 op 的 ciphertext / wrapped_item_key 解码后字节上限。凭据密文 KB 级；
/// 更大的载荷（附件）是 §11 开放问题，走 v2 通道。
pub(crate) const MAX_PAYLOAD_BYTES: usize = 512 * 1024;
/// pull 单页默认/最大条数（沿 events 的游标分页惯例）。
const PULL_DEFAULT_LIMIT: u32 = 200;
const PULL_MAX_FETCH: u32 = 500;

mod devices;
mod oplog;
mod push_pull;
mod snapshot;
mod status;
mod wire;

pub use devices::{
    delete_device, get_group_keys, list_devices, put_device_remark, put_group_key, register_device,
    rotate_begin,
};
pub use push_pull::{pull, push};
pub use snapshot::{get_snapshot, put_snapshot};
pub use status::status;
use wire::{
    DeviceInfo, DeviceListResponse, GroupKeyEntry, GroupKeysResponse, PullResponse, PushResponse,
    RegisterDeviceResponse, RotateBeginResponse,
};
pub use wire::{
    PullQuery, PushRequest, PutGroupKeyRequest, PutRemarkRequest, RegisterDeviceRequest,
    RotateBeginRequest, WireOp, WirePayload,
};

#[cfg(test)]
mod tests;
