//! SSH / passkey 审批事件负载（`persona://*-approval` wire 报文）。

use serde::Serialize;

/// `persona://ssh-approval` 事件负载：一条待审批的 SSH 签名请求
#[derive(Debug, Clone, Serialize)]
pub struct SshApprovalRequest {
    pub request_id: String,
    /// 凭据 UUID（非敏感）
    pub key_id: String,
    /// 公钥指纹（SHA256 前 8 字节，用于人工核对）
    pub fingerprint: String,
    /// 操作名（当前恒为 "sign"）
    pub operation: String,
    /// 目标主机（未知时为 null）
    pub peer: Option<String>,
    /// 触发原因（策略说明）
    pub reason: String,
}

/// `persona://passkey-approval` 事件负载：一条待审批的 bridge passkey 请求。
/// 只含 origin/rp/账号等元数据 —— clientDataJSON 永不出 bridge 进程。
#[derive(Debug, Clone, Serialize)]
pub struct PasskeyApprovalRequest {
    pub request_id: String,
    /// 沿用 bridge wire 的操作名："passkey_create" | "passkey_assert"
    pub operation: String,
    /// 人工核对的 relying party（assert 时为 None：rp 存在 vault item 上）
    pub rp_id: Option<String>,
    /// 发起请求的完整页面 origin
    pub origin: String,
    /// create 时的账号名（assert 时在存储 item 上，桌面无从得知）
    pub user_name: Option<String>,
    /// assert 时对应 vault item 的 UUID
    pub item_id: Option<String>,
}

// ---- 账号体系（M2：persona-server /api/v1/accounts/* 的 tauri 代理层
//      契约。字段名/形状与 desktop/src/utils/api.ts 的 account seam 及
//      server/src/api/accounts.rs 一一对应；命令侧见 commands.rs 的
//      account_* 族）----
