//! 同步远端的 HTTP 客户端（feature `remote-auth`）：[`super::engine::SyncRemote`]
//! 接 persona-server 的 `/api/v1/sync/oplog`（oplog 收发），[`SyncAdminApi`]
//! 接 `/devices` + `/group-keys`（设备登记/group key 信封，§6 设备生命周期）。
//! wire 契约的权威定义在 `server/src/api/sync.rs`：base64 STANDARD、错误
//! 包络 `{"error":{"code","message",…}}`。
//!
//! `Vec<u8>` 的 serde 默认是数字数组而非 base64 字符串，与服务器 wire 层
//! （`WirePayload` 收发 base64 文本）对不上——本模块用 [`WireOp`]/[`WirePayload`]
//! 中间结构手工转换，不直接序列化 `SyncOp`。
//!
//! 条目级损坏的容错口径（[`SyncRemote`] trait 约定）：pull 单条 op 解析
//! 失败（坏 UUID / 坏 base64 / put-delete 与 payload 形状矛盾）→ 跳过该条，
//! 不废整批。oplog 是 append-only 密文中继，一条损坏不应卡死其余条目的
//! 收敛；跳过只影响该条，不影响游标推进。push 侧载荷是本地刚产出的密文，
//! 无损坏路径。未知 `kind` → [`ItemKind::Unknown`] 落库（前向兼容，不跳过）。

mod admin;
mod client;
mod http;
mod wire;

pub use admin::*;
pub use client::*;

#[cfg(test)]
mod tests;
