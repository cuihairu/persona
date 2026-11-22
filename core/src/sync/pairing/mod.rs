//! 同步组动态密码配对（跨设备同步 S1，`docs/sync-group-mode.md` §二.1-2）。
//!
//! 零账号入组：邀请端出短时效动态密码，加入端输入同码，经 PAKE 换出强
//! 共享钥（pairing key），组密钥以其 AEAD 包裹后经中转递交——短码与组密钥
//! 都不上中转线路（中转只见 SRP 公开消息与密文信封，零知识）。
//!
//! 协议（SRP-6a 原语复用 [`crate::auth::srp`]，RFC 5054 向量锁定），
//! host = 邀请端（组内、持组密钥），guest = 加入端，中转 = 无账号信箱：
//!
//! 1. [`PairingHost::new_invite`] → `(host, invite{code, salt})`，code 展示
//! 2. [`PairingGuest::start`]（输码）→ `client_public` 经中转交 host
//! 3. [`PairingHost::accept_join`] → `server_public` 经中转回 guest；
//!    双端各自派生 6 位数字短指纹展示，人工比对（防中间人）
//! 4. [`PairingGuest::finish`] → `client_proof`（M1）经中转交 host
//!    （比对通过后才提交）
//! 5. [`PairingHost::complete`] → 校验 M1，交出 `{server_proof(M2),
//!    wrapped_group_key}`；M2 只在 M1 验证通过后交付
//! 6. [`PairingGuest::accept_handoff`] → 校验 M2，解出组密钥，入组完成
//!
//! 安全语义：
//! - **短码不作密钥**：先 Argon2id（独立域前缀，与本地解锁/备份/登录
//!   SRP 互为不同协议域）派生，派生值才进 SRP 的 `x`；
//! - **防中间人**：无短码的中间人派不出同款 pairing key，短指纹不一致
//!   即被人工比对拦下；M1/M2 双向证明兜底；
//! - **单向递送**：`wrapped_group_key` 只有 pairing key 能开，中转存密文
//!   无益；`complete`/`accept_handoff` 均一次性（消耗握手态）。
//! - TTL/单次会话/限次尝试由中转层负责（见 server `/api/v1/pairing/*`），
//!   本模块只做纯密码逻辑，无 IO。
//!
//! # 模块布局
//!
//! 参数与码/KDF/指纹/组密钥封解在 [`crypto`]，host 侧在 [`host`]，guest
//! 侧在 [`guest`]，wire 消息与邀请串在 [`message`]，中继客户端在
//! [`relay`]。

mod crypto;
mod guest;
mod host;
mod message;
#[cfg(feature = "remote-auth")]
pub mod relay;

pub use crypto::*;
pub use guest::*;
pub use host::*;
pub use message::*;

#[cfg(test)]
mod tests;
