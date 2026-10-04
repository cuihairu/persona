//! 账号域（persona-server `/api/v1/accounts/*`）的客户端与契约类型。
//!
//! 落点纪律与 E2EE sync 轨道一致：网络与 wire 在 core（[`remote`]，纯
//! HTTP 代理），密码学/仪式编排也在 core（[`login`]，SRP 数学不出
//! core——渲染层不做任何口令推导）。feature `accounts`（随 `remote-auth`
//! 等 reqwest 消费者同款独立门禁）。

pub mod login;
pub mod remote;
