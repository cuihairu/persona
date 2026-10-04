//! 账号域（persona-server `/api/v1/accounts/*`）的客户端与契约类型。
//!
//! 落点纪律与 E2EE sync 轨道一致：网络与 wire 在 core，密码学/仪式编排
//! 也归 core 或宿主共同完成；本模块只做 HTTP 代理（见 [`remote`] 的模块
//! 文档）。feature `accounts`（随 `remote-auth` 等 reqwest 消费者同款
//! 独立门禁）。

pub mod remote;
