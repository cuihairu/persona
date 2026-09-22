//! Connect 本机自动化令牌（CONNECT_AUTOMATION_DESIGN 阶段 1；迁移 015）。
//!
//! 职责边界：本模块只持有 scope 类型、token 生成/哈希纯函数与判定逻辑；
//! 表访问在 [`crate::storage::ConnectTokenRepository`]，解锁态编排（创建/
//! 认证/数据面 scope 过滤）在 [`crate::PersonaService`] 的 `connect_*` 方法。
//! HTTP 面（Host/Origin 三防线、限额、响应包络）是宿主层（desktop axum /
//! CLI serve）的职责，不属于本模块——框架无关。
//!
//! 安全不变式（由 service 层测试锁定）：
//! - token 明文只在创建时返回一次，库里只有 SHA-256 哈希 + 指纹；
//! - 无效/吊销/不存在的 token 一律 `None`（404/403 同形由端点层落实）；
//! - scope 恒排除敏感类型（SSH key / crypto wallet / 自定义），
//!   verbs 起步只有 `read`。

pub mod token;

pub use token::{
    fingerprint_from_hash, generate_token, hash_token, ConnectItemType, ConnectTokenRow,
    ConnectTokenScope, ConnectVerb, TOKEN_PREFIX,
};
