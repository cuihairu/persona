//! E2EE 同步核心（E2EE_SYNC_DESIGN 阶段 2）。
//!
//! 信任根 = 主密码 + 每设备私钥（DR-1）；同步密文与主密码解耦——条目由
//! per-item key 封装（本地同款信封结构），item key 由 group key 包裹，
//! group key 只以「设备信封」形态存在于服务器（[`envelope`]）。
//!
//! - [`keys`]：group key / 设备密钥对的生成与类型
//! - [`envelope`]：`persona-dev-env-1` 信封密封与开启
//!
//! 本模块只做纯密码层与数据结构；oplog 存储、LWW 冲突、同步引擎随阶段 2
//! 后续批次落地。设备私钥的持久化（OS keyring `persona-device` / 0600 文件
//! fallback）由宿主负责——core 不依赖 keyring。

pub mod envelope;
pub mod keys;
