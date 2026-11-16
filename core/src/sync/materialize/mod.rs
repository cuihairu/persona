//! pull 物化层（E2EE_SYNC_DESIGN §5/§7）——把 oplog 主位落进本地主库。
//!
//! 阶段 2 的 `pull_cycle` 只把远端 op 记入本地 oplog 表；本模块补上「写主库」
//! 的最后一步：对每个 item 用 [`item_view`] 从 **op 集合**推导主位（终态只
//! 取决于 op 集合，与到达顺序无关），再按 §7 落库：
//!
//! - 主位 put：group key 拆出 item key → 解快照密文 → 重包 item key 到本机
//!   主密钥（各设备主密码不同步，同步密文与主密码解耦）→ 写凭据行。
//! - 主位 tombstone：删本地行（无 payload 可解）。
//! - 主位是**本机** op：主库已是事实源（写路径直接写入），跳过。
//! - 真冲突的败方不物化——冲突副本留驻 oplog（[`item_view`] 的 `conflicts`），
//!   由阶段 3 的裁决 UI 展示；「采纳」会经写路径产生新 lamport 的 put，
//!   自然赢回主位。
//!
//! 幂等且可反复跑：物化失败（如快照引用的身份尚未同步）的 op **留在 oplog**，
//! 下轮重跑自动补齐。身份缺失是常规状态（Identity 条目的同步在阶段 3 后续
//! 批次），不是错误——用 [`MaterializeOutcome::SkippedPendingIdentity`] 诚实
//! 上报。同步是尽力而为的旁路：本层任何单 item 失败只计入报告，不中断整体。

mod materializer;
mod report;

pub use materializer::Materializer;
pub use report::{MaterializeOutcome, MaterializeReport};

#[cfg(test)]
mod tests;
