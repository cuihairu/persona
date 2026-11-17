//! Context-aware identity suggestion（设计 docs/CONTEXT_AWARE_DESIGN.md 阶段 1）。
//!
//! 铁律（与 concepts/context.md 一致）：**Context 只建议，不授权**。建议结果
//! 永远不会绕过策略放行动作；未被确认的建议不改变 `active_identity_id`，
//! 只改变「默认候选」。打分是确定性纯函数（无随机/ML），决策在 core、
//! 客户端只采集信号。
//!
//! 信号（v1）：`cwd`（上溯 `.git` 读 `remote origin` → forge 归一化）、
//! `host`（`PERSONA_HOST` 覆盖 / gethostname）。映射表 `~/.persona/context.toml`
//! （全局）+ `$repo/.persona/context.toml`（仓库内，链上位高）；覆盖链
//! （高优先在上）：`PERSONA_CONTEXT_OVERRIDE` > 仓库内映射 > 全局映射 >
//! active identity。隐私：信号全部本地计算，永不外发；审计只记用户确认
//! （复用 switch 审计），不记信号本身。

mod git;
mod map;
mod signals;
mod suggest;
#[cfg(test)]
mod tests;

pub use git::{discover_git_repo, normalize_remote_url, parse_origin_url};
pub use map::{ContextMapFile, IdentityEntry};
pub use signals::{current_host, ContextSignals};
pub use suggest::{cwd_hash, suggest, SuggestResult, Suggestion};

/// 候选入选阈值：score < MIN_SUGGEST 不进候选（设计 §4）。
pub const MIN_SUGGEST: f64 = 0.6;
/// 项目映射命中权重（设计示例：score 1.0）。
pub const PROJECT_WEIGHT: f64 = 1.0;
/// 主机正则命中权重（低于项目命中，高于阈值）。
pub const HOST_WEIGHT: f64 = 0.8;
/// 历史学习候选权重（设计 §4.1 示例：score 0.7，低于任何映射命中）。
pub const LEARN_WEIGHT: f64 = 0.7;
/// 学习计数窗口（设计示例「最近 30 天」）：窗口外记录不计入。
pub const LEARN_WINDOW_DAYS: i64 = 30;
