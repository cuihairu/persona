//! 自动锁策略命令：CLI 参数面（`AutoLockArgs`/`AutoLockCommand`）。
//!
//! # 模块布局
//!
//! 分发与仓储初始化在 [`flow`]，策略 CRUD 在 [`policies`]，用户指派在
//! [`assignment`]，统计/状态看板在 [`dashboard`]，会话锁操作在
//! [`session`]，格式化与用例解析在 [`display`]。

use clap::{Args, Subcommand};
use persona_core::models::auto_lock_policy::AutoLockSecurityLevel;

mod assignment;
mod dashboard;
mod display;
mod flow;
mod policies;
mod session;

pub use flow::handle_auto_lock;

#[cfg(test)]
mod tests;

#[derive(Args)]
pub struct AutoLockArgs {
    #[command(subcommand)]
    pub command: AutoLockCommand,
}

#[derive(Subcommand)]
pub enum AutoLockCommand {
    /// List all auto-lock policies
    List {
        /// Show only active policies
        #[arg(long, short)]
        active: bool,

        /// Filter by security level
        #[arg(long)]
        security_level: Option<AutoLockSecurityLevel>,

        /// Search policies by name
        #[arg(long)]
        search: Option<String>,
    },
    /// Show details of a specific policy
    Show {
        /// Policy ID or name
        policy_identifier: String,
    },
    /// Create a new auto-lock policy
    Create {
        /// Policy name
        #[arg(long, short)]
        name: String,

        /// Policy description
        #[arg(long, short)]
        description: Option<String>,

        /// Security level (low, medium, high, maximum)
        #[arg(long, short)]
        security_level: AutoLockSecurityLevel,

        /// Inactivity timeout in seconds
        #[arg(long, short)]
        inactivity_timeout: Option<u64>,

        /// Absolute session timeout in seconds
        #[arg(long, short)]
        absolute_timeout: Option<u64>,

        /// Sensitive operation timeout in seconds
        #[arg(long)]
        sensitive_timeout: Option<u64>,

        /// Maximum concurrent sessions
        #[arg(long)]
        max_sessions: Option<usize>,

        /// Enable lock warnings
        #[arg(long)]
        warnings: bool,

        /// Warning time before lock in seconds
        #[arg(long)]
        warning_time: Option<u64>,

        /// Force lock on sensitive operations
        #[arg(long)]
        force_sensitive: bool,

        /// Create from predefined use case (personal|corporate|public|developer|high-security)
        #[arg(long, short)]
        use_case: Option<String>,
    },
    /// Update an existing auto-lock policy
    Update {
        /// Policy ID
        policy_id: uuid::Uuid,

        /// New policy name
        #[arg(long, short)]
        name: Option<String>,

        /// New policy description
        #[arg(long, short)]
        description: Option<String>,

        /// New security level
        #[arg(long, short)]
        security_level: Option<AutoLockSecurityLevel>,

        /// New inactivity timeout in seconds
        #[arg(long, short)]
        inactivity_timeout: Option<u64>,

        /// New absolute session timeout in seconds
        #[arg(long, short)]
        absolute_timeout: Option<u64>,

        /// New sensitive operation timeout in seconds
        #[arg(long)]
        sensitive_timeout: Option<u64>,

        /// New maximum concurrent sessions
        #[arg(long)]
        max_sessions: Option<usize>,

        /// Enable/disable warnings
        #[arg(long)]
        warnings: Option<bool>,

        /// New warning time in seconds
        #[arg(long)]
        warning_time: Option<u64>,

        /// Enable/disable force sensitive lock
        #[arg(long)]
        force_sensitive: Option<bool>,
    },
    /// Delete an auto-lock policy
    Delete {
        /// Policy ID
        policy_id: uuid::Uuid,

        /// Skip confirmation prompt
        #[arg(long, short)]
        force: bool,
    },
    /// Assign a policy to a user
    Assign {
        /// User ID (email or UUID)
        user_id: String,

        /// Policy ID or name
        policy_identifier: String,
    },
    /// Remove policy assignment from user
    Unassign {
        /// User ID (email or UUID)
        user_id: String,
    },
    /// Show policy assigned to a user
    UserPolicy {
        /// User ID (email or UUID)
        user_id: String,
    },
    /// Set a policy as the default
    SetDefault {
        /// Policy ID
        policy_id: uuid::Uuid,
    },
    /// Get current auto-lock statistics
    Stats {
        /// Policy ID to get statistics for specific policy
        #[arg(long, short)]
        policy_id: Option<uuid::Uuid>,
    },
    /// Show current session status
    Status {
        /// User ID (optional, defaults to current user)
        #[arg(long, short)]
        user_id: Option<String>,
    },
    /// Lock current session
    Lock {
        /// Session ID (optional, defaults to current session)
        #[arg(long, short)]
        session_id: Option<String>,
    },
    /// Unlock a session
    Unlock {
        /// Session ID
        session_id: String,
    },
}
