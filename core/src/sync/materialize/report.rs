use uuid::Uuid;

/// 单个 item 的物化结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializeOutcome {
    /// 远端 put 落库（新建或覆盖既有行）。
    Written,
    /// 远端 tombstone 落地（本地行已删除，或本就不存在）。
    Tombstoned,
    /// 主位是本机 op——主库已是事实源，无需物化。
    SkippedLocalPrimary,
    /// 快照引用的身份本地还没有（Identity 同步在后续批次）——留待下轮。
    SkippedPendingIdentity { identity_id: Uuid },
    /// 不支持的条目种类（Identity 的捕获与物化在后续批次；未知 kind）。
    SkippedUnsupportedKind,
    /// oplog 无该 item 的 op（防御：调用方枚举与查询竞态）。
    NoPrimary,
}

/// 一轮全量物化的汇总。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaterializeReport {
    pub written: usize,
    pub tombstoned: usize,
    pub skipped_local_primary: usize,
    pub skipped_unsupported_kind: usize,
    pub no_primary: usize,
    /// (item_id, identity_id)：等身份同步后重跑即可补齐。
    pub pending_identity: Vec<(Uuid, Uuid)>,
}
