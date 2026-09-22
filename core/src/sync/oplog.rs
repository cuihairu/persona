//! oplog 条目结构与 LWW 冲突解决（E2EE_SYNC_DESIGN DR-4 / §5 / §7）。
//!
//! 全序 = `(lamport, device_id)`：lamport 大者赢，相等比 device_id 字典序；
//! 两端独立计算结果必然一致。同 item 两个版本 **lamport 相等且来自不同设备**
//! = 真冲突（离线双编辑典型形态）→ 保双版本：胜者占主位，负者进冲突区，
//! 等用户裁决（裁决 UI 属阶段 3，这里保证不丢数据、不静默覆盖）。
//!
//! 与设计稿的一处偏差：`conflict_of` 不作为落库快照列，而是
//! [`item_view`] 从该 item 的 op 集合**推导**（主位 = 全序最大者；副本 =
//! 与主位 lamport 相等但 device 不同的其余版本）——append-only 日志免维护，
//! 语义等价且不存在「主位被覆盖后副本指向失效」的问题。
//!
//! 删除 = tombstone（payload 为空的 delete op），参与同样的 LWW，防止离线
//! 删除被旧版本复活；服务器只存与转发，不做任何胜负判定。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use uuid::Uuid;

/// 同步条目类型。与服务器 wire 层的 kind 字符串一一对应（snake_case）；
/// 未知 kind 的前向兼容在 wire 解析层处理（跳过，不进本枚举）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Credential,
    Identity,
    Passkey,
}

/// 操作类型：put = 写入/更新；delete = tombstone（payload 恒空）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpType {
    Put,
    Delete,
}

/// oplog 条目的密文载荷（§5）：全部字节都是密文，服务器不可读。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPayload {
    pub ciphertext: Vec<u8>,
    /// 被 group key 包裹的 per-item key（本地 wrapped_item_key 同源）。
    pub wrapped_item_key: Vec<u8>,
}

/// 一条同步操作（§5 SyncOp）。`timestamp` 仅展示，**不参与任何排序**
/// （时钟只信客户端 Lamport 计数）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncOp {
    /// 幂等去重键（push 重放 / pull 重复投递均按此忽略）。
    pub op_id: Uuid,
    pub item_id: Uuid,
    pub kind: ItemKind,
    pub op: OpType,
    pub lamport: u64,
    pub device_id: Uuid,
    pub timestamp: Option<DateTime<Utc>>,
    /// delete（tombstone）时为 None。
    pub payload: Option<SyncPayload>,
}

impl SyncOp {
    pub fn is_tombstone(&self) -> bool {
        self.op == OpType::Delete
    }
}

/// LWW 全序比较（DR-4）：先比 lamport，再比 device_id。**不含 op_id**——
/// 同 (lamport, device_id) 的两条 op 在协议上不应共存（单设备时钟单调）。
pub fn compare_ops(a: &SyncOp, b: &SyncOp) -> Ordering {
    a.lamport
        .cmp(&b.lamport)
        .then(a.device_id.cmp(&b.device_id))
}

/// 真冲突：同一 item、lamport 相等、来自不同设备（DR-4 定义）。
pub fn is_true_conflict(a: &SyncOp, b: &SyncOp) -> bool {
    a.item_id == b.item_id && a.lamport == b.lamport && a.device_id != b.device_id
}

/// 单个 item 的 LWW 视图：主位 + 冲突副本区。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ItemState {
    /// 当前胜者（put 或 tombstone）。
    pub primary: Option<SyncOp>,
    /// 真冲突中被淘汰的并发版本，等待用户裁决（阶段 3 UI）。
    pub conflicts: Vec<SyncOp>,
}

impl ItemState {
    /// 从该 item 的全部 op 推导视图（[`item_view`] 的方法形态）。
    pub fn from_ops(ops: Vec<SyncOp>) -> Self {
        let mut state = Self::default();
        // 以确定顺序回放，等价于逐条 apply
        let mut ops = ops;
        ops.sort_by(|a, b| {
            b.lamport
                .cmp(&a.lamport)
                .then(b.device_id.cmp(&a.device_id))
                .then(b.op_id.cmp(&a.op_id))
        });
        for op in ops {
            apply_op(&mut state, op);
        }
        state
    }

    pub fn seen_op(&self, op_id: &Uuid) -> bool {
        self.primary.as_ref().is_some_and(|p| &p.op_id == op_id)
            || self.conflicts.iter().any(|c| &c.op_id == op_id)
    }
}

/// 从一组同 item 的 op 推导主位与冲突副本（见模块文档的 conflict_of 偏差）。
pub fn item_view(ops: Vec<SyncOp>) -> ItemState {
    ItemState::from_ops(ops)
}

/// 单步应用结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// incoming 成为新主位。`demoted` 仅在真冲突赢方替换时出现——被降级的
    /// 前主位（本函数已将其推入 `conflicts`，此处返回供调用方感知/审计）。
    Applied { demoted: Option<SyncOp> },
    /// incoming 是并发输家，降级为冲突副本。
    ConflictCopy,
    /// 旧版本、重放（op_id 已见）、或同 (lamport, device_id) 的越界重复。
    Ignored,
}

/// 把一条 op 应用到 item 状态（纯函数；[`apply_batch`] 的单步内核）。
pub fn apply_op(state: &mut ItemState, incoming: SyncOp) -> StepOutcome {
    // 幂等：op_id 已在主位或副本区 → 重放/重复投递，忽略
    if state.seen_op(&incoming.op_id) {
        return StepOutcome::Ignored;
    }
    let Some(incumbent) = state.primary.clone() else {
        state.primary = Some(incoming);
        return StepOutcome::Applied { demoted: None };
    };
    match compare_ops(&incoming, &incumbent) {
        Ordering::Less => {
            if incoming.lamport == incumbent.lamport {
                // 并发输家（真冲突败方晚到）：保双版本
                state.conflicts.push(incoming);
                StepOutcome::ConflictCopy
            } else {
                // 严格旧版本（含对 tombstone 的迟到 put：防复活）
                StepOutcome::Ignored
            }
        }
        Ordering::Greater => {
            if incoming.lamport == incumbent.lamport {
                // 真冲突赢方：前主位降级进冲突区（保双版本）
                let demoted = state.primary.replace(incoming);
                state
                    .conflicts
                    .push(demoted.clone().expect("primary just replaced"));
                StepOutcome::Applied { demoted }
            } else {
                state.primary = Some(incoming);
                StepOutcome::Applied { demoted: None }
            }
        }
        Ordering::Equal => {
            // 同 (lamport, device_id) 而 op_id 不同：违反单设备时钟单调的
            // 协议不变量。防御性忽略后到者，不覆盖、不崩溃。
            StepOutcome::Ignored
        }
    }
}

/// 一批 ops 的应用汇总。`max_lamport` 供调用方推进本机时钟：
/// `local = max(local, report.max_lamport)`（pull 时钟推进，DR-4）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BatchReport {
    pub applied: usize,
    pub conflicts: usize,
    pub ignored: usize,
    pub max_lamport: u64,
}

/// 应用一批 pull 到的 op（§7 操作序）：先按 (lamport, device_id, op_id)
/// **降序**稳定排序，再逐条 [`apply_op`]。乱序投递/跨批乱序天然容错——
/// 终态只取决于 op 集合本身，与到达顺序无关。
pub fn apply_batch(items: &mut BTreeMap<Uuid, ItemState>, ops: Vec<SyncOp>) -> BatchReport {
    let mut ops = ops;
    ops.sort_by(|a, b| {
        b.lamport
            .cmp(&a.lamport)
            .then(b.device_id.cmp(&a.device_id))
            .then(b.op_id.cmp(&a.op_id))
    });
    let mut report = BatchReport::default();
    for op in ops {
        report.max_lamport = report.max_lamport.max(op.lamport);
        let state = items.entry(op.item_id).or_default();
        match apply_op(state, op) {
            StepOutcome::Applied { .. } => report.applied += 1,
            StepOutcome::ConflictCopy => report.conflicts += 1,
            StepOutcome::Ignored => report.ignored += 1,
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITEM: Uuid = uuid::uuid!("00000000-0000-0000-0000-000000000001");
    const DEVICE_A: Uuid = uuid::uuid!("00000000-0000-0000-0000-00000000000a");
    const DEVICE_B: Uuid = uuid::uuid!("00000000-0000-0000-0000-00000000000b");

    fn put(lamport: u64, device: Uuid, tag: u8) -> SyncOp {
        SyncOp {
            op_id: Uuid::new_v4(),
            item_id: ITEM,
            kind: ItemKind::Credential,
            op: OpType::Put,
            lamport,
            device_id: device,
            timestamp: None,
            payload: Some(SyncPayload {
                ciphertext: vec![tag],
                wrapped_item_key: vec![tag],
            }),
        }
    }

    fn delete(lamport: u64, device: Uuid) -> SyncOp {
        SyncOp {
            op: OpType::Delete,
            payload: None,
            ..put(lamport, device, 0)
        }
    }

    // ---- compare_ops / is_true_conflict ----

    #[test]
    fn lamport_decides_regardless_of_device() {
        let low = put(1, DEVICE_B, 0);
        let high = put(2, DEVICE_A, 1);
        assert_eq!(compare_ops(&high, &low), Ordering::Greater);
        assert_eq!(compare_ops(&low, &high), Ordering::Less);
    }

    #[test]
    fn equal_lamport_falls_back_to_device_id() {
        let a = put(3, DEVICE_A, 0);
        let b = put(3, DEVICE_B, 1);
        assert_eq!(compare_ops(&b, &a), Ordering::Greater);
        assert!(is_true_conflict(&a, &b));
        assert!(!is_true_conflict(&a, &a)); // 自身非冲突
    }

    #[test]
    fn same_lamport_same_device_is_not_conflict() {
        let x = put(3, DEVICE_A, 0);
        let mut y = x.clone();
        y.op_id = Uuid::new_v4();
        assert!(!is_true_conflict(&x, &y));
        assert_eq!(compare_ops(&x, &y), Ordering::Equal);
    }

    // ---- apply_op ----

    #[test]
    fn first_op_takes_primary() {
        let mut state = ItemState::default();
        let op = put(1, DEVICE_A, 7);
        assert_eq!(
            apply_op(&mut state, op.clone()),
            StepOutcome::Applied { demoted: None }
        );
        assert_eq!(state.primary, Some(op));
        assert!(state.conflicts.is_empty());
    }

    #[test]
    fn newer_put_overwrites_primary_without_demote() {
        let mut state = ItemState::default();
        let old = put(1, DEVICE_A, 0);
        let new = put(2, DEVICE_A, 1);
        apply_op(&mut state, old);
        assert_eq!(
            apply_op(&mut state, new.clone()),
            StepOutcome::Applied { demoted: None }
        );
        assert_eq!(state.primary, Some(new));
    }

    #[test]
    fn stale_put_is_ignored() {
        let mut state = ItemState::default();
        apply_op(&mut state, put(5, DEVICE_A, 0));
        assert_eq!(
            apply_op(&mut state, put(4, DEVICE_B, 1)),
            StepOutcome::Ignored
        );
    }

    #[test]
    fn tombstone_prevents_revival_by_stale_put() {
        // 离线删除被旧版本复活是 DR-4 明确防住的形态
        let mut state = ItemState::default();
        apply_op(&mut state, put(1, DEVICE_A, 0));
        apply_op(&mut state, delete(2, DEVICE_A));
        assert!(state.primary.as_ref().unwrap().is_tombstone());
        assert_eq!(
            apply_op(&mut state, put(1, DEVICE_B, 9)),
            StepOutcome::Ignored
        );
        assert!(state.primary.as_ref().unwrap().is_tombstone());
    }

    #[test]
    fn true_conflict_keeps_both_versions_regardless_of_arrival_order() {
        let a = put(3, DEVICE_A, 1);
        let b = put(3, DEVICE_B, 2);
        assert!(is_true_conflict(&a, &b));

        // A 先到：B 赢（device 字典序），A 降级
        let mut state1 = ItemState::default();
        apply_op(&mut state1, a.clone());
        assert_eq!(
            apply_op(&mut state1, b.clone()),
            StepOutcome::Applied {
                demoted: Some(a.clone())
            }
        );
        assert_eq!(state1.primary.as_ref().unwrap().device_id, DEVICE_B);
        assert_eq!(state1.conflicts, vec![a.clone()]);

        // B 先到：A 直接降级——两种到达顺序终态一致（收敛）
        let mut state2 = ItemState::default();
        apply_op(&mut state2, b.clone());
        assert_eq!(apply_op(&mut state2, a.clone()), StepOutcome::ConflictCopy);
        assert_eq!(state1, state2);
    }

    #[test]
    fn replayed_op_id_is_ignored_wherever_it_landed() {
        let op = put(1, DEVICE_A, 0);
        let mut state = ItemState::default();
        apply_op(&mut state, op.clone());
        assert_eq!(apply_op(&mut state, op.clone()), StepOutcome::Ignored);

        // 副本区的 op_id 重放同样忽略
        let loser = put(2, DEVICE_A, 5);
        let winner = put(2, DEVICE_B, 6);
        apply_op(&mut state, loser.clone());
        apply_op(&mut state, winner);
        assert_eq!(apply_op(&mut state, loser), StepOutcome::Ignored);
    }

    #[test]
    fn protocol_violation_same_key_different_op_id_is_ignored() {
        let x = put(3, DEVICE_A, 0);
        let mut y = x.clone();
        y.op_id = Uuid::new_v4();
        let mut state = ItemState::default();
        apply_op(&mut state, x);
        assert_eq!(apply_op(&mut state, y), StepOutcome::Ignored);
    }

    #[test]
    fn timestamp_never_participates_in_ordering() {
        let mut early = put(3, DEVICE_A, 0);
        early.timestamp = Some(DateTime::from_timestamp(0, 0).unwrap());
        let mut late = put(3, DEVICE_A, 1);
        late.timestamp = Some(DateTime::from_timestamp(999, 0).unwrap());
        late.op_id = Uuid::new_v4();
        let mut state = ItemState::default();
        apply_op(&mut state, early);
        // 同 (lamport, device)：后到者忽略——墙钟新旧不影响
        assert_eq!(apply_op(&mut state, late), StepOutcome::Ignored);
    }

    // ---- apply_batch / item_view ----

    #[test]
    fn batch_is_order_independent() {
        let ops = vec![
            put(1, DEVICE_A, 0),
            put(3, DEVICE_B, 1),
            put(2, DEVICE_A, 2),
        ];
        let mut forward = BTreeMap::new();
        let fwd = apply_batch(&mut forward, ops.clone());
        let mut shuffled = BTreeMap::new();
        let mut reversed = ops.clone();
        reversed.reverse();
        let rev = apply_batch(&mut shuffled, reversed);
        assert_eq!(forward, shuffled);
        // 只有全序最大的一条成为主位；其余是严格旧版本，被正确忽略
        // （历史仍在本地 items 表，LWW 视图只留胜者）
        assert_eq!(fwd.applied, 1);
        assert_eq!(fwd.ignored, 2);
        assert_eq!(fwd.max_lamport, 3);
        assert_eq!(rev.max_lamport, 3);
    }

    #[test]
    fn batch_replay_is_fully_ignored() {
        let ops = vec![put(1, DEVICE_A, 0), put(2, DEVICE_B, 1)];
        let mut items = BTreeMap::new();
        let first = apply_batch(&mut items, ops.clone());
        // lamport 2 为主位，lamport 1 是严格旧版本 → 只 applied 一条
        assert_eq!(first.applied, 1);
        assert_eq!(first.max_lamport, 2);
        let replay = apply_batch(&mut items, ops);
        assert_eq!(
            (replay.applied, replay.conflicts, replay.ignored),
            (0, 0, 2)
        );
    }

    #[test]
    fn batch_conflict_keeps_both_and_reports_clock() {
        let a = put(3, DEVICE_A, 1);
        let b = put(3, DEVICE_B, 2);
        let mut items = BTreeMap::new();
        let report = apply_batch(&mut items, vec![a, b]);
        assert_eq!(report.applied, 1);
        assert_eq!(report.conflicts, 1);
        assert_eq!(report.max_lamport, 3);
        let view = items.get(&ITEM).unwrap();
        assert_eq!(view.primary.as_ref().unwrap().device_id, DEVICE_B);
        assert_eq!(view.conflicts.len(), 1);
    }

    #[test]
    fn item_view_derives_primary_and_conflicts_from_full_log() {
        let mut ops = vec![
            put(1, DEVICE_A, 0),
            put(2, DEVICE_A, 1), // 主位历史
            put(3, DEVICE_B, 2), // 当前主位
            put(3, DEVICE_A, 3), // 与主位真冲突 → 副本
        ];
        // 故意乱序喂
        ops.swap(0, 3);
        let state = item_view(ops);
        assert_eq!(state.primary.as_ref().unwrap().lamport, 3);
        assert_eq!(state.conflicts.len(), 1);
        assert_eq!(state.conflicts[0].lamport, 3);
        assert_eq!(state.conflicts[0].device_id, DEVICE_A);
    }
}
