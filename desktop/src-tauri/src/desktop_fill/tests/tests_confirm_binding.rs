use super::{bind_confirmed_snapshot, ConfirmBindRejection, FillTarget};

fn target(id: &str, hwnd: isize) -> FillTarget {
    FillTarget {
        hwnd,
        title: format!("login window {id}"),
        pid: 4242,
        window_class: "Notepad".to_string(),
        exe_path: "C:\\Windows\\notepad.exe".to_string(),
        snapshot_id: id.to_string(),
    }
}

/// 请求缺 snapshot_id：确认面协议错误，优先如实报出
#[test]
fn request_without_snapshot_id_is_rejected() {
    let slot = target("snap-a", 1);
    assert_eq!(
        bind_confirmed_snapshot(Some(&slot), None),
        Err(ConfirmBindRejection::SnapshotRequired)
    );
    assert_eq!(
        bind_confirmed_snapshot(None, None),
        Err(ConfirmBindRejection::SnapshotRequired)
    );
}

/// 隐藏即丢弃：浮窗收起清槽后，携旧 id 的在途请求拒绝
#[test]
fn cleared_slot_discards_inflight_confirmation() {
    assert_eq!(
        bind_confirmed_snapshot(None, Some("snap-a")),
        Err(ConfirmBindRejection::TargetDiscarded)
    );
}

/// 确认 A → 浮窗重新捕获 B：携 A 的 id 的在途请求拒绝，绝不转投 B
#[test]
fn recaptured_target_rejects_stale_confirmation() {
    let a = target("snap-a", 1);
    let b = target("snap-b", 2);
    let rejection = bind_confirmed_snapshot(Some(&b), Some(&a.snapshot_id));
    assert_eq!(rejection, Err(ConfirmBindRejection::TargetChanged));
    // 拒绝路径不返回任何可注入目标（类型层面就无法把 B 误当返回值用）
    assert_ne!(b.snapshot_id, a.snapshot_id);
}

/// id 与当前槽位一致：放行并绑定到被确认的那份快照
#[test]
fn matching_snapshot_binds_confirmation_to_that_target() {
    let a = target("snap-a", 1);
    let bound = bind_confirmed_snapshot(Some(&a), Some("snap-a")).expect("must bind");
    assert_eq!(bound, a);
    assert_eq!(bound.snapshot_id, "snap-a");
    assert_eq!(bound.hwnd, 1);
}

/// 同一槽位先后两份快照：只有当前快照的 id 放行，前一份的 id 拒绝
#[test]
fn only_current_snapshot_id_is_accepted() {
    let current = target("snap-b", 2);
    assert_eq!(
        bind_confirmed_snapshot(Some(&current), Some("snap-b")).map(|t| t.snapshot_id),
        Ok("snap-b".to_string())
    );
    assert_eq!(
        bind_confirmed_snapshot(Some(&current), Some("snap-a")),
        Err(ConfirmBindRejection::TargetChanged)
    );
}

/// 命令层重查闭包工厂（`slot_recheck_for`，第四轮取消边界收口）：
/// 与绑定比较共用同一语义——槽位在 → 放行；清槽 → Discarded；
/// 换新快照 → Changed。注入循环内每个字段写入前调用它。
#[test]
fn slot_recheck_closure_matches_bind_semantics() {
    use std::sync::Mutex;
    let slot: Mutex<Option<FillTarget>> = Mutex::new(Some(target("snap-live", 7)));
    let recheck = super::slot_recheck_for(&slot, "snap-live".to_string());
    recheck().expect("current snapshot must pass the recheck");

    // 清槽（浮窗收起）：在途注入的下一次重查必须拒绝
    *slot.lock().unwrap_or_else(|p| p.into_inner()) = None;
    assert_eq!(
        recheck().map(|_| ()),
        Err(ConfirmBindRejection::TargetDiscarded)
    );

    // 重新捕获（换新快照）：携旧 id 的重查必须拒绝
    *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(target("snap-new", 8));
    assert_eq!(
        recheck().map(|_| ()),
        Err(ConfirmBindRejection::TargetChanged)
    );
}
