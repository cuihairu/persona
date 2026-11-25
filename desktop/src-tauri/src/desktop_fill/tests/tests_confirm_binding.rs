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

/// Request missing snapshot_id: a confirmation-surface protocol error, reported
/// honestly first
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

/// Hidden means discarded: once the floating window dismisses and clears the
/// slot, in-flight requests carrying a stale id are rejected
#[test]
fn cleared_slot_discards_inflight_confirmation() {
    assert_eq!(
        bind_confirmed_snapshot(None, Some("snap-a")),
        Err(ConfirmBindRejection::TargetDiscarded)
    );
}

/// A confirmed → floating window re-captures B: in-flight requests carrying
/// A's id are rejected; never re-routed to B
#[test]
fn recaptured_target_rejects_stale_confirmation() {
    let a = target("snap-a", 1);
    let b = target("snap-b", 2);
    let rejection = bind_confirmed_snapshot(Some(&b), Some(&a.snapshot_id));
    assert_eq!(rejection, Err(ConfirmBindRejection::TargetChanged));
    // The rejection path returns no injectable target (at the type level it is
    // impossible to misuse B as a return value)
    assert_ne!(b.snapshot_id, a.snapshot_id);
}

/// id matches the current slot: allowed through and bound to the confirmed
/// snapshot
#[test]
fn matching_snapshot_binds_confirmation_to_that_target() {
    let a = target("snap-a", 1);
    let bound = bind_confirmed_snapshot(Some(&a), Some("snap-a")).expect("must bind");
    assert_eq!(bound, a);
    assert_eq!(bound.snapshot_id, "snap-a");
    assert_eq!(bound.hwnd, 1);
}

/// Two snapshots held by the same slot in sequence: only the current
/// snapshot's id is allowed through; the earlier id is rejected
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

/// Command-layer recheck closure factory (`slot_recheck_for`, fourth-round
/// cancellation boundary closure):
/// shares the same semantics as the binding comparison — slot present → allow
/// through; slot cleared → Discarded; newer snapshot → Changed. Called before
/// every field write inside the injection loop.
#[test]
fn slot_recheck_closure_matches_bind_semantics() {
    use std::sync::Mutex;
    let slot: Mutex<Option<FillTarget>> = Mutex::new(Some(target("snap-live", 7)));
    let recheck = super::slot_recheck_for(&slot, "snap-live".to_string());
    recheck().expect("current snapshot must pass the recheck");

    // Slot cleared (floating window dismissed): the next recheck of the
    // in-flight injection must reject
    *slot.lock().unwrap_or_else(|p| p.into_inner()) = None;
    assert_eq!(
        recheck().map(|_| ()),
        Err(ConfirmBindRejection::TargetDiscarded)
    );

    // Re-captured (new snapshot replaces it): the recheck carrying the old id
    // must reject
    *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(target("snap-new", 8));
    assert_eq!(
        recheck().map(|_| ()),
        Err(ConfirmBindRejection::TargetChanged)
    );
}
