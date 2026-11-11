//! Windows 真会话集成测试：靶窗是真实 Win32 窗口（同一桌面会话），
//! 跑的是"捕获 → 枚举 → 分类 → 逐控件重验证 → 注入 → 读回"整条真链，
//! 不是 mock。

use super::classify_fields;
use super::win::test_window::TestTargetWindow;
use super::win::{enumerate_edit_fields, read_field_text, revalidate_field, validate_target};
use super::{execute_fill, FillError, FillTarget};

/// 用户名/密码框识别 + execute_fill 全链（指纹验证 → 枚举 → 分类 →
/// 逐控件重验证 → WM_SETTEXT）注入 + WM_GETTEXT 读回一致。
/// 这是桌面填充的真机验收核心断言（openclaw Windows Server 2022 跑）。
#[test]
fn settext_injection_roundtrip_on_real_window() {
    let target =
        TestTargetWindow::create("persona fill test - login", true).expect("create target");
    let fields = enumerate_edit_fields(target.top);
    assert_eq!(fields.len(), 2, "two EDIT controls expected");
    assert_eq!(fields[0].hwnd, target.username);
    assert!(!fields[0].is_password);
    assert_eq!(fields[1].hwnd, target.password);
    assert!(fields[1].is_password);

    let classified = classify_fields(&fields).expect("classify");
    assert_eq!(classified.username_hwnd, Some(target.username));
    assert_eq!(classified.password_hwnd, target.password);

    // 全链注入：self_pid 伪造成别的进程（快照 pid 是真实测试进程 pid）
    let snapshot = target.snapshot("persona fill test - login");
    let fake_self_pid = std::process::id().wrapping_add(1).max(1);
    let (user_filled, pwd_filled, title) = execute_fill(
        &snapshot,
        "alice@example.com",
        "s3cret-Пароль⚡",
        fake_self_pid,
        &|| Ok(()),
    )
    .expect("execute_fill");
    assert!(user_filled && pwd_filled);
    assert_eq!(title, "persona fill test - login");
    assert_eq!(read_field_text(target.username), "alice@example.com");
    assert_eq!(read_field_text(target.password), "s3cret-Пароль⚡");
    target.destroy();
}

/// 取消边界（第四轮收口）：**清槽落在第一字段写入之后**。重查闭包按
/// 调用序计数：第 1 次（username 写入前）放行；第 2 次（password 写入
/// 前）先断言 username 已真实落值（证明清槽钩子确实落在第一字段写入
/// 之后），再清槽并让重查拒绝。注入必须中止剩余写入并以
/// [`FillError::Aborted`] 如实报部分完成（username=true、password=false），
/// 密码框零残留。
#[test]
fn slot_cleared_after_first_write_aborts_remaining_write() {
    use std::sync::Mutex;
    let target =
        TestTargetWindow::create("persona fill test - cancel clear", true).expect("create");
    let snapshot = target.snapshot("persona fill test - cancel clear");
    let slot: Mutex<Option<FillTarget>> = Mutex::new(Some(snapshot.clone()));
    let inner = super::slot_recheck_for(&slot, snapshot.snapshot_id.clone());
    let call = std::cell::Cell::new(0usize);
    let username_hwnd = target.username;
    let recheck = || {
        let n = call.get() + 1;
        call.set(n);
        if n == 2 {
            // 此刻第一字段写入已完成——清槽钩子落在第一字段写入之后
            assert_eq!(
                read_field_text(username_hwnd),
                "alice@example.com",
                "clear hook must fire after the first field write landed"
            );
            *slot.lock().unwrap_or_else(|p| p.into_inner()) = None;
        }
        inner()
    };
    let fake_self_pid = std::process::id().wrapping_add(1).max(1);
    let result = execute_fill(
        &snapshot,
        "alice@example.com",
        "s3cret-Пароль⚡",
        fake_self_pid,
        &recheck,
    );
    match result {
        Err(FillError::Aborted {
            reason: super::ConfirmBindRejection::TargetDiscarded,
            username_filled: true,
            password_filled: false,
            ..
        }) => {}
        other => panic!("mid-fill clear must abort with partial completion, got {other:?}"),
    }
    assert_eq!(
        read_field_text(target.password),
        "",
        "password write must be aborted (no residue after the clear)"
    );
    target.destroy();
}

/// 取消边界（第四轮收口）：**槽位在第一字段写入后被新一轮捕获替换**
///（确认 A 后浮窗捕获了 B）。与清槽用例同一时序控制：第 2 次重查时槽
/// 位已换成新 id，注入必须以 `TargetChanged` 中止剩余写入，密码不落。
#[test]
fn slot_replaced_after_first_write_aborts_remaining_write() {
    use std::sync::Mutex;
    let target = TestTargetWindow::create("persona fill test - cancel swap", true).expect("create");
    let snapshot = target.snapshot("persona fill test - cancel swap");
    let slot: Mutex<Option<FillTarget>> = Mutex::new(Some(snapshot.clone()));
    let inner = super::slot_recheck_for(&slot, snapshot.snapshot_id.clone());
    let call = std::cell::Cell::new(0usize);
    let username_hwnd = target.username;
    let recheck = || {
        let n = call.get() + 1;
        call.set(n);
        if n == 2 {
            assert_eq!(
                read_field_text(username_hwnd),
                "alice@example.com",
                "swap hook must fire after the first field write landed"
            );
            // 模拟重新捕获：槽位换成新快照（不同 id）
            let mut replacement = snapshot.clone();
            replacement.snapshot_id = "re-captured-target-B".to_string();
            *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(replacement);
        }
        inner()
    };
    let fake_self_pid = std::process::id().wrapping_add(1).max(1);
    let result = execute_fill(
        &snapshot,
        "alice@example.com",
        "s3cret-Пароль⚡",
        fake_self_pid,
        &recheck,
    );
    match result {
        Err(FillError::Aborted {
            reason: super::ConfirmBindRejection::TargetChanged,
            username_filled: true,
            password_filled: false,
            ..
        }) => {}
        other => {
            panic!("mid-fill target swap must abort with partial completion, got {other:?}")
        }
    }
    assert_eq!(
        read_field_text(target.password),
        "",
        "password must never land in the re-captured target"
    );
    target.destroy();
}

/// 无任何 ES_PASSWORD 框 → 拒绝注入（历史"第二个框"启发式已移除：
/// 普通框可能是攻击者伪装的明文收集器）。
#[test]
fn plain_only_window_is_rejected_no_password_guessing() {
    let target = TestTargetWindow::create("persona fill test - plain", false).expect("create");
    let fields = enumerate_edit_fields(target.top);
    assert_eq!(fields.len(), 2);
    assert!(fields.iter().all(|f| !f.is_password));
    assert!(
        classify_fields(&fields).is_none(),
        "no ES_PASSWORD field must reject classification"
    );
    let snapshot = target.snapshot("persona fill test - plain");
    let fake_self_pid = std::process::id().wrapping_add(1).max(1);
    let err = execute_fill(&snapshot, "alice", "s3cret", fake_self_pid, &|| Ok(()))
        .expect_err("plain-only window must be rejected");
    let FillError::Rejected(err) = err else {
        panic!("expected Rejected, got {err:?}");
    };
    assert!(
        err.contains("ES_PASSWORD"),
        "error must mention ES_PASSWORD: {err}"
    );
    // 两个普通框都必须原样为空（没写进去任何东西）
    assert_eq!(read_field_text(target.username), "");
    assert_eq!(read_field_text(target.password), "");
    target.destroy();
}

/// 分类守卫（纯函数）：不可见/禁用/只读的密码框不合格；只有不可见
/// 密码框时整体拒绝。
#[test]
fn classification_guards_ineligible_fields() {
    use super::FieldState as F;
    // 只读密码框：不合格 → 无合格密码框 → 拒绝
    let ro = vec![F {
        hwnd: 1,
        is_password: true,
        visible: true,
        enabled: true,
        read_only: true,
    }];
    assert!(classify_fields(&ro).is_none());
    // 隐藏密码框：拒绝
    let hidden = vec![F {
        hwnd: 2,
        is_password: true,
        visible: false,
        enabled: true,
        read_only: false,
    }];
    assert!(classify_fields(&hidden).is_none());
    // 禁用密码框：拒绝
    let disabled = vec![F {
        hwnd: 3,
        is_password: true,
        visible: true,
        enabled: false,
        read_only: false,
    }];
    assert!(classify_fields(&disabled).is_none());
    // 隐藏密码框 + 可见用户名框：仍然拒绝（不能只填用户名进可疑窗口）
    let mixed = vec![
        F {
            hwnd: 4,
            is_password: false,
            visible: true,
            enabled: true,
            read_only: false,
        },
        F {
            hwnd: 5,
            is_password: true,
            visible: false,
            enabled: true,
            read_only: false,
        },
    ];
    assert!(classify_fields(&mixed).is_none());
    // 合格密码框 + 隐藏用户名框：填密码，用户名如实报未填
    let pwd_only = vec![
        F {
            hwnd: 6,
            is_password: false,
            visible: false,
            enabled: true,
            read_only: false,
        },
        F {
            hwnd: 7,
            is_password: true,
            visible: true,
            enabled: true,
            read_only: false,
        },
    ];
    let c = classify_fields(&pwd_only).unwrap();
    assert_eq!(c.username_hwnd, None);
    assert_eq!(c.password_hwnd, 7);
    // 空目标
    assert!(classify_fields(&[]).is_none());
}

/// 逐控件写入前重验证：死句柄拒绝、只读/禁用/隐藏拒绝、密码框丢失
/// ES_PASSWORD 样式拒绝（hwnd 复用字段角色对调的场景）。
#[test]
fn revalidate_field_rejects_gone_and_role_swapped_fields() {
    let target = TestTargetWindow::create("persona fill test - revalidate", true).expect("create");
    let mut pid = 0u32;
    unsafe {
        GetWindowThreadProcessId(
            windows::Win32::Foundation::HWND(target.top as *mut _),
            Some(&mut pid),
        );
    }
    // 好路径
    revalidate_field(target.password, target.top, pid, true).expect("eligible password field");
    revalidate_field(target.username, target.top, pid, false).expect("eligible username field");
    // 死句柄
    assert!(revalidate_field(0xDEAD_BEEFisize, target.top, pid, true).is_err());
    target.destroy();
    // 销毁后全部拒绝
    assert!(revalidate_field(target.password, target.top, pid, true).is_err());
    assert!(revalidate_field(target.username, target.top, pid, false).is_err());
}

/// 目标重验证（真 hwnd 走 validate_snapshot）：pid 不符拒绝、标题前缀
/// 不符拒绝、空标题不再恒真、死句柄拒绝、销毁后拒绝；validate_target
/// 对本进程窗口（pid == self_pid）恒拒绝。
#[test]
fn target_validation_guards_hwnd_reuse() {
    use super::win::validate_snapshot;
    let fake_other_pid = std::process::id().wrapping_add(1).max(1);
    let target =
        TestTargetWindow::create("persona fill test - validate", true).expect("create target");

    let real_pid = {
        let mut pid = 0u32;
        unsafe {
            GetWindowThreadProcessId(
                windows::Win32::Foundation::HWND(target.top as *mut _),
                Some(&mut pid),
            );
        }
        pid
    };
    let class = super::win::window_class_name(target.top);
    let exe = super::win::process_image_path(real_pid);
    assert!(
        !class.is_empty() && !exe.is_empty(),
        "fingerprint helpers must work in-test"
    );

    // 指纹全对（self_pid 伪造成别的进程）→ 放行
    assert!(
        validate_snapshot(
            target.top,
            "persona fill test - validate",
            real_pid,
            &class,
            &exe,
            fake_other_pid
        ),
        "matching snapshot must pass"
    );

    // 标题前缀不一致 → 拒绝（模拟 hwnd 复用到别的窗口）
    assert!(
        !validate_snapshot(
            target.top,
            "totally different window",
            real_pid,
            &class,
            &exe,
            fake_other_pid
        ),
        "stale title must be rejected"
    );

    // 空快照标题 + 非空当前标题 → 拒绝（堵 starts_with("") 恒真的洞）
    assert!(
        !validate_snapshot(target.top, "", real_pid, &class, &exe, fake_other_pid),
        "empty snapshot title must not match a titled window"
    );

    // 快照 pid 乱填（=0）与真实 pid 不符 → 拒绝
    assert!(
        !validate_snapshot(
            target.top,
            "persona fill test - validate",
            0,
            &class,
            &exe,
            fake_other_pid
        ),
        "mismatched pid must be rejected"
    );

    // 类名不符 → 拒绝
    assert!(
        !validate_snapshot(
            target.top,
            "persona fill test - validate",
            real_pid,
            "OtherClass",
            &exe,
            fake_other_pid
        ),
        "mismatched class must be rejected"
    );

    // 可执行文件路径不符 → 拒绝（同标题同 pid 的伪装进程场景）
    assert!(
        !validate_snapshot(
            target.top,
            "persona fill test - validate",
            real_pid,
            &class,
            "C:\\attacker.exe",
            fake_other_pid
        ),
        "mismatched exe path must be rejected"
    );

    // 死句柄 → 拒绝
    assert!(!validate_snapshot(
        0xDEAD_BEEFisize,
        "",
        real_pid,
        &class,
        &exe,
        fake_other_pid
    ));

    // validate_target 层：本进程窗口（pid == self_pid）恒拒绝
    let own = FillTarget {
        hwnd: target.top,
        title: "persona fill test - validate".to_string(),
        pid: real_pid,
        window_class: class.clone(),
        exe_path: exe.clone(),
        snapshot_id: "test-own-window-snapshot".to_string(),
    };
    assert!(
        !validate_target(&own, real_pid),
        "own-process window must be rejected"
    );

    target.destroy();
    assert!(
        !validate_snapshot(
            target.top,
            "persona fill test - validate",
            real_pid,
            &class,
            &exe,
            fake_other_pid
        ),
        "destroyed window must be rejected"
    );
}

/// 剪贴板备份/恢复闭环：粘贴期间密文在场、结束后原内容恢复；
/// 闭包 panic 不绕过恢复。
#[test]
fn clipboard_backup_restore_roundtrip() {
    let _guard = clipboard_test_lock();
    use super::win::{seed_clipboard, with_clipboard_paste};
    // 预置"原有内容"（直接写，不走备份/恢复语义）。值带每次运行的
    // 唯一后缀：机器的 RDP/剪贴板同步链路（rdpclip 等）可能把**上一
    // 轮**运行写过的固定字面量在剪贴板被清空后回灌（run4-red 实测
    // 复现）——固定值会跟陈旧内容撞车，唯一值让回灌内容必然对不上。
    let prev = format!("PREV-{}", uuid::Uuid::new_v4());
    seed_clipboard(&prev).expect("seed clipboard");
    assert_eq!(read_clipboard_text(), prev);

    // 粘贴假密文：断言闭包期间读到的是密文、结束后恢复 prev
    let seen = std::cell::RefCell::new(String::new());
    let (_, warn) = with_clipboard_paste("TOP-SECRET", || {
        *seen.borrow_mut() = read_clipboard_text();
    })
    .expect("paste roundtrip");
    assert_eq!(
        seen.borrow().as_str(),
        "TOP-SECRET",
        "secret must be on clipboard during paste"
    );
    assert_eq!(
        read_clipboard_text(),
        prev,
        "previous content must be restored"
    );
    assert!(warn.is_none(), "restore should not warn: {warn:?}");

    // 无原有内容时：结束后密文被清掉（写空串），不残留。断空必须
    // **读一次**：retry-until-non-empty 的旧读法会给外部剪贴板同步
    // 进程留出整整 1 秒把陈旧内容灌回来（见上），把"读不到"放大成
    // "读到垃圾"。
    seed_clipboard("").expect("clear clipboard");
    let (_, _) = with_clipboard_paste("GHOST", || ()).expect("paste roundtrip 2");
    assert_eq!(
        read_clipboard_text_expect_maybe_empty(),
        "",
        "no prior content must leave no residue"
    );

    // 闭包 panic：恢复仍要发生，panic 在恢复之后传播
    let prev_panic = format!("PREV-PANIC-{}", uuid::Uuid::new_v4());
    seed_clipboard(&prev_panic).expect("seed clipboard 2");
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = with_clipboard_paste("PANIC-SECRET", || panic!("boom in paste closure"));
    }));
    assert!(
        panicked.is_err(),
        "closure panic must propagate after restore"
    );
    assert_eq!(
        read_clipboard_text(),
        prev_panic,
        "panic must not bypass clipboard restore"
    );
}

/// 原剪贴板是非文本内容（文件/位图/自定义格式）时：恢复不了原文、
/// 结束覆写为空串——必须返回告警，不许静默销毁用户剪贴板。
#[test]
fn clipboard_paste_warns_when_non_text_content_is_cleared() {
    let _guard = clipboard_test_lock();
    use super::win::{seed_clipboard_non_text, with_clipboard_paste};
    seed_clipboard_non_text().expect("seed non-text clipboard");

    let ((_, warn), logged) =
        capture_warns(|| with_clipboard_paste("GHOST-SECRET", || ()).unwrap());
    let warn = warn.expect("wiping non-text clipboard content must surface a warning");
    assert!(
        warn.to_lowercase().contains("non-text"),
        "warning must explain the non-text wipe: {warn}"
    );
    // tracing::warn 必须真实落日志（不只返回值）
    assert!(
        logged
            .iter()
            .any(|w| w.contains("previous non-text clipboard content")),
        "non-text wipe must be logged via tracing::warn: {logged:?}"
    );
    // 密文不残留（覆写为空串），并顺手把剪贴板清回空态。期望空的
    // 读必须用 expect_maybe_empty：retry-until-non-empty 会给 rdpclip
    // 等外部同步进程留出把上一条用例的 PREV-* 灌回来的窗口
    // （openclaw 实测：本断言读到 roundtrip 用例的 PREV-PANIC 值）。
    assert_eq!(
        read_clipboard_text_expect_maybe_empty(),
        "",
        "no prior content must leave no residue"
    );
    super::win::seed_clipboard("").ok();
}

/// 覆写失败（set 失败）分支：恢复路径的告警不能被吞——Err 原样上抛，
/// 同时 `tracing::warn!("...swallowed by paste failure...")` 必须落日志。
/// 注入失败的写入函数确定性触发（不必与真实剪贴板时序赛跑）。
#[test]
fn clipboard_paste_warns_when_restore_warning_is_swallowed_by_paste_failure() {
    let _guard = clipboard_test_lock();
    use super::win::with_clipboard_paste_with_writer;
    let (_, warns) = capture_warns(|| {
        let err = with_clipboard_paste_with_writer(
            "TOP-SECRET",
            || panic!("paste closure must never run when the overwrite failed"),
            |_| Err("injected clipboard writer failure".to_string()),
        )
        .expect_err("injected writer failure must surface as Err");
        assert!(
            err.contains("injected clipboard writer failure"),
            "Err must carry the overwrite failure: {err}"
        );
    });
    assert!(
        warns.iter().any(|w| {
            w.contains("swallowed by paste failure")
                && w.contains("injected clipboard writer failure")
        }),
        "swallowed restore warning must be logged via tracing::warn: {warns:?}"
    );
}

/// 闭包 panic 分支：恢复完成后 `tracing::warn!("...on panic path...")`
/// 必须落日志，panic 在恢复之后原样重抛。注入的写入函数**只让恢复
/// 失败**（第一次调用=明文覆写成功，之后=写回备份失败），确定性覆盖
/// 「panic + 恢复失败」的组合分支——若覆写就失败，闭包根本不会执行，
/// panic 分支无从触发（openclaw 实测：全 Err 写入函数让本用例恒红）。
#[test]
fn clipboard_paste_warns_on_panic_path_when_restore_fails() {
    let _guard = clipboard_test_lock();
    use super::win::with_clipboard_paste_with_writer;
    // 第 1 次写（明文覆写）成功，第 2 次写（恢复备份）起确定性失败
    let calls = std::cell::Cell::new(0usize);
    let (_, warns) = capture_warns(|| {
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = with_clipboard_paste_with_writer(
                "PANIC-SECRET",
                || panic!("boom in paste closure"),
                |_| {
                    let n = calls.get();
                    calls.set(n + 1);
                    if n == 0 {
                        Ok(())
                    } else {
                        Err("injected clipboard writer failure".to_string())
                    }
                },
            );
        }));
        assert!(
            panicked.is_err(),
            "closure panic must propagate after restore"
        );
    });
    assert!(
        warns.iter().any(|w| {
            w.contains("on panic path") && w.contains("injected clipboard writer failure")
        }),
        "panic-path restore warning must be logged via tracing::warn: {warns:?}"
    );
    // 恢复是注入失败的：明文 PANIC-SECRET 还留在真剪贴板上——测试
    // 自己清掉，别把它留给后面用例或外部剪贴板同步进程。
    super::win::seed_clipboard("").ok();
}

/// tracing 告警捕获（thread-local dispatcher，测试体内落 warn）：
/// 返回 (测试体返回值, 捕获到的 warn 文案)——断言各失败分支的
/// `tracing::warn!` 真实输出，不只看返回值。
fn capture_warns<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
    use std::sync::{Arc, Mutex};
    struct WarnCapture(Arc<Mutex<Vec<String>>>);
    struct MessageVisitor(String);
    impl tracing::field::Visit for MessageVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{value:?}");
            }
        }
    }
    impl tracing::Subscriber for WarnCapture {
        fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
            meta.level() == &tracing::Level::WARN
        }
        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::Id, _follows: &tracing::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = MessageVisitor(String::new());
            event.record(&mut visitor);
            self.0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(visitor.0);
        }
        fn enter(&self, _span: &tracing::Id) {}
        fn exit(&self, _span: &tracing::Id) {}
    }
    let capture = Arc::new(WarnCapture(Arc::new(Mutex::new(Vec::new()))));
    let sink = capture.0.clone();
    let out = tracing::subscriber::with_default(capture, f);
    let warns = sink.lock().unwrap_or_else(|p| p.into_inner()).clone();
    (out, warns)
}

/// 剪贴板是进程全局的：同二进制内多个剪贴板用例并行会互相踩——
/// 用进程内互斥串行化（Linux 侧不编译本模块，无此依赖）。
fn clipboard_test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::Mutex;
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|p| p.into_inner())
}

/// 本机常有剪贴板监听进程短暂持有剪贴板（OpenClipboard 瞬时失败时
/// `read_clipboard_text_once` 静默返回空串）；读回断言先小间隔重试，
/// 把瞬时竞争与真实空剪贴板区分开（重试耗尽仍为空按空处理）。
/// **只用于期望非空的断言**——期望为空的断言用
/// [`read_clipboard_text_expect_maybe_empty`]，retry-until-non-empty
/// 会给外部剪贴板同步进程留时间灌回陈旧内容。
fn read_clipboard_text() -> String {
    for _ in 0..20 {
        let text = read_clipboard_text_once();
        if !text.is_empty() {
            return text;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    String::new()
}

/// 期望为空的读回：只在 OpenClipboard 失败（监听进程短暂持锁）时
/// 重试，剪贴板一旦打开立即按当时内容返回——不给外部同步进程留
/// 灌回陈旧内容的窗口。
fn read_clipboard_text_expect_maybe_empty() -> String {
    for _ in 0..20 {
        match read_clipboard_text_once_state() {
            ReadOutcome::Opened(text) => return text,
            ReadOutcome::OpenFailed => {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
    String::new()
}

enum ReadOutcome {
    Opened(String),
    OpenFailed,
}

fn read_clipboard_text_once() -> String {
    match read_clipboard_text_once_state() {
        ReadOutcome::Opened(text) => text,
        ReadOutcome::OpenFailed => String::new(),
    }
}

fn read_clipboard_text_once_state() -> ReadOutcome {
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
    use windows::Win32::System::Ole::CF_UNICODETEXT;
    unsafe {
        if OpenClipboard(None).is_err() {
            return ReadOutcome::OpenFailed;
        }
        let out: Option<String> = (|| {
            let h = GetClipboardData(CF_UNICODETEXT.0 as u32).ok()?;
            if h.is_invalid() {
                return None;
            }
            let gh = windows::Win32::Foundation::HGLOBAL(h.0);
            let ptr = GlobalLock(gh);
            if ptr.is_null() {
                return None;
            }
            let scan_limit = ((GlobalSize(gh) / 2) as usize).min(1 << 20);
            let wide = std::slice::from_raw_parts(ptr as *const u16, scan_limit);
            let mut n = 0usize;
            while n < wide.len() && wide[n] != 0 {
                n += 1;
            }
            let text = String::from_utf16_lossy(&wide[..n]);
            let _ = GlobalUnlock(gh);
            Some(text)
        })();
        let _ = CloseClipboard();
        ReadOutcome::Opened(out.unwrap_or_default())
    }
}

use windows::Win32::UI::WindowsAndMessaging::GetWindowThreadProcessId;
