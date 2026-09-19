//! Persona 桌面端库入口。
//!
//! 应用装配（Builder 链、托盘）放在这里，`main.rs` 只留薄入口。passkey
//! 审批服务端由 init_service 按 workspace 开关门禁启动（见
//! `commands::maybe_start_passkey_server`）。lib 化让集成测试可以经 `tests/` 独立进程直驱带 mock runtime 的
//! `AppHandle`（mock runtime 会毒化所在进程的 tokio socket IO 探测，见
//! `passkey_bridge::tests` 中 FakeSink 的注释）——bin 单进程时代这些路径
//! 只能用 FakeSink 绕过。

pub mod approval;
#[cfg(test)]
mod command_layer_tests;
pub mod commands;
mod error;
pub mod passkey_bridge;
#[cfg(test)]
mod test_support;
pub mod types;

use std::collections::HashMap;
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;
use tokio::sync::Mutex;
use types::AppState;

/// 显示主窗口（托盘左键 / Open 菜单共用）
pub fn show_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// 当前会话有无显示服务器（托盘/menu 的 muda 后端在无 display 时 panic）。
#[cfg(target_os = "linux")]
fn display_session_available() -> bool {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

#[cfg(not(target_os = "linux"))]
fn display_session_available() -> bool {
    true
}

/// 构建系统托盘与菜单（需显示会话；关窗驻留时的常驻入口）。
fn setup_tray<R: tauri::Runtime>(app: &tauri::App<R>) -> Result<(), Box<dyn std::error::Error>> {
    let open_item = MenuItem::with_id(app, "open", "Open Persona", true, None::<&str>)?;
    let lock_item = MenuItem::with_id(app, "lock", "Lock", true, None::<&str>)?;
    let quit_item = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let tray_menu = Menu::with_items(app, &[&open_item, &lock_item, &quit_item])?;

    TrayIconBuilder::with_id("persona-tray")
        .icon(
            // 打包缺 icon 时回退编译期内嵌图标（dev/测试无 bundle icon）
            app.default_window_icon()
                .cloned()
                .unwrap_or_else(|| tauri::include_image!("icons/32x32.png")),
        )
        .tooltip("Persona")
        .menu(&tray_menu)
        .show_menu_on_left_click(false)
        .on_tray_icon_event(|tray, event| {
            // 左键点击 = 唤出主窗口（菜单留在右键）
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main_window(app),
            "lock" => {
                // 走事件链（Locked → persona://auto-lock → 前端回解锁屏），
                // 再兜底清内存主密钥（与回调同一动作，幂等）
                let service = app.state::<AppState>().service.clone();
                tauri::async_runtime::spawn(async move {
                    let mut guard = service.lock().await;
                    if let Some(service) = guard.as_mut() {
                        let _ = service.force_lock_session().await;
                        service.lock();
                    }
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

/// 组装应用（托盘、passkey 审批服务端、全部命令注册）。
///
/// context 参数化：生产 [`run`] 传 `generate_context!`，集成测试传
/// `tauri::test::mock_context(noop_assets())` 整链跑 setup。
pub fn build<R: tauri::Runtime>(context: tauri::Context<R>) -> tauri::App<R> {
    tauri::Builder::<R>::new()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState {
            service: Arc::new(Mutex::new(None)),
            db_path: Mutex::new(None),
            agent_handle: Mutex::new(None),
            auto_lock_registered: std::sync::atomic::AtomicBool::new(false),
            passkey_server_started: std::sync::atomic::AtomicBool::new(false),
            ssh_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
            passkey_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
            sync_emitter: Mutex::new(None),
        })
        .setup(|app| {
            // 系统托盘：关窗后审批弹窗仍可送达，托盘是常驻入口。
            // 无显示会话（CI/容器/ssh-only）下 muda 菜单会直接 panic，
            // 跳过托盘降级运行 —— 审批链路不依赖托盘存活。
            if display_session_available() {
                setup_tray(app)?;
            } else {
                tracing::info!("no display session; running headless without tray");
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // 关闭主窗口 = 隐藏到托盘（passkey/SSH 审批照常工作）；托盘 Quit 才退出
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::init_service,
            commands::lock_service,
            commands::is_service_unlocked,
            commands::create_identity,
            commands::get_identities,
            commands::get_identity,
            commands::get_active_identity,
            commands::set_active_identity,
            commands::clear_active_identity,
            commands::get_workspace_settings,
            commands::set_feature_flags,
            commands::set_sync_config,
            commands::update_identity,
            commands::delete_identity,
            commands::create_credential,
            commands::get_credentials_for_identity,
            commands::get_credential_data,
            commands::get_totp_code,
            commands::search_credentials,
            commands::generate_password,
            commands::get_statistics,
            commands::toggle_credential_favorite,
            commands::fetch_credential_favicon,
            commands::get_favicons,
            commands::delete_credential,
            commands::get_ssh_agent_status,
            commands::start_ssh_agent,
            commands::stop_ssh_agent,
            commands::ssh_approval_respond,
            commands::passkey_approval_respond,
            commands::get_ssh_keys,
            commands::wallet_list,
            commands::wallet_list_addresses,
            commands::wallet_generate,
            commands::wallet_import,
            commands::wallet_add_address,
            commands::wallet_delete,
            commands::wallet_export,
            commands::wallet_create_transaction,
            commands::wallet_pending_transactions,
            commands::wallet_sign_transaction,
            commands::configure_auto_lock,
            commands::get_auto_lock_status,
            commands::touch_activity,
            commands::start_auto_lock_monitoring,
            commands::stop_auto_lock_monitoring,
            commands::audit_query,
            commands::audit_statistics,
            commands::audit_cleanup,
            commands::health_scan,
            commands::passkey_list,
            commands::passkey_list_by_rp,
            commands::passkey_get,
            commands::passkey_delete,
            commands::passkey_create,
            commands::passkey_self_test,
            commands::passkey_export_private_key,
            commands::export_identity,
            commands::reveal_credential_secret,
            commands::reauth_verify,
        ])
        .build(context)
        .expect("error while building tauri application")
}

/// 组装并运行应用（进程入口调用；事件循环不退出直至 Quit）。
pub fn run() {
    let app = build::<tauri::Wry>(tauri::generate_context!());
    app.run(|app_handle, event| {
        // RunEvent::Exit 是进程退出前的最后回调（托盘 Quit → app.exit(0)
        // 唯一退出路径在 ExitRequested 之后到达这里）；主线程仍存活，
        // block_on 尽力 flush 同步上报器队列（与 CLI 尾部 stop 同语义）。
        if let tauri::RunEvent::Exit = event {
            tauri::async_runtime::block_on(async {
                let emitter = app_handle
                    .state::<AppState>()
                    .sync_emitter
                    .lock()
                    .await
                    .take();
                if let Some(emitter) = emitter {
                    emitter.stop().await;
                }
            });
        }
    });
}

#[cfg(test)]
mod tests {
    /// mock_app 的 mock runtime 与测试 tokio reactor 的共存性探针：
    /// 若 sqlx 在 mock_app 之后挂起，这里会先于所有命令级测试失败，
    /// 给出明确根因（参见 passkey_bridge.rs 中 FakeSink 的注释）。
    #[tokio::test]
    async fn sqlite_works_after_mock_app_creation() {
        let _app = tauri::test::mock_app();

        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("smoke.db");
        let db = persona_core::storage::Database::from_file(db_path.to_str().unwrap())
            .await
            .unwrap();

        let migrated = tokio::time::timeout(std::time::Duration::from_secs(20), db.migrate())
            .await
            .expect("sqlx never completed under mock_app — reactor poisoned");
        migrated.unwrap();

        // 一条真实查询 + 一条真实写入，确认 reactor 干扰不限于 migrate。
        use persona_core::storage::Repository;
        let repo = persona_core::storage::IdentityRepository::new(db);
        let identity = persona_core::models::Identity::new(
            "Smoke".to_string(),
            persona_core::models::IdentityType::Personal,
        );
        let created = repo.create(&identity).await.unwrap();
        let fetched = repo.find_by_id(&created.id).await.unwrap();
        assert!(fetched.is_some());
    }
}
