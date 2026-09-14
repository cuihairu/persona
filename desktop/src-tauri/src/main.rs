// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod approval;
mod commands;
mod error;
#[cfg(test)]
mod test_support;
mod types;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use types::AppState;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_notification::init())
        .manage(AppState {
            service: Arc::new(Mutex::new(None)),
            db_path: Mutex::new(None),
            agent_handle: Mutex::new(None),
            auto_lock_registered: std::sync::atomic::AtomicBool::new(false),
            ssh_approvals: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
            commands::delete_credential,
            commands::get_ssh_agent_status,
            commands::start_ssh_agent,
            commands::stop_ssh_agent,
            commands::ssh_approval_respond,
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
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
