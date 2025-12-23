// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod types;

use types::AppState;
use tokio::sync::Mutex;

fn main() {
    tauri::Builder::default()
        .manage(AppState {
            service: Mutex::new(None),
            db_path: Mutex::new(None),
            agent_handle: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            commands::init_service,
            commands::lock_service,
            commands::is_service_unlocked,
            commands::create_identity,
            commands::get_identities,
            commands::get_identity,
            commands::create_credential,
            commands::get_credentials_for_identity,
            commands::get_credential_data,
            commands::search_credentials,
            commands::generate_password,
            commands::get_statistics,
            commands::toggle_credential_favorite,
            commands::delete_credential,
            commands::get_ssh_agent_status,
            commands::start_ssh_agent,
            commands::stop_ssh_agent,
            commands::get_ssh_keys,
            commands::wallet_list,
            commands::wallet_list_addresses,
            commands::wallet_generate,
            commands::wallet_import,
            commands::wallet_add_address,
            commands::wallet_export,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
