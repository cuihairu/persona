use super::*;
use data_encoding::BASE32_NOPAD;
use persona_core::crypto::totp::{decode_base32_secret, hotp};
use persona_core::storage::IdentityRepository;
use persona_core::Database;
use persona_core::Repository;
use proptest::string::string_regex;
use proptest::{collection, prelude::*, sample::select};
use tempfile::TempDir;
use url::form_urlencoded;

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn label_strategy() -> impl Strategy<Value = String> {
    string_regex("[A-Za-z0-9._-]{1,20}").unwrap()
}

fn base32_secret_strategy() -> impl Strategy<Value = String> {
    collection::vec(0usize..BASE32_ALPHABET.len(), 16..=40).prop_map(|indices| {
        indices
            .into_iter()
            .map(|i| BASE32_ALPHABET[i] as char)
            .collect::<String>()
    })
}

fn encode_component(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn config_for(dir: &TempDir) -> crate::config::CliConfig {
    let mut config = crate::config::CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    config
}

/// Serializes env mutations against the bridge and service tests.
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn lock_process_env() -> (
    std::sync::MutexGuard<'static, ()>,
    std::sync::MutexGuard<'static, ()>,
) {
    // Recover from a poisoned lock: a panicking sibling test must not
    // cascade into every other env-gated test.
    fn lock_or_recover(lock: &std::sync::Mutex<()>) -> std::sync::MutexGuard<'_, ()> {
        lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    (
        lock_or_recover(&crate::commands::bridge::tests::ENV_LOCK),
        lock_or_recover(&ENV_LOCK),
    )
}

async fn service_db(config: &crate::config::CliConfig) -> Database {
    Database::from_file(config.get_database_path())
        .await
        .unwrap()
}

mod dispatch;
mod parse;
mod setup;
mod steam;
