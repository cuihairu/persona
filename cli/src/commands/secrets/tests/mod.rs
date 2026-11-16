// -----------------------------------------------------------------------
// 测试：ScriptedUi 缝 + env 串行（connect.rs 同款 fixture）
// -----------------------------------------------------------------------

use super::fields::{data_fields_of, extract_data_field, primary_secret_field};
use super::refs::{parse_env_assignments, parse_kv_pairs, valid_key};
use super::render::{resolve_external_map, K8sObjectMeta, K8sSecretManifest};
use super::run::spawn_with_env;
use super::*;
use crate::utils::prompt::scripted::ScriptedUi;
use base64::Engine;
use persona_core::models::credential::CredentialData;
use persona_core::models::{
    ApiKeyData, BankCardData, CredentialType, CryptoWalletData, IdentityType,
    PasswordCredentialData, SecureNoteData, SecurityLevel, ServerConfigData, SoftwareLicenseData,
    SshKeyData, TwoFactorData,
};
use persona_core::storage::Database;
use persona_core::Repository;
use std::collections::BTreeMap;

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    crate::commands::bridge::tests::ENV_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

struct EnvVar(&'static str);

impl EnvVar {
    fn set(name: &'static str, value: &str) -> Self {
        std::env::set_var(name, value);
        Self(name)
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        std::env::remove_var(self.0);
    }
}

fn config_for(dir: &tempfile::TempDir) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    config
}

/// 建带 master 用户的库：work 身份下 password/api_key/totp/ssh/note
/// 五种凭据，覆盖元数据字段与各类型字段词汇。
async fn seeded_workspace() -> (tempfile::TempDir, CliConfig) {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(&dir);
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    persona_core::storage::WorkspaceRepository::new(db.clone())
        .create(&persona_core::models::Workspace::new(
            dir.path().to_path_buf(),
            "test".to_string(),
        ))
        .await
        .unwrap();
    let mut service = crate::commands::service::new_service(db).await.unwrap();
    service.initialize_user("master-pin").await.unwrap();
    let identity = service
        .create_identity("work".to_string(), IdentityType::Work)
        .await
        .unwrap();

    let mut login = service
        .create_credential(
            identity.id,
            "login".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            &CredentialData::Password(PasswordCredentialData {
                password: "p@ss".to_string(),
                email: Some("a@b.c".to_string()),
                security_questions: vec![],
            }),
        )
        .await
        .unwrap();
    login.username = Some("alice".to_string());
    login.url = Some("https://x.example".to_string());
    login.notes = Some("rotated quarterly".to_string());
    service.update_credential(&login).await.unwrap();

    service
        .create_credential(
            identity.id,
            "deploy".to_string(),
            CredentialType::ApiKey,
            SecurityLevel::High,
            &CredentialData::ApiKey(ApiKeyData {
                api_key: "sk-123".to_string(),
                api_secret: None,
                token: None,
                permissions: vec![],
                expires_at: None,
            }),
        )
        .await
        .unwrap();

    service
        .create_credential(
            identity.id,
            "github-2fa".to_string(),
            CredentialType::TwoFactor,
            SecurityLevel::Medium,
            &CredentialData::TwoFactor(TwoFactorData {
                secret_key: "JBSWY3DPEHPK3PXP".to_string(),
                issuer: "github".to_string(),
                account_name: "alice".to_string(),
                algorithm: "SHA1".to_string(),
                digits: 6,
                hotp: None,
                initial_counter: None,
                period: 30,
            }),
        )
        .await
        .unwrap();

    service
        .create_credential(
            identity.id,
            "server".to_string(),
            CredentialType::SshKey,
            SecurityLevel::High,
            &CredentialData::SshKey(SshKeyData {
                private_key: "PRIVATE".to_string(),
                public_key: "PUBLIC".to_string(),
                key_type: "ed25519".to_string(),
                passphrase: None,
            }),
        )
        .await
        .unwrap();

    service
        .create_credential(
            identity.id,
            "playbook".to_string(),
            CredentialType::SecureNote,
            SecurityLevel::Low,
            &CredentialData::SecureNote(SecureNoteData {
                note: "run book steps".to_string(),
            }),
        )
        .await
        .unwrap();

    (dir, config)
}

fn resolve_args(refs: &[&str]) -> SecretsArgs {
    SecretsArgs {
        command: SecretsCommand::Resolve {
            refs: refs.iter().map(|s| s.to_string()).collect(),
        },
    }
}

fn k8s_args(keys: &[&str]) -> SecretsArgs {
    SecretsArgs {
        command: SecretsCommand::K8s {
            name: "app-secret".to_string(),
            namespace: Some("prod".to_string()),
            keys: keys.iter().map(|s| s.to_string()).collect(),
            labels: vec!["app.kubernetes.io/managed-by=persona".to_string()],
            annotations: vec![],
        },
    }
}

/// 每种有独立字段词汇的凭据类型一个样本；可选字段全部 Some，
/// 保证词汇表内每个字段都能取到值（unset 分支由错误路径测试覆盖）。
fn sample_of_each_variant() -> Vec<(&'static str, CredentialData)> {
    vec![
        (
            "password",
            CredentialData::Password(PasswordCredentialData {
                password: "p".into(),
                email: Some("e@x.io".into()),
                security_questions: vec![],
            }),
        ),
        (
            "api_key",
            CredentialData::ApiKey(ApiKeyData {
                api_key: "k".into(),
                api_secret: Some("s".into()),
                token: Some("t".into()),
                permissions: vec![],
                expires_at: None,
            }),
        ),
        (
            "two_factor",
            CredentialData::TwoFactor(TwoFactorData {
                secret_key: "SEED".into(),
                issuer: "github".into(),
                account_name: "alice".into(),
                algorithm: "SHA1".into(),
                digits: 6,
                hotp: None,
                initial_counter: None,
                period: 30,
            }),
        ),
        (
            "ssh_key",
            CredentialData::SshKey(SshKeyData {
                private_key: "PRIVATE".into(),
                public_key: "PUBLIC".into(),
                key_type: "ed25519".into(),
                passphrase: Some("pp".into()),
            }),
        ),
        (
            "bank_card",
            CredentialData::BankCard(BankCardData {
                card_number: "4111".into(),
                cardholder_name: "Alice".into(),
                expiry_date: "12/30".into(),
                cvv: "123".into(),
                bank_name: "Bank".into(),
                card_type: "visa".into(),
            }),
        ),
        (
            "server_config",
            CredentialData::ServerConfig(ServerConfigData {
                hostname: "host".into(),
                ip_address: Some("10.0.0.2".into()),
                port: 2222,
                protocol: "ssh".into(),
                username: "root".into(),
                password: Some("pw".into()),
                ssh_key_id: None,
                additional_config: Default::default(),
            }),
        ),
        (
            "secure_note",
            CredentialData::SecureNote(SecureNoteData { note: "n".into() }),
        ),
        (
            "crypto_wallet",
            CredentialData::CryptoWallet(CryptoWalletData {
                wallet_type: "bip39".into(),
                mnemonic_phrase: Some("m".into()),
                private_key: Some("pk".into()),
                public_key: "pub".into(),
                address: "0xabc".into(),
                network: "ethereum".into(),
                bip39_passphrase: None,
                item_password_hash: None,
                item_password_hint: None,
            }),
        ),
        (
            "software_license",
            CredentialData::SoftwareLicense(SoftwareLicenseData {
                license_key: "LIC".into(),
                version: Some("2.0".into()),
                publisher: Some("Soft".into()),
                purchase_date: Some("2026-01-01".into()),
                order_number: Some("ORD".into()),
                support_email: Some("s@x.io".into()),
                download_url: Some("https://d.x.io".into()),
                seats: Some(3),
                valid_until: Some("2027-01-01".into()),
            }),
        ),
    ]
}

/// k8s 各入参校验在解锁前就 bail：config 指向空目录即可。
async fn k8s_validation_run(
    config: &CliConfig,
    name: &str,
    namespace: Option<&str>,
    keys: &[&str],
    labels: &[&str],
) -> Result<()> {
    execute_with(
        SecretsArgs {
            command: SecretsCommand::K8s {
                name: name.to_string(),
                namespace: namespace.map(str::to_string),
                keys: keys.iter().map(|s| s.to_string()).collect(),
                labels: labels.iter().map(|s| s.to_string()).collect(),
                annotations: vec![],
            },
        },
        config,
        &ScriptedUi::new(),
    )
    .await
}

mod fields;
mod k8s;
mod lifecycle;
mod refs;
mod run;
