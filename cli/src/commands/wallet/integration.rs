use super::commands::{handle_wallet_with, init_wallet_repository, resolve_default_identity_id};
use super::*;
use crate::config::CliConfig;
use crate::utils::prompt::scripted::{FailOn, PromptKind, ScriptedUi};
use persona_core::models::wallet::BlockchainNetwork;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serializes env mutations against the bridge, service and switch tests.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_process_env() -> (
    std::sync::MutexGuard<'static, ()>,
    std::sync::MutexGuard<'static, ()>,
) {
    (
        crate::commands::bridge::tests::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
    )
}

fn config_for(dir: &TempDir) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    config
}

/// Wallet rows reference `identities(id)` via foreign key, so seed one.
async fn seed_identity(dir: &TempDir, name: &str) {
    seed_identity_get_id(dir, name).await;
}

/// Same as [`seed_identity`] but returns the new identity's id.
async fn seed_identity_get_id(dir: &TempDir, name: &str) -> uuid::Uuid {
    use persona_core::models::{Identity, IdentityType};
    use persona_core::storage::IdentityRepository;
    use persona_core::Repository;
    let db = Database::from_file(dir.path().join("identities.db"))
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let identity = Identity::new(name.to_string(), IdentityType::Personal);
    let id = identity.id;
    IdentityRepository::new(db).create(&identity).await.unwrap();
    id
}

/// Insert a wallet directly, bypassing the command layer.
async fn insert_wallet(config: &CliConfig, wallet: &CryptoWallet) {
    let repo = init_wallet_repository(config).await.unwrap();
    repo.create(wallet).await.unwrap();
}

fn generate_args(name: &str, network: &str, hd: bool, address_count: usize) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::Generate {
            name: name.to_string(),
            description: None,
            network: network.to_string(),
            hd,
            bip_version: 44,
            account: 1,
            address_count,
        },
    }
}

fn import_args(format: &str, data: &str, name: Option<&str>) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::Import {
            format: format.to_string(),
            data: data.to_string(),
            name: name.map(String::from),
        },
    }
}

fn export_args(
    identifier: &str,
    format: &str,
    include_private: bool,
    output: Option<&str>,
) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::Export {
            wallet_identifier: identifier.to_string(),
            format: format.to_string(),
            include_private,
            output: output.map(String::from),
        },
    }
}

fn show_args(identifier: &str) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::Show {
            wallet_identifier: identifier.to_string(),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn tx_args(
    identifier: &str,
    to: &str,
    amount: &str,
    fee: &str,
    gas_price: Option<&str>,
    gas_limit: Option<u64>,
    nonce: Option<u64>,
    memo: Option<&str>,
    sign: bool,
) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::CreateTransaction {
            wallet_identifier: identifier.to_string(),
            to: to.to_string(),
            amount: amount.to_string(),
            fee: fee.to_string(),
            gas_price: gas_price.map(String::from),
            gas_limit,
            nonce,
            memo: memo.map(String::from),
            sign,
            confirm_poisoning_check: false,
            broadcast: false,
            expires_in: None,
        },
    }
}

fn list_tx_args(identifier: &str) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::ListTransactions {
            wallet_identifier: identifier.to_string(),
            pending: false,
            signed: false,
            broadcast: false,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn create_args(
    name: &str,
    network: &str,
    wallet_type: &str,
    watch_only: bool,
    xpub: Option<&str>,
    security_level: Option<&str>,
    description: Option<&str>,
) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::Create {
            name: name.to_string(),
            description: description.map(String::from),
            network: network.to_string(),
            wallet_type: wallet_type.to_string(),
            bip_version: None,
            address_count: None,
            watch_only,
            xpub: xpub.map(String::from),
            security_level: security_level.map(String::from),
            mnemonic: None,
            private_key: None,
            derivation_path: None,
        },
    }
}

#[tokio::test]
async fn wallet_create_list_show_update_stats_round_trip() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;

    // Empty list reports the hint.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::List {
                network: None,
                security_level: None,
                watch_only: false,
                search: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("empty list must succeed");

    // Watch-only Create without xpub is rejected.
    let err = handle_wallet_with(
        create_args("solo", "bitcoin", "single", true, None, None, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("watch-only without xpub must fail");
    assert!(err.to_string().contains("require an extended public key"));

    // Create a normal wallet and a watch-only wallet.
    handle_wallet_with(
        create_args(
            "vault",
            "bitcoin",
            "single",
            false,
            None,
            Some("high"),
            Some("main savings"),
        ),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("create normal wallet");
    handle_wallet_with(
            create_args("watcher", "ethereum", "single", true, Some("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs"), None, None),
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("create watch-only wallet");

    // List: default, filtered by network / level / search / watch_only.
    for list_args in [
        WalletCommand::List {
            network: None,
            security_level: None,
            watch_only: false,
            search: None,
        },
        WalletCommand::List {
            network: Some("bitcoin".into()),
            security_level: None,
            watch_only: false,
            search: None,
        },
        WalletCommand::List {
            network: None,
            security_level: Some("high".into()),
            watch_only: false,
            search: None,
        },
        WalletCommand::List {
            network: None,
            security_level: None,
            watch_only: false,
            search: Some("vau".into()),
        },
        WalletCommand::List {
            network: None,
            security_level: None,
            watch_only: true,
            search: None,
        },
        WalletCommand::List {
            network: Some("solana".into()),
            security_level: None,
            watch_only: false,
            search: None,
        },
        WalletCommand::List {
            network: None,
            security_level: Some("bogus".into()),
            watch_only: false,
            search: None,
        },
    ] {
        // The bogus security level must fail; the rest must succeed.
        let result = handle_wallet_with(
            WalletArgs { command: list_args },
            &config,
            &ScriptedUi::new(),
        )
        .await;
        match result {
            Ok(()) => {}
            Err(e) => assert!(
                e.to_string().contains("Invalid security level"),
                "unexpected error: {e}"
            ),
        }
    }

    // Show by name (normal) and by name (watch-only covers xpub rendering).
    handle_wallet_with(show_args("vault"), &config, &ScriptedUi::new())
        .await
        .expect("show by name");
    handle_wallet_with(show_args("watcher"), &config, &ScriptedUi::new())
        .await
        .expect("show watch-only");

    let err = handle_wallet_with(show_args("ghost"), &config, &ScriptedUi::new())
        .await
        .expect_err("unknown wallet must fail");
    assert!(err.to_string().to_lowercase().contains("not found"));

    // Empty identifier is rejected outright.
    let err = handle_wallet_with(show_args("   "), &config, &ScriptedUi::new())
        .await
        .expect_err("empty identifier must fail");
    assert!(err.to_string().contains("cannot be empty"));

    // Locate the wallet id through the repository for id-based commands.
    let repo = init_wallet_repository(&config).await.unwrap();
    let all = repo.find_all().await.into_anyhow().unwrap();
    let vault = all.iter().find(|w| w.name == "vault").unwrap().clone();
    drop(repo);

    // Update with an invalid security level fails.
    let err = handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Update {
                wallet_id: vault.id,
                name: None,
                description: None,
                security_level: Some("ultra".into()),
                add_tag: None,
                remove_tag: None,
                platform: None,
                purpose: None,
                note: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("invalid update level must fail");
    assert!(err.to_string().contains("Invalid security level"));

    // Update every mutable field.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Update {
                wallet_id: vault.id,
                name: Some("vault2".into()),
                description: Some("updated".into()),
                security_level: Some("maximum".into()),
                add_tag: Some("cold".into()),
                remove_tag: Some("hot".into()),
                platform: Some("ledger".into()),
                purpose: Some("savings".into()),
                note: Some("n".into()),
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("update all fields");

    let ghost = uuid::Uuid::new_v4();
    let err = handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Update {
                wallet_id: ghost,
                name: None,
                description: None,
                security_level: None,
                add_tag: None,
                remove_tag: None,
                platform: None,
                purpose: None,
                note: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("update missing wallet must fail");
    assert!(err.to_string().contains("not found"));

    // Stats for the wallet and system-wide.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Stats {
                wallet_identifier: Some("vault2".into()),
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("stats for wallet");
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Stats {
                wallet_identifier: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("system stats");

    // Delete without force only warns.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Delete {
                wallet_id: vault.id,
                force: false,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("delete without force warns only");
    // Force delete works and a missing delete reports.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Delete {
                wallet_id: vault.id,
                force: true,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("force delete works");
    let err = handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Delete {
                wallet_id: ghost,
                force: true,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("delete missing wallet must fail");
    assert!(err.to_string().contains("not found"));
}

#[tokio::test]
async fn wallet_addresses_mark_used_and_export_paths() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;

    handle_wallet_with(
        create_args("hot", "ethereum", "hd", false, None, None, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("create hd wallet");

    let repo = init_wallet_repository(&config).await.unwrap();
    let all = repo.find_all().await.into_anyhow().unwrap();
    let hot = all.iter().find(|w| w.name == "hot").unwrap().clone();
    drop(repo);

    // Add an address; unknown wallet fails.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::AddAddress {
                wallet_id: hot.id,
                address: "0xabc123def4567890abcdef1234567890abcdef12".into(),
                address_type: "ethereum".into(),
                index: 0,
                derivation_path: Some("m/44'/60'/0'/0/0".into()),
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("add address");
    let err = handle_wallet_with(
        WalletArgs {
            command: WalletCommand::AddAddress {
                wallet_id: uuid::Uuid::new_v4(),
                address: "0xdeadbeef".into(),
                address_type: "ethereum".into(),
                index: 1,
                derivation_path: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("add address to unknown wallet must fail");
    assert!(err.to_string().contains("not found"));

    // A second address makes the limited listing truncate, printing the
    // "Showing N of M" notice.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::AddAddress {
                wallet_id: hot.id,
                address: "0x999888777666555444333222111000fffdddcccbb".into(),
                address_type: "ethereum".into(),
                index: 1,
                derivation_path: Some("m/44'/60'/0'/0/1".into()),
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("add second address");

    // ListAddresses: all, unused-only, limit.
    for (used, unused, limit) in [
        (false, false, None),
        (false, true, None),
        (false, false, Some(1)),
    ] {
        handle_wallet_with(
            WalletArgs {
                command: WalletCommand::ListAddresses {
                    wallet_identifier: "hot".into(),
                    used,
                    unused,
                    limit,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("list addresses");
    }
    // Filter that matches nothing prints the hint.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::ListAddresses {
                wallet_identifier: "hot".into(),
                used: true,
                unused: false,
                limit: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("unused filter prints hint");

    // Mark used: success then unknown address error branch.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::MarkUsed {
                wallet_identifier: "hot".into(),
                address: "0xabc123def4567890abcdef1234567890abcdef12".into(),
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("mark used");
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::MarkUsed {
                wallet_identifier: "hot".into(),
                address: "0xunknown00000000000000000000000000000000".into(),
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("mark unknown address reports via formatter");

    // Now the used-only filter matches.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::ListAddresses {
                wallet_identifier: "hot".into(),
                used: true,
                unused: false,
                limit: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("used filter matches after mark");

    // CreateWatchOnly standalone command works.
    handle_wallet_with(
            WalletArgs {
                command: WalletCommand::CreateWatchOnly {
                    name: "cold-watch".into(),
                    description: Some("watch".into()),
                    network: "bitcoin".into(),
                    xpub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDHsk3QtFKLNDbjKZ2vBKtK9BfOHmSib8aLerSzhVbfJogu6vndeXTZvoQDLasZJHnJQrAGNKG".into(),
                    address_count: None,
                },
            },
            &config,
            &ScriptedUi::new(),
        )
        .await
        .expect("create watch-only");

    // Export xpub to stdout and json (no private data) to a file.
    handle_wallet_with(
        export_args("cold-watch", "xpub", false, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("xpub export");
    let out_path = dir.path().join("wallet-export.json");
    handle_wallet_with(
        export_args(
            "cold-watch",
            "json",
            false,
            Some(&out_path.display().to_string()),
        ),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("json export to file");
    assert!(out_path.exists(), "export file written");

    // Unknown export format fails.
    let err = handle_wallet_with(
        export_args("hot", "yaml", false, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("unknown export format must fail");
    assert!(err.to_string().contains("Unknown export format"));

    // Invalid network is rejected during create.
    let err = handle_wallet_with(
        create_args("bad", "moon", "single", false, None, None, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("invalid network must fail");
    assert!(err.to_string().contains("Unsupported network"));
}

#[tokio::test]
async fn generate_scripts_password_and_press_enter_ack() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;

    // A too-short password bails before any key material exists.
    let ui = ScriptedUi::new().password("short");
    let err = handle_wallet_with(
        generate_args("never-created", "bitcoin", false, 1),
        &config,
        &ui,
    )
    .await
    .expect_err("short password must fail");
    assert!(err.to_string().contains("at least 8 characters"));
    assert!(ui.exhausted());

    // Happy path consumes the password and the "Press Enter" ack.
    let ui = ScriptedUi::new()
        .password("long-enough-passphrase")
        .input("");
    handle_wallet_with(generate_args("gen", "bitcoin", true, 12), &config, &ui)
        .await
        .expect("generate must succeed");
    assert!(ui.exhausted());

    let repo = init_wallet_repository(&config).await.unwrap();
    let all = repo.find_all().await.into_anyhow().unwrap();
    let gen = all.iter().find(|w| w.name == "gen").unwrap().clone();
    drop(repo);

    assert_eq!(gen.addresses.len(), 12);
    assert!(
        gen.encrypted_mnemonic.is_some(),
        "mnemonic stored encrypted"
    );
    assert_eq!(
        gen.derivation_path.as_deref(),
        Some("m/44'/0'/1'/0"),
        "hd generation uses the account-aware BIP-44 path"
    );

    // Showing a wallet with more than 10 addresses exercises the
    // "... and N more addresses" branch.
    handle_wallet_with(show_args("gen"), &config, &ScriptedUi::new())
        .await
        .expect("show generated wallet");
}

#[tokio::test]
async fn import_flows_cover_every_format_and_error_path() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const WIF: &str = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn";

    // Unknown format fails before any prompt is shown.
    let err = handle_wallet_with(
        import_args("yaml", "junk", None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("unknown import format must fail");
    assert!(err.to_string().contains("Unknown import format"));

    // Malformed keystore JSON fails after the password prompt.
    let ui = ScriptedUi::new().password("import-pass-123");
    let err = handle_wallet_with(import_args("keystore", "{}", None), &config, &ui)
        .await
        .expect_err("malformed keystore import must fail");
    assert!(err.to_string().contains("Failed to import keystore"));
    assert!(ui.exhausted());

    // A real keystore file imports end to end with no extra prompts
    // (network is implied by the format; scrypt factors kept tiny).
    let key = [7u8; 32];
    let keystore_json = persona_core::crypto::wallet_encryption::export_to_keystore_with_params(
        &key,
        "import-pass-123",
        None,
        persona_core::crypto::wallet_encryption::ScryptExportParams {
            log_n: 4,
            r: 1,
            p: 1,
        },
    )
    .expect("build keystore fixture");
    let keystore_path = dir.path().join("wallet.json");
    std::fs::write(&keystore_path, &keystore_json).unwrap();
    let ui = ScriptedUi::new().password("import-pass-123");
    handle_wallet_with(
        import_args(
            "keystore",
            keystore_path.to_str().unwrap(),
            Some("Keystore Wallet"),
        ),
        &config,
        &ui,
    )
    .await
    .expect("keystore import must succeed");
    assert!(ui.exhausted());

    // Short password bails.
    let ui = ScriptedUi::new().password("short");
    let err = handle_wallet_with(import_args("mnemonic", PHRASE, None), &config, &ui)
        .await
        .expect_err("short import password must fail");
    assert!(err.to_string().contains("at least 8 characters"));
    assert!(ui.exhausted());

    // Invalid network answer for the mnemonic flow.
    let ui = ScriptedUi::new().password("import-pass-123").input("moon");
    let err = handle_wallet_with(import_args("mnemonic", PHRASE, None), &config, &ui)
        .await
        .expect_err("bad network answer must fail");
    assert!(err.to_string().contains("Unsupported network"));
    assert!(ui.exhausted());

    // Mnemonic import with scripted network and a custom address count.
    let ui = ScriptedUi::new()
        .password("import-pass-123")
        .input("ethereum")
        .input("3");
    handle_wallet_with(
        import_args("mnemonic", PHRASE, Some("imp-mnemonic")),
        &config,
        &ui,
    )
    .await
    .expect("mnemonic import");
    assert!(ui.exhausted());

    // Private-key import (hex) on bitcoin.
    let ui = ScriptedUi::new()
        .password("import-pass-123")
        .input("bitcoin");
    handle_wallet_with(
        import_args("private_key", &"11".repeat(32), Some("imp-key")),
        &config,
        &ui,
    )
    .await
    .expect("private key import");
    assert!(ui.exhausted());

    // WIF import asks no network question.
    let ui = ScriptedUi::new().password("import-pass-123");
    handle_wallet_with(import_args("wif", WIF, Some("imp-wif")), &config, &ui)
        .await
        .expect("wif import");
    assert!(ui.exhausted());

    // A `data` that points at a file is read from disk.
    let phrase_file = dir.path().join("phrase.txt");
    std::fs::write(&phrase_file, PHRASE).unwrap();
    let ui = ScriptedUi::new()
        .password("import-pass-123")
        .input("solana")
        .input("2");
    handle_wallet_with(
        import_args(
            "mnemonic",
            &phrase_file.display().to_string(),
            Some("imp-file"),
        ),
        &config,
        &ui,
    )
    .await
    .expect("file-based mnemonic import");
    assert!(ui.exhausted());

    // JSON export round-trip with a name override.
    let source = persona_core::crypto::import_from_mnemonic(
        uuid::Uuid::new_v4(),
        "json-src".to_string(),
        PHRASE,
        "",
        BlockchainNetwork::Bitcoin,
        None,
        2,
        "export-pass",
    )
    .unwrap();
    let json = persona_core::crypto::export_to_json(&source, true, Some("export-pass")).unwrap();
    let ui = ScriptedUi::new().password("import-pass-123");
    handle_wallet_with(import_args("json", &json, Some("renamed")), &config, &ui)
        .await
        .expect("json import");
    assert!(ui.exhausted());

    // Verify what landed in the database.
    let repo = init_wallet_repository(&config).await.unwrap();
    let all = repo.find_all().await.into_anyhow().unwrap();
    drop(repo);

    let mnemonic_wallet = all.iter().find(|w| w.name == "imp-mnemonic").unwrap();
    assert_eq!(mnemonic_wallet.addresses.len(), 3);
    assert_eq!(mnemonic_wallet.network, BlockchainNetwork::Ethereum);

    let key_wallet = all.iter().find(|w| w.name == "imp-key").unwrap();
    assert_eq!(key_wallet.addresses.len(), 1);
    assert!(key_wallet.addresses[0].address.starts_with("bc1q"));

    let wif_wallet = all.iter().find(|w| w.name == "imp-wif").unwrap();
    assert_eq!(wif_wallet.network, BlockchainNetwork::Bitcoin);
    assert_eq!(wif_wallet.addresses.len(), 1);

    let file_wallet = all.iter().find(|w| w.name == "imp-file").unwrap();
    assert_eq!(file_wallet.network, BlockchainNetwork::Solana);
    assert_eq!(file_wallet.addresses.len(), 2);

    let renamed = all.iter().find(|w| w.name == "renamed").unwrap();
    assert_eq!(renamed.addresses.len(), 2);
}

#[tokio::test]
async fn export_private_flows_prompt_for_a_password() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let identity_id = seed_identity_get_id(&dir, "alice").await;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const ETH_KEY: &str = "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b";
    let password = "export-pass-123";

    let hd = persona_core::crypto::import_from_mnemonic(
        identity_id,
        "hd-export".to_string(),
        PHRASE,
        "",
        BlockchainNetwork::Ethereum,
        None,
        2,
        password,
    )
    .unwrap();
    insert_wallet(&config, &hd).await;

    let eth_single = persona_core::crypto::import_from_private_key(
        identity_id,
        "eth-single".to_string(),
        ETH_KEY,
        BlockchainNetwork::Ethereum,
        password,
    )
    .unwrap();
    insert_wallet(&config, &eth_single).await;

    let btc_single = persona_core::crypto::import_from_private_key(
        identity_id,
        "btc-single".to_string(),
        &"11".repeat(32),
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();
    insert_wallet(&config, &btc_single).await;

    // Wrong password fails the mnemonic decryption.
    let ui = ScriptedUi::new().password("wrong-pass");
    let err = handle_wallet_with(
        export_args("hd-export", "mnemonic", false, None),
        &config,
        &ui,
    )
    .await
    .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Failed to export mnemonic"));
    assert!(ui.exhausted());

    // Correct password exports the phrase.
    let ui = ScriptedUi::new().password(password);
    handle_wallet_with(
        export_args("hd-export", "mnemonic", false, None),
        &config,
        &ui,
    )
    .await
    .expect("mnemonic export");
    assert!(ui.exhausted());

    // Private key export works for a single-key wallet.
    let ui = ScriptedUi::new().password(password);
    handle_wallet_with(
        export_args("eth-single", "private_key", false, None),
        &config,
        &ui,
    )
    .await
    .expect("private key export");
    assert!(ui.exhausted());

    // WIF export for the bitcoin single-address wallet.
    let ui = ScriptedUi::new().password(password);
    handle_wallet_with(export_args("btc-single", "wif", false, None), &config, &ui)
        .await
        .expect("wif export");
    assert!(ui.exhausted());

    // WIF is rejected for non-bitcoin wallets.
    let ui = ScriptedUi::new().password(password);
    let err = handle_wallet_with(export_args("eth-single", "wif", false, None), &config, &ui)
        .await
        .expect_err("wif export on ethereum must fail");
    assert!(format!("{:#}", err).contains("only supported for Bitcoin"));
    assert!(ui.exhausted());

    // JSON export with private data to a file (password branch + warning).
    let out_path = dir.path().join("private-export.json");
    let ui = ScriptedUi::new().password(password);
    handle_wallet_with(
        export_args(
            "hd-export",
            "json",
            true,
            Some(&out_path.display().to_string()),
        ),
        &config,
        &ui,
    )
    .await
    .expect("json private export");
    assert!(ui.exhausted());
    assert!(out_path.exists());
    let exported = std::fs::read_to_string(&out_path).unwrap();
    assert!(exported.contains(PHRASE), "mnemonic included in export");

    // A wallet without a stored mnemonic cannot export one.
    let ui = ScriptedUi::new().password(password);
    let err = handle_wallet_with(
        export_args("eth-single", "mnemonic", false, None),
        &config,
        &ui,
    )
    .await
    .expect_err("mnemonic export without mnemonic must fail");
    assert!(format!("{:#}", err).contains("Wallet has no mnemonic"));
    assert!(ui.exhausted());
}

#[tokio::test]
async fn create_transaction_request_and_listing() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let identity_id = seed_identity_get_id(&dir, "alice").await;

    let eth_single = persona_core::crypto::import_from_private_key(
        identity_id,
        "tx-src".to_string(),
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
        BlockchainNetwork::Ethereum,
        "unused-here",
    )
    .unwrap();
    insert_wallet(&config, &eth_single).await;

    let fresh = persona_core::crypto::import_from_private_key(
        identity_id,
        "quiet-wallet".to_string(),
        "2222222222222222222222222222222222222222222222222222222222222222",
        BlockchainNetwork::Ethereum,
        "unused-here",
    )
    .unwrap();
    insert_wallet(&config, &fresh).await;

    // Create a request without signing (memo covers the listing line).
    handle_wallet_with(
        tx_args(
            "tx-src",
            "0x1111111111111111111111111111111111111111",
            "1000000000000000000",
            "21000",
            None,
            None,
            None,
            Some("run money"),
            false,
        ),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("create transaction request");

    // Listing shows the pending request for one wallet and the empty
    // hint for the other.
    handle_wallet_with(list_tx_args("tx-src"), &config, &ScriptedUi::new())
        .await
        .expect("list transactions");
    handle_wallet_with(list_tx_args("quiet-wallet"), &config, &ScriptedUi::new())
        .await
        .expect("empty transaction list");

    let repo = init_wallet_repository(&config).await.unwrap();
    let pending = repo
        .get_pending_requests(&eth_single.id)
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].memo.as_deref(), Some("run money"));
}

#[tokio::test]
async fn create_transaction_sign_success_and_failure_paths() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let identity_id = seed_identity_get_id(&dir, "alice").await;
    let password = "sign-pass-123";

    let eth_single = persona_core::crypto::import_from_private_key(
        identity_id,
        "signer".to_string(),
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
        BlockchainNetwork::Ethereum,
        password,
    )
    .unwrap();
    insert_wallet(&config, &eth_single).await;

    let btc_single = persona_core::crypto::import_from_private_key(
        identity_id,
        "btc-signer".to_string(),
        &"11".repeat(32),
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();
    insert_wallet(&config, &btc_single).await;

    let sol_hd = persona_core::crypto::import_from_mnemonic(
            identity_id,
            "sol-signer".to_string(),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            BlockchainNetwork::Solana,
            None,
            1,
            "sol-pass-123",
        )
        .unwrap();
    insert_wallet(&config, &sol_hd).await;

    let watcher = CryptoWallet::new_watch_only(
            identity_id,
            "watch-signer".to_string(),
            BlockchainNetwork::Ethereum,
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYf1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs".to_string(),
        );
    insert_wallet(&config, &watcher).await;

    // Ethereum: full sign -> verify -> raw assembly -> stored.
    let ui = ScriptedUi::new().password(password);
    handle_wallet_with(
        tx_args(
            "signer",
            "0x1111111111111111111111111111111111111111",
            "1000000000000000000",
            "21000",
            Some("20000000000"),
            Some(21000),
            Some(0),
            None,
            true,
        ),
        &config,
        &ui,
    )
    .await
    .expect("ethereum sign must succeed");
    assert!(ui.exhausted());

    let repo = init_wallet_repository(&config).await.unwrap();
    let stats = repo
        .get_transaction_stats(&eth_single.id)
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(stats.total_transactions, 1);
    drop(repo);

    // Wrong password fails key derivation.
    let ui = ScriptedUi::new().password("wrong-pass");
    let err = handle_wallet_with(
        tx_args(
            "signer",
            "0x1111111111111111111111111111111111111111",
            "1",
            "1",
            Some("1"),
            Some(21000),
            Some(0),
            None,
            true,
        ),
        &config,
        &ui,
    )
    .await
    .expect_err("wrong password must fail");
    assert!(err.to_string().contains("Failed to derive signing key"));
    assert!(ui.exhausted());

    // Watch-only wallets cannot sign.
    let ui = ScriptedUi::new().password(password);
    let err = handle_wallet_with(
        tx_args(
            "watch-signer",
            "0x1111111111111111111111111111111111111111",
            "1",
            "1",
            Some("1"),
            Some(21000),
            Some(0),
            None,
            true,
        ),
        &config,
        &ui,
    )
    .await
    .expect_err("watch-only signing must fail");
    assert!(format!("{:#}", err).contains("Watch-only wallets cannot sign"));
    assert!(ui.exhausted());

    // Solana signing requires the serialized message in
    // `raw_transaction_data`, which the request does not carry -> the
    // signing itself fails before anything is stored.
    let ui = ScriptedUi::new().password("sol-pass-123");
    let err = handle_wallet_with(
        tx_args(
            "sol-signer",
            &sol_hd.addresses[0].address,
            "1",
            "1",
            None,
            None,
            None,
            None,
            true,
        ),
        &config,
        &ui,
    )
    .await
    .expect_err("solana sign without raw data must fail");
    assert!(err.to_string().contains("Failed to sign transaction"));
    assert!(format!("{:#}", err).contains("raw_transaction_data"));
    assert!(ui.exhausted());

    // Bitcoin without UTXO metadata stores only the audit signature.
    let ui = ScriptedUi::new().password(password);
    handle_wallet_with(
        tx_args(
            "btc-signer",
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "5000",
            "300",
            None,
            None,
            None,
            None,
            true,
        ),
        &config,
        &ui,
    )
    .await
    .expect("bitcoin audit sign must succeed");
    assert!(ui.exhausted());

    let repo = init_wallet_repository(&config).await.unwrap();
    let stats = repo
        .get_transaction_stats(&btc_single.id)
        .await
        .into_anyhow()
        .unwrap();
    assert_eq!(stats.total_transactions, 1);
}

#[tokio::test]
async fn create_transaction_non_interactive_uses_env_password() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_WALLET_PASSWORD");

    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.ui.interactive = false;
    let identity_id = seed_identity_get_id(&dir, "alice").await;
    let password = "env-pass-123";

    let eth_single = persona_core::crypto::import_from_private_key(
        identity_id,
        "env-signer".to_string(),
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
        BlockchainNetwork::Ethereum,
        password,
    )
    .unwrap();
    insert_wallet(&config, &eth_single).await;

    // Missing env var is rejected.
    let err = handle_wallet_with(
        tx_args(
            "env-signer",
            "0x1111111111111111111111111111111111111111",
            "1000000000000000000",
            "21000",
            Some("20000000000"),
            Some(21000),
            Some(0),
            None,
            true,
        ),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("missing env password must fail");
    assert!(err
        .to_string()
        .contains("PERSONA_WALLET_PASSWORD must be set"));

    // The env var supplies the password.
    std::env::set_var("PERSONA_WALLET_PASSWORD", password);
    handle_wallet_with(
        tx_args(
            "env-signer",
            "0x1111111111111111111111111111111111111111",
            "1000000000000000000",
            "21000",
            Some("20000000000"),
            Some(21000),
            Some(0),
            None,
            true,
        ),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("env-password sign must succeed");

    std::env::remove_var("PERSONA_WALLET_PASSWORD");
}

#[tokio::test]
async fn sign_refuses_address_poisoning_spoof_until_confirmed() {
    let _guard = lock_process_env();
    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.ui.interactive = false;
    let identity_id = seed_identity_get_id(&dir, "alice").await;
    let password = "poison-pass-1";

    let signer = persona_core::crypto::import_from_private_key(
        identity_id,
        "poison-signer".to_string(),
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
        BlockchainNetwork::Ethereum,
        password,
    )
    .unwrap();
    insert_wallet(&config, &signer).await;

    // 仿冒地址：与钱包自身地址前 6 + 后 6 字符相同、中段不同
    let own = signer.addresses.first().unwrap().address.clone();
    assert!(own.len() >= 12);
    let spoof = format!(
        "{}{}{}",
        &own[..6],
        "0".repeat(own.len() - 12),
        &own[own.len() - 6..]
    );
    let (gas_price, gas_limit, nonce) = (Some("20000000000"), Some(21000), Some(0));

    std::env::set_var("PERSONA_WALLET_PASSWORD", password);

    // 拦截：不输口令即被拒（检查在口令 prompt 之前）
    let err = handle_wallet_with(
        tx_args(
            "poison-signer",
            &spoof,
            "1",
            "100",
            gas_price,
            gas_limit,
            nonce,
            None,
            true,
        ),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("address-poisoning spoof must be refused");
    assert!(err.to_string().contains("Address-poisoning check refused"));
    // 内层 PersonaError 文本在 anyhow 的全链显示里（与文件内其他断言同口径）
    assert!(format!("{:#}", err).contains("address-poisoning spoof"));

    // 显式确认后放行
    let args = WalletArgs {
        command: WalletCommand::CreateTransaction {
            wallet_identifier: "poison-signer".to_string(),
            to: spoof.clone(),
            amount: "1".to_string(),
            fee: "100".to_string(),
            gas_price: gas_price.map(String::from),
            gas_limit,
            nonce,
            memo: None,
            sign: true,
            confirm_poisoning_check: true,
            broadcast: false,
            expires_in: None,
        },
    };
    handle_wallet_with(args, &config, &ScriptedUi::new())
        .await
        .expect("confirmed poisoning sign must succeed");
}

fn passwd_args(identifier: &str) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::Passwd {
            wallet_identifier: identifier.to_string(),
        },
    }
}

#[tokio::test]
async fn passwd_rewraps_private_key_and_mnemonic() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_WALLET_PASSWORD");

    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.ui.interactive = true;
    let identity_id = seed_identity_get_id(&dir, "alice").await;
    let old_password = "rotate-old-pass";
    let new_password = "rotate-new-pass";
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let wallet = persona_core::crypto::import_from_mnemonic(
        identity_id,
        "rotate-me".to_string(),
        phrase,
        "",
        BlockchainNetwork::Ethereum,
        None,
        1,
        old_password,
    )
    .unwrap();
    insert_wallet(&config, &wallet).await;

    // ScriptedUi consumes one answer per password() call (confirmation
    // auto-matches), so old + new is two scripted answers.
    let ui = ScriptedUi::new()
        .password(old_password)
        .password(new_password);
    handle_wallet_with(passwd_args("rotate-me"), &config, &ui)
        .await
        .expect("passwd must succeed");
    assert!(ui.exhausted());

    let repo = init_wallet_repository(&config).await.unwrap();
    let updated = find_wallet_by_identifier(&repo, "rotate-me").await.unwrap();

    // New password unlocks both blobs; the old one unlocks neither.
    let mnemonic = persona_core::crypto::export_mnemonic(&updated, new_password).unwrap();
    assert_eq!(mnemonic, phrase);
    let private_key = persona_core::crypto::export_private_key(&updated, new_password).unwrap();
    let before = persona_core::crypto::export_private_key(&wallet, old_password).unwrap();
    assert_eq!(private_key, before);

    assert!(persona_core::crypto::export_mnemonic(&updated, old_password).is_err());
    assert!(persona_core::crypto::export_private_key(&updated, old_password).is_err());

    // Both wraps got fresh salt/nonce (independent re-wrap).
    let old_key: persona_core::crypto::EncryptedWalletKey =
        serde_json::from_slice(&wallet.encrypted_private_key).unwrap();
    let new_key: persona_core::crypto::EncryptedWalletKey =
        serde_json::from_slice(&updated.encrypted_private_key).unwrap();
    assert_ne!(old_key.salt, new_key.salt);
    assert_ne!(old_key.nonce, new_key.nonce);
    let old_mnemonic: persona_core::crypto::EncryptedMnemonic =
        serde_json::from_slice(wallet.encrypted_mnemonic.as_ref().unwrap()).unwrap();
    let new_mnemonic: persona_core::crypto::EncryptedMnemonic =
        serde_json::from_slice(updated.encrypted_mnemonic.as_ref().unwrap()).unwrap();
    assert_ne!(old_mnemonic.salt, new_mnemonic.salt);
    assert_ne!(old_mnemonic.nonce, new_mnemonic.nonce);
}

#[tokio::test]
async fn passwd_rejects_wrong_old_password_without_touching_the_row() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_WALLET_PASSWORD");

    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.ui.interactive = true;
    let identity_id = seed_identity_get_id(&dir, "alice").await;
    let password = "rotate-real-pass";

    let wallet = persona_core::crypto::import_from_private_key(
        identity_id,
        "wrong-old".to_string(),
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
        BlockchainNetwork::Ethereum,
        password,
    )
    .unwrap();
    insert_wallet(&config, &wallet).await;

    let ui = ScriptedUi::new()
        .password("totally-wrong")
        .password("rotate-new-pass");
    let err = handle_wallet_with(passwd_args("wrong-old"), &config, &ui)
        .await
        .expect_err("wrong old password must fail");
    assert!(err
        .to_string()
        .contains("Failed to re-wrap private key (wrong password?)"));

    // The row is untouched: the original password still decrypts.
    let repo = init_wallet_repository(&config).await.unwrap();
    let unchanged = find_wallet_by_identifier(&repo, "wrong-old").await.unwrap();
    assert!(persona_core::crypto::export_private_key(&unchanged, password).is_ok());
    assert!(persona_core::crypto::export_private_key(&unchanged, "rotate-new-pass").is_err());
}

#[tokio::test]
async fn passwd_rejects_watch_only_and_weak_or_same_new_password() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_WALLET_PASSWORD");

    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.ui.interactive = true;
    let identity_id = seed_identity_get_id(&dir, "alice").await;

    let mut watcher = CryptoWallet::new(
        identity_id,
        "watcher".to_string(),
        BlockchainNetwork::Ethereum,
        persona_core::models::wallet::WalletType::SingleAddress,
        vec![],
    );
    watcher.watch_only = true;
    // DB CHECK constraint: watch-only rows must carry an xpub.
    watcher.extended_public_key = Some("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDHsk3PeQXtoy3xsj5BfuDGLJbl26NZf8Koc1tSNevURNWrqzEMBEq9VXdGiJZzhyTNt7ESChi".to_string());
    insert_wallet(&config, &watcher).await;

    let err = handle_wallet_with(
        passwd_args("watcher"),
        &config,
        &ScriptedUi::new().password("x").password("y"),
    )
    .await
    .expect_err("watch-only wallet must be refused");
    assert!(err
        .to_string()
        .contains("Watch-only wallets hold no key material"));

    // Same new password as the old one is rejected.
    let wallet = persona_core::crypto::import_from_private_key(
        identity_id,
        "same-pass".to_string(),
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
        BlockchainNetwork::Ethereum,
        "same-old-pass",
    )
    .unwrap();
    insert_wallet(&config, &wallet).await;
    let err = handle_wallet_with(
        passwd_args("same-pass"),
        &config,
        &ScriptedUi::new()
            .password("same-old-pass")
            .password("same-old-pass"),
    )
    .await
    .expect_err("same password must be refused");
    assert!(err.to_string().contains("New password must be different"));

    // Short new password is rejected.
    let err = handle_wallet_with(
        passwd_args("same-pass"),
        &config,
        &ScriptedUi::new()
            .password("same-old-pass")
            .password("short"),
    )
    .await
    .expect_err("short password must be refused");
    assert!(err.to_string().contains("at least 8 characters"));
}

const PSBT_INPUTS_JSON: &str = r#"[
        {"txid":"1111111111111111111111111111111111111111111111111111111111111111","vout":0,"amount":"100000"},
        {"txid":"2222222222222222222222222222222222222222222222222222222222222222","vout":1,"amount":"200000"}
    ]"#;

fn psbt_export_args(wallet: &str, to: &str, confirm: bool) -> WalletArgs {
    WalletArgs {
        command: WalletCommand::ExportPsbt {
            wallet_identifier: wallet.to_string(),
            to: to.to_string(),
            amount: "280000".to_string(),
            fee: "20000".to_string(),
            inputs: PSBT_INPUTS_JSON.to_string(),
            change_address: None,
            confirm_poisoning_check: confirm,
        },
    }
}

#[tokio::test]
async fn psbt_export_sign_finalize_roundtrip() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_WALLET_PASSWORD");

    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.ui.interactive = true;
    let identity_id = seed_identity_get_id(&dir, "alice").await;
    let password = "psbt-pass-123";

    let wallet = persona_core::crypto::import_from_private_key(
        identity_id,
        "psbt-wallet".to_string(),
        "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9",
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();
    assert!(wallet.addresses[0].address.starts_with("bc1q"));
    insert_wallet(&config, &wallet).await;
    let to = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();

    // Export through the command arm (wiring), then through the helper
    // for the bytes (content): both must agree.
    let repo = init_wallet_repository(&config).await.unwrap();
    handle_wallet_with(
        psbt_export_args("psbt-wallet", &to, false),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("psbt export wiring must succeed");
    let unsigned = run_export_psbt(
        &repo,
        "psbt-wallet",
        &to,
        "280000",
        "20000",
        PSBT_INPUTS_JSON,
        None,
        false,
    )
    .await
    .expect("psbt export helper must succeed");
    let unsigned_again = run_export_psbt(
        &repo,
        "psbt-wallet",
        &to,
        "280000",
        "20000",
        PSBT_INPUTS_JSON,
        None,
        false,
    )
    .await
    .unwrap();
    assert_eq!(unsigned, unsigned_again, "export must be deterministic");

    // Sign via the command arm needs no captured output; use the helper
    // for the bytes and chain them into finalize.
    let signed = run_sign_psbt(
        &repo,
        "psbt-wallet",
        &BASE64.encode(&unsigned),
        &config,
        &ScriptedUi::new().password(password),
    )
    .await
    .expect("psbt sign must succeed");
    assert_ne!(signed, unsigned, "signing must change the PSBT");

    // Deterministic signing (RFC-6979): same inputs → same artifact.
    let signed_again = run_sign_psbt(
        &repo,
        "psbt-wallet",
        &BASE64.encode(&unsigned),
        &config,
        &ScriptedUi::new().password(password),
    )
    .await
    .unwrap();
    assert_eq!(signed, signed_again);

    // Finalize via the command arm wiring; via the core path for content.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::FinalizePsbt {
                psbt: BASE64.encode(&signed),
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("finalize wiring must succeed");
    let finalized = persona_core::crypto::finalize_bitcoin_psbt(&signed).unwrap();
    assert_eq!(finalized.hash.len(), 64);
    assert!(!finalized.raw.is_empty());
}

#[tokio::test]
async fn psbt_export_enforces_poisoning_and_network_gates() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_WALLET_PASSWORD");

    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.ui.interactive = true;
    let identity_id = seed_identity_get_id(&dir, "alice").await;

    // Non-Bitcoin wallet is refused outright.
    let eth = persona_core::crypto::import_from_private_key(
        identity_id,
        "eth-only".to_string(),
        "4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9b14da7c84f0f4f6b",
        BlockchainNetwork::Ethereum,
        "psbt-pass-123",
    )
    .unwrap();
    insert_wallet(&config, &eth).await;
    let err = run_export_psbt(
        &init_wallet_repository(&config).await.unwrap(),
        "eth-only",
        "0x3535353535353535353535353535353535353535",
        "280000",
        "20000",
        PSBT_INPUTS_JSON,
        None,
        false,
    )
    .await
    .expect_err("non-Bitcoin export must be refused");
    assert!(err.to_string().contains("only supported for Bitcoin"));

    // A spoofed recipient is refused before any artifact is built.
    let btc = persona_core::crypto::import_from_private_key(
        identity_id,
        "btc-spoofed".to_string(),
        "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9",
        BlockchainNetwork::Bitcoin,
        "psbt-pass-123",
    )
    .unwrap();
    insert_wallet(&config, &btc).await;
    let own = btc.addresses[0].address.clone();
    let spoof = format!(
        "{}{}{}",
        &own[..6],
        "q".repeat(own.len() - 12),
        &own[own.len() - 6..]
    );
    let err = run_export_psbt(
        &init_wallet_repository(&config).await.unwrap(),
        "btc-spoofed",
        &spoof,
        "280000",
        "20000",
        PSBT_INPUTS_JSON,
        None,
        false,
    )
    .await
    .expect_err("spoofed recipient must be refused");
    assert!(err.to_string().contains("Address-poisoning check refused"));
}

#[tokio::test]
async fn psbt_sign_rejects_watch_only_foreign_psbt_and_bad_base64() {
    let _guard = lock_process_env();
    std::env::remove_var("PERSONA_WALLET_PASSWORD");

    let dir = TempDir::new().unwrap();
    let mut config = config_for(&dir);
    config.ui.interactive = true;
    let identity_id = seed_identity_get_id(&dir, "alice").await;
    let password = "psbt-pass-123";

    let wallet = persona_core::crypto::import_from_private_key(
        identity_id,
        "btc-signer".to_string(),
        "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9",
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();
    insert_wallet(&config, &wallet).await;
    let repo = init_wallet_repository(&config).await.unwrap();

    // Bad base64.
    let err = run_sign_psbt(
        &repo,
        "btc-signer",
        "!!!not base64!!!",
        &config,
        &ScriptedUi::new().password(password),
    )
    .await
    .expect_err("bad base64 must be refused");
    assert!(err.to_string().contains("Invalid base64 PSBT"));

    // Wrong password fails at key derivation, before the PSBT is touched.
    let to = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
    let unsigned = run_export_psbt(
        &repo,
        "btc-signer",
        &to,
        "280000",
        "20000",
        PSBT_INPUTS_JSON,
        None,
        false,
    )
    .await
    .unwrap();
    let err = run_sign_psbt(
        &repo,
        "btc-signer",
        &BASE64.encode(&unsigned),
        &config,
        &ScriptedUi::new().password("wrong-pass-1"),
    )
    .await
    .expect_err("wrong password must be refused");
    assert!(err.to_string().contains("wrong password?"));

    // A PSBT from a foreign key is refused by ownership.
    let stranger = persona_core::crypto::import_from_private_key(
        identity_id,
        "btc-stranger".to_string(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        BlockchainNetwork::Bitcoin,
        password,
    )
    .unwrap();
    insert_wallet(&config, &stranger).await;
    let repo2 = init_wallet_repository(&config).await.unwrap();
    let err = run_sign_psbt(
        &repo2,
        "btc-stranger",
        &BASE64.encode(&unsigned),
        &config,
        &ScriptedUi::new().password(password),
    )
    .await
    .expect_err("foreign PSBT must be refused");
    assert!(err
        .to_string()
        .contains("No wallet key owns all PSBT inputs"));

    // Watch-only wallets refuse to sign.
    let mut watcher = CryptoWallet::new(
        identity_id,
        "psbt-watcher".to_string(),
        BlockchainNetwork::Bitcoin,
        persona_core::models::wallet::WalletType::SingleAddress,
        vec![],
    );
    watcher.watch_only = true;
    watcher.extended_public_key = Some("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDHsk3PeQXtoy3xsj5BfuDGLJbl26NZf8Koc1tSNevURNWrqzEMBEq9VXdGiJZzhyTNt7ESChi".to_string());
    insert_wallet(&config, &watcher).await;
    let err = run_sign_psbt(
        &repo,
        "psbt-watcher",
        &BASE64.encode(&unsigned),
        &config,
        &ScriptedUi::new().password(password),
    )
    .await
    .expect_err("watch-only sign must be refused");
    assert!(err
        .to_string()
        .contains("Watch-only wallets hold no key material"));
}

#[tokio::test]
async fn find_wallet_by_identifier_resolution_paths() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let identity_id = seed_identity_get_id(&dir, "alice").await;

    let repo = init_wallet_repository(&config).await.unwrap();

    let mk_wallet = |name: &str, id: Option<uuid::Uuid>| {
        let mut wallet = CryptoWallet::new(
            identity_id,
            name.to_string(),
            BlockchainNetwork::Bitcoin,
            persona_core::models::wallet::WalletType::SingleAddress,
            vec![1, 2, 3, 4],
        );
        if let Some(id) = id {
            wallet.id = id;
        }
        wallet
    };

    // Two wallets whose ids share the "aaaaaaaa" prefix.
    repo.create(&mk_wallet(
        "alpha",
        Some(uuid::Uuid::parse_str("aaaaaaaa-0000-0000-0000-000000000001").unwrap()),
    ))
    .await
    .unwrap();
    repo.create(&mk_wallet(
        "gamma",
        Some(uuid::Uuid::parse_str("aaaaaaaa-0000-0000-0000-000000000002").unwrap()),
    ))
    .await
    .unwrap();

    // A wallet with a hex-like name exercises the prefix-to-name
    // fall-through, and twins exercise the name/fuzzy ambiguity errors.
    repo.create(&mk_wallet("deadbeef01", None)).await.unwrap();
    repo.create(&mk_wallet("twin", None)).await.unwrap();
    repo.create(&mk_wallet("twin", None)).await.unwrap();

    // A single, uniquely prefixed id is resolvable by its short form.
    let delta = repo.create(&mk_wallet("delta", None)).await.unwrap();
    drop(repo);

    // Ambiguous id prefix lists the candidates and bails.
    let err =
        find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "aaaaaaaa")
            .await
            .expect_err("ambiguous prefix must fail");
    let msg = err.to_string();
    assert!(msg.contains("Multiple wallets match ID prefix 'aaaaaaaa'"));
    assert!(msg.contains("alpha") && msg.contains("gamma"));

    // Full UUID resolves directly.
    let wallet = find_wallet_by_identifier(
        &init_wallet_repository(&config).await.unwrap(),
        "aaaaaaaa-0000-0000-0000-000000000001",
    )
    .await
    .unwrap();
    assert_eq!(wallet.name, "alpha");

    // Short unique prefix resolves.
    let prefix = delta.id.to_string()[..8].to_string();
    let wallet =
        find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), &prefix)
            .await
            .unwrap();
    assert_eq!(wallet.name, "delta");

    // A hex-looking name that matches no id falls through to the name.
    let wallet = find_wallet_by_identifier(
        &init_wallet_repository(&config).await.unwrap(),
        "deadbeef01",
    )
    .await
    .unwrap();
    assert_eq!(wallet.name, "deadbeef01");

    // Ambiguous exact names.
    let err = find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "twin")
        .await
        .expect_err("duplicate names must fail");
    assert!(err
        .to_string()
        .contains("Multiple wallets are named 'twin'"));

    // Fuzzy match: single and ambiguous.
    let wallet = find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "alph")
        .await
        .unwrap();
    assert_eq!(wallet.name, "alpha");
    let err = find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "twi")
        .await
        .expect_err("ambiguous fuzzy match must fail");
    assert!(err.to_string().contains("Multiple wallets match 'twi'"));

    // Unknown identifier fails.
    let err = find_wallet_by_identifier(&init_wallet_repository(&config).await.unwrap(), "ghost")
        .await
        .expect_err("unknown identifier must fail");
    assert!(err.to_string().contains("Wallet 'ghost' not found"));
}

#[tokio::test]
async fn create_rejects_unknown_wallet_type_bip_and_security_level() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;

    let err = handle_wallet_with(
        create_args("w1", "bitcoin", "paper", false, None, None, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("unknown wallet type must fail");
    assert!(err.to_string().contains("Unsupported wallet type: paper"));

    let err = handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Create {
                name: "w2".into(),
                description: None,
                network: "bitcoin".into(),
                wallet_type: "hd".into(),
                bip_version: Some(33),
                address_count: None,
                watch_only: false,
                xpub: None,
                security_level: None,
                mnemonic: None,
                private_key: None,
                derivation_path: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("unknown BIP version must fail");
    assert!(err.to_string().contains("Unsupported BIP version: 33"));

    let err = handle_wallet_with(
        create_args("w3", "bitcoin", "single", false, None, Some("ultra"), None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("invalid security level must fail");
    assert!(err.to_string().contains("Invalid security level"));
}

#[tokio::test]
async fn create_wallet_requires_a_seed_identity() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);

    let err = handle_wallet_with(
        create_args("orphan", "bitcoin", "single", false, None, None, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect_err("creating without any identity must fail");
    assert!(err.to_string().contains("No identity found"));
}

#[tokio::test]
async fn resolve_default_identity_prefers_the_active_workspace_identity() {
    use persona_core::models::Workspace;
    use persona_core::storage::WorkspaceRepository;
    use persona_core::Repository;

    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity_get_id(&dir, "first").await;
    let second = seed_identity_get_id(&dir, "second").await;

    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    let mut ws = Workspace::new(config.workspace.path.clone(), "ws".to_string());
    ws.switch_identity(second);
    WorkspaceRepository::new(db.clone())
        .create(&ws)
        .await
        .unwrap();
    drop(db);

    assert_eq!(resolve_default_identity_id(&config).await.unwrap(), second);
}

#[tokio::test]
async fn resolve_default_identity_falls_back_to_the_first_identity() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    let only = seed_identity_get_id(&dir, "only").await;

    assert_eq!(resolve_default_identity_id(&config).await.unwrap(), only);
}

#[tokio::test]
async fn resolve_default_identity_requires_an_identity() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);

    let err = resolve_default_identity_id(&config)
        .await
        .expect_err("no identity must fail");
    assert!(err.to_string().contains("No identity found"));
}

#[tokio::test]
async fn terminal_entry_point_and_watch_only_filter_hint() {
    // The TerminalUi-backed entry point works on a fresh workspace: the
    // repository bootstraps an empty database and lists zero wallets.
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    handle_wallet(
        WalletArgs {
            command: WalletCommand::List {
                network: None,
                security_level: None,
                watch_only: false,
                search: None,
            },
        },
        &config,
    )
    .await
    .expect("empty workspace lists zero wallets");

    // A watch-only filter that hides every wallet prints the dedicated
    // hint instead of the table.
    seed_identity(&dir, "alice").await;
    handle_wallet_with(
        create_args("plain", "bitcoin", "single", false, None, None, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("non-watch-only wallet created");
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::List {
                network: None,
                security_level: None,
                watch_only: true,
                search: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("watch-only filter with no matches succeeds");
}

#[tokio::test]
async fn generate_without_hd_and_failing_ack_prompt() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;

    // hd=false passes no path, and the core import fills in the
    // account-0 recommended default.
    let ui = ScriptedUi::new()
        .password("long-enough-passphrase")
        .input("");
    handle_wallet_with(
        generate_args("plain-gen", "bitcoin", false, 2),
        &config,
        &ui,
    )
    .await
    .expect("non-HD generation must succeed");
    assert!(ui.exhausted());

    let repo = init_wallet_repository(&config).await.unwrap();
    let all = repo.find_all().await.into_anyhow().unwrap();
    let gen = all.iter().find(|w| w.name == "plain-gen").unwrap().clone();
    drop(repo);
    assert_eq!(gen.derivation_path.as_deref(), Some("m/44'/0'/0'/0"));

    // A failing "Press Enter" acknowledgement propagates.
    let inner = ScriptedUi::new().password("long-enough-passphrase");
    let ui = FailOn::new(&inner, PromptKind::Input);
    let err = handle_wallet_with(
        generate_args("never-created", "bitcoin", true, 1),
        &config,
        &ui,
    )
    .await
    .expect_err("failing acknowledgement must abort");
    assert!(err.to_string().contains("failing ui: input prompt"));
}

#[tokio::test]
async fn update_with_sparse_fields_leaves_the_rest_untouched() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;
    handle_wallet_with(
        create_args(
            "sparse",
            "bitcoin",
            "single",
            false,
            None,
            Some("high"),
            Some("desc"),
        ),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("wallet created");

    let repo = init_wallet_repository(&config).await.unwrap();
    let all = repo.find_all().await.into_anyhow().unwrap();
    let wallet = all.iter().find(|w| w.name == "sparse").unwrap().clone();
    drop(repo);

    // Only name/description change; level and tag lists are skipped.
    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::Update {
                wallet_id: wallet.id,
                name: Some("sparse2".into()),
                description: Some("new desc".into()),
                security_level: None,
                add_tag: None,
                remove_tag: None,
                platform: None,
                purpose: None,
                note: None,
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("sparse update succeeds");

    let repo = init_wallet_repository(&config).await.unwrap();
    let all = repo.find_all().await.into_anyhow().unwrap();
    let updated = all.iter().find(|w| w.name == "sparse2").unwrap().clone();
    drop(repo);
    assert_eq!(updated.security_level, wallet.security_level);
    assert_eq!(updated.metadata.tags, wallet.metadata.tags);
}

#[tokio::test]
async fn list_addresses_limit_reports_the_shown_count() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;

    handle_wallet_with(
        create_args("limited", "ethereum", "hd", false, None, None, None),
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("hd wallet created");

    handle_wallet_with(
        WalletArgs {
            command: WalletCommand::ListAddresses {
                wallet_identifier: "limited".into(),
                used: false,
                unused: false,
                limit: Some(1),
            },
        },
        &config,
        &ScriptedUi::new(),
    )
    .await
    .expect("limited listing succeeds");
}

#[tokio::test]
async fn import_prompt_errors_propagate() {
    let dir = TempDir::new().unwrap();
    let config = config_for(&dir);
    seed_identity(&dir, "alice").await;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // A failing password prompt aborts the import immediately.
    let inner = ScriptedUi::new();
    let ui = FailOn::new(&inner, PromptKind::Password);
    let err = handle_wallet_with(import_args("mnemonic", PHRASE, None), &config, &ui)
        .await
        .expect_err("failing password must abort");
    assert!(err.to_string().contains("failing ui: password prompt"));

    // A failing address-count prompt aborts after network selection.
    let inner = ScriptedUi::new()
        .password("import-pass-123")
        .input("bitcoin");
    let ui = FailOn::new(&inner, PromptKind::InputWithDefault);
    let err = handle_wallet_with(import_args("mnemonic", PHRASE, None), &config, &ui)
        .await
        .expect_err("failing count prompt must abort");
    assert!(err.to_string().contains("failing ui: default input prompt"));
}
