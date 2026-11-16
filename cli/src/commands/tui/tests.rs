use super::*;

use crate::utils::prompt::scripted::ScriptedUi;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use persona_core::models::Identity as CoreIdentity;
use persona_core::storage::Repository;
use tempfile::TempDir;
use tokio::runtime::Runtime;

async fn tui_test_config(dir: &TempDir) -> CliConfig {
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();
    config
}

#[tokio::test]
async fn data_provider_is_direct_without_users() {
    let dir = TempDir::new().unwrap();
    let config = tui_test_config(&dir).await;
    let ui = ScriptedUi::new();

    let provider = init_data_provider(&config, &ui)
        .await
        .expect("userless workspace opens directly");
    assert!(matches!(provider, DataProvider::Direct { .. }));
    assert!(ui.exhausted(), "no prompt consumed");
}

#[tokio::test]
async fn data_provider_unlocks_with_scripted_password() {
    let dir = TempDir::new().unwrap();
    let config = tui_test_config(&dir).await;
    {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
    }

    // Wrong scripted password is rejected.
    let ui = ScriptedUi::new().password("wrong-pin");
    let err = init_data_provider(&config, &ui)
        .await
        .err()
        .expect("wrong password must fail");
    assert!(err.to_string().contains("Authentication failed"));
    assert!(ui.exhausted());

    // Correct scripted password yields the unlocked service provider.
    let ui = ScriptedUi::new().password("master-pin");
    let provider = init_data_provider(&config, &ui)
        .await
        .expect("correct password unlocks");
    assert!(matches!(provider, DataProvider::Service(_)));
    assert!(ui.exhausted());
}

/// Seeded database with two identities; the second has one credential.
async fn seeded_provider(dir: &TempDir) -> (CliConfig, DataProvider) {
    use persona_core::models::Identity as CoreIdentityModel;

    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let db = Database::from_file(config.get_database_path())
        .await
        .unwrap();
    db.migrate().await.unwrap();

    let repo = IdentityRepository::new(db.clone());
    for name in ["alice", "bob"] {
        repo.create(&CoreIdentityModel::new(
            name.to_string(),
            persona_core::models::IdentityType::Personal,
        ))
        .await
        .unwrap();
    }

    let provider = DataProvider::Direct {
        identity_repo: repo,
        credential_repo: CredentialRepository::new(db),
    };
    (config, provider)
}

fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

fn spawn_runtime() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

fn block_on_load(runtime: &Runtime, provider: &mut DataProvider, hint: Option<&str>) -> AppState {
    runtime.block_on(AppState::load(provider, hint)).unwrap()
}

#[test]
fn app_state_loads_identities_sorted_and_reports_counts() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let (_config, mut provider) = runtime.block_on(seeded_provider(&dir));

    let app = block_on_load(&runtime, &mut provider, None);
    let names: Vec<_> = app.identities.iter().map(|i| i.name.as_str()).collect();
    assert_eq!(names, vec!["alice", "bob"]);
    assert_eq!(app.selected, 0);
    assert!(app.status.contains("2 identities loaded"));
    assert!(app.show_help, "help starts visible");
    assert!(!app.should_exit);
}

#[test]
fn app_state_preselect_prefers_name_case_insensitively() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let (_config, mut provider) = runtime.block_on(seeded_provider(&dir));

    let app = block_on_load(&runtime, &mut provider, Some("BOB"));
    assert_eq!(app.selected, 1);

    // Unknown hint keeps the default selection.
    let app = block_on_load(&runtime, &mut provider, Some("carol"));
    assert_eq!(app.selected, 0);
}

#[test]
fn app_state_navigation_wraps_and_jumps() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let (_config, mut provider) = runtime.block_on(seeded_provider(&dir));
    let mut app = block_on_load(&runtime, &mut provider, None);

    assert!(app.select_next());
    assert_eq!(app.selected, 1);
    // Wraps around at the end.
    assert!(app.select_next());
    assert_eq!(app.selected, 0);

    assert!(app.select_previous());
    assert_eq!(app.selected, 1);
    // Wraps backwards past the top.
    assert!(app.select_previous());
    assert_eq!(app.selected, 0);

    assert!(app.jump_last());
    assert_eq!(app.selected, 1);
    assert!(!app.jump_last(), "already at last");
    assert!(app.jump_first());
    assert_eq!(app.selected, 0);
    assert!(!app.jump_first(), "already at first");

    app.toggle_help();
    assert!(!app.show_help);
    app.set_status("custom");
    assert_eq!(app.status, "custom");
    assert_eq!(app.current_identity_name(), Some("alice"));
}

#[test]
fn app_state_empty_workspace_is_reported() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let db = runtime
        .block_on(Database::from_file(config.get_database_path()))
        .unwrap();
    runtime.block_on(db.migrate()).unwrap();
    let mut provider = DataProvider::Direct {
        identity_repo: IdentityRepository::new(db.clone()),
        credential_repo: CredentialRepository::new(db),
    };

    let mut app = block_on_load(&runtime, &mut provider, None);
    assert!(app.identities.is_empty());
    assert!(app.status.contains("No identities found"));
    // Navigation helpers are no-ops on an empty list.
    assert!(!app.select_next());
    assert!(!app.select_previous());
    assert!(!app.jump_first());
    assert!(!app.jump_last());
}

#[test]
fn key_bindings_quit_toggle_and_navigate() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let (_config, mut provider) = runtime.block_on(seeded_provider(&dir));

    let mut app = block_on_load(&runtime, &mut provider, None);

    // Ctrl+C exits.
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('c'), KeyModifiers::CONTROL),
    )
    .unwrap();
    assert!(app.should_exit);
    app.should_exit = false;

    // Plain q exits.
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('q'), KeyModifiers::NONE),
    )
    .unwrap();
    assert!(app.should_exit);
    app.should_exit = false;

    // Escape exits.
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Esc, KeyModifiers::NONE),
    )
    .unwrap();
    assert!(app.should_exit);
    app.should_exit = false;

    // h toggles help twice (back to visible).
    app.show_help = false;
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('h'), KeyModifiers::NONE),
    )
    .unwrap();
    assert!(app.show_help);

    // j / k move the selection; G / g jump.
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('j'), KeyModifiers::NONE),
    )
    .unwrap();
    assert_eq!(app.selected, 1);
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('G'), KeyModifiers::SHIFT),
    )
    .unwrap();
    assert_eq!(app.selected, 1);
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('k'), KeyModifiers::NONE),
    )
    .unwrap();
    assert_eq!(app.selected, 0);
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Down, KeyModifiers::NONE),
    )
    .unwrap();
    assert_eq!(app.selected, 1);
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Up, KeyModifiers::NONE),
    )
    .unwrap();
    assert_eq!(app.selected, 0);
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('g'), KeyModifiers::SHIFT),
    )
    .unwrap();
    assert_eq!(app.selected, 1);
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('g'), KeyModifiers::NONE),
    )
    .unwrap();
    assert_eq!(app.selected, 0);

    // r refreshes while keeping the current identity selected.
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('j'), KeyModifiers::NONE),
    )
    .unwrap();
    handle_key(
        &runtime,
        &mut provider,
        &mut app,
        key(KeyCode::Char('r'), KeyModifiers::NONE),
    )
    .unwrap();
    assert_eq!(app.selected, 1);
    assert_eq!(app.status, "Workspace reloaded");
}

#[test]
fn render_ui_draws_header_identities_and_help() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let (_config, mut provider) = runtime.block_on(seeded_provider(&dir));
    let app = block_on_load(&runtime, &mut provider, None);

    let backend = ratatui::backend::TestBackend::new(80, 24);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render_ui(f, &app)).unwrap();

    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("Persona TUI"));
    assert!(text.contains("Identities"));
    assert!(text.contains("Credentials"));
    assert!(text.contains("alice"));
    assert!(text.contains("bob"));
    assert!(text.contains("identities loaded"));
    assert!(text.contains("q: quit"));
}

#[test]
fn render_ui_hides_help_and_reports_empty_identity_list() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let db = runtime
        .block_on(Database::from_file(config.get_database_path()))
        .unwrap();
    runtime.block_on(db.migrate()).unwrap();
    let mut provider = DataProvider::Direct {
        identity_repo: IdentityRepository::new(db.clone()),
        credential_repo: CredentialRepository::new(db),
    };

    let mut app = block_on_load(&runtime, &mut provider, None);
    app.toggle_help(); // hide help footer

    let backend = ratatui::backend::TestBackend::new(80, 24);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render_ui(f, &app)).unwrap();

    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("No identities found"));
    assert!(!text.contains("q: quit"), "help line hidden");
}

#[test]
fn service_provider_lists_identities_and_credentials() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let (mut provider, alice_id) = runtime.block_on(async {
        let mut config = CliConfig::default();
        config.workspace.path = dir.path().to_path_buf();
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let mut service = crate::commands::service::new_service(db).await.unwrap();
        service.initialize_user("master-pin").await.unwrap();
        let alice = service
            .create_identity_full(CoreIdentity::new(
                "alice".to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();

        let ui = ScriptedUi::new().password("master-pin");
        let provider = init_data_provider(&config, &ui).await.unwrap();
        assert!(ui.exhausted());
        assert!(matches!(provider, DataProvider::Service(_)));
        (provider, alice.id)
    });

    let (identities, credentials) = runtime.block_on(async {
        let identities = provider.identities().await.unwrap();
        let credentials = provider.credentials(&alice_id).await.unwrap();
        (identities, credentials)
    });
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].name, "alice");
    assert!(credentials.is_empty());
}

#[test]
fn key_navigation_without_identities_skips_credential_reload() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let db = runtime
        .block_on(Database::from_file(config.get_database_path()))
        .unwrap();
    runtime.block_on(db.migrate()).unwrap();
    let mut provider = DataProvider::Direct {
        identity_repo: IdentityRepository::new(db.clone()),
        credential_repo: CredentialRepository::new(db),
    };

    let mut app = block_on_load(&runtime, &mut provider, None);
    assert!(app.identities.is_empty());

    // j/k/g/G on an empty list are no-ops: the credential reload is
    // skipped because the selection never moved.
    for code in [
        KeyCode::Char('j'),
        KeyCode::Char('k'),
        KeyCode::Char('g'),
        key(KeyCode::Char('G'), KeyModifiers::SHIFT).code,
    ] {
        handle_key(
            &runtime,
            &mut provider,
            &mut app,
            key(code, KeyModifiers::NONE),
        )
        .unwrap();
    }
    assert!(!app.should_exit);

    // Reloading credentials with no identities clears the table.
    runtime
        .block_on(app.load_credentials_for_current(&mut provider))
        .unwrap();
    assert!(app.credentials.is_empty());
}

#[test]
fn reload_clamps_selection_when_identities_shrink() {
    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let (config, mut provider) = runtime.block_on(seeded_provider(&dir));
    let mut app = block_on_load(&runtime, &mut provider, None);

    // Drop "bob" so the list shrinks under the selection.
    let bob_id = runtime.block_on(async {
        let repo = IdentityRepository::new(
            Database::from_file(config.get_database_path())
                .await
                .unwrap(),
        );
        let bob = repo.find_by_name("bob").await.unwrap().unwrap();
        repo.delete(&bob.id).await.unwrap();
        bob.id
    });

    // An out-of-range selection without a hint is clamped to the last
    // remaining identity.
    app.selected = 5;
    runtime.block_on(app.reload(&mut provider, None)).unwrap();
    assert_eq!(app.selected, 0);

    // A hint that no longer resolves falls back to the clamp as well.
    app.selected = 1;
    runtime
        .block_on(app.reload(&mut provider, Some("bob")))
        .unwrap();
    assert_eq!(app.selected, 0, "clamped after {bob_id} was deleted");
}

#[test]
fn credential_rows_tags_and_inactive_styling_render() {
    use persona_core::models::{Credential as CoreCredentialModel, CredentialType, SecurityLevel};

    let runtime = spawn_runtime();
    let dir = TempDir::new().unwrap();
    let mut config = CliConfig::default();
    config.workspace.path = dir.path().to_path_buf();
    let (identity_repo, credential_repo) = runtime.block_on(async {
        let db = Database::from_file(config.get_database_path())
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let repo = IdentityRepository::new(db.clone());
        for name in ["alice", "bob"] {
            repo.create(&CoreIdentity::new(
                name.to_string(),
                persona_core::models::IdentityType::Personal,
            ))
            .await
            .unwrap();
        }

        // alice carries tags and a credential with a username.
        let mut alice = repo.find_by_name("alice").await.unwrap().unwrap();
        alice.tags = vec!["ops".to_string(), "oncall".to_string()];
        repo.update(&alice).await.unwrap();

        let mut cred = CoreCredentialModel::new(
            alice.id,
            "GitHub".to_string(),
            CredentialType::Password,
            SecurityLevel::High,
            b"secret".to_vec(),
            None,
        );
        cred.username = Some("alice@example.com".to_string());
        let cred_repo = CredentialRepository::new(db.clone());
        cred_repo.create(&cred).await.unwrap();

        // bob is inactive → the dimmed styling branch renders.
        let mut bob = repo.find_by_name("bob").await.unwrap().unwrap();
        bob.is_active = false;
        repo.update(&bob).await.unwrap();
        (repo, cred_repo)
    });

    let mut provider = DataProvider::Direct {
        identity_repo,
        credential_repo,
    };
    let app = block_on_load(&runtime, &mut provider, None);
    assert_eq!(app.credentials.len(), 1);
    assert_eq!(app.credentials[0].name, "GitHub");
    assert_eq!(app.credentials[0].username, "alice@example.com");

    // Wide enough that the username column is not truncated.
    let backend = ratatui::backend::TestBackend::new(160, 24);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| render_ui(f, &app)).unwrap();

    let text: String = terminal
        .backend()
        .buffer()
        .content
        .iter()
        .map(|cell| cell.symbol())
        .collect();
    assert!(text.contains("GitHub"));
    assert!(text.contains("alice@example.com"));
    assert!(text.contains("ops, oncall"));
}
