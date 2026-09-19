use crate::utils::prompt::{PromptUi, TerminalUi};
use crate::{config::CliConfig, utils::core_ext::CoreResultExt};
use anyhow::{anyhow, Context, Result};
use clap::Args;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use persona_core::{
    auth::AuthResult,
    models::{Credential as CoreCredential, Identity as CoreIdentity},
    storage::{CredentialRepository, IdentityRepository, Repository},
    Database, PersonaService,
};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Wrap},
    widgets::{Cell, Row},
};

use tokio::runtime::{Builder, Runtime};
use uuid::Uuid;

#[derive(Args, Clone)]
pub struct TuiArgs {
    /// Preselect an identity by name
    #[arg(short, long)]
    pub identity: Option<String>,
}

pub async fn execute(args: TuiArgs, config: &CliConfig) -> Result<()> {
    let provider = init_data_provider(config, &TerminalUi).await?;
    let identity_hint = args.identity.clone();

    tokio::task::spawn_blocking(move || {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build TUI runtime")?;
        crate::commands::tui_runtime::run_tui(&runtime, provider, identity_hint)
    })
    .await??;

    Ok(())
}

async fn init_data_provider(config: &CliConfig, ui: &dyn PromptUi) -> Result<DataProvider> {
    let db_path = config.get_database_path();
    let db: persona_core::Database = Database::from_file::<std::path::PathBuf>(db_path.to_owned())
        .await
        .into_anyhow()
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
    db.migrate()
        .await
        .context("Failed to run database migrations")?;

    let repo_db = db.clone();
    let mut service = crate::commands::service::new_service(db)
        .await
        .context("Failed to construct Persona service")?;

    if service
        .has_users()
        .await
        .context("Failed to check workspace users")?
    {
        let password = ui
            .password("Enter master password to unlock", false, None)
            .context("Failed to read password")?;

        match service
            .authenticate_user(&password)
            .await
            .context("Authentication failed")?
        {
            AuthResult::Success => Ok(DataProvider::Service(service)),
            other => Err(anyhow!("Authentication failed: {:?}", other)),
        }
    } else {
        Ok(DataProvider::Direct {
            identity_repo: IdentityRepository::new(repo_db.clone()),
            credential_repo: CredentialRepository::new(repo_db),
        })
    }
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum DataProvider {
    Service(PersonaService),
    Direct {
        identity_repo: IdentityRepository,
        credential_repo: CredentialRepository,
    },
}

impl DataProvider {
    async fn identities(&mut self) -> Result<Vec<CoreIdentity>> {
        match self {
            DataProvider::Service(service) => service
                .get_identities()
                .await
                .map_err(|e| anyhow!("Failed to load identities: {}", e)),
            DataProvider::Direct { identity_repo, .. } => identity_repo
                .find_all()
                .await
                .map_err(|e| anyhow!("Failed to load identities: {}", e)),
        }
    }

    async fn credentials(&mut self, identity_id: &Uuid) -> Result<Vec<CoreCredential>> {
        match self {
            DataProvider::Service(service) => service
                .get_credentials_for_identity(identity_id)
                .await
                .map_err(|e| anyhow!("Failed to load credentials: {}", e)),
            DataProvider::Direct {
                credential_repo, ..
            } => credential_repo
                .find_by_identity(identity_id)
                .await
                .map_err(|e| anyhow!("Failed to load credentials: {}", e)),
        }
    }
}

pub(crate) fn handle_key(
    runtime: &Runtime,
    provider: &mut DataProvider,
    app: &mut AppState,
    key: KeyEvent,
) -> Result<()> {
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        if matches!(key.code, KeyCode::Char('c') | KeyCode::Char('d')) {
            app.should_exit = true;
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_exit = true,
        KeyCode::Char('h') | KeyCode::Char('?') => app.toggle_help(),
        KeyCode::Char('r') => {
            runtime.block_on(app.refresh(provider))?;
            app.set_status("Workspace reloaded");
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.select_next() {
                runtime.block_on(app.load_credentials_for_current(provider))?;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.select_previous() {
                runtime.block_on(app.load_credentials_for_current(provider))?;
            }
        }
        KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::SHIFT) => {
            if app.jump_last() {
                runtime.block_on(app.load_credentials_for_current(provider))?;
            }
        }
        KeyCode::Char('g') if app.jump_first() => {
            runtime.block_on(app.load_credentials_for_current(provider))?;
        }
        _ => {}
    }

    Ok(())
}

pub(crate) struct IdentityItem {
    id: Uuid,
    name: String,
    identity_type: String,
    tags: Vec<String>,
    active: bool,
}

impl From<CoreIdentity> for IdentityItem {
    fn from(value: CoreIdentity) -> Self {
        Self {
            id: value.id,
            name: value.name,
            identity_type: value.identity_type.to_string(),
            tags: value.tags,
            active: value.is_active,
        }
    }
}

pub(crate) struct CredentialItem {
    name: String,
    credential_type: String,
    username: String,
    security: String,
    updated: String,
}

impl From<CoreCredential> for CredentialItem {
    fn from(value: CoreCredential) -> Self {
        let username = value.username.unwrap_or_else(|| "-".to_string());
        let updated = value.updated_at.format("%Y-%m-%d %H:%M").to_string();
        Self {
            name: value.name,
            credential_type: value.credential_type.to_string(),
            username,
            security: value.security_level.to_string(),
            updated,
        }
    }
}

pub(crate) struct AppState {
    pub(crate) identities: Vec<IdentityItem>,
    pub(crate) credentials: Vec<CredentialItem>,
    pub(crate) selected: usize,
    pub(crate) status: String,
    pub(crate) show_help: bool,
    pub(crate) should_exit: bool,
}

impl AppState {
    pub(crate) async fn load(provider: &mut DataProvider, preferred: Option<&str>) -> Result<Self> {
        let mut state = Self {
            identities: Vec::new(),
            credentials: Vec::new(),
            selected: 0,
            status: String::from("Welcome to Persona TUI"),
            show_help: true,
            should_exit: false,
        };
        state.reload(provider, preferred).await?;
        Ok(state)
    }

    async fn reload(&mut self, provider: &mut DataProvider, preferred: Option<&str>) -> Result<()> {
        let mut identities = provider.identities().await?;
        identities.sort_by_key(|a| a.name.to_lowercase());
        self.identities = identities.into_iter().map(IdentityItem::from).collect();

        if self.identities.is_empty() {
            self.selected = 0;
            self.credentials.clear();
            self.status = "No identities found. Use `persona add` to create one.".to_string();
            return Ok(());
        }

        if let Some(name) = preferred {
            if let Some(pos) = self
                .identities
                .iter()
                .position(|id| id.name.eq_ignore_ascii_case(name))
            {
                self.selected = pos;
            } else if self.selected >= self.identities.len() {
                self.selected = self.identities.len() - 1;
            }
        } else if self.selected >= self.identities.len() {
            self.selected = self.identities.len() - 1;
        }

        self.load_credentials_for_current(provider).await?;
        self.status = format!("{} identities loaded", self.identities.len());
        Ok(())
    }

    async fn refresh(&mut self, provider: &mut DataProvider) -> Result<()> {
        let preferred = self.current_identity_name().map(str::to_string);
        self.reload(provider, preferred.as_deref()).await
    }

    async fn load_credentials_for_current(&mut self, provider: &mut DataProvider) -> Result<()> {
        if let Some(identity) = self.identities.get(self.selected) {
            let credentials = provider.credentials(&identity.id).await?;
            self.credentials = credentials.into_iter().map(CredentialItem::from).collect();
            self.status = format!(
                "{} credential(s) for {}",
                self.credentials.len(),
                identity.name
            );
        } else {
            self.credentials.clear();
        }

        Ok(())
    }

    fn select_next(&mut self) -> bool {
        if self.identities.is_empty() {
            return false;
        }
        let prev = self.selected;
        self.selected = (self.selected + 1) % self.identities.len();
        prev != self.selected
    }

    fn select_previous(&mut self) -> bool {
        if self.identities.is_empty() {
            return false;
        }
        let prev = self.selected;
        if self.selected == 0 {
            self.selected = self.identities.len() - 1;
        } else {
            self.selected -= 1;
        }
        prev != self.selected
    }

    fn jump_first(&mut self) -> bool {
        if self.identities.is_empty() {
            return false;
        }
        let changed = self.selected != 0;
        self.selected = 0;
        changed
    }

    fn jump_last(&mut self) -> bool {
        if self.identities.is_empty() {
            return false;
        }
        let last = self.identities.len() - 1;
        let changed = self.selected != last;
        self.selected = last;
        changed
    }

    fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    fn set_status<S: Into<String>>(&mut self, status: S) {
        self.status = status.into();
    }

    fn current_identity_name(&self) -> Option<&str> {
        self.identities
            .get(self.selected)
            .map(|id| id.name.as_str())
    }
}

pub(crate) fn render_ui(f: &mut ratatui::Frame, app: &AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(if app.show_help { 4 } else { 3 }),
            ]
            .as_ref(),
        )
        .split(f.area());

    let header = Paragraph::new(vec![
        Line::from(Span::styled(
            "Persona TUI",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("Master your digital identity.")),
    ])
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(header, layout[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)].as_ref())
        .split(layout[1]);

    render_identity_list(f, body[0], app);
    render_credentials(f, body[1], app);

    let mut footer_lines = vec![Line::from(Span::raw(app.status.clone()))];
    if app.show_help {
        footer_lines.push(Line::from(Span::styled(
            "q: quit  •  r: reload  •  ↑/↓ or j/k: navigate  •  g/G: jump  •  h: toggle help",
            Style::default().fg(Color::Gray),
        )));
    }

    let status = Paragraph::new(footer_lines)
        .wrap(Wrap { trim: true })
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(status, layout[2]);
}

fn render_identity_list(f: &mut ratatui::Frame, area: ratatui::prelude::Rect, app: &AppState) {
    let items: Vec<ListItem> = if app.identities.is_empty() {
        vec![ListItem::new("No identities found")]
    } else {
        app.identities
            .iter()
            .map(|identity| {
                let mut line = Vec::new();
                line.push(Span::styled(
                    identity.name.clone(),
                    Style::default()
                        .fg(if identity.active {
                            Color::Green
                        } else {
                            Color::DarkGray
                        })
                        .add_modifier(Modifier::BOLD),
                ));
                line.push(Span::raw(format!("  ({})", identity.identity_type)));
                if !identity.tags.is_empty() {
                    line.push(Span::raw(format!("  • {}", identity.tags.join(", "))));
                }
                ListItem::new(Line::from(line))
            })
            .collect()
    };

    let mut state = ratatui::widgets::ListState::default();
    if !app.identities.is_empty() {
        state.select(Some(app.selected));
    }

    let list = List::new(items)
        .block(Block::default().title("Identities").borders(Borders::ALL))
        .highlight_symbol("› ")
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    f.render_stateful_widget(list, area, &mut state);
}

fn render_credentials(f: &mut ratatui::Frame, area: ratatui::prelude::Rect, app: &AppState) {
    let header = Row::new(vec![
        Cell::from("Name"),
        Cell::from("Type"),
        Cell::from("Username"),
        Cell::from("Security"),
        Cell::from("Updated"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = if app.credentials.is_empty() {
        vec![Row::new(vec![Cell::from(
            "No credentials for this identity",
        )])]
    } else {
        app.credentials
            .iter()
            .map(|cred| {
                Row::new(vec![
                    Cell::from(cred.name.clone()),
                    Cell::from(cred.credential_type.clone()),
                    Cell::from(cred.username.clone()),
                    Cell::from(cred.security.clone()),
                    Cell::from(cred.updated.clone()),
                ])
            })
            .collect()
    };

    let table = Table::new(
        rows,
        &[
            Constraint::Percentage(30),
            Constraint::Percentage(15),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
        ],
    )
    .header(header)
    .block(Block::default().title("Credentials").borders(Borders::ALL));

    f.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::prompt::scripted::ScriptedUi;
    use tempfile::TempDir;

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

    fn block_on_load(
        runtime: &Runtime,
        provider: &mut DataProvider,
        hint: Option<&str>,
    ) -> AppState {
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
        use persona_core::models::{
            Credential as CoreCredentialModel, CredentialType, SecurityLevel,
        };

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
}
