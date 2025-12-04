use crate::config::CliConfig;
use anyhow::{anyhow, Context, Result};
use clap::Args;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dialoguer::Password;
use persona_core::{
    auth::AuthResult,
    models::{Credential as CoreCredential, Identity as CoreIdentity},
    storage::{CredentialRepository, IdentityRepository, Repository},
    Database, PersonaService,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Wrap},
    widgets::{Cell, Row},
    Terminal,
};
use std::{
    io::{self, Stdout},
    time::{Duration, Instant},
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
    let provider = init_data_provider(config).await?;
    let identity_hint = args.identity.clone();

    tokio::task::spawn_blocking(move || {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build TUI runtime")?;
        run_tui(&runtime, provider, identity_hint)
    })
    .await??;

    Ok(())
}

async fn init_data_provider(config: &CliConfig) -> Result<DataProvider> {
    let db_path = config.get_database_path();
    let db = Database::from_file(db_path.as_ref())
        .await
        .with_context(|| format!("Failed to open database at {}", db_path.display()))?;
    db.migrate()
        .await
        .context("Failed to run database migrations")?;

    let repo_db = db.clone();
    let mut service = PersonaService::new(db)
        .await
        .context("Failed to construct Persona service")?;

    if service
        .has_users()
        .await
        .context("Failed to check workspace users")?
    {
        let password = Password::new()
            .with_prompt("Enter master password to unlock")
            .allow_empty_password(false)
            .interact()
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

enum DataProvider {
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

fn run_tui(runtime: &Runtime, provider: DataProvider, identity_hint: Option<String>) -> Result<()> {
    let mut provider = provider;
    let mut app = runtime.block_on(AppState::load(&mut provider, identity_hint.as_deref()))?;

    let mut terminal = init_terminal()?;
    let result = run_event_loop(runtime, &mut terminal, &mut provider, &mut app);
    restore_terminal(&mut terminal)?;
    result
}

fn init_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode().context("failed to enable raw mode")?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).context("failed to initialize terminal")
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode().context("failed to disable raw mode")?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .context("failed to leave alternate screen")?;
    terminal.show_cursor().context("failed to show cursor")
}

fn run_event_loop(
    runtime: &Runtime,
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    provider: &mut DataProvider,
    app: &mut AppState,
) -> Result<()> {
    const TICK_RATE: Duration = Duration::from_millis(200);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| render_ui(f, app))?;

        if app.should_exit {
            break;
        }

        let timeout = TICK_RATE
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                handle_key(runtime, provider, app, key)?;
            }
        }

        if last_tick.elapsed() >= TICK_RATE {
            last_tick = Instant::now();
        }
    }

    Ok(())
}

fn handle_key(
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
        KeyCode::Char('g') => {
            if app.jump_first() {
                runtime.block_on(app.load_credentials_for_current(provider))?;
            }
        }
        _ => {}
    }

    Ok(())
}

struct IdentityItem {
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

struct CredentialItem {
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

struct AppState {
    identities: Vec<IdentityItem>,
    credentials: Vec<CredentialItem>,
    selected: usize,
    status: String,
    show_help: bool,
    should_exit: bool,
}

impl AppState {
    async fn load(provider: &mut DataProvider, preferred: Option<&str>) -> Result<Self> {
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
        identities.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
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

fn render_ui(f: &mut ratatui::Frame, app: &AppState) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(5),
                Constraint::Length(if app.show_help { 3 } else { 2 }),
            ]
            .as_ref(),
        )
        .split(f.size());

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

fn render_identity_list(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    app: &AppState,
) {
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

fn render_credentials(
    f: &mut ratatui::Frame,
    area: ratatui::prelude::Rect,
    app: &AppState,
) {
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

    let table = Table::new(rows, &[
            Constraint::Percentage(30),
            Constraint::Percentage(15),
            Constraint::Percentage(25),
            Constraint::Percentage(15),
            Constraint::Percentage(15),
        ])
        .header(header)
        .block(Block::default().title("Credentials").borders(Borders::ALL));

    f.render_widget(table, area);
}
