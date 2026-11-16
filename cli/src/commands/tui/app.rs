use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::runtime::Runtime;

use super::data::{CredentialItem, DataProvider, IdentityItem};

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

    pub(super) async fn reload(
        &mut self,
        provider: &mut DataProvider,
        preferred: Option<&str>,
    ) -> Result<()> {
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

    pub(super) async fn load_credentials_for_current(
        &mut self,
        provider: &mut DataProvider,
    ) -> Result<()> {
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

    pub(super) fn select_next(&mut self) -> bool {
        if self.identities.is_empty() {
            return false;
        }
        let prev = self.selected;
        self.selected = (self.selected + 1) % self.identities.len();
        prev != self.selected
    }

    pub(super) fn select_previous(&mut self) -> bool {
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

    pub(super) fn jump_first(&mut self) -> bool {
        if self.identities.is_empty() {
            return false;
        }
        let changed = self.selected != 0;
        self.selected = 0;
        changed
    }

    pub(super) fn jump_last(&mut self) -> bool {
        if self.identities.is_empty() {
            return false;
        }
        let last = self.identities.len() - 1;
        let changed = self.selected != last;
        self.selected = last;
        changed
    }

    pub(super) fn toggle_help(&mut self) {
        self.show_help = !self.show_help;
    }

    pub(super) fn set_status<S: Into<String>>(&mut self, status: S) {
        self.status = status.into();
    }

    pub(super) fn current_identity_name(&self) -> Option<&str> {
        self.identities
            .get(self.selected)
            .map(|id| id.name.as_str())
    }
}
