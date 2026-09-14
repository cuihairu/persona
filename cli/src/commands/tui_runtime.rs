//! Terminal lifecycle for the interactive TUI.
//!
//! These functions drive a real terminal — alternate screen, raw mode,
//! crossterm key events — and cannot execute under a test harness. They are
//! excluded from coverage measurement via `--ignore-filename-regex`
//! (`cli/src/commands/tui_runtime.rs`). Everything testable (state, key
//! handling, rendering) lives in [`crate::commands::tui`].

use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::{
    io::{self, Stdout},
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;

use crate::commands::tui::{handle_key, render_ui, AppState, DataProvider};

pub(crate) fn run_tui(
    runtime: &Runtime,
    provider: DataProvider,
    identity_hint: Option<String>,
) -> Result<()> {
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
