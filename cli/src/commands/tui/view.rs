use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Wrap},
    widgets::{Cell, Row},
};

use super::app::AppState;

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
