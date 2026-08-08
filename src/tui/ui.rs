//! TUI rendering (see `08` §2.3, §2.8).
//!
//! Single view: title bar (count + quit hint), list area (ListState), footer
//! (keybindings). Popups render as centered clear areas over the main view.
//! Colors follow the terminal default (no hardcoded palette).

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, Mode};

/// Render the full TUI for `app`.
pub fn draw(app: &mut App, frame: &mut Frame) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(1),    // list
            Constraint::Length(2), // footer (status line + keybinding hints)
        ])
        .split(area);

    draw_title(frame, chunks[0], app);
    draw_list(frame, chunks[1], app);
    draw_footer(frame, chunks[2], app);

    match &app.mode {
        Mode::ShowPassword { reveal } => draw_show_password(frame, app, *reveal),
        Mode::AddPrompt | Mode::EditPrompt | Mode::RenamePrompt => draw_prompt(frame, app),
        Mode::ConfirmDelete => {
            let id = app.selected_id().unwrap_or("(none)");
            let lines = vec![
                Line::from(format!("Delete '{id}'?")),
                Line::from(""),
                Line::from(Span::styled(
                    "⚠ This action is irreversible.",
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from("[Enter] confirm delete   [Esc] cancel"),
            ];
            draw_centered_msg_strings(frame, "Confirm Delete", lines);
        }
        Mode::SyncMenu => draw_centered_msg(
            frame,
            "Sync",
            vec!["[p] push  [u] pull  [t] status", "[Esc] cancel"],
        ),
        Mode::SyncProgress { msg } => draw_centered_msg(frame, "Sync", vec![msg.as_str()]),
        Mode::Help => draw_help(frame),
        Mode::Search => draw_search_hint(frame, app),
        Mode::Normal => {}
    }
}

fn draw_title(frame: &mut Frame, area: Rect, app: &App) {
    let count = app.items.len();
    let title = format!(" avpm — Vault Secrets ({count}) ");
    let hint = "[q] quit";
    let line = Line::from(vec![
        Span::styled(title, Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::raw(hint),
    ]);
    let block = Block::default().borders(Borders::ALL);
    let p = Paragraph::new(line).block(block).alignment(Alignment::Left);
    frame.render_widget(p, area);
}

fn draw_list(frame: &mut Frame, area: Rect, app: &mut App) {
    // Snapshot the ids to end the immutable borrow of `app` before we mutably
    // borrow `app.state` for the stateful render. We deliberately render id
    // only — the keyring exposes no per-secret "updated_at" metadata, so any
    // timestamp would be forged data (acceptance finding #14).
    let ids: Vec<String> = app.filtered_items().iter().map(|i| i.id.clone()).collect();
    let items: Vec<ListItem> = ids
        .into_iter()
        .map(|id| ListItem::new(Line::from(vec![Span::raw(id)])))
        .collect();
    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" Vault IDs "))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_symbol("▸ ");
    frame.render_stateful_widget(list, area, &mut app.state);
}

fn draw_footer(frame: &mut Frame, area: Rect, app: &App) {
    // Two rows: a status/message line (operation feedback, clipboard state)
    // and a contextual keybinding hint that changes with the current mode
    // (lazygit-style — only show keys that apply right now).
    let status = app.message.clone().unwrap_or_default();
    let hints = contextual_hints(&app.mode);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);
    // Status line (no border; dim if empty so it doesn't distract).
    let status_style = if status.is_empty() {
        Style::default().add_modifier(Modifier::DIM)
    } else {
        Style::default()
    };
    let status_line = if status.is_empty() {
        Line::from(" avpm")
    } else {
        Line::from(Span::styled(status, status_style))
    };
    frame.render_widget(
        Paragraph::new(status_line).style(Style::default()),
        chunks[0],
    );
    // Keybinding hints.
    frame.render_widget(
        Paragraph::new(Line::from(hints)).style(Style::default()),
        chunks[1],
    );
}

/// Mode-specific keybinding hints (lazygit-style contextual footer).
fn contextual_hints(mode: &Mode) -> String {
    match mode {
        Mode::Normal => {
            "[y] copy  [Enter] show  [e] edit  [a] add  [d] delete  [/] search  [s] sync  [?] help  [q] quit"
                .to_string()
        }
        Mode::ShowPassword { reveal } => {
            if *reveal {
                "[Space] hide  [y] copy  [Esc] back".to_string()
            } else {
                "[Space] reveal  [y] copy  [Esc] back".to_string()
            }
        }
        Mode::Search => "type to filter  [Esc] cancel".to_string(),
        Mode::AddPrompt | Mode::EditPrompt | Mode::RenamePrompt => {
            "[Enter] confirm  [Esc] cancel".to_string()
        }
        Mode::ConfirmDelete => "[Enter] confirm delete  [Esc] cancel".to_string(),
        Mode::SyncMenu => "[p] push  [u] pull  [t] status  [Esc] cancel".to_string(),
        Mode::SyncProgress { .. } => "[Esc] continue".to_string(),
        Mode::Help => "[any key] close".to_string(),
    }
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let pop = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length((area.height - height) / 2),
            Constraint::Length(height),
            Constraint::Min(0),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length((area.width - width) / 2),
            Constraint::Length(width),
            Constraint::Min(0),
        ])
        .split(pop[1])[1]
}

fn draw_centered_msg(frame: &mut Frame, title: &str, lines: Vec<&str>) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let height = (lines.len() as u16) + 2;
    let r = centered_rect(area, 60, height);
    let body: Vec<Line> = lines.into_iter().map(Line::from).collect();
    let p = Paragraph::new(body)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(p, r);
}

fn draw_show_password(frame: &mut Frame, app: &App, reveal: bool) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let r = centered_rect(area, 64, 6);
    let id = app.selected_id().unwrap_or("(none)");
    let (display, hint) = match &app.shown_secret {
        Some(s) if reveal => (
            s.as_str().to_string(),
            "[Space] hide   [Esc] back".to_string(),
        ),
        Some(s) => (
            "•".repeat(s.len()),
            "[Space] reveal   [Esc] back".to_string(),
        ),
        None => (
            String::new(),
            "(no password loaded; press Esc and try again)".to_string(),
        ),
    };
    let lines = vec![
        Line::from(format!("Vault: {id}")),
        Line::from(""),
        Line::from(display),
        Line::from(""),
        Line::from(hint),
    ];
    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Password "))
        .wrap(Wrap { trim: false });
    frame.render_widget(p, r);
}

fn draw_prompt(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let r = centered_rect(area, 60, 4);
    let (title, hint) = match app.mode {
        Mode::AddPrompt => ("Add", "new vault-id"),
        Mode::EditPrompt => ("Edit", "new password (will prompt after)"),
        Mode::RenamePrompt => ("Rename", "new vault-id"),
        _ => ("Input", ""),
    };
    // Horizontal scroll so long inputs stay visible around the cursor
    // (tui-input provides visual_scroll for exactly this).
    let inner_width = r.width.saturating_sub(2) as usize; // minus borders
    let scroll = app.input.visual_scroll(inner_width);
    let lines = vec![
        Line::from(format!("{title}: enter {hint}")),
        Line::from(""),
        Line::from(app.input.value()),
    ];
    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        )
        .scroll((0, scroll as u16));
    frame.render_widget(p, r);
    // Place the terminal cursor where tui-input says it is, so the user sees
    // a real blinking cursor and can use Left/Right/Ctrl-A/E naturally.
    let cursor_x = r.x + 1 + (app.input.visual_cursor().saturating_sub(scroll)) as u16;
    let cursor_y = r.y + 1 + 2; // two lines down (label + blank)
    frame.set_cursor_position((cursor_x, cursor_y));
}

fn draw_centered_msg_strings(frame: &mut Frame, title: &str, lines: Vec<Line>) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let height = (lines.len() as u16) + 2;
    let r = centered_rect(area, 60, height);
    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(p, r);
}

fn draw_help(frame: &mut Frame) {
    let lines = vec![
        Line::from("avpm TUI keybindings"),
        Line::from(""),
        Line::from("j/k or ↓/↑   move selection"),
        Line::from("g / G         top / bottom"),
        Line::from("Enter         show password (hold Space to reveal)"),
        Line::from("e             edit selected password"),
        Line::from("a / n         add new vault-id"),
        Line::from("d             delete selected"),
        Line::from("r             rename selected"),
        Line::from("/             search / filter"),
        Line::from("s             sync menu (push/pull/status)"),
        Line::from("?             this help"),
        Line::from("q / Esc       quit / cancel"),
        Line::from(""),
        Line::from("[any key] close"),
    ];
    draw_centered_msg_strings(frame, "Help", lines);
}

fn draw_search_hint(frame: &mut Frame, app: &App) {
    let area = frame.area();
    let r = Rect {
        x: 0,
        y: 0,
        width: area.width,
        height: 3,
    };
    let line = Line::from(format!("/{}", app.search));
    let p = Paragraph::new(line)
        .block(Block::default().borders(Borders::ALL).title(" Search "))
        .alignment(Alignment::Left);
    frame.render_widget(p, r);
}
