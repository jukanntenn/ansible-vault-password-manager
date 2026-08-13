//! TUI rendering.
//!
//! Single view: title bar (count + quit hint), list area (ListState), footer
//! (status line + keybinding hints). Popups render as centered panels over the
//! main view. The Form popup renders one [`super::input::TextField`] per field
//! with the focused field highlighted; password fields are masked at the field
//! level (see [`super::app`]).

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use super::app::{App, FormKind, Mode};

/// Render the full TUI for `app`.
pub fn draw<S: crate::vault::VaultStore>(app: &mut App<'_, S>, frame: &mut Frame) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // title
            Constraint::Min(1),    // list
            Constraint::Length(2), // footer
        ])
        .split(area);

    draw_title(frame, chunks[0], app);
    draw_list(frame, chunks[1], app);
    draw_footer(frame, chunks[2], app);

    match &app.mode {
        Mode::ShowPassword { reveal } => draw_show_password(frame, app, *reveal),
        Mode::Form { kind, focus } => draw_form(frame, app, *kind, *focus),
        Mode::ConfirmDelete => draw_confirm_delete(frame, app),
        Mode::SyncMenu => draw_centered_msg(
            frame,
            "Sync",
            vec![
                "Run from the shell (passphrase prompt):",
                "  avpm sync push | pull | status",
                "[Esc] close",
            ],
        ),
        Mode::Help => draw_help(frame),
        Mode::Search => draw_search_hint(frame, app),
        Mode::Normal => {}
    }
}

fn draw_title<S: crate::vault::VaultStore>(frame: &mut Frame, area: Rect, app: &App<'_, S>) {
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

fn draw_list<S: crate::vault::VaultStore>(frame: &mut Frame, area: Rect, app: &mut App<'_, S>) {
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

fn draw_footer<S: crate::vault::VaultStore>(frame: &mut Frame, area: Rect, app: &App<'_, S>) {
    let status = app.message.clone().unwrap_or_default();
    let hints = contextual_hints(&app.mode);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Length(1)])
        .split(area);
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
    frame.render_widget(Paragraph::new(status_line), chunks[0]);
    frame.render_widget(
        Paragraph::new(Line::from(hints)).style(Style::default().add_modifier(Modifier::BOLD)),
        chunks[1],
    );
}

/// Mode-specific keybinding hints (contextual footer).
fn contextual_hints(mode: &Mode) -> String {
    match mode {
        Mode::Normal => {
            "[y] copy  [Enter] show  [e] edit  [a] add  [d] delete  [r] rename  [/] search  [?] help  [q] quit"
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
        Mode::Form { kind, .. } => {
            let gen = if matches!(kind, FormKind::Add | FormKind::Edit) {
                "  [g] generate"
            } else {
                ""
            };
            format!("[Tab] next field{gen}  [Enter] submit  [Esc] cancel")
        }
        Mode::ConfirmDelete => "[Enter] confirm delete  [Esc] cancel".to_string(),
        Mode::SyncMenu => "[Esc] close".to_string(),
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
    let r = centered_rect(area, 64, height);
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

fn draw_show_password<S: crate::vault::VaultStore>(
    frame: &mut Frame,
    app: &App<'_, S>,
    reveal: bool,
) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let r = centered_rect(area, 64, 7);
    let id = app.selected_id().unwrap_or("(none)");
    let (display, hint) = match &app.shown_secret {
        Some(s) if reveal => (s.as_str().to_string(), "[Space] hide"),
        Some(s) => ("•".repeat(s.as_str().chars().count()), "[Space] reveal"),
        None => (
            String::new(),
            "(no password loaded; press Esc and try again)",
        ),
    };
    let mut lines = vec![
        Line::from(format!("Vault: {id}")),
        Line::from(""),
        Line::from(display),
        Line::from(""),
    ];
    // Hint line: bold so it stands out from the password area.
    lines.push(Line::from(Span::styled(
        format!("{hint}   [y] copy   [Esc] back"),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Password "))
        .wrap(Wrap { trim: false });
    frame.render_widget(p, r);
}

/// Render the add/edit/rename form popup. Each field is a labeled input;
/// the focused field gets a highlighted border.
fn draw_form<S: crate::vault::VaultStore>(
    frame: &mut Frame,
    app: &mut App<'_, S>,
    kind: FormKind,
    focus: usize,
) {
    let area = frame.area();
    frame.render_widget(Clear, area);
    let title = match kind {
        FormKind::Add => "Add Vault",
        FormKind::Edit => "Edit Password",
        FormKind::Rename => "Rename Vault ID",
    };
    let n = kind.field_count();
    // Each field: 1 label line + 3 textarea lines (top border + 1 content +
    // bottom border) = 4, plus a title line.
    let height = (n as u16) * 4 + 1;
    let r = centered_rect(area, 60, height);
    // Stack: title, then per-field [label, textarea].
    let mut constraints = vec![Constraint::Length(1)]; // title line
    for _ in 0..n {
        constraints.push(Constraint::Length(1)); // label
        constraints.push(Constraint::Length(3)); // textarea: border + 1 content + border
    }
    let rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(r);

    // Title.
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            format!(" {title} "),
            Style::default().add_modifier(Modifier::BOLD),
        ))),
        rects[0],
    );

    // Set each field's border style (focused vs unfocused).
    for i in 0..n {
        let border_style = if i == focus {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        };
        if let Some(field) = app.form_fields_mut().get_mut(i) {
            field.set_block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style),
            );
        }
    }

    // Render labels and fields.
    for i in 0..n {
        let label_rect = rects[1 + i * 2];
        let ta_rect = rects[1 + i * 2 + 1];
        let label = kind.field_label(i);
        let label_style = if i == focus {
            Style::default().add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(label, label_style))),
            label_rect,
        );
        if let Some(field) = app.form_fields().get(i) {
            frame.render_widget(field, ta_rect);
        }
    }

    // Position the terminal cursor inside the focused field so the user
    // sees a blinking cursor and text editing works as expected.
    if let Some(field) = app.form_fields().get(focus) {
        let ta_rect = rects[1 + focus * 2 + 1];
        let cursor_x = ta_rect.x + 1 + field.cursor_col() as u16;
        let cursor_y = ta_rect.y + 1;
        frame.set_cursor_position((cursor_x, cursor_y));
    }
}

fn draw_confirm_delete<S: crate::vault::VaultStore>(frame: &mut Frame, app: &App<'_, S>) {
    let id = app.selected_id().unwrap_or("(none)");
    let lines = vec![
        Line::from(format!("Delete '{id}'?")),
        Line::from(""),
        Line::from(Span::styled(
            "⚠ This action is irreversible.",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "[Enter] confirm delete   [Esc] cancel",
            Style::default().add_modifier(Modifier::BOLD),
        )),
    ];
    let area = frame.area();
    frame.render_widget(Clear, area);
    let height = (lines.len() as u16) + 2;
    let r = centered_rect(area, 60, height);
    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Confirm Delete "),
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
        Line::from("Enter         show password (Space to reveal)"),
        Line::from("e             edit selected password"),
        Line::from("a / n         add new vault-id"),
        Line::from("d             delete selected"),
        Line::from("r             rename selected"),
        Line::from("/             search / filter"),
        Line::from("y             copy password to clipboard"),
        Line::from("?             this help"),
        Line::from("q / Esc       quit / cancel"),
        Line::from(""),
        Line::from("[any key] close"),
    ];
    let area = frame.area();
    frame.render_widget(Clear, area);
    let height = (lines.len() as u16) + 2;
    let r = centered_rect(area, 60, height);
    let p = Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title(" Help "))
        .wrap(Wrap { trim: true });
    frame.render_widget(p, r);
}

fn draw_search_hint<S: crate::vault::VaultStore>(frame: &mut Frame, app: &App<'_, S>) {
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
