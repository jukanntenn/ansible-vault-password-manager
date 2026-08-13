//! Minimal single-line text input for form fields.
//!
//! Replaces `tui-textarea`, whose latest release (0.7.0) only supports
//! ratatui 0.29 — a version that depends on the unmaintained `paste`
//! proc-macro (RUSTSEC-2024-0436). Forms need a small editing subset:
//! character insertion at a cursor, Backspace/Delete, Left/Right/Home/End,
//! and render-time masking for password fields. This widget implements that
//! subset directly on ratatui primitives.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Paragraph, Widget};

/// A single-line editable field. Holds the real characters; `mask` is applied
/// only at render time so the plaintext never reaches the terminal.
pub struct TextField {
    chars: Vec<char>,
    cursor: usize,
    mask: Option<char>,
    block: Option<Block<'static>>,
}

impl TextField {
    /// Create an empty field. `Some(m)` renders every character as `m`.
    pub fn new(mask: Option<char>) -> Self {
        Self {
            chars: Vec::new(),
            cursor: 0,
            mask,
            block: None,
        }
    }

    /// The field's plaintext value.
    #[must_use]
    pub fn value(&self) -> String {
        self.chars.iter().collect()
    }

    /// Replace the whole content (used by password generation) and place the
    /// cursor at the end.
    pub fn replace(&mut self, s: &str) {
        self.chars = s.chars().collect();
        self.cursor = self.chars.len();
    }

    /// Set the bordered frame rendered around the field.
    pub fn set_block(&mut self, block: Block<'static>) {
        self.block = Some(block);
    }

    /// 0-based character column of the cursor (relative to the content area).
    #[must_use]
    pub fn cursor_col(&self) -> usize {
        self.cursor
    }

    /// Apply an editing key; returns whether the key was consumed.
    pub fn input(&mut self, key: KeyEvent) -> bool {
        // App-level shortcuts own Ctrl/Alt combinations; only plain (and
        // Shift) presses edit the field.
        if key
            .modifiers
            .contains(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return false;
        }
        match key.code {
            KeyCode::Char(c) if !c.is_control() => {
                self.chars.insert(self.cursor, c);
                self.cursor += 1;
                true
            }
            KeyCode::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.chars.remove(self.cursor);
                }
                true
            }
            KeyCode::Delete => {
                if self.cursor < self.chars.len() {
                    self.chars.remove(self.cursor);
                }
                true
            }
            KeyCode::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                true
            }
            KeyCode::Right => {
                self.cursor = (self.cursor + 1).min(self.chars.len());
                true
            }
            KeyCode::Home => {
                self.cursor = 0;
                true
            }
            KeyCode::End => {
                self.cursor = self.chars.len();
                true
            }
            _ => false,
        }
    }
}

impl TextField {
    fn render_into(&self, area: Rect, buf: &mut Buffer) {
        let display: String = match self.mask {
            Some(m) => m.to_string().repeat(self.chars.len()),
            None => self.chars.iter().collect(),
        };
        let mut p = Paragraph::new(Line::from(display));
        if let Some(b) = &self.block {
            p = p.block(b.clone());
        }
        p.render(area, buf);
    }
}

impl Widget for TextField {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_into(area, buf);
    }
}

impl Widget for &TextField {
    fn render(self, area: Rect, buf: &mut Buffer) {
        self.render_into(area, buf);
    }
}
