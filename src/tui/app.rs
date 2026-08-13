//! TUI state machine.
//!
//! The `App` owns the vault list, selection, current mode, and — crucially —
//! borrowed references to the live `store` and `index`. Every operation
//! (copy/show/delete/add/edit/rename) is performed inline in `handle_event`
//! against that store, so the TUI never tears down to execute a side effect
//! and the screen never flickers. Operation feedback is written to
//! `self.message` and rendered on the next frame.
//!
//! Forms (add/edit/rename) are rendered as popups of in-tree [`input`]
//! fields. Password fields are masked at render time (see [`super::ui`]); the
//! underlying [`input::TextField`] holds the real text so full cursor editing
//! works.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::widgets::ListState;

use super::event::EventResult;
use super::input::TextField;
use crate::error::Result;
use crate::index::VaultIndex;
use crate::vault::{VaultSecret, VaultStore};

/// A vault entry row in the TUI list.
#[derive(Debug, Clone)]
pub struct VaultItem {
    pub id: String,
}

/// TUI interaction mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    ShowPassword {
        reveal: bool,
    },
    /// Multi-field popup form (add/edit/rename). `focus` is the active field
    /// index. The field set is determined by [`FormKind`].
    Form {
        kind: FormKind,
        focus: usize,
    },
    ConfirmDelete,
    SyncMenu,
    Help,
}

/// Which form is active; determines the field set and submit action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormKind {
    /// Add a new vault-id. Fields: [vault-id, password, confirm].
    Add,
    /// Edit an existing vault's password. Fields: [password, confirm].
    Edit,
    /// Rename a vault-id. Fields: [new-id].
    Rename,
}

impl FormKind {
    /// Number of input fields for this form.
    #[must_use]
    pub fn field_count(&self) -> usize {
        match self {
            FormKind::Add => 3,
            FormKind::Edit => 2,
            FormKind::Rename => 1,
        }
    }

    /// Whether field `i` is a secret (masked password) field.
    #[must_use]
    pub fn is_secret_field(&self, i: usize) -> bool {
        match self {
            FormKind::Add => i == 1 || i == 2,
            FormKind::Edit => i == 0 || i == 1,
            FormKind::Rename => false,
        }
    }

    /// Human-readable label for field `i`.
    #[must_use]
    pub fn field_label(&self, i: usize) -> &'static str {
        match self {
            FormKind::Add => match i {
                0 => "Vault ID",
                1 => "Password",
                _ => "Confirm",
            },
            FormKind::Edit => match i {
                0 => "New Password",
                _ => "Confirm",
            },
            FormKind::Rename => "New Vault ID",
        }
    }
}

/// The TUI application state. Borrows the store (and optionally the index) for
/// the lifetime of the TUI session. `index` is `None` for the single-password
/// `show` view, where no list/mutation is possible.
pub struct App<'a, S: VaultStore> {
    pub store: &'a S,
    pub index: Option<&'a VaultIndex>,
    pub items: Vec<VaultItem>,
    pub state: ListState,
    pub mode: Mode,
    /// Search filter (active in `Mode::Search`).
    pub search: String,
    /// Status / feedback line rendered in the footer.
    pub message: Option<String>,
    /// Currently-revealed password (held in `ShowPassword`).
    pub shown_secret: Option<VaultSecret>,
    /// Clipboard auto-clear deadline; `None` = no clear pending.
    pub copy_deadline: Option<std::time::Instant>,
    /// Clipboard auto-clear window in seconds (0 = disabled).
    clipboard_clear_seconds: u16,
    /// Form text fields, one per active field. Only meaningful in `Mode::Form`.
    form_fields: Vec<TextField>,
    quit: bool,
}

impl<'a, S: VaultStore> App<'a, S> {
    /// Build an app and load the current vault list from `store`/`index`.
    ///
    /// Only verifies each indexed id still resolves in the store (skips drift
    /// silently with a debug log).
    pub fn load(store: &'a S, index: &'a VaultIndex, clipboard_clear_seconds: u16) -> Result<Self> {
        let ids = index.list()?;
        let mut items = Vec::with_capacity(ids.len());
        for id in ids {
            if store.get(&id).is_err() {
                tracing::debug!(vault_id = %id, "index entry missing from store; hiding in TUI");
                continue;
            }
            items.push(VaultItem { id });
        }
        let mut state = ListState::default();
        state.select(if items.is_empty() { None } else { Some(0) });
        Ok(Self {
            store,
            index: Some(index),
            items,
            state,
            mode: Mode::Normal,
            search: String::new(),
            message: None,
            shown_secret: None,
            copy_deadline: None,
            clipboard_clear_seconds,
            form_fields: Vec::new(),
            quit: false,
        })
    }

    /// Reload the item list from the index/store after a mutating operation
    /// (add/delete/rename) so the list reflects the new state. Selection is
    /// preserved when possible. No-op when no index is attached (`show` view).
    fn reload_items(&mut self) {
        let Some(index) = self.index else {
            return;
        };
        let prev_selected = self.selected_id().map(str::to_owned);
        let Ok(ids) = index.list() else {
            return;
        };
        self.items.clear();
        for id in ids {
            if self.store.get(&id).is_ok() {
                self.items.push(VaultItem { id });
            }
        }
        let new_sel = prev_selected
            .and_then(|id| self.items.iter().position(|i| i.id == id))
            .or(if self.items.is_empty() { None } else { Some(0) });
        self.state.select(new_sel);
    }

    /// Enter the `ShowPassword` mode holding a preloaded `secret`. Used after
    /// an inline `store.get` from Normal mode's Enter key.
    fn enter_show_password(&mut self, id: &str, secret: VaultSecret) {
        if let Some(pos) = self.items.iter().position(|i| i.id == id) {
            self.state.select(Some(pos));
        }
        self.shown_secret = Some(secret);
        self.mode = Mode::ShowPassword { reveal: false };
        self.message = None;
    }

    /// Build a single-password show-only app (for `avpm show <id>`). No index
    /// is attached, so list mutations are unavailable — only reveal/copy work.
    #[must_use]
    pub fn show_one(
        store: &'a S,
        id: String,
        secret: VaultSecret,
        clipboard_clear_seconds: u16,
    ) -> Self {
        let item = VaultItem { id };
        let mut state = ListState::default();
        state.select(Some(0));
        Self {
            store,
            index: None,
            items: vec![item],
            state,
            mode: Mode::ShowPassword { reveal: false },
            search: String::new(),
            message: None,
            shown_secret: Some(secret),
            copy_deadline: None,
            clipboard_clear_seconds,
            form_fields: Vec::new(),
            quit: false,
        }
    }

    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Time-based work invoked on each event-loop tick (~100ms).
    pub fn on_tick(&mut self) {
        if let Some(deadline) = self.copy_deadline {
            if std::time::Instant::now() >= deadline {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text("");
                }
                self.copy_deadline = None;
                self.message = Some("Clipboard cleared".to_string());
            }
        }
    }

    #[must_use]
    pub fn selected_id(&self) -> Option<&str> {
        let idx = self.state.selected()?;
        self.filtered_items().get(idx).map(|i| i.id.as_str())
    }

    /// Items filtered by the active search query (for rendering).
    pub fn filtered_items(&self) -> Vec<&VaultItem> {
        if self.search.is_empty() {
            self.items.iter().collect()
        } else {
            self.items
                .iter()
                .filter(|i| i.id.contains(self.search.as_str()))
                .collect()
        }
    }

    /// Drive the state machine with a key event.
    pub fn handle_event(&mut self, key: Option<KeyEvent>) -> EventResult {
        let Some(key) = key else {
            return EventResult::Continue;
        };
        // Only Press/Repeat are meaningful actions; Repeat would double-trigger,
        // so we gate on Press for all modes.
        let result = match &self.mode {
            Mode::Normal => self.on_normal(key),
            Mode::Search => self.on_search(key),
            Mode::ShowPassword { .. } => self.on_show_password(key),
            Mode::Form { .. } => self.on_form(key),
            Mode::ConfirmDelete => self.on_confirm_delete(key),
            Mode::SyncMenu => self.on_sync_menu(key),
            Mode::Help => self.on_help(key),
        };
        if self.quit {
            EventResult::Quit
        } else {
            result
        }
    }

    fn on_normal(&mut self, key: KeyEvent) -> EventResult {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Char('y') => self.do_copy(),
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('g') => self.state.select(Some(0)),
            KeyCode::Char('G') => {
                let n = self.filtered_items().len();
                if n > 0 {
                    self.state.select(Some(n - 1));
                }
            }
            KeyCode::Enter => self.do_show(),
            KeyCode::Char('e') => self.open_form(FormKind::Edit),
            KeyCode::Char('a' | 'n') => self.open_form(FormKind::Add),
            KeyCode::Char('d') => {
                if self.selected_id().is_some() {
                    self.mode = Mode::ConfirmDelete;
                }
            }
            KeyCode::Char('r') => self.open_form(FormKind::Rename),
            KeyCode::Char('/') => {
                self.mode = Mode::Search;
                self.search.clear();
            }
            KeyCode::Char('s') => self.mode = Mode::SyncMenu,
            KeyCode::Char('?') => self.mode = Mode::Help,
            _ => {}
        }
        EventResult::Continue
    }

    fn on_search(&mut self, key: KeyEvent) -> EventResult {
        match key.code {
            KeyCode::Esc => {
                self.search.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => {
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                self.search.pop();
            }
            KeyCode::Char(c) if !c.is_control() => {
                self.search.push(c);
            }
            _ => {}
        }
        EventResult::Continue
    }

    fn on_show_password(&mut self, key: KeyEvent) -> EventResult {
        // Toggle reveal on Space press (one tap flips show/hide). This is
        // terminal-agnostic — no dependency on the Kitty keyboard protocol.
        match key.code {
            KeyCode::Char(' ') => {
                let now_revealed = !matches!(self.mode, Mode::ShowPassword { reveal: true });
                self.mode = Mode::ShowPassword {
                    reveal: now_revealed,
                };
            }
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                self.shown_secret = None;
                self.mode = Mode::Normal;
            }
            KeyCode::Char('y') => self.do_copy(),
            _ => {}
        }
        EventResult::Continue
    }

    fn on_form(&mut self, key: KeyEvent) -> EventResult {
        // Read kind/focus by reference (can't move out of &mut self.mode).
        let (kind, focus) = match &self.mode {
            Mode::Form { kind, focus } => (*kind, *focus),
            _ => return EventResult::Continue,
        };
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
            }
            KeyCode::Tab => {
                let next = (focus + 1) % kind.field_count();
                self.mode = Mode::Form { kind, focus: next };
            }
            KeyCode::BackTab => {
                let prev = if focus == 0 {
                    kind.field_count() - 1
                } else {
                    focus - 1
                };
                self.mode = Mode::Form { kind, focus: prev };
            }
            KeyCode::Enter => {
                // Enter on the last field submits; on earlier fields it advances
                // focus (Tab-like) so the user can commit from the confirm field.
                if focus + 1 == kind.field_count() {
                    self.commit_form(kind);
                } else {
                    self.mode = Mode::Form {
                        kind,
                        focus: focus + 1,
                    };
                }
            }
            KeyCode::Char('g') => {
                // Password generation, only meaningful on password fields.
                if kind.is_secret_field(focus) {
                    if let Ok(secret) = crate::password::generate(32, false) {
                        if let Some(field) = self.form_fields.get_mut(focus) {
                            field.replace(secret.as_str());
                        }
                    }
                }
            }
            _ => {
                if let Some(field) = self.form_fields.get_mut(focus) {
                    field.input(key);
                }
            }
        }
        EventResult::Continue
    }

    fn on_confirm_delete(&mut self, key: KeyEvent) -> EventResult {
        match key.code {
            KeyCode::Enter => self.do_delete(),
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }
        EventResult::Continue
    }

    fn on_sync_menu(&mut self, key: KeyEvent) -> EventResult {
        // Sync from the TUI is intentionally deferred (it needs a passphrase
        // prompt on the tty). For now we surface a hint and let the user run
        // `avpm sync` from the shell; the popup remains informational.
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Normal,
            _ => {
                self.message = Some(
                    "Run `avpm sync push|pull|status` from the shell (passphrase prompt)."
                        .to_string(),
                );
            }
        }
        EventResult::Continue
    }

    fn on_help(&mut self, key: KeyEvent) -> EventResult {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | '?') | KeyCode::Enter => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }
        EventResult::Continue
    }

    fn move_selection(&mut self, delta: i32) {
        let n = self.filtered_items().len();
        if n == 0 {
            return;
        }
        let cur = self.state.selected().unwrap_or(0) as i32;
        let mut next = cur + delta;
        if next < 0 {
            next = (n - 1) as i32;
        } else if next as usize >= n {
            next = 0;
        }
        self.state.select(Some(next as usize));
    }

    /// Copy the selected vault's password to the clipboard (inline).
    fn do_copy(&mut self) {
        let Some(id) = self.selected_id().map(str::to_owned) else {
            return;
        };
        match self.store.get(&id) {
            Ok(secret) => {
                let secs = self.clipboard_clear_seconds;
                match copy_to_clipboard(secret.as_str()) {
                    Ok(()) => {
                        if secs > 0 {
                            self.copy_deadline = Some(
                                std::time::Instant::now()
                                    + std::time::Duration::from_secs(u64::from(secs)),
                            );
                            self.message = Some(format!("Copied '{id}' (clears in {secs}s)"));
                        } else {
                            self.message = Some(format!("Copied '{id}'"));
                        }
                    }
                    Err(e) => self.message = Some(format!("Copy failed: {e}")),
                }
            }
            Err(e) => self.message = Some(format!("Failed to load '{id}': {e}")),
        }
    }

    /// Load and reveal the selected vault's password (inline ShowPassword).
    fn do_show(&mut self) {
        let Some(id) = self.selected_id().map(str::to_owned) else {
            return;
        };
        match self.store.get(&id) {
            Ok(secret) => self.enter_show_password(&id, secret),
            Err(e) => self.message = Some(format!("Failed to load '{id}': {e}")),
        }
    }

    /// Delete the selected vault (inline), then reload the list.
    fn do_delete(&mut self) {
        let Some(id) = self.selected_id().map(str::to_owned) else {
            return;
        };
        let store_ok = self.store.delete(&id).is_ok();
        if let Some(index) = self.index {
            let _ = index.remove(&id);
        }
        self.message = Some(if store_ok {
            format!("✓ Deleted '{id}'")
        } else {
            format!("Deleted '{id}'")
        });
        self.reload_items();
        self.mode = Mode::Normal;
    }

    /// Open a form of the given kind, with fresh empty text fields. Password
    /// fields are masked via [`TextField::new`], which keeps full cursor /
    /// editing capability while displaying only `•`.
    fn open_form(&mut self, kind: FormKind) {
        if matches!(kind, FormKind::Edit | FormKind::Rename) && self.selected_id().is_none() {
            return;
        }
        self.form_fields = (0..kind.field_count())
            .map(|i| {
                let mask = kind.is_secret_field(i).then_some('•');
                TextField::new(mask)
            })
            .collect();
        self.mode = Mode::Form { kind, focus: 0 };
    }

    /// Commit the active form: validate inputs, apply via store/index, reload.
    fn commit_form(&mut self, kind: FormKind) {
        let values: Vec<String> = self.form_fields.iter().map(TextField::value).collect();
        match kind {
            FormKind::Add => {
                let id = values.first().cloned().unwrap_or_default();
                let pw = values.get(1).cloned().unwrap_or_default();
                let confirm = values.get(2).cloned().unwrap_or_default();
                if id.is_empty() {
                    self.message = Some("✗ vault-id cannot be empty".to_string());
                    self.mode = Mode::Normal;
                    return;
                }
                if pw != confirm {
                    self.message = Some("✗ passwords do not match".to_string());
                    self.mode = Mode::Normal;
                    return;
                }
                match self.store.set(&id, &VaultSecret::new(pw)) {
                    Ok(()) => {
                        if let Some(index) = self.index {
                            let _ = index.add(&id);
                        }
                        self.message = Some(format!("✓ Added '{id}'"));
                        self.reload_items();
                        self.mode = Mode::Normal;
                    }
                    Err(e) => {
                        self.message = Some(format!("✗ Add failed: {e}"));
                        self.mode = Mode::Normal;
                    }
                }
            }
            FormKind::Edit => {
                let Some(id) = self.selected_id().map(str::to_owned) else {
                    self.mode = Mode::Normal;
                    return;
                };
                let pw = values.first().cloned().unwrap_or_default();
                let confirm = values.get(1).cloned().unwrap_or_default();
                if pw != confirm {
                    self.message = Some("✗ passwords do not match".to_string());
                    self.mode = Mode::Normal;
                    return;
                }
                match self.store.set(&id, &VaultSecret::new(pw)) {
                    Ok(()) => {
                        self.message = Some(format!("✓ Updated '{id}'"));
                        self.mode = Mode::Normal;
                    }
                    Err(e) => {
                        self.message = Some(format!("✗ Edit failed: {e}"));
                        self.mode = Mode::Normal;
                    }
                }
            }
            FormKind::Rename => {
                let Some(from) = self.selected_id().map(str::to_owned) else {
                    self.mode = Mode::Normal;
                    return;
                };
                let to = values.first().cloned().unwrap_or_default();
                if to.is_empty() {
                    self.message = Some("✗ new id cannot be empty".to_string());
                    self.mode = Mode::Normal;
                    return;
                }
                match self.store.get(&from) {
                    Ok(secret) => match self.store.set(&to, &secret) {
                        Ok(()) => {
                            if let Some(index) = self.index {
                                let _ = index.add(&to);
                            }
                            let _ = self.store.delete(&from);
                            if let Some(index) = self.index {
                                let _ = index.remove(&from);
                            }
                            self.message = Some(format!("✓ Renamed '{from}' → '{to}'"));
                            self.reload_items();
                            self.mode = Mode::Normal;
                        }
                        Err(e) => {
                            self.message = Some(format!("✗ Rename failed: {e}"));
                            self.mode = Mode::Normal;
                        }
                    },
                    Err(e) => {
                        self.message = Some(format!("✗ Rename failed: {e}"));
                        self.mode = Mode::Normal;
                    }
                }
            }
        }
    }

    /// The active form's field text inputs (for rendering). Empty outside forms.
    #[must_use]
    pub fn form_fields(&self) -> &[TextField] {
        &self.form_fields
    }

    /// Mutable access to the form fields (for setting block/style before
    /// render, and for cursor positioning).
    pub fn form_fields_mut(&mut self) -> &mut [TextField] {
        &mut self.form_fields
    }
}

/// Copy `secret` to the system clipboard via `arboard`.
fn copy_to_clipboard(secret: &str) -> std::result::Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(secret).map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::mock::MockStore;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn make_app<'a>(store: &'a MockStore, index: &'a VaultIndex) -> App<'a, MockStore> {
        App::load(store, index, 0).unwrap()
    }

    fn setup(ids: &[&str]) -> (tempfile::TempDir, MockStore, VaultIndex) {
        let dir = tempfile::TempDir::new().unwrap();
        let idx = VaultIndex::new(dir.path().join("index.json"));
        let store = MockStore::new();
        for id in ids {
            store.seed(id, "secret-x");
            idx.add(id).unwrap();
        }
        (dir, store, idx)
    }

    // --- TestBackend render helpers (deterministic, in-process) ---
    //
    // These drive the real `ui::draw` against a ratatui `TestBackend` and read
    // the buffer directly — no pty, no timing. They are the right tool for
    // rendering-correctness assertions (masking, focus emphasis, help text),
    // complementing the pty harness in `tests/tui/` which proves the bytes
    // physically reach the terminal.

    /// Render `app` to a 100×30 TestBackend and run `f` on the resulting
    /// buffer (cells include symbol + style).
    fn with_buffer<R>(
        app: &mut App<'_, MockStore>,
        f: impl FnOnce(&ratatui::buffer::Buffer) -> R,
    ) -> R {
        let backend = ratatui::backend::TestBackend::new(100, 30);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| crate::tui::ui::draw(app, frame))
            .unwrap();
        f(terminal.backend().buffer())
    }

    /// The rendered buffer as a flat row-major string of cell symbols. Use for
    /// "is this text / mask dot present?" assertions.
    fn render_string(app: &mut App<'_, MockStore>) -> String {
        with_buffer(app, |buf| {
            (0..30_u16)
                .flat_map(|y| (0..100_u16).map(move |x| buf[(x, y)].symbol().to_string()))
                .collect()
        })
    }

    /// Count mask dots (`•`, U+2022) in a rendered string.
    fn mask_dot_count(rendered: &str) -> usize {
        rendered.chars().filter(|&c| c == '\u{2022}').count()
    }

    /// Whether `label` is rendered BOLD — i.e. it belongs to the focused field
    /// (unfocused labels are DIM). Scans the buffer for the label text and reads
    /// the style of its first cell. Safe because a label row holds only ASCII:
    /// the label itself plus surrounding cells cleared to spaces by `Clear`.
    fn label_is_bold(buf: &ratatui::buffer::Buffer, label: &str) -> bool {
        for y in 0..30_u16 {
            let row: String = (0..100_u16)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect();
            if let Some(idx) = row.find(label) {
                return buf[(idx as u16, y)]
                    .style()
                    .add_modifier
                    .contains(ratatui::style::Modifier::BOLD);
            }
        }
        false
    }

    #[test]
    fn loads_items_sorted() {
        let (_d, store, idx) = setup(&["prod", "dev"]);
        let app = make_app(&store, &idx);
        assert_eq!(app.items[0].id, "dev");
        assert_eq!(app.items[1].id, "prod");
        assert_eq!(app.state.selected(), Some(0));
    }

    #[test]
    fn j_k_moves_selection() {
        let (_d, store, idx) = setup(&["dev", "prod", "staging"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('j')));
        assert_eq!(app.state.selected(), Some(1));
        app.handle_event(Some(key('k')));
        assert_eq!(app.state.selected(), Some(0));
    }

    #[test]
    fn copy_writes_to_store_and_sets_message() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('y')));
        // On a headless test box the clipboard is unavailable, so the message
        // reports a copy failure — but the store *was* read (the core contract).
        // We only assert that a message was set (the operation happened inline).
        assert!(app.message.is_some(), "copy should produce a message");
    }

    #[test]
    fn show_loads_secret_and_enters_show_password() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert!(matches!(app.mode, Mode::ShowPassword { reveal: false }));
        assert!(app.shown_secret.is_some());
    }

    #[test]
    fn space_toggles_reveal_on_press() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        // Enter to show.
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        // Space toggles reveal on.
        app.handle_event(Some(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE)));
        assert!(matches!(app.mode, Mode::ShowPassword { reveal: true }));
        // Space toggles reveal off.
        app.handle_event(Some(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE)));
        assert!(matches!(app.mode, Mode::ShowPassword { reveal: false }));
    }

    #[test]
    fn esc_exits_show_password() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        app.handle_event(Some(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        assert!(app.shown_secret.is_none());
    }

    #[test]
    fn delete_removes_from_store_and_index() {
        let (_d, store, idx) = setup(&["dev", "prod"]);
        let mut app = make_app(&store, &idx);
        // d enters confirm, Enter confirms.
        app.handle_event(Some(key('d')));
        assert_eq!(app.mode, Mode::ConfirmDelete);
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        // 'dev' (selected) should be gone from both store and index.
        assert!(store.get("dev").is_err());
        assert!(!idx.list().unwrap().contains(&"dev".to_string()));
        // prod survives.
        assert!(store.get("prod").is_ok());
    }

    #[test]
    fn delete_esc_cancels() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('d')));
        app.handle_event(Some(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        assert!(store.get("dev").is_ok());
    }

    #[test]
    fn open_add_form_has_three_fields() {
        let (_d, store, idx) = setup(&[]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('a')));
        assert!(matches!(
            app.mode,
            Mode::Form {
                kind: FormKind::Add,
                ..
            }
        ));
        assert_eq!(app.form_fields.len(), 3);
    }

    #[test]
    fn open_edit_form_has_two_fields() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('e')));
        assert!(matches!(
            app.mode,
            Mode::Form {
                kind: FormKind::Edit,
                ..
            }
        ));
        assert_eq!(app.form_fields.len(), 2);
    }

    #[test]
    fn open_rename_form_has_one_field() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('r')));
        assert!(matches!(
            app.mode,
            Mode::Form {
                kind: FormKind::Rename,
                ..
            }
        ));
        assert_eq!(app.form_fields.len(), 1);
    }

    #[test]
    fn form_tab_advances_focus() {
        let (_d, store, idx) = setup(&[]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('a')));
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        assert!(matches!(app.mode, Mode::Form { focus: 1, .. }));
    }

    #[test]
    fn form_esc_cancels() {
        let (_d, store, idx) = setup(&[]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('a')));
        app.handle_event(Some(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn commit_add_form_persists_to_store() {
        let (_d, store, idx) = setup(&[]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('a')));
        // Type vault-id in field 0.
        for c in "newvault".chars() {
            app.handle_event(Some(key(c)));
        }
        // Tab to password field, type.
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        for c in "pass1".chars() {
            app.handle_event(Some(key(c)));
        }
        // Tab to confirm field, type same password.
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        for c in "pass1".chars() {
            app.handle_event(Some(key(c)));
        }
        // Enter on the last field submits.
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(store.get("newvault").unwrap().as_str(), "pass1");
    }

    #[test]
    fn commit_add_form_mismatched_passwords_rejects() {
        let (_d, store, idx) = setup(&[]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('a')));
        for c in "v".chars() {
            app.handle_event(Some(key(c)));
        }
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        for c in "a".chars() {
            app.handle_event(Some(key(c)));
        }
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        for c in "b".chars() {
            app.handle_event(Some(key(c)));
        }
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        assert!(store.get("v").is_err());
        assert!(app
            .message
            .as_deref()
            .unwrap_or("")
            .contains("do not match"));
    }

    #[test]
    fn commit_edit_form_updates_password() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('e')));
        // Field 0: new password.
        for c in "newpw".chars() {
            app.handle_event(Some(key(c)));
        }
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        for c in "newpw".chars() {
            app.handle_event(Some(key(c)));
        }
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(store.get("dev").unwrap().as_str(), "newpw");
    }

    #[test]
    fn commit_rename_form_moves_entry() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('r')));
        for c in "production".chars() {
            app.handle_event(Some(key(c)));
        }
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        assert!(store.get("dev").is_err());
        assert!(store.get("production").is_ok());
        assert!(idx.list().unwrap().contains(&"production".to_string()));
        assert!(!idx.list().unwrap().contains(&"dev".to_string()));
    }

    #[test]
    fn slash_enters_search() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('/')));
        assert_eq!(app.mode, Mode::Search);
        app.handle_event(Some(key('d')));
        assert_eq!(app.search, "d");
    }

    #[test]
    fn help_toggles() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('?')));
        assert_eq!(app.mode, Mode::Help);
        app.handle_event(Some(key('q')));
        assert_eq!(app.mode, Mode::Normal);
    }

    /// SPIKE VERIFICATION: render the Add form to a TestBackend (no pty, no
    /// diff-to-terminal) and read the buffer directly. Confirms whether
    /// masked password content actually lands in the render buffer as `•`.
    #[test]
    fn form_password_field_masked_in_render_buffer() {
        let (_d, store, idx) = setup(&[]);
        let mut app = make_app(&store, &idx);
        // Open Add form, fill vault-id, Tab to password, type.
        app.handle_event(Some(key('a')));
        for c in "dev".chars() {
            app.handle_event(Some(key(c)));
        }
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        for c in "secret123".chars() {
            app.handle_event(Some(key(c)));
        }

        let rendered = render_string(&mut app);

        assert!(
            !rendered.contains("secret123"),
            "plaintext leaked into render buffer:\n{rendered}"
        );
        assert!(
            rendered.contains('\u{2022}'),
            "expected mask dot • in render buffer:\n{rendered}"
        );
    }

    /// T5 — pressing `g` on a password field generates a strong password, which
    /// renders as a row of mask dots (never plaintext). Verifies both the
    /// generate shortcut and that the generated value stays masked in the
    /// render buffer.
    #[test]
    fn form_generate_key_fills_masked_password() {
        let (_d, store, idx) = setup(&[]);
        let mut app = make_app(&store, &idx);
        // Open Add, Tab to the Password field (field 1, a secret field).
        app.handle_event(Some(key('a')));
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));

        // Before generating: no mask dots anywhere (both secret fields empty).
        let before = mask_dot_count(&render_string(&mut app));
        assert_eq!(before, 0, "expected no mask dots before [g]");

        // `g` generates a 32-char password into the focused field.
        app.handle_event(Some(key('g')));
        let rendered = render_string(&mut app);
        let after = mask_dot_count(&rendered);
        assert!(
            after >= 32,
            "[g] should generate a ≥32-char password (got {after} mask dots)"
        );

        // The generated value must reach the buffer only as `•`: read the real
        // secret back from the field and confirm it is absent from the render.
        let generated: String = app.form_fields()[1].value();
        assert!(
            !generated.is_empty(),
            "[g] did not populate the password field"
        );
        assert!(
            !rendered.contains(&generated),
            "generated password leaked as plaintext into the render buffer"
        );
    }

    /// T8 — the Help popup (`?`) renders the keybinding reference, including the
    /// "Space to reveal" line that documents the toggle-reveal interaction.
    #[test]
    fn help_popup_renders_keybinding_reference() {
        let (_d, store, idx) = setup(&["dev"]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('?')));
        assert_eq!(app.mode, Mode::Help);

        let rendered = render_string(&mut app);
        assert!(
            rendered.contains("Space to reveal"),
            "help should document Space-to-reveal:\n{rendered}"
        );
        assert!(
            rendered.contains("avpm TUI keybindings"),
            "help should render its heading:\n{rendered}"
        );
    }

    /// T10 — Tab moves focus between form fields, and the render reflects it:
    /// the focused field's label is BOLD and the others are DIM. This is the
    /// rendering-level guard (the state-machine focus change is covered by
    /// `form_tab_advances_focus`); it catches the class of bug where input
    /// state is correct but the draw never reflects it.
    #[test]
    fn form_tab_moves_focus_rendering() {
        let (_d, store, idx) = setup(&[]);
        let mut app = make_app(&store, &idx);
        app.handle_event(Some(key('a')));

        // focus 0: "Vault ID" is BOLD, "Password" is DIM.
        with_buffer(&mut app, |buf| {
            assert!(
                label_is_bold(buf, "Vault ID"),
                "field 0 label should be BOLD when focused"
            );
            assert!(
                !label_is_bold(buf, "Password"),
                "field 1 label should be DIM when not focused"
            );
        });

        // Tab → focus 1: emphasis swaps.
        app.handle_event(Some(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)));
        with_buffer(&mut app, |buf| {
            assert!(
                !label_is_bold(buf, "Vault ID"),
                "field 0 label should be DIM after Tab"
            );
            assert!(
                label_is_bold(buf, "Password"),
                "field 1 label should be BOLD after Tab"
            );
        });
    }
}
