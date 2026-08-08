//! TUI state machine (see `08` §2.4, §2.5).
//!
//! The `App` owns a list of vault entries (id only — the keyring exposes no
//! per-secret metadata), a `ListState` for selection, the current `Mode`, and
//! an input buffer. It is UI-agnostic: [`super::ui::draw`] reads state;
//! `handle_event` mutates it.
//!
//! Persistence (keyring + index) goes through the injected `Store`/`Index`,
//! so the same state machine is exercised in tests with `MockStore`.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind};
use ratatui::widgets::ListState;

use crate::error::Result;
use crate::index::VaultIndex;
use crate::password;
use crate::vault::{VaultSecret, VaultStore};

/// A vault entry row in the TUI list.
///
/// NOTE: the OS keyring exposes no "last updated" metadata, so we deliberately
/// do **not** surface a timestamp in the UI — showing `now()` would be forged
/// data and mislead users (acceptance finding #14). The id alone is the row.
#[derive(Debug, Clone)]
pub struct VaultItem {
    pub id: String,
}

/// TUI interaction mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search,
    ShowPassword { reveal: bool },
    AddPrompt,
    EditPrompt,
    RenamePrompt,
    ConfirmDelete,
    SyncMenu,
    SyncProgress { msg: String },
    Help,
}

/// The TUI application state.
pub struct App {
    pub items: Vec<VaultItem>,
    pub state: ListState,
    pub mode: Mode,
    pub input: tui_input::Input,
    pub message: Option<String>,
    /// Search filter (active in `Mode::Search`).
    pub search: String,
    /// Currently-revealed password (held briefly in `ShowPassword`).
    pub shown_secret: Option<VaultSecret>,
    /// Deadline at which the clipboard should be cleared (gopass cliptimeout).
    /// `None` = no clear pending. Checked on each Tick from the event loop.
    pub copy_deadline: Option<std::time::Instant>,
    /// Action requested via a popup (e.g. SyncMenu's p/u/t) for the command
    /// handler to apply after the loop exits.
    pending: Option<PendingAction>,
    quit: bool,
}

impl App {
    /// Build an app and load the current vault list from `store`/`index`.
    ///
    /// Only verifies each indexed id still resolves in the store (skips drift
    /// silently with a debug log); does not invent metadata the keyring can't
    /// provide (no fake `updated_at` — `14`).
    pub fn load(store: &impl VaultStore, index: &VaultIndex) -> Result<Self> {
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
            items,
            state,
            mode: Mode::Normal,
            input: tui_input::Input::default(),
            message: None,
            search: String::new(),
            shown_secret: None,
            copy_deadline: None,
            pending: None,
            quit: false,
        })
    }

    /// Enter the `ShowPassword` mode holding a preloaded `secret`.
    ///
    /// Used by the TUI command handler after a `PendingAction::Show`: the list
    /// view recorded a show request, the handler loaded the secret from the
    /// store, and now re-enters the TUI pointing at this entry with the secret
    /// in hand (so `draw_show_password` has something to render).
    pub fn enter_show_password(&mut self, id: &str, secret: VaultSecret) {
        // Make sure the selection points at `id` so `selected_id()` resolves in
        // the show view (used for the "Vault: <id>" header).
        if let Some(pos) = self.items.iter().position(|i| i.id == id) {
            self.state.select(Some(pos));
        }
        self.shown_secret = Some(secret);
        self.mode = Mode::ShowPassword { reveal: false };
        self.message = None;
        self.quit = false;
        self.pending = None;
    }

    /// Build a single-password show-only app (for `avpm show <id>`).
    #[must_use]
    pub fn show_one(id: String, secret: VaultSecret) -> Self {
        let item = VaultItem { id };
        let mut state = ListState::default();
        state.select(Some(0));
        Self {
            items: vec![item],
            state,
            mode: Mode::ShowPassword { reveal: false },
            input: tui_input::Input::default(),
            message: None,
            search: String::new(),
            shown_secret: Some(secret),
            copy_deadline: None,
            pending: None,
            quit: false,
        }
    }

    #[must_use]
    pub fn should_quit(&self) -> bool {
        self.quit
    }

    /// Time-based work invoked on each event-loop tick (~100ms). Currently:
    /// - Clears the clipboard when the auto-clear deadline passes (gopass
    ///   `cliptimeout` pattern). Silently no-ops on headless boxes where the
    ///   clipboard isn't writable.
    pub fn on_tick(&mut self) {
        if let Some(deadline) = self.copy_deadline {
            if std::time::Instant::now() >= deadline {
                // Best-effort clear; failures (headless/no display) are fine.
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

    /// Drive the state machine with a key event. Returns whether to continue.
    pub fn handle_event(&mut self, key: Option<KeyEvent>) -> super::EventResult {
        let Some(key) = key else {
            return super::EventResult::Continue;
        };
        let result = match &self.mode {
            Mode::Normal => self.on_normal(key),
            Mode::Search => self.on_search(key),
            Mode::ShowPassword { .. } => self.on_show_password(key),
            Mode::AddPrompt | Mode::EditPrompt | Mode::RenamePrompt => self.on_input(key),
            Mode::ConfirmDelete => self.on_confirm_delete(key),
            Mode::SyncMenu => self.on_sync_menu(key),
            Mode::SyncProgress { .. } => self.on_sync_progress(key),
            Mode::Help => self.on_help(key),
        };
        if self.quit {
            super::EventResult::Quit
        } else {
            result
        }
    }

    fn on_normal(&mut self, key: KeyEvent) -> super::EventResult {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            // `y` (yank) copies the selected vault's password to the clipboard.
            // Mirrors lazygit's yank and gopass's `-c`. The actual clipboard
            // write happens in the command handler (the App has no store); we
            // record a Copy pending action and break the loop.
            KeyCode::Char('y') => {
                if let Some(id) = self.selected_id().map(str::to_owned) {
                    self.pending = Some(PendingAction::Copy { id });
                    self.quit = true;
                }
            }
            KeyCode::Char('j') | KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') | KeyCode::Up => self.move_selection(-1),
            KeyCode::Char('g') => self.state.select(Some(0)),
            KeyCode::Char('G') => {
                let n = self.filtered_items().len();
                if n > 0 {
                    self.state.select(Some(n - 1));
                }
            }
            KeyCode::Enter => {
                // Enter on a list row requests a password reveal. The App does
                // not own the store, so it records a `Show` pending action and
                // breaks the loop; the command handler loads the secret and
                // re-enters the TUI directly in `ShowPassword` mode (holding
                // the secret). This keeps the state machine store-agnostic
                // while still showing the password.
                if let Some(id) = self.selected_id().map(str::to_owned) {
                    self.pending = Some(PendingAction::Show { id });
                    self.quit = true;
                }
            }
            KeyCode::Char('e') => {
                if self.selected_id().is_some() {
                    self.mode = Mode::EditPrompt;
                    self.input.reset();
                }
            }
            KeyCode::Char('a' | 'n') => {
                self.mode = Mode::AddPrompt;
                self.input.reset();
            }
            KeyCode::Char('d') => {
                if self.selected_id().is_some() {
                    self.mode = Mode::ConfirmDelete;
                }
            }
            KeyCode::Char('r') => {
                if self.selected_id().is_some() {
                    self.mode = Mode::RenamePrompt;
                    self.input.reset();
                }
            }
            KeyCode::Char('/') => {
                self.mode = Mode::Search;
                self.search.clear();
            }
            KeyCode::Char('s') => self.mode = Mode::SyncMenu,
            KeyCode::Char('?') => self.mode = Mode::Help,
            _ => {}
        }
        super::EventResult::Continue
    }

    fn on_search(&mut self, key: KeyEvent) -> super::EventResult {
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
        super::EventResult::Continue
    }

    fn on_show_password(&mut self, key: KeyEvent) -> super::EventResult {
        // "Hold Space to reveal": on terminals that support the Kitty keyboard
        // protocol (enabled in `tui::run` via REPORT_EVENT_TYPES), Space fires
        // a Press then a Release — we reveal on Press and hide on Release.
        // Terminals that only deliver Press (the default) get toggle-on-press
        // semantics as a graceful degrade (`08` §2.6, `#15`).
        match key.code {
            KeyCode::Char(' ') => match key.kind {
                KeyEventKind::Press => {
                    // Toggle when the terminal only emits Press (no Release
                    // will ever arrive); on capable terminals, the matching
                    // Release below flips it back off so the net effect is
                    // "revealed while held".
                    let now_revealed = !matches!(self.mode, Mode::ShowPassword { reveal: true });
                    self.mode = Mode::ShowPassword {
                        reveal: now_revealed,
                    };
                }
                KeyEventKind::Release => {
                    self.mode = Mode::ShowPassword { reveal: false };
                }
                KeyEventKind::Repeat => {}
            },
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                self.shown_secret = None;
                self.mode = Mode::Normal;
            }
            // `y` copies the currently-shown vault's password to the clipboard
            // (same handler as Normal mode's yank).
            KeyCode::Char('y') => {
                if let Some(id) = self.selected_id().map(str::to_owned) {
                    self.shown_secret = None;
                    self.pending = Some(PendingAction::Copy { id });
                    self.quit = true;
                }
            }
            _ => {}
        }
        super::EventResult::Continue
    }

    fn on_input(&mut self, key: KeyEvent) -> super::EventResult {
        // Enter / Esc are handled here (tui-input doesn't own "commit"/"cancel"
        // — those are app-level intents). Everything else (Backspace, arrows,
        // Ctrl-A/E/W, Home/End, char insertion) is delegated to tui-input via
        // its crossterm backend, which gives us full readline-style editing
        // for free.
        match key.code {
            KeyCode::Esc => {
                self.input.reset();
                self.mode = Mode::Normal;
            }
            KeyCode::Enter => {
                self.commit_input();
            }
            _ => {
                // tui-input only treats Press/Repeat as edits (Release is a
                // no-op); to_input_request returns None for non-edit events.
                let event = crossterm::event::Event::Key(key);
                if let Some(req) = tui_input::backend::crossterm::to_input_request(&event) {
                    self.input.handle(req);
                }
            }
        }
        super::EventResult::Continue
    }

    fn on_confirm_delete(&mut self, key: KeyEvent) -> super::EventResult {
        // lazygit-style confirmation: Enter confirms, Esc cancels (no y/n —
        // Enter is the universal "confirm" key in TUIs and harder to hit
        // accidentally than a letter).
        match key.code {
            KeyCode::Enter => {
                self.do_delete();
                // do_delete sets pending + quit; mode reset is irrelevant then.
            }
            KeyCode::Esc | KeyCode::Char('q') => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }
        super::EventResult::Continue
    }

    fn on_sync_menu(&mut self, key: KeyEvent) -> super::EventResult {
        // The popup advertises [p] push / [u] pull / [t] status. Each records a
        // pending action and breaks the loop so `tui_cmd` can drive the sync
        // engine (which needs a passphrase prompt — collected on the tty after
        // the TUI tears down, since in-TUI password input is out of scope for
        // now — `#19`).
        match key.code {
            KeyCode::Char('p') => {
                self.pending = Some(PendingAction::SyncPush);
                self.quit = true;
            }
            KeyCode::Char('u') => {
                self.pending = Some(PendingAction::SyncPull);
                self.quit = true;
            }
            KeyCode::Char('t') => {
                self.pending = Some(PendingAction::SyncStatus);
                self.quit = true;
            }
            KeyCode::Esc | KeyCode::Char('q') => self.mode = Mode::Normal,
            _ => {}
        }
        super::EventResult::Continue
    }

    fn on_sync_progress(&mut self, key: KeyEvent) -> super::EventResult {
        match key.code {
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => self.mode = Mode::Normal,
            _ => {}
        }
        super::EventResult::Continue
    }

    fn on_help(&mut self, key: KeyEvent) -> super::EventResult {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | '?') | KeyCode::Enter => {
                self.mode = Mode::Normal;
            }
            _ => {}
        }
        super::EventResult::Continue
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

    /// Commit the active input-mode (add/edit/rename). Persists via the
    /// injected store/index kept by the caller (we can't reach them from here,
    /// so the command handler reads `input` + `mode` after the loop exits and
    /// applies the change, then reloads). For simplicity we mark the action in
    /// `message`.
    fn commit_input(&mut self) {
        let action = match self.mode {
            Mode::AddPrompt => "add",
            Mode::EditPrompt => "edit",
            Mode::RenamePrompt => "rename",
            _ => return,
        };
        self.message = Some(format!("pending {action}: '{}'", self.input));
        // Signal exit to the loop so the command handler can apply + reload.
        self.quit = true;
    }

    fn do_delete(&mut self) {
        // Record the delete as an explicit pending action. We must NOT rely on
        // the mode-based fallthrough in `pending_action` because `on_confirm_delete`
        // resets `mode` to Normal right after calling us, which would otherwise
        // make `pending_action` miss it (returning `None` → the TUI exits without
        // deleting). Setting `pending` explicitly is unambiguous.
        if let Some(id) = self.selected_id().map(str::to_owned) {
            self.pending = Some(PendingAction::Delete { id });
            self.message = Some("pending delete".to_string());
            self.quit = true;
        }
    }
}

/// Actions the command handler must apply after the TUI loop exits (the state
/// machine does not own the store/index; it only records intent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingAction {
    None,
    Add {
        id: String,
    },
    Edit {
        id: String,
    },
    Rename {
        from: String,
        to: String,
    },
    Delete {
        id: String,
    },
    Show {
        id: String,
    },
    /// Copy the named vault's password to the clipboard. The command handler
    /// loads the secret, puts it on the clipboard, and arms an auto-clear
    /// timer (gopass `cliptimeout` pattern).
    Copy {
        id: String,
    },
    SyncPush,
    SyncPull,
    SyncStatus,
}

impl App {
    /// Decode the mode/input state into a pending action for the command
    /// handler to apply. Sync actions (set explicitly via `pending` by the
    /// SyncMenu) take precedence over mode-derived ones.
    #[must_use]
    pub fn pending_action(&self) -> PendingAction {
        // SyncMenu sets `pending` explicitly; surface it first so it isn't
        // shadowed by the mode fallthrough below.
        if let Some(action) = &self.pending {
            return action.clone();
        }
        match &self.mode {
            Mode::AddPrompt if self.quit => PendingAction::Add {
                id: self.input.value().to_string(),
            },
            Mode::EditPrompt if self.quit => PendingAction::Edit {
                id: self.selected_id().unwrap_or("").to_string(),
            },
            Mode::RenamePrompt if self.quit => PendingAction::Rename {
                from: self.selected_id().unwrap_or("").to_string(),
                to: self.input.value().to_string(),
            },
            Mode::ConfirmDelete if self.quit => PendingAction::Delete {
                id: self.selected_id().unwrap_or("").to_string(),
            },
            _ => PendingAction::None,
        }
    }
}

// Re-exported to keep ui.rs / commands concise.
pub use PendingAction as Action;

/// Helper used by command handlers to (re)build an [`App`] snapshot.
#[allow(clippy::missing_errors_doc)]
pub fn build_app<S: VaultStore>(store: &S, index: &VaultIndex) -> Result<App> {
    App::load(store, index)
}

// Quiet unused warnings for password import retained for future edit-flow.
#[allow(unused_imports)]
use password as _;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::mock::MockStore;
    use crossterm::event::KeyModifiers;

    fn make_app(ids: &[&str]) -> App {
        let store = MockStore::new();
        let dir = tempfile::TempDir::new().unwrap();
        let idx = VaultIndex::new(dir.path().join("index.json"));
        for id in ids {
            idx.add(id).unwrap();
            store.set(id, &VaultSecret::new("p".into())).unwrap();
        }
        App::load(&store, &idx).unwrap()
    }

    fn key(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
    }

    #[test]
    fn loads_items_sorted() {
        let app = make_app(&["prod", "dev"]);
        assert_eq!(app.items[0].id, "dev");
        assert_eq!(app.items[1].id, "prod");
        assert_eq!(app.state.selected(), Some(0));
    }

    #[test]
    fn j_k_moves_selection() {
        let mut app = make_app(&["dev", "prod", "staging"]);
        app.handle_event(Some(key('j')));
        assert_eq!(app.state.selected(), Some(1));
        app.handle_event(Some(key('k')));
        assert_eq!(app.state.selected(), Some(0));
    }

    #[test]
    fn g_big_g_jump_ends() {
        let mut app = make_app(&["a", "b", "c"]);
        app.handle_event(Some(key('G')));
        assert_eq!(app.state.selected(), Some(2));
        app.handle_event(Some(key('g')));
        assert_eq!(app.state.selected(), Some(0));
    }

    #[test]
    fn enter_requests_show_pending() {
        // Enter on a list row records a Show pending action + breaks the loop;
        // the command handler then loads the secret and re-enters in
        // ShowPassword mode (see `enter_show_password_loads_secret`).
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert!(app.should_quit());
        assert_eq!(
            app.pending_action(),
            PendingAction::Show { id: "dev".into() }
        );
    }

    #[test]
    fn enter_show_password_loads_secret() {
        // After the handler loads the secret, enter_show_password puts the app
        // into ShowPassword with the secret held — so draw_show_password has
        // something to render (was the root cause of "无法显示密码").
        let mut app = make_app(&["dev", "prod"]);
        // Select prod to verify the selection is repositioned to the shown id.
        app.handle_event(Some(key('j')));
        assert_eq!(app.state.selected(), Some(1));
        let secret = VaultSecret::new("the-password".into());
        app.enter_show_password("dev", secret);
        assert!(matches!(app.mode, Mode::ShowPassword { reveal: false }));
        assert_eq!(app.selected_id(), Some("dev"));
        assert!(app.shown_secret.is_some());
    }

    /// Helper: put an app straight into ShowPassword holding a secret, as the
    /// command handler does after a `PendingAction::Show`.
    fn app_in_show(ids: &[&str], secret: &str) -> App {
        let mut app = make_app(ids);
        app.enter_show_password(
            ids.first().copied().unwrap_or("x"),
            VaultSecret::new(secret.into()),
        );
        app
    }

    #[test]
    fn space_press_reveals_release_hides() {
        // Capable-terminal path: Press → reveal, Release → hide.
        let mut app = app_in_show(&["dev"], "p");
        let press =
            KeyEvent::new_with_kind(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
        app.handle_event(Some(press));
        assert!(matches!(app.mode, Mode::ShowPassword { reveal: true }));
        let release = KeyEvent::new_with_kind(
            KeyCode::Char(' '),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        app.handle_event(Some(release));
        assert!(matches!(app.mode, Mode::ShowPassword { reveal: false }));
        // Esc exits to Normal.
        app.handle_event(Some(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn space_press_only_toggles_on_dumb_terminal() {
        // Dumb-terminal path: only Press arrives, so two presses toggle
        // reveal off→on→off.
        let mut app = app_in_show(&["dev"], "p");
        let press =
            KeyEvent::new_with_kind(KeyCode::Char(' '), KeyModifiers::NONE, KeyEventKind::Press);
        app.handle_event(Some(press));
        assert!(matches!(app.mode, Mode::ShowPassword { reveal: true }));
        app.handle_event(Some(press));
        assert!(matches!(app.mode, Mode::ShowPassword { reveal: false }));
    }

    #[test]
    fn slash_enters_search() {
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('/')));
        assert_eq!(app.mode, Mode::Search);
        app.handle_event(Some(key('d')));
        assert_eq!(app.search, "d");
    }

    #[test]
    fn d_enters_confirm_delete() {
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('d')));
        assert_eq!(app.mode, Mode::ConfirmDelete);
    }

    #[test]
    fn confirm_delete_records_pending_and_quits() {
        // Regression: previously `do_delete` did not set `pending`, and
        // `on_confirm_delete` reset mode to Normal, so `pending_action`
        // returned None → the TUI exited without deleting. Now delete sets an
        // explicit pending action regardless of the mode reset.
        // Confirmation is via Enter (lazygit-style), not y/n.
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('d')));
        app.handle_event(Some(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));
        assert!(app.should_quit());
        assert_eq!(
            app.pending_action(),
            PendingAction::Delete { id: "dev".into() }
        );
    }

    #[test]
    fn confirm_delete_esc_cancels() {
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('d')));
        app.handle_event(Some(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        assert!(!app.should_quit());
        assert_eq!(app.pending_action(), PendingAction::None);
    }

    #[test]
    fn y_in_normal_records_copy_pending() {
        // `y` (yank) copies the selected vault's password. The App records a
        // Copy pending action; the command handler does the actual clipboard
        // write (the state machine is store-agnostic).
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('y')));
        assert!(app.should_quit());
        assert_eq!(
            app.pending_action(),
            PendingAction::Copy { id: "dev".into() }
        );
    }

    #[test]
    fn y_in_show_password_records_copy_pending() {
        // yank works inside the show view too (copy the currently-shown vault).
        let mut app = app_in_show(&["dev"], "secret");
        app.handle_event(Some(key('y')));
        assert!(app.should_quit());
        assert_eq!(
            app.pending_action(),
            PendingAction::Copy { id: "dev".into() }
        );
    }

    #[test]
    fn on_tick_clears_clipboard_after_deadline() {
        // A past deadline triggers a best-effort clipboard clear (no-op in
        // headless test env, but the deadline is consumed + message set).
        let mut app = make_app(&["dev"]);
        app.copy_deadline = Some(
            std::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .unwrap_or_else(std::time::Instant::now),
        );
        app.on_tick();
        assert!(app.copy_deadline.is_none(), "deadline should be consumed");
        assert!(
            app.message.as_deref().unwrap_or("").contains("cleared"),
            "expected clear message, got {:?}",
            app.message
        );
    }

    #[test]
    fn help_toggles() {
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('?')));
        assert_eq!(app.mode, Mode::Help);
        app.handle_event(Some(key('q')));
        assert_eq!(app.mode, Mode::Normal);
    }

    #[test]
    fn sync_menu_p_records_push_and_quits() {
        // Acceptance #11: the SyncMenu must actually act on p/u/t rather than
        // being a dead popup. Each key records a pending sync action.
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('s')));
        assert_eq!(app.mode, Mode::SyncMenu);
        app.handle_event(Some(key('p')));
        assert!(app.should_quit());
        assert_eq!(app.pending_action(), PendingAction::SyncPush);
    }

    #[test]
    fn sync_menu_u_pull_and_t_status() {
        let mut app_pull = make_app(&["dev"]);
        app_pull.handle_event(Some(key('s')));
        app_pull.handle_event(Some(key('u')));
        assert_eq!(app_pull.pending_action(), PendingAction::SyncPull);

        let mut app_status = make_app(&["dev"]);
        app_status.handle_event(Some(key('s')));
        app_status.handle_event(Some(key('t')));
        assert_eq!(app_status.pending_action(), PendingAction::SyncStatus);
    }

    #[test]
    fn sync_menu_esc_returns_without_pending() {
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('s')));
        app.handle_event(Some(key('p'))); // start a push intent...
                                          // (new session: user cancels instead)
        let mut app = make_app(&["dev"]);
        app.handle_event(Some(key('s')));
        app.handle_event(Some(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(app.mode, Mode::Normal);
        assert!(!app.should_quit());
        assert_eq!(app.pending_action(), PendingAction::None);
    }
}
