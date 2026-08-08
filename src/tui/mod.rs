//! TUI (see `08-cli-and-tui.md`).
//!
//! Single-view + popups, simplified gitui pattern. Uses `try_init()` /
//! `restore()` instead of `ratatui::run`/`init` (which panic on failure) to
//! honor the no-panic principle (reported deviation #3).
//!
//! On entry we request `KeyboardEnhancementFlags::REPORT_EVENT_TYPES` so
//! capable terminals (Kitty/WezTerm/foot/iTerm2/Windows Terminal — the WSL2
//! default) emit key *release* events. This lets "hold Space to reveal"
//! actually detect Space-up (`08` §2.6). Terminals that don't speak the Kitty
//! protocol silently ignore the push and only deliver Press events; the
//! show-password handler then degrades to toggle-on-press (`#15`).

pub mod app;
pub mod event;
pub mod ui;

pub use app::{App, Mode};
pub use event::EventResult;

use crate::error::{Error, Result};

/// Run the full TUI loop for the given [`App`] until the user quits.
pub fn run(app: &mut App) -> Result<()> {
    let mut terminal =
        ratatui::try_init().map_err(|e| Error::Other(anyhow::anyhow!("TUI init failed: {e}")))?;

    // Request key-release events from capable terminals (Kitty protocol /
    // CSI-u). Failure is non-fatal: dumb terminals ignore it, and the
    // reveal-on-hold handler degrades to toggle-on-press (`#15`).
    push_keyboard_enhancement_flags();

    let out = app_loop(app, &mut terminal);

    // Best-effort teardown of the enhancement flags.
    pop_keyboard_enhancement_flags();

    ratatui::restore();
    out
}

fn app_loop(app: &mut App, terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    loop {
        terminal
            .draw(|f| ui::draw(app, f))
            .map_err(|e| Error::Other(anyhow::anyhow!("TUI draw failed: {e}")))?;
        match event::poll()? {
            Some(event::TuiEvent::Key(k)) => match app.handle_event(Some(k)) {
                EventResult::Continue => {}
                EventResult::Quit => return Ok(()),
            },
            Some(event::TuiEvent::Tick) => app.on_tick(),
            None => {}
        }
        if app.should_quit() {
            return Ok(());
        }
    }
}

/// Push Kitty keyboard enhancement flags (REPORT_EVENT_TYPES) so capable
/// terminals send Release/Repeat events. Wrapped in `try_execute_queue`
/// because `PushKeyboardEnhancementFlags::execute` can panic on write errors;
/// we turn any failure into a debug log and keep going (graceful degrade).
fn push_keyboard_enhancement_flags() {
    use crossterm::event::{KeyboardEnhancementFlags, PushKeyboardEnhancementFlags};
    let flags = KeyboardEnhancementFlags::REPORT_EVENT_TYPES;
    if let Err(e) = crossterm::execute!(std::io::stdout(), PushKeyboardEnhancementFlags(flags)) {
        tracing::debug!(error = %e, "could not enable key-release events; falling back to toggle-on-press");
    }
}

fn pop_keyboard_enhancement_flags() {
    use crossterm::event::PopKeyboardEnhancementFlags;
    if let Err(e) = crossterm::execute!(std::io::stdout(), PopKeyboardEnhancementFlags) {
        tracing::debug!(error = %e, "could not pop keyboard enhancement flags");
    }
}
