//! TUI — full-screen interactive vault manager.
//!
//! Architecture (post-rebuild): the [`App`] state machine owns references to
//! the vault `store` and `index`, so every operation (copy / show / delete /
//! add / edit / rename) is executed **inside** the event loop without tearing
//! the TUI down. There is no pending-action queue and no outer rebuild loop;
//! the screen never flickers or drops to the raw terminal mid-operation.
//!
//! We use `ratatui::try_init()` / `restore()` (instead of the panicking
//! `init`/`run`) to honor the no-panic principle.

pub mod app;
pub mod event;
pub mod ui;

pub use app::{App, FormKind, Mode};
pub use event::EventResult;

use crate::error::{Error, Result};
use crate::vault::VaultStore;

/// Run the full TUI loop, driving `app` until the user quits.
///
/// The terminal is entered in raw mode and restored on exit (including on
/// error paths). The caller owns `app` (and the store/index it borrows); this
/// function only renders and dispatches events.
pub fn run<S: VaultStore>(app: &mut App<'_, S>) -> Result<()> {
    let mut terminal =
        ratatui::try_init().map_err(|e| Error::Other(anyhow::anyhow!("TUI init failed: {e}")))?;

    let out = app_loop(app, &mut terminal);

    ratatui::restore();
    out
}

fn app_loop<S: VaultStore>(
    app: &mut App<'_, S>,
    terminal: &mut ratatui::DefaultTerminal,
) -> Result<()> {
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
