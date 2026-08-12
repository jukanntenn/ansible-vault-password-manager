//! `avpm tui` - full interactive TUI.
//!
//! The TUI runs as a single `tui::run` call. Because the `App` owns the store
//! and index, every operation (copy/show/delete/add/edit/rename) happens
//! inline within the event loop; there is no outer rebuild loop, no pending
//! action queue, and the terminal never flickers to the raw shell mid-action.

use crate::config::Config;
use crate::error::Result;
use crate::index::VaultIndex;
use crate::tui;
use crate::vault::VaultStore;

pub async fn execute<S: VaultStore>(cfg: &Config, store: &S, index: &VaultIndex) -> Result<()> {
    let clipboard_secs = cfg.clipboard_config().clear_seconds;
    let mut app = tui::app::App::load(store, index, clipboard_secs)?;
    tui::run(&mut app)
}
