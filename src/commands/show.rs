//! `avpm show` - secure single-password TUI view.
//!
//! Opens a minimal TUI showing just one vault's password (hold to reveal /
//! copy). Unlike the full `avpm tui`, this view has no list and no mutations;
//! it shares the same `App` with an `index: None` so reveal/copy work.

use crate::config::Config;
use crate::error::Result;
use crate::tui;
use crate::vault::VaultStore;

pub async fn execute<S: VaultStore>(cfg: &Config, store: &S, vault_id: &str) -> Result<()> {
    // Eagerly read the secret so a missing vault-id fails before entering TUI.
    let secret = store.get(vault_id)?;
    let clipboard_secs = cfg.clipboard_config().clear_seconds;
    let mut app = tui::App::show_one(store, vault_id.to_string(), secret, clipboard_secs);
    tui::run(&mut app)
}
