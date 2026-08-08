//! `avpm show` - secure single-password TUI view.

use crate::error::Result;
use crate::tui;
use crate::vault::VaultStore;

pub async fn execute<S: VaultStore>(store: &S, vault_id: &str) -> Result<()> {
    // Eagerly read the secret so a missing vault-id fails before entering TUI.
    let secret = store.get(vault_id)?;
    let mut app = tui::App::show_one(vault_id.to_string(), secret);
    tui::run(&mut app)
}
