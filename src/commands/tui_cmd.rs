//! `avpm tui` - full interactive TUI.

use crate::config::Config;
use crate::error::Result;
use crate::index::VaultIndex;
use crate::tui;
use crate::tui::app::PendingAction;
use crate::vault::VaultStore;

pub async fn execute<S: VaultStore>(cfg: &Config, store: &S, index: &VaultIndex) -> Result<()> {
    // `pending_msg` carries a status message (success or error) from the
    // previous loop iteration into the next TUI render so the user sees
    // feedback inside the TUI rather than on stderr after quitting.
    let mut pending_msg: Option<String> = None;
    // `pending_copy_deadline` carries a clipboard-clear deadline across loop
    // iterations so the timer survives the TUI teardown/rebuild around actions.
    let mut pending_copy_deadline: Option<std::time::Instant> = None;
    loop {
        let mut app = tui::app::build_app(store, index)?;
        app.message = pending_msg.take();
        app.copy_deadline = pending_copy_deadline.take();
        tui::run(&mut app)?;
        // Apply any pending action, then loop (reload) so the user stays in the TUI.
        match app.pending_action() {
            PendingAction::None => return Ok(()),
            PendingAction::Copy { id } => {
                // yank: load secret, write to clipboard, arm auto-clear.
                match store.get(&id) {
                    Ok(secret) => {
                        let secs = cfg.clipboard_config().clear_seconds;
                        match copy_to_clipboard(secret.as_str(), secs) {
                            Ok(CopyOutcome::Copied { cleared_in }) => {
                                if secs > 0 {
                                    pending_copy_deadline = Some(
                                        std::time::Instant::now()
                                            + std::time::Duration::from_secs(u64::from(secs)),
                                    );
                                    pending_msg = Some(format!(
                                        "Copied '{id}' to clipboard (clears in {cleared_in}s)"
                                    ));
                                } else {
                                    pending_msg = Some(format!("Copied '{id}' to clipboard"));
                                }
                            }
                            Ok(CopyOutcome::Unavailable) => {
                                pending_msg = Some(format!(
                                    "Clipboard unavailable on this system; press Enter to reveal '{id}'"
                                ));
                            }
                            Err(e) => {
                                pending_msg = Some(format!("Copy failed: {e}"));
                            }
                        }
                    }
                    Err(e) => pending_msg = Some(format!("Failed to load '{id}': {e}")),
                }
            }
            PendingAction::Show { id } => {
                // Enter on a list row: load the secret and re-enter the TUI
                // directly in ShowPassword mode. On Esc the user returns to the
                // list (the outer loop reloads from Normal mode).
                match store.get(&id) {
                    Ok(secret) => {
                        let mut show_app = tui::app::build_app(store, index)?;
                        show_app.enter_show_password(&id, secret);
                        tui::run(&mut show_app)?;
                    }
                    Err(e) => pending_msg = Some(format!("✗ Failed to load '{id}': {e}")),
                }
            }
            PendingAction::Add { id } => match apply_add(store, index, &id) {
                Ok(()) => pending_msg = Some(format!("✓ Added '{id}'")),
                Err(e) => pending_msg = Some(format!("✗ Add failed: {e}")),
            },
            PendingAction::Edit { id } => match apply_edit(store, index, &id) {
                Ok(()) => pending_msg = Some(format!("✓ Updated '{id}'")),
                Err(e) => pending_msg = Some(format!("✗ Edit failed: {e}")),
            },
            PendingAction::Rename { from, to } => {
                apply_rename(store, index, &from, &to);
                pending_msg = Some(format!("✓ Renamed '{from}' → '{to}'"));
            }
            PendingAction::Delete { id } => {
                apply_delete(store, index, &id);
                pending_msg = Some(format!("✓ Deleted '{id}'"));
            }
            // SyncMenu (p/u/t) recorded an action; defer to the sync command
            // handler which collects the passphrase and drives the backend.
            // We stay in the loop: after sync completes the TUI reloads.
            PendingAction::SyncPush => {
                match run_sync(
                    cfg,
                    store,
                    index,
                    crate::cli::SyncCmd::Push { message: None },
                )
                .await
                {
                    Ok(()) => pending_msg = Some("✓ Sync push complete".to_string()),
                    Err(e) => pending_msg = Some(format!("✗ Sync push failed: {e}")),
                }
            }
            PendingAction::SyncPull => {
                match run_sync(cfg, store, index, crate::cli::SyncCmd::Pull).await {
                    Ok(()) => pending_msg = Some("✓ Sync pull complete".to_string()),
                    Err(e) => pending_msg = Some(format!("✗ Sync pull failed: {e}")),
                }
            }
            PendingAction::SyncStatus => {
                match run_sync(cfg, store, index, crate::cli::SyncCmd::Status).await {
                    Ok(()) => pending_msg = Some("✓ Sync status fetched".to_string()),
                    Err(e) => pending_msg = Some(format!("✗ Sync status failed: {e}")),
                }
            }
        }
    }
}

async fn run_sync<S: VaultStore>(
    cfg: &Config,
    store: &S,
    index: &VaultIndex,
    cmd: crate::cli::SyncCmd,
) -> Result<()> {
    // Defer to the same handler `avpm sync` uses. The TUI has been torn down
    // before we get here, so the passphrase prompt lands on the tty as normal.
    crate::commands::sync_cmd::execute(cfg, store, index, cmd).await
}

fn apply_add<S: VaultStore>(store: &S, index: &VaultIndex, id: &str) -> Result<()> {
    use crate::password;
    if id.is_empty() {
        return Ok(());
    }
    let secret = password::prompt_confirm(&format!("Password for '{id}'"))?;
    store.set(id, &secret)?;
    index.add(id)?;
    Ok(())
}

fn apply_edit<S: VaultStore>(store: &S, index: &VaultIndex, id: &str) -> Result<()> {
    use crate::password;
    if id.is_empty() {
        return Ok(());
    }
    let secret = password::prompt_confirm(&format!("New password for '{id}'"))?;
    store.set(id, &secret)?;
    index.add(id)?;
    Ok(())
}

fn apply_rename<S: VaultStore>(store: &S, index: &VaultIndex, from: &str, to: &str) {
    if let Ok(secret) = store.get(from) {
        if store.set(to, &secret).is_ok() && index.add(to).is_ok() {
            let _ = store.delete(from);
            let _ = index.remove(from);
        }
    }
}

fn apply_delete<S: VaultStore>(store: &S, index: &VaultIndex, id: &str) {
    if store.delete(id).is_ok() {
        let _ = index.remove(id);
    }
}

/// Outcome of a clipboard copy attempt.
enum CopyOutcome {
    /// Password written to the clipboard; `cleared_in` is the auto-clear window
    /// in seconds (0 = no auto-clear configured).
    Copied { cleared_in: u16 },
    /// No clipboard available (headless / no display). Caller should fall back
    /// to revealing the password in the TUI instead.
    Unavailable,
}

/// Copy `secret` to the system clipboard via `arboard`. Returns
/// [`CopyOutcome::Unavailable`] when the clipboard can't be reached (headless
/// boxes, no display server) so the caller can degrade gracefully rather than
/// surfacing a hard error.
fn copy_to_clipboard(secret: &str, clear_seconds: u16) -> Result<CopyOutcome> {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        cb.set_text(secret)
            .map_err(|e| crate::error::Error::Other(anyhow::anyhow!("clipboard write: {e}")))?;
        Ok(CopyOutcome::Copied {
            cleared_in: clear_seconds,
        })
    } else {
        // arboard fails fast when there's no display / clipboard daemon
        // (WSL2 headless, pure SSH, CI). Treat as a soft "unavailable".
        tracing::debug!("clipboard unavailable; falling back to reveal");
        Ok(CopyOutcome::Unavailable)
    }
}
