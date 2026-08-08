//! Command dispatch.
//!
//! Thin orchestration layer. Each handler is a generic function over
//! `<S: VaultStore>`. `dispatch` resolves the default-action (`avpm <id>` →
//! `get`) and the `--vault-id` ansible-client form.
//!
//! All handlers are `async` for a uniform dispatch signature even when they
//! don't await - that's why we allow `unused_async` module-wide.

#![allow(clippy::unused_async)]

pub mod config_cmd;
pub mod get;
pub mod list;
pub mod remove;
pub mod rename;
pub mod set;
pub mod show;
pub mod sync_cmd;
pub mod tui_cmd;
pub mod unlock;

use std::io::IsTerminal;

use crate::cli::{Cli, Command};
use crate::config::{Config, StorageBackend};
use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::paths;
use crate::vault::{
    master, AnyStore, FileStore, KeyringStore, VaultError, VaultSecret, VaultStore,
};

/// Resolve the effective command, accounting for the default-action form
/// and the ansible client form.
fn resolve_command(cli: &Cli) -> Result<Command> {
    if let Some(cmd) = &cli.command {
        return Ok((*cmd).clone());
    }
    if let Some(id) = &cli.vault_id {
        return Ok(Command::Get {
            vault_id: id.clone(),
        });
    }
    if let [first, ..] = cli.positional.as_slice() {
        return Ok(Command::Get {
            vault_id: first.clone(),
        });
    }
    Err(Error::Other(anyhow::anyhow!(
        "no command given. Run `avpm --help` for usage."
    )))
}

/// Probe whether the OS keyring is usable by writing and deleting a throwaway
/// entry. Returns `Ok(())` on success, `Err` if the keyring is unavailable.
fn probe_keyring(service: &str) -> Result<()> {
    let store = KeyringStore::new(service);
    let probe_id = "_avpm_probe_";
    let secret = VaultSecret::new("probe".to_string());
    store.set(probe_id, &secret)?;
    // Clean up the probe entry; a failure to delete is non-fatal (we already
    // confirmed writability), so ignore it.
    let _ = store.delete(probe_id);
    Ok(())
}

/// Obtain a master passphrase for the file backend, per the unlock contract:
///
/// 1. If a cached passphrase exists in the keyring, use it.
/// 2. Otherwise, if stdin is a TTY (interactive use), prompt and best-effort
///    cache it (a cache failure is downgraded to a warning, not a hard error,
///    so the user's just-typed passphrase still works for this invocation).
/// 3. Otherwise (non-interactive, e.g. ansible pipe), return `Locked` so the
///    caller exits with code 5 and a stderr hint - never block on stdin.
pub(crate) fn require_master_passphrase() -> Result<String> {
    if let Some(cached) = master::read_cached()? {
        return Ok(cached);
    }
    if std::io::stdin().is_terminal() {
        let passphrase = crate::password::prompt("Master passphrase")?;
        // Best-effort cache: if the keyring won't hold it, the passphrase still
        // works for *this* process; just warn that it won't persist.
        if let Err(e) = master::cache(passphrase.as_str()) {
            eprintln!("warning: could not cache master passphrase ({e}); you may need to re-enter it later");
        }
        Ok(passphrase.as_str().to_string())
    } else {
        Err(Error::Vault(VaultError::Locked))
    }
}

/// Build a [`FileStore`] rooted at the default `store.age`, obtaining the
/// passphrase via [`require_master_passphrase`].
fn file_store() -> Result<FileStore> {
    let passphrase = require_master_passphrase()?;
    Ok(FileStore::new(paths::store_path(), passphrase))
}

/// Resolve the production store from the config's `[storage].backend` setting.
///
/// - `Keyring`: use the OS keyring; failure propagates (explicit user choice).
/// - `File`: use the encrypted file store (prompts/caches master passphrase).
/// - `Auto` (default): prefer the file store once it exists (a prior `avpm
///   unlock`/`set` created `store.age`, signalling the user is on the file
///   backend). Otherwise probe the OS keyring; if that is unavailable (e.g.
///   WSL2 without a GUI to unlock GNOME Keyring) fall back to the file store.
///
/// The "store.age exists ⇒ prefer file" rule avoids a subtle misjudgement on
/// WSL2: the Secret Service `session` collection is writable but non-persistent,
/// so a naive keyring probe could succeed there yet lose data on the next WSL
/// restart. On healthy systems (macOS Keychain, Linux desktop with an unlocked
/// `login` collection) `store.age` never exists, so the keyring is used as
/// intended. On WSL2 the default alias points at `/` (no `login`), the probe
/// fails, and the user is routed to the file backend on first use.
pub fn resolve_store(cfg: &Config) -> Result<AnyStore> {
    let store_path = paths::store_path();
    match cfg.storage_config().backend {
        StorageBackend::Keyring => Ok(AnyStore::Keyring(KeyringStore::new(cfg.service()))),
        StorageBackend::File => Ok(AnyStore::File(file_store()?)),
        StorageBackend::Auto if store_path.exists() => {
            // User has already initialized the file backend (prior unlock/set).
            // Stick with it so data stays in the persistent store.age rather
            // than being written through a possibly-ephemeral session keyring.
            Ok(AnyStore::File(file_store()?))
        }
        StorageBackend::Auto => match probe_keyring(cfg.service()) {
            Ok(()) => Ok(AnyStore::Keyring(KeyringStore::new(cfg.service()))),
            Err(_) => Ok(AnyStore::File(file_store()?)),
        },
    }
}

/// The default index handle.
pub fn index_handle() -> VaultIndex {
    VaultIndex::new(paths::index_path())
}

/// Dispatch the resolved command, driving the appropriate handler.
pub async fn dispatch(cli: &Cli, cfg: &Config) -> Result<()> {
    let cmd = resolve_command(cli)?;
    // Several commands never touch the vault store, so resolving a backend
    // (which may prompt for a master passphrase or fail non-interactively)
    // would only get in their way. Dispatch them before store resolution.
    match cmd {
        Command::Unlock => return unlock::execute().await,
        Command::Config { cmd } => return config_cmd::execute(cfg, cmd).await,
        Command::List => return list::execute(&index_handle()).await,
        Command::Sync { cmd: sync_cmd } => {
            // sync must report "not configured" before touching the store
            // (which may need a master passphrase); check config first.
            if cfg.sync_config().is_none() {
                return Err(Error::Sync(crate::sync::SyncError::NotConfigured));
            }
            let store = resolve_store(cfg)?;
            return sync_cmd::execute(cfg, &store, &index_handle(), sync_cmd).await;
        }
        _ => {}
    }
    let store = resolve_store(cfg)?;
    let index = index_handle();
    match cmd {
        Command::Get { vault_id } => get::execute(&store, &vault_id).await,
        Command::Set {
            vault_id,
            generate,
            length,
            no_symbols,
        } => set::execute(&store, &index, &vault_id, generate, length, no_symbols).await,
        Command::Rm { vault_ids, force } => {
            remove::execute(&store, &index, &vault_ids, force).await
        }
        Command::Show { vault_id } => show::execute(&store, &vault_id).await,
        Command::Rename { from, to } => rename::execute(&store, &index, &from, &to).await,
        Command::Tui => tui_cmd::execute(cfg, &store, &index).await,
        Command::Sync { .. } | Command::List | Command::Config { .. } | Command::Unlock => {
            unreachable!("handled above")
        }
    }
}
