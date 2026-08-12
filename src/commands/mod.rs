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
use crate::vault::{master, AnyStore, FileStore, KeyringStore, VaultError, VaultStore};

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

/// Which backing store is in effect for this config, without constructing it.
///
/// This is the lightweight, side-effect-free companion to [`resolve_store`]:
/// it answers "keyring or file?" so callers that must behave differently per
/// backend (notably `avpm unlock`) can branch without paying for a full store
/// build (which, for the file backend, would prompt for the master passphrase).
#[must_use]
pub fn backend_kind(cfg: &Config) -> StorageBackend {
    match cfg.storage_config().backend {
        explicit @ (StorageBackend::Keyring | StorageBackend::File) => explicit,
        StorageBackend::Auto => match probe_keyring(cfg.service()) {
            Ok(()) => StorageBackend::Keyring,
            Err(_) => StorageBackend::File,
        },
    }
}

/// Probe whether the OS keyring is reachable, using a **read-only** lookup.
///
/// We `get` an entry that is guaranteed not to exist. The outcome tells us
/// about the keyring itself, not the entry:
/// - `NotFound` (`keyring::Error::NoEntry`) — the keyring answered, so it is
///   reachable and usable. Return `Ok(())`.
/// - `KeyringUnavailable` / `KeyringFailed` — the keyring cannot be reached
///   (no Secret Service daemon, locked, etc.). Return `Err`.
///
/// Read-only probing has no side effects: unlike a write+delete probe, it
/// never triggers a macOS Keychain authorization dialog and never leaves
/// stray entries behind. It also makes `resolve_store` cheap to call on
/// every command.
fn probe_keyring(service: &str) -> Result<()> {
    let store = KeyringStore::new(service);
    match store.get("_avpm_probe_") {
        // The keyring answered — either with NotFound (the probe entry
        // doesn't exist, but the keyring itself is up) or, improbably, with
        // a value. Both mean the keyring is reachable and usable.
        Err(Error::Vault(VaultError::NotFound(_))) | Ok(_) => Ok(()),
        // The keyring is unreachable — fall back to the file store.
        Err(e) => Err(e),
    }
}

/// Environment-variable escape hatch for the file-backend master passphrase.
///
/// When set, [`require_master_passphrase`] uses it directly — no keyring lookup,
/// no interactive prompt. This is intended for non-interactive / CI use where
/// stdin is not a TTY and no passphrase is cached, and for driving the file
/// backend in automated tests without an `rpassword` prompt (which would
/// conflict with `crossterm`'s terminal setup under a pty).
pub const MASTER_PASSPHRASE_ENV: &str = "AVPM_MASTER_PASSPHRASE";

/// Obtain a master passphrase for the file backend, per the unlock contract:
///
/// 1. If [`MASTER_PASSPHRASE_ENV`] is set (and non-empty), use it directly —
///    explicit override, no cache or prompt. For CI / automation / tests.
/// 2. Else if a cached passphrase exists in the keyring, use it.
/// 3. Else if stdin is a TTY (interactive use), prompt and best-effort cache it
///    (a cache failure is downgraded to a warning, not a hard error, so the
///    user's just-typed passphrase still works for this invocation).
///    - If `store.age` does not exist yet (first run), use `prompt_confirm`
///      so the user types the new passphrase twice, preventing typos.
///    - If `store.age` exists, use a single `prompt` (verification happens
///      implicitly when the caller tries to decrypt with it).
/// 4. Otherwise (non-interactive, e.g. ansible pipe), return `Locked` so the
///    caller exits with code 5 and a stderr hint - never block on stdin.
pub(crate) fn require_master_passphrase() -> Result<String> {
    if let Ok(pw) = std::env::var(MASTER_PASSPHRASE_ENV) {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }
    if let Some(cached) = master::read_cached()? {
        return Ok(cached);
    }
    if std::io::stdin().is_terminal() {
        let passphrase = if paths::store_path().exists() {
            crate::password::prompt("Master passphrase")?
                .as_str()
                .to_string()
        } else {
            crate::password::prompt_confirm("Set master passphrase")?
                .as_str()
                .to_string()
        };
        // Best-effort cache: if the keyring won't hold it, the passphrase still
        // works for *this* process; just warn that it won't persist.
        if let Err(e) = master::cache(passphrase.as_str()) {
            eprintln!("warning: could not cache master passphrase ({e}); you may need to re-enter it later");
        }
        Ok(passphrase)
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
/// - `Auto` (default): probe the OS keyring with a read-only lookup; if it is
///   reachable use it, otherwise fall back to the encrypted file store.
///
/// `Auto` is **purely probe-driven**: the keyring is used whenever it answers,
/// regardless of whether a `store.age` exists. A prior accidental `avpm
/// unlock`/`set` that created `store.age` therefore never locks the user out
/// of the keyring on a healthy system (macOS Keychain, Linux desktop). On
/// headless boxes without a Secret Service daemon (WSL2 without a GUI), the
/// probe fails and the file store is used as intended.
pub fn resolve_store(cfg: &Config) -> Result<AnyStore> {
    // backend_kind already collapses Auto into Keyring/File, so we only ever
    // see those two here; Keyring is the natural default for the collapsed
    // Auto→Keyring path.
    match backend_kind(cfg) {
        StorageBackend::File => Ok(AnyStore::File(file_store()?)),
        StorageBackend::Keyring | StorageBackend::Auto => {
            Ok(AnyStore::Keyring(KeyringStore::new(cfg.service())))
        }
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
        Command::Unlock => return unlock::execute(cfg).await,
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
        Command::Show { vault_id } => show::execute(cfg, &store, &vault_id).await,
        Command::Rename { from, to } => rename::execute(&store, &index, &from, &to).await,
        Command::Tui => tui_cmd::execute(cfg, &store, &index).await,
        Command::Sync { .. } | Command::List | Command::Config { .. } | Command::Unlock => {
            unreachable!("handled above")
        }
    }
}
