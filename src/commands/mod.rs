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
use crate::vault::{master, AnyStore, FileStore, KeyringStore, VaultError};

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
        StorageBackend::Auto => {
            if keyring_usable_for_auto() {
                StorageBackend::Keyring
            } else {
                StorageBackend::File
            }
        }
    }
}

/// Decide whether the `Auto` backend should resolve to the keyring, based on
/// the **persistent** existence of the default Secret Service collection —
/// never its volatile lock state. Falling back to file merely because the
/// collection is locked would split keyring/file data ("passwords look gone").
///
/// Decision table:
/// - daemon unreachable → file
/// - collection exists (ready *or* locked) → keyring (the lock only decides
///   whether a non-interactive caller must first run `avpm unlock`; see
///   [`resolve_store`])
/// - collection absent + a GUI is reachable (`DISPLAY`/`WAYLAND_DISPLAY`) →
///   keyring (the first `set` creates it via a GUI prompt)
/// - collection absent + no GUI → file (a headless box cannot create it
///   non-interactively)
///
/// Side-effect-free: connect + `ReadAlias` + `Locked` property + env-var
/// checks. Never prompts, so [`backend_kind`] stays cheap to call on every
/// command. On non-Secret-Service platforms the probe always reports "ready",
/// preserving existing macOS/Windows behavior.
fn keyring_usable_for_auto() -> bool {
    let status = crate::vault::ss::default_collection_status().ok();
    crate::vault::ss::auto_prefers_keyring(status, crate::vault::ss::gui_available())
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
/// - `Auto` (default): use the keyring when its default collection exists (or
///   can be created via a GUI on first `set`); otherwise fall back to file.
///
/// For the keyring backend, a **locked** collection in a *non-interactive*
/// call surfaces as [`VaultError::KeyringLocked`] (exit code 6) rather than
/// blocking on a GUI prompt — Ansible can detect this and prompt the user to
/// run `avpm unlock`. The lock state never causes a fallback to file (that
/// would split keyring/file data); only *collection absence* can.
pub fn resolve_store(cfg: &Config) -> Result<AnyStore> {
    // backend_kind already collapses Auto into Keyring/File, so we only ever
    // see those two here; Keyring is the natural default for the collapsed
    // Auto→Keyring path.
    match backend_kind(cfg) {
        StorageBackend::File => Ok(AnyStore::File(file_store()?)),
        StorageBackend::Keyring | StorageBackend::Auto => {
            // A locked collection in a non-interactive call would otherwise
            // block on a GUI unlock prompt (the keyring crate's access path can
            // prompt). Surface it as a distinct exit code (6) and never fall
            // back to file. Interactive calls proceed and let the keyring
            // crate prompt on access.
            let locked_non_interactive = matches!(
                crate::vault::ss::default_collection_status(),
                Ok(crate::vault::ss::DefaultCollectionStatus::ExistsLocked)
            ) && !std::io::stdin().is_terminal();
            if locked_non_interactive {
                return Err(Error::Vault(VaultError::KeyringLocked));
            }
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
