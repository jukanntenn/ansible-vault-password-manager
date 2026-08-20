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

use std::cell::RefCell;
use std::io::IsTerminal;

use crate::cli::{Cli, Command};
use crate::config::{Config, StorageBackend};
use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::paths;
use crate::vault::{gkr, master, ss, AnyStore, FileStore, KeyringStore, VaultError};

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

/// The backend a command should use, resolved from the config plus a live probe.
///
/// Replaces the old `backend_kind` collapse: `Auto` no longer silently degrades
/// to the file backend when the Secret Service daemon is down — it stops with
/// guidance instead (see [`resolve_effective_backend`]). The Secret Service
/// daemon is the floor: without it the master passphrase can't be
/// session-cached, so non-interactive (ansible) calls would fail.
enum ResolvedBackend {
    /// OS keyring — explicit `Keyring`, or `Auto` that preferred the keyring.
    Keyring,
    /// Encrypted file store, explicitly chosen (`backend = "file"`). The user
    /// opted in with eyes open; no guidance, no nudge.
    File,
    /// Encrypted file store chosen by `Auto` because the daemon is up but the
    /// absent default collection cannot be created here — no GUI to answer a
    /// prompt and no gnome-keyring control socket for terminal setup. It works
    /// (the session collection caches the master passphrase), but the user
    /// could upgrade to the keyring backend — `avpm unlock` emits a one-time
    /// nudge in this case.
    AutoFileNoGui,
}

/// Pure `Auto` decision, factored out so the table is unit-testable without a
/// live daemon. Composes [`ss::auto_prefers_keyring`] and adds the daemon-down
/// distinction that the old silent fallback lost:
/// - keyring preferred (collection ready/locked, or absent + something can
///   create it) → [`AutoDecision::Keyring`]
/// - daemon up but collection absent + no bootstrap option →
///   [`AutoDecision::AutoFileNoGui`]
/// - daemon unreachable → [`AutoDecision::NeedsGuidance`] (a hard stop, not a
///   silent file fallback: without the daemon the master passphrase can't be
///   session-cached, so non-interactive/ansible calls would fail)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutoDecision {
    Keyring,
    AutoFileNoGui,
    NeedsGuidance,
}

#[must_use]
fn auto_decide(
    status: Option<ss::DefaultCollectionStatus>,
    gui: bool,
    headless_bootstrap: bool,
) -> AutoDecision {
    if ss::auto_prefers_keyring(status, gui, headless_bootstrap) {
        AutoDecision::Keyring
    } else if status.is_none() {
        AutoDecision::NeedsGuidance
    } else {
        AutoDecision::AutoFileNoGui
    }
}

/// Resolve the effective backend for a command. The single resolution path
/// shared by [`resolve_store`] and `avpm unlock`. Explicit `Keyring`/`File` are
/// honored as-is; `Auto` is resolved by [`resolve_auto_backend`] (daemon-aware).
fn resolve_effective_backend(cfg: &Config) -> Result<ResolvedBackend> {
    match cfg.storage_config().backend {
        StorageBackend::Keyring => Ok(ResolvedBackend::Keyring),
        StorageBackend::File => Ok(ResolvedBackend::File),
        StorageBackend::Auto => resolve_auto_backend(),
    }
}

/// `Auto` resolution against a live probe. Daemon-down → guidance error (not a
/// silent file fallback); daemon-up with no way to bootstrap the collection
/// (neither GUI nor gnome-keyring control socket) → file backend (works, via
/// the session collection); otherwise → keyring.
fn resolve_auto_backend() -> Result<ResolvedBackend> {
    let status = ss::default_collection_status();
    let decision = auto_decide(
        status.as_ref().ok().copied(),
        ss::gui_available(),
        gkr::control_available(),
    );
    match decision {
        AutoDecision::Keyring => Ok(ResolvedBackend::Keyring),
        AutoDecision::AutoFileNoGui => Ok(ResolvedBackend::AutoFileNoGui),
        // NeedsGuidance implies the probe errored (auto_decide returns it only
        // when the status Option is None). Reuse the probe's error source.
        AutoDecision::NeedsGuidance => match status {
            Err(e) => Err(daemon_unreachable_error(e)),
            Ok(_) => Ok(ResolvedBackend::AutoFileNoGui),
        },
    }
}

/// Build the daemon-unreachable guidance error from the failed probe. Reuses
/// the probe's original `keyring::Error` source (the real D-Bus failure) and
/// rewrites the message so it states the ansible/session-cache consequence and
/// the two ways forward; `keyring_hint()` (auto-appended by the error display)
/// carries the install steps.
fn daemon_unreachable_error(err: Error) -> Error {
    match err {
        Error::Vault(VaultError::KeyringUnavailable { source, .. }) => {
            Error::Vault(VaultError::KeyringUnavailable {
                message: "Secret Service daemon is unreachable, so the OS keyring can't be used. \
                          Without the daemon the master passphrase also can't be session-cached, \
                          which means non-interactive (ansible) calls would fail. Either enable \
                          the keyring (steps below) or explicitly opt into the file backend by \
                          setting [storage] backend = \"file\" in the config (and provide the \
                          master passphrase via AVPM_MASTER_PASSPHRASE for automation)."
                    .to_string(),
                source,
            })
        }
        // Probe failed in an unexpected shape — surface it verbatim.
        other => other,
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

// In-process memo for an interactively-acquired master passphrase. A single
// command may need it twice (file-backend `sync`: once to decrypt `store.age`,
// once to encrypt the sync blob); the memo guarantees one prompt and one
// consistent value across those calls.
//
// Only the interactive branch writes it — `MASTER_PASSPHRASE_ENV` and
// session-cache hits return early without touching it, so env-driven tests are
// unaffected and there is no cross-test leakage (integration tests run avpm as
// subprocesses, each with its own thread-local).
thread_local! {
    static INTERACTIVE_PASSPHRASE: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Obtain a master passphrase, per the unlock contract:
///
/// 0. If one was already acquired interactively in this same process, reuse it
///    (see [`INTERACTIVE_PASSPHRASE`]) — at most one prompt per command.
/// 1. If [`MASTER_PASSPHRASE_ENV`] is set (and non-empty), use it directly —
///    explicit override, no cache or prompt. For CI / automation / tests.
/// 2. Else if a cached passphrase exists in the session collection, use it.
/// 3. Else if stdin is a TTY (interactive use), prompt and best-effort cache it
///    (a cache failure is downgraded to a warning, not a hard error, so the
///    user's just-typed passphrase still works for this invocation).
///    - First run ([`first_run_passphrase`]) → `prompt_confirm` (twice, no
///      typos). On the keyring backend this is the first `sync`; on the file
///      backend, the first `set`.
///    - Otherwise → a single `prompt`; verification happens implicitly when the
///      caller decrypts `store.age` / `sync-base.age` with it.
/// 4. Otherwise (non-interactive, e.g. ansible pipe), return `Locked` so the
///    caller exits with code 5 and a stderr hint - never block on stdin.
pub(crate) fn require_master_passphrase() -> Result<String> {
    // 0. In-process memo of an earlier interactive acquisition in this process.
    if let Some(p) = INTERACTIVE_PASSPHRASE.with(|m| m.borrow().clone()) {
        return Ok(p);
    }
    if let Ok(pw) = std::env::var(MASTER_PASSPHRASE_ENV) {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }
    if let Some(cached) = master::read_cached()? {
        return Ok(cached);
    }
    if std::io::stdin().is_terminal() {
        let first_run = first_run_passphrase(
            paths::store_path().exists(),
            paths::sync_base_path().exists(),
        );
        let passphrase = if first_run {
            // First establishment: explain what this is (distinct from the OS
            // keyring password) so the user isn't confused, then confirm twice.
            eprintln!(
                "This master passphrase encrypts your sync backup end-to-end (and your\n\
                 vault file on the file backend). It is separate from your OS keyring\n\
                 password, if any. Use the same one on every device you sync."
            );
            crate::password::prompt_confirm("Set master passphrase")?
                .as_str()
                .to_string()
        } else {
            crate::password::prompt("Master passphrase")?
                .as_str()
                .to_string()
        };
        INTERACTIVE_PASSPHRASE.with(|m| *m.borrow_mut() = Some(passphrase.clone()));
        // Best-effort session cache: if it won't hold it, the passphrase still
        // works for *this* process; just warn that it won't persist.
        if let Err(e) = master::cache(passphrase.as_str()) {
            eprintln!("warning: could not cache master passphrase ({e}); you may need to re-enter it later");
        }
        Ok(passphrase)
    } else {
        Err(Error::Vault(VaultError::Locked))
    }
}

/// Pure first-run predicate: the master passphrase is "not yet established" iff
/// no local encrypted artifact exists that it would have to decrypt — `store.age`
/// (file backend) or `sync-base.age` (sync snapshot). Before either exists the
/// user is establishing it (`Set`); afterward they provide the existing one
/// (`Enter`). The keyring backend never has `store.age`, but `sync-base.age`
/// appears after the first sync — so it MUST be part of the signal, else the
/// keyring backend would re-`Set` on every cold-cache sync (and a divergent
/// value would split `sync-base.age` decryption). Factored out so the decision
/// table is unit-testable without fs/tty access.
#[must_use]
fn first_run_passphrase(store_exists: bool, sync_base_exists: bool) -> bool {
    !store_exists && !sync_base_exists
}

/// Build a [`FileStore`] rooted at the default `store.age`, obtaining the
/// passphrase via [`require_master_passphrase`].
fn file_store() -> Result<FileStore> {
    let passphrase = require_master_passphrase()?;
    Ok(FileStore::new(paths::store_path(), passphrase))
}

/// Resolve the production store for a command via [`resolve_effective_backend`].
///
/// - `Keyring` (explicit or `Auto`-preferred): use the OS keyring.
/// - `File` / `AutoFileNoGui`: use the encrypted file store (prompts/caches the
///   master passphrase).
///
/// For the keyring backend, a **locked** collection in a *non-interactive* call
/// surfaces as [`VaultError::KeyringLocked`] (exit code 6) rather than blocking
/// on a GUI prompt — Ansible can detect this and prompt the user to run
/// `avpm unlock`. The lock state never causes a fallback to file (that would
/// split keyring/file data).
///
/// `Auto` with the Secret Service daemon unreachable surfaces as
/// [`VaultError::KeyringUnavailable`] (with guidance) rather than silently
/// degrading to the file backend — see [`resolve_effective_backend`].
pub fn resolve_store(cfg: &Config) -> Result<AnyStore> {
    match resolve_effective_backend(cfg)? {
        ResolvedBackend::File | ResolvedBackend::AutoFileNoGui => Ok(AnyStore::File(file_store()?)),
        ResolvedBackend::Keyring => {
            // A locked collection in a non-interactive call would otherwise
            // block on a GUI unlock prompt (the keyring crate's access path can
            // prompt). Surface it as a distinct exit code (6) and never fall
            // back to file. Interactive calls proceed and let the keyring crate
            // prompt on access.
            let locked_non_interactive = matches!(
                ss::default_collection_status(),
                Ok(ss::DefaultCollectionStatus::ExistsLocked)
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
        Command::Tui => {
            // Front-load any keyring bootstrap prompt while the terminal is
            // still plain — a password prompt (or GUI dialog trigger) from
            // inside the TUI would garble the screen.
            if matches!(store, AnyStore::Keyring(_)) {
                crate::vault::ss::ensure_default_collection()?;
            }
            tui_cmd::execute(cfg, &store, &index).await
        }
        Command::Sync { .. } | Command::List | Command::Config { .. } | Command::Unlock => {
            unreachable!("handled above")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{auto_decide, first_run_passphrase, AutoDecision};
    use crate::vault::ss::DefaultCollectionStatus as S;

    /// The first-run predicate's full decision table. The `(false, true)` cell
    /// is the keyring-backend fix: `store.age` never exists there, but
    /// `sync-base.age` does after the first sync → must NOT be first run.
    #[test]
    fn first_run_passphrase_decision_table() {
        // Nothing on disk yet → first run (Set).
        assert!(first_run_passphrase(false, false));
        // store.age present (file backend, after first set) → not first run.
        assert!(!first_run_passphrase(true, false));
        // sync-base.age present, store.age absent (keyring backend, post-sync)
        // → not first run. This is the regression guard.
        assert!(!first_run_passphrase(false, true));
        // Both present → not first run.
        assert!(!first_run_passphrase(true, true));
    }

    /// The `Auto` decision table. The `None` cells are the daemon-floor guard:
    /// daemon unreachable must guide (hard stop), never silently fall back to
    /// file. `(Some(Absent), gui=false, control=true)` is the headless
    /// keyring path: a gnome-keyring control socket bootstraps the collection
    /// from the terminal, no GUI needed.
    #[test]
    fn auto_decide_decision_table() {
        // Keyring-preferred (collection ready/locked; or absent + GUI; or
        // absent + control socket).
        assert_eq!(
            auto_decide(Some(S::Ready), false, false),
            AutoDecision::Keyring
        );
        assert_eq!(
            auto_decide(Some(S::Ready), true, true),
            AutoDecision::Keyring
        );
        assert_eq!(
            auto_decide(Some(S::ExistsLocked), false, false),
            AutoDecision::Keyring
        );
        assert_eq!(
            auto_decide(Some(S::Absent), true, false),
            AutoDecision::Keyring
        );
        assert_eq!(
            auto_decide(Some(S::Absent), false, true),
            AutoDecision::Keyring
        );

        // Daemon up, collection absent, no GUI and no control socket (e.g. a
        // non-gnome-keyring provider on a headless box) → file backend (works;
        // nudged in `avpm unlock`).
        assert_eq!(
            auto_decide(Some(S::Absent), false, false),
            AutoDecision::AutoFileNoGui
        );

        // Daemon DOWN → guidance, never silent file. Regression guard for
        // machine 2 (no Secret Service at all).
        assert_eq!(auto_decide(None, false, false), AutoDecision::NeedsGuidance);
        assert_eq!(auto_decide(None, true, true), AutoDecision::NeedsGuidance);
    }
}
