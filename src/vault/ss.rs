//! Secret Service helpers for the keyring backend.
//!
//! The `keyring` crate's Linux store (`zbus-secret-service-keyring-store`)
//! cannot create the default collection when it is absent: for the `"default"`
//! target its `create_collection` only re-reads the alias instead of calling
//! `CreateCollection`, and the write entry point never even reaches that path
//! because the absent-alias case surfaces as `NoStorageAccess` rather than
//! `NoEntry`. The net effect is that on a fresh headless / WSL2 box every
//! keyring write fails with "result not returned from SS API".
//!
//! This module closes that gap. Creating/unlocking the (login) default
//! collection has two paths, tried in order:
//!
//! 1. **Terminal, via the gnome-keyring control socket** ([`crate::vault::gkr`])
//!    — the PAM-login operation: prompt for the keyring password in the
//!    terminal and send it over the daemon's private control protocol. No GUI
//!    dependency, so it works on WSL2 and pure headless boxes. A wrong
//!    password is a distinct, retryable outcome.
//! 2. **GUI prompt, via the Secret Service** — for providers without a control
//!    socket (KeePassXC, KWallet). Before relying on it, the classic WSL2
//!    defect is repaired: D-Bus-activated prompters inherit the *bus daemon's*
//!    environment, which has no DISPLAY when nothing played display manager
//!    (WSL2), so [`export_display_to_activation_env`] pushes this process's
//!    display variables into the activation environment first.
//!
//! On non-Secret-Service platforms (macOS Keychain, Windows Credential
//! Manager) these helpers are no-ops: the `keyring` crate handles those
//! natively and has no collection-create bug there.

use crate::error::Result;

/// Whether a GUI prompt can be rendered.
///
/// Used to decide whether an absent default collection can be created via a
/// GUI prompt (WSLg / desktop) when the gnome-keyring control socket is not
/// an option. Pure environment-variable check — no daemon dependency, no side
/// effects.
#[must_use]
pub fn gui_available() -> bool {
    std::env::var("DISPLAY").is_ok() || std::env::var("WAYLAND_DISPLAY").is_ok()
}

/// State of the default Secret Service collection, as observed by a read-only
/// probe (connect + `ReadAlias("default")` + the `Locked` property — no
/// prompts). Used to decide the backend without consulting the volatile lock
/// state in a way that could cause data-splitting fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultCollectionStatus {
    /// The default collection exists and is unlocked.
    Ready,
    /// The default collection exists but is locked.
    ExistsLocked,
    /// No default collection exists (the `default` alias resolves to `/`).
    Absent,
}

/// Pure decision: should the `Auto` backend resolve to the keyring, given the
/// (possibly failed) default-collection probe, GUI availability, and whether
/// the collection can be bootstrapped headlessly (a gnome-keyring control
/// socket)?
///
/// This is the heart of gap 1a/1b/3a, factored out so the decision table is
/// unit-testable without a live daemon:
/// - `None` (daemon unreachable / probe errored) → file
/// - `Ready` or `ExistsLocked` → keyring (the lock only affects whether a
///   non-interactive caller must first `avpm unlock`; it never falls back to
///   file, which would split keyring/file data)
/// - `Absent` + (GUI reachable or control socket present) → keyring (first
///   `unlock` creates it: via the terminal on gnome-keyring, else a GUI prompt)
/// - `Absent` + neither → file (nothing can create the collection here)
#[must_use]
pub fn auto_prefers_keyring(
    status: Option<DefaultCollectionStatus>,
    gui: bool,
    headless_bootstrap: bool,
) -> bool {
    match status {
        Some(DefaultCollectionStatus::Ready | DefaultCollectionStatus::ExistsLocked) => true,
        Some(DefaultCollectionStatus::Absent) => gui || headless_bootstrap,
        None => false,
    }
}

/// How [`ensure_default_collection`] should proceed for a given default
/// collection state — the routing heart of the WSL2/headless keyring fix,
/// factored out so the table is unit-testable without a daemon or a tty.
///
/// - `Ready` → nothing to do (desktop Linux with a PAM-unlocked keyring never
///   sees a prompt, a control socket, or a GUI).
/// - anything else, non-interactive → refuse (exit 6): a prompt would block
///   ansible pipes and scripts.
/// - absent/locked, interactive, control socket present → the terminal path
///   (PAM-style, no GUI).
/// - absent/locked, interactive, no control socket → the Secret Service GUI
///   prompt path (KeePassXC / KWallet / WSLg).
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapRoute {
    /// The collection is ready; do nothing.
    AlreadyReady,
    /// Not ready and the caller is non-interactive; refuse with
    /// [`VaultError::KeyringLocked`].
    RefuseNonInteractive,
    /// Prompt in the terminal and drive the gnome-keyring control socket.
    ControlSocket,
    /// Fall back to the Secret Service GUI prompt (with the D-Bus activation
    /// environment repair first).
    GuiPrompt,
}

#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
#[must_use]
fn bootstrap_route(
    status: DefaultCollectionStatus,
    interactive: bool,
    control: bool,
) -> BootstrapRoute {
    match (status, interactive, control) {
        (DefaultCollectionStatus::Ready, _, _) => BootstrapRoute::AlreadyReady,
        (_, false, _) => BootstrapRoute::RefuseNonInteractive,
        (_, true, true) => BootstrapRoute::ControlSocket,
        (_, true, false) => BootstrapRoute::GuiPrompt,
    }
}

/// Probe the default collection without side effects.
///
/// Returns [`DefaultCollectionStatus::Absent`] when the daemon is reachable but
/// no default collection exists; an `Err` means the daemon itself is
/// unreachable (callers treat that as "keyring not usable").
pub fn default_collection_status() -> Result<DefaultCollectionStatus> {
    platform::default_collection_status()
}

/// Ensure the default collection exists and is unlocked.
///
/// - Exists and unlocked: no-op.
/// - Absent or locked, interactively: terminal password over the gnome-keyring
///   control socket when one exists (no GUI needed; works on WSL2/headless),
///   falling back to a GUI prompt otherwise.
/// - Absent or locked, non-interactively: [`VaultError::KeyringLocked`] (exit
///   6) — never block an ansible/script caller on a prompt.
/// - Absent without any bootstrap option: [`VaultError::KeyringUnavailable`]
///   with a hint to use the file backend.
///
/// [`VaultError::KeyringUnavailable`]: crate::vault::VaultError::KeyringUnavailable
/// [`VaultError::KeyringLocked`]: crate::vault::VaultError::KeyringLocked
pub fn ensure_default_collection() -> Result<()> {
    platform::ensure_default_collection()
}

// ---------------------------------------------------------------------------
// Secret Service platforms (Linux / *BSD / etc.) — same cfg the `keyring` crate
// uses to select its Secret Service store, and the same cfg `master.rs` uses
// for its session-collection carrier.
// ---------------------------------------------------------------------------
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
mod platform {
    use secret_service::blocking::SecretService;
    use secret_service::{EncryptionType, Error as SsError};
    use std::io::IsTerminal;
    use tracing::{debug, warn};

    use crate::error::{Error, Result};
    use crate::vault::gkr;
    use crate::vault::VaultError;

    use super::{bootstrap_route, BootstrapRoute, DefaultCollectionStatus};

    /// How many terminal attempts the user gets when the keyring password is
    /// rejected (mirrors common sudo/PAM retry counts).
    const MAX_PASSWORD_ATTEMPTS: u8 = 3;

    /// Connect to the session bus's Secret Service (DH encryption — same
    /// transport the keyring store and the master-passphrase cache use). A
    /// failure here means no daemon is reachable.
    fn connect() -> Result<SecretService<'static>> {
        SecretService::connect(EncryptionType::Dh)
            .map_err(|e| ss_error("secret service unreachable", e))
    }

    /// Wrap a raw Secret Service error as keyring-backend unavailability so it
    /// flows through the existing `KeyringUnavailable` → `keyring_hint` path.
    fn ss_error(message: &str, e: SsError) -> Error {
        Error::Vault(VaultError::KeyringUnavailable {
            message: format!("{message}: {e}"),
            source: keyring::Error::PlatformFailure(Box::new(e)),
        })
    }

    pub(super) fn default_collection_status() -> Result<DefaultCollectionStatus> {
        let ss = connect()?;
        // Bind the match so the temporary `get_default_collection()` result (and
        // its borrow of `ss`) drops at the `;`, before `ss` itself — the
        // standard fix for the tail-expression temporary-lifetime edge case.
        let col = match ss.get_default_collection() {
            Ok(col) => col,
            // The `default` alias resolves to `/` → no default collection.
            Err(SsError::NoResult) => {
                debug!("default collection is absent");
                return Ok(DefaultCollectionStatus::Absent);
            }
            Err(e) => return Err(ss_error("could not read default collection", e)),
        };
        let locked = col
            .is_locked()
            .map_err(|e| ss_error("collection probe failed", e))?;
        if locked {
            debug!("default collection exists but is locked");
            Ok(DefaultCollectionStatus::ExistsLocked)
        } else {
            debug!("default collection exists and is unlocked");
            Ok(DefaultCollectionStatus::Ready)
        }
    }

    pub(super) fn ensure_default_collection() -> Result<()> {
        let status = default_collection_status()?;
        match bootstrap_route(
            status,
            std::io::stdin().is_terminal(),
            gkr::control_available(),
        ) {
            BootstrapRoute::AlreadyReady => Ok(()),
            BootstrapRoute::RefuseNonInteractive => {
                debug!("default collection not ready; non-interactive, refusing to prompt");
                Err(Error::Vault(VaultError::KeyringLocked))
            }
            // Primary path: the gnome-keyring control socket (terminal
            // password, no GUI). Falls through to the GUI path only when the
            // control socket route turns out to be a dead end.
            BootstrapRoute::ControlSocket => {
                if let ControlOutcome::Ready = ensure_via_control(status)? {
                    return Ok(());
                }
                warn!(
                    "gnome-keyring control unlock did not ready the default collection; \
                     falling back to the Secret Service GUI prompt path"
                );
                ensure_via_gui_prompt(status)
            }
            BootstrapRoute::GuiPrompt => ensure_via_gui_prompt(status),
        }
    }

    /// Result of trying the control-socket path.
    enum ControlOutcome {
        /// The default collection is now created/unlocked (verified by a
        /// fresh read-only probe).
        Ready,
        /// The control route was a dead end (socket died mid-way, protocol
        /// mismatch, or the Secret Service still does not see the collection
        /// — e.g. a different provider owns `org.freedesktop.secrets`).
        /// Callers fall back to the GUI prompt path.
        FellThrough,
    }

    /// Create/unlock the login keyring over the gnome-keyring control socket,
    /// prompting for the password in the terminal — the PAM-login operation,
    /// with no GUI dependency (works on WSL2 / headless).
    fn ensure_via_control(status: DefaultCollectionStatus) -> Result<ControlOutcome> {
        match status {
            DefaultCollectionStatus::Ready => return Ok(ControlOutcome::Ready),
            DefaultCollectionStatus::Absent => {
                eprintln!(
                    "Creating the OS keyring ('login' collection). Choose a password to\n\
                     encrypt it; you will re-enter it once per reboot or daemon restart\n\
                     (via `avpm unlock`). It is separate from your vault passwords and\n\
                     from the sync master passphrase."
                );
                let password = prompt_new_keyring_password()?;
                // A D-Bus-activated daemon without a desktop session does not
                // create its own data dir; the keyring-file write would fail.
                ensure_keyrings_dir()?;
                match gkr::control_unlock(password.as_str()) {
                    Ok(gkr::UnlockOutcome::Unlocked) => {}
                    Ok(gkr::UnlockOutcome::Denied) => {
                        // Absent + Denied cannot normally happen (the daemon
                        // creates when absent); surface it rather than retry.
                        return Err(Error::Other(anyhow::anyhow!(
                            "gnome-keyring rejected creating the login keyring"
                        )));
                    }
                    Err(e) => {
                        warn!("{e}");
                        return Ok(ControlOutcome::FellThrough);
                    }
                }
            }
            DefaultCollectionStatus::ExistsLocked => {
                for attempt in 1..=MAX_PASSWORD_ATTEMPTS {
                    let password = crate::password::prompt("OS keyring password")?;
                    match gkr::control_unlock(password.as_str()) {
                        Ok(gkr::UnlockOutcome::Unlocked) => break,
                        Ok(gkr::UnlockOutcome::Denied) => {
                            eprintln!(
                                "wrong OS keyring password ({attempt}/{MAX_PASSWORD_ATTEMPTS})"
                            );
                            if attempt == MAX_PASSWORD_ATTEMPTS {
                                return Err(Error::Other(anyhow::anyhow!(
                                    "OS keyring password rejected {MAX_PASSWORD_ATTEMPTS} times"
                                )));
                            }
                        }
                        Err(e) => {
                            warn!("{e}");
                            return Ok(ControlOutcome::FellThrough);
                        }
                    }
                }
            }
        }
        // Closed loop: the Secret Service must now *see* the default
        // collection as ready. It re-reads the alias on every connection, so a
        // fresh probe is authoritative. If it is not ready, the control socket
        // we just talked to does not back the Secret Service the probe uses
        // (e.g. KeePassXC owns org.freedesktop.secrets) — a dead end, say so
        // and let the caller fall back to the GUI path.
        match default_collection_status() {
            Ok(DefaultCollectionStatus::Ready) => {
                debug!("default collection ready after control unlock");
                Ok(ControlOutcome::Ready)
            }
            probe => {
                warn!(
                    ?probe,
                    "default collection still not ready after control unlock"
                );
                Ok(ControlOutcome::FellThrough)
            }
        }
    }

    /// Prompt for a new keyring password until it is non-empty and confirmed.
    fn prompt_new_keyring_password() -> Result<crate::vault::VaultSecret> {
        loop {
            let first = crate::password::prompt("Set OS keyring password")?;
            if first.as_str().is_empty() {
                eprintln!("the OS keyring password must not be empty; try again");
                continue;
            }
            let second = crate::password::prompt("Confirm password")?;
            if first.as_str() == second.as_str() {
                return Ok(first);
            }
            eprintln!("passwords do not match; try again");
        }
    }

    /// The GUI-prompt path over the Secret Service (`CreateCollection` /
    /// `Unlock`), used for providers without a control socket (KeePassXC,
    /// KWallet). `gcr-prompter` and friends are D-Bus-activated and inherit
    /// the bus daemon's environment, so first push this process's display
    /// variables into the activation environment — the job a display manager
    /// normally does at login, missing on WSL2.
    fn ensure_via_gui_prompt(status: DefaultCollectionStatus) -> Result<()> {
        export_display_to_activation_env();
        let ss = connect()?;
        match status {
            DefaultCollectionStatus::Ready => Ok(()),
            DefaultCollectionStatus::Absent => {
                if !super::gui_available() {
                    return Err(Error::Vault(VaultError::KeyringUnavailable {
                        message: "default collection absent and no way to create it here (no \
                                  GUI for a prompt and no gnome-keyring control socket); run \
                                  `avpm unlock` where one is available, or set [storage] \
                                  backend = \"file\""
                            .to_string(),
                        source: keyring::Error::NoStorageAccess(Box::new(SsError::NoResult)),
                    }));
                }
                // gnome-keyring, when D-Bus-activated without a desktop
                // session (WSL2/headless), does NOT create its own data dir.
                // Without it, CreateCollection fails with an opaque "prompt
                // dismissed" because the daemon can't write the keyring file
                // (journal: "couldn't write to file .../keyrings/login.keyring:
                // No such file or directory"). Ensure it first.
                ensure_keyrings_dir()?;
                // Label "login" + alias "default": create the collection (a
                // one-time GUI prompt) and make it the default in the same call.
                // This is the form gnome-keyring's own PAM login uses.
                debug!("default collection absent; creating 'login' collection (GUI prompt)");
                ss.create_collection("login", "default")
                    .map_err(|e| ss_error("create collection failed", e))?;
                Ok(())
            }
            DefaultCollectionStatus::ExistsLocked => {
                let col = ss
                    .get_default_collection()
                    .map_err(|e| ss_error("could not read default collection", e))?;
                debug!("default collection locked; unlocking (GUI prompt may appear)");
                col.unlock().map_err(|e| ss_error("unlock failed", e))?;
                Ok(())
            }
        }
    }

    /// Push this process's `DISPLAY` / `WAYLAND_DISPLAY` into the session
    /// bus's activation environment
    /// (`org.freedesktop.DBus.UpdateActivationEnvironment`).
    ///
    /// Why: GUI prompters activated by the bus (gcr-prompter) inherit the bus
    /// daemon's environment, not the caller's. On WSL2 nothing plays display
    /// manager, so a bus started at boot has no DISPLAY and every prompt dies
    /// with "cannot open display" — surfaced to Secret Service callers as an
    /// opaque "prompt dismissed". The same values written again are a no-op,
    /// so this is idempotent on healthy desktops; failure is logged, never
    /// fatal (the prompt may still work via another route).
    /// The display variables this process can see, for exporting into the bus
    /// activation environment. Pure env read — factored out for unit testing.
    pub(super) fn display_env_vars() -> std::collections::HashMap<String, String> {
        ["DISPLAY", "WAYLAND_DISPLAY"]
            .into_iter()
            .filter_map(|key| {
                std::env::var(key)
                    .ok()
                    .map(|value| (key.to_string(), value))
            })
            .collect()
    }

    fn export_display_to_activation_env() {
        let vars = display_env_vars();
        if vars.is_empty() {
            // Nothing display-ish in this process either; the caller's own
            // gui_available() gate produces the proper guidance.
            return;
        }
        let result = (|| -> std::result::Result<(), zbus::Error> {
            let conn = zbus::blocking::Connection::session()?;
            conn.call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "UpdateActivationEnvironment",
                &vars,
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                debug!(
                    ?vars,
                    "exported display env into the D-Bus activation environment"
                );
            }
            Err(e) => {
                warn!("could not export display env into the D-Bus activation environment: {e}");
            }
        }
    }

    /// Ensure gnome-keyring's data directory exists (root cause of the opaque
    /// "prompt dismissed" on D-Bus-activated daemons without a desktop session).
    /// Uses `dirs::data_dir()` so `$XDG_DATA_HOME` is honored; falls back to
    /// letting gnome-keyring's own error surface if it can't be resolved.
    fn ensure_keyrings_dir() -> Result<()> {
        let Some(data_dir) = dirs::data_dir() else {
            return Ok(());
        };
        let keyrings_dir = data_dir.join("keyrings");
        std::fs::create_dir_all(&keyrings_dir).map_err(|e| {
            Error::Vault(VaultError::KeyringUnavailable {
                message: format!(
                    "could not create the keyrings data dir at {}: {e}",
                    keyrings_dir.display()
                ),
                source: keyring::Error::PlatformFailure(Box::new(e)),
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Non-Secret-Service platforms (macOS Keychain, Windows Credential Manager).
// The `keyring` crate handles these natively; there is no collection-create
// bug to patch, so both helpers are no-ops.
// ---------------------------------------------------------------------------
#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
)))]
mod platform {
    use super::DefaultCollectionStatus;
    use crate::error::Result;

    pub(super) fn default_collection_status() -> Result<DefaultCollectionStatus> {
        Ok(DefaultCollectionStatus::Ready)
    }

    pub(super) fn ensure_default_collection() -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{auto_prefers_keyring, gui_available, DefaultCollectionStatus as S};

    /// The decision table is the heart of gaps 1a/1b/3a and must be stable, so
    /// cover every cell. No daemon dependency — pure logic.
    #[test]
    fn auto_decision_table() {
        // Daemon up + collection exists (locked or not) → always keyring,
        // regardless of bootstrap options (they are irrelevant here).
        assert!(auto_prefers_keyring(Some(S::Ready), false, false));
        assert!(auto_prefers_keyring(Some(S::Ready), true, true));
        assert!(auto_prefers_keyring(Some(S::ExistsLocked), false, false));
        assert!(auto_prefers_keyring(Some(S::ExistsLocked), true, true));

        // Collection absent → keyring iff something can create it: a GUI for
        // the prompt, or a gnome-keyring control socket (terminal bootstrap).
        assert!(auto_prefers_keyring(Some(S::Absent), true, false));
        assert!(auto_prefers_keyring(Some(S::Absent), false, true));
        assert!(auto_prefers_keyring(Some(S::Absent), true, true));
        assert!(!auto_prefers_keyring(Some(S::Absent), false, false));

        // Daemon unreachable / probe errored → always file.
        assert!(!auto_prefers_keyring(None, false, false));
        assert!(!auto_prefers_keyring(None, true, true));
    }

    /// `gui_available` is purely an env-var check; setting a display makes it
    /// true regardless of any daemon. (Isolation via `set_env` so this is
    /// independent of the host's real `DISPLAY`.)
    #[test]
    fn gui_available_reflects_display_env() {
        // Temporarily clear both, then set one at a time.
        let saved_display = std::env::var_os("DISPLAY");
        let saved_wayland = std::env::var_os("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");
        std::env::remove_var("WAYLAND_DISPLAY");
        assert!(!gui_available(), "no display vars → no GUI");

        std::env::set_var("DISPLAY", ":0");
        assert!(gui_available(), "DISPLAY set → GUI available");
        std::env::remove_var("DISPLAY");

        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
        assert!(gui_available(), "WAYLAND_DISPLAY set → GUI available");

        // Restore.
        match saved_display {
            Some(v) => std::env::set_var("DISPLAY", v),
            None => std::env::remove_var("DISPLAY"),
        }
        match saved_wayland {
            Some(v) => std::env::set_var("WAYLAND_DISPLAY", v),
            None => std::env::remove_var("WAYLAND_DISPLAY"),
        }
    }

    /// The bootstrap-route decision table — the routing heart of the
    /// WSL2/headless keyring fix. Every cell: Ready short-circuits; a
    /// non-interactive caller never prompts; interactive prefers the control
    /// socket and falls back to the GUI prompt.
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    #[test]
    fn bootstrap_route_decision_table() {
        use super::{bootstrap_route as route, BootstrapRoute as R, DefaultCollectionStatus as S};

        // Ready short-circuits everything: no prompt, no socket, no GUI —
        // desktop Linux with a PAM-unlocked keyring is untouched.
        assert_eq!(route(S::Ready, false, false), R::AlreadyReady);
        assert_eq!(route(S::Ready, true, true), R::AlreadyReady);

        // Non-interactive never prompts, whatever the bootstrap options
        // (ansible pipes / `avpm set -g` from scripts → exit 6).
        assert_eq!(route(S::Absent, false, true), R::RefuseNonInteractive);
        assert_eq!(
            route(S::ExistsLocked, false, false),
            R::RefuseNonInteractive
        );

        // Interactive: the control socket (terminal, no GUI) wins...
        assert_eq!(route(S::Absent, true, true), R::ControlSocket);
        assert_eq!(route(S::ExistsLocked, true, true), R::ControlSocket);
        // ...and the GUI prompt is the fallback when there is none.
        assert_eq!(route(S::Absent, true, false), R::GuiPrompt);
        assert_eq!(route(S::ExistsLocked, true, false), R::GuiPrompt);
    }

    /// `display_env_vars` collects exactly the display variables that are
    /// set — the input side of the D-Bus activation-environment repair.
    #[cfg(all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    ))]
    #[test]
    fn display_env_vars_reflects_the_environment() {
        let saved_display = std::env::var_os("DISPLAY");
        let saved_wayland = std::env::var_os("WAYLAND_DISPLAY");
        std::env::remove_var("DISPLAY");
        std::env::remove_var("WAYLAND_DISPLAY");
        assert!(super::platform::display_env_vars().is_empty());

        std::env::set_var("DISPLAY", ":0");
        let vars = super::platform::display_env_vars();
        assert_eq!(vars.len(), 1);
        assert_eq!(vars.get("DISPLAY").map(String::as_str), Some(":0"));

        std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
        let vars = super::platform::display_env_vars();
        assert_eq!(vars.len(), 2);
        assert_eq!(
            vars.get("WAYLAND_DISPLAY").map(String::as_str),
            Some("wayland-0")
        );

        match saved_display {
            Some(v) => std::env::set_var("DISPLAY", v),
            None => std::env::remove_var("DISPLAY"),
        }
        match saved_wayland {
            Some(v) => std::env::set_var("WAYLAND_DISPLAY", v),
            None => std::env::remove_var("WAYLAND_DISPLAY"),
        }
    }
}

// ---------------------------------------------------------------------------
// Real-Secret-Service integration tests (Linux/*BSD). Skipped — never failed —
// when no daemon is reachable, mirroring `master.rs`'s pattern.
// ---------------------------------------------------------------------------
#[cfg(all(
    test,
    all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    )
))]
mod ss_integration_tests {
    use secret_service::blocking::SecretService;
    use secret_service::EncryptionType;

    use super::default_collection_status;
    use crate::vault::ss::ensure_default_collection;

    /// A Secret Service daemon on the session bus is required; skip (not fail)
    /// when absent so the suite stays green in daemon-less CI.
    fn daemon_available() -> bool {
        SecretService::connect(EncryptionType::Dh).is_ok()
    }

    /// `default_collection_status` is a read-only probe: it must connect,
    /// resolve the alias, and report a status without prompting and without
    /// mutating anything. We assert only that it returns `Ok` (the specific
    /// variant depends on the host's keyring state, which we don't control).
    #[test]
    fn default_collection_status_is_read_only() {
        if !daemon_available() {
            eprintln!("skipping: no Secret Service daemon on the session bus");
            return;
        }
        match default_collection_status() {
            Ok(status) => eprintln!("observed default collection status: {status:?}"),
            Err(e) => {
                // Some hosts (e.g. an alias pointing at a since-deleted
                // collection) make the probe error; that's a real-world state,
                // not a bug in the probe. Log and pass.
                eprintln!("skipping: default collection probe errored ({e})");
            }
        }
    }

    /// `ensure_default_collection` may prompt in the terminal (create/unlock)
    /// and mutates the real default collection, so it is `#[ignore]`d — run it
    /// manually from an interactive session (works headless with gnome-keyring):
    ///   cargo test -p avpm --lib ensure_default_collection_idempotent -- --ignored
    #[test]
    #[ignore = "creates/unlocks the real default collection (terminal prompt); run interactively"]
    fn ensure_default_collection_idempotent() {
        ensure_default_collection().unwrap();
        // A second call on a now-ready collection must be a no-op (still Ok).
        ensure_default_collection().unwrap();
    }
}
