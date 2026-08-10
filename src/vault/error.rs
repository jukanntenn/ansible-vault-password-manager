//! Vault-domain errors.

use std::path::PathBuf;

/// Errors from vault secret storage / index operations.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The named vault-id does not exist. Maps to exit code 2 (ansible contract).
    #[error("vault '{0}' not found")]
    NotFound(String),

    /// The keyring backend is unavailable (locked / no D-Bus session / etc.).
    /// `source` keeps the original keyring error so the failure chain is
    /// traceable (e.g. NoStorageAccess vs PlatformFailure), matching the
    /// other `#[source]`-carrying variants.
    #[error("keyring unavailable: {message}\n\n{}", keyring_hint())]
    KeyringUnavailable {
        message: String,
        #[source]
        source: keyring::Error,
    },

    /// A raw keyring operation failed.
    #[error("keyring operation failed: {0}")]
    KeyringFailed(#[from] keyring::Error),

    /// The Secret Service session-collection cache is unavailable (no D-Bus
    /// session, daemon not reachable, etc.). Used by the master-passphrase
    /// cache only; `read_cached` treats it as a cache miss.
    #[error("session cache unavailable: {0}")]
    SessionCache(String),

    /// File backend: I/O or parse error at the encrypted store file.
    /// `path` is the location of `store.age`; `message` describes the failure.
    #[error("file store error at {path}: {message}")]
    FileStore { path: PathBuf, message: String },

    /// File backend: the master passphrase is not cached. The caller must run
    /// `avpm unlock` first. Maps to exit code 5 (distinct from `NotFound`'s 2
    /// so ansible/non-interactive callers can tell "locked" from "absent").
    #[error(
        "master passphrase not cached.\n  \
             Hint: run `avpm unlock` to decrypt the file store\n  \
             (OS keyring unavailable on this system; using encrypted file store)"
    )]
    Locked,

    /// File backend: `store.age` could not be decrypted (wrong passphrase or
    /// corrupted file). Maps to exit code 4 (shared with sync decrypt failures).
    #[error("store decryption failed (wrong master passphrase or corrupted store)")]
    StoreDecrypt,

    /// The local index file could not be read/written/parsed.
    #[error("index error at {path}: {source}")]
    Index {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The local index file contains invalid JSON.
    #[error("index file at {path} is corrupted: {source}")]
    IndexCorrupted {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

/// User-facing hint for resolving Secret Service unavailability on Linux / WSL2.
///
/// Two distinct failure modes exist, and they need different fixes:
///
/// 1. **No Secret Service daemon at all** — the D-Bus error
///    `org.freedesktop.DBus.Error.ServiceUnknown: The name
///    org.freedesktop.secrets was not provided by any .service files` means no
///    package has registered the `org.freedesktop.secrets` D-Bus service.
///    Install `gnome-keyring` (it ships the `.service` file that lets D-Bus
///    auto-start `gnome-keyring-daemon`).
///
/// 2. **Daemon present but `login` collection missing/locked** — GNOME Keyring
///    needs a GUI prompt to create or unlock the `login` collection. On a
///    headless box that prompt never appears, so the collection stays absent.
///    The session collection (non-persistent, no GUI) is an alternative that
///    avpm uses for its master-passphrase cache.
///
/// See `docs/troubleshooting.md` for the full walkthrough.
#[must_use]
pub fn keyring_hint() -> &'static str {
    "The OS keyring (Secret Service) is unavailable on this system.\n\n\
     Common causes and fixes:\n\n\
     1. Secret Service daemon not installed (error: \"The name\n\
        org.freedesktop.secrets was not provided by any .service files\"):\n\n\
        sudo apt-get install -y gnome-keyring dbus-x11 libsecret-tools\n\
        (then restart your session / WSL so systemd + D-Bus pick it up)\n\n\
     2. WSL2 without systemd:\n\n\
        Ensure /etc/wsl.conf contains:\n\
          [boot]\n\
          systemd=true\n\
        Then run `wsl --shutdown` from Windows and reopen.\n\n\
     3. Daemon present but login collection locked (needs a GUI):\n\n\
        Install seahorse and unlock once via the GUI, or use the headless\n\
        session-collection workaround described in docs/troubleshooting.md.\n\n\
     See docs/troubleshooting.md for full diagnostics and step-by-step setup."
}
