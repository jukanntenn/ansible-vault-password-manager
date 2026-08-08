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

/// User-facing hint for resolving keyring unavailability on Linux / WSL2.
///
/// `gnome-keyring-daemon --start` only *starts* the daemon; it does not create
/// or unlock the `login` collection. On a fresh WSL2 / headless box the
/// `login` collection does not exist yet, and GNOME Keyring requires a GUI
/// prompt to create/unlock it — so `--start` alone never makes writes succeed.
/// The advice below walks the user through the two working paths.
#[must_use]
pub fn keyring_hint() -> &'static str {
    "The OS keyring (Secret Service) is not ready: the `login` collection is\n\
     missing or locked, and GNOME Keyring needs a GUI prompt to create/unlock it.\n\n\
     Fix (pick one):\n\n\
     1. With WSLg / a GUI (recommended, persistent):\n      \
        sudo apt-get install -y gnome-keyring libsecret-tools seahorse && \\\n      \
        echo -n x | secret-tool store --label=init service avpm vault-id init\n      \
        (a dialog appears to set the keyring password; create it once)\n\n\
     2. Headless, no GUI (temporary, lost on WSL restart):\n      \
        gdbus call --session --dest org.freedesktop.secrets \\\n      \
          --object-path /org/freedesktop/secrets \\\n      \
          --method org.freedesktop.Secret.Service.SetAlias \\\n      \
          default /org/freedesktop/secrets/collection/session\n\n\
     WSL2 also needs systemd enabled in /etc/wsl.conf and `dbus-x11` installed."
}
