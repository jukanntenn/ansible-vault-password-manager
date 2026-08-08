//! Platform path location (XDG on Linux, Library on macOS).
//!
//! See `04-project-structure.md` §2.10.

use std::path::PathBuf;

const APP_DIR: &str = "avpm";
const CONFIG_FILE: &str = "config.toml";
const INDEX_FILE: &str = "index.json";
const STORE_FILE: &str = "store.age";

/// Returns the config file path (`~/.config/avpm/config.toml` on Linux,
/// `~/Library/Application Support/avpm/config.toml` on macOS).
#[must_use]
pub fn config_path() -> PathBuf {
    config_dir().join(CONFIG_FILE)
}

/// Returns the config *directory* (parent of the config file).
#[must_use]
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR)
}

/// Returns the data directory (`~/.local/share/avpm/` on Linux).
#[must_use]
pub fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR)
}

/// Returns the index file path (`<data_dir>/index.json`).
#[must_use]
pub fn index_path() -> PathBuf {
    data_dir().join(INDEX_FILE)
}

/// Returns the encrypted file-store path (`<data_dir>/store.age`).
///
/// Used by the `FileStore` backend when the OS keyring is unavailable (e.g.
/// WSL2 without a GUI). Distinct from sync's remote `vault.age` blob.
#[must_use]
pub fn store_path() -> PathBuf {
    data_dir().join(STORE_FILE)
}

/// Returns the cache directory (`~/.cache/avpm/` on Linux), used for git clone
/// temp working dirs during sync.
#[must_use]
pub fn cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_DIR)
}

/// Returns the sync temp working directory (`<cache_dir>/sync-tmp/`).
#[must_use]
pub fn sync_tmp_dir() -> PathBuf {
    cache_dir().join("sync-tmp")
}
