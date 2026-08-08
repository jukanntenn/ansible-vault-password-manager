//! Configuration (see `05-configuration.md`).
//!
//! Loaded from a single optional TOML file via `config-rs`. Pure
//! deserialization; no runtime state lives here.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::paths;

/// Top-level config.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default)]
    pub default: DefaultConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub clipboard: ClipboardConfig,
    #[serde(default)]
    pub sync: Option<SyncConfig>,
}

impl Config {
    /// Load config from `path` (or the default location when `None`).
    ///
    /// A missing file yields `Config::default()` (CRUD works without a config
    /// file; only `sync` requires configuration).
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let resolved: PathBuf = path.map_or_else(paths::config_path, std::path::Path::to_path_buf);

        let source = config::File::from(resolved.clone())
            .format(config::FileFormat::Toml)
            .required(false);

        let built = config::Config::builder()
            .add_source(source)
            .build()
            .map_err(|e| {
                Error::Config(ConfigError::Load {
                    path: resolved.clone(),
                    source: e,
                })
            })?;

        let cfg: Config = built.try_deserialize().map_err(|e| {
            Error::Config(ConfigError::Load {
                path: resolved,
                source: e,
            })
        })?;
        Ok(cfg)
    }

    /// The keyring service name (default `"avpm"`).
    #[must_use]
    pub fn service(&self) -> &str {
        &self.default.service
    }

    /// The sync config, if configured.
    #[must_use]
    pub fn sync_config(&self) -> Option<&SyncConfig> {
        self.sync.as_ref()
    }

    /// The storage-backend config (default: `auto`).
    #[must_use]
    pub fn storage_config(&self) -> &StorageConfig {
        &self.storage
    }

    /// The clipboard config (auto-clear timeout).
    #[must_use]
    pub fn clipboard_config(&self) -> &ClipboardConfig {
        &self.clipboard
    }
}

/// `[default]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DefaultConfig {
    #[serde(default = "default_service")]
    pub service: String,
}

impl Default for DefaultConfig {
    fn default() -> Self {
        Self {
            service: default_service(),
        }
    }
}

fn default_service() -> String {
    "avpm".to_string()
}

/// `[storage]` section. Selects where vault secrets are kept.
///
/// - `auto` (default): try the OS keyring first; if unavailable (e.g. WSL2 with
///   no GUI to unlock GNOME Keyring) fall back to the encrypted file store.
/// - `keyring`: force the OS keyring; fail if unavailable.
/// - `file`: force the encrypted file store (`store.age` + master passphrase).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct StorageConfig {
    #[serde(default)]
    pub backend: StorageBackend,
}

/// Storage backend selector. Mirrors `BackendKind`'s serde style.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum StorageBackend {
    #[default]
    Auto,
    Keyring,
    File,
}

/// `[clipboard]` section. Controls auto-clear of copied passwords (gopass
/// `cliptimeout` pattern). `clear_seconds = 0` disables auto-clear.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClipboardConfig {
    #[serde(default = "default_clear_seconds")]
    pub clear_seconds: u16,
}

impl Default for ClipboardConfig {
    fn default() -> Self {
        Self {
            clear_seconds: default_clear_seconds(),
        }
    }
}

/// Default clipboard auto-clear window (seconds). Matches gopass's default.
fn default_clear_seconds() -> u16 {
    45
}

/// `[sync]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SyncConfig {
    pub backend: BackendKind,
    #[serde(default)]
    pub git: Option<GitConfig>,
    #[serde(default)]
    pub webdav: Option<WebDavConfig>,
}

/// Sync backend selector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    Git,
    WebDav,
}

/// `[sync.git]` section.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GitConfig {
    pub remote: String,
    #[serde(default = "default_git_path")]
    pub path: String,
    /// Remote branch to push/pull (default `main`).
    #[serde(default = "default_git_branch")]
    pub branch: String,
}

fn default_git_path() -> String {
    "vault.age".to_string()
}

fn default_git_branch() -> String {
    "main".to_string()
}

impl Default for GitConfig {
    fn default() -> Self {
        Self {
            remote: String::new(),
            path: default_git_path(),
            branch: default_git_branch(),
        }
    }
}

/// `[sync.webdav]` section. The password is **never** stored here; it lives in
/// the keyring under service `avpm-webdav`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WebDavConfig {
    pub url: String,
    pub username: String,
}

/// Config-domain errors (see `07` §3.4).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to load config from {path}: {source}")]
    Load {
        path: PathBuf,
        #[source]
        source: config::ConfigError,
    },

    #[error("invalid config: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_config(dir: &TempDir, contents: &str) -> PathBuf {
        let path = dir.path().join("config.toml");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn missing_file_uses_defaults() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("absent.toml");
        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.service(), "avpm");
        assert!(cfg.sync_config().is_none());
    }

    #[test]
    fn parses_minimal_config() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "[default]\nservice = \"custom\"\n");
        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.service(), "custom");
    }

    #[test]
    fn parses_sync_git_config() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            "[sync]\nbackend = \"git\"\n[sync.git]\nremote = \"git@github.com:me/v.git\"\n",
        );
        let cfg = Config::load(Some(&path)).unwrap();
        let sync = cfg.sync_config().expect("sync configured");
        assert_eq!(sync.backend, BackendKind::Git);
        let git = sync.git.as_ref().expect("git configured");
        assert_eq!(git.remote, "git@github.com:me/v.git");
        assert_eq!(git.path, "vault.age"); // default
        assert_eq!(git.branch, "main"); // default
    }

    #[test]
    fn parses_sync_webdav_config() {
        let dir = TempDir::new().unwrap();
        let path = write_config(
            &dir,
            "[sync]\nbackend = \"webdav\"\n[sync.webdav]\nurl = \"https://x/dav/\"\nusername = \"me\"\n",
        );
        let cfg = Config::load(Some(&path)).unwrap();
        let sync = cfg.sync_config().unwrap();
        assert_eq!(sync.backend, BackendKind::WebDav);
        let webdav = sync.webdav.as_ref().unwrap();
        assert_eq!(webdav.url, "https://x/dav/");
        assert_eq!(webdav.username, "me");
    }

    #[test]
    fn storage_defaults_to_auto_when_absent() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "[default]\nservice = \"avpm\"\n");
        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.storage_config().backend, StorageBackend::Auto);
    }

    #[test]
    fn parses_storage_backend_explicit() {
        for (toml, expected) in [
            ("[storage]\nbackend = \"auto\"\n", StorageBackend::Auto),
            (
                "[storage]\nbackend = \"keyring\"\n",
                StorageBackend::Keyring,
            ),
            ("[storage]\nbackend = \"file\"\n", StorageBackend::File),
        ] {
            let dir = TempDir::new().unwrap();
            let path = write_config(&dir, toml);
            let cfg = Config::load(Some(&path)).unwrap();
            assert_eq!(
                cfg.storage_config().backend,
                expected,
                "failed for `{toml}`"
            );
        }
    }

    #[test]
    fn clipboard_defaults_to_45_seconds() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "[default]\nservice = \"avpm\"\n");
        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.clipboard_config().clear_seconds, 45);
    }

    #[test]
    fn parses_clipboard_clear_seconds() {
        let dir = TempDir::new().unwrap();
        let path = write_config(&dir, "[clipboard]\nclear_seconds = 10\n");
        let cfg = Config::load(Some(&path)).unwrap();
        assert_eq!(cfg.clipboard_config().clear_seconds, 10);
    }
}
