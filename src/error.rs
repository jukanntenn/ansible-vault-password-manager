//! Unified error type for avpm.
//!
//! Layering (see `07-error-handling.md`):
//! - Domain errors (`vault`, `sync`, `config`) are strongly-typed via `thiserror`.
//! - This top-level `Error` aggregates them with `#[from]`.
//! - Command orchestration uses `anyhow` for `.context()`.
//!
//! Exit code mapping (see `07` §4):
//! - `0` success
//! - `1` generic error
//! - `2` vault-id not found (ansible client contract)
//! - `3` configuration error
//! - `4` decryption failure (sync or file-store)
//! - `5` file store locked (run `avpm unlock`)

use crate::config::ConfigError;
use crate::sync::SyncError;
use crate::vault::VaultError;

/// The top-level error returned by all library operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error(transparent)]
    Sync(#[from] SyncError),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("decryption failed: {0}")]
    Decrypt(#[from] age::DecryptError),

    #[error("encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

/// Convenience `Result` alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Maps an error to the process exit code (see module docs / `07` §4).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Vault(VaultError::NotFound(_)) => 2,
            Error::Config(_) => 3,
            Error::Sync(SyncError::Decrypt(_))
            | Error::Decrypt(_)
            | Error::Vault(VaultError::StoreDecrypt) => 4,
            Error::Vault(VaultError::Locked) => 5,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    //! Exit-code mapping matrix (see module docs).
    //!
    //! The full error→exit-code contract, including the ansible-critical
    //! distinction between "vault-id absent" (exit 2) and "file store locked"
    //! (exit 5) so non-interactive callers can tell them apart.

    use super::Error;
    use crate::config::ConfigError;
    use crate::sync::SyncError;
    use crate::vault::VaultError;

    #[test]
    fn vault_not_found_maps_to_exit_2() {
        assert_eq!(
            Error::Vault(VaultError::NotFound("dev".into())).exit_code(),
            2
        );
    }

    #[test]
    fn config_error_maps_to_exit_3() {
        assert_eq!(
            Error::Config(ConfigError::Invalid("bad".into())).exit_code(),
            3
        );
    }

    #[test]
    fn store_decrypt_maps_to_exit_4() {
        // age::DecryptError isn't trivially constructible, but
        // VaultError::StoreDecrypt routes through the same exit-code arm.
        assert_eq!(Error::Vault(VaultError::StoreDecrypt).exit_code(), 4);
    }

    #[test]
    fn locked_maps_to_exit_5() {
        // Distinct from exit 2 so ansible/non-interactive callers can tell
        // "locked" from "vault-id absent".
        assert_eq!(Error::Vault(VaultError::Locked).exit_code(), 5);
    }

    #[test]
    fn generic_fallback_maps_to_exit_1() {
        assert_eq!(Error::Sync(SyncError::NotConfigured).exit_code(), 1);
    }
}
