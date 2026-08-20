//! Vault secret storage domain.
//!
//! `VaultStore` is the port trait (static dispatch); `KeyringStore` is the
//! production implementation backed by the OS keyring; `FileStore` is the
//! encrypted-file fallback used when the keyring is unavailable (e.g. WSL2
//! without a GUI); `MockStore` is the `#[cfg(test)]` HashMap-backed test
//! double. `list` lives in the separate `index` module (keyring has no
//! reliable enumeration API).

pub mod error;
pub mod file;
pub mod gkr;
pub mod keyring;
pub mod master;
#[cfg(any(test, feature = "testing"))]
pub mod mock;
pub mod secret;
pub mod ss;
pub mod store;

pub use error::VaultError;
pub use file::FileStore;
pub use keyring::KeyringStore;
pub use secret::VaultSecret;
pub use store::{AnyStore, VaultStore};

use crate::error::Result;

/// Convenience helper: build the production `KeyringStore` for the given
/// keyring `service` name.
pub fn store_for_service(service: &str) -> KeyringStore {
    KeyringStore::new(service)
}

/// Re-exported for command handlers that need `Result` alongside store types.
pub type StoreResult<T> = Result<T>;
