//! The `VaultStore` port trait.
//!
//! Used via generics (static dispatch). `list` is intentionally **not** on the
//! trait (keyring enumeration is unreliable); it lives in `crate::index`.
//!
//! [`AnyStore`] provides enum dispatch when the backend is chosen at runtime
//! (config-driven `auto`/`keyring`/`file` selection) while preserving static
//! dispatch within each arm - consistent with the project's "generics over
//! `&dyn`" principle.

use crate::error::Result;
use crate::vault::{FileStore, KeyringStore, VaultSecret};

/// Port for single-vault CRUD against a backing store.
///
/// Production impls: [`KeyringStore`] (OS keyring), [`FileStore`] (encrypted
/// file fallback). Test impl: [`crate::vault::MockStore`] (`#[cfg(test)]`).
pub trait VaultStore {
    /// Fetch the password for `vault_id`. `NotFound` if absent.
    fn get(&self, vault_id: &str) -> Result<VaultSecret>;

    /// Store (creating or overwriting) the password for `vault_id`.
    fn set(&self, vault_id: &str, secret: &VaultSecret) -> Result<()>;

    /// Delete the password for `vault_id`. `NotFound` if absent.
    fn delete(&self, vault_id: &str) -> Result<()>;
}

/// Runtime-selected store backend, chosen from config.
///
/// This is enum dispatch rather than `Box<dyn VaultStore>`: the trait's methods
/// all return owned types (no `async`, no `Self`-typed returns), so forwarding
/// through an enum keeps static dispatch in each arm and avoids any vtable,
/// matching the project's zero-cost-abstraction principle.
#[derive(Debug, Clone)]
pub enum AnyStore {
    /// OS keyring (macOS Keychain / Linux Secret Service).
    Keyring(KeyringStore),
    /// Encrypted file fallback.
    File(FileStore),
}

impl VaultStore for AnyStore {
    fn get(&self, vault_id: &str) -> Result<VaultSecret> {
        match self {
            Self::Keyring(s) => s.get(vault_id),
            Self::File(s) => s.get(vault_id),
        }
    }

    fn set(&self, vault_id: &str, secret: &VaultSecret) -> Result<()> {
        match self {
            Self::Keyring(s) => s.set(vault_id, secret),
            Self::File(s) => s.set(vault_id, secret),
        }
    }

    fn delete(&self, vault_id: &str) -> Result<()> {
        match self {
            Self::Keyring(s) => s.delete(vault_id),
            Self::File(s) => s.delete(vault_id),
        }
    }
}
