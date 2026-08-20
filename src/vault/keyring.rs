//! `KeyringStore` - the production `VaultStore` backed by the OS keyring
//!.
//!
//! Uses `keyring` v1 API: `Entry::new(service, username)` where `username`
//! is the vault-id. All methods are synchronous.

use crate::error::{Error, Result};
use crate::vault::store::VaultStore;
use crate::vault::{VaultError, VaultSecret};
use tracing::{debug, instrument};

/// Production [`VaultStore`] backed by the OS keyring.
#[derive(Debug, Clone)]
pub struct KeyringStore {
    service: String,
}

impl KeyringStore {
    /// Create a store that targets keyring entries under `service`.
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// The keyring service name this store targets.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    fn entry(&self, vault_id: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, vault_id).map_err(map_keyring_error(vault_id))
    }
}

impl VaultStore for KeyringStore {
    #[instrument(skip(self), fields(service = %self.service, vault_id = %vault_id))]
    fn get(&self, vault_id: &str) -> Result<VaultSecret> {
        let entry = self.entry(vault_id)?;
        let pw = entry.get_password().map_err(map_keyring_error(vault_id))?;
        debug!(password_len = pw.len(), "keyring get ok");
        Ok(VaultSecret::new(pw))
    }

    #[instrument(skip(self, secret), fields(service = %self.service, vault_id = %vault_id, password_len = secret.len()))]
    fn set(&self, vault_id: &str, secret: &VaultSecret) -> Result<()> {
        // The `keyring` crate cannot create the default Secret Service
        // collection when absent (it only re-reads the alias), so every write
        // would fail with "result not returned from SS API" on a fresh
        // headless/WSL2 box. Ensure the collection exists (and is unlocked)
        // first — terminal password via the gnome-keyring control socket when
        // available, GUI prompt otherwise; the keyring crate then writes into
        // the now-existing collection. No-op on macOS/Windows.
        crate::vault::ss::ensure_default_collection()?;
        let entry = self.entry(vault_id)?;
        entry
            .set_password(secret.as_str())
            .map_err(map_keyring_error(vault_id))?;
        debug!("keyring set ok");
        Ok(())
    }

    #[instrument(skip(self), fields(service = %self.service, vault_id = %vault_id))]
    fn delete(&self, vault_id: &str) -> Result<()> {
        let entry = self.entry(vault_id)?;
        entry
            .delete_credential()
            .map_err(map_keyring_error(vault_id))?;
        debug!("keyring delete ok");
        Ok(())
    }
}

/// Map a `keyring::Error` (by value) onto an [`Error`].
///
/// `keyring::Error` is non-exhaustive; we pattern-match the variants we care
/// about and fall back to wrapping the raw error. This central function lets
/// us adjust to `keyring-core`'s exact variant shapes in one place.
fn map_keyring_error(vault_id: &str) -> impl Fn(keyring::Error) -> Error + '_ {
    let vault_id = vault_id.to_string();
    move |e: keyring::Error| {
        use keyring::Error as K;
        match e {
            K::NoEntry => Error::Vault(VaultError::NotFound(vault_id.clone())),
            K::NoStorageAccess(_) | K::PlatformFailure(_) => {
                Error::Vault(VaultError::KeyringUnavailable {
                    message: e.to_string(),
                    source: e,
                })
            }
            other => Error::Vault(VaultError::KeyringFailed(other)),
        }
    }
}

#[cfg(test)]
mod real_keyring_tests {
    use super::*;

    #[test]
    #[ignore = "requires a real unlocked keyring / D-Bus session"]
    fn round_trip() {
        let store = KeyringStore::new("avpm-test-real");
        let id = "avpm-real-roundtrip";
        let secret = VaultSecret::new("p@ss".to_string());
        store.set(id, &secret).unwrap();
        let got = store.get(id).unwrap();
        assert_eq!(got.as_str(), "p@ss");
        store.delete(id).unwrap();
        assert!(store.get(id).is_err());
    }
}
