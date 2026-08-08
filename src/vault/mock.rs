//! `MockStore` - in-memory test double for [`VaultStore`].
//!
//! Gated by `#[cfg(any(test, feature = "testing"))]`; backed by a
//! `RefCell<HashMap<String, VaultSecret>>`.

#![cfg(any(test, feature = "testing"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::cell::RefCell;
use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::vault::store::VaultStore;
use crate::vault::{VaultError, VaultSecret};

/// In-memory `VaultStore` for unit/integration tests.
pub struct MockStore {
    inner: RefCell<HashMap<String, VaultSecret>>,
}

impl MockStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RefCell::new(HashMap::new()),
        }
    }

    /// Insert a secret without going through the trait (test fixture helper).
    pub fn seed(&self, vault_id: &str, secret: &str) {
        self.inner
            .borrow_mut()
            .insert(vault_id.to_string(), VaultSecret::new(secret.to_string()));
    }

    /// Number of stored secrets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.borrow().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.borrow().is_empty()
    }

    /// Snapshot of all stored vault-ids (sorted).
    #[must_use]
    pub fn vault_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.inner.borrow().keys().cloned().collect();
        ids.sort();
        ids
    }
}

impl Default for MockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultStore for MockStore {
    fn get(&self, vault_id: &str) -> Result<VaultSecret> {
        match self.inner.borrow().get(vault_id) {
            Some(s) => Ok(s.clone()),
            None => Err(Error::Vault(VaultError::NotFound(vault_id.to_string()))),
        }
    }

    fn set(&self, vault_id: &str, secret: &VaultSecret) -> Result<()> {
        self.inner
            .borrow_mut()
            .insert(vault_id.to_string(), secret.clone());
        Ok(())
    }

    fn delete(&self, vault_id: &str) -> Result<()> {
        if self.inner.borrow_mut().remove(vault_id).is_some() {
            Ok(())
        } else {
            Err(Error::Vault(VaultError::NotFound(vault_id.to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crud_roundtrip() {
        let s = MockStore::new();
        assert!(s.is_empty());
        s.set("dev", &VaultSecret::new("p1".into())).unwrap();
        assert_eq!(s.get("dev").unwrap().as_str(), "p1");
        assert_eq!(s.len(), 1);
        s.set("dev", &VaultSecret::new("p2".into())).unwrap(); // overwrite
        assert_eq!(s.get("dev").unwrap().as_str(), "p2");
        assert_eq!(s.len(), 1);
        s.delete("dev").unwrap();
        assert!(s.get("dev").is_err());
    }

    #[test]
    fn delete_missing_is_not_found() {
        let s = MockStore::new();
        let err = s.delete("nope").unwrap_err();
        match err {
            Error::Vault(VaultError::NotFound(id)) => assert_eq!(id, "nope"),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn vault_ids_sorted() {
        let s = MockStore::new();
        s.seed("prod", "x");
        s.seed("dev", "y");
        s.seed("staging", "z");
        assert_eq!(s.vault_ids(), vec!["dev", "prod", "staging"]);
    }
}
