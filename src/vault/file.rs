//! `FileStore` - an encrypted-file fallback [`VaultStore`].
//!
//! Used when the OS keyring is unavailable (e.g. WSL2 without a GUI to unlock
//! GNOME Keyring). All vault secrets are kept in a single JSON map, encrypted
//! with age (scrypt passphrase) into an armored ASCII file at `store.age`.
//!
//! Reuses `crate::sync::encrypt::{encrypt, decrypt}` - the same age seal box
//! that sync uses for the remote `vault.age` blob - so there is exactly one
//! encryption scheme in the project.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::{debug, instrument};

use crate::error::{Error, Result};
use crate::sync::encrypt;
use crate::vault::store::VaultStore;
use crate::vault::{VaultError, VaultSecret};

/// Encrypted-file [`VaultStore`] backend. Holds the store path and the master
/// passphrase (obtained via `avpm unlock` / cache). Stateless between calls:
/// each `get`/`set`/`delete` re-reads and rewrites the file.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
    passphrase: String,
}

impl FileStore {
    /// Create a store backed by `path`, unlocked with `passphrase`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, passphrase: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            passphrase: passphrase.into(),
        }
    }

    /// The store file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Decrypt `store.age` into the in-memory vault map.
    ///
    /// A missing file is treated as an empty store (first use); any vault
    /// created afterwards will write a fresh file.
    fn load(&self) -> Result<HashMap<String, String>> {
        let armored = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = %self.path.display(), "store file absent; empty store");
                return Ok(HashMap::new());
            }
            Err(e) => {
                return Err(Error::Vault(VaultError::FileStore {
                    path: self.path.clone(),
                    message: format!("read failed: {e}"),
                }));
            }
        };
        // Empty file also means fresh store (avoids age choking on empty input).
        if armored.trim().is_empty() {
            return Ok(HashMap::new());
        }
        // Decrypt: age::DecryptError surfaces as Error::Decrypt inside the
        // Result. We re-wrap it as VaultError::StoreDecrypt (exit 4) so callers
        // see a vault-domain error; any non-decrypt error passes through.
        let plaintext = encrypt::decrypt(&armored, &self.passphrase).map_err(|e| match e {
            Error::Decrypt(_) => Error::Vault(VaultError::StoreDecrypt),
            other => other,
        })?;
        let json = String::from_utf8(plaintext).map_err(|e| {
            Error::Vault(VaultError::FileStore {
                path: self.path.clone(),
                message: format!("plaintext is not valid UTF-8: {e}"),
            })
        })?;
        let map: HashMap<String, String> = serde_json::from_str(&json).map_err(|e| {
            Error::Vault(VaultError::FileStore {
                path: self.path.clone(),
                message: format!("decrypted JSON is malformed: {e}"),
            })
        })?;
        Ok(map)
    }

    /// Serialize the map to JSON, age-encrypt, and atomically write `store.age`.
    ///
    /// Atomicity mirrors `VaultIndex::write`: write a sibling `.tmp` file then
    /// rename, so a crash mid-write never leaves a half-encrypted store.
    fn save(&self, map: &HashMap<String, String>) -> Result<()> {
        // Ensure parent dir exists (first write on a fresh system).
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Vault(VaultError::FileStore {
                        path: parent.to_path_buf(),
                        message: format!("create_dir_all failed: {e}"),
                    })
                })?;
            }
        }
        let json = serde_json::to_string(map).map_err(|e| {
            Error::Vault(VaultError::FileStore {
                path: self.path.clone(),
                message: format!("serialize failed: {e}"),
            })
        })?;
        let armored = encrypt::encrypt(json.as_bytes(), &self.passphrase)?;
        // write tmp then rename (same pattern as index.rs).
        let tmp = self.path.with_extension("age.tmp");
        std::fs::write(&tmp, armored.as_bytes()).map_err(|e| {
            Error::Vault(VaultError::FileStore {
                path: tmp.clone(),
                message: format!("write tmp failed: {e}"),
            })
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            Error::Vault(VaultError::FileStore {
                path: self.path.clone(),
                message: format!("rename failed: {e}"),
            })
        })?;
        Ok(())
    }
}

impl VaultStore for FileStore {
    #[instrument(skip(self), fields(path = %self.path.display(), vault_id = %vault_id))]
    fn get(&self, vault_id: &str) -> Result<VaultSecret> {
        let map = self.load()?;
        match map.get(vault_id) {
            Some(pw) => {
                debug!(password_len = pw.len(), "file store get ok");
                Ok(VaultSecret::new(pw.clone()))
            }
            None => Err(Error::Vault(VaultError::NotFound(vault_id.to_string()))),
        }
    }

    #[instrument(skip(self, secret), fields(path = %self.path.display(), vault_id = %vault_id, password_len = secret.len()))]
    fn set(&self, vault_id: &str, secret: &VaultSecret) -> Result<()> {
        let mut map = self.load()?;
        map.insert(vault_id.to_string(), secret.as_str().to_string());
        self.save(&map)?;
        debug!("file store set ok");
        Ok(())
    }

    #[instrument(skip(self), fields(path = %self.path.display(), vault_id = %vault_id))]
    fn delete(&self, vault_id: &str) -> Result<()> {
        let mut map = self.load()?;
        if map.remove(vault_id).is_some() {
            self.save(&map)?;
            debug!("file store delete ok");
            Ok(())
        } else {
            Err(Error::Vault(VaultError::NotFound(vault_id.to_string())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Build a FileStore rooted at `<dir>/store.age` with the given passphrase.
    fn store_in(dir: &TempDir, passphrase: &str) -> FileStore {
        FileStore::new(dir.path().join("store.age"), passphrase)
    }

    // age scrypt is memory-bandwidth intensive; parallel age-heavy tests
    // cause intermittent decrypt failures from cache contention, not bugs.
    // Each test holds the global guard to run serially w.r.t. the other
    // age-heavy tests (FileStore + sync::encrypt).
    #[test]
    fn crud_roundtrip() {
        let _g = crate::test_util::age_test_lock();
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir, "master-pw");
        let secret = VaultSecret::new("dev-password".to_string());
        store.set("dev", &secret).unwrap();
        let got = store.get("dev").unwrap();
        assert_eq!(got.as_str(), "dev-password");
        store.delete("dev").unwrap();
        assert!(store.get("dev").is_err());
    }

    #[test]
    fn set_overwrites() {
        let _g = crate::test_util::age_test_lock();
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir, "master-pw");
        store.set("dev", &VaultSecret::new("v1".into())).unwrap();
        store.set("dev", &VaultSecret::new("v2".into())).unwrap();
        assert_eq!(store.get("dev").unwrap().as_str(), "v2");
    }

    #[test]
    fn get_missing_is_not_found() {
        let _g = crate::test_util::age_test_lock();
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir, "master-pw");
        let err = store.get("nope").unwrap_err();
        assert!(matches!(
            err,
            Error::Vault(VaultError::NotFound(ref id)) if id == "nope"
        ));
    }

    #[test]
    fn delete_missing_is_not_found() {
        let _g = crate::test_util::age_test_lock();
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir, "master-pw");
        let err = store.delete("nope").unwrap_err();
        assert!(matches!(
            err,
            Error::Vault(VaultError::NotFound(ref id)) if id == "nope"
        ));
    }

    #[test]
    fn persists_across_handles() {
        let _g = crate::test_util::age_test_lock();
        // A new FileStore handle pointing at the same file + passphrase must
        // see data written by a previous handle (proves on-disk persistence).
        let dir = TempDir::new().unwrap();
        let store1 = store_in(&dir, "master-pw");
        store1
            .set("prod", &VaultSecret::new("prod-pw".into()))
            .unwrap();
        let store2 = store_in(&dir, "master-pw");
        assert_eq!(store2.get("prod").unwrap().as_str(), "prod-pw");
    }

    #[test]
    fn wrong_passphrase_fails_to_decrypt() {
        let _g = crate::test_util::age_test_lock();
        let dir = TempDir::new().unwrap();
        let store1 = store_in(&dir, "correct-pw");
        store1.set("dev", &VaultSecret::new("x".into())).unwrap();
        // A second handle with the wrong passphrase cannot decrypt the file.
        let store2 = store_in(&dir, "wrong-pw");
        let err = store2.get("dev").unwrap_err();
        assert!(
            matches!(err, Error::Vault(VaultError::StoreDecrypt)),
            "{err:?}"
        );
    }

    #[test]
    fn store_file_is_age_armored() {
        let _g = crate::test_util::age_test_lock();
        // The on-disk file must be age-armored ASCII (not plaintext, not opaque
        // binary) so it is git-diff friendly and inspectable.
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir, "master-pw");
        store
            .set("dev", &VaultSecret::new("secret-value".into()))
            .unwrap();
        let on_disk = std::fs::read_to_string(store.path()).unwrap();
        assert!(
            on_disk.contains("AGE ENCRYPTED FILE"),
            "expected armored age output, got: {on_disk}"
        );
        // The plaintext must never appear on disk.
        assert!(!on_disk.contains("secret-value"));
    }

    #[test]
    fn multiple_vaults_persist_together() {
        let _g = crate::test_util::age_test_lock();
        let dir = TempDir::new().unwrap();
        let store = store_in(&dir, "master-pw");
        store.set("dev", &VaultSecret::new("d".into())).unwrap();
        store.set("prod", &VaultSecret::new("p".into())).unwrap();
        store.set("staging", &VaultSecret::new("s".into())).unwrap();
        let store2 = store_in(&dir, "master-pw");
        assert_eq!(store2.get("dev").unwrap().as_str(), "d");
        assert_eq!(store2.get("prod").unwrap().as_str(), "p");
        assert_eq!(store2.get("staging").unwrap().as_str(), "s");
        // Deleting one preserves the others.
        store2.delete("prod").unwrap();
        let store3 = store_in(&dir, "master-pw");
        assert_eq!(store3.get("dev").unwrap().as_str(), "d");
        assert!(store3.get("prod").is_err());
        assert_eq!(store3.get("staging").unwrap().as_str(), "s");
    }
}
