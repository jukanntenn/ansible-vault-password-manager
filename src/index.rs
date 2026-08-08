//! `VaultIndex` - the local vault-id index file.
//!
//! The index is a *cache*, not the source of truth: the keyring holds the
//! secrets. `list` reads it; `set`/`delete` keep it in sync. Loss/corruption
//! does not destroy passwords (a future `reconcile` command could rebuild it).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument, warn};

use crate::error::{Error, Result};
use crate::vault::VaultError;

const INDEX_VERSION: u32 = 1;

/// On-disk index of known vault-ids.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexFile {
    version: u32,
    #[serde(default)]
    vault_ids: BTreeSet<String>,
}

impl Default for IndexFile {
    fn default() -> Self {
        Self {
            version: INDEX_VERSION,
            vault_ids: BTreeSet::new(),
        }
    }
}

/// Local vault-id index backed by `index.json`.
#[derive(Debug, Clone)]
pub struct VaultIndex {
    path: PathBuf,
}

impl VaultIndex {
    /// Create an index handle targeting `path` (typically `paths::index_path()`).
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// The backing file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// List known vault-ids, sorted (BTreeSet order). An absent file yields an
    /// empty list; a corrupted file yields an `IndexCorrupted` error.
    #[instrument(skip(self))]
    pub fn list(&self) -> Result<Vec<String>> {
        let file = self.read_or_default()?;
        Ok(file.vault_ids.into_iter().collect())
    }

    /// Append `vault_id` to the index (idempotent, dedup'd, re-sorted).
    #[instrument(skip(self))]
    pub fn add(&self, vault_id: &str) -> Result<()> {
        let mut file = self.read_or_default()?;
        let inserted = file.vault_ids.insert(vault_id.to_string());
        if inserted {
            self.write(&file)?;
            debug!("index added '{vault_id}'");
        } else {
            debug!("index already had '{vault_id}'");
        }
        Ok(())
    }

    /// Remove `vault_id` from the index. Missing id is a no-op (not an error).
    #[instrument(skip(self))]
    pub fn remove(&self, vault_id: &str) -> Result<()> {
        let mut file = self.read_or_default()?;
        if file.vault_ids.remove(vault_id) {
            self.write(&file)?;
            debug!("index removed '{vault_id}'");
        } else {
            debug!("index did not contain '{vault_id}'");
        }
        Ok(())
    }

    fn read_or_default(&self) -> Result<IndexFile> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let file: IndexFile = serde_json::from_slice(&bytes).map_err(|e| {
                    Error::Vault(VaultError::IndexCorrupted {
                        path: self.path.clone(),
                        source: e,
                    })
                })?;
                if file.version != INDEX_VERSION {
                    warn!(
                        path = %self.path.display(),
                        actual = file.version,
                        expected = INDEX_VERSION,
                        "index version mismatch; proceeding"
                    );
                }
                Ok(file)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(IndexFile::default()),
            Err(e) => Err(Error::Vault(VaultError::Index {
                path: self.path.clone(),
                source: e,
            })),
        }
    }

    fn write(&self, file: &IndexFile) -> Result<()> {
        // Ensure parent dir exists.
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Vault(VaultError::Index {
                        path: self.path.clone(),
                        source: e,
                    })
                })?;
            }
        }
        // Atomic-ish write: serialize -> write tmp -> rename.
        let bytes = serde_json::to_vec_pretty(file).map_err(|e| {
            Error::Vault(VaultError::IndexCorrupted {
                path: self.path.clone(),
                source: e,
            })
        })?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| {
            Error::Vault(VaultError::Index {
                path: tmp.clone(),
                source: e,
            })
        })?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            Error::Vault(VaultError::Index {
                path: self.path.clone(),
                source: e,
            })
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn index_in(dir: &TempDir) -> VaultIndex {
        VaultIndex::new(dir.path().join("index.json"))
    }

    #[test]
    fn missing_file_lists_empty() {
        let dir = TempDir::new().unwrap();
        let idx = index_in(&dir);
        assert!(idx.list().unwrap().is_empty());
    }

    #[test]
    fn add_then_list_sorted() {
        let dir = TempDir::new().unwrap();
        let idx = index_in(&dir);
        idx.add("prod").unwrap();
        idx.add("dev").unwrap();
        idx.add("staging").unwrap();
        idx.add("dev").unwrap(); // dedup
        assert_eq!(idx.list().unwrap(), vec!["dev", "prod", "staging"]);
    }

    #[test]
    fn remove_idempotent() {
        let dir = TempDir::new().unwrap();
        let idx = index_in(&dir);
        idx.add("dev").unwrap();
        idx.remove("dev").unwrap();
        idx.remove("dev").unwrap(); // no-op, no error
        assert!(idx.list().unwrap().is_empty());
    }

    #[test]
    fn persists_across_handles() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("index.json");
        {
            let idx = VaultIndex::new(path.clone());
            idx.add("dev").unwrap();
        }
        let idx2 = VaultIndex::new(path);
        assert_eq!(idx2.list().unwrap(), vec!["dev"]);
    }

    #[test]
    fn corrupted_file_errors() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("index.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let idx = VaultIndex::new(path);
        assert!(matches!(
            idx.list(),
            Err(Error::Vault(VaultError::IndexCorrupted { .. }))
        ));
    }
}
