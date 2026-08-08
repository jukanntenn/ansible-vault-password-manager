//! Sync `Manifest` data structures.
//!
//! Spec note: `00/04/09` originally wrote `#[serde(with = "jiff::serde::timestamp")]`
//! on `VaultEntry::updated_at`, but that path does **not exist** in jiff 0.2
//! (verified against `.local/contexts/jiff` source: serde helpers live under
//! `jiff::fmt::serde::*` and only cover *integer* timestamps). The default
//! `jiff::Timestamp` serde already emits/parses RFC3339 strings, which is
//! exactly what the spec intended. We therefore omit the attribute (reported
//! deviation #1).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::vault::{VaultSecret, VaultStore};

/// Manifest format version.
pub const MANIFEST_VERSION: u32 = 1;

/// The encrypted manifest payload: a versioned map of vault-id → entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    pub version: u32,
    pub vaults: BTreeMap<String, VaultEntry>,
}

impl Manifest {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: MANIFEST_VERSION,
            vaults: BTreeMap::new(),
        }
    }

    /// Build a manifest from the local store + index (used by `sync push`).
    pub fn from_local<S: VaultStore>(store: &S, index: &VaultIndex) -> Result<Self> {
        let ids = index.list()?;
        let mut vaults = BTreeMap::new();
        for id in ids {
            match store.get(&id) {
                Ok(secret) => {
                    vaults.insert(id.clone(), VaultEntry::from_secret(&secret));
                }
                Err(Error::Vault(crate::vault::VaultError::NotFound(_))) => {
                    // Index lists an id absent from keyring: skip (cache drift).
                    tracing::warn!(vault_id = %id, "index entry missing from store; skipping");
                }
                Err(e) => return Err(e),
            }
        }
        Ok(Self {
            version: MANIFEST_VERSION,
            vaults,
        })
    }

    /// Serialize to JSON bytes (stable order via BTreeMap).
    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Sync(crate::sync::SyncError::Manifest(e.to_string())))
    }

    /// Deserialize from JSON bytes.
    ///
    /// Rejects payloads whose `version` does not match [`MANIFEST_VERSION`],
    /// so a future incompatible format surfaces as a clear error rather than
    /// a silent misparse.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|e| Error::Sync(crate::sync::SyncError::Manifest(e.to_string())))?;
        if manifest.version != MANIFEST_VERSION {
            return Err(Error::Sync(crate::sync::SyncError::Manifest(format!(
                "manifest version mismatch: file has {}, avpm supports {}",
                manifest.version, MANIFEST_VERSION
            ))));
        }
        Ok(manifest)
    }

    /// Iterator over (vault-id, entry) pairs.
    pub fn entries(&self) -> impl Iterator<Item = (&String, &VaultEntry)> {
        self.vaults.iter()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vaults.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vaults.is_empty()
    }
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}

/// A single vault secret entry within a manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultEntry {
    pub password: String,
    /// RFC3339 timestamp (jiff default serde).
    pub updated_at: jiff::Timestamp,
}

impl VaultEntry {
    /// Build an entry from a secret, stamped *now*.
    #[must_use]
    pub fn from_secret(secret: &VaultSecret) -> Self {
        Self {
            password: secret.as_str().to_string(),
            updated_at: jiff::Timestamp::now(),
        }
    }

    /// Build an entry with an explicit timestamp (testing).
    #[must_use]
    pub fn new(password: String, updated_at: jiff::Timestamp) -> Self {
        Self {
            password,
            updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::mock::MockStore;

    #[test]
    fn roundtrips_json_stably() {
        let mut m = Manifest::new();
        m.vaults.insert(
            "dev".into(),
            VaultEntry::new("p1".into(), jiff::Timestamp::UNIX_EPOCH),
        );
        m.vaults.insert(
            "prod".into(),
            VaultEntry::new("p2".into(), jiff::Timestamp::UNIX_EPOCH),
        );
        let bytes = m.to_json().unwrap();
        let back = Manifest::from_json(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn btremap_keeps_sorted_keys() {
        let mut m = Manifest::new();
        m.vaults.insert(
            "prod".into(),
            VaultEntry::new("p".into(), jiff::Timestamp::UNIX_EPOCH),
        );
        m.vaults.insert(
            "dev".into(),
            VaultEntry::new("p".into(), jiff::Timestamp::UNIX_EPOCH),
        );
        let bytes = m.to_json().unwrap();
        let s = String::from_utf8(bytes).unwrap();
        let dev = s.find("\"dev\"").unwrap();
        let prod = s.find("\"prod\"").unwrap();
        assert!(dev < prod, "dev should serialize before prod");
    }

    #[test]
    fn from_local_skips_index_store_drift() {
        let dir = tempfile::TempDir::new().unwrap();
        let idx = VaultIndex::new(dir.path().join("index.json"));
        idx.add("dev").unwrap();
        idx.add("ghost").unwrap(); // in index, not store
        let store = MockStore::new();
        store.set("dev", &VaultSecret::new("p".into())).unwrap();
        let m = Manifest::from_local(&store, &idx).unwrap();
        assert_eq!(m.len(), 1);
        assert!(m.vaults.contains_key("dev"));
    }

    #[test]
    fn version_is_one() {
        let m = Manifest::new();
        assert_eq!(m.version, MANIFEST_VERSION);
    }

    #[test]
    fn from_json_rejects_version_mismatch() {
        // A payload claiming a future version must be rejected rather than
        // silently misparsed.
        let future = r#"{"version":99,"vaults":{}}"#;
        let err = Manifest::from_json(future.as_bytes()).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("version mismatch"),
            "expected version-mismatch error, got: {msg}"
        );
    }
}
