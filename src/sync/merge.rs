//! Merge + conflict resolution (see `09` §5).
//!
//! Pure functions: `compute_decisions` inspects two manifests and emits a
//! list of [`MergeDecision`]s; `apply_decisions` mutates the local manifest
//! and store/index, consulting a [`ConflictResolver`] for conflicts. This
//! keeps merge logic decoupled from the UI (CLI stdin vs TUI popup).

use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::sync::manifest::{Manifest, VaultEntry};
use crate::vault::{VaultSecret, VaultStore};
use tracing::{info, warn};

/// A per-vault-id merge decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeDecision {
    /// Remote has a vault-id absent locally: add it.
    AddLocal(String),
    /// Local-only vault-id (remote lacks it): keep it as-is.
    KeepLocal(String),
    /// Both sides have it, but local is newer: keep local. Behaviourally
    /// identical to `KeepLocal` for `pull`; `status` uses this to distinguish
    /// "local-only" from "local-newer" in its summary.
    NewerLocal(String),
    /// Remote is newer (or local missing the entry): take remote.
    UpdateFromRemote(String),
    /// Both sides identical: nothing to do.
    Skip(String),
    /// Same timestamp but different password: needs UI resolution.
    Conflict(String),
}

/// Outcome of resolving a single conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    KeepLocal,
    KeepRemote,
    /// Keep local; store remote under a new id `<id>.remote`.
    KeepBoth,
}

/// UI-agnostic conflict resolution hook (CLI implements stdin prompts,
/// TUI implements a popup). Returns `None` to abort/skip the conflict.
pub trait ConflictResolver {
    /// Resolve a conflict for `vault_id`, showing both entries.
    fn resolve(
        &mut self,
        vault_id: &str,
        local: &VaultEntry,
        remote: &VaultEntry,
    ) -> Result<ConflictResolution>;
}

/// Compute merge decisions (pure). See `09` §5.2 matrix.
#[must_use]
pub fn compute_decisions(local: &Manifest, remote: &Manifest) -> Vec<MergeDecision> {
    let mut decisions = Vec::new();

    // Remote-only ids → AddLocal.
    for (id, _) in remote.entries() {
        if !local.vaults.contains_key(id) {
            decisions.push(MergeDecision::AddLocal(id.clone()));
        }
    }

    // ids present in both (or local-only) → compare.
    for (id, local_entry) in local.entries() {
        match remote.vaults.get(id) {
            None => decisions.push(MergeDecision::KeepLocal(id.clone())),
            Some(remote_entry) => {
                if local_entry.password == remote_entry.password {
                    decisions.push(MergeDecision::Skip(id.clone()));
                } else if local_entry.updated_at > remote_entry.updated_at {
                    decisions.push(MergeDecision::NewerLocal(id.clone()));
                } else if local_entry.updated_at < remote_entry.updated_at {
                    decisions.push(MergeDecision::UpdateFromRemote(id.clone()));
                } else {
                    // Same timestamp, different password → conflict.
                    decisions.push(MergeDecision::Conflict(id.clone()));
                }
            }
        }
    }

    decisions
}

/// Summary of a pull merge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeSummary {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub kept_local: Vec<String>,
    pub skipped: Vec<String>,
    pub conflicts: Vec<String>,
}

/// Apply merge decisions to the local manifest, writing through to `store`
/// and `index` for any remote-originating change. Conflicts are routed to
/// `resolver`.
pub fn apply_decisions<S: VaultStore>(
    local: &mut Manifest,
    remote: &Manifest,
    decisions: &[MergeDecision],
    store: &S,
    index: &VaultIndex,
    resolver: &mut impl ConflictResolver,
) -> Result<MergeSummary> {
    let mut summary = MergeSummary::default();

    for decision in decisions {
        match decision {
            MergeDecision::AddLocal(id) => {
                let entry = remote.vaults.get(id).ok_or_else(|| missing_id_error(id))?;
                write_entry(local, store, index, id, entry)?;
                summary.added.push(id.clone());
                info!(vault_id = %id, "added vault from remote");
            }
            MergeDecision::KeepLocal(id) | MergeDecision::NewerLocal(id) => {
                // Both mean "local wins" - keep local unchanged. (`NewerLocal`
                // only exists so `status` can tell local-only from
                // local-newer; for `pull` the outcome is the same.)
                summary.kept_local.push(id.clone());
            }
            MergeDecision::Skip(id) => {
                summary.skipped.push(id.clone());
            }
            MergeDecision::UpdateFromRemote(id) => {
                let entry = remote.vaults.get(id).ok_or_else(|| missing_id_error(id))?;
                write_entry(local, store, index, id, entry)?;
                summary.updated.push(id.clone());
                info!(vault_id = %id, "updated vault from remote");
            }
            MergeDecision::Conflict(id) => {
                let local_entry = local.vaults.get(id).ok_or_else(|| missing_id_error(id))?;
                let remote_entry = remote.vaults.get(id).ok_or_else(|| missing_id_error(id))?;
                summary.conflicts.push(id.clone());
                warn!(vault_id = %id, "conflict during merge");
                match resolver.resolve(id, local_entry, remote_entry)? {
                    ConflictResolution::KeepLocal => {}
                    ConflictResolution::KeepRemote => {
                        write_entry(local, store, index, id, remote_entry)?;
                        summary.updated.push(id.clone());
                    }
                    ConflictResolution::KeepBoth => {
                        let new_id = format!("{id}.remote");
                        write_entry(local, store, index, &new_id, remote_entry)?;
                        summary.added.push(new_id);
                    }
                }
            }
        }
    }

    Ok(summary)
}

fn missing_id_error(id: &str) -> Error {
    // Merge decisions are computed from the manifests, so a missing id is an
    // internal invariant violation rather than user input. We still surface it
    // as a recoverable error rather than panicking (no-panic principle).
    Error::Sync(crate::sync::SyncError::Manifest(format!(
        "merge decision referenced absent vault-id '{id}'"
    )))
}

fn write_entry<S: VaultStore>(
    local: &mut Manifest,
    store: &S,
    index: &VaultIndex,
    vault_id: &str,
    entry: &VaultEntry,
) -> Result<()> {
    let secret = VaultSecret::new(entry.password.clone());
    store.set(vault_id, &secret)?;
    index.add(vault_id)?;
    local.vaults.insert(vault_id.to_string(), entry.clone());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::mock::MockStore;
    use jiff::Timestamp;

    fn entry(pw: &str, ts: i64) -> VaultEntry {
        VaultEntry::new(pw.to_string(), Timestamp::from_second(ts).unwrap())
    }

    fn manifest(pairs: &[(&str, &str, i64)]) -> Manifest {
        let mut m = Manifest::new();
        for (id, pw, ts) in pairs {
            m.vaults.insert((*id).to_string(), entry(pw, *ts));
        }
        m
    }

    #[test]
    fn remote_only_is_added() {
        let local = manifest(&[]);
        let remote = manifest(&[("dev", "p", 10)]);
        let d = compute_decisions(&local, &remote);
        assert_eq!(d, vec![MergeDecision::AddLocal("dev".into())]);
    }

    #[test]
    fn local_only_is_kept() {
        let local = manifest(&[("dev", "p", 10)]);
        let remote = manifest(&[]);
        let d = compute_decisions(&local, &remote);
        assert_eq!(d, vec![MergeDecision::KeepLocal("dev".into())]);
    }

    #[test]
    fn identical_is_skip() {
        let local = manifest(&[("dev", "p", 10)]);
        let remote = manifest(&[("dev", "p", 10)]);
        let d = compute_decisions(&local, &remote);
        assert_eq!(d, vec![MergeDecision::Skip("dev".into())]);
    }

    #[test]
    fn local_newer_is_newer_local() {
        // local newer than remote → NewerLocal (distinct from KeepLocal which
        // is local-only). status uses this split; pull treats both the same.
        let local = manifest(&[("dev", "p1", 20)]);
        let remote = manifest(&[("dev", "p2", 10)]);
        let d = compute_decisions(&local, &remote);
        assert_eq!(d, vec![MergeDecision::NewerLocal("dev".into())]);
    }

    #[test]
    fn remote_newer_updates() {
        let local = manifest(&[("dev", "p1", 10)]);
        let remote = manifest(&[("dev", "p2", 20)]);
        let d = compute_decisions(&local, &remote);
        assert_eq!(d, vec![MergeDecision::UpdateFromRemote("dev".into())]);
    }

    #[test]
    fn same_ts_different_password_is_conflict() {
        let local = manifest(&[("dev", "p1", 10)]);
        let remote = manifest(&[("dev", "p2", 10)]);
        let d = compute_decisions(&local, &remote);
        assert_eq!(d, vec![MergeDecision::Conflict("dev".into())]);
    }

    struct AlwaysKeepRemote;
    impl ConflictResolver for AlwaysKeepRemote {
        fn resolve(
            &mut self,
            _id: &str,
            _local: &VaultEntry,
            _remote: &VaultEntry,
        ) -> Result<ConflictResolution> {
            Ok(ConflictResolution::KeepRemote)
        }
    }

    #[test]
    fn apply_add_writes_through() {
        let dir = tempfile::TempDir::new().unwrap();
        let idx = VaultIndex::new(dir.path().join("index.json"));
        let store = MockStore::new();
        let mut local = manifest(&[]);
        let remote = manifest(&[("dev", "p", 10)]);
        let decisions = vec![MergeDecision::AddLocal("dev".into())];
        let mut resolver = AlwaysKeepRemote;
        let summary =
            apply_decisions(&mut local, &remote, &decisions, &store, &idx, &mut resolver).unwrap();
        assert_eq!(summary.added, vec!["dev"]);
        assert_eq!(store.get("dev").unwrap().as_str(), "p");
        assert_eq!(idx.list().unwrap(), vec!["dev"]);
        assert!(local.vaults.contains_key("dev"));
    }

    struct KeepBothResolver;
    impl ConflictResolver for KeepBothResolver {
        fn resolve(
            &mut self,
            _: &str,
            _: &VaultEntry,
            _: &VaultEntry,
        ) -> Result<ConflictResolution> {
            Ok(ConflictResolution::KeepBoth)
        }
    }

    #[test]
    fn apply_conflict_keep_both_creates_remote_id() {
        let dir = tempfile::TempDir::new().unwrap();
        let idx = VaultIndex::new(dir.path().join("index.json"));
        let store = MockStore::new();
        store.set("dev", &VaultSecret::new("p1".into())).unwrap();
        idx.add("dev").unwrap();
        let mut local = manifest(&[("dev", "p1", 10)]);
        let remote = manifest(&[("dev", "p2", 10)]);
        let decisions = vec![MergeDecision::Conflict("dev".into())];

        let mut resolver = KeepBothResolver;
        let summary =
            apply_decisions(&mut local, &remote, &decisions, &store, &idx, &mut resolver).unwrap();
        assert_eq!(summary.added, vec!["dev.remote"]);
        assert!(store.get("dev").is_ok());
        assert!(store.get("dev.remote").is_ok());
    }

    #[test]
    fn apply_newer_local_keeps_local_unchanged() {
        // pull treats NewerLocal identically to KeepLocal: local wins, store
        // and remote are not modified. Records it under kept_local.
        let dir = tempfile::TempDir::new().unwrap();
        let idx = VaultIndex::new(dir.path().join("index.json"));
        let store = MockStore::new();
        store
            .set("dev", &VaultSecret::new("local-pw".into()))
            .unwrap();
        idx.add("dev").unwrap();
        let mut local = manifest(&[("dev", "local-pw", 20)]);
        let remote = manifest(&[("dev", "remote-pw", 10)]);
        let decisions = vec![MergeDecision::NewerLocal("dev".into())];

        let mut resolver = AlwaysKeepRemote;
        let summary =
            apply_decisions(&mut local, &remote, &decisions, &store, &idx, &mut resolver).unwrap();
        assert_eq!(summary.kept_local, vec!["dev"]);
        // Store untouched: still the local password.
        assert_eq!(store.get("dev").unwrap().as_str(), "local-pw");
    }
}
