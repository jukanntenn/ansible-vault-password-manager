//! 3-way merge with conservative conflict detection.
//!
//! Given a common ancestor (`base`), the local manifest, and the remote
//! manifest, decide per vault-id whether a change is **unambiguous** (safe to
//! apply automatically) or **divergent** (a conflict requiring user
//! resolution).
//!
//! Design policy (per spec): *any* case that is not absolutely safe to
//! auto-merge becomes a conflict. Concretely, only these are auto-merged:
//! - one side changed while the other is unchanged vs base;
//! - one side has a new id the other lacks;
//! - both sides converged to the same value;
//! - both sides deleted the same id.
//!
//! Everything else — both changed differently, delete-vs-modify, both created
//! the same id with different values — is a conflict routed to the resolver.
//!
//! Timestamps are **not** used for decisions (the base comparison decides);
//! they are carried only so the resolver can show "edited <when>" to help the
//! user decide. A future "newer wins" preference can consult them.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::sync::manifest::{Manifest, VaultEntry};
use crate::vault::{VaultSecret, VaultStore};
use tracing::{info, warn};

/// A per-vault-id 3-way merge decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeDecision {
    /// Present only in remote (not base, not local): a remote-only addition.
    AddFromRemote(String),
    /// Present only in local (not base, not remote): keep local as-is.
    KeepLocal(String),
    /// Both have it; remote == base (remote unchanged) and local changed: keep
    /// local (the change is unambiguously the local user's).
    TakeLocal(String),
    /// Both have it; local == base (local unchanged) and remote changed: take
    /// remote (the change is unambiguously the remote's).
    TakeRemote(String),
    /// Both sides agree (same value, or both deleted): nothing to do.
    Skip(String),
    /// Divergent — needs user resolution.
    Conflict(String),
}

/// Outcome of resolving a single conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    /// Keep the local state (local value if present, else local deletion).
    KeepLocal,
    /// Take the remote state (remote value if present, else remote deletion).
    KeepRemote,
    /// Keep local and also store the remote value under `<id>.remote`. Only
    /// meaningful when both sides have a value; the resolver should not offer
    /// it for delete-vs-modify conflicts.
    KeepBoth,
}

/// UI-agnostic conflict resolution hook. Receives the full 3-way context
/// (`base`, `local`, `remote` — any may be `None` for deletion conflicts) so the
/// UI can show enough information for an informed decision.
pub trait ConflictResolver {
    fn resolve(
        &mut self,
        vault_id: &str,
        base: Option<&VaultEntry>,
        local: Option<&VaultEntry>,
        remote: Option<&VaultEntry>,
    ) -> Result<ConflictResolution>;
}

/// Compute 3-way merge decisions (pure). See the module docs for the matrix.
///
/// `base` may be empty (first-ever sync): every id is then "new on one side"
/// or "both created", so the merge degrades to a 2-way union — still safe, just
/// with conflicts only on same-id-different-value.
#[must_use]
pub fn compute_decisions(
    base: &Manifest,
    local: &Manifest,
    remote: &Manifest,
) -> Vec<MergeDecision> {
    let ids: BTreeSet<&String> = base
        .vaults
        .keys()
        .chain(local.vaults.keys())
        .chain(remote.vaults.keys())
        .collect();

    ids.into_iter()
        .map(|id| {
            decide(
                id,
                base.vaults.get(id),
                local.vaults.get(id),
                remote.vaults.get(id),
            )
        })
        .collect()
}

/// Per-id 3-way decision. `b/l/r` are base/local/remote entries (`None` =
/// absent). Compares passwords only — timestamps are informational.
fn decide(
    id: &str,
    b: Option<&VaultEntry>,
    l: Option<&VaultEntry>,
    r: Option<&VaultEntry>,
) -> MergeDecision {
    let owned = id.to_string();
    match (b, l, r) {
        // --- id not in base (created since last sync, or first sync) ---
        (None, Some(_), None) => MergeDecision::KeepLocal(owned), // local-only new
        (None, None, Some(_)) => MergeDecision::AddFromRemote(owned), // remote-only new
        (None, Some(le), Some(re)) => {
            if le.password == re.password {
                MergeDecision::Skip(owned) // both created the same value
            } else {
                MergeDecision::Conflict(owned) // both created different values
            }
        }
        // Both sides deleted vs base, or the unreachable (None,None,None) (id
        // came from base ∪ local ∪ remote): a no-op Skip either way.
        (None | Some(_), None, None) => MergeDecision::Skip(owned),
        // delete-vs-keep or delete-vs-modify: either way, a conflict (we never
        // auto-propagate a deletion — too destructive to merge silently).
        (Some(_), None, Some(_)) | (Some(_), Some(_), None) => MergeDecision::Conflict(owned),
        (Some(be), Some(le), Some(re)) => {
            if le.password == re.password {
                MergeDecision::Skip(owned) // convergent (identical result)
            } else if le.password == be.password {
                MergeDecision::TakeRemote(owned) // local unchanged, remote changed
            } else if re.password == be.password {
                MergeDecision::TakeLocal(owned) // remote unchanged, local changed
            } else {
                MergeDecision::Conflict(owned) // both changed differently
            }
        }
    }
}

/// Summary of a pull merge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeSummary {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub removed: Vec<String>,
    pub kept_local: Vec<String>,
    pub skipped: Vec<String>,
    pub conflicts: Vec<String>,
}

/// Apply merge decisions to the local manifest, writing through to `store` and
/// `index` for any remote-originating change. Conflicts are routed to
/// `resolver`.
///
/// Write ordering is store-first, then index: the store is the source of truth,
/// the index a cache. `local` mirrors store+index so it stays consistent as we
/// apply each decision.
pub fn apply_decisions<S: VaultStore>(
    local: &mut Manifest,
    base: &Manifest,
    remote: &Manifest,
    decisions: &[MergeDecision],
    store: &S,
    index: &VaultIndex,
    resolver: &mut impl ConflictResolver,
) -> Result<MergeSummary> {
    let mut summary = MergeSummary::default();

    for decision in decisions {
        match decision {
            MergeDecision::AddFromRemote(id) | MergeDecision::TakeRemote(id) => {
                let entry = remote.vaults.get(id).ok_or_else(|| missing_id_error(id))?;
                write_entry(local, store, index, id, entry)?;
                if matches!(decision, MergeDecision::AddFromRemote(_)) {
                    summary.added.push(id.clone());
                    info!(vault_id = %id, "added vault from remote");
                } else {
                    summary.updated.push(id.clone());
                    info!(vault_id = %id, "updated vault from remote");
                }
            }
            MergeDecision::KeepLocal(id) | MergeDecision::TakeLocal(id) => {
                // Local already holds this state in store+index; nothing to write.
                summary.kept_local.push(id.clone());
            }
            MergeDecision::Skip(id) => {
                summary.skipped.push(id.clone());
            }
            MergeDecision::Conflict(id) => {
                let b = base.vaults.get(id);
                let l = local.vaults.get(id);
                let r = remote.vaults.get(id);
                summary.conflicts.push(id.clone());
                warn!(vault_id = %id, "conflict during 3-way merge");
                match resolver.resolve(id, b, l, r)? {
                    ConflictResolution::KeepLocal => {
                        // Local store+index already reflect local state (including a
                        // local deletion, which means the id is already absent).
                    }
                    ConflictResolution::KeepRemote => {
                        if let Some(remote_entry) = r {
                            write_entry(local, store, index, id, remote_entry)?;
                            summary.updated.push(id.clone());
                        } else {
                            // Remote deleted this id: propagate the deletion locally.
                            remove_entry(local, store, index, id)?;
                            summary.removed.push(id.clone());
                        }
                    }
                    ConflictResolution::KeepBoth => {
                        // Only meaningful when both sides have a value.
                        if let (Some(_le), Some(remote_entry)) = (l, r) {
                            let new_id = format!("{id}.remote");
                            write_entry(local, store, index, &new_id, remote_entry)?;
                            summary.added.push(new_id);
                        } else {
                            // KeepBoth on a delete-vs-modify: fall back to KeepRemote
                            // so no data is silently lost.
                            if let Some(remote_entry) = r {
                                write_entry(local, store, index, id, remote_entry)?;
                                summary.updated.push(id.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(summary)
}

fn missing_id_error(id: &str) -> Error {
    // Decisions are computed from the manifests, so a missing id is an internal
    // invariant violation, surfaced as a recoverable error (no-panic policy).
    Error::Sync(crate::sync::SyncError::Manifest(format!(
        "merge decision referenced absent vault-id '{id}'"
    )))
}

/// Write `entry` to store, then index, then the in-memory manifest (store is
/// authoritative; index is a cache that mirrors it).
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

/// Remove `vault_id` from store, index, and the in-memory manifest.
fn remove_entry<S: VaultStore>(
    local: &mut Manifest,
    store: &S,
    index: &VaultIndex,
    vault_id: &str,
) -> Result<()> {
    let _ = store.delete(vault_id);
    index.remove(vault_id)?;
    local.vaults.remove(vault_id);
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

    // The base timestamp is irrelevant to decisions (only passwords matter);
    // we vary timestamps across sides to prove they do NOT change the outcome.
    fn base_of(pairs: &[(&str, &str)]) -> Manifest {
        let mut m = Manifest::new();
        for (id, pw) in pairs {
            m.vaults.insert((*id).to_string(), entry(pw, 0));
        }
        m
    }

    #[test]
    fn remote_only_is_added() {
        let base = base_of(&[]);
        let local = manifest(&[]);
        let remote = manifest(&[("dev", "p", 10)]);
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::AddFromRemote("dev".into())]
        );
    }

    #[test]
    fn local_only_is_kept() {
        let base = base_of(&[]);
        let local = manifest(&[("dev", "p", 10)]);
        let remote = manifest(&[]);
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::KeepLocal("dev".into())]
        );
    }

    #[test]
    fn convergent_is_skip() {
        let base = base_of(&[("dev", "old")]);
        let local = manifest(&[("dev", "new", 20)]);
        let remote = manifest(&[("dev", "new", 30)]);
        // Both reached "new" via different timestamps → still Skip (same value).
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::Skip("dev".into())]
        );
    }

    #[test]
    fn only_local_changed_takes_local() {
        let base = base_of(&[("dev", "old")]);
        let local = manifest(&[("dev", "local-new", 20)]);
        let remote = manifest(&[("dev", "old", 10)]); // == base
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::TakeLocal("dev".into())]
        );
    }

    #[test]
    fn only_remote_changed_takes_remote() {
        let base = base_of(&[("dev", "old")]);
        let local = manifest(&[("dev", "old", 10)]); // == base
        let remote = manifest(&[("dev", "remote-new", 20)]);
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::TakeRemote("dev".into())]
        );
    }

    #[test]
    fn both_changed_differently_is_conflict() {
        let base = base_of(&[("dev", "old")]);
        let local = manifest(&[("dev", "l-new", 100)]); // local newer by ts
        let remote = manifest(&[("dev", "r-new", 10)]); // remote older by ts
                                                        // Despite the timestamp skew, both changed vs base → conflict (no LWW).
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::Conflict("dev".into())]
        );
    }

    #[test]
    fn both_deleted_is_skip() {
        let base = base_of(&[("dev", "old")]);
        let local = manifest(&[]);
        let remote = manifest(&[]);
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::Skip("dev".into())]
        );
    }

    #[test]
    fn delete_vs_keep_is_conflict() {
        let base = base_of(&[("dev", "old")]);
        let local = manifest(&[]); // deleted locally
        let remote = manifest(&[("dev", "old", 10)]); // unchanged on remote
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::Conflict("dev".into())]
        );
    }

    #[test]
    fn both_created_same_id_same_value_is_skip() {
        let base = base_of(&[]);
        let local = manifest(&[("dev", "p", 10)]);
        let remote = manifest(&[("dev", "p", 20)]);
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::Skip("dev".into())]
        );
    }

    #[test]
    fn both_created_same_id_different_value_is_conflict() {
        let base = base_of(&[]);
        let local = manifest(&[("dev", "p1", 10)]);
        let remote = manifest(&[("dev", "p2", 20)]);
        assert_eq!(
            compute_decisions(&base, &local, &remote),
            vec![MergeDecision::Conflict("dev".into())]
        );
    }

    #[test]
    fn empty_base_degrades_to_2way_union() {
        // First sync (no base): union of both sides, conflict only on clashing
        // same-id-different-value.
        let base = base_of(&[]);
        let local = manifest(&[("a", "1", 1), ("c", "l", 1)]);
        let remote = manifest(&[("b", "2", 1), ("c", "r", 1)]);
        let d = compute_decisions(&base, &local, &remote);
        assert!(d.contains(&MergeDecision::KeepLocal("a".into())));
        assert!(d.contains(&MergeDecision::AddFromRemote("b".into())));
        assert!(d.contains(&MergeDecision::Conflict("c".into())));
    }

    struct AlwaysKeepRemote;
    impl ConflictResolver for AlwaysKeepRemote {
        fn resolve(
            &mut self,
            _id: &str,
            _b: Option<&VaultEntry>,
            _l: Option<&VaultEntry>,
            _r: Option<&VaultEntry>,
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
        let base = base_of(&[]);
        let remote = manifest(&[("dev", "p", 10)]);
        let decisions = vec![MergeDecision::AddFromRemote("dev".into())];
        let mut resolver = AlwaysKeepRemote;
        let summary = apply_decisions(
            &mut local,
            &base,
            &remote,
            &decisions,
            &store,
            &idx,
            &mut resolver,
        )
        .unwrap();
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
            _: Option<&VaultEntry>,
            _: Option<&VaultEntry>,
            _: Option<&VaultEntry>,
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
        let base = base_of(&[("dev", "old")]);
        let remote = manifest(&[("dev", "p2", 10)]);
        let decisions = vec![MergeDecision::Conflict("dev".into())];

        let mut resolver = KeepBothResolver;
        let summary = apply_decisions(
            &mut local,
            &base,
            &remote,
            &decisions,
            &store,
            &idx,
            &mut resolver,
        )
        .unwrap();
        assert_eq!(summary.added, vec!["dev.remote"]);
        assert!(store.get("dev").is_ok());
        assert!(store.get("dev.remote").is_ok());
    }

    #[test]
    fn apply_take_remote_overwrites_store() {
        let dir = tempfile::TempDir::new().unwrap();
        let idx = VaultIndex::new(dir.path().join("index.json"));
        let store = MockStore::new();
        store.set("dev", &VaultSecret::new("old".into())).unwrap();
        idx.add("dev").unwrap();
        let mut local = manifest(&[("dev", "old", 1)]); // == base
        let base = base_of(&[("dev", "old")]);
        let remote = manifest(&[("dev", "remote-new", 2)]);
        let decisions = vec![MergeDecision::TakeRemote("dev".into())];
        let mut resolver = AlwaysKeepRemote;
        let _ = apply_decisions(
            &mut local,
            &base,
            &remote,
            &decisions,
            &store,
            &idx,
            &mut resolver,
        )
        .unwrap();
        assert_eq!(store.get("dev").unwrap().as_str(), "remote-new");
    }

    #[test]
    fn apply_conflict_keep_remote_on_remote_deletion_removes_locally() {
        let dir = tempfile::TempDir::new().unwrap();
        let idx = VaultIndex::new(dir.path().join("index.json"));
        let store = MockStore::new();
        store.set("dev", &VaultSecret::new("old".into())).unwrap();
        idx.add("dev").unwrap();
        let mut local = manifest(&[("dev", "old", 1)]);
        let base = base_of(&[("dev", "old")]);
        let remote = manifest(&[]); // remote deleted dev
        let decisions = vec![MergeDecision::Conflict("dev".into())];
        let mut resolver = AlwaysKeepRemote; // picks KeepRemote → accept deletion
        let summary = apply_decisions(
            &mut local,
            &base,
            &remote,
            &decisions,
            &store,
            &idx,
            &mut resolver,
        )
        .unwrap();
        assert_eq!(summary.removed, vec!["dev"]);
        assert!(store.get("dev").is_err());
        assert!(!idx.list().unwrap().contains(&"dev".to_string()));
    }
}
