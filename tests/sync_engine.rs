//! Sync engine domain logic.
//!
//! Drives [`avpm::sync::SyncEngine`] in-process with a `MockStore` +
//! `MockBackend` (shared via `Arc` across two simulated devices) to verify the
//! 3-way merge, read-merge-write push, conflict-resolution, and error paths
//! without touching a real keyring or git remote. Real-git coverage lives in
//! [`crate::sync_backend`].

#![cfg(feature = "testing")]

use std::sync::Arc;

use avpm::index::VaultIndex;
use avpm::sync::backend::MockBackend;
use avpm::sync::engine::SyncEngine;
use avpm::sync::manifest::{Manifest, VaultEntry};
use avpm::sync::merge::{compute_decisions, ConflictResolution, MergeDecision};
use avpm::vault::mock::MockStore;
use avpm::vault::{VaultSecret, VaultStore};

fn index_in(dir: &tempfile::TempDir) -> VaultIndex {
    VaultIndex::new(dir.path().join("index.json"))
}

/// Each simulated device gets its own local base file (the 3-way common
/// ancestor is per-device state, never shared).
fn base_in(dir: &tempfile::TempDir) -> std::path::PathBuf {
    dir.path().join("sync-base.age")
}

fn entry(pw: &str, ts: i64) -> VaultEntry {
    VaultEntry::new(pw.to_string(), jiff::Timestamp::from_second(ts).unwrap())
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn push_then_pull_round_trips() {
    // Device 1: two vaults.
    let dir1 = tempfile::TempDir::new().unwrap();
    let index1 = index_in(&dir1);
    let store1 = MockStore::new();
    store1
        .set("dev", &VaultSecret::new("dev-pw".into()))
        .unwrap();
    index1.add("dev").unwrap();
    store1
        .set("prod", &VaultSecret::new("prod-pw".into()))
        .unwrap();
    index1.add("prod").unwrap();

    // Shared backend so device 2 reads what device 1 pushed.
    let backend = Arc::new(MockBackend::new());
    let engine1 = SyncEngine::new(backend.clone());
    let push = engine1
        .push(&store1, &index1, &base_in(&dir1), "passphrase", None)
        .await
        .expect("push");
    assert_eq!(push.pushed_count, 2);
    assert!(push.ciphertext_size > 0);

    // Device 2: empty store/index, reads the shared blob.
    let dir2 = tempfile::TempDir::new().unwrap();
    let index2 = index_in(&dir2);
    let store2 = MockStore::new();
    let engine2 = SyncEngine::new(backend);
    let mut resolver = avpm::sync::engine::KeepLocalResolver;
    let pull = engine2
        .pull(
            &store2,
            &index2,
            &base_in(&dir2),
            "passphrase",
            &mut resolver,
        )
        .await
        .expect("pull");
    assert_eq!(pull.added, vec!["dev", "prod"]);
    assert_eq!(store2.get("dev").unwrap().as_str(), "dev-pw");
    assert_eq!(store2.get("prod").unwrap().as_str(), "prod-pw");
}

#[tokio::test]
async fn wrong_passphrase_fails_to_pull() {
    let dir = tempfile::TempDir::new().unwrap();
    let index = index_in(&dir);
    let store = MockStore::new();
    store.set("dev", &VaultSecret::new("pw".into())).unwrap();
    index.add("dev").unwrap();

    let backend = Arc::new(MockBackend::new());
    SyncEngine::new(backend.clone())
        .push(&store, &index, &base_in(&dir), "right", None)
        .await
        .unwrap();

    let store2 = MockStore::new();
    let dir2 = tempfile::TempDir::new().unwrap();
    let index2 = index_in(&dir2);
    let engine2 = SyncEngine::new(backend);
    let mut resolver = avpm::sync::engine::KeepLocalResolver;
    let res = engine2
        .pull(&store2, &index2, &base_in(&dir2), "wrong", &mut resolver)
        .await;
    assert!(res.is_err(), "wrong passphrase must fail decryption");
}

#[tokio::test]
async fn pull_on_empty_remote_is_a_noop() {
    // Absent remote is modelled as an empty manifest (no special case), so pull
    // succeeds with nothing to merge rather than erroring.
    let dir = tempfile::TempDir::new().unwrap();
    let index = index_in(&dir);
    let store = MockStore::new();
    let backend = Arc::new(MockBackend::new()); // never pushed
    let engine = SyncEngine::new(backend);
    let mut resolver = avpm::sync::engine::KeepLocalResolver;
    let pull = engine
        .pull(&store, &index, &base_in(&dir), "pw", &mut resolver)
        .await
        .expect("pull on empty remote should be a no-op success");
    assert!(pull.added.is_empty());
    assert!(pull.updated.is_empty());
}

// ---------------------------------------------------------------------------
// 3-way merge decisions
// ---------------------------------------------------------------------------

#[test]
fn both_created_same_id_different_value_is_conflict() {
    // No common ancestor (first sync): both sides created 'dev' with different
    // values → conflict. Timestamps are irrelevant to the decision.
    let base = Manifest::new();
    let mut local = Manifest::new();
    local.vaults.insert("dev".into(), entry("local-pw", 100));
    let mut remote = Manifest::new();
    remote.vaults.insert("dev".into(), entry("remote-pw", 100));
    assert_eq!(
        compute_decisions(&base, &local, &remote),
        vec![MergeDecision::Conflict("dev".into())]
    );
}

#[test]
fn only_one_side_changed_is_safe_auto_merge() {
    // base has 'dev'=old; only remote changed → TakeRemote (safe, no conflict)
    // even though local has a newer timestamp.
    let mut base = Manifest::new();
    base.vaults.insert("dev".into(), entry("old", 0));
    let mut local = Manifest::new();
    local.vaults.insert("dev".into(), entry("old", 100)); // == base value, newer ts
    let mut remote = Manifest::new();
    remote.vaults.insert("dev".into(), entry("remote-new", 10));
    assert_eq!(
        compute_decisions(&base, &local, &remote),
        vec![MergeDecision::TakeRemote("dev".into())]
    );
}

struct Always(ConflictResolution);
impl avpm::sync::merge::ConflictResolver for Always {
    fn resolve(
        &mut self,
        _id: &str,
        _base: Option<&VaultEntry>,
        _local: Option<&VaultEntry>,
        _remote: Option<&VaultEntry>,
    ) -> avpm::Result<ConflictResolution> {
        Ok(self.0)
    }
}

#[tokio::test]
async fn pull_conflict_keep_remote_overwrites_local() {
    // Device 1 pushes 'dev' = remote-pw.
    let dir1 = tempfile::TempDir::new().unwrap();
    let index1 = index_in(&dir1);
    let store1 = MockStore::new();
    store1
        .set("dev", &VaultSecret::new("remote-pw".into()))
        .unwrap();
    index1.add("dev").unwrap();
    let backend = Arc::new(MockBackend::new());
    SyncEngine::new(backend.clone())
        .push(&store1, &index1, &base_in(&dir1), "pw", None)
        .await
        .unwrap();

    // Device 2 has 'dev' = local-pw; no base yet → both-created-different ⇒
    // conflict. Resolving KeepRemote must overwrite store2 with remote-pw.
    let dir2 = tempfile::TempDir::new().unwrap();
    let index2 = index_in(&dir2);
    let store2 = MockStore::new();
    store2
        .set("dev", &VaultSecret::new("local-pw".into()))
        .unwrap();
    index2.add("dev").unwrap();

    let mut resolver = Always(ConflictResolution::KeepRemote);
    let _ = SyncEngine::new(backend)
        .pull(&store2, &index2, &base_in(&dir2), "pw", &mut resolver)
        .await
        .expect("pull");
    assert_eq!(
        store2.get("dev").unwrap().as_str(),
        "remote-pw",
        "KeepRemote must overwrite the local value"
    );
}

#[tokio::test]
async fn push_aborts_when_remote_conflicts() {
    // Device 1 pushes 'dev' = remote-pw and establishes the shared base.
    let dir1 = tempfile::TempDir::new().unwrap();
    let index1 = index_in(&dir1);
    let store1 = MockStore::new();
    store1
        .set("dev", &VaultSecret::new("remote-pw".into()))
        .unwrap();
    index1.add("dev").unwrap();
    let backend = Arc::new(MockBackend::new());
    SyncEngine::new(backend.clone())
        .push(&store1, &index1, &base_in(&dir1), "pw", None)
        .await
        .unwrap();

    // Device 2 has a conflicting 'dev' (local-pw, no shared base) and tries to
    // push: the 3-way merge sees both-created-different ⇒ push must ABORT
    // rather than silently clobber device 1's value.
    let dir2 = tempfile::TempDir::new().unwrap();
    let index2 = index_in(&dir2);
    let store2 = MockStore::new();
    store2
        .set("dev", &VaultSecret::new("local-pw".into()))
        .unwrap();
    index2.add("dev").unwrap();

    let err = SyncEngine::new(backend)
        .push(&store2, &index2, &base_in(&dir2), "pw", None)
        .await
        .expect_err("conflicting push must abort");
    match err {
        avpm::Error::Sync(avpm::sync::SyncError::Conflict(ids)) => {
            assert_eq!(ids, vec!["dev".to_string()], "conflict must name 'dev'");
        }
        other => panic!("expected Conflict error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Real 3-way merge: shared base → diverge → re-sync.
//
// Every test below FIRST establishes a common ancestor (device 1 pushes,
// device 2 pulls), THEN diverges and re-syncs. This is the state the earlier
// round of tests skipped: they only ever had an empty base (first sync), so
// they exercised the 2-way-union degradation, not the real 3-way logic where
// `base` actually distinguishes "one side changed" (auto-merge) from "both
// changed" (conflict).
// ---------------------------------------------------------------------------

/// One simulated device: its own in-memory store, index, and local base file.
struct Device {
    store: MockStore,
    index: VaultIndex,
    base: std::path::PathBuf,
}

impl Device {
    fn new(dir: &tempfile::TempDir, name: &str) -> Self {
        Self {
            store: MockStore::new(),
            index: VaultIndex::new(dir.path().join(format!("{name}.index.json"))),
            base: dir.path().join(format!("{name}.base.age")),
        }
    }
    fn set(&self, id: &str, pw: &str) {
        self.store.set(id, &VaultSecret::new(pw.into())).unwrap();
        self.index.add(id).unwrap();
    }
    fn delete(&self, id: &str) {
        self.store.delete(id).unwrap();
        self.index.remove(id).unwrap();
    }
    fn pw(&self, id: &str) -> String {
        self.store.get(id).unwrap().as_str().to_string()
    }
}

/// Device 1 pushes, device 2 pulls. Afterwards both share an identical base and
/// identical stores — the precondition for a genuine 3-way divergence test.
async fn establish_shared_base(d1: &Device, d2: &Device, backend: &Arc<MockBackend>, pw: &str) {
    SyncEngine::new(backend.clone())
        .push(&d1.store, &d1.index, &d1.base, pw, None)
        .await
        .unwrap();
    let mut r = avpm::sync::engine::KeepLocalResolver;
    SyncEngine::new(backend.clone())
        .pull(&d2.store, &d2.index, &d2.base, pw, &mut r)
        .await
        .unwrap();
}

/// One side edits, the other is idle. Re-sync must auto-merge (TakeRemote) with
/// **no conflict** — the headline 3-way guarantee that the old 2-way/LWW merge
/// could not make safely.
#[tokio::test]
async fn shared_base_single_sided_edit_auto_merges() {
    let tmp = tempfile::TempDir::new().unwrap();
    let d1 = Device::new(&tmp, "d1");
    let d2 = Device::new(&tmp, "d2");
    let backend = Arc::new(MockBackend::new());
    d1.set("dev", "old");
    establish_shared_base(&d1, &d2, &backend, "pw").await;
    assert_eq!(d2.pw("dev"), "old");

    d1.set("dev", "new-from-d1");
    SyncEngine::new(backend.clone())
        .push(&d1.store, &d1.index, &d1.base, "pw", None)
        .await
        .unwrap();
    let mut r = avpm::sync::engine::KeepLocalResolver;
    let pull = SyncEngine::new(backend.clone())
        .pull(&d2.store, &d2.index, &d2.base, "pw", &mut r)
        .await
        .unwrap();
    assert!(
        pull.conflicts.is_empty(),
        "single-sided edit must auto-merge, not conflict"
    );
    assert_eq!(d2.pw("dev"), "new-from-d1");
}

/// Both devices edit *different* vaults: both changes survive, no conflict.
#[tokio::test]
async fn shared_base_parallel_edits_different_vaults_merge() {
    let tmp = tempfile::TempDir::new().unwrap();
    let d1 = Device::new(&tmp, "d1");
    let d2 = Device::new(&tmp, "d2");
    let backend = Arc::new(MockBackend::new());
    d1.set("dev", "old");
    d1.set("prod", "old");
    establish_shared_base(&d1, &d2, &backend, "pw").await;

    d1.set("dev", "d1-dev");
    d2.set("prod", "d2-prod");
    SyncEngine::new(backend.clone())
        .push(&d1.store, &d1.index, &d1.base, "pw", None)
        .await
        .unwrap();
    let mut r = avpm::sync::engine::KeepLocalResolver;
    let pull = SyncEngine::new(backend.clone())
        .pull(&d2.store, &d2.index, &d2.base, "pw", &mut r)
        .await
        .unwrap();
    assert!(pull.conflicts.is_empty());
    assert_eq!(d2.pw("dev"), "d1-dev"); // pulled from d1 (TakeRemote)
    assert_eq!(d2.pw("prod"), "d2-prod"); // kept d2's own edit (TakeLocal)
}

/// Both devices edit the *same* vault differently after sharing a base: a real
/// both-changed-vs-base conflict. Push must abort; pull resolves via KeepRemote.
#[tokio::test]
async fn shared_base_both_edit_same_vault_is_conflict() {
    let tmp = tempfile::TempDir::new().unwrap();
    let d1 = Device::new(&tmp, "d1");
    let d2 = Device::new(&tmp, "d2");
    let backend = Arc::new(MockBackend::new());
    d1.set("dev", "old");
    establish_shared_base(&d1, &d2, &backend, "pw").await;

    d1.set("dev", "a");
    d2.set("dev", "b");
    SyncEngine::new(backend.clone())
        .push(&d1.store, &d1.index, &d1.base, "pw", None)
        .await
        .unwrap();

    // d2 pushes its 'b' while remote has 'a' (both diverged from 'old') → abort.
    let err = SyncEngine::new(backend.clone())
        .push(&d2.store, &d2.index, &d2.base, "pw", None)
        .await
        .expect_err("both-changed push must abort");
    assert!(matches!(
        err,
        avpm::Error::Sync(avpm::sync::SyncError::Conflict(_))
    ));

    // d2 pulls and resolves KeepRemote → dev becomes 'a'.
    let mut r = Always(ConflictResolution::KeepRemote);
    let pull = SyncEngine::new(backend.clone())
        .pull(&d2.store, &d2.index, &d2.base, "pw", &mut r)
        .await
        .unwrap();
    assert_eq!(pull.conflicts, vec!["dev".to_string()]);
    assert_eq!(d2.pw("dev"), "a");
}

/// Both devices make the *same* edit (convergence): no conflict, value holds.
#[tokio::test]
async fn shared_base_convergent_edit_no_conflict() {
    let tmp = tempfile::TempDir::new().unwrap();
    let d1 = Device::new(&tmp, "d1");
    let d2 = Device::new(&tmp, "d2");
    let backend = Arc::new(MockBackend::new());
    d1.set("dev", "old");
    establish_shared_base(&d1, &d2, &backend, "pw").await;

    d1.set("dev", "converged");
    d2.set("dev", "converged");
    SyncEngine::new(backend.clone())
        .push(&d1.store, &d1.index, &d1.base, "pw", None)
        .await
        .unwrap();
    let mut r = avpm::sync::engine::KeepLocalResolver;
    let pull = SyncEngine::new(backend.clone())
        .pull(&d2.store, &d2.index, &d2.base, "pw", &mut r)
        .await
        .unwrap();
    assert!(
        pull.conflicts.is_empty(),
        "convergent edits must not conflict"
    );
    assert_eq!(d2.pw("dev"), "converged");
}

/// A local deletion can't be pushed while the remote still has the id (== base):
/// delete-vs-keep is a conflict, so push aborts — we never silently propagate a
/// deletion across devices.
#[tokio::test]
async fn shared_base_local_deletion_blocks_push() {
    let tmp = tempfile::TempDir::new().unwrap();
    let d1 = Device::new(&tmp, "d1");
    let d2 = Device::new(&tmp, "d2");
    let backend = Arc::new(MockBackend::new());
    d1.set("dev", "old");
    d1.set("prod", "old");
    establish_shared_base(&d1, &d2, &backend, "pw").await;

    d1.delete("dev");
    let err = SyncEngine::new(backend.clone())
        .push(&d1.store, &d1.index, &d1.base, "pw", None)
        .await
        .expect_err("deletion push must abort");
    match err {
        avpm::Error::Sync(avpm::sync::SyncError::Conflict(ids)) => {
            assert_eq!(ids, vec!["dev".to_string()]);
        }
        other => panic!("expected Conflict on 'dev', got {other:?}"),
    }
}
