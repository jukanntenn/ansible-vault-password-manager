//! Sync end-to-end flow.
//!
//! Drives [`avpm::sync::SyncEngine`] in-process with a `MockStore` +
//! `MockBackend` (shared via `Arc` across two simulated devices) to verify the
//! full push→pull round-trip without touching a real keyring or git remote.
//! (Real-git coverage lives in `sync::backend::git::real_git_tests` and
//! `tests/sync_git_e2e.rs`.)

#![cfg(feature = "testing")]

use std::sync::Arc;

use avpm::index::VaultIndex;
use avpm::sync::backend::MockBackend;
use avpm::sync::engine::SyncEngine;
use avpm::vault::mock::MockStore;
use avpm::vault::{VaultSecret, VaultStore};

fn index_in(dir: &tempfile::TempDir) -> VaultIndex {
    VaultIndex::new(dir.path().join("index.json"))
}

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
        .push(&store1, &index1, "passphrase", None)
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
        .pull(&store2, &index2, "passphrase", &mut resolver)
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
        .push(&store, &index, "right", None)
        .await
        .unwrap();

    let store2 = MockStore::new();
    let dir2 = tempfile::TempDir::new().unwrap();
    let index2 = index_in(&dir2);
    let engine2 = SyncEngine::new(backend);
    let mut resolver = avpm::sync::engine::KeepLocalResolver;
    let res = engine2.pull(&store2, &index2, "wrong", &mut resolver).await;
    assert!(res.is_err(), "wrong passphrase must fail decryption");
}

#[tokio::test]
async fn pull_on_empty_remote_is_remote_not_found() {
    let dir = tempfile::TempDir::new().unwrap();
    let index = index_in(&dir);
    let store = MockStore::new();
    let backend = Arc::new(MockBackend::new()); // never pushed
    let engine = SyncEngine::new(backend);
    let mut resolver = avpm::sync::engine::KeepLocalResolver;
    let res = engine.pull(&store, &index, "pw", &mut resolver).await;
    assert!(res.is_err());
}
