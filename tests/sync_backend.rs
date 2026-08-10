//! Sync backend integration against the **real git backend**.
//!
//! Drives [`avpm::sync::SyncEngine`] in-process with a `MockStore` and a real
//! `GitBackend` pointed at a temp bare repo — the acceptance F1-F6 flow
//! without a keyring or a passphrase cache. These tests encode the regressions
//! from the sync acceptance run:
//!
//! - F4: after the first push, a plain `git clone` must check out `vault.age`
//!   (remote HEAD must point at the pushed branch).
//! - F5: a second device (fresh store) must pull everything back.
//! - No unrelated-history forks on remotes that already have a default branch.

#![cfg(feature = "testing")]

use std::path::{Path, PathBuf};

use tokio::process::Command;

use avpm::config::GitConfig;
use avpm::index::VaultIndex;
use avpm::sync::backend::GitBackend;
use avpm::sync::engine::{KeepLocalResolver, SyncEngine};
use avpm::vault::mock::MockStore;
use avpm::vault::{VaultSecret, VaultStore};

fn index_in(dir: &tempfile::TempDir) -> VaultIndex {
    VaultIndex::new(dir.path().join("index.json"))
}

async fn setup_bare(dir: &Path) -> PathBuf {
    let bare = dir.join("vault.git");
    Command::new("git")
        .arg("init")
        .arg("--bare")
        .arg(&bare)
        .output()
        .await
        .unwrap();
    bare
}

/// Device 1 with three vaults, ready to push.
fn device1(dir: &tempfile::TempDir) -> (MockStore, VaultIndex) {
    let store = MockStore::new();
    let index = index_in(dir);
    for (id, pw) in [("dev", "dev-pw"), ("prod", "prod-pw"), ("staging", "s-pw")] {
        store.set(id, &VaultSecret::new(pw.into())).unwrap();
        index.add(id).unwrap();
    }
    (store, index)
}

/// The acceptance F1-F6 flow, engine-level:
/// push → remote HEAD points at the branch → plain clone sees the encrypted
/// blob → second device pulls → status reports no differences.
#[tokio::test]
// age_test_lock serializes the scrypt-heavy engine calls against other
// age-heavy tests (see test_util docs); the std-Mutex guard held across the
// awaits is exactly what we want here.
#[allow(clippy::await_holding_lock)]
async fn acceptance_flow_push_clone_pull_status() {
    let _g = avpm::test_util::age_test_lock();
    let tmp = tempfile::TempDir::new().unwrap();
    let bare = setup_bare(tmp.path()).await;

    let cfg = GitConfig {
        remote: bare.display().to_string(),
        path: "vault.age".into(),
        branch: "main".into(),
    };

    // F3: push.
    let (store1, index1) = device1(&tmp);
    let summary = SyncEngine::new(GitBackend::new(&cfg))
        .push(&store1, &index1, "master-pw", Some("initial backup"))
        .await
        .unwrap();
    assert_eq!(summary.pushed_count, 3);
    assert!(summary.ciphertext_size > 0);

    // F4: the remote HEAD points at the pushed branch, and a plain `git
    // clone` checks out the age-armored blob.
    let head = String::from_utf8_lossy(
        &Command::new("git")
            .arg("--git-dir")
            .arg(&bare)
            .arg("symbolic-ref")
            .arg("HEAD")
            .output()
            .await
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert_eq!(head, "refs/heads/main");

    let check = tmp.path().join("check");
    let clone = Command::new("git")
        .args(["clone", bare.to_str().unwrap(), check.to_str().unwrap()])
        .output()
        .await
        .unwrap();
    assert!(
        clone.status.success(),
        "clone stderr: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    let blob = std::fs::read_to_string(check.join("vault.age")).unwrap();
    assert!(
        blob.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"),
        "remote blob must be age armored, got: {blob:?}"
    );

    // F5: a second device pulls everything back.
    let (store2, index2) = (MockStore::new(), index_in(&tmp));
    let mut resolver = KeepLocalResolver;
    let pull = SyncEngine::new(GitBackend::new(&cfg))
        .pull(&store2, &index2, "master-pw", &mut resolver)
        .await
        .unwrap();
    assert_eq!(pull.added, vec!["dev", "prod", "staging"]);
    assert_eq!(store2.get("dev").unwrap().as_str(), "dev-pw");
    assert_eq!(store2.get("prod").unwrap().as_str(), "prod-pw");
    assert_eq!(store2.get("staging").unwrap().as_str(), "s-pw");

    // F6: status between identical stores reports everything unchanged.
    let status = SyncEngine::new(GitBackend::new(&cfg))
        .status(&store2, &index2, "master-pw")
        .await
        .unwrap();
    assert_eq!(status.unchanged.len(), 3);
    assert!(status.conflicts.is_empty() && status.local_only.is_empty());
}

/// First push to a remote that already has a `master` branch must adopt
/// `master` (extend the existing history) — never fork into an unrelated
/// `main` — and a second device must still pull successfully.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn first_push_to_master_only_remote_adopts_and_pulls() {
    let _g = avpm::test_util::age_test_lock();
    let tmp = tempfile::TempDir::new().unwrap();
    let bare = setup_bare(tmp.path()).await;

    // Seed the remote with a master branch holding a README.
    let seed = tmp.path().join("seed");
    std::fs::create_dir_all(&seed).unwrap();
    Command::new("git")
        .args(["init", "-b", "master", "."])
        .current_dir(&seed)
        .output()
        .await
        .unwrap();
    std::fs::write(seed.join("README"), "init").unwrap();
    Command::new("git")
        .args(["add", "."])
        .current_dir(&seed)
        .output()
        .await
        .unwrap();
    Command::new("git")
        .args([
            "-c",
            "user.email=a@b",
            "-c",
            "user.name=a",
            "commit",
            "-m",
            "init",
        ])
        .current_dir(&seed)
        .output()
        .await
        .unwrap();
    Command::new("git")
        .args(["remote", "add", "origin", bare.to_str().unwrap()])
        .current_dir(&seed)
        .output()
        .await
        .unwrap();
    Command::new("git")
        .args(["push", "-u", "origin", "master"])
        .current_dir(&seed)
        .output()
        .await
        .unwrap();

    let cfg = GitConfig {
        remote: bare.display().to_string(),
        path: "vault.age".into(),
        branch: "main".into(),
    };

    let (store1, index1) = device1(&tmp);
    SyncEngine::new(GitBackend::new(&cfg))
        .push(&store1, &index1, "master-pw", None)
        .await
        .unwrap();

    // Only one branch: the adopted master.
    let refs = String::from_utf8_lossy(
        &Command::new("git")
            .arg("--git-dir")
            .arg(&bare)
            .arg("for-each-ref")
            .arg("--format=%(refname:short)")
            .output()
            .await
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert_eq!(refs, "master");

    // Device 2 pulls through the same config (branch still says main).
    let (store2, index2) = (MockStore::new(), index_in(&tmp));
    let mut resolver = KeepLocalResolver;
    let pull = SyncEngine::new(GitBackend::new(&cfg))
        .pull(&store2, &index2, "master-pw", &mut resolver)
        .await
        .unwrap();
    assert_eq!(pull.added.len(), 3);
}
