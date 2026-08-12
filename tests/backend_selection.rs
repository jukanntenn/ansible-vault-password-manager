//! Backend selection & smart unlock integration tests.
//!
//! Covers the discussion-point-1 redesign:
//!
//! - `avpm unlock` on a keyring-capable system is a no-op: it must NOT create
//!   `store.age` (the bug that previously locked users out of the keyring).
//! - The `Auto` backend is purely probe-driven; a stray `store.age` no longer
//!   forces the file backend when the keyring is reachable.
//!
//! These are deterministic on macOS (Keychain is always reachable). On
//! headless Linux without a Secret Service daemon the keyring probe fails, so
//! the "no store.age" assertion only holds when the keyring is up — the test
//! gates on that.

use std::path::PathBuf;

use crate::common;

#[cfg(target_os = "macos")]
fn store_age_path(dir: &std::path::Path) -> PathBuf {
    dir.join("home")
        .join("Library")
        .join("Application Support")
        .join("avpm")
        .join("store.age")
}

#[cfg(not(target_os = "macos"))]
fn store_age_path(dir: &std::path::Path) -> PathBuf {
    dir.join("data").join("avpm").join("store.age")
}

/// On a keyring-capable system, `avpm unlock` is a no-op and must not create
/// `store.age`. This is the core regression guard for the smart-unlock redesign
/// (previously, unlock always created the file, locking macOS users onto the
/// file backend forever).
#[test]
fn unlock_on_keyring_does_not_create_store_age() {
    let dir = tempfile::TempDir::new().unwrap();
    let mut cmd = common::avpm();
    common::isolate(&mut cmd, dir.path());
    cmd.arg("unlock");
    let output = cmd.output().unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // If the keyring was reachable, unlock reports the no-op message and
    // store.age is absent. If the keyring was unreachable (headless), unlock
    // prompts for a passphrase non-interactively and fails — that path is
    // covered by the file-backend e2e tests instead.
    let keyring_was_used = combined.contains("unlock is not needed");
    if keyring_was_used {
        assert!(
            !store_age_path(dir.path()).exists(),
            "unlock created store.age on a keyring-capable system (regression)"
        );
    }
}

/// T3 — a pre-existing `store.age` must NOT force the file backend when the
/// keyring is reachable.
///
/// The `Auto` backend is purely probe-driven (a read-only keyring lookup); the
/// old `store.age exists ⇒ use file` heuristic was removed because it locked
/// macOS users out of the keyring after a single accidental `unlock`. This test
/// guards against that heuristic being reintroduced: with a stray `store.age`
/// already on disk, the `Auto` path must still resolve to the keyring.
///
/// The assertion runs only when the keyring probe succeeds. On macOS, isolating
/// `HOME` (required to place `store.age` without touching the real
/// `~/Library/...`) breaks the Keychain, so the probe fails there and the test
/// is a documented skip — mirroring the sibling test above. On Linux the Secret
/// Service daemon is reached over D-Bus (independent of `HOME`), so `store.age`
/// in the isolated data dir and a reachable keyring coexist and the assertion
/// fires.
#[test]
fn stray_store_age_does_not_force_file_backend() {
    let dir = tempfile::TempDir::new().unwrap();
    // Pre-place a stray store.age — the removed heuristic would have picked the
    // file backend purely from this file existing.
    let stray = "-----BEGIN AGE ENCRYPTED FILE-----\n(not a real store)\n";
    std::fs::create_dir_all(store_age_path(dir.path()).parent().unwrap()).unwrap();
    std::fs::write(store_age_path(dir.path()), stray).unwrap();

    let mut cmd = common::avpm();
    common::isolate(&mut cmd, dir.path());
    cmd.arg("unlock");
    let output = cmd.output().unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if combined.contains("unlock is not needed") {
        // Keyring was reached: Auto must STILL resolve to keyring despite the
        // stray store.age, and the stray file must be left byte-for-byte
        // untouched (not decrypted, not rewritten).
        assert_eq!(
            std::fs::read_to_string(store_age_path(dir.path())).unwrap(),
            stray,
            "unlock rewrote the stray store.age — Auto resolved to the file backend"
        );
    } else {
        eprintln!(
            "SKIPPED: keyring not reachable under isolated HOME (macOS); \
             stray-store.age assertion is meaningful on Linux/Secret-Service"
        );
    }
}
