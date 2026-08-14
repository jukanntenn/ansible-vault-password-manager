//! Backend selection & smart unlock integration tests.
//!
//! Covers the keyring-backend redesign (gaps 1a/1b/1c/2a):
//!
//! - `avpm unlock` on a keyring-capable system readies the default collection
//!   (creating/unlocking it via a GUI prompt if needed) and must NOT create
//!   `store.age` (the bug that previously locked users out of the keyring).
//! - The `Auto` backend is decided by the **existence** of the default
//!   collection (not a stray `store.age`); a pre-existing `store.age` does not
//!   force the file backend when the keyring collection exists.
//!
//! These are deterministic on macOS (no Secret Service — the collection probe
//! always reports "ready"). On headless Linux without a usable default
//! collection the keyring path isn't taken, so the assertions only fire when
//! the keyring is usable — the tests gate on the reported message.

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

/// On a keyring-capable system, `avpm unlock` readies the default collection
/// and must not create `store.age`. This is the core regression guard (unlock
/// previously created the file, locking macOS users onto the file backend).
///
/// Gated on the default collection already being ready, so the test never
/// blocks on a GUI create/unlock prompt (which would happen on a WSLg box whose
/// collection is absent or locked — that interactive path is exercised by the
/// `#[ignore]`'d ss integration test instead).
#[test]
fn unlock_on_keyring_does_not_create_store_age() {
    if !common::default_collection_is_ready() {
        eprintln!(
            "SKIPPED: default collection not ready (would prompt); \
             keyring-path assertion is meaningful only when unlock is a no-op"
        );
        return;
    }
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
    assert!(
        combined.contains("keyring backend ready"),
        "expected the keyring path, got: {combined}"
    );
    assert!(
        !store_age_path(dir.path()).exists(),
        "unlock created store.age on a keyring-capable system (regression)"
    );
}

/// T3 — a pre-existing `store.age` must NOT force the file backend when the
/// keyring's default collection exists.
///
/// `Auto` is decided by default-collection existence (gap 1b), not by the
/// presence of `store.age`. This guards against the old `store.age exists ⇒ use
/// file` heuristic being reintroduced: with a stray `store.age` already on disk,
/// the `Auto` path must still resolve to the keyring when the collection exists.
///
/// The assertion fires only when the keyring path is taken. On macOS the
/// collection probe always reports "ready" (no Secret Service), so the keyring
/// path is taken and the assertion fires. On Linux it fires when a usable
/// default collection exists; otherwise the test is a documented skip.
#[test]
fn stray_store_age_does_not_force_file_backend() {
    if !common::default_collection_is_ready() {
        eprintln!(
            "SKIPPED: default collection not ready (would prompt); \
             stray-store.age assertion is meaningful only when unlock is a no-op"
        );
        return;
    }
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

    assert!(
        combined.contains("keyring backend ready"),
        "expected the keyring path despite the stray store.age, got: {combined}"
    );
    // Auto must STILL resolve to keyring despite the stray store.age, and the
    // stray file must be left byte-for-byte untouched (not decrypted/rewritten).
    assert_eq!(
        std::fs::read_to_string(store_age_path(dir.path())).unwrap(),
        stray,
        "unlock rewrote the stray store.age — Auto resolved to the file backend"
    );
}
