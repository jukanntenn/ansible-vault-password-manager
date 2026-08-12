//! ansible-vault end-to-end round-trip through the real `avpm-client` binary.
//!
//! Proves the headline feature: Ansible's `ansible-vault encrypt/view`, pointed
//! at `avpm-client` as a vault-password client (`--vault-id <id>@<client>`),
//! can encrypt and decrypt a secret whose password avpm manages. This is the
//! outermost acceptance test — every other layer (client contract, parity,
//! store) exists to make this work.
//!
//! Follows the `e2e` acceptance pattern: force the file backend, seed the real
//! Secret Service session collection with the master passphrase (snapshotted and
//! restored so a dev's active unlock is never clobbered), set the vault-id, then
//! drive `ansible-vault` exactly as Ansible would.
//!
//! Skips with a message when `ansible-vault` is absent or no Secret Service
//! daemon is reachable. macOS Keychain has no Secret Service, so the file-store
//! cache path this test relies on is unavailable there — the keyring client
//! contract (`--vault-id` → exit 2) is instead exercised by `ansible_client`.

use std::path::Path;
use std::process::Command as StdCommand;

use assert_cmd::cargo::cargo_bin;

use crate::common::{self, cache_test_lock, restore_cache, seed_cache, snapshot_cache};

const MASTER_PW: &str = "master123";
/// Unique vault-id so the round-trip can never collide with real data. Used as
/// both the avpm vault-id and the ansible `--vault-id` label (avpm-client
/// receives `--vault-id <label>` and fetches that exact id).
const VAULT_ID: &str = "avpm_ansible_e2e";
const PLAINTEXT: &str = "the eagle has landed at noon\n";

/// Is `ansible-vault` installed and runnable?
fn ansible_vault_available() -> bool {
    StdCommand::new("ansible-vault")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Drive `avpm <args>` isolated under `dir` (same env the ansible-vault child
/// will inherit), asserting success.
fn avpm_ok(dir: &Path, args: &[&str]) {
    let mut cmd = common::avpm();
    common::isolate(&mut cmd, dir);
    cmd.args(args);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "`avpm {:?}` failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `ansible-vault encrypt` then `view` through `avpm-client`, with the vault-id
/// avpm just stored. The password itself is opaque — Ansible fetches it via the
/// client, so we never need to know the generated value.
#[test]
fn ansible_vault_round_trip_via_avpm_client() {
    if !ansible_vault_available() {
        eprintln!("SKIPPED: ansible-vault not installed");
        return;
    }
    let _guard = cache_test_lock();
    let previous = snapshot_cache();
    if !seed_cache(MASTER_PW) {
        eprintln!("SKIPPED: no Secret Service daemon (file-backend cache unavailable; macOS uses the keyring path)");
        return;
    }

    let dir = tempfile::TempDir::new().unwrap();
    common::write_config(dir.path(), "[storage]\nbackend = \"file\"\n");

    // Plant the vault password avpm will serve to Ansible. `-g` generates a
    // strong password non-interactively (the id is unique, so no overwrite
    // prompt).
    avpm_ok(dir.path(), &["set", VAULT_ID, "-g"]);

    // A plaintext file Ansible will encrypt in place.
    let plain = dir.path().join("secret.txt");
    std::fs::write(&plain, PLAINTEXT.as_bytes()).unwrap();

    let client: std::path::PathBuf = cargo_bin("avpm-client");
    let vault_id_arg = format!("{VAULT_ID}@{}", client.display());

    // encrypt: ansible-vault calls `avpm-client --vault-id <VAULT_ID>` to fetch
    // the password, then encrypts the file in place.
    let mut enc = StdCommand::new("ansible-vault");
    enc.args(["encrypt", "--vault-id", &vault_id_arg])
        .arg(&plain);
    common::isolate(&mut enc, dir.path());
    let enc_out = enc.output().unwrap();
    assert!(
        enc_out.status.success(),
        "ansible-vault encrypt failed: {}",
        String::from_utf8_lossy(&enc_out.stderr)
    );

    // The file is now ciphertext (ansible-vault's `$ANSIBLE_VAULT` header) and
    // no longer contains the plaintext.
    let blob = std::fs::read_to_string(&plain).unwrap();
    assert!(
        blob.contains("$ANSIBLE_VAULT"),
        "file not encrypted: {blob}"
    );
    assert!(
        !blob.contains(PLAINTEXT.trim()),
        "plaintext leaked into the encrypted file"
    );

    // view: ansible-vault fetches the same password via avpm-client and writes
    // the decrypted content to stdout.
    let mut view = StdCommand::new("ansible-vault");
    view.args(["view", "--vault-id", &vault_id_arg])
        .arg(&plain);
    common::isolate(&mut view, dir.path());
    let view_out = view.output().unwrap();
    assert!(
        view_out.status.success(),
        "ansible-vault view failed: {}",
        String::from_utf8_lossy(&view_out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&view_out.stdout),
        PLAINTEXT,
        "decrypted content does not match the original plaintext"
    );

    restore_cache(previous);
}
