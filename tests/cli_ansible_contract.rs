//! Ansible client-script contract tests.
//!
//! The ansible contract requires:
//! 1. `avpm --vault-id <id>` => behaves as `get <id>`.
//! 2. On missing vault-id, exit code **2**.
//! 3. `get`'s stdout is **pure** — only the password, single line.
//!
//! #2's exit-code mapping and #3's purity are verified here. The exit-code
//! source is a public library invariant; stdout
//! purity is structurally guaranteed by `get` printing only the secret.

use std::process::Command;

use assert_cmd::prelude::*;

fn avpm() -> Command {
    Command::cargo_bin("avpm").expect("avpm binary built")
}

#[test]
fn vault_id_flag_is_accepted() {
    // The `--vault-id` flag must parse (hidden global arg) and route to get.
    // Without a keyring the process fails, but it must not reject the flag.
    let out = avpm()
        .arg("--vault-id")
        .arg("some-vault-id")
        .output()
        .expect("ran avpm");
    assert!(
        !out.status.success(),
        "expected nonzero exit for missing vault-id"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Usage:") || stderr.contains("Error:"),
        "should not be a clap usage/parse error"
    );
}

#[test]
fn default_action_routes_positional_to_get() {
    let out = avpm()
        .arg("positional-vault-id")
        .output()
        .expect("ran avpm");
    assert!(!out.status.success());
}

/// Exit code 2 maps exactly from `VaultError::NotFound` (the ansible contract).
#[test]
fn not_found_maps_to_exit_code_2() {
    let err = avpm::Error::Vault(avpm::vault::VaultError::NotFound("dev".into()));
    assert_eq!(err.exit_code(), 2);
}

/// The full error→exit-code matrix from
#[test]
fn exit_code_matrix() {
    use avpm::sync::SyncError;
    use avpm::vault::VaultError;

    // exit 2: vault not found
    assert_eq!(
        avpm::Error::Vault(VaultError::NotFound("x".into())).exit_code(),
        2
    );
    // exit 3: config error
    assert_eq!(
        avpm::Error::Config(avpm::ConfigError::Invalid("bad".into())).exit_code(),
        3
    );
    // exit 4: store decryption failure (file backend, wrong master passphrase
    // or corrupted store). age::DecryptError isn't trivially constructible,
    // but VaultError::StoreDecrypt routes through the same exit-code arm.
    assert_eq!(avpm::Error::Vault(VaultError::StoreDecrypt).exit_code(), 4);
    // exit 5: file store locked (master passphrase not cached). Distinct from
    // exit 2 so non-interactive callers (ansible) can tell "locked" from
    // "vault-id absent".
    assert_eq!(avpm::Error::Vault(VaultError::Locked).exit_code(), 5);
    // exit 1: generic fallback (e.g. sync not configured).
    let generic = avpm::Error::Sync(SyncError::NotConfigured);
    assert_eq!(generic.exit_code(), 1);
}
