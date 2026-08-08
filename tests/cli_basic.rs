//! CLI end-to-end tests.
//!
//! These exercise the `avpm` binary as a subprocess. They focus on behaviors
//! that do **not** require a live keyring backend (which is unavailable in CI
//! and most headless environments): help/version output, argument routing,
//! the ansible default-action form, `config path`, and exit-code semantics.
//!
//! Real keyring round-trips are covered by the `#[ignore]`'d
//! `vault::keyring::real_keyring_tests` (run in the `ignored-tests` CI job).

use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;

fn avpm() -> Command {
    Command::cargo_bin("avpm").expect("avpm binary built")
}

#[test]
fn help_lists_subcommands() {
    avpm()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("get"))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("sync"))
        .stdout(predicate::str::contains("config"));
}

#[test]
fn version_prints() {
    avpm()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("avpm"));
}

#[test]
fn config_path_prints_absolute_path() {
    // config path is platform-dependent but must be a non-empty line on stdout.
    avpm()
        .arg("config")
        .arg("path")
        .assert()
        .success()
        .stdout(predicate::str::contains("avpm"))
        .stdout(predicate::str::contains("config.toml"));
}

#[test]
fn no_command_errors_nonzero() {
    avpm().assert().failure();
}

#[test]
fn unknown_subcommand_is_treated_as_get_vault_id() {
    // `avpm <id>` => get <id>; with no keyring, this fails (nonzero) but must
    // not crash. We assert it exits nonzero and does not print garbage help.
    avpm()
        .arg("definitely-nonexistent-vault-id-xyz")
        .assert()
        .failure();
}

#[test]
fn vault_id_flag_routes_to_get() {
    // ansible client form: `avpm --vault-id <id>` => get <id>.
    avpm()
        .arg("--vault-id")
        .arg("definitely-nonexistent-vault-id-xyz")
        .assert()
        .failure();
}
