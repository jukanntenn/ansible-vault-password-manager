//! Contract tests: dual-binary parity (T2) and the exit-code matrix (T9).
//!
//! `avpm` and `avpm-client` share `avpm::client_main` verbatim — they differ
//! only in file name, because Ansible's `script_is_client` detection requires
//! the `-client` suffix to invoke a vault password script with `--vault-id`.
//! This module pins that contract: for every argument shape the two binaries
//! must agree on exit code, stdout, and stderr, so a future refactor that
//! splits the entry points is caught immediately.
//!
//! The exit-code matrix (T9) exercises the deterministic, keyring-free codes
//! end-to-end through the real binary. The error→code *mapping* is unit-tested
//! in `src/error.rs` (`error::tests`); here we verify those codes actually
//! surface from the CLI. The environment-dependent codes (exit 2 on a
//! keyring-capable box, exit 5 on a locked file store) are covered by
//! `ansible_client` and `e2e` respectively; this file pins the deterministic
//! ones (1 and 3) plus a forced-file-backend exit 5.

use std::path::Path;
use std::process::Command;

use crate::common;

/// Captured output of one binary run, for cross-binary comparison.
struct BinOut {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run a binary (`avpm` or `avpm-client`) isolated under `dir` with `args`.
fn run(make: fn() -> Command, dir: &Path, args: &[&str]) -> BinOut {
    let mut cmd = make();
    common::isolate(&mut cmd, dir);
    cmd.args(args);
    let out = cmd.output().unwrap();
    BinOut {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// RAII guard that guarantees the shared session-collection master-passphrase
/// cache is empty for a test that asserts exit 5 (Locked), then restores the
/// prior value on drop — even if the test panics. Required because parallel e2e
/// tests seed the *same* real cache; without this, a polluted cache turns the
/// expected exit 5 into exit 2 (NotFound) on any host with a Secret Service
/// daemon. No-op on daemon-less hosts (snapshot/restore are best-effort).
struct EmptyCacheGuard {
    previous: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EmptyCacheGuard {
    fn new() -> Self {
        let _lock = common::cache_test_lock();
        let previous = common::snapshot_cache();
        common::restore_cache(None);
        Self { previous, _lock }
    }
}

impl Drop for EmptyCacheGuard {
    fn drop(&mut self) {
        common::restore_cache(self.previous.take());
    }
}

/// Assert `avpm` and `avpm-client` agree completely (exit + stdout + stderr)
/// for one argument shape.
fn assert_parity(dir: &Path, args: &[&str]) {
    let a = run(common::avpm, dir, args);
    let b = run(common::avpm_client, dir, args);
    assert_eq!(
        a.code, b.code,
        "exit code mismatch for args {args:?}: avpm={} avpm-client={}",
        a.code, b.code
    );
    assert_eq!(
        a.stdout, b.stdout,
        "stdout mismatch for args {args:?}\n-- avpm --\n{}\n-- avpm-client --\n{}",
        a.stdout, b.stdout
    );
    assert_eq!(
        a.stderr, b.stderr,
        "stderr mismatch for args {args:?}\n-- avpm --\n{}\n-- avpm-client --\n{}",
        a.stderr, b.stderr
    );
}

// ---------------------------------------------------------------------------
// T2 — dual-binary parity
// ---------------------------------------------------------------------------

/// `--version` is byte-identical: both print `avpm <version>` (the command
/// name is fixed at `avpm` via `#[command(name = "avpm")]`, independent of the
/// binary file name).
#[test]
fn version_output_matches() {
    let dir = tempfile::TempDir::new().unwrap();
    assert_parity(dir.path(), &["--version"]);
}

/// `--help` differs only in the invocation name on the `Usage:` line (clap
/// derives that from `argv[0]`); every other line — subcommand list, flags,
/// descriptions — must be identical.
#[test]
fn help_body_matches() {
    let dir = tempfile::TempDir::new().unwrap();
    let a = run(common::avpm, dir.path(), &["--help"]).stdout;
    let b = run(common::avpm_client, dir.path(), &["--help"])
        .stdout
        .replace("Usage: avpm-client", "Usage: avpm");
    assert_eq!(
        a, b,
        "help bodies differ beyond the invocation name\n-- avpm --\n{a}\n-- avpm-client (normalized) --\n{b}"
    );
}

/// `config path` resolves the same path under the same isolated environment.
#[test]
fn config_path_matches() {
    let dir = tempfile::TempDir::new().unwrap();
    assert_parity(dir.path(), &["config", "path"]);
}

/// The ansible-client form `--vault-id <id>` with the file backend forced and
/// no cached passphrase: both binaries exit 5 (locked) with identical stderr.
#[test]
fn ansible_form_matches_when_locked() {
    let _cache = EmptyCacheGuard::new();
    let dir = tempfile::TempDir::new().unwrap();
    common::write_config(dir.path(), "[storage]\nbackend = \"file\"\n");
    assert_parity(dir.path(), &["--vault-id", "no_such_id"]);
}

// ---------------------------------------------------------------------------
// T9 — deterministic exit-code matrix (end-to-end through the binary)
// ---------------------------------------------------------------------------

/// No command ⇒ exit 1, with a usage hint. (Both binaries; see `assert_parity`.)
#[test]
fn no_command_exits_1() {
    let dir = tempfile::TempDir::new().unwrap();
    let out = run(common::avpm, dir.path(), &[]);
    assert_eq!(
        out.code, 1,
        "expected exit 1, got {}: {}",
        out.code, out.stderr
    );
    assert_parity(dir.path(), &[]);
}

/// A malformed config file ⇒ exit 3 (configuration error), surfaced before any
/// store/keyring access.
#[test]
fn malformed_config_exits_3() {
    let dir = tempfile::TempDir::new().unwrap();
    common::write_config(dir.path(), "this is = = not valid toml [[\n");
    let out = run(common::avpm, dir.path(), &["get", "x"]);
    assert_eq!(
        out.code, 3,
        "expected exit 3 for malformed config, got {}: {}",
        out.code, out.stderr
    );
    assert!(out.stderr.contains("TOML parse error"));
}

/// File backend, no cached passphrase, non-interactive ⇒ exit 5 (locked), the
/// exact contract Ansible's non-interactive calls rely on. Deterministic
/// regardless of keyring availability because the file backend is forced and
/// the shared session cache is isolated by [`EmptyCacheGuard`].
#[test]
fn file_backend_get_exits_5() {
    let _cache = EmptyCacheGuard::new();
    let dir = tempfile::TempDir::new().unwrap();
    common::write_config(dir.path(), "[storage]\nbackend = \"file\"\n");
    let out = run(common::avpm, dir.path(), &["get", "x"]);
    assert_eq!(
        out.code, 5,
        "expected exit 5 (locked), got {}: {}",
        out.code, out.stderr
    );
    assert!(out.stderr.contains("run `avpm unlock`"));
}
