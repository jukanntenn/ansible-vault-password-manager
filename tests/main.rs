//! avpm integration test suite.
//!
//! Single test binary (ripgrep-style): every file under `tests/` is a module
//! declared here, so the whole suite compiles once and shares [`common`].
//! `autotests = false` in `Cargo.toml` keeps cargo from treating each
//! `tests/*.rs` as its own binary.
//!
//! Organization is by **domain**, not by test layer — no `_e2e` / `_acceptance`
//! suffixes. Each module covers one essential, independent area of the product:
//!
//! - [`sync_engine`]: the sync domain logic (push/pull/status/conflict), driven
//!   in-process with `MockStore` + `MockBackend` (no system dependencies).
//! - [`sync_backend`]: real `GitBackend` integration against local bare git
//!   repos (the engine-level regression suite; needs system `git`).
//! - [`e2e`]: full end-to-end acceptance through the real binary — the locked
//!   path (deterministic exit 5), the real-cache set→push→clone→pull flow, and
//!   the interactive `avpm unlock` over a pty. System-gated (Secret Service
//!   daemon / `script` pty); skips with a message when unavailable.
//! - `cmd` cases (`tests/cmd/*.toml`): declarative trycmd snapshots for the
//!   deterministic, keyring-free CLI surface — `--help`, `--version`,
//!   `config path`, no-command, argument routing.

mod ansible_client;
mod ansible_e2e;
mod backend_selection;
mod common;
mod contract;
mod e2e;
mod sync_backend;
mod sync_engine;
mod sync_webdav;
mod tui;

/// Declarative CLI snapshot cases under `tests/cmd/`.
///
/// Covers only deterministic, keyring-free CLI behavior (help / version /
/// config path / error exit codes / argument routing) — the part trycmd is
/// purpose-built for. Everything needing a live keyring or config setup stays
/// in the Rust modules above.
#[test]
fn cli_snapshots() {
    trycmd::TestCases::new().case("tests/cmd/*.toml");
}
