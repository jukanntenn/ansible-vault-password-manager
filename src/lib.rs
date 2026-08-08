//! avpm - Ansible Vault Password Manager.
//!
//! A minimal system keyring adapter that stores Ansible Vault passwords in the
//! OS-native keyring (macOS Keychain / Linux Secret Service), serves them to
//! Ansible via the vault password client script protocol, and offers
//! end-to-end encrypted multi-device sync (Git / WebDAV backends) as a
//! first-class feature.
//!
//! See the README for the full design overview.
//!
//! # Design principles
//! 1. Zero-cost abstraction - generics over `&dyn`; only 2 traits
//!    (`VaultStore`, `SyncBackend`).
//! 2. Testability - system interactions go through traits for Mock injection.
//! 3. Minimalism - no auth/daemon/IPC/WSL hacks/home-grown crypto.
//! 4. High observability - structured `tracing` logs at every decision point.
//! 5. No panics - `forbid(unsafe_code)` + `deny(unwrap_used, expect_used)`.

#![forbid(unsafe_code)]
// `unwrap`/`expect` are forbidden in production code but permitted in tests
// (where panics surface failures clearly). The cfg_attr keeps the strict
// `deny` for non-test builds and relaxes it for `#[cfg(test)]`.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::all, clippy::pedantic)]
// Selective allowances for pedantic lints that clash with the project's
// design (large library `Error` enum, async-fn-in-trait) or are pure
// documentation churn that adds no safety.
#![allow(
    clippy::result_large_err,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_lossless
)]

pub mod cli;
pub mod commands;
pub mod config;
pub mod error;
pub mod index;
pub mod logging;
pub mod password;
pub mod paths;
pub mod sync;
pub mod tui;
pub mod vault;

#[cfg(any(test, feature = "testing"))]
pub mod test_util;

pub use config::{Config, ConfigError};
pub use error::{Error, Result};
pub use index::VaultIndex;
pub use vault::{KeyringStore, VaultSecret, VaultStore};

/// Convenience alias used across command handlers.
pub type AnyResult<T> = std::result::Result<T, anyhow::Error>;
