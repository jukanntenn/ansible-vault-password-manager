//! Sync subsystem (see `09-sync-mechanism.md`).
//!
//! End-to-end encrypted multi-device sync. Local vault secrets are collected
//! into a `Manifest`, age-encrypted with a user passphrase, and transported
//! via a pluggable `SyncBackend` (Git / WebDAV).

pub mod backend;
pub mod encrypt;
pub mod engine;
pub mod error;
pub mod manifest;
pub mod merge;

pub use engine::{PullSummary, PushSummary, StatusSummary, SyncEngine};
pub use error::{SyncBackendError, SyncError};
pub use manifest::{Manifest, VaultEntry};

use crate::error::Result;

/// Convenience re-export alias for sync-domain results.
pub type SyncResult<T> = Result<T>;
