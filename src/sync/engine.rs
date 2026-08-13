//! `SyncEngine` — orchestrates push/pull/status over a `SyncBackend`.
//!
//! All three operations share the same core: fetch the remote manifest (an
//! empty manifest if the remote is absent — there is no "first push" special
//! case), load the local base (last-synced snapshot), and run a **3-way merge**
//! (base / local / remote).
//!
//! - **push** = read-merge-write: it never blindly overwrites the remote. It
//!   merges remote into local first; if the merge has any conflict it
//!   **aborts** (exit non-zero) and tells the user to `sync pull` to resolve,
//!   so no side is ever silently picked. Only a conflict-free merge is
//!   encrypted and uploaded, and the base is then updated to the merged
//!   result.
//! - **pull** = merge with interactive conflict resolution, writing through to
//!   the local store/index. No auto-push.
//! - **status** = 3-way compare, read-only.

use std::path::Path;

use tracing::{info, info_span, instrument};

use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::sync::backend::SyncBackend;
use crate::sync::encrypt;
use crate::sync::manifest::Manifest;
use crate::sync::merge::{
    apply_decisions, compute_decisions, ConflictResolution, ConflictResolver, MergeDecision,
};
use crate::vault::VaultStore;

/// `sync push` outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushSummary {
    pub pushed_count: usize,
    pub ciphertext_size: usize,
}

/// `sync pull` outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PullSummary {
    pub added: Vec<String>,
    pub updated: Vec<String>,
    pub removed: Vec<String>,
    pub conflicts: Vec<String>,
    pub kept_local: Vec<String>,
    pub skipped: Vec<String>,
}

/// `sync status` outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusSummary {
    pub local_only: Vec<String>,
    pub remote_only: Vec<String>,
    /// local changed vs base (remote unchanged).
    pub newer_local: Vec<String>,
    /// remote changed vs base (local unchanged).
    pub newer_remote: Vec<String>,
    pub conflicts: Vec<String>,
    pub unchanged: Vec<String>,
}

/// Sync orchestrator over a backend `B`.
pub struct SyncEngine<B: SyncBackend> {
    backend: B,
}

impl<B: SyncBackend> SyncEngine<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Fetch + decrypt the remote manifest.
    ///
    /// An **absent** remote yields an empty manifest (no first-push special
    /// case — the merge treats it as a 2-way union). A network/auth error from
    /// `exists()` / `pull()` is surfaced as `Err` (never faked as "absent").
    async fn fetch_remote(&self, passphrase: &str) -> Result<Manifest> {
        if !self.backend.exists().await? {
            return Ok(Manifest::new());
        }
        let encrypted = self.backend.pull().await?;
        let plain = encrypt::decrypt(
            std::str::from_utf8(&encrypted).map_err(|e| {
                Error::Sync(crate::sync::SyncError::Manifest(format!(
                    "non-utf8 ciphertext: {e}"
                )))
            })?,
            passphrase,
        )?;
        Manifest::from_json(&plain)
    }

    /// Load the local base manifest (the 3-way common ancestor), age-encrypted
    /// at `base_path`. A missing or undecryptable base yields an empty
    /// manifest — the merge then degrades to a safe 2-way union (more
    /// conflicts, no data loss).
    fn load_base(base_path: &Path, passphrase: &str) -> Manifest {
        let Some(bytes) = std::fs::read(base_path).ok() else {
            return Manifest::new();
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Manifest::new();
        };
        if let Ok(plain) = encrypt::decrypt(text, passphrase) {
            Manifest::from_json(&plain).unwrap_or_else(|_| Manifest::new())
        } else {
            tracing::warn!("could not decrypt sync base; merging without a common ancestor");
            Manifest::new()
        }
    }

    /// Persist the merged manifest as the new base (age-encrypted, atomic write).
    fn save_base(base_path: &Path, manifest: &Manifest, passphrase: &str) -> Result<()> {
        let json = manifest.to_json()?;
        let armored = encrypt::encrypt(&json, passphrase)?;
        if let Some(parent) = base_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(io_err)?;
            }
        }
        let tmp = base_path.with_extension("age.tmp");
        std::fs::write(&tmp, armored.as_bytes()).map_err(io_err)?;
        std::fs::rename(&tmp, base_path).map_err(io_err)?;
        Ok(())
    }

    /// Read-merge-write push. See the module docs: never blindly overwrites.
    #[instrument(
        skip(self, store, index, base_path, passphrase, message),
        fields(vault_count)
    )]
    pub async fn push<S: VaultStore>(
        &self,
        store: &S,
        index: &VaultIndex,
        base_path: &Path,
        passphrase: &str,
        message: Option<&str>,
    ) -> Result<PushSummary> {
        let _span = info_span!("sync_push").entered();
        let local = Manifest::from_local(store, index)?;
        let remote = self.fetch_remote(passphrase).await?;
        let base = Self::load_base(base_path, passphrase);

        let decisions = compute_decisions(&base, &local, &remote);
        let conflicts: Vec<String> = decisions
            .iter()
            .filter_map(|d| match d {
                MergeDecision::Conflict(id) => Some(id.clone()),
                _ => None,
            })
            .collect();
        if !conflicts.is_empty() {
            return Err(Error::Sync(crate::sync::SyncError::Conflict(conflicts)));
        }

        // Conflict-free: apply remote-originating changes into local (store is
        // authoritative, index mirrors it). `merged` absorbs remote's entries
        // so the uploaded blob is the union, not just the old local snapshot.
        let mut merged = local;
        apply_decisions(
            &mut merged,
            &base,
            &remote,
            &decisions,
            store,
            index,
            &mut KeepLocalResolver,
        )?;
        let count = merged.len();
        tracing::Span::current().record("vault_count", count);

        let json = merged.to_json()?;
        let armored = encrypt::encrypt(&json, passphrase)?;
        let ct_len = armored.len();
        self.backend.push(armored.as_bytes(), message).await?;

        // The merged result is now the confirmed common state on both sides.
        Self::save_base(base_path, &merged, passphrase)?;

        info!(
            vault_count = count,
            ciphertext_size = ct_len,
            "push complete"
        );
        Ok(PushSummary {
            pushed_count: count,
            ciphertext_size: ct_len,
        })
    }

    /// Pull, decrypt, 3-way merge into local store + index with interactive
    /// conflict resolution.
    #[instrument(skip(self, store, index, base_path, passphrase, resolver))]
    pub async fn pull<S: VaultStore>(
        &self,
        store: &S,
        index: &VaultIndex,
        base_path: &Path,
        passphrase: &str,
        resolver: &mut impl ConflictResolver,
    ) -> Result<PullSummary> {
        let _span = info_span!("sync_pull").entered();
        let remote = self.fetch_remote(passphrase).await?;
        let base = Self::load_base(base_path, passphrase);
        let mut local = Manifest::from_local(store, index)?;

        let decisions = compute_decisions(&base, &local, &remote);
        let merge = apply_decisions(
            &mut local, &base, &remote, &decisions, store, index, resolver,
        )?;

        // After a successful pull, the local state is the new common ancestor.
        Self::save_base(base_path, &local, passphrase)?;

        Ok(PullSummary {
            added: merge.added,
            updated: merge.updated,
            removed: merge.removed,
            conflicts: merge.conflicts,
            kept_local: merge.kept_local,
            skipped: merge.skipped,
        })
    }

    /// Compare local vs remote (3-way) without modifying anything.
    pub async fn status<S: VaultStore>(
        &self,
        store: &S,
        index: &VaultIndex,
        base_path: &Path,
        passphrase: &str,
    ) -> Result<StatusSummary> {
        let _span = info_span!("sync_status").entered();
        let local = Manifest::from_local(store, index)?;
        let remote = self.fetch_remote(passphrase).await?;
        let base = Self::load_base(base_path, passphrase);

        let mut summary = StatusSummary::default();
        for decision in compute_decisions(&base, &local, &remote) {
            match decision {
                MergeDecision::AddFromRemote(id) => summary.remote_only.push(id),
                MergeDecision::KeepLocal(id) => summary.local_only.push(id),
                MergeDecision::TakeLocal(id) => summary.newer_local.push(id),
                MergeDecision::TakeRemote(id) => summary.newer_remote.push(id),
                MergeDecision::Skip(id) => summary.unchanged.push(id),
                MergeDecision::Conflict(id) => summary.conflicts.push(id),
            }
        }
        Ok(summary)
    }
}

fn io_err(e: std::io::Error) -> Error {
    Error::Sync(crate::sync::SyncError::Backend(
        crate::sync::SyncBackendError::Io(e),
    ))
}

/// A no-op resolver that keeps local on any conflict. Used by `push` (which
/// aborts before reaching the resolver anyway) and as a non-interactive
/// default where one is required.
pub struct KeepLocalResolver;
impl ConflictResolver for KeepLocalResolver {
    fn resolve(
        &mut self,
        _vault_id: &str,
        _base: Option<&crate::sync::manifest::VaultEntry>,
        _local: Option<&crate::sync::manifest::VaultEntry>,
        _remote: Option<&crate::sync::manifest::VaultEntry>,
    ) -> Result<ConflictResolution> {
        Ok(ConflictResolution::KeepLocal)
    }
}

/// Bounded retry on a concurrent-modification failure is deferred (see spec):
/// the read-merge-write above already eliminates the blind-overwrite (P0). The
/// narrow fetch→write race is a documented follow-up (WebDAV `If-Match` via the
/// backend's conditional PUT + a git non-fast-forward retry loop).
#[allow(dead_code)]
fn _concurrency_todo_marker() {}
