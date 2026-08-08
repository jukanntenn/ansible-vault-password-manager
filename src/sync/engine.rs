//! `SyncEngine` - orchestrates push/pull/status.
//!
//! Push: gather local manifest → serialize → encrypt → backend.push.
//! Pull: backend.exists? → backend.pull → decrypt → parse → merge → write-back.
//! Status: like pull but compare-only (no write-back).

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
    pub conflicts: Vec<String>,
    pub kept_local: Vec<String>,
    pub skipped: Vec<String>,
}

/// `sync status` outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatusSummary {
    pub local_only: Vec<String>,
    pub remote_only: Vec<String>,
    pub newer_remote: Vec<String>,
    pub newer_local: Vec<String>,
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

    /// Encrypt and push the local manifest.
    ///
    /// `message` is forwarded to the backend (git uses it as the commit
    /// message — enables `avpm sync push -m`; blob stores ignore it). See
    ///2,4.
    #[instrument(skip(self, store, index, passphrase, message), fields(vault_count))]
    pub async fn push<S: VaultStore>(
        &self,
        store: &S,
        index: &VaultIndex,
        passphrase: &str,
        message: Option<&str>,
    ) -> Result<PushSummary> {
        let _span = info_span!("sync_push").entered();
        let manifest = Manifest::from_local(store, index)?;
        let count = manifest.len();
        // Record the count into the parent span *after* computing it (avoids
        // running from_local twice just for the instrument field —3).
        tracing::Span::current().record("vault_count", count);
        let json = manifest.to_json()?;
        let armored = encrypt::encrypt(&json, passphrase)?;
        let ct_len = armored.len();
        self.backend.push(armored.as_bytes(), message).await?;
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

    /// Pull, decrypt, merge into local store + index.
    pub async fn pull<S: VaultStore>(
        &self,
        store: &S,
        index: &VaultIndex,
        passphrase: &str,
        resolver: &mut impl ConflictResolver,
    ) -> Result<PullSummary> {
        let _span = info_span!("sync_pull").entered();
        if !self.backend.exists().await? {
            return Err(Error::Sync(crate::sync::SyncError::Backend(
                crate::sync::error::SyncBackendError::RemoteNotFound,
            )));
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
        let remote = Manifest::from_json(&plain)?;
        let mut local = Manifest::from_local(store, index)?;
        let decisions = compute_decisions(&local, &remote);
        let merge = apply_decisions(&mut local, &remote, &decisions, store, index, resolver)?;
        Ok(PullSummary {
            added: merge.added,
            updated: merge.updated,
            conflicts: merge.conflicts,
            kept_local: merge.kept_local,
            skipped: merge.skipped,
        })
    }

    /// Compare local vs remote without modifying anything.
    pub async fn status<S: VaultStore>(
        &self,
        store: &S,
        index: &VaultIndex,
        passphrase: &str,
    ) -> Result<StatusSummary> {
        let _span = info_span!("sync_status").entered();
        let local = Manifest::from_local(store, index)?;
        let mut summary = StatusSummary::default();
        if !self.backend.exists().await? {
            // Remote empty: everything is local-only.
            for (id, _) in local.entries() {
                summary.local_only.push(id.clone());
            }
            return Ok(summary);
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
        let remote = Manifest::from_json(&plain)?;
        for decision in compute_decisions(&local, &remote) {
            match decision {
                MergeDecision::AddLocal(id) => summary.remote_only.push(id),
                MergeDecision::KeepLocal(id) => summary.local_only.push(id),
                MergeDecision::NewerLocal(id) => summary.newer_local.push(id),
                MergeDecision::UpdateFromRemote(id) => summary.newer_remote.push(id),
                MergeDecision::Skip(id) => summary.unchanged.push(id),
                MergeDecision::Conflict(id) => summary.conflicts.push(id),
            }
        }
        Ok(summary)
    }
}

/// A no-op resolver that keeps local on any conflict (non-interactive default
/// for `sync pull` when no TUI/CLI resolver is wired).
pub struct KeepLocalResolver;

impl ConflictResolver for KeepLocalResolver {
    fn resolve(
        &mut self,
        _vault_id: &str,
        _local: &crate::sync::manifest::VaultEntry,
        _remote: &crate::sync::manifest::VaultEntry,
    ) -> Result<ConflictResolution> {
        Ok(ConflictResolution::KeepLocal)
    }
}
