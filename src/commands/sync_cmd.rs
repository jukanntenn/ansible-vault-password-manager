//! `avpm sync push/pull/status`.

use crate::cli::SyncCmd;
use crate::commands::require_master_passphrase;
use crate::config::{BackendKind, Config};
use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::sync::backend::{GitBackend, SyncBackend, WebDavBackend};
use crate::sync::engine::{KeepLocalResolver, SyncEngine};
use crate::sync::merge::ConflictResolver;
use crate::vault::VaultStore;

use std::io::Write;

/// CLI conflict resolver that prompts on stderr.
struct CliResolver;
impl ConflictResolver for CliResolver {
    fn resolve(
        &mut self,
        vault_id: &str,
        local: &crate::sync::manifest::VaultEntry,
        remote: &crate::sync::manifest::VaultEntry,
    ) -> Result<crate::sync::merge::ConflictResolution> {
        eprintln!("Conflict on '{vault_id}':");
        eprintln!(
            "  local  : updated {}, {} chars",
            local.updated_at,
            local.password.len()
        );
        eprintln!(
            "  remote : updated {}, {} chars",
            remote.updated_at,
            remote.password.len()
        );
        eprintln!("[1] keep local  [2] keep remote  [3] keep both");
        loop {
            eprint!("Enter 1/2/3: ");
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| Error::Other(anyhow::anyhow!("reading choice: {e}")))?;
            match line.trim() {
                "1" => return Ok(crate::sync::merge::ConflictResolution::KeepLocal),
                "2" => return Ok(crate::sync::merge::ConflictResolution::KeepRemote),
                "3" => return Ok(crate::sync::merge::ConflictResolution::KeepBoth),
                // Invalid input: loop and re-prompt (default branch is implicit).
                _ => {}
            }
        }
    }
}

pub async fn execute<S: VaultStore>(
    cfg: &Config,
    store: &S,
    index: &VaultIndex,
    cmd: SyncCmd,
) -> Result<()> {
    let sync = cfg
        .sync_config()
        .ok_or(Error::Sync(crate::sync::SyncError::NotConfigured))?;
    // The file store's master passphrase, per the unlock contract: cached
    // passphrase is used as-is; interactive runs prompt (and best-effort
    // re-cache); non-interactive runs without a cache exit 5 (Locked) instead
    // of blocking on stdin.
    let passphrase = require_master_passphrase()?;
    match sync.backend {
        BackendKind::Git => {
            let git_cfg = sync
                .git
                .as_ref()
                .ok_or_else(|| invalid("git backend configured but [sync.git] missing"))?;
            let backend = GitBackend::new(git_cfg);
            run_with(store, index, backend, &passphrase, cmd).await
        }
        BackendKind::WebDav => {
            let wd_cfg = sync
                .webdav
                .as_ref()
                .ok_or_else(|| invalid("webdav backend configured but [sync.webdav] missing"))?;
            let backend = WebDavBackend::new(wd_cfg);
            backend.ensure_password()?;
            run_with(store, index, backend, &passphrase, cmd).await
        }
    }
}

async fn run_with<S: VaultStore, B: SyncBackend>(
    store: &S,
    index: &VaultIndex,
    backend: B,
    passphrase: &str,
    cmd: SyncCmd,
) -> Result<()> {
    let engine = SyncEngine::new(backend);
    match cmd {
        SyncCmd::Push { message } => {
            let s = engine
                .push(store, index, passphrase, message.as_deref())
                .await?;
            println!(
                "Pushed {} vault(s) ({} bytes ciphertext)",
                s.pushed_count, s.ciphertext_size
            );
        }
        SyncCmd::Pull => {
            let mut resolver = CliResolver;
            let s = engine.pull(store, index, passphrase, &mut resolver).await?;
            println!(
                "Pull complete: +{} ~{} !{} (kept local: {})",
                s.added.len(),
                s.updated.len(),
                s.conflicts.len(),
                s.kept_local.len()
            );
        }
        SyncCmd::Status => {
            let s = engine.status(store, index, passphrase).await?;
            let _ = KeepLocalResolver; // unused here but documents the default
            println!("local-only : {}", s.local_only.len());
            println!("remote-only: {}", s.remote_only.len());
            println!("newer remote: {}", s.newer_remote.len());
            println!("conflicts  : {}", s.conflicts.len());
            println!("unchanged  : {}", s.unchanged.len());
        }
    }
    Ok(())
}

fn invalid(msg: &str) -> Error {
    Error::Sync(crate::sync::SyncError::Manifest(msg.to_string()))
}
