//! `avpm sync push/pull/status`.

use crate::cli::SyncCmd;
use crate::commands::require_master_passphrase;
use crate::config::{BackendKind, Config};
use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::paths;
use crate::sync::backend::{GitBackend, SyncBackend, WebDavBackend};
use crate::sync::engine::SyncEngine;
use crate::sync::manifest::VaultEntry;
use crate::sync::merge::{ConflictResolution, ConflictResolver};
use crate::sync::SyncError;
use crate::vault::VaultStore;

use std::io::Write;

/// Last few characters of a password, shown as a fingerprint so the user can
/// tell conflicting values apart without dumping full plaintext to stderr.
/// Full reveal (hold-to-reveal) is a future TUI-resolver concern.
fn fingerprint(s: &str) -> String {
    const N: usize = 4;
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= N {
        "•".repeat(chars.len())
    } else {
        format!("…{}", chars[chars.len() - N..].iter().collect::<String>())
    }
}

/// CLI conflict resolver that prompts on stderr, showing the full 3-way
/// context (base / local / remote) so the user can make an informed choice.
struct CliResolver;
impl ConflictResolver for CliResolver {
    fn resolve(
        &mut self,
        vault_id: &str,
        base: Option<&VaultEntry>,
        local: Option<&VaultEntry>,
        remote: Option<&VaultEntry>,
    ) -> Result<ConflictResolution> {
        eprintln!("⚠ Conflict on '{vault_id}':");
        match base {
            Some(b) => eprintln!(
                "  base   : updated {}, {} chars ({})",
                b.updated_at,
                b.password.len(),
                fingerprint(&b.password)
            ),
            None => eprintln!("  base   : (absent — new on both sides since last sync)"),
        }
        match local {
            Some(l) => eprintln!(
                "  local  : updated {}, {} chars ({})",
                l.updated_at,
                l.password.len(),
                fingerprint(&l.password)
            ),
            None => eprintln!("  local  : (deleted on this device)"),
        }
        match remote {
            Some(r) => eprintln!(
                "  remote : updated {}, {} chars ({})",
                r.updated_at,
                r.password.len(),
                fingerprint(&r.password)
            ),
            None => eprintln!("  remote : (deleted on remote)"),
        }
        let both_present = local.is_some() && remote.is_some();
        if both_present {
            eprintln!(
                "[1] keep local  [2] keep remote  [3] keep both (remote as '{vault_id}.remote')"
            );
        } else {
            eprintln!("[1] keep local  [2] keep remote");
        }
        loop {
            eprint!("Enter 1/2{}: ", if both_present { "/3" } else { "" });
            std::io::stderr().flush().ok();
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| Error::Other(anyhow::anyhow!("reading choice: {e}")))?;
            match (line.trim(), both_present) {
                ("1", _) => return Ok(ConflictResolution::KeepLocal),
                ("2", _) => return Ok(ConflictResolution::KeepRemote),
                ("3", true) => return Ok(ConflictResolution::KeepBoth),
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
        .ok_or(Error::Sync(SyncError::NotConfigured))?;
    // The file store's master passphrase, per the unlock contract: cached
    // passphrase is used as-is; interactive runs prompt (and best-effort
    // re-cache); non-interactive runs without a cache exit 5 (Locked) instead
    // of blocking on stdin.
    let passphrase = require_master_passphrase()?;
    let base_path = paths::sync_base_path();
    match sync.backend {
        BackendKind::Git => {
            let git_cfg = sync
                .git
                .as_ref()
                .ok_or_else(|| invalid("git backend configured but [sync.git] missing"))?;
            let backend = GitBackend::new(git_cfg);
            run_with(store, index, backend, &base_path, &passphrase, cmd).await
        }
        BackendKind::WebDav => {
            let wd_cfg = sync
                .webdav
                .as_ref()
                .ok_or_else(|| invalid("webdav backend configured but [sync.webdav] missing"))?;
            let backend = WebDavBackend::new(wd_cfg);
            backend.ensure_password()?;
            run_with(store, index, backend, &base_path, &passphrase, cmd).await
        }
    }
}

async fn run_with<S: VaultStore, B: SyncBackend>(
    store: &S,
    index: &VaultIndex,
    backend: B,
    base_path: &std::path::Path,
    passphrase: &str,
    cmd: SyncCmd,
) -> Result<()> {
    let engine = SyncEngine::new(backend);
    match cmd {
        SyncCmd::Push { message } => match engine
            .push(store, index, base_path, passphrase, message.as_deref())
            .await
        {
            Ok(s) => {
                println!(
                    "Pushed {} vault(s) ({} bytes ciphertext)",
                    s.pushed_count, s.ciphertext_size
                );
            }
            Err(Error::Sync(SyncError::Conflict(ids))) => {
                eprintln!(
                    "Push aborted: {} conflict(s): {}",
                    ids.len(),
                    ids.join(", ")
                );
                eprintln!("Run `avpm sync pull` to resolve interactively, then push again.");
                return Err(Error::Sync(SyncError::Conflict(ids)));
            }
            Err(e) => return Err(e),
        },
        SyncCmd::Pull => {
            let mut resolver = CliResolver;
            let s = engine
                .pull(store, index, base_path, passphrase, &mut resolver)
                .await?;
            println!(
                "Pull complete: +{} ~{} -{} !{} (kept local: {}, unchanged: {})",
                s.added.len(),
                s.updated.len(),
                s.removed.len(),
                s.conflicts.len(),
                s.kept_local.len(),
                s.skipped.len()
            );
        }
        SyncCmd::Status => {
            let s = engine.status(store, index, base_path, passphrase).await?;
            println!("local-only   : {}", s.local_only.len());
            println!("remote-only  : {}", s.remote_only.len());
            println!("local-changed: {}", s.newer_local.len());
            println!("remote-changed: {}", s.newer_remote.len());
            println!("conflicts    : {}", s.conflicts.len());
            println!("unchanged    : {}", s.unchanged.len());
        }
    }
    Ok(())
}

fn invalid(msg: &str) -> Error {
    Error::Sync(SyncError::Manifest(msg.to_string()))
}
