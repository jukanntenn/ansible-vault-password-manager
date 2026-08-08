//! `GitBackend` - sync via a system `git` subprocess (see `09` §4.2, `03` §3).
//!
//! push: clone/pull the remote to a temp dir, overwrite the blob, commit, push.
//! pull: clone, read the blob.
//! Authentication is fully delegated to the user's system git (SSH keys,
//! credential helpers, 2FA) - avpm never handles credentials. Tests use a
//! local `file://` bare repo to avoid network/auth.

use std::path::{Path, PathBuf};

use tokio::process::Command;
use tracing::{debug, instrument, trace};

use crate::config::GitConfig;
use crate::error::{Error, Result};
use crate::paths;
use crate::sync::backend::SyncBackend;
use crate::sync::error::SyncBackendError;

/// Git-backed sync transport.
pub struct GitBackend {
    remote: String,
    path: String,
    branch: String,
}

impl GitBackend {
    /// Build from a parsed `[sync.git]` config.
    #[must_use]
    pub fn new(cfg: &GitConfig) -> Self {
        Self {
            remote: cfg.remote.clone(),
            path: cfg.path.clone(),
            branch: cfg.branch.clone(),
        }
    }

    fn work_dir(&self) -> PathBuf {
        // `&self` reserved for a future per-instance work-base override; the
        // current implementation derives the path from the global cache dir.
        let _ = self;
        let base = paths::sync_tmp_dir();
        let id = format!("{:x}", rand::random::<u128>());
        base.join(id)
    }
}

impl SyncBackend for GitBackend {
    #[instrument(skip(self, data), fields(remote = %self.remote, path = %self.path, branch = %self.branch, bytes = data.len()))]
    async fn push(&self, data: &[u8], message: Option<&str>) -> Result<()> {
        let work = self.work_dir();
        std::fs::create_dir_all(&work).map_err(io_to_backend)?;

        // Which branch do we land on?
        // - The configured branch, if the remote already has it.
        // - An empty remote is seeded from scratch (and its HEAD pointed at
        //   our branch, so a plain `git clone` finds the data).
        // - A non-empty remote without our branch is adopted on its *default*
        //   branch, extending the existing history instead of forking it.
        // Log clone failures at debug level before falling back, since failure
        // can also mean network/auth issues (not just an unprepared remote) —
        // keeps the high-observability promise (`06`).
        let push_branch = match git_clone(&self.remote, &work, Some(&self.branch)).await {
            Ok(()) => self.branch.clone(),
            Err(e) => {
                debug!(error = %e, "git clone --branch {} failed; probing remote", self.branch);
                cleanup_work_dir(&work);
                std::fs::create_dir_all(&work).map_err(io_to_backend)?;
                if git_ls_remote(&self.remote, &work).await?.is_empty() {
                    debug!("remote is empty; seeding from scratch");
                    git_init_and_add_origin(&work, &self.remote).await?;
                    // A bare repo created with `git init --bare` still points
                    // HEAD at git's default branch (master); point it at ours
                    // so `git clone` (no --branch) checks out the data.
                    git_sync_remote_head(&self.remote, &self.branch).await;
                    self.branch.clone()
                } else {
                    debug!(
                        "remote has refs but no {branch}; adopting its default branch",
                        branch = self.branch
                    );
                    git_clone(&self.remote, &work, None).await?;
                    git_head_branch(&work).await?
                }
            }
        };

        let blob_path = work.join(&self.path);
        std::fs::write(&blob_path, data).map_err(io_to_backend)?;

        git_add(&work, &self.path).await?;
        let msg = match message {
            Some(m) if !m.trim().is_empty() => m.to_string(),
            _ => format!("avpm sync push {}", jiff::Timestamp::now()),
        };
        git_commit(&work, &msg).await?;
        git_push(&work, &push_branch).await?;

        // Cleanup. Errors here are non-fatal (temp dir best-effort).
        cleanup_work_dir(&work);
        debug!("git push ok");
        Ok(())
    }

    #[instrument(skip(self), fields(remote = %self.remote, path = %self.path, branch = %self.branch))]
    async fn pull(&self) -> Result<Vec<u8>> {
        let work = self.work_dir();
        std::fs::create_dir_all(&work).map_err(io_to_backend)?;

        // Prefer the configured branch; fall back to the remote's default
        // branch so devices never get stuck on a differently-named branch.
        if let Err(e) = git_clone(&self.remote, &work, Some(&self.branch)).await {
            debug!(error = %e, "git clone --branch {} failed; trying default branch", self.branch);
            cleanup_work_dir(&work);
            std::fs::create_dir_all(&work).map_err(io_to_backend)?;
            git_clone(&self.remote, &work, None).await?;
        }
        let blob_path = work.join(&self.path);
        if !blob_path.exists() {
            cleanup_work_dir(&work);
            return Err(Error::Sync(crate::sync::SyncError::Backend(
                SyncBackendError::RemoteNotFound,
            )));
        }
        let bytes = std::fs::read(&blob_path).map_err(io_to_backend)?;
        cleanup_work_dir(&work);
        debug!(bytes = bytes.len(), "git pull ok");
        Ok(bytes)
    }

    #[instrument(skip(self), fields(remote = %self.remote, path = %self.path, branch = %self.branch))]
    async fn exists(&self) -> Result<bool> {
        let work = self.work_dir();
        std::fs::create_dir_all(&work).map_err(io_to_backend)?;
        let res = match git_clone(&self.remote, &work, Some(&self.branch)).await {
            Ok(()) => work.join(&self.path).exists(),
            Err(e) => {
                debug!(error = %e, "git clone --branch {} failed in exists(); retrying default branch", self.branch);
                cleanup_work_dir(&work);
                std::fs::create_dir_all(&work).map_err(io_to_backend)?;
                match git_clone(&self.remote, &work, None).await {
                    Ok(()) => work.join(&self.path).exists(),
                    // Clone failure could be empty remote (legit false) or
                    // network error; we report false and let the caller
                    // decide. Log at debug.
                    Err(e) => {
                        debug!(error = %e, "git clone failed in exists(); reporting absent");
                        false
                    }
                }
            }
        };
        cleanup_work_dir(&work);
        Ok(res)
    }
}

/// Best-effort removal of the temp work dir; logs non-fatal errors instead of
/// silently swallowing them (high observability, `06`).
fn cleanup_work_dir(work: &Path) {
    if let Err(e) = std::fs::remove_dir_all(work) {
        debug!(error = %e, path = %work.display(), "failed to clean git work dir (non-fatal)");
    }
}

fn io_to_backend(e: std::io::Error) -> Error {
    Error::Sync(crate::sync::SyncError::Backend(SyncBackendError::Io(e)))
}

fn git_cmd(work: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(work);
    c.env("GIT_TERMINAL_PROMPT", "0"); // never prompt for credentials
    c.env("GIT_AUTHOR_NAME", "avpm");
    c.env("GIT_AUTHOR_EMAIL", "avpm@localhost");
    c.env("GIT_COMMITTER_NAME", "avpm");
    c.env("GIT_COMMITTER_EMAIL", "avpm@localhost");
    c
}

/// Clone `remote` into `work`. With `branch`, checks out that branch (used
/// when the remote is known to have it); without, checks out the remote's
/// default branch (follows the remote HEAD).
async fn git_clone(remote: &str, work: &Path, branch: Option<&str>) -> Result<()> {
    let mut cmd = git_cmd(work.parent().unwrap_or(work));
    cmd.arg("clone");
    if let Some(branch) = branch {
        cmd.arg("--branch").arg(branch);
    }
    cmd.arg("--").arg(remote).arg(work);
    let out = cmd
        .output()
        .await
        .map_err(|e| backend_git(&e, "git clone", remote))?;
    if out.status.success() {
        trace!(stdout = ?String::from_utf8_lossy(&out.stdout), "clone ok");
        Ok(())
    } else {
        Err(backend_git_output("git clone", remote, &out))
    }
}

/// List refs on `remote`. An empty result means the remote exists but has no
/// branches yet (freshly created bare repo).
async fn git_ls_remote(remote: &str, work: &Path) -> Result<Vec<String>> {
    let out = git_cmd(work)
        .arg("ls-remote")
        .arg("--")
        .arg(remote)
        .output()
        .await
        .map_err(|e| backend_git(&e, "git ls-remote", remote))?;
    if out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        Ok(stdout
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect())
    } else {
        Err(backend_git_output("git ls-remote", remote, &out))
    }
}

/// The name of the branch checked out in `work` (the remote's default branch
/// after a branch-less clone).
async fn git_head_branch(work: &Path) -> Result<String> {
    let out = git_cmd(work)
        .arg("rev-parse")
        .arg("--abbrev-ref")
        .arg("HEAD")
        .output()
        .await
        .map_err(|e| backend_git(&e, "git rev-parse", "HEAD"))?;
    if out.status.success() {
        let branch = String::from_utf8_lossy(&out.stdout).trim().to_string();
        // "HEAD" means detached; an empty remote has no branch at all.
        if branch.is_empty() || branch == "HEAD" {
            Err(backend_git_output("git rev-parse", "HEAD", &out))
        } else {
            Ok(branch)
        }
    } else {
        Err(backend_git_output("git rev-parse", "HEAD", &out))
    }
}

/// Point a locally-accessible bare remote's HEAD at `branch`, so a plain
/// `git clone` (no `--branch`) checks out the synced data. Best-effort:
/// hosting platforms set HEAD to the first pushed branch themselves, and
/// non-bare remotes are skipped (flipping their HEAD would affect the
/// working tree).
async fn git_sync_remote_head(remote: &str, branch: &str) {
    let Some(path) = local_remote_path(remote) else {
        return;
    };
    let bare = git_cmd(&path)
        .arg("rev-parse")
        .arg("--is-bare-repository")
        .output()
        .await;
    let Ok(out) = bare else { return };
    if !out.status.success() || !String::from_utf8_lossy(&out.stdout).trim().eq("true") {
        return;
    }
    match git_cmd(&path)
        .arg("symbolic-ref")
        .arg("HEAD")
        .arg(format!("refs/heads/{branch}"))
        .output()
        .await
    {
        Ok(o) if o.status.success() => debug!("set remote HEAD -> refs/heads/{branch}"),
        Ok(o) => {
            debug!(stderr = ?String::from_utf8_lossy(&o.stderr), "could not set remote HEAD (non-fatal)");
        }
        Err(e) => debug!(error = %e, "could not set remote HEAD (non-fatal)"),
    }
}

/// The filesystem path of `remote` if it is locally accessible (`/path`,
/// `~/path`, `file:///path`); `None` for ssh/https URLs.
fn local_remote_path(remote: &str) -> Option<PathBuf> {
    let path = if let Some(rest) = remote.strip_prefix("file://") {
        rest
    } else if remote.contains("://") || remote.contains('@') {
        return None;
    } else {
        remote
    };
    match path.strip_prefix("~/") {
        Some(rest) => Some(dirs::home_dir()?.join(rest)),
        None => Some(PathBuf::from(path)),
    }
}

async fn git_init_and_add_origin(work: &Path, remote: &str) -> Result<()> {
    let cmdstr = "git init / git remote add";
    let init = git_cmd(work)
        .arg("init")
        .arg("-b")
        .arg("main")
        .arg(".")
        .output()
        .await
        .map_err(|e| backend_git(&e, cmdstr, remote))?;
    if !init.status.success() {
        return Err(backend_git_output(cmdstr, remote, &init));
    }
    let add = git_cmd(work)
        .arg("remote")
        .arg("add")
        .arg("origin")
        .arg(remote)
        .output()
        .await
        .map_err(|e| backend_git(&e, cmdstr, remote))?;
    if !add.status.success() {
        return Err(backend_git_output(cmdstr, remote, &add));
    }
    Ok(())
}

async fn git_add(work: &Path, path: &str) -> Result<()> {
    let out = git_cmd(work)
        .arg("add")
        .arg("--")
        .arg(path)
        .output()
        .await
        .map_err(|e| backend_git(&e, "git add", path))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(backend_git_output("git add", path, &out))
    }
}

async fn git_commit(work: &Path, msg: &str) -> Result<()> {
    let out = git_cmd(work)
        .arg("commit")
        .arg("-m")
        .arg(msg)
        .output()
        .await
        .map_err(|e| backend_git(&e, "git commit", msg))?;
    if out.status.success() {
        Ok(())
    } else {
        // allow "nothing to commit" as success (idempotent push)
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("nothing to commit") || stderr.contains("no changes") {
            return Ok(());
        }
        Err(backend_git_output("git commit", msg, &out))
    }
}

async fn git_push(work: &Path, branch: &str) -> Result<()> {
    let out = git_cmd(work)
        .arg("push")
        .arg("-u")
        .arg("origin")
        .arg(branch)
        .output()
        .await
        .map_err(|e| backend_git(&e, "git push", branch))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(backend_git_output("git push", branch, &out))
    }
}

fn backend_git(e: &std::io::Error, cmd: &str, ctx: &str) -> Error {
    Error::Sync(crate::sync::SyncError::Backend(SyncBackendError::Git {
        message: format!("{e}"),
        command: format!("{cmd} ({ctx})"),
    }))
}

fn backend_git_output(cmd: &str, ctx: &str, out: &std::process::Output) -> Error {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    Error::Sync(crate::sync::SyncError::Backend(SyncBackendError::Git {
        message: format!(
            "exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
            out.status.code()
        ),
        command: format!("{cmd} ({ctx})"),
    }))
}

#[cfg(test)]
mod real_git_tests {
    //! Real-git tests against local bare repos. These are NOT `#[ignore]`d:
    //! system `git` is available in CI and on every dev machine, and each
    //! test is hermetic (temp dirs). They cover the acceptance flows that
    //! regressed (F4: remote HEAD vs pushed branch; the unrelated-history
    //! fork on non-empty remotes).

    use super::*;

    async fn setup_bare(tmp: &Path) -> PathBuf {
        let bare = tmp.join("remote.git");
        Command::new("git")
            .arg("init")
            .arg("--bare")
            .arg(&bare)
            .output()
            .await
            .unwrap();
        bare
    }

    /// Seed `bare` with an initial `master` branch holding `README`, the way a
    /// pre-existing remote (e.g. a GitHub repo with a README) would look.
    async fn seed_master_branch(tmp: &Path, bare: &Path) {
        let seed = tmp.join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        Command::new("git")
            .args(["init", "-b", "master", "."])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
        std::fs::write(seed.join("README"), "init").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
        Command::new("git")
            .args([
                "-c",
                "user.email=a@b",
                "-c",
                "user.name=a",
                "commit",
                "-m",
                "init",
            ])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
        Command::new("git")
            .args(["remote", "add", "origin", bare.to_str().unwrap()])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
        Command::new("git")
            .args(["push", "-u", "origin", "master"])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
    }

    async fn plain_clone(bare: &Path, dest: &Path) -> std::process::Output {
        Command::new("git")
            .args(["clone", bare.to_str().unwrap(), dest.to_str().unwrap()])
            .output()
            .await
            .unwrap()
    }

    async fn branch_names(bare: &Path) -> Vec<String> {
        let refs = Command::new("git")
            .arg("--git-dir")
            .arg(bare)
            .arg("for-each-ref")
            .arg("--format=%(refname:short)")
            .output()
            .await
            .unwrap();
        String::from_utf8_lossy(&refs.stdout)
            .lines()
            .map(str::to_string)
            .collect()
    }

    #[tokio::test]
    async fn push_pull_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bare = setup_bare(tmp.path()).await;
        let cfg = GitConfig {
            remote: format!("file://{}", bare.display()),
            path: "vault.age".into(),
            branch: "main".into(),
        };
        // First push needs an initial commit on the bare; create via a seed repo.
        let seed = tmp.path().join("seed");
        std::fs::create_dir_all(&seed).unwrap();
        Command::new("git")
            .args(["init", "-b", "main", "."])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
        std::fs::write(seed.join("README"), "init").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
        Command::new("git")
            .args([
                "-c",
                "user.email=a@b",
                "-c",
                "user.name=a",
                "commit",
                "-m",
                "init",
            ])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
        Command::new("git")
            .args([
                "remote",
                "add",
                "origin",
                &format!("file://{}", bare.display()),
            ])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();
        Command::new("git")
            .args(["push", "-u", "origin", "main"])
            .current_dir(&seed)
            .output()
            .await
            .unwrap();

        let be = GitBackend::new(&cfg);
        be.push(b"payload", None).await.unwrap();
        assert!(be.exists().await.unwrap());
        let got = be.pull().await.unwrap();
        assert_eq!(got, b"payload");
    }

    /// Acceptance F1-F4: a bare repo created with `git init --bare` (HEAD
    /// defaults to `master`) plus a first push must let a plain `git clone`
    /// check out the data — the remote HEAD must point at the pushed branch.
    #[tokio::test]
    async fn first_push_seeds_empty_remote_and_heads_it() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bare = setup_bare(tmp.path()).await;
        let cfg = GitConfig {
            remote: bare.display().to_string(),
            path: "vault.age".into(),
            branch: "main".into(),
        };
        let be = GitBackend::new(&cfg);
        be.push(b"payload", None).await.unwrap();

        // The remote HEAD now points at the pushed branch...
        let head = Command::new("git")
            .arg("--git-dir")
            .arg(&bare)
            .arg("symbolic-ref")
            .arg("HEAD")
            .output()
            .await
            .unwrap();
        assert!(head.status.success());
        assert_eq!(
            String::from_utf8_lossy(&head.stdout).trim(),
            "refs/heads/main"
        );

        // ...and a plain `git clone` (no --branch) checks out vault.age.
        let dest = tmp.path().join("check");
        let clone = plain_clone(&bare, &dest).await;
        assert!(
            clone.status.success(),
            "clone stderr: {}",
            String::from_utf8_lossy(&clone.stderr)
        );
        assert_eq!(std::fs::read(dest.join("vault.age")).unwrap(), b"payload");
    }

    /// A remote that already has a `master` branch (seed commit) must be
    /// extended on `master`, not forked into an unrelated `main`.
    #[tokio::test]
    async fn first_push_to_nonempty_remote_adopts_default_branch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bare = setup_bare(tmp.path()).await;
        seed_master_branch(tmp.path(), &bare).await;

        let cfg = GitConfig {
            remote: bare.display().to_string(),
            path: "vault.age".into(),
            branch: "main".into(),
        };
        GitBackend::new(&cfg).push(b"payload", None).await.unwrap();

        // Only one branch exists: the adopted `master` (no `main` fork).
        assert_eq!(branch_names(&bare).await, vec!["master"]);

        // `master` holds both the seed file and the blob.
        let tree_out = Command::new("git")
            .arg("--git-dir")
            .arg(&bare)
            .arg("ls-tree")
            .arg("--name-only")
            .arg("master")
            .output()
            .await
            .unwrap();
        let tree_stdout = String::from_utf8_lossy(&tree_out.stdout);
        let files: Vec<&str> = tree_stdout.lines().collect();
        assert!(files.contains(&"README") && files.contains(&"vault.age"));
    }

    /// A second device whose config still says `main` must still pull from a
    /// master-only remote (default-branch fallback).
    #[tokio::test]
    async fn pull_falls_back_to_remote_default_branch() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bare = setup_bare(tmp.path()).await;
        seed_master_branch(tmp.path(), &bare).await;

        let cfg = GitConfig {
            remote: bare.display().to_string(),
            path: "vault.age".into(),
            branch: "main".into(),
        };
        GitBackend::new(&cfg).push(b"payload", None).await.unwrap();

        // Device 2: same config (branch main) — pull must adopt master too.
        let be = GitBackend::new(&cfg);
        assert!(be.exists().await.unwrap());
        let got = be.pull().await.unwrap();
        assert_eq!(got, b"payload");
    }

    /// Pulling from an empty remote is `RemoteNotFound`, not a clone error.
    #[tokio::test]
    async fn pull_from_empty_remote_is_remote_not_found() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bare = setup_bare(tmp.path()).await;
        let cfg = GitConfig {
            remote: bare.display().to_string(),
            path: "vault.age".into(),
            branch: "main".into(),
        };
        let err = GitBackend::new(&cfg).pull().await.unwrap_err();
        assert!(matches!(
            err,
            Error::Sync(crate::sync::SyncError::Backend(
                SyncBackendError::RemoteNotFound
            ))
        ));
    }

    /// After repeated pushes the remote HEAD must stay stable and a plain
    /// clone must keep seeing the latest payload.
    #[tokio::test]
    async fn repeated_pushes_keep_remote_head_stable() {
        let tmp = tempfile::TempDir::new().unwrap();
        let bare = setup_bare(tmp.path()).await;
        let cfg = GitConfig {
            remote: bare.display().to_string(),
            path: "vault.age".into(),
            branch: "main".into(),
        };
        let be = GitBackend::new(&cfg);
        be.push(b"payload-v1", None).await.unwrap();
        be.push(b"payload-v2", None).await.unwrap();

        let head = String::from_utf8_lossy(
            &Command::new("git")
                .arg("--git-dir")
                .arg(&bare)
                .arg("symbolic-ref")
                .arg("HEAD")
                .output()
                .await
                .unwrap()
                .stdout,
        )
        .trim()
        .to_string();
        assert_eq!(head, "refs/heads/main");

        let dest = tmp.path().join("check");
        let clone = plain_clone(&bare, &dest).await;
        assert!(clone.status.success());
        assert_eq!(
            std::fs::read(dest.join("vault.age")).unwrap(),
            b"payload-v2"
        );
    }

    #[test]
    fn local_remote_path_is_recognized_correctly() {
        // Locally accessible forms resolve to a filesystem path.
        assert_eq!(
            local_remote_path("/tmp/x/vault.git"),
            Some(PathBuf::from("/tmp/x/vault.git"))
        );
        assert_eq!(
            local_remote_path("file:///tmp/x/vault.git"),
            Some(PathBuf::from("/tmp/x/vault.git"))
        );
        assert_eq!(
            local_remote_path("~/vault.git"),
            dirs::home_dir().map(|h| h.join("vault.git"))
        );
        // Remote URLs are not locally accessible.
        assert_eq!(local_remote_path("https://github.com/u/v.git"), None);
        assert_eq!(local_remote_path("ssh://git@host/v.git"), None);
        assert_eq!(local_remote_path("git@host:u/v.git"), None);
    }
}
