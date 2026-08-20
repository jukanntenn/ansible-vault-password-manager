//! End-to-end acceptance through the real `avpm` binary.
//!
//! Three kinds of coverage:
//!
//! 1. **Deterministic locked path** (no daemon needed): with the file backend
//!    forced and no cached passphrase, non-interactive calls must exit 5 with
//!    the `run avpm unlock` hint.
//! 2. **Full acceptance flow** (needs a Secret Service session collection —
//!    headless WSL2 qualifies; skipped with a message otherwise): seed the
//!    real cache, then run the real binary through set → sync push → plain
//!    `git clone` sees `vault.age` (F4) → second device pull/list/status →
//!    non-interactive `get` (ansible contract). The cache is snapshotted and
//!    restored so a dev's active unlock is never clobbered.
//! 3. **Interactive `avpm unlock`** (needs the util-linux `script` pty
//!    wrapper; BSD/macOS `script` does not forward piped stdin the same way,
//!    so this case is Linux-only).
//! 4. **Interactive keyring bootstrap** (also pty-based, `#[ignore]`d because
//!    it creates the *real* login keyring): `avpm unlock` with an absent
//!    default collection and a gnome-keyring control socket prompts for the
//!    keyring password in the terminal — no GUI.

use std::path::Path;
use std::process::Command as StdCommand;

use assert_cmd::prelude::*;

#[cfg(target_os = "linux")]
use crate::common::default_collection_is_ready;
#[cfg(target_os = "linux")]
use crate::common::script_available;
use crate::common::{
    avpm, cache_test_lock, isolate, restore_cache, seed_cache, snapshot_cache, write_config,
};

const MASTER_PW: &str = "master123";
const BARE_GIT_CONFIG: &str = r#"
[sync]
backend = "git"
[sync.git]
remote = "{remote}"
"#;

fn bare_repo(dir: &Path) -> std::path::PathBuf {
    let bare = dir.join("vault.git");
    std::process::Command::new("git")
        .arg("init")
        .arg("--bare")
        .arg(&bare)
        .output()
        .unwrap();
    bare
}

/// Run `avpm` with isolated XDG dirs in one call.
trait PipeCmd {
    fn pipe_cmd(&mut self, dir: &Path) -> &mut Self;
}

impl PipeCmd for StdCommand {
    fn pipe_cmd(&mut self, dir: &Path) -> &mut Self {
        isolate(self, dir);
        self
    }
}

// ---------------------------------------------------------------------------
// 1. Deterministic locked path (exit 5) — no daemon required.
// ---------------------------------------------------------------------------

#[test]
fn non_interactive_get_is_locked_without_cache() {
    let _guard = cache_test_lock();
    let previous = snapshot_cache();
    restore_cache(None); // guarantee the "no cache" precondition
    let tmp = tempfile::TempDir::new().unwrap();
    write_config(tmp.path(), "[storage]\nbackend = \"file\"\n");
    avpm()
        .arg("get")
        .arg("dev")
        .pipe_cmd(tmp.path())
        .assert()
        .code(5)
        .stderr(predicates::str::contains("master passphrase not cached"))
        .stderr(predicates::str::contains("run `avpm unlock`"));
    restore_cache(previous);
}

#[test]
fn non_interactive_sync_push_is_locked_without_cache() {
    let _guard = cache_test_lock();
    let previous = snapshot_cache();
    restore_cache(None);
    let tmp = tempfile::TempDir::new().unwrap();
    let bare = bare_repo(tmp.path());
    write_config(
        tmp.path(),
        &format!(
            "[storage]\nbackend = \"file\"\n{}",
            BARE_GIT_CONFIG.replace("{remote}", &bare.display().to_string())
        ),
    );
    avpm()
        .arg("sync")
        .arg("push")
        .arg("-m")
        .arg("locked")
        .pipe_cmd(tmp.path())
        .assert()
        .code(5)
        .stderr(predicates::str::contains("master passphrase not cached"));
    restore_cache(previous);
}

// ---------------------------------------------------------------------------
// 2. Full acceptance flow — real Secret Service session collection required.
// ---------------------------------------------------------------------------

/// `avpm set <id> -g` then return the generated password via `avpm get <id>`.
fn set_and_get(dir: &Path, id: &str) -> String {
    avpm()
        .arg("set")
        .arg(id)
        .arg("-g")
        .pipe_cmd(dir)
        .assert()
        .success();
    let out = avpm().arg("get").arg(id).pipe_cmd(dir).output().unwrap();
    assert!(
        out.status.success(),
        "get {id} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn acceptance_flow_set_push_clone_pull_status() {
    let _guard = cache_test_lock();
    let previous = snapshot_cache();
    if !seed_cache(MASTER_PW) {
        eprintln!("SKIPPED: no Secret Service daemon on the session bus");
        return;
    }

    let tmp = tempfile::TempDir::new().unwrap();
    let bare = bare_repo(tmp.path());

    // Device 1: three vaults, then push. Force the file backend so the flow is
    // deterministic regardless of keyring state — on a GUI box with no default
    // collection, `Auto` would otherwise pick the keyring and a non-interactive
    // `set -g` would exit 6 instead of succeeding.
    let dev1 = tempfile::TempDir::new().unwrap();
    write_config(
        dev1.path(),
        &format!(
            "[storage]\nbackend = \"file\"\n{}",
            BARE_GIT_CONFIG.replace("{remote}", &bare.display().to_string())
        ),
    );
    let dev_pw = set_and_get(dev1.path(), "dev");
    let prod_pw = set_and_get(dev1.path(), "prod");
    let _staging_pw = set_and_get(dev1.path(), "staging");

    let push = avpm()
        .arg("sync")
        .arg("push")
        .arg("-m")
        .arg("initial backup")
        .pipe_cmd(dev1.path())
        .output()
        .unwrap();
    assert!(
        push.status.success(),
        "push failed: {}",
        String::from_utf8_lossy(&push.stderr)
    );
    let push_stdout = String::from_utf8_lossy(&push.stdout);
    assert!(
        push_stdout.contains("Pushed 3 vault(s)"),
        "unexpected push output: {push_stdout}"
    );

    // F4: remote HEAD points at the pushed branch and a plain `git clone`
    // checks out the age-armored vault.age.
    let head = String::from_utf8_lossy(
        &std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&bare)
            .arg("symbolic-ref")
            .arg("HEAD")
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    assert_eq!(head, "refs/heads/main");

    let check = tmp.path().join("check");
    let clone = std::process::Command::new("git")
        .args(["clone", bare.to_str().unwrap(), check.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        clone.status.success(),
        "clone stderr: {}",
        String::from_utf8_lossy(&clone.stderr)
    );
    let blob = std::fs::read_to_string(check.join("vault.age")).unwrap();
    assert!(blob.starts_with("-----BEGIN AGE ENCRYPTED FILE-----"));

    // F5: a second device (fresh XDG dirs) pulls everything back.
    let dev2 = tempfile::TempDir::new().unwrap();
    write_config(
        dev2.path(),
        &format!(
            "[storage]\nbackend = \"file\"\n{}",
            BARE_GIT_CONFIG.replace("{remote}", &bare.display().to_string())
        ),
    );
    let pull = avpm()
        .arg("sync")
        .arg("pull")
        .pipe_cmd(dev2.path())
        .output()
        .unwrap();
    assert!(
        pull.status.success(),
        "pull failed: {}",
        String::from_utf8_lossy(&pull.stderr)
    );

    let list = avpm().arg("list").pipe_cmd(dev2.path()).output().unwrap();
    assert!(list.status.success());
    let list_stdout = String::from_utf8_lossy(&list.stdout);
    for id in ["dev", "prod", "staging"] {
        assert!(list_stdout.contains(id), "list missing {id}: {list_stdout}");
    }

    // F6: status reports no differences. The label is column-aligned in
    // sync_cmd.rs ("unchanged" + 4 spaces + ":"), so match that exact format.
    let status = avpm()
        .arg("sync")
        .arg("status")
        .pipe_cmd(dev2.path())
        .output()
        .unwrap();
    assert!(status.status.success());
    let status_stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        status_stdout.contains("unchanged    : 3"),
        "unexpected status: {status_stdout}"
    );

    // Non-interactive `avpm get` (ansible contract) reads the cache and
    // returns the exact passwords.
    for (id, expected) in [("dev", &dev_pw), ("prod", &prod_pw)] {
        let out = avpm()
            .arg("get")
            .arg(id)
            .pipe_cmd(dev2.path())
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim(),
            expected.as_str()
        );
    }

    restore_cache(previous);
}

// ---------------------------------------------------------------------------
// 3. Interactive `avpm unlock` — pty wrapper required.
// ---------------------------------------------------------------------------

/// Run `cmd` under the util-linux `script` pty wrapper, feeding `input` on
/// stdin. The command goes through `-c` (a single shell string): util-linux
/// ≥ 2.39 rejects extra positional arguments after the typescript file, and
/// BSD `script` accepts `-c` too. Linux-only: BSD/macOS `script` does not
/// forward piped stdin the way this flow needs.
#[cfg(target_os = "linux")]
fn script_pipe(cmd: &mut StdCommand, input: &str) -> std::process::Output {
    use std::io::Write;
    use std::process::Stdio;

    fn shell_quote(s: &str) -> String {
        if s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        {
            s.to_string()
        } else {
            format!("'{}'", s.replace('\'', "'\\''"))
        }
    }

    let command_line = std::iter::once(shell_quote(&cmd.get_program().to_string_lossy()))
        .chain(cmd.get_args().map(|a| shell_quote(&a.to_string_lossy())))
        .collect::<Vec<_>>()
        .join(" ");

    let mut script = StdCommand::new("script");
    script
        .args(["-q", "-c", &command_line, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in cmd.get_envs().filter_map(|(k, v)| v.map(|v| (k, v))) {
        script.env(k, v);
    }
    let mut child = script.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

/// Interactive `avpm unlock` over a pty (util-linux `script`). Linux-only:
/// BSD `script` doesn't forward piped stdin, and the flow is the headless
/// WSL2 story anyway.
///
/// Forces the file backend (`backend = "file"`) so the unlock flow is
/// deterministic regardless of whether a Secret Service daemon is present
/// (with the new smart unlock, a reachable keyring would make `unlock` a
/// no-op).
#[cfg(target_os = "linux")]
#[test]
fn unlock_interactive_flow() {
    let _guard = cache_test_lock();
    if !script_available() {
        eprintln!("SKIPPED: `script` pty wrapper not available");
        return;
    }
    let previous = snapshot_cache();

    let dev = tempfile::TempDir::new().unwrap();
    write_config(dev.path(), "[storage]\nbackend = \"file\"\n");
    let mut cmd = avpm();
    cmd.arg("unlock");
    isolate(&mut cmd, dev.path());

    // A1: first run sets the master passphrase with confirmation.
    let first = script_pipe(&mut cmd, "master123\nmaster123\n");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        combined.contains("Set master passphrase:"),
        "expected first-run prompt, got: {combined}"
    );
    assert!(
        combined.contains("unlocked (master passphrase cached for this session)"),
        "expected unlock message, got: {combined}"
    );
    assert!(
        !combined.contains("could not be cached"),
        "unexpected cache warning: {combined}"
    );

    // A2: a real `set` births store.age (the cached passphrase makes it
    // non-interactive) — unlock never creates the file itself, by design.
    let mut set_cmd = avpm();
    set_cmd.args(["set", "dev", "-g"]);
    isolate(&mut set_cmd, dev.path());
    let set_out = set_cmd.output().unwrap();
    assert!(
        set_out.status.success(),
        "set should succeed via the cached passphrase: {set_out:?}"
    );

    // A3: second run verifies against the now-existing store.
    let second = script_pipe(&mut cmd, "master123\n");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(
        combined.contains("Master passphrase:") && combined.contains("unlocked"),
        "expected verify prompt + unlock, got: {combined}"
    );

    restore_cache(previous);
}

/// Interactive keyring bootstrap over a pty: with the default collection
/// absent and a gnome-keyring control socket present (a fresh WSL2/headless
/// box), `avpm unlock` prompts for the keyring password **in the terminal**
/// (no GUI) and creates the login keyring — the fix for the "prompt
/// dismissed" dead end.
///
/// `#[ignore]`d because it creates the user's *real* login keyring with the
/// password fed here. Run manually on a box whose default collection is
/// absent (a fresh WSL2 works well):
///
/// ```sh
/// cargo test --test integration keyring_bootstrap_interactive -- --ignored
/// ```
///
/// Afterwards the keyring password is `boot-123`; delete
/// `~/.local/share/keyrings/login.keyring` (and restart the daemon) to reset.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "creates the real login keyring (terminal prompt); run on a box whose default collection is absent"]
fn keyring_bootstrap_interactive() {
    if !script_available() {
        eprintln!("SKIPPED: `script` pty wrapper not available");
        return;
    }
    if !avpm::vault::gkr::control_available() {
        eprintln!("SKIPPED: no gnome-keyring control socket");
        return;
    }
    if default_collection_is_ready() {
        eprintln!("SKIPPED: default collection already ready (bootstrap would be a no-op)");
        return;
    }

    let dev = tempfile::TempDir::new().unwrap();
    let mut cmd = avpm();
    cmd.arg("unlock");
    isolate(&mut cmd, dev.path());

    // Feed the retry ladder: an empty password, then a mismatched pair, then
    // a matching pair — one run exercises the full prompt loop.
    let out = script_pipe(&mut cmd, "\nmismatch1\nboot-123\nboot-123\nboot-123\n");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("Set OS keyring password:"),
        "expected the terminal keyring-password prompt, got: {combined}"
    );
    assert!(
        combined.contains("must not be empty"),
        "expected the empty-password retry, got: {combined}"
    );
    assert!(
        combined.contains("passwords do not match"),
        "expected the mismatch retry, got: {combined}"
    );
    assert!(
        combined.contains("keyring backend ready"),
        "expected the ready message, got: {combined}"
    );
}
