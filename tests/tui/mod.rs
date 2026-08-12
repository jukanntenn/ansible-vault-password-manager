//! TUI integration tests.
//!
//! Drives the real `avpm tui` binary under a pty (via `portable-pty`) and
//! asserts on the raw byte stream. The driver lives in [`harness`].
//!
//! These tests never hang the suite: [`require_tui_or_skip`] probes whether
//! the active backend would let the TUI start cleanly, and the test returns
//! with a `SKIPPED` message otherwise (e.g. headless Linux without a Secret
//! Service daemon, where `avpm tui` would prompt for the master passphrase on
//! the pty and block).

mod harness;
mod interaction;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;

use harness::{Key, TuiSession};

/// Whether `avpm tui` can start without blocking. Callers should `return`
/// early when this returns `false`.
///
/// `avpm tui` startup resolves the store: on a keyring-capable system the
/// read-only probe succeeds and the TUI opens; on a keyring-less system it
/// falls back to the file backend and prompts for the master passphrase on
/// the (tty) pty, which would hang the test.
///
/// The probe runs `avpm --vault-id __tui_gate_probe__` non-interactively:
/// - exit 2 (vault-id not found) ⇒ keyring reachable ⇒ TUI starts clean.
/// - exit 5 (Locked) or a hang ⇒ file backend without cache ⇒ TUI would
///   prompt ⇒ skip.
///
/// The probe reads a guaranteed-nonexistent id (NoEntry) so it never prompts
/// the macOS Keychain and never touches real data.
fn tui_env_ok() -> bool {
    let mut cmd = Command::new(cargo_bin("avpm"));
    cmd.args(["--vault-id", "__tui_gate_probe__"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIPPED: cannot spawn avpm gate probe: {e}");
            return false;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(4);
    let code = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status.code(),
            Ok(None) => {}
            Err(_) => break None,
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            eprintln!("SKIPPED: gate probe hung (TUI would block on master passphrase)");
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    match code {
        Some(2) => true, // keyring reachable — TUI starts clean
        Some(5) | None => {
            eprintln!("SKIPPED: file backend without cached passphrase (exit {code:?})");
            false
        }
        Some(c) => {
            eprintln!("SKIPPED: gate probe unexpected exit {c}");
            false
        }
    }
}

/// T4 — typing into a password field must render mask dots (`•`, U+2022) and
/// must never leak the plaintext to the terminal.
///
/// Asserted on the raw pty byte stream since the typing action: the security
/// property is precisely "plaintext never reaches the pty", because
/// `tui-textarea` applies the mask char at render time and writes only `•`
/// into the cell buffer that crossterm flushes.
#[test]
fn add_form_masks_password_field() {
    if !tui_env_ok() {
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let mut tui = TuiSession::spawn(&["tui"], dir.path());

    // Open the Add form, fill the vault-id, Tab to the password field.
    tui.key(Key::Char('a'));
    tui.type_str("dev");
    tui.key(Key::Tab);

    // Scope the assertion to bytes emitted while typing the password.
    let before = tui.mark();
    tui.type_str("secret123");
    tui.settle();
    let stream = String::from_utf8_lossy(tui.bytes_since(before));

    assert!(
        !stream.contains("secret123"),
        "plaintext password leaked into the pty stream:\n{stream}"
    );
    let mask_dot = "\u{2022}"; // •
    assert!(
        stream.contains(mask_dot),
        "expected mask dot {mask_dot} in the pty stream after typing a password:\n{stream}"
    );

    tui.quit();
}
