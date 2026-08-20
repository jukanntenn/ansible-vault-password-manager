//! gnome-keyring control-socket client — the GUI-free way to create/unlock
//! the login keyring.
//!
//! The Secret Service API's answer to "create/unlock the default collection"
//! is a GUI prompt: the daemon D-Bus-activates `gcr-prompter`, which needs a
//! working display *in the D-Bus activation environment*. WSL2 and headless
//! boxes have no display manager to put one there, so the prompter dies with
//! "cannot open display" and every `CreateCollection` surfaces to callers as
//! an opaque "prompt dismissed".
//!
//! gnome-keyring's own PAM module never uses that path. At every desktop
//! login it talks to the daemon's control socket and sends the login password
//! over a private binary protocol; the daemon then *creates* the login keyring
//! with that password if absent, or *unlocks* it if present
//! (`daemon/login/gkd-login.c: gkd_login_unlock`) — no GUI involved. The
//! `default` Secret Service alias falls back to `login` when no alias file
//! exists (`daemon/dbus/gkd-secret-service.c: update_default`), so the created
//! keyring is immediately the (unlocked) default collection.
//!
//! This module is a Rust port of that client, matching
//! `daemon/control/gkd-control-client.c` and `pam/gkr-pam-client.c`:
//!
//! - socket: `$GNOME_KEYRING_CONTROL/control`, else `$XDG_RUNTIME_DIR/keyring/control`
//! - credentials: one NUL byte (the server reads the peer uid via `SO_PEERCRED`
//!   and rejects other users)
//! - request: `[u32 BE total][u32 BE op=1][u32 BE pw_len][pw bytes]` — egg-buffer
//!   strings are length-prefixed, not NUL-terminated, and `total` counts itself
//! - reply: `[u32 BE total][u32 BE result]` with OK=0, DENIED=1, FAILED=2,
//!   NO_DAEMON=3 (`daemon/control/gkd-control-codes.h`)

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tracing::debug;
use zeroize::Zeroize;

/// Control operation code for UNLOCK (`daemon/control/gkd-control-codes.h`).
const OP_UNLOCK: u32 = 1;

/// Control result codes (`daemon/control/gkd-control-codes.h`).
const RESULT_OK: u32 = 0;
const RESULT_DENIED: u32 = 1;

/// Bound on the reply we are willing to read (the real reply is 8 bytes).
const MAX_REPLY: usize = 1024;

/// How long to wait for the daemon's reply before giving up. The daemon
/// replies inline while handling the request; anything slower is a dead peer.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// Outcome of a control-socket UNLOCK that the daemon actually answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockOutcome {
    /// The login keyring was created (was absent) or unlocked (was locked).
    Unlocked,
    /// The password was rejected — the login keyring exists and stays locked.
    Denied,
}

/// A control-socket UNLOCK could not be performed at all.
#[derive(Debug, thiserror::Error)]
#[error("gnome-keyring control socket unavailable: {0}")]
pub struct Unavailable(pub String);

/// Resolve the control socket path the way gnome-keyring's PAM module does
/// (`pam/gkr-pam-module.c: get_control_file`): an explicit
/// `$GNOME_KEYRING_CONTROL` directory wins, else `$XDG_RUNTIME_DIR/keyring`.
#[must_use]
pub fn control_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("GNOME_KEYRING_CONTROL") {
        return Some(PathBuf::from(dir).join("control"));
    }
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(|dir| PathBuf::from(dir).join("keyring").join("control"))
}

/// Whether a gnome-keyring control socket exists — i.e. the Secret Service
/// provider is gnome-keyring and its collection can be bootstrapped from the
/// terminal, with no GUI dependency.
///
/// Pure path check: no connect, no side effects, no journal noise. The live
/// check happens in [`control_unlock`], which reports [`Unavailable`] if the
/// socket turns out to be dead.
#[must_use]
pub fn control_available() -> bool {
    control_path().is_some_and(|p| p.exists())
}

/// Ask the running gnome-keyring daemon to create-or-unlock the login keyring
/// with `password` — the PAM-login operation.
///
/// Errors with [`Unavailable`] when there is no usable control socket (not
/// gnome-keyring, daemon down, protocol mismatch); callers should fall back
/// to the Secret Service GUI-prompt path then. A wrong password is *not* an
/// error: it comes back as [`UnlockOutcome::Denied`] so the caller can
/// re-prompt.
pub fn control_unlock(password: &str) -> Result<UnlockOutcome, Unavailable> {
    let Some(path) = control_path() else {
        return Err(Unavailable(
            "neither GNOME_KEYRING_CONTROL nor XDG_RUNTIME_DIR is set".into(),
        ));
    };
    control_unlock_at(&path, password)
}

/// The testable core of [`control_unlock`], against an explicit socket path.
fn control_unlock_at(path: &Path, password: &str) -> Result<UnlockOutcome, Unavailable> {
    control_unlock_with_timeout(path, password, REPLY_TIMEOUT)
}

/// The protocol core with an injectable reply timeout (tests drive it down;
/// production uses [`REPLY_TIMEOUT`]).
fn control_unlock_with_timeout(
    path: &Path,
    password: &str,
    timeout: Duration,
) -> Result<UnlockOutcome, Unavailable> {
    if password.as_bytes().contains(&0) {
        // The daemon treats egg-buffer strings as C strings; a NUL would
        // silently truncate the password on its side.
        return Err(Unavailable("password contains a NUL byte".into()));
    }
    let mut stream = UnixStream::connect(path)
        .map_err(|e| Unavailable(format!("could not connect to {}: {e}", path.display())))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| Unavailable(format!("could not set a reply timeout: {e}")))?;

    // The credentials byte: the server reads one byte and simultaneously picks
    // up the peer uid via SO_PEERCRED, rejecting connections from other users.
    stream
        .write_all(&[0])
        .map_err(|e| Unavailable(format!("could not send credentials byte: {e}")))?;

    let mut packet = encode_unlock(password.as_bytes());
    let sent = stream.write_all(&packet);
    packet.zeroize();
    sent.map_err(|e| Unavailable(format!("could not send unlock request: {e}")))?;

    // Reply: [u32 BE total][u32 BE result]. `total` counts itself; a result at
    // offset 4 means the smallest sane reply is 8 bytes.
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| Unavailable(format!("could not read reply length: {e}")))?;
    let total = u32::from_be_bytes(len_buf) as usize;
    if !(8..=MAX_REPLY).contains(&total) {
        return Err(Unavailable(format!("nonsense reply length: {total}")));
    }
    let mut rest = vec![0u8; total - 4];
    stream
        .read_exact(&mut rest)
        .map_err(|e| Unavailable(format!("could not read reply body: {e}")))?;
    let result = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    debug!(result, "gnome-keyring control unlock replied");

    match result {
        RESULT_OK => Ok(UnlockOutcome::Unlocked),
        RESULT_DENIED => Ok(UnlockOutcome::Denied),
        code => Err(Unavailable(format!(
            "control result code {code} (daemon refused or failed)"
        ))),
    }
}

/// Encode an UNLOCK request (see the module docs for the wire format).
fn encode_unlock(password: &[u8]) -> Vec<u8> {
    let total = 12 + password.len();
    let mut packet = Vec::with_capacity(total);
    packet.extend_from_slice(&(total as u32).to_be_bytes());
    packet.extend_from_slice(&OP_UNLOCK.to_be_bytes());
    packet.extend_from_slice(&(password.len() as u32).to_be_bytes());
    packet.extend_from_slice(password);
    packet
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;

    use super::*;

    /// What the mock daemon observed, for request-side assertions.
    #[derive(Debug)]
    struct Observed {
        credentials_byte: u8,
        op: u32,
        password: String,
    }

    /// A mock gnome-keyring control daemon bound at `dir/control` that
    /// replies `result` to exactly one request. Returns a channel carrying
    /// what it observed, so tests assert on the request bytes too.
    fn mock_daemon(dir: &tempfile::TempDir, result: u32) -> mpsc::Receiver<Observed> {
        let listener = UnixListener::bind(dir.path().join("control")).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut cred = [0u8; 1];
            stream.read_exact(&mut cred).unwrap();
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total - 4];
            stream.read_exact(&mut body).unwrap();
            let op = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
            let pw_len = u32::from_be_bytes([body[4], body[5], body[6], body[7]]) as usize;
            let password = String::from_utf8(body[8..8 + pw_len].to_vec()).unwrap();
            let mut reply = Vec::with_capacity(8);
            reply.extend_from_slice(&8u32.to_be_bytes());
            reply.extend_from_slice(&result.to_be_bytes());
            stream.write_all(&reply).unwrap();
            tx.send(Observed {
                credentials_byte: cred[0],
                op,
                password,
            })
            .unwrap();
        });
        rx
    }

    #[test]
    fn unlock_ok_sends_the_pam_wire_format() {
        let dir = tempfile::tempdir().unwrap();
        let observed = mock_daemon(&dir, RESULT_OK);
        let outcome = control_unlock_at(&dir.path().join("control"), "s3cret").unwrap();
        assert_eq!(outcome, UnlockOutcome::Unlocked);
        let seen = observed.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(seen.credentials_byte, 0);
        assert_eq!(seen.op, OP_UNLOCK);
        assert_eq!(seen.password, "s3cret");
    }

    #[test]
    fn unlock_denied_is_an_outcome_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let observed = mock_daemon(&dir, RESULT_DENIED);
        let outcome = control_unlock_at(&dir.path().join("control"), "wrong").unwrap();
        assert_eq!(outcome, UnlockOutcome::Denied);
        assert_eq!(
            observed
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .password,
            "wrong"
        );
    }

    #[test]
    fn nonsense_reply_length_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("control")).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut cred = [0u8; 1];
            stream.read_exact(&mut cred).unwrap();
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total - 4];
            stream.read_exact(&mut body).unwrap();
            // A reply whose total (4) cannot contain a result u32 at offset 4.
            stream.write_all(&4u32.to_be_bytes()).unwrap();
        });
        let err = control_unlock_at(&dir.path().join("control"), "pw").unwrap_err();
        assert!(err.0.contains("nonsense reply length"), "got: {err}");
    }

    #[test]
    fn refused_result_code_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let observed = mock_daemon(&dir, 2); // FAILED
        let err = control_unlock_at(&dir.path().join("control"), "pw").unwrap_err();
        assert!(err.0.contains("result code 2"), "got: {err}");
        drop(observed.recv_timeout(Duration::from_secs(5)).unwrap());
    }

    #[test]
    fn no_socket_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let err = control_unlock_at(&dir.path().join("control"), "pw").unwrap_err();
        assert!(err.0.contains("could not connect"), "got: {err}");
    }

    #[test]
    fn nul_in_password_is_rejected_before_any_io() {
        let dir = tempfile::tempdir().unwrap();
        let err = control_unlock_at(&dir.path().join("nonexistent"), "a\0b").unwrap_err();
        assert!(err.0.contains("NUL"), "got: {err}");
    }

    #[test]
    fn control_unlock_without_any_env_is_unavailable() {
        let saved = (
            std::env::var_os("GNOME_KEYRING_CONTROL"),
            std::env::var_os("XDG_RUNTIME_DIR"),
        );
        std::env::remove_var("GNOME_KEYRING_CONTROL");
        std::env::remove_var("XDG_RUNTIME_DIR");
        let err = control_unlock("pw").unwrap_err();
        assert!(err.0.contains("neither"), "got: {err}");
        let (saved_control, saved_runtime) = saved;
        match saved_control {
            Some(v) => std::env::set_var("GNOME_KEYRING_CONTROL", v),
            None => std::env::remove_var("GNOME_KEYRING_CONTROL"),
        }
        match saved_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    /// The public entry resolves the socket via `GNOME_KEYRING_CONTROL` —
    /// the seam a private test daemon uses, and the override a manually
    /// spawned gnome-keyring would export.
    #[test]
    fn control_unlock_resolves_the_socket_from_env() {
        let dir = tempfile::tempdir().unwrap();
        let observed = mock_daemon(&dir, RESULT_OK);
        let saved = std::env::var_os("GNOME_KEYRING_CONTROL");
        std::env::set_var("GNOME_KEYRING_CONTROL", dir.path().as_os_str());

        let outcome = control_unlock("env-pw").unwrap();

        match saved {
            Some(v) => std::env::set_var("GNOME_KEYRING_CONTROL", v),
            None => std::env::remove_var("GNOME_KEYRING_CONTROL"),
        }
        assert_eq!(outcome, UnlockOutcome::Unlocked);
        let seen = observed.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(seen.password, "env-pw");
    }

    #[test]
    fn absurd_reply_length_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("control")).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut cred = [0u8; 1];
            stream.read_exact(&mut cred).unwrap();
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total - 4];
            stream.read_exact(&mut body).unwrap();
            // A reply claiming u32::MAX bytes: the guard must reject before
            // any allocation.
            stream.write_all(&u32::MAX.to_be_bytes()).unwrap();
        });
        let err = control_unlock_at(&dir.path().join("control"), "pw").unwrap_err();
        assert!(err.0.contains("nonsense reply length"), "got: {err}");
    }

    /// A daemon that accepts the request but never replies must not hang avpm
    /// forever — the read timeout turns it into `Unavailable` (the caller
    /// falls back to the GUI path).
    #[test]
    fn hung_daemon_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let listener = UnixListener::bind(dir.path().join("control")).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut cred = [0u8; 1];
            stream.read_exact(&mut cred).unwrap();
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total - 4];
            stream.read_exact(&mut body).unwrap();
            // Swallow the request, never reply; hold the stream open.
            std::thread::sleep(Duration::from_secs(30));
        });
        let started = std::time::Instant::now();
        let err = control_unlock_with_timeout(
            &dir.path().join("control"),
            "pw",
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "timed out too slowly"
        );
        assert!(
            err.0.contains("reply"),
            "expected a reply-read failure, got: {err}"
        );
    }

    #[test]
    fn encode_unlock_matches_egg_buffer_layout() {
        // Golden bytes derived from egg-buffer: big-endian, length-prefixed
        // string, total counts itself. `abc` → total 15, op 1, len 3.
        assert_eq!(
            encode_unlock(b"abc"),
            [0, 0, 0, 15, 0, 0, 0, 1, 0, 0, 0, 3, b'a', b'b', b'c']
        );
        // Empty password is a valid packet (12 bytes, len 0).
        assert_eq!(encode_unlock(b""), [0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0]);
    }

    /// Path resolution mirrors the PAM module: GNOME_KEYRING_CONTROL wins,
    /// else XDG_RUNTIME_DIR/keyring. Env save/restore follows the same
    /// pattern as the `gui_available` test in `ss.rs`.
    #[test]
    fn control_path_resolution() {
        let saved = (
            std::env::var_os("GNOME_KEYRING_CONTROL"),
            std::env::var_os("XDG_RUNTIME_DIR"),
        );
        std::env::remove_var("GNOME_KEYRING_CONTROL");
        std::env::remove_var("XDG_RUNTIME_DIR");
        assert_eq!(control_path(), None);

        std::env::set_var("XDG_RUNTIME_DIR", "/run/user/1000");
        assert_eq!(
            control_path(),
            Some(PathBuf::from("/run/user/1000/keyring/control"))
        );

        std::env::set_var("GNOME_KEYRING_CONTROL", "/tmp/custom-keyring");
        assert_eq!(
            control_path(),
            Some(PathBuf::from("/tmp/custom-keyring/control"))
        );

        let (saved_control, saved_runtime) = saved;
        match saved_control {
            Some(v) => std::env::set_var("GNOME_KEYRING_CONTROL", v),
            None => std::env::remove_var("GNOME_KEYRING_CONTROL"),
        }
        match saved_runtime {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    /// `control_available` is a pure path-existence check.
    #[test]
    fn control_available_reflects_socket_existence() {
        let dir = tempfile::tempdir().unwrap();
        let saved = std::env::var_os("GNOME_KEYRING_CONTROL");
        std::env::set_var("GNOME_KEYRING_CONTROL", dir.path().as_os_str());
        assert!(!control_available());

        UnixListener::bind(dir.path().join("control")).unwrap();
        assert!(control_available());

        match saved {
            Some(v) => std::env::set_var("GNOME_KEYRING_CONTROL", v),
            None => std::env::remove_var("GNOME_KEYRING_CONTROL"),
        }
    }
}
