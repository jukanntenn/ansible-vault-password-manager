//! TUI test harness: drive `avpm tui` under a pty and assert on the raw byte
//! stream the program emits to the terminal.
//!
//! Why raw bytes (not a terminal emulator)?
//! - The masking guarantee we test is "plaintext never reaches the pty".
//!   The form input widget applies its mask char at render time, so the stream
//!   physically contains `•` (U+2022) and never the secret. Asserting on the
//!   raw stream tests that protocol-layer property directly — a strictly
//!   stronger check than "screen cell N shows •".
//! - A terminal-emulator crate (vt100) was blocked by ratatui's exact
//!   `unicode-width =0.2.0` pin; `vte` remains a future option if a test ever
//!   needs positional precision.
//!
//! Design:
//! - A dedicated **reader thread** blocks on `pty.read` and ships every chunk
//!   to an mpsc channel, so the main thread can drain reliably without missing
//!   short render bursts (the bug that plagued an earlier Python prototype).
//! - `mark()` / `bytes_since()` let a test scope assertions to "what changed
//!   since this action", avoiding false matches against stale cumulative text.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

const COLS: u16 = 100;
const ROWS: u16 = 30;
/// crossterm waits roughly this long to decide a lone ESC is not the start of
/// an Alt+<char> sequence. Sleeping after ESC ensures the TUI reads it as a
/// standalone Escape rather than Alt+<next key>.
const ESC_TIMEOUT: Duration = Duration::from_millis(250);

/// A high-level keystroke so tests don't hand-encode bytes.
#[allow(dead_code)] // Enter/Space used by forthcoming interaction tests.
pub enum Key {
    Char(char),
    Esc,
    Tab,
    Enter,
    Space,
}

pub struct TuiSession {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    writer: Box<dyn Write + Send>,
    rx: mpsc::Receiver<Vec<u8>>,
    /// Every byte the pty has emitted so far.
    raw: Vec<u8>,
}

impl TuiSession {
    /// Spawn `avpm <args>` (typically `["tui"]`) in an isolated 100x30 pty on
    /// the **keyring** backend path.
    ///
    /// `isolated_dir` redirects XDG data/config so the binary never touches the
    /// developer's real `~/.local/share/avpm` / config. HOME is intentionally
    /// NOT overridden: the keyring crate's macOS backend locates the keychain
    /// relative to HOME, so a throwaway HOME makes the keyring unavailable and
    /// `avpm tui` falls back to the file backend. On Linux, XDG_* are honored
    /// by `dirs` and Secret Service is reached via D-Bus (not HOME-relative).
    /// macOS TUI tests on this path therefore use the real keychain/index; they
    /// must be non-destructive (no submit) or clean up unique ids they create.
    #[allow(clippy::needless_pass_by_value)]
    pub fn spawn(args: &[&str], isolated_dir: &Path) -> Self {
        let mut cmd = Self::base_cmd(args);
        cmd.env("XDG_DATA_HOME", isolated_dir.join("data"));
        cmd.env("XDG_CONFIG_HOME", isolated_dir.join("config"));
        Self::spawn_cmd(cmd)
    }

    /// Spawn `avpm tui` on an isolated **file** backend so the TUI starts
    /// cleanly WITHOUT touching the OS keyring.
    ///
    /// This is the deterministic, cross-platform spawn for interaction tests
    /// (add/delete/show/search). HOME is overridden so the keyring is
    /// unreachable, and the master passphrase is supplied via the
    /// `AVPM_MASTER_PASSPHRASE` escape hatch instead of an `rpassword` prompt:
    /// prompting over the pty would manipulate `/dev/tty`'s termios, which
    /// breaks `crossterm`'s subsequent raw-mode init and hangs the TUI. With the
    /// env var there is no prompt, so the TUI enters raw mode and renders
    /// normally. The whole session runs on an encrypted `store.age` under the
    /// isolated data dir — no keychain dialogs, no real data touched.
    ///
    /// portable-pty uses `$HOME` as the child's working directory when no cwd
    /// is set; HOME here points at a deliberately non-existent `home/` subdir
    /// (that non-existence is what makes the OS keyring unreachable). The
    /// explicit cwd keeps spawn working on Linux, where a non-existent
    /// current-directory fails the exec (macOS's posix_spawn tolerates it).
    pub fn spawn_file(isolated_dir: &Path, master_passphrase: &str) -> Self {
        crate::common::write_config(isolated_dir, "[storage]\nbackend = \"file\"\n");
        let mut cmd = Self::base_cmd(&["tui"]);
        cmd.env("XDG_DATA_HOME", isolated_dir.join("data"));
        cmd.env("XDG_CONFIG_HOME", isolated_dir.join("config"));
        cmd.env("HOME", isolated_dir.join("home"));
        cmd.env("AVPM_MASTER_PASSPHRASE", master_passphrase);
        cmd.cwd(isolated_dir);
        let mut s = Self::spawn_cmd(cmd);
        // Wait for the TUI to render its first frame before returning. The
        // crossterm/ratatui init under a pty can take a few seconds to flush the
        // first frame; more importantly, returning only after raw mode is live
        // means the caller's keystrokes are never sitting in the canonical-line
        // buffer when crossterm switches to raw mode (which would flush them).
        if !s.wait_for("Vault Secrets", Duration::from_secs(10)) {
            eprintln!(
                "WARN: TUI did not render its title within 10s; bytes so far:\n{}",
                String::from_utf8_lossy(s.bytes())
            );
        }
        s
    }

    /// Build a CommandBuilder for `avpm <args>` with a capable TERM.
    /// crossterm/ratatui query capabilities by TERM; a missing/dumb value can
    /// degrade rendering (content cells silently not emitted).
    fn base_cmd(args: &[&str]) -> CommandBuilder {
        let avpm: PathBuf = cargo_bin("avpm");
        let mut cmd = CommandBuilder::new(&avpm);
        cmd.args(args);
        cmd.env("TERM", "xterm-256color");
        cmd
    }

    /// Spawn the CommandBuilder in a 100x30 pty and start the reader thread.
    fn spawn_cmd(cmd: CommandBuilder) -> Self {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: ROWS,
                cols: COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");
        let child = pair.slave.spawn_command(cmd).expect("spawn avpm");
        let reader = pair.master.try_clone_reader().expect("clone reader");
        let writer = pair.master.take_writer().expect("take writer");
        // Release the slave so EOF propagates to the reader when the child exits.
        drop(pair.slave);

        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        thread::spawn(move || {
            let mut r = reader;
            let mut buf = [0u8; 8192];
            loop {
                match r.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break; // main thread dropped the receiver
                        }
                    }
                }
            }
        });

        let mut s = TuiSession {
            child,
            writer,
            rx,
            raw: Vec::new(),
        };
        s.drain(Duration::from_secs(2), Duration::from_millis(400));
        s
    }

    /// Pull pending reader chunks into `raw`. Stops after `idle` of silence
    /// or at `timeout` overall (whichever first).
    ///
    /// Note: the reader thread continuously feeds an unbounded channel, so
    /// chunks that arrive between `drain` calls are NOT lost — they queue and
    /// are picked up by the next drain. The `idle` window only decides when a
    /// single drain call returns.
    fn drain(&mut self, timeout: Duration, idle: Duration) {
        let deadline = Instant::now() + timeout;
        loop {
            match self.rx.recv_timeout(idle) {
                Ok(chunk) => self.raw.extend_from_slice(&chunk),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            if Instant::now() >= deadline {
                break;
            }
        }
    }

    /// Wait generously for the TUI to finish rendering after a burst of input.
    /// Use before asserting on `bytes_since`: ratatui's crossterm backend
    /// sometimes emits a cell-content burst (e.g. mask dots) slightly after
    /// the keystroke that triggered it, so a short idle window can miss it.
    pub fn settle(&mut self) {
        self.drain(Duration::from_secs(2), Duration::from_millis(600));
    }

    /// Drain in a loop until `needle` appears in the captured bytes, or `timeout`
    /// elapses. Use to wait for the TUI to render a specific frame (e.g. its
    /// title) before interacting — the first frame can take a few seconds to
    /// flush under a pty, and waiting until it's live avoids sending keystrokes
    /// that raw-mode activation would discard.
    pub fn wait_for(&mut self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            // Short drain windows; the reader thread buffers anything that
            // arrives between calls, so nothing is lost. Match on escape-stripped
            // text so multi-character strings render-diffed cell-by-cell still hit.
            self.drain(Duration::from_millis(600), Duration::from_millis(200));
            if strip_ansi(&self.raw).contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return strip_ansi(&self.raw).contains(needle);
            }
        }
    }

    /// Like [`Self::wait_for`], but only considers bytes received since `mark`.
    /// Essential when the needle (e.g. "Added") already appears earlier in the
    /// cumulative stream from a previous operation — the unscoped `wait_for`
    /// would return instantly on the stale match.
    pub fn wait_for_since(&mut self, mark: usize, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            self.drain(Duration::from_millis(600), Duration::from_millis(200));
            if strip_ansi(&self.raw[mark..]).contains(needle) {
                return true;
            }
            if Instant::now() >= deadline {
                return strip_ansi(&self.raw[mark..]).contains(needle);
            }
        }
    }

    fn write_all(&mut self, b: &[u8]) {
        self.writer.write_all(b).expect("pty write");
        self.writer.flush().ok();
    }

    /// Send a key. ESC is followed by the crossterm escape-timeout gap; all
    /// keys then drain the render response.
    pub fn key(&mut self, k: Key) {
        let bytes: Vec<u8> = match k {
            Key::Char(c) => {
                let mut buf = [0u8; 4];
                c.encode_utf8(&mut buf).as_bytes().to_vec()
            }
            Key::Esc => {
                self.write_all(&[0x1b]);
                thread::sleep(ESC_TIMEOUT);
                self.drain(Duration::from_millis(500), Duration::from_millis(200));
                return;
            }
            Key::Tab => vec![b'\t'],
            Key::Enter => vec![b'\r'],
            Key::Space => vec![b' '],
        };
        self.write_all(&bytes);
        thread::sleep(Duration::from_millis(120));
        self.drain(Duration::from_millis(800), Duration::from_millis(200));
    }

    /// Type a string of (non-ESC) characters in one shot.
    pub fn type_str(&mut self, s: &str) {
        self.write_all(s.as_bytes());
        thread::sleep(Duration::from_millis(150));
        self.drain(Duration::from_secs(1), Duration::from_millis(400));
    }

    /// Current byte offset — pair with [`bytes_since`] to scope an assertion
    /// to "what changed since this point".
    #[must_use]
    pub fn mark(&self) -> usize {
        self.raw.len()
    }

    /// All bytes received since the given mark.
    #[must_use]
    pub fn bytes_since(&self, mark: usize) -> &[u8] {
        &self.raw[mark..]
    }

    /// Every byte received so far.
    #[must_use]
    #[allow(dead_code)] // used by forthcoming tests that assert on full history
    pub fn bytes(&self) -> &[u8] {
        &self.raw
    }

    /// The full captured stream with ANSI escape sequences (CSI cursor moves,
    /// SGR styles, OSC, hide/show cursor) stripped, leaving only the visible
    /// text. Use for substring assertions on rendered words: ratatui's
    /// diff renderer emits each changed cell as `<cursor-move><char><style
    /// resets>`, so a multi-character string like "Added" is **not** contiguous
    /// in the raw stream even when it is on screen. Stripping the escapes
    /// rejoins the visible characters.
    #[must_use]
    pub fn text(&self) -> String {
        strip_ansi(&self.raw)
    }

    /// Visible text since `mark` (escape-stripped). See [`Self::text`].
    #[must_use]
    pub fn text_since(&self, mark: usize) -> String {
        strip_ansi(&self.raw[mark..])
    }

    /// Send `q`, give the TUI a moment to exit cleanly. Anything still alive is
    /// force-killed by [`Drop`].
    pub fn quit(mut self) {
        self.write_all(b"q");
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        // Drop will kill + reap.
    }
}

impl Drop for TuiSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        // Reap so we don't leak a zombie; ignore errors (already exited).
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if self.child.try_wait().ok().flatten().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Strip ANSI escape sequences (CSI, OSC, and lone `ESC x`) from a byte stream,
/// returning only the visible text. ratatui's crossterm backend diff-renders
/// changed cells as `CSI<pos>H<char>CSI<attrs>m`, so rendered words are not
/// contiguous in the raw stream; this rejoins them for substring assertions.
fn strip_ansi(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        // We have an ESC; consume the rest of the sequence.
        match chars.next() {
            Some('[') => {
                // CSI: parameters (0x30-0x3F) + intermediates (0x20-0x2F) +
                // a final byte (0x40-0x7E). Consume through the final byte.
                for nc in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&nc) {
                        break;
                    }
                }
            }
            Some(']') => {
                // OSC: terminated by BEL (\x07) or ST (ESC \).
                while let Some(nc) = chars.next() {
                    if nc == '\x07' {
                        break;
                    }
                    if nc == '\x1b' && chars.next() == Some('\\') {
                        break;
                    }
                }
            }
            Some(_) => {
                // Lone `ESC <char>` (e.g. SS3); the one char was already consumed.
            }
            None => break,
        }
    }
    out
}
