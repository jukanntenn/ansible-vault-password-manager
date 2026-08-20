# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial release of **avpm** — a minimal system-keyring adapter for Ansible
Vault passwords, with end-to-end encrypted multi-device sync.

### Highlights

- **Drop-in for Ansible** — serves vault passwords via the standard
  vault-password-client protocol (`avpm --vault-id <id>`); pure stdout, no
  noise.
- **Secure by design** — OS-native keyring storage (macOS Keychain / Linux
  Secret Service), an age-encrypted file-store fallback for keyring-less
  environments (headless WSL2), `#![forbid(unsafe_code)]`, and zeroized
  password memory.
- **End-to-end encrypted sync** — age-encrypted (scrypt + ChaCha20-Poly1305)
  manifests synced over Git or WebDAV, with timestamp-based merging and
  interactive conflict resolution.
- **Full-featured CLI + TUI** — `set`/`get`/`list`/`show`/`rename`/`rm`,
  password generation, a full-screen TUI, and interactive config setup.
- **One-liner install** — `cargo install --git https://github.com/jukanntenn/ansible-vault-password-manager --locked`.

### Changed (WSL2 keyring bootstrap)

- **Terminal keyring bootstrap (no GUI)**: `avpm unlock` now prompts for the
  OS keyring password in the terminal and drives gnome-keyring's control
  socket — the same PAM-login mechanism a desktop uses at login — to create
  the default collection (if absent) or unlock it (if locked, up to three
  attempts on a wrong password). This works on WSL2 and pure headless boxes,
  fixing the opaque `SS error: prompt dismissed` dead end (root cause: the
  D-Bus-activated `gcr-prompter` inherits a bus environment without `DISPLAY`,
  so no dialog can appear). Providers without a control socket (KeePassXC,
  KWallet) keep the one-time GUI prompt, now preceded by a best-effort
  `org.freedesktop.DBus.UpdateActivationEnvironment` repair that exports
  `DISPLAY`/`WAYLAND_DISPLAY` into the bus activation environment.
- **`Auto` picks the keyring on headless gnome-keyring boxes**: an absent
  default collection no longer requires a GUI to be creatable — a gnome-keyring
  control socket is enough, so headless WSL2 resolves to the keyring backend
  instead of the file backend.
- **TUI prompts before the alternate screen**: `avpm tui` readies the keyring
  (terminal prompt if needed) before opening the TUI, so a password prompt can
  never garble the full-screen interface mid-session.

### Changed (architecture rebuild)

- **Dual binaries**: `avpm` (manager) + **`avpm-client`** (Ansible entry point).
  Ansible only passes `--vault-id` to scripts named `*-client` (its
  `script_is_client` detection), so a dedicated `avpm-client` binary is now
  required for the vault-password-client protocol. **Breaking**: Ansible
  integration must point at `avpm-client`, not `avpm`.
- **`AVPM_MASTER_PASSPHRASE` escape hatch**: when set, the file backend uses
  this master passphrase directly — no keyring lookup, no interactive prompt.
  Intended for non-interactive / CI use (where stdin is not a TTY and nothing
  is cached) on keyring-less systems. Takes precedence over the keyring cache
  and the `rpassword` prompt.
- **Smart `unlock`**: on a keyring-capable system (macOS/desktop Linux),
  `avpm unlock` is now a no-op that prints an informational message and
  creates no files. On keyring-less systems (headless WSL2) it initializes the
  file store as before. Previously, `unlock` always created `store.age`, which
  locked macOS users out of the keyring permanently.
- **Pure probe-driven `Auto` backend**: the `store.age exists ⇒ use file`
  heuristic is removed. The `Auto` backend now does a read-only keyring lookup
  to decide availability — no side effects, no macOS Keychain auth prompts.
- **TUI rebuilt around an inline store**: the `App` now owns the store, so
  copy / show / delete / add / edit / rename all execute inside the event
  loop. The terminal no longer tears down to the raw shell mid-operation
  (the `PendingAction` queue and outer rebuild loop are gone).
- **In-TUI forms**: add / edit / rename use in-tree input-widget popups with
  masked password fields and a `[g] generate` shortcut, instead of dropping to
  a terminal `rpassword` prompt.
- **Toggle password reveal**: Space now toggles show/hide on every terminal
  (the Kitty keyboard-enhancement protocol dependency is removed).

### Dependencies

- `tui-input` / `tui-textarea` replaced by an in-tree single-line input
  widget (`src/tui/input.rs`, masked fields with full cursor editing).
- `ratatui` bumped to 0.30 (drops the unmaintained `paste` proc-macro,
  RUSTSEC-2024-0436; `tui-textarea` 0.7 only supports ratatui 0.29).
