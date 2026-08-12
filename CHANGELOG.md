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
- **In-TUI forms**: add / edit / rename use `tui-textarea` popups with masked
  password fields and a `[g] generate` shortcut, instead of dropping to a
  terminal `rpassword` prompt.
- **Toggle password reveal**: Space now toggles show/hide on every terminal
  (the Kitty keyboard-enhancement protocol dependency is removed).

### Dependencies

- `tui-input` replaced by `tui-textarea` (multi-field forms, masked input).
- `ratatui` pinned to 0.29 (aligns with `tui-textarea` 0.7; 0.30 pulls a
  second ratatui copy and the `Widget` impls don't line up).
