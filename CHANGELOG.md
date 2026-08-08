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
