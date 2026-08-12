# avpm — Ansible Vault Password Manager

> **English** | [中文](README_zh.md)

[![CI](https://img.shields.io/github/actions/workflow/status/jukanntenn/ansible-vault-password-manager/ci.yml?branch=main)](https://github.com/jukanntenn/ansible-vault-password-manager/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

A **minimal system-keyring adapter** for Ansible Vault passwords, with
**end-to-end encrypted multi-device sync** as a first-class feature.

avpm stores each Vault password in the OS-native keyring (macOS Keychain /
Linux Secret Service) and serves it to Ansible via the [vault password client
script][ansible-vault] protocol. It can also sync your vault-ids across
machines using age-encrypted manifests over Git or WebDAV backends.

[ansible-vault]: https://docs.ansible.com/ansible/latest/user_guide/vault.html#providing-vault-passwords

## Features

- **Drop-in for Ansible** — ships `avpm-client`, the standard vault-password-client
  script (`avpm-client --vault-id <id>`); pure stdout, nothing else, safe to pipe.
- **Zero-config start** — `set`/`get`/`list`/`rm` work out of the box, no
  config file required.
- **Secure by design** — passwords live in the OS keyring (macOS Keychain /
  Linux Secret Service) or an age-encrypted file store; `#![forbid(unsafe_code)]`,
  `deny(unwrap_used, expect_used)`, zeroized password memory.
- **End-to-end encrypted sync** — age-encrypted (scrypt + ChaCha20-Poly1305)
  manifests pushed/pulled over **Git or WebDAV**, with timestamp-based merging
  and interactive conflict resolution.
- **CLI + TUI, one binary** — password generation (`-g -L 40`), a secure
  hold-Space-to-reveal view, and a full-screen interactive manager.
- **Observable** — structured `tracing` logs on stderr (stdout stays pure);
  passwords are never logged.

## Supported platforms

| Platform | Keyring backend |
|---|---|
| Linux (incl. WSL2) | Secret Service (GNOME Keyring / KWallet) via `keyring` v1's zbus backend |
| macOS | Keychain Services via `keyring` v1's apple-native backend |
| Windows | **Not supported** (Ansible itself doesn't run on Windows) |

For WSL2 / headless Linux, see the [WSL2 setup](#wsl2--headless-linux-setup)
section below.

## WSL2 / Headless Linux setup

On WSL2 and other headless Linux systems without a desktop environment, the
Secret Service daemon (`gnome-keyring`) is usually not installed. Without it,
avpm falls back to the encrypted file store and **cannot cache** the master
passphrase across processes — meaning you'll be re-prompted every time, and
Ansible's non-interactive calls (`avpm --vault-id <id>`) will fail with exit
code 5.

To fix this, install and enable the Secret Service daemon:

```bash
# 1. Install the packages (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y gnome-keyring dbus-x11 libsecret-tools

# 2. Enable systemd in WSL2 — add to /etc/wsl.conf:
#    [boot]
#    systemd=true
# Then from Windows PowerShell:  wsl --shutdown   (and reopen WSL)

# 3. Verify
gdbus call --session \
  --dest org.freedesktop.DBus \
  --object-path /org/freedesktop/DBus \
  --method org.freedesktop.DBus.ListActivatableNames \
  | tr ',' '\n' | grep secret
# expected: 'org.freedesktop.secrets'
```

Once the daemon is reachable, `avpm unlock` caches the master passphrase in
the session collection (non-persistent, no GUI required) and subsequent
`avpm` calls — including Ansible's `avpm --vault-id <id>` — work without
prompting.

See [`docs/troubleshooting.md`](docs/troubleshooting.md) for full diagnostics,
the session cache explanation, and alternative headless workarounds.

## Install

**Requires Rust ≥ 1.88** ([rustup](https://rustup.rs) recommended: `rustup update stable`).

```bash
cargo install --git https://github.com/jukanntenn/ansible-vault-password-manager --locked
```

## Build

```bash
cargo build --release
# the binary is at target/release/avpm
```

## Usage

```bash
# Core CRUD (no config file needed)
avpm set dev               # interactively set the password for vault-id 'dev'
avpm set dev -g -L 40      # generate a 40-char password instead
avpm get dev               # print the password to stdout (single line)
avpm list                  # list known vault-ids (alphabetical)
avpm show dev              # secure TUI view: hold Space to reveal the password
avpm rename dev production # rename a vault-id
avpm rm dev prod -f        # remove one or more vault-ids

# TUI
avpm tui                   # full-screen interactive manager

# Encrypted sync (requires [sync] config — see below)
avpm sync push             # age-encrypt local vaults and push
avpm sync pull             # pull + timestamp-merge into local
avpm sync status           # compare local vs remote, no changes

# Config
avpm config init           # interactive setup
avpm config path           # print the config file path
avpm config edit           # open the config in $EDITOR

# File-store backend (keyring-less environments, e.g. headless WSL2)
avpm unlock                # keyring backend: no-op; file backend: cache the master passphrase
```

### Ansible integration

avpm ships **two binaries**:

- **`avpm`** — the full password manager (CLI + TUI).
- **`avpm-client`** — the Ansible vault password client entry point.

`avpm-client` exists because Ansible only invokes a vault password script
with `--vault-id <id>` when the script's file name ends in `-client` (see
Ansible's `script_is_client` detection in
`lib/ansible/parsing/vault/__init__.py`). Without the `-client` suffix,
Ansible calls the script with **no arguments** and avpm cannot learn which
vault-id is requested. So **always use `avpm-client` (not `avpm`) as the
vault password source.**

`avpm-client --vault-id <id>` prints the password to stdout; an unknown
vault-id exits with code **2** (matching Ansible's `VAULT_ID_UNKNOWN_RC = 2`,
which tells Ansible "this client doesn't have that vault-id").

```bash
# 1. ansible.cfg (recommended)
[defaults]
vault_password_file = /path/to/avpm-client

# 2. Environment variable
export ANSIBLE_VAULT_PASSWORD_FILE=/path/to/avpm-client

# 3. Command line — single vault-id
ansible-playbook --vault-password-file /path/to/avpm-client site.yml

# 4. Multiple vault-ids (label@client)
ansible-playbook --vault-id dev@/path/to/avpm-client site.yml
ansible-playbook --vault-id dev@/path/to/avpm-client --vault-id prod@/path/to/avpm-client site.yml
```

`avpm-client`'s stdout is **pure** — only the password, one line — so it is
safe for Ansible to consume via pipe.

### Storage backends

avpm stores vaults in one of two backends, selected by `[storage].backend`
(`auto` by default):

- **`keyring`** — OS-native keyring (macOS Keychain / Linux Secret Service).
- **`file`** — age-encrypted file store (`store.age`, scrypt + armored ASCII)
  for keyring-less environments (headless WSL2 / CI containers). Requires
  `avpm unlock` once per session to cache the master passphrase; non-
  interactive calls without a cache exit **5** (`Locked`).
- **`auto`** (default) — probe the OS keyring with a read-only lookup; use it
  when reachable, otherwise fall back to the file store. The probe is purely
  availability-driven — a stray `store.age` never forces the file backend when
  the keyring is up, so macOS/desktop users are never accidentally pulled off
  the keyring.

### Sync configuration

`~/.config/avpm/config.toml` (all keys optional except sync backends):

```toml
[default]
service = "avpm"   # keyring service name; default "avpm"

# Storage backend: "auto" (default), "keyring", or "file"
[storage]
backend = "auto"

# Sync is optional. Configure one backend:
[sync]
backend = "git"    # or "webdav"

[sync.git]
remote = "git@github.com:me/vault-sync.git"
# path = "vault.age"   # default: encrypted manifest path inside the repo
# branch = "main"      # default

# [sync.webdav]
# url = "https://nextcloud.example.com/remote.php/dav/files/me/avpm/"
# username = "me"
# (password is prompted on first use and stored in the keyring, never on disk)
```

The sync manifest is encrypted with [age] using a passphrase you enter each
time (`scrypt` + ChaCha20-Poly1305 STREAM). The passphrase is **never stored**.

[age]: https://age-encryption.org

## Development

```bash
cargo fmt
cargo clippy --all-targets --features testing -- -D warnings
cargo test --features testing                       # skips #[ignore]'d real-system tests
cargo test --features testing -- --ignored          # real keyring + git (needs D-Bus)
```

`#[ignore]`'d tests require a live keyring (D-Bus session) and/or system git;
the CI `ignored-tests` job sets those up.

## License

Licensed under the [MIT License](LICENSE).
