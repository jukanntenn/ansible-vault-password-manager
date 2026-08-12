# Troubleshooting

Common issues and their solutions. If your problem isn't listed here, please
[open an issue](https://github.com/jukanntenn/ansible-vault-password-manager/issues).

---

## Table of Contents

- [WSL2 / Headless Linux: Secret Service unavailable](#wsl2--headless-linux-secret-service-unavailable)
- [Session cache warnings (`could not cache master passphrase`)](#session-cache-warnings-could-not-cache-master-passphrase)
- [Ansible: "vault password client script did not find a secret"](#ansible-vault-password-client-script-did-not-find-a-secret)
- [macOS: `cargo install` fails (rustc version too old)](#macos-cargo-install-fails-rustc-version-too-old)

---

## WSL2 / Headless Linux: Secret Service unavailable

### Symptom

Any `avpm` command prints a warning like:

```
warning: could not cache master passphrase (session cache unavailable:
zbus error: org.freedesktop.DBus.Error.ServiceUnknown: The name
org.freedesktop.secrets was not provided by any .service files);
you may need to re-enter it later
```

Or the keyring itself is unavailable:

```
Error: keyring unavailable: ...
```

### Root cause

The D-Bus session bus cannot find a service registered under the well-known
name `org.freedesktop.secrets`. On Debian/Ubuntu this service is provided by
the **`gnome-keyring`** package, which installs the D-Bus service file at
`/usr/share/dbus-1/services/org.freedesktop.secrets.service`. Without that
file, D-Bus has no way to auto-start `gnome-keyring-daemon`, and every Secret
Service call fails.

avpm falls back to the encrypted file store (`store.age`) when this happens,
but the file store's master-passphrase cache *also* uses the Secret Service
session collection — so without the daemon, the cache can't work and you'll
be re-prompted in every new process.

### Fix: install and enable the Secret Service daemon

**1. Install the required packages:**

```bash
sudo apt-get update
sudo apt-get install -y gnome-keyring dbus-x11 libsecret-tools
```

What each package provides:

| Package | Purpose |
|---|---|
| `gnome-keyring` | The `gnome-keyring-daemon` + the D-Bus `.service` file |
| `dbus-x11` | D-Bus session bus support (needed for WSL2) |
| `libsecret-tools` | The `secret-tool` CLI for manual verification |

**2. Enable systemd (WSL2 only):**

Create or edit `/etc/wsl.conf`:

```ini
[boot]
systemd=true
```

Then from **Windows PowerShell** restart WSL:

```powershell
wsl --shutdown
```

Reopen your WSL terminal. Verify systemd is running:

```bash
systemctl is-system-running
# expected output: running
```

**3. Verify the Secret Service is reachable:**

```bash
# Check that D-Bus can activate the service:
gdbus call --session \
  --dest org.freedesktop.DBus \
  --object-path /org/freedesktop/DBus \
  --method org.freedesktop.DBus.ListActivatableNames \
  | tr ',' '\n' | grep secret

# expected output: 'org.freedesktop.secrets'

# Check that the session collection exists:
gdbus call --session \
  --dest org.freedesktop.secrets \
  --object-path /org/freedesktop/secrets/collection/session \
  --method org.freedesktop.DBus.Properties.Get \
  org.freedesktop.Secret.Collection Label

# expected output: (<''>,)  — empty label is normal for the session collection
```

If both commands succeed, `avpm unlock` / `avpm set` will cache the master
passphrase correctly and subsequent non-interactive calls (`avpm-client
--vault-id dev` from Ansible) will work without prompting.

---

## Session cache warnings (`could not cache master passphrase`)

### Symptom

```
➜  ~ avpm unlock
Set master passphrase:
Confirm password:
warning: passphrase verified but could not be cached (session cache unavailable:
zbus error: org.freedesktop.DBus.Error.ServiceUnknown: ...);
  it will need to be re-entered in each new process
```

### What this means

`avpm unlock` verified your master passphrase (the file store decrypted
successfully), but it could not cache the passphrase for other processes to
reuse. Every new `avpm` process will prompt again. For interactive use this is
merely annoying; for Ansible's non-interactive `avpm-client --vault-id <id>`
calls it is fatal (exit code 5, `Locked`).

### Fix

Follow the [Secret Service setup](#wsl2--headless-linux-secret-service-unavailable)
steps above. Once the Secret Service daemon is running and the session
collection is reachable, `avpm unlock` will cache successfully and the warning
disappears.

### Why the session collection?

avpm caches the master passphrase in the Secret Service **session collection**
(not the `login` collection) on Linux. The session collection is:

- **Non-persistent** — cleared when the D-Bus session ends (WSL restart, logout).
  This is intentional: the master passphrase should not survive a reboot.
- **No GUI required** — unlike the `login` collection, the session collection
  can be created and written on a fully headless system without any desktop
  environment.
- **Addressed by alias/path** — GNOME Keyring's session collection has an empty
  label, so avpm reaches it via its `session` alias
  (`/org/freedesktop/secrets/collection/session`) rather than through the
  `keyring` crate's label-based lookup.

This is why a working Secret Service daemon is required even on headless WSL2.

---

## Ansible: "vault password client script did not find a secret"

### Symptom

```
ERROR! vault password client script /path/to/avpm did not find a secret for vault-id=dev: ...
```

or

```
ERROR! Problem running vault password client script /path/to/avpm (...).
```

### Root cause

Ansible only invokes a vault password script **with** `--vault-id <id>` when
the script's file name ends in `-client` (the `script_is_client` check in
`lib/ansible/parsing/vault/__init__.py`). A script named `avpm` (no `-client`
suffix) is treated as a plain `ScriptVaultSecret` and called with **no
arguments**, so avpm reports "no command given" and Ansible surfaces it as an
error.

### Fix

Point Ansible at **`avpm-client`** (the client entry point), not `avpm`:

```ini
# ansible.cfg
[defaults]
vault_password_file = /path/to/avpm-client
```

```bash
# or on the command line
ansible-playbook --vault-id dev@/path/to/avpm-client site.yml
```

`avpm-client` ships alongside `avpm` (both are installed by `cargo install`).
Verify both are on your `PATH`:

```bash
which avpm avpm-client
```

If `avpm-client` is missing, reinstall: `cargo install --path . --locked`.

---

## macOS: `cargo install` fails (rustc version too old)

### Symptom

```
error: failed to compile `avpm ...`

Caused by:
  rustc 1.86.0 is not supported by the following packages:
    keyring@4.1.6 requires rustc 1.88.0
    ratatui@0.29.0 requires rustc 1.88.0
    ...
```

### Root cause

avpm depends on crates (notably `keyring` and `ratatui`) that require
**Rust 1.88 or newer**. The `rustc` on your system is older than that.

### Fix

Upgrade your Rust toolchain to ≥ 1.88:

**Using rustup (recommended):**

```bash
rustup update stable
rustc --version  # should print 1.88.0 or newer
```

Then reinstall:

```bash
cargo install --git https://github.com/jukanntenn/ansible-vault-password-manager --locked
```

**Using Homebrew:**

```bash
brew upgrade rust
```

If your package manager does not provide Rust ≥ 1.88 yet, install rustup
instead:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
