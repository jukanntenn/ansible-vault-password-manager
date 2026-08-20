//! Shared helpers for binary-level acceptance tests.
//!
//! Provides: isolated config/data dirs per test, config-file writing, and
//! snapshot/seed/restore of the real Secret Service session-collection cache
//! that `avpm unlock` populates (binary tests exercise the production
//! `avpm-master`/`master` entry; helpers restore whatever was there before so
//! a dev's active unlock is never clobbered).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use assert_cmd::prelude::*;

pub const CACHE_SERVICE: &str = "avpm-master";
pub const CACHE_USERNAME: &str = "master";

pub fn avpm() -> Command {
    Command::cargo_bin("avpm").expect("avpm binary built")
}

/// The `avpm-client` binary (the Ansible vault password client entry point).
/// It shares the implementation with [`avpm`]; tests verify the
/// `--vault-id` protocol that Ansible's `ClientScriptVaultSecret` relies on.
pub fn avpm_client() -> Command {
    Command::cargo_bin("avpm-client").expect("avpm-client binary built")
}

/// Point `cmd` at isolated dirs so it can never touch the developer's real
/// `~/.local/share/avpm` / `~/.config/avpm`.
///
/// The `dirs` crate honors `XDG_*` on Linux but on macOS only `$HOME` (via
/// `~/Library/Application Support`), so redirect both.
pub fn isolate(cmd: &mut Command, dir: &Path) {
    cmd.env("XDG_DATA_HOME", dir.join("data"))
        .env("XDG_CONFIG_HOME", dir.join("config"));
    #[cfg(target_os = "macos")]
    {
        cmd.env("HOME", dir.join("home"));
    }
}

/// Base dir under which avpm looks for its config on this platform.
fn config_base(dir: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dir.join("home").join("Library").join("Application Support")
    }
    #[cfg(not(target_os = "macos"))]
    {
        dir.join("config")
    }
}

/// Write `<config-base>/avpm/config.toml` for the test.
pub fn write_config(dir: &Path, toml: &str) {
    let path = config_base(dir).join("avpm");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(path.join("config.toml"), toml).unwrap();
}

fn session_collection<'s>(
    ss: &'s secret_service::blocking::SecretService<'s>,
) -> Option<secret_service::blocking::Collection<'s>> {
    if let Ok(c) = ss.get_collection_by_alias("session") {
        return Some(c);
    }
    let path: zvariant::OwnedObjectPath =
        zvariant::ObjectPath::try_from("/org/freedesktop/secrets/collection/session")
            .ok()?
            .into();
    ss.get_collection_by_path(path).ok()
}

fn attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([("service", CACHE_SERVICE), ("username", CACHE_USERNAME)])
}

/// Snapshot the current real cache value, if any.
pub fn snapshot_cache() -> Option<String> {
    let ss = secret_service::blocking::SecretService::connect(secret_service::EncryptionType::Dh)
        .ok()?;
    let collection = session_collection(&ss)?;
    let item = {
        let items = collection.search_items(attributes()).ok()?;
        items.into_iter().next()?
    };
    {
        let secret = item.get_secret().ok()?;
        String::from_utf8(secret).ok()
    }
}

/// Seed the real cache with `passphrase` (exactly what `avpm unlock` does).
pub fn seed_cache(passphrase: &str) -> bool {
    let Ok(ss) =
        secret_service::blocking::SecretService::connect(secret_service::EncryptionType::Dh)
    else {
        return false;
    };
    let Some(collection) = session_collection(&ss) else {
        return false;
    };
    let ok = collection
        .create_item(
            CACHE_SERVICE,
            attributes(),
            passphrase.as_bytes(),
            true,
            "text/plain",
        )
        .is_ok();
    ok
}

/// Restore a previously snapshotted cache value (re-cache or clear).
pub fn restore_cache(previous: Option<String>) {
    match previous {
        Some(pw) => {
            let _ = seed_cache(&pw);
        }
        None => {
            let Ok(ss) = secret_service::blocking::SecretService::connect(
                secret_service::EncryptionType::Dh,
            ) else {
                return;
            };
            let collection = session_collection(&ss);
            if let Some(collection) = collection {
                if let Ok(items) = collection.search_items(attributes()) {
                    for item in items {
                        let _ = item.delete();
                    }
                }
            }
        }
    }
}

/// Is the Secret Service default collection present and unlocked — i.e. would
/// `avpm unlock` on the keyring backend be a non-prompting no-op?
///
/// Used to gate keyring-path assertions in integration tests so they never
/// block on a GUI create/unlock prompt (which happens on a WSLg box whose
/// default collection is absent or locked). On macOS there is no Secret
/// Service: the keyring path is always taken and `ensure_default_collection`
/// is a no-op, so this reports `true`.
pub fn default_collection_is_ready() -> bool {
    #[cfg(target_os = "macos")]
    {
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        use secret_service::blocking::SecretService;
        use secret_service::EncryptionType;
        let Ok(ss) = SecretService::connect(EncryptionType::Dh) else {
            return false; // no daemon → Auto resolves to the file backend
        };
        // `get_default_collection` errs (NoResult) when the alias is absent;
        // an alias pointing at a since-deleted collection makes `is_locked`
        // error — both mean "not ready" (would prompt or fall back). Bind the
        // match so the temporary collection result drops before `ss`.
        let ready = match ss.get_default_collection() {
            Ok(col) => matches!(col.is_locked(), Ok(false)),
            Err(_) => false,
        };
        ready
    }
}

/// Is `script` (pty wrapper) available? (runtime-skip gate for the
/// interactive-unlock test; uses the `-c` command form that both util-linux
/// and BSD accept — util-linux ≥ 2.39 rejects extra positional arguments.)
#[cfg(target_os = "linux")]
pub fn script_available() -> bool {
    Command::new("script")
        .args(["-q", "-c", "true", "/dev/null"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Serializes tests that read/write the *real* session-collection cache: they
/// all use the production `avpm-master`/`master` entry, and parallel runs
/// would race (a test expecting "no cache" could observe another test's
/// seeding). Same pattern as `test_util::age_test_lock`.
pub fn cache_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static CACHE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    CACHE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
