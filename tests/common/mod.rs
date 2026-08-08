//! Shared helpers for binary-level acceptance tests.
//!
//! Provides: isolated config/data dirs per test, config-file writing, and
//! snapshot/seed/restore of the real Secret Service session-collection cache
//! that `avpm unlock` populates (binary tests exercise the production
//! `avpm-master`/`master` entry; helpers restore whatever was there before so
//! a dev's active unlock is never clobbered).

#![allow(dead_code)] // each consumer uses a subset

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use assert_cmd::prelude::*;

pub const CACHE_SERVICE: &str = "avpm-master";
pub const CACHE_USERNAME: &str = "master";

pub fn avpm() -> Command {
    Command::cargo_bin("avpm").expect("avpm binary built")
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

/// Is a Secret Service daemon reachable? (runtime-skip gate)
pub fn session_daemon_available() -> bool {
    secret_service::blocking::SecretService::connect(secret_service::EncryptionType::Dh).is_ok()
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

/// Is `script` (pty wrapper) available? (runtime-skip gate for the
/// interactive-unlock test; works on util-linux and BSD.)
pub fn script_available() -> bool {
    Command::new("script")
        .args(["-q", "/dev/null", "true"])
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
