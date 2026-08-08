//! Master-passphrase cache for the `FileStore` backend.
//!
//! The file store encrypts `store.age` with a master passphrase. To keep
//! ansible's non-interactive `avpm --vault-id dev` calls working (they can't
//! prompt), `avpm unlock` caches the passphrase so subsequent processes can
//! read it back without prompting.
//!
//! The cache carrier is platform-dependent:
//!
//! - **Secret Service platforms** (Linux / *BSD / etc.): the OS keyring's
//!   **session collection** — writable, non-persistent, and typically usable
//!   headless even when the `login` collection cannot be created (the exact
//!   WSL2 asymmetry that makes the file backend viable). Reached by its
//!   `session` alias / well-known path, NOT through the `keyring` crate:
//!   keyring-rs targets collections by *label*, and GNOME Keyring's session
//!   collection has an empty label, so that lookup always fails (and would
//!   hang on a GUI prompt trying to create a collection). libsecret and this
//!   module use the alias / path instead.
//! - **Other platforms** (macOS Keychain, Windows Credential Manager): keep
//!   the previous behavior of caching in the default collection via
//!   `KeyringStore`; those stores have no session-collection concept.
//!
//! All operations are best-effort: if the cache is unavailable, `read_cached`
//! returns `Ok(None)` (no cache) rather than an error, since a missing cache
//! is a recoverable state (prompt the user) but a hard error would block the
//! command entirely.

use crate::error::{Error, Result};
use crate::vault::VaultError;
use tracing::{debug, instrument};

/// Service name under which the master passphrase is cached.
const MASTER_SERVICE: &str = "avpm-master";

/// Username (entry label) for the cached master passphrase.
const MASTER_USERNAME: &str = "master";

/// Port for the master-passphrase cache carrier.
///
/// The carrier decides *where* the cache lives — the Secret Service session
/// collection on SS platforms, the OS keyring default collection elsewhere.
/// The trait is also the test seam: unit tests drive the wrapper logic with a
/// mock, and integration tests exercise the real carriers.
trait MasterCache {
    /// Read the cached passphrase, if any.
    fn read(&self) -> Result<Option<String>>;

    /// Cache `passphrase`.
    fn cache(&self, passphrase: &str) -> Result<()>;

    /// Remove any cached passphrase.
    fn clear(&self) -> Result<()>;
}

/// Read the cached master passphrase, if any.
///
/// Returns `Ok(None)` when there is no cached passphrase (first run, cache
/// evicted, or cache unavailable). Returns `Ok(Some)` only on a confirmed
/// cache hit.
#[instrument]
pub fn read_cached() -> Result<Option<String>> {
    read_cached_with(&platform_cache())
}

/// Cache `passphrase` for subsequent processes to read.
///
/// Used by `avpm unlock`. Failures to write the cache are propagated (the user
/// should know their unlock won't persist across processes); callers may
/// downgrade to a warning if appropriate.
#[instrument(skip(passphrase))]
pub fn cache(passphrase: &str) -> Result<()> {
    platform_cache().cache(passphrase)
}

/// Remove any cached master passphrase (e.g. for `avpm lock`, if added).
#[instrument]
pub fn clear() -> Result<()> {
    platform_cache().clear()
}

/// The production carrier for this platform, addressing the `avpm-master` /
/// `master` entry.
fn platform_cache() -> carrier::Cache {
    carrier::Cache::new(MASTER_SERVICE, MASTER_USERNAME)
}

/// The wrapper logic around a carrier (extracted for unit testing).
///
/// The cache is an optimization, not a hard dependency: unavailability is a
/// cache miss, not an error.
fn read_cached_with(cache: &impl MasterCache) -> Result<Option<String>> {
    match cache.read() {
        Err(Error::Vault(VaultError::SessionCache(_))) => {
            debug!("master passphrase cache miss: session cache unavailable");
            Ok(None)
        }
        other => other,
    }
}

/// Cache carrier. The two platform variants expose the same `MasterCache`
/// contract; only the *where* differs.
///
/// Secret Service platforms — same cfg the `keyring` crate uses to select its
/// Secret Service store. The cache lives in the session collection.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
mod carrier {

    use std::collections::HashMap;

    use secret_service::blocking::{Collection, SecretService};
    use secret_service::EncryptionType;

    use crate::error::{Error, Result};
    use crate::vault::VaultError;
    use tracing::{debug, instrument};

    use super::MasterCache;

    /// Well-known session-collection path (GNOME Keyring, KSecretService).
    const SESSION_PATH: &str = "/org/freedesktop/secrets/collection/session";

    /// The Secret Service session-collection cache.
    pub struct Cache {
        service: String,
        username: String,
    }

    impl Cache {
        pub fn new(service: &str, username: &str) -> Self {
            Self {
                service: service.to_string(),
                username: username.to_string(),
            }
        }

        /// Search attributes for the cached passphrase; identical to the
        /// `service` / `username` pair the keyring backends use.
        fn attributes(&self) -> HashMap<&str, &str> {
            HashMap::from([
                ("service", self.service.as_str()),
                ("username", self.username.as_str()),
            ])
        }

        /// Connect to the session bus (blocking; same transport the keyring
        /// store already uses from these async handlers).
        fn connect() -> Result<SecretService<'static>> {
            SecretService::connect(EncryptionType::Dh)
                .map_err(|e| Error::Vault(VaultError::SessionCache(e.to_string())))
        }

        /// The session collection, by its `session` alias with a fallback to
        /// the well-known path for daemons that don't register the alias.
        fn session_collection<'s>(ss: &'s SecretService<'s>) -> Result<Collection<'s>> {
            if let Ok(collection) = ss.get_collection_by_alias("session") {
                return Ok(collection);
            }
            let path: zvariant::OwnedObjectPath = zvariant::ObjectPath::try_from(SESSION_PATH)
                .map_err(|e| {
                    Error::Vault(VaultError::SessionCache(format!(
                        "invalid session collection path: {e}"
                    )))
                })?
                .into();
            ss.get_collection_by_path(path)
                .map_err(|e| Error::Vault(VaultError::SessionCache(e.to_string())))
        }
    }

    impl MasterCache for Cache {
        #[instrument(skip(self))]
        fn read(&self) -> Result<Option<String>> {
            let ss = Self::connect()?;
            let collection = Self::session_collection(&ss)?;
            let items = collection
                .search_items(self.attributes())
                .map_err(|e| Error::Vault(VaultError::SessionCache(e.to_string())))?;
            if let Some(item) = items.first() {
                let secret = item
                    .get_secret()
                    .map_err(|e| Error::Vault(VaultError::SessionCache(e.to_string())))?;
                let passphrase = String::from_utf8(secret).map_err(|e| {
                    Error::Vault(VaultError::SessionCache(format!(
                        "cache entry is not valid UTF-8: {e}"
                    )))
                })?;
                debug!("master passphrase cache hit");
                Ok(Some(passphrase))
            } else {
                debug!("master passphrase cache miss: no entry");
                Ok(None)
            }
        }

        #[instrument(skip(self, passphrase))]
        fn cache(&self, passphrase: &str) -> Result<()> {
            let ss = Self::connect()?;
            let collection = Self::session_collection(&ss)?;
            // replace=true: repeated `avpm unlock` atomically overwrites the
            // single cache item (no duplicates, no cleanup needed).
            collection
                .create_item(
                    &self.service,
                    self.attributes(),
                    passphrase.as_bytes(),
                    true,
                    "text/plain",
                )
                .map_err(|e| Error::Vault(VaultError::SessionCache(e.to_string())))?;
            debug!("master passphrase cached (session collection)");
            Ok(())
        }

        #[instrument(skip(self))]
        fn clear(&self) -> Result<()> {
            let ss = Self::connect()?;
            let collection = Self::session_collection(&ss)?;
            for item in collection
                .search_items(self.attributes())
                .map_err(|e| Error::Vault(VaultError::SessionCache(e.to_string())))?
            {
                item.delete()
                    .map_err(|e| Error::Vault(VaultError::SessionCache(e.to_string())))?;
            }
            debug!("master passphrase cache cleared");
            Ok(())
        }
    }
}

/// Cache carrier. The two platform variants expose the same `MasterCache`
/// contract; only the *where* differs.
///
/// Non-Secret-Service platforms: previous behavior, unchanged.
#[cfg(not(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
)))]
mod carrier {

    use crate::error::{Error, Result};
    use crate::vault::{KeyringStore, VaultError, VaultStore};
    use tracing::{debug, instrument};

    use super::MasterCache;

    /// The default-collection cache (macOS Keychain / Windows Credential
    /// Manager).
    pub struct Cache {
        service: String,
        username: String,
    }

    impl Cache {
        pub fn new(service: &str, username: &str) -> Self {
            Self {
                service: service.to_string(),
                username: username.to_string(),
            }
        }
    }

    impl MasterCache for Cache {
        #[instrument(skip(self))]
        fn read(&self) -> Result<Option<String>> {
            let store = KeyringStore::new(&self.service);
            match store.get(&self.username) {
                Ok(secret) => {
                    debug!("master passphrase cache hit");
                    Ok(Some(secret.as_str().to_string()))
                }
                Err(Error::Vault(VaultError::NotFound(_))) => {
                    debug!("master passphrase cache miss: no entry");
                    Ok(None)
                }
                Err(Error::Vault(VaultError::KeyringUnavailable { .. })) => {
                    debug!("master passphrase cache miss: keyring unavailable");
                    Ok(None)
                }
                Err(e) => {
                    // Unexpected failure - surface it so we don't silently misbehave.
                    debug!(error = %e, "master passphrase cache read failed unexpectedly");
                    Err(e)
                }
            }
        }

        #[instrument(skip(self, passphrase))]
        fn cache(&self, passphrase: &str) -> Result<()> {
            let store = KeyringStore::new(&self.service);
            let secret = crate::vault::VaultSecret::new(passphrase.to_string());
            store.set(&self.username, &secret)?;
            debug!("master passphrase cached");
            Ok(())
        }

        #[instrument(skip(self))]
        fn clear(&self) -> Result<()> {
            let store = KeyringStore::new(&self.service);
            match store.delete(&self.username) {
                Ok(()) => {
                    debug!("master passphrase cache cleared");
                    Ok(())
                }
                // Already absent - treat as success.
                Err(Error::Vault(VaultError::NotFound(_))) => Ok(()),
                Err(e) => Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{read_cached_with, MasterCache};
    use crate::error::{Error, Result};
    use crate::vault::VaultError;

    /// What the mock's `read` should return.
    enum ReadBehavior {
        Hit(&'static str),
        Miss,
        CacheUnavailable,
        OtherError,
    }

    /// Scriptable test double for the master-cache carrier.
    struct MockMasterCache {
        read: ReadBehavior,
        cache_ok: bool,
        clear_ok: bool,
    }

    impl MasterCache for MockMasterCache {
        fn read(&self) -> Result<Option<String>> {
            match self.read {
                ReadBehavior::Hit(pw) => Ok(Some(pw.to_string())),
                ReadBehavior::Miss => Ok(None),
                ReadBehavior::CacheUnavailable => {
                    Err(Error::Vault(VaultError::SessionCache("no daemon".into())))
                }
                ReadBehavior::OtherError => Err(Error::Other(anyhow::anyhow!("boom"))),
            }
        }

        fn cache(&self, _passphrase: &str) -> Result<()> {
            if self.cache_ok {
                Ok(())
            } else {
                Err(Error::Vault(VaultError::SessionCache("no daemon".into())))
            }
        }

        fn clear(&self) -> Result<()> {
            if self.clear_ok {
                Ok(())
            } else {
                Err(Error::Vault(VaultError::SessionCache("no daemon".into())))
            }
        }
    }

    fn mock(read: ReadBehavior) -> MockMasterCache {
        MockMasterCache {
            read,
            cache_ok: true,
            clear_ok: true,
        }
    }

    #[test]
    fn read_cached_passes_through_cache_hit() {
        let cache = mock(ReadBehavior::Hit("master123"));
        assert_eq!(
            read_cached_with(&cache).unwrap().as_deref(),
            Some("master123")
        );
    }

    #[test]
    fn read_cached_passes_through_cache_miss() {
        let cache = mock(ReadBehavior::Miss);
        assert_eq!(read_cached_with(&cache).unwrap(), None);
    }

    #[test]
    fn read_cached_downgrades_cache_unavailable_to_miss() {
        // The regression guard for the WSL2 acceptance failure: a broken
        // session cache must never hard-fail `avpm get`/`sync` — it becomes
        // a cache miss (interactive re-prompt / exit 5 non-interactively).
        let cache = mock(ReadBehavior::CacheUnavailable);
        assert_eq!(read_cached_with(&cache).unwrap(), None);
    }

    #[test]
    fn read_cached_propagates_unexpected_errors() {
        let cache = mock(ReadBehavior::OtherError);
        assert!(read_cached_with(&cache).is_err());
    }

    #[test]
    fn cache_failures_propagate_for_the_unlock_warning() {
        // `avpm unlock` turns this into a warning; if we swallowed it, users
        // would never learn their unlock won't persist.
        let cache = MockMasterCache {
            read: ReadBehavior::Miss,
            cache_ok: false,
            clear_ok: true,
        };
        assert!(cache.cache("master123").is_err());
    }

    #[test]
    fn clear_success_and_failure_are_passthrough() {
        let ok = MockMasterCache {
            read: ReadBehavior::Miss,
            cache_ok: true,
            clear_ok: true,
        };
        assert!(ok.clear().is_ok());
        let bad = MockMasterCache {
            read: ReadBehavior::Miss,
            cache_ok: true,
            clear_ok: false,
        };
        assert!(bad.clear().is_err());
    }
}

#[cfg(all(
    test,
    all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    )
))]
mod session_cache_integration_tests {
    //! Real-Secret-Service round-trip for the session-collection carrier.
    //!
    //! These tests run whenever a Secret Service daemon is reachable (a
    //! headless gnome-keyring session collection qualifies) and skip with a
    //! message otherwise — never fail in daemon-less CI. They use their own
    //! service/username so the developer's real `avpm-master` cache is never
    //! touched.

    use std::collections::HashMap;

    use secret_service::blocking::SecretService;
    use secret_service::EncryptionType;

    use super::carrier::Cache;
    use crate::vault::master::MasterCache;

    /// Well-known session-collection path (GNOME Keyring, KSecretService).
    const SESSION_PATH: &str = "/org/freedesktop/secrets/collection/session";

    const TEST_SERVICE: &str = "avpm-test-master";
    const TEST_USERNAME: &str = "test-master";
    /// Distinct entry for the corrupt-entry test so it can't race the
    /// round-trip test (both drive the real session collection in parallel).
    const CORRUPT_SERVICE: &str = "avpm-test-corrupt";
    const CORRUPT_USERNAME: &str = "corrupt";

    /// A Secret Service daemon on the session bus is required; skip (not
    /// fail) when absent so the suite stays green in daemon-less CI.
    fn daemon_available() -> bool {
        SecretService::connect(EncryptionType::Dh).is_ok()
    }

    fn test_cache() -> Cache {
        Cache::new(TEST_SERVICE, TEST_USERNAME)
    }

    fn attributes() -> HashMap<&'static str, &'static str> {
        HashMap::from([("service", TEST_SERVICE), ("username", TEST_USERNAME)])
    }

    #[test]
    fn session_cache_round_trip_lives_in_session_collection() {
        if !daemon_available() {
            eprintln!("skipping: no Secret Service daemon on the session bus");
            return;
        }
        let cache = test_cache();
        let _ = cache.clear(); // clean slate

        cache.cache("pw-1").unwrap();
        assert_eq!(cache.read().unwrap().as_deref(), Some("pw-1"));

        // Overwrite is idempotent: still exactly one item.
        cache.cache("pw-2").unwrap();
        assert_eq!(cache.read().unwrap().as_deref(), Some("pw-2"));

        let ss = SecretService::connect(EncryptionType::Dh).unwrap();
        let session = ss.get_collection_by_alias("session").unwrap();
        let items = session.search_items(attributes()).unwrap();
        assert_eq!(items.len(), 1, "expected exactly one cache item");
        // THE regression guard: the entry must live under the session
        // collection, never the default (login) collection.
        let path = items[0].item_path.to_string();
        assert!(
            path.starts_with(SESSION_PATH),
            "cache entry landed outside the session collection: {path}"
        );

        // The default collection must not contain the cache entry.
        if let Ok(default) = ss.get_default_collection() {
            let default_items = default.search_items(attributes()).unwrap();
            assert!(default_items.is_empty());
        }

        cache.clear().unwrap();
        assert_eq!(cache.read().unwrap(), None);
        assert!(session.search_items(attributes()).unwrap().is_empty());
    }

    #[test]
    fn session_cache_read_surfaces_corrupt_entries() {
        if !daemon_available() {
            eprintln!("skipping: no Secret Service daemon on the session bus");
            return;
        }
        let cache = Cache::new(CORRUPT_SERVICE, CORRUPT_USERNAME);
        let _ = cache.clear();

        // Corrupt the entry with non-UTF-8 bytes behind the carrier's back.
        let ss = SecretService::connect(EncryptionType::Dh).unwrap();
        let session = ss.get_collection_by_alias("session").unwrap();
        session
            .create_item(
                CORRUPT_SERVICE,
                HashMap::from([("service", CORRUPT_SERVICE), ("username", CORRUPT_USERNAME)]),
                b"\xff\xfe",
                true,
                "text/plain",
            )
            .unwrap();

        let err = cache.read().unwrap_err();
        assert!(
            err.to_string().contains("not valid UTF-8"),
            "unexpected error: {err}"
        );

        cache.clear().unwrap();
    }
}
