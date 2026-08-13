//! `WebDavBackend` — sync via WebDAV HTTP, backed by the `reqwest_dav` client.
//!
//! `exists` → GET (probe), `push` → PUT, `pull` → GET. Auth is HTTP Basic with
//! credentials stored in the keyring under service `avpm-webdav`; `reqwest_dav`
//! assembles the `Authorization` header (no hand-rolled base64). The `url` is a
//! directory; the blob filename is fixed `vault.age`.
//!
//! Error precision: a network/auth failure surfaces as `Err` (never faked as
//! "absent"), while an HTTP 404 yields `Ok(false)` / `RemoteNotFound`. The
//! `read-merge-write` engine relies on this to distinguish "remote empty"
//! from "can't reach remote".

use reqwest_dav::{Auth, ClientBuilder};
use tracing::{debug, instrument};

use crate::config::WebDavConfig;
use crate::error::{Error, Result};
use crate::password;
use crate::sync::backend::SyncBackend;
use crate::sync::error::SyncBackendError;
use crate::vault::{KeyringStore, VaultStore};

const WEBDAV_SERVICE: &str = "avpm-webdav";
const WEBDAV_USER: &str = "default";
const BLOB_NAME: &str = "vault.age";

/// WebDAV-backed sync transport.
pub struct WebDavBackend {
    base_url: String,
    username: String,
    cred_store: KeyringStore,
    /// When set (tests / non-keyring environments), used instead of the keyring.
    password_override: Option<String>,
}

impl WebDavBackend {
    /// Build a backend. The password is resolved from the keyring on each
    /// operation (after [`Self::ensure_password`] has stored it).
    #[must_use]
    pub fn new(cfg: &WebDavConfig) -> Self {
        Self {
            base_url: normalize_dir_url(&cfg.url),
            username: cfg.username.clone(),
            cred_store: KeyringStore::new(WEBDAV_SERVICE),
            password_override: None,
        }
    }

    /// Build a backend with an inline password, bypassing the keyring. For
    /// httpmock-backed e2e tests (and any keyring-less environment) so they
    /// don't depend on a live Secret Service / Keychain.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn new_with_password(cfg: &WebDavConfig, password: String) -> Self {
        Self {
            base_url: normalize_dir_url(&cfg.url),
            username: cfg.username.clone(),
            cred_store: KeyringStore::new(WEBDAV_SERVICE),
            password_override: Some(password),
        }
    }

    /// Prompt for and store the WebDAV password if not already in the keyring.
    /// A no-op when an inline password override is set.
    pub fn ensure_password(&self) -> Result<()> {
        if self.password_override.is_some() {
            return Ok(());
        }
        match self.cred_store.get(WEBDAV_USER) {
            Ok(_) => Ok(()),
            Err(Error::Vault(crate::vault::VaultError::NotFound(_))) => {
                let secret = password::prompt("WebDAV password")?;
                self.cred_store.set(WEBDAV_USER, &secret)?;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn password(&self) -> Result<String> {
        if let Some(pw) = &self.password_override {
            return Ok(pw.clone());
        }
        Ok(self.cred_store.get(WEBDAV_USER)?.as_str().to_string())
    }

    /// Build a `reqwest_dav` client. Sync issues only a handful of requests per
    /// operation, so a fresh client per call is fine.
    fn dav(&self) -> Result<reqwest_dav::Client> {
        let pw = self.password()?;
        ClientBuilder::new()
            .set_host(self.base_url.clone())
            .set_auth(Auth::Basic(self.username.clone(), pw))
            .build()
            .map_err(|e| webdav_err(&e.to_string()))
    }
}

impl SyncBackend for WebDavBackend {
    #[instrument(skip(self, data), fields(path = BLOB_NAME, bytes = data.len()))]
    async fn push(&self, data: &[u8], message: Option<&str>) -> Result<()> {
        // Flat blob store: no commit/audit concept, so the message is ignored.
        let _ = message;
        debug!("webdav PUT");
        let client = self.dav()?;
        client
            .put(BLOB_NAME, data.to_vec())
            .await
            .map_err(|e| webdav_err(&e.to_string()))?;
        Ok(())
    }

    #[instrument(skip(self), fields(path = BLOB_NAME))]
    async fn pull(&self) -> Result<Vec<u8>> {
        debug!("webdav GET");
        let client = self.dav()?;
        // get_raw returns the response without a status assertion, so we can
        // distinguish 404 (RemoteNotFound) from other failures.
        let resp = client
            .get_raw(BLOB_NAME)
            .await
            .map_err(|e| webdav_err(&e.to_string()))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::Sync(crate::sync::SyncError::Backend(
                SyncBackendError::RemoteNotFound,
            )));
        }
        if !status.is_success() {
            return Err(Error::Sync(crate::sync::SyncError::Backend(
                SyncBackendError::WebDav(format!("GET returned {status}")),
            )));
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| webdav_err(&e.to_string()))
    }

    #[instrument(skip(self), fields(path = BLOB_NAME))]
    async fn exists(&self) -> Result<bool> {
        debug!("webdav probe GET");
        let client = self.dav()?;
        let resp = client
            .get_raw(BLOB_NAME)
            .await
            .map_err(|e| webdav_err(&e.to_string()))?;
        let status = resp.status();
        Ok(status.is_success())
        // 404 → false (absent); a transport error already became Err above.
    }
}

fn webdav_err(msg: &str) -> Error {
    Error::Sync(crate::sync::SyncError::Backend(SyncBackendError::WebDav(
        msg.to_string(),
    )))
}

fn normalize_dir_url(url: &str) -> String {
    if url.ends_with('/') {
        url.to_string()
    } else {
        format!("{url}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_dir_url_appends_slash() {
        assert_eq!(normalize_dir_url("https://x/dav"), "https://x/dav/");
        assert_eq!(normalize_dir_url("https://x/dav/"), "https://x/dav/");
    }

    #[test]
    fn new_stores_normalized_base_and_blob_name() {
        let cfg = WebDavConfig {
            url: "https://x/dav".into(),
            username: "u".into(),
        };
        let be = WebDavBackend::new(&cfg);
        assert_eq!(be.base_url, "https://x/dav/");
        // The blob name is fixed; reqwest_dav joins host + "vault.age".
        assert_eq!(BLOB_NAME, "vault.age");
    }
}
