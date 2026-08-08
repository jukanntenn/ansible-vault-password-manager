//! `WebDavBackend` - sync via WebDAV HTTP (see `09` §4.3).
//!
//! `exists` → PROPFIND/HEAD, `push` → PUT, `pull` → GET. Auth is HTTP Basic
//! with credentials stored in the keyring under service `avpm-webdav`.
//! The `url` is treated as a *directory*; the blob filename is fixed
//! `vault.age`.

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::{Client, Method};
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
    client: Client,
    base_url: String,
    username: String,
    cred_store: KeyringStore,
}

impl WebDavBackend {
    /// Build a backend. Lazily resolves the password from the keyring on each
    /// request; if missing, the caller (sync engine) is expected to prompt the
    /// user and store it via [`WebDavBackend::ensure_password`].
    #[must_use]
    pub fn new(cfg: &WebDavConfig) -> Self {
        Self {
            client: Client::new(),
            base_url: normalize_dir_url(&cfg.url),
            username: cfg.username.clone(),
            cred_store: KeyringStore::new(WEBDAV_SERVICE),
        }
    }

    /// Prompt for and store the WebDAV password if not already in the keyring.
    pub fn ensure_password(&self) -> Result<()> {
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

    fn basic_auth_header(&self) -> Result<HeaderValue> {
        let pw = self.cred_store.get(WEBDAV_USER)?;
        let creds = format!("{}:{}", self.username, pw.as_str());
        let encoded = base64_encode(creds.as_bytes());
        let val = HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|e| {
            Error::Sync(crate::sync::SyncError::Backend(SyncBackendError::WebDav(
                e.to_string(),
            )))
        })?;
        Ok(val)
    }

    fn blob_url(&self) -> String {
        format!("{base}{BLOB_NAME}", base = self.base_url)
    }

    async fn request(&self, method: Method, body: Option<&[u8]>) -> Result<reqwest::Response> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, self.basic_auth_header()?);
        let mut req = self
            .client
            .request(method, self.blob_url())
            .headers(headers);
        if let Some(b) = body {
            req = req.body(b.to_vec());
        }
        req.send().await.map_err(|e| {
            Error::Sync(crate::sync::SyncError::Backend(SyncBackendError::WebDav(
                e.to_string(),
            )))
        })
    }
}

impl SyncBackend for WebDavBackend {
    #[instrument(skip(self, data), fields(url = %self.blob_url(), bytes = data.len()))]
    async fn push(&self, data: &[u8], message: Option<&str>) -> Result<()> {
        // WebDAV is a flat blob store with no commit/audit concept; the
        // optional message is ignored (only git uses it for the commit msg).
        // Bind to `message` (not `_message`) to avoid clippy's pedantic
        // `used_underscore_binding` lint while still documenting intent.
        let _ = message;
        debug!("webdav PUT");
        let resp = self.request(Method::PUT, Some(data)).await?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(Error::Sync(crate::sync::SyncError::Backend(
                SyncBackendError::WebDav(format!("PUT returned {status}")),
            )))
        }
    }

    #[instrument(skip(self), fields(url = %self.blob_url()))]
    async fn pull(&self) -> Result<Vec<u8>> {
        debug!("webdav GET");
        let resp = self.request(Method::GET, None).await?;
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
        resp.bytes_to_vec_await().await
    }

    #[instrument(skip(self), fields(url = %self.blob_url()))]
    async fn exists(&self) -> Result<bool> {
        debug!("webdav HEAD");
        let resp = self.request(Method::HEAD, None).await?;
        let status = resp.status();
        Ok(status.is_success())
    }
}

/// Minimal non-allocating base64 encoder (avoids pulling a base64 crate for a
/// single use). RFC 4648 standard alphabet, padded.
fn base64_encode(input: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let n = (u32::from(c[0]) << 16) | (u32::from(c[1]) << 8) | u32::from(c[2]);
        out.push(TBL[((n >> 18) & 0x3F) as usize] as char);
        out.push(TBL[((n >> 12) & 0x3F) as usize] as char);
        out.push(TBL[((n >> 6) & 0x3F) as usize] as char);
        out.push(TBL[(n & 0x3F) as usize] as char);
    }
    let rem = chunks.remainder();
    match rem.len() {
        1 => {
            let n = u32::from(rem[0]) << 16;
            out.push(TBL[((n >> 18) & 0x3F) as usize] as char);
            out.push(TBL[((n >> 12) & 0x3F) as usize] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let n = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(TBL[((n >> 18) & 0x3F) as usize] as char);
            out.push(TBL[((n >> 12) & 0x3F) as usize] as char);
            out.push(TBL[((n >> 6) & 0x3F) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

fn normalize_dir_url(url: &str) -> String {
    if url.ends_with('/') {
        url.to_string()
    } else {
        format!("{url}/")
    }
}

// Small extension trait to keep the main flow readable.
trait BytesToVecAwait {
    async fn bytes_to_vec_await(self) -> Result<Vec<u8>>;
}

impl BytesToVecAwait for reqwest::Response {
    async fn bytes_to_vec_await(self) -> Result<Vec<u8>> {
        self.bytes().await.map(|b| b.to_vec()).map_err(|e| {
            Error::Sync(crate::sync::SyncError::Backend(SyncBackendError::WebDav(
                e.to_string(),
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn normalize_dir_url_appends_slash() {
        assert_eq!(normalize_dir_url("https://x/dav"), "https://x/dav/");
        assert_eq!(normalize_dir_url("https://x/dav/"), "https://x/dav/");
    }

    #[test]
    fn blob_url_joins_filename() {
        let cfg = WebDavConfig {
            url: "https://x/dav".into(),
            username: "u".into(),
        };
        let be = WebDavBackend::new(&cfg);
        assert_eq!(be.blob_url(), "https://x/dav/vault.age");
    }
}
