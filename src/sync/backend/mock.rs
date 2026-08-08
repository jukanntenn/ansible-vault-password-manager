//! `MockBackend` - in-memory test double for [`SyncBackend`].

#![cfg(any(test, feature = "testing"))]
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::sync::backend::SyncBackend;
use crate::sync::error::SyncBackendError;

/// In-memory `SyncBackend` for tests.
pub struct MockBackend {
    blob: Mutex<Option<Vec<u8>>>,
}

impl MockBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            blob: Mutex::new(None),
        }
    }

    /// Pre-seed the remote blob (e.g. simulate prior push).
    pub fn seed(&self, data: &[u8]) {
        *self.blob.lock().expect("mock mutex poisoned") = Some(data.to_vec());
    }

    /// Snapshot of the current blob.
    #[must_use]
    pub fn snapshot(&self) -> Option<Vec<u8>> {
        self.blob.lock().expect("mock mutex poisoned").clone()
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncBackend for MockBackend {
    async fn push(&self, data: &[u8], _message: Option<&str>) -> Result<()> {
        // MockBackend is a blob store; the message is ignored (matches webdav
        // semantics — only git versions the blob).
        *self.blob.lock().expect("mock mutex poisoned") = Some(data.to_vec());
        Ok(())
    }

    async fn pull(&self) -> Result<Vec<u8>> {
        match &*self.blob.lock().expect("mock mutex poisoned") {
            Some(v) => Ok(v.clone()),
            None => Err(Error::Sync(crate::sync::SyncError::Backend(
                SyncBackendError::RemoteNotFound,
            ))),
        }
    }

    async fn exists(&self) -> Result<bool> {
        Ok(self.blob.lock().expect("mock mutex poisoned").is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn push_pull_roundtrip() {
        let b = MockBackend::new();
        assert!(!b.exists().await.unwrap());
        b.push(b"hello", None).await.unwrap();
        assert!(b.exists().await.unwrap());
        let got = b.pull().await.unwrap();
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn pull_empty_is_remote_not_found() {
        let b = MockBackend::new();
        let err = b.pull().await.unwrap_err();
        match err {
            Error::Sync(crate::sync::SyncError::Backend(SyncBackendError::RemoteNotFound)) => {}
            other => panic!("expected RemoteNotFound, got {other:?}"),
        }
    }
}
