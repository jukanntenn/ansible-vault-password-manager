//! Sync transport backends.
//!
//! `SyncBackend` uses native `async fn` in trait (Rust 1.75+) - **no**
//! `async_trait` macro (zero-cost, per the zero-abstraction principle).
//!
//! Note on `Send`: we require the returned futures to be `Send` so they can
//! drive on tokio's multi-thread runtime. Native async-fn-in-trait does not
//! let us express `-> impl Future + Send` directly on the signature, so
//! consumers that need `Send` (e.g. spawning) use `tokio::task::spawn` only
//! where the concrete future is known `Send`. For our `SyncEngine`, all
//! driving happens via `.await` on the borrowed `&self` future within a single
//! task, which does not require `Send`.

pub mod git;
#[cfg(any(test, feature = "testing"))]
pub mod mock;
pub mod webdav;

pub use git::GitBackend;
#[cfg(any(test, feature = "testing"))]
pub use mock::MockBackend;
pub use webdav::WebDavBackend;

use crate::error::Result;

/// Transport port for encrypted sync blobs.
///
/// Implementations: [`GitBackend`] (system git subprocess), [`WebDavBackend`]
/// (reqwest HTTP), [`MockBackend`] (test double).
///
/// All methods deal only in opaque encrypted bytes - backends never see
/// plaintext.
///
/// # On `async fn` in trait
/// Per3.2 we use native async fn (Rust 1.75+) instead of the
/// `async_trait` macro. The default lint warns that auto-trait bounds (e.g.
/// `Send`) cannot be expressed on the returned futures. For this project all
/// backend implementations produce `Send` futures (tokio subprocess + reqwest
/// are both `Send`), and the engine drives them via `.await` within a single
/// tokio task, so the absence of an explicit `Send` bound is acceptable.
#[allow(async_fn_in_trait)]
pub trait SyncBackend: Send + Sync {
    /// Overwrite the remote blob with `data`.
    ///
    /// `message` is an optional human-readable commit/audit note. Backends that
    /// version the blob (e.g. git) use it as the commit message; blob stores
    /// (webdav, mock) may ignore it. This lets `avpm sync push -m` flow through
    /// to the backend.
    async fn push(&self, data: &[u8], message: Option<&str>) -> Result<()>;

    /// Pull the remote blob. Error with `RemoteNotFound` if absent.
    async fn pull(&self) -> Result<Vec<u8>>;

    /// Whether the remote blob exists.
    async fn exists(&self) -> Result<bool>;
}

// Blanket impl so any `SyncBackend` can be shared behind an `Arc` (e.g. a
// `MockBackend` exercised by two simulated devices in integration tests, or a
// backend reused across engine instances). Arc<T> is Send+Sync when T is.
impl<T: SyncBackend + ?Sized> SyncBackend for std::sync::Arc<T> {
    async fn push(&self, data: &[u8], message: Option<&str>) -> Result<()> {
        (**self).push(data, message).await
    }
    async fn pull(&self) -> Result<Vec<u8>> {
        (**self).pull().await
    }
    async fn exists(&self) -> Result<bool> {
        (**self).exists().await
    }
}

/// Re-export alias.
pub type BackendResult<T> = Result<T>;
