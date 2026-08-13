//! Sync-domain errors (see `07` §3.3).

/// Errors raised by the sync subsystem.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync not configured. Run `avpm config init` to set up sync")]
    NotConfigured,

    #[error("backend error: {0}")]
    Backend(#[from] SyncBackendError),

    #[error("manifest serialization failed: {0}")]
    Manifest(String),

    /// `sync push` aborts when the 3-way merge finds conflicts: it must not
    /// silently pick a side. Carries the conflicting vault-ids so the CLI can
    /// tell the user to run `sync pull` to resolve interactively.
    #[error("sync push aborted: conflicts need resolution. Run `avpm sync pull` first")]
    Conflict(Vec<String>),

    #[error("decryption failed: wrong master password or corrupted data")]
    Decrypt(#[from] age::DecryptError),

    #[error("encryption failed: {0}")]
    Encrypt(#[from] age::EncryptError),
}

/// Errors raised by a sync transport backend.
#[derive(Debug, thiserror::Error)]
pub enum SyncBackendError {
    #[error("git operation failed: {message}\ncommand: {command}")]
    Git { message: String, command: String },

    #[error("webdav request failed: {0}")]
    WebDav(String),

    #[error("remote data not found. Run `avpm sync push` first")]
    RemoteNotFound,

    #[error("io error during backend operation: {0}")]
    Io(#[from] std::io::Error),
}
