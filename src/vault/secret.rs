//! `VaultSecret` - a zeroizing newtype around `String`.
//!
//! Wrapping the password in `Zeroizing<String>` ensures the heap memory is
//! overwritten when the secret is dropped, preventing residual leakage.

use std::fmt;
use zeroize::Zeroizing;

/// A password string that wipes its memory on drop.
#[derive(Clone)]
pub struct VaultSecret(Zeroizing<String>);

impl VaultSecret {
    /// Wrap an owned `String`.
    #[must_use]
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Borrow the secret as `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for VaultSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never leak the secret via Debug.
        f.debug_struct("VaultSecret")
            .field("len", &self.len())
            .finish()
    }
}

impl From<String> for VaultSecret {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_str_roundtrips() {
        let s = VaultSecret::new("hunter2".to_string());
        assert_eq!(s.as_str(), "hunter2");
        assert_eq!(s.len(), 7);
        assert!(!s.is_empty());
    }

    #[test]
    fn debug_does_not_leak() {
        let s = VaultSecret::new("topsecret".to_string());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("topsecret"), "Debug leaked secret: {dbg}");
        assert!(dbg.contains("len"));
    }

    #[test]
    fn clone_independent() {
        let a = VaultSecret::new("x".to_string());
        let b = a.clone();
        assert_eq!(a.as_str(), b.as_str());
    }
}
