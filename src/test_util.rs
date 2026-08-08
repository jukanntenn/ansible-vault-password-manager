//! Test-only helpers shared across modules.
//!
//! Currently provides a process-wide [`age_test_lock`] that serializes tests
//! performing heavy age scrypt operations. age's scrypt KDF is memory-bandwidth
//! intensive; when many such tests run in parallel the cache/memory-pressure
//! causes intermittent decrypt failures unrelated to the code under test.
//! Tests that exercise `encrypt::encrypt`/`decrypt` or `FileStore` should
//! `let _guard = age_test_lock();` at the top to run serially.

#![cfg(any(test, feature = "testing"))]

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Process-wide lock acquired by age-heavy tests to force serialization.
static AGE_GUARD: Mutex<()> = Mutex::new(());

/// Acquire the global age-test lock. Hold the returned guard for the test's
/// duration to run serially w.r.t. other age-heavy tests.
///
/// # Panics
/// Panics if the lock is poisoned (a previous holder panicked), which is the
/// correct behaviour for a test helper.
pub fn age_test_lock() -> MutexGuard<'static, ()> {
    AGE_GUARD.lock().unwrap_or_else(PoisonError::into_inner)
}
