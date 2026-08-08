//! `avpm get` - print a single password to stdout.
//!
//! stdout purity is mandatory: only the password (single line) is written.
//! All diagnostics go to stderr via tracing.

use crate::error::Result;
use crate::vault::VaultStore;

pub async fn execute<S: VaultStore>(store: &S, vault_id: &str) -> Result<()> {
    let secret = store.get(vault_id)?;
    // stdout = password only (single line). Trailing newline is acceptable per
    // the ansible contract; `get_password` style clients strip it.
    println!("{}", secret.as_str());
    Ok(())
}
