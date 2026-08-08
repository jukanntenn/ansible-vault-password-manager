//! `avpm rm` - remove one or more vault-ids.

use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::password;
use crate::vault::{VaultError, VaultStore};

pub async fn execute<S: VaultStore>(
    store: &S,
    index: &VaultIndex,
    vault_ids: &[String],
    force: bool,
) -> Result<()> {
    if vault_ids.is_empty() {
        return Err(Error::Other(anyhow::anyhow!(
            "rm requires at least one vault-id"
        )));
    }
    for id in vault_ids {
        if !force && !password::prompt_yes_no(&format!("Delete '{id}'?"))? {
            eprintln!("skipped '{id}'");
            continue;
        }
        match store.delete(id) {
            Ok(()) => {
                index.remove(id)?;
                eprintln!("removed '{id}'");
            }
            Err(Error::Vault(VaultError::NotFound(_))) => {
                // The store has no such entry. Also drop any stale index entry
                // so `list` (which reads the index) stays consistent with the
                // store (the keyring/file is the source of truth; the index is
                // a cache -6). `index.remove` is idempotent.
                index.remove(id)?;
                eprintln!("warning: '{id}' not found, skipping");
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
