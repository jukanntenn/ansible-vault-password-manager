//! `avpm rename` - rename a vault-id.

use crate::error::{Error, Result};
use crate::index::VaultIndex;
use crate::password;
use crate::vault::{VaultError, VaultStore};

pub async fn execute<S: VaultStore>(
    store: &S,
    index: &VaultIndex,
    from: &str,
    to: &str,
) -> Result<()> {
    // Source must exist.
    let secret = match store.get(from) {
        Ok(s) => s,
        Err(Error::Vault(VaultError::NotFound(_))) => {
            return Err(Error::Vault(VaultError::NotFound(from.to_string())));
        }
        Err(e) => return Err(e),
    };

    // Destination overwrite check.
    if store.get(to).is_ok()
        && !password::prompt_yes_no(&format!("Destination '{to}' exists. Overwrite?"))?
    {
        eprintln!("aborted");
        return Ok(());
    }

    store.set(to, &secret)?;
    index.add(to)?;
    store.delete(from)?;
    index.remove(from)?;
    eprintln!("renamed '{from}' -> '{to}'");
    Ok(())
}
