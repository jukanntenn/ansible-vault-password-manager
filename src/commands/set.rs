//! `avpm set` - create/overwrite a vault secret.

use crate::error::Result;
use crate::index::VaultIndex;
use crate::password;
use crate::vault::VaultStore;

pub async fn execute<S: VaultStore>(
    store: &S,
    index: &VaultIndex,
    vault_id: &str,
    generate: bool,
    length: Option<usize>,
    no_symbols: bool,
) -> Result<()> {
    // Overwrite confirmation.
    if store.get(vault_id).is_ok() && !password::prompt_yes_no(&format!("Overwrite '{vault_id}'?"))?
    {
        eprintln!("aborted");
        return Ok(());
    }

    let secret = if generate {
        let len = length.unwrap_or(password::DEFAULT_LENGTH);
        password::generate(len, !no_symbols)?
    } else {
        password::prompt_confirm("Enter password")?
    };

    store.set(vault_id, &secret)?;
    index.add(vault_id)?;
    eprintln!("set '{vault_id}'");
    Ok(())
}
