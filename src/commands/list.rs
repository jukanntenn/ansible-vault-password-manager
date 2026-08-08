//! `avpm list` - list all known vault-ids.

use crate::error::Result;
use crate::index::VaultIndex;

pub async fn execute(index: &VaultIndex) -> Result<()> {
    let ids = index.list()?;
    if ids.is_empty() {
        eprintln!("No vault-ids found");
        return Ok(());
    }
    for id in ids {
        println!("{id}");
    }
    Ok(())
}
