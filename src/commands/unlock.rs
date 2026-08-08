//! `avpm unlock` - cache the file-store master passphrase.
//!
//! Only relevant when the OS keyring is unavailable (e.g. WSL2 without a GUI)
//! and avpm falls back to the encrypted file store. Running `unlock` once per
//! session caches the master passphrase so subsequent non-interactive calls
//! (notably ansible's `avpm --vault-id <id>`) can decrypt `store.age` without
//! prompting.

use std::path::Path;

use crate::error::Result;
use crate::paths;
use crate::vault::{master, FileStore, VaultSecret, VaultStore};

/// Execute the unlock flow.
///
/// - If `store.age` does not exist yet, prompt for a new master passphrase
///   (twice, with confirmation) and create the store by writing a probe entry.
/// - If `store.age` exists, prompt for the passphrase and verify it by
///   decrypting; a wrong passphrase exits with code 4.
/// - On success, cache the passphrase in the keyring for this session.
pub async fn execute() -> Result<()> {
    let store_path = paths::store_path();
    let passphrase = if Path::new(&store_path).exists() {
        // Existing store: verify the passphrase by decrypting. We probe by
        // reading any single entry - on a valid passphrase this succeeds (or
        // returns NotFound if the store is empty, both prove decryption worked);
        // on a wrong passphrase FileStore::get returns StoreDecrypt.
        let pass = crate::password::prompt("Master passphrase")?;
        let probe = FileStore::new(store_path.clone(), pass.as_str());
        // A get on an empty-but-valid store returns NotFound (decryption still
        // happened); a wrong passphrase returns StoreDecrypt. Both non-fatal
        // variants prove the passphrase check outcome.
        match probe.get("_avpm_unlock_probe_") {
            Ok(_) | Err(crate::error::Error::Vault(crate::vault::VaultError::NotFound(_))) => {
                pass.as_str().to_string()
            }
            Err(e) => return Err(e),
        }
    } else {
        // First run: set a new master passphrase with confirmation.
        let secret = crate::password::prompt_confirm("Set master passphrase")?;
        let pass = secret.as_str().to_string();
        // Create the store by writing an initial entry, then remove it so the
        // store exists but is empty. (FileStore::save writes the file even for
        // an empty map, but going through the trait keeps a single code path.)
        let store = FileStore::new(store_path.clone(), pass.clone());
        store.set("_avpm_init_", &VaultSecret::new(String::new()))?;
        let _ = store.delete("_avpm_init_");
        pass
    };

    // Best-effort cache: if the keyring won't hold it, the unlock still
    // verified the passphrase for this process; warn the user it won't persist
    // across processes (so a follow-up `avpm get` in a new process would need
    // `avpm unlock` again, or an interactive re-prompt).
    match master::cache(&passphrase) {
        Ok(()) => eprintln!("unlocked (master passphrase cached for this session)"),
        Err(e) => eprintln!(
            "warning: passphrase verified but could not be cached ({e});\n  \
             it will need to be re-entered in each new process"
        ),
    }
    Ok(())
}
