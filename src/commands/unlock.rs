//! `avpm unlock` - cache credentials for the active backend.
//!
//! Behavior depends on the resolved backend ([`super::backend_kind`]):
//!
//! - **Keyring backend** (macOS Keychain / Linux Secret Service): ensure the
//!   default collection exists and is unlocked. On a fresh headless/WSL2 box
//!   the (`login`) default collection may be absent or locked; this creates it
//!   (GUI prompt) or unlocks it (GUI prompt) so subsequent reads/writes —
//!   including ansible's non-interactive `avpm-client --vault-id <id>` — work
//!   without a prompt. It never creates `store.age`, so a user who runs `avpm
//!   unlock` on a keyring-capable system is not pulled onto the file backend.
//!
//! - **File backend** (keyring unavailable, e.g. headless WSL2): the file
//!   store encrypts `store.age` with a master passphrase. `unlock` verifies
//!   (existing store) or sets (first run) that passphrase and caches it in
//!   the session keyring so subsequent non-interactive calls — notably
//!   ansible's `avpm-client --vault-id <id>` — can decrypt without prompting.
//!   It does **not** create an empty `store.age`; the file is born naturally
//!   on the first real `set`.

use std::path::Path;

use crate::config::Config;
use crate::error::Result;
use crate::paths;
use crate::vault::{master, FileStore, VaultError, VaultStore};

use super::backend_kind;
use crate::config::StorageBackend;

/// Execute the unlock flow, dispatching on the resolved backend.
pub async fn execute(cfg: &Config) -> Result<()> {
    match backend_kind(cfg) {
        StorageBackend::Keyring => {
            // Create the default collection if absent (GUI prompt) and unlock
            // it if locked (GUI prompt). Idempotent: a ready collection is a
            // no-op. This is the one command responsible for making the
            // keyring backend usable after a daemon restart on WSL2/headless.
            crate::vault::ss::ensure_default_collection()?;
            eprintln!(
                "keyring backend ready (default collection exists and is unlocked).\n  \
                 passwords are stored in the OS keyring and are available \
                 without a separate per-command unlock step."
            );
            Ok(())
        }
        // backend_kind collapses Auto into Keyring/File, so File (and the
        // collapsed Auto) both route to the file-store unlock flow.
        StorageBackend::File | StorageBackend::Auto => unlock_file_store().await,
    }
}

/// File-backend unlock: verify or set the master passphrase, then cache it.
///
/// - If `store.age` exists, prompt for the passphrase and verify it by
///   decrypting (a wrong passphrase surfaces as `StoreDecrypt`, exit 4).
/// - If `store.age` does not exist yet (first run), prompt for a new
///   passphrase with confirmation. No empty `store.age` is written; the file
///   is created naturally on the first real `set`.
/// - On success, cache the passphrase in the session keyring.
async fn unlock_file_store() -> Result<()> {
    let store_path = paths::store_path();
    let passphrase = if Path::new(&store_path).exists() {
        // Existing store: verify the passphrase by decrypting. We probe by
        // reading any single entry - on a valid passphrase this succeeds (or
        // returns NotFound if the store is empty, both prove decryption
        // worked); on a wrong passphrase FileStore::get returns StoreDecrypt.
        let pass = crate::password::prompt("Master passphrase")?;
        let probe = FileStore::new(store_path.clone(), pass.as_str());
        match probe.get("_avpm_unlock_probe_") {
            Ok(_) | Err(crate::error::Error::Vault(VaultError::NotFound(_))) => {
                pass.as_str().to_string()
            }
            Err(e) => return Err(e),
        }
    } else {
        // First run: set a new master passphrase with confirmation. The
        // store file is NOT created here; it will be born on the first real
        // `set`, encrypted with this passphrase. We only cache the passphrase
        // so the upcoming `set` (and ansible's non-interactive calls) can
        // proceed without re-prompting.
        let secret = crate::password::prompt_confirm("Set master passphrase")?;
        secret.as_str().to_string()
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
