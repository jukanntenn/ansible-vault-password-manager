//! `avpm-client` binary entry point — the Ansible vault password client.
//!
//! This binary exists purely so its file name ends in `-client`, which is how
//! Ansible decides to invoke a vault password script with the
//! `--vault-id <id>` argument (see Ansible's `script_is_client` in
//! `lib/ansible/parsing/vault/__init__.py`). Without the `-client` suffix,
//! Ansible would call the script with no arguments and avpm could not learn
//! which vault-id is being requested.
//!
//! The implementation is shared 1:1 with the `avpm` binary via
//! [`avpm::client_main`]; the two binaries are intentional aliases so that
//! `avpm-client` can also be used interactively (e.g. `avpm-client set dev`)
//! if the user prefers.

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    avpm::client_main()
}
