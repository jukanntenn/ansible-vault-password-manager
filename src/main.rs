//! `avpm` binary entry point.
//!
//! The full implementation lives in the library ([`avpm::client_main`]) so it
//! can be shared verbatim with the `avpm-client` binary (the Ansible vault
//! password client entry point, which must be named `*-client` per Ansible's
//! `script_is_client` detection).

#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    avpm::client_main()
}
