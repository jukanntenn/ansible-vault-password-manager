//! Tracing initialization (see `06-logging.md`).
//!
//! Default level is `info` (high observability during the eat-own-dogfood
//! phase). Verbosity flags map `-v`=info, `-vv`=debug, `-vvv`=trace, `-q`=error.
//! `RUST_LOG` env var takes precedence over CLI flags.

use tracing_subscriber::{fmt, EnvFilter};

/// Initialize the global tracing subscriber.
///
/// Idempotent: subsequent calls are no-ops (safe to call from tests that share
/// a process). All logs go to **stderr**; `get`'s stdout stays clean for the
/// ansible password contract.
pub fn init(verbose: u8, quiet: bool) {
    let default_filter = if quiet {
        "avpm=error"
    } else {
        match verbose {
            0 | 1 => "avpm=info",
            2 => "avpm=debug",
            _ => "avpm=trace",
        }
    };

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    // `try_init` returns Err if a subscriber is already installed (e.g. shared
    // test process); ignore that case.
    let _ = fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}
