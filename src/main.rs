//! Entry point: tokio runtime + CLI parse + config load + dispatch + exit code.
//!1,2.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]
#![warn(clippy::all, clippy::pedantic)]
// The `Error` enum (library aggregate) is intentionally large; returning it
// from `runtime_main` is fine. Mirrors the lib-level allow.
#![allow(clippy::result_large_err, clippy::missing_errors_doc)]

use std::process::ExitCode;

use avpm::cli::Cli;
use avpm::commands;
use avpm::config::Config;
use avpm::error::Error;
use avpm::logging;

use clap::Parser;

#[tokio::main]
async fn runtime_main() -> Result<(), Error> {
    let cli = Cli::parse();
    logging::init(cli.verbose, cli.quiet);
    let cfg = Config::load(cli.config.as_deref())?;
    commands::dispatch(&cli, &cfg).await
}

fn main() -> ExitCode {
    match runtime_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let code = e.exit_code();
            eprintln!("Error: {e}");
            ExitCode::from(code)
        }
    }
}
