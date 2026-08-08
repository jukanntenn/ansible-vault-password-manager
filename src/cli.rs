//! CLI definition (clap derive,3,

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// avpm - Ansible Vault Password Manager.
#[derive(Parser, Debug)]
#[command(name = "avpm", version, about = "Ansible Vault Password Manager — a minimal keyring adapter with encrypted sync", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Ansible client-script compatibility: `avpm --vault-id dev` => `get dev`.
    #[arg(long = "vault-id", global = true, hide = true)]
    pub vault_id: Option<String>,

    /// Log verbosity (repeatable: -v info, -vv debug, -vvv trace).
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Quiet mode (errors only).
    #[arg(short = 'q', long = "quiet", global = true)]
    pub quiet: bool,

    /// Override the config file path.
    #[arg(long = "config", global = true)]
    pub config: Option<PathBuf>,

    /// Positional fallback: `avpm <vault-id>` => `get <vault-id>`.
    #[arg(trailing_var_arg = true, hide = true)]
    pub positional: Vec<String>,
}

/// Top-level subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Print the password for a vault-id to stdout (ansible contract).
    Get { vault_id: String },

    /// Set or overwrite a vault-id's password.
    Set {
        vault_id: String,
        #[arg(short = 'g', long = "generate")]
        generate: bool,
        #[arg(short = 'L', long = "length")]
        length: Option<usize>,
        #[arg(long = "no-symbols")]
        no_symbols: bool,
    },

    /// Remove one or more vault-ids.
    Rm {
        vault_ids: Vec<String>,
        #[arg(short = 'f', long = "force")]
        force: bool,
    },

    /// List all known vault-ids.
    List,

    /// Show a password in a secure TUI view (hold Space to reveal).
    Show { vault_id: String },

    /// Rename a vault-id.
    Rename { from: String, to: String },

    /// Open the full interactive TUI.
    Tui,

    /// Cache the master passphrase for the file store (one-time per session).
    ///
    /// Only relevant when the OS keyring is unavailable and avpm falls back to
    /// the encrypted file store. Required before ansible can call `avpm
    /// --vault-id <id>` non-interactively.
    Unlock,

    /// Encrypted multi-device sync.
    Sync {
        #[command(subcommand)]
        cmd: SyncCmd,
    },

    /// Configuration management.
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
}

/// `avpm sync` subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum SyncCmd {
    /// Encrypt local vaults and push to the remote.
    Push {
        #[arg(short = 'm', long = "message")]
        message: Option<String>,
    },
    /// Pull and merge the remote into local.
    Pull,
    /// Compare local vs remote without modifying anything.
    Status,
}

/// `avpm config` subcommands.
#[derive(Subcommand, Debug, Clone)]
pub enum ConfigCmd {
    /// Interactively generate a config file.
    Init,
    /// Print the config file path.
    Path,
    /// Open the config file in `$EDITOR`.
    Edit,
}
