//! `avpm config init/path/edit`.

use std::io::Write;
use std::process::Command;

use crate::cli::ConfigCmd;
use crate::config::Config;
use crate::error::{Error, Result};
use crate::password;

// We use `write!` into a `String` builder instead of `push_str(&format!(..))`
// to satisfy clippy::format_push_string.
use std::fmt::Write as _;

pub async fn execute(_cfg: &Config, cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Init => init().await,
        ConfigCmd::Path => {
            println!("{}", crate::paths::config_path().display());
            Ok(())
        }
        ConfigCmd::Edit => edit(),
    }
}

async fn init() -> Result<()> {
    let path = crate::paths::config_path();
    eprintln!("avpm config init");
    eprint!("service name [avpm]: ");
    let service = read_line_or_default("avpm")?;

    eprint!("Configure sync now? [y/N]: ");
    let do_sync = yes_no();

    let mut toml = String::new();
    // `write!` into the String builder (avoids `push_str(&format!(..))`).
    write!(&mut toml, "[default]\nservice = \"{service}\"\n").ok();

    if do_sync {
        eprint!("backend (git/webdav) [git]: ");
        let backend = read_line_or_default("git")?;
        match backend.as_str() {
            "git" => {
                eprint!("git remote URL: ");
                let remote = read_line_required("remote")?;
                toml.push_str("\n[sync]\nbackend = \"git\"\n");
                write!(&mut toml, "[sync.git]\nremote = \"{remote}\"\n").ok();
            }
            "webdav" => {
                eprint!("webdav URL: ");
                let url = read_line_required("url")?;
                eprint!("webdav username: ");
                let user = read_line_required("username")?;
                toml.push_str("\n[sync]\nbackend = \"webdav\"\n");
                write!(
                    &mut toml,
                    "[sync.webdav]\nurl = \"{url}\"\nusername = \"{user}\"\n"
                )
                .ok();
                eprintln!("note: webdav password will be prompted on first sync and stored in keyring (avpm-webdav)");
            }
            other => {
                return Err(Error::Other(anyhow::anyhow!(
                    "unknown backend '{other}' (expected git|webdav)"
                )))
            }
        }
    }

    if path.exists() && !password::prompt_yes_no(&format!("{} exists. Overwrite?", path.display()))?
    {
        eprintln!("aborted");
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::File::create(&path)?;
    f.write_all(toml.as_bytes())?;
    eprintln!("wrote {}", path.display());
    Ok(())
}

fn edit() -> Result<()> {
    let path = crate::paths::config_path();
    if !path.exists() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, b"# avpm config\n[default]\nservice = \"avpm\"\n")?;
    }
    let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".to_string());
    let status = Command::new(&editor)
        .arg(&path)
        .status()
        .map_err(|e| Error::Other(anyhow::anyhow!("running $EDITOR ({editor}): {e}")))?;
    if !status.success() {
        return Err(Error::Other(anyhow::anyhow!(
            "$EDITOR exited with status {status}"
        )));
    }
    Ok(())
}

fn read_line_or_default(default: &str) -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::Other(anyhow::anyhow!("reading input: {e}")))?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

fn read_line_required(name: &str) -> Result<String> {
    let v = read_line_or_default("")?;
    if v.is_empty() {
        Err(Error::Other(anyhow::anyhow!("{name} is required")))
    } else {
        Ok(v)
    }
}

fn yes_no() -> bool {
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let t = line.trim().to_ascii_lowercase();
    t == "y" || t == "yes"
}
