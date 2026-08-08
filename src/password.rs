//! Password generation and interactive reading.
//!
//! `generate` is a pure function backed by `rand` CSPRNG (no dedicated crate).
//! `prompt_*` helpers wrap `rpassword` and write prompts to stderr so that
//! `get`'s stdout stays clean.

use crate::error::{Error, Result};
use crate::vault::VaultSecret;
use rand::seq::SliceRandom;
use rand::Rng;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";

/// Default generated password length.
pub const DEFAULT_LENGTH: usize = 32;

/// Generate a random password of `length` using a CSPRNG.
///
/// When `include_symbols` is true the character set is `[a-zA-Z0-9] + SYMBOLS`;
/// otherwise it is `[a-zA-Z0-9]`. The returned secret is wrapped in
/// [`VaultSecret`] (zeroized on drop).
///
/// # Panics
/// Never (returns an error for `length == 0`).
pub fn generate(length: usize, include_symbols: bool) -> Result<VaultSecret> {
    if length == 0 {
        return Err(Error::Other(anyhow::anyhow!("password length must be > 0")));
    }

    let mut alphabet: Vec<u8> = Vec::new();
    alphabet.extend_from_slice(LOWERCASE);
    alphabet.extend_from_slice(UPPERCASE);
    alphabet.extend_from_slice(DIGITS);
    if include_symbols {
        alphabet.extend_from_slice(SYMBOLS);
    }

    let mut rng = rand::thread_rng();
    let chars: Vec<u8> = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..alphabet.len());
            alphabet[idx]
        })
        .collect();

    // Shuffle to avoid any positional bias from fixed-order alphabet slices.
    let mut bytes = chars;
    bytes.shuffle(&mut rng);
    let s = String::from_utf8(bytes)
        .map_err(|e| Error::Other(anyhow::anyhow!("generated non-utf8 password: {e}")))?;
    Ok(VaultSecret::new(s))
}

/// Prompt for a password (hidden input) and confirmation, returning the secret.
/// Writes the prompts to stderr.
pub fn prompt_confirm(prompt: &str) -> Result<VaultSecret> {
    let first = read_password_from_stderr(&format!("{prompt}: "))?;
    let second = read_password_from_stderr("Confirm password: ")?;
    if first.as_str() != second.as_str() {
        return Err(Error::Other(anyhow::anyhow!("passwords do not match")));
    }
    Ok(first)
}

/// Prompt for a single password (no confirmation).
pub fn prompt(prompt: &str) -> Result<VaultSecret> {
    read_password_from_stderr(&format!("{prompt}: "))
}

/// Prompt for a yes/no confirmation on stderr; returns true if the user
/// answered `y` or `yes` (case-insensitive).
pub fn prompt_yes_no(prompt: &str) -> Result<bool> {
    eprint!("{prompt} [y/N] ");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| Error::Other(anyhow::anyhow!("reading confirmation: {e}")))?;
    let trimmed = line.trim().to_ascii_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

fn read_password_from_stderr(prompt: &str) -> Result<VaultSecret> {
    // `rpassword::prompt_password` writes the prompt to stderr and reads from
    // the tty, keeping stdout clean (ansible contract for `get`).
    let pw = rpassword::prompt_password(prompt)
        .map_err(|e| Error::Other(anyhow::anyhow!("reading password: {e}")))?;
    Ok(VaultSecret::new(pw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_length_is_exact() {
        for len in [1usize, 8, 20, 64] {
            let s = generate(len, true).unwrap();
            assert_eq!(s.as_str().len(), len);
        }
    }

    #[test]
    fn generate_zero_length_errors() {
        assert!(generate(0, true).is_err());
    }

    #[test]
    fn generate_without_symbols_uses_alphanumeric() {
        let s = generate(200, false).unwrap();
        for b in s.as_str().bytes() {
            let ok = b.is_ascii_alphanumeric();
            assert!(ok, "non-alphanumeric char {b:?} in no-symbols password");
        }
    }

    #[test]
    fn generate_with_symbols_can_produce_symbol() {
        // Probabilistic but with 200 chars + symbols it's essentially certain.
        let s = generate(200, true).unwrap();
        let has_symbol = s.as_str().chars().any(|c| !c.is_alphanumeric());
        assert!(has_symbol, "expected at least one symbol");
    }

    #[test]
    fn generate_is_random_across_calls() {
        let a = generate(32, true).unwrap();
        let b = generate(32, true).unwrap();
        assert_ne!(a.as_str(), b.as_str(), "passwords should differ");
    }

    proptest::proptest! {
        #[test]
        fn generate_length_prop(len in 1usize..100) {
            let s = generate(len, true).unwrap();
            proptest::prop_assert_eq!(s.as_str().len(), len);
        }
    }
}
