//! age encryption seal box.
//!
//! Pure functions wrapping the age scrypt passphrase API. Encryption produces
//! armored ASCII (PEM-style) output for git-diff friendliness. Decryption
//! auto-detects armor (requires the `armor` feature on `age`).

use age::secrecy::SecretString;
use tracing::debug;

use crate::error::Result;

/// Encrypt `plaintext` with `passphrase`, returning armored ASCII.
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<String> {
    let recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    let armored = age::encrypt_and_armor(&recipient, plaintext)?;
    debug!(
        plaintext_len = plaintext.len(),
        ciphertext_len = armored.len(),
        "age encryption ok (armored)"
    );
    Ok(armored)
}

/// Decrypt armored `ciphertext` with `passphrase`.
///
/// `age::scrypt::Identity::new` already defaults the max work factor to
/// `target + 4` (~16s), matching the spec's DoS-protection guidance (`09`
/// §3.4,4). We rely on that default rather than calling
/// `set_max_work_factor` again (the default already equals what the spec asks
/// for; reported deviation #4).
pub fn decrypt(armored: &str, passphrase: &str) -> Result<Vec<u8>> {
    let identity = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));
    let plaintext = age::decrypt(&identity, armored.as_bytes())?;
    debug!(
        ciphertext_len = armored.len(),
        plaintext_len = plaintext.len(),
        "age decryption ok"
    );
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let _g = crate::test_util::age_test_lock();
        let msg = b"hello avpm sync";
        let enc = encrypt(msg, "passphrase").unwrap();
        assert!(enc.contains("AGE ENCRYPTED FILE"));
        let dec = decrypt(&enc, "passphrase").unwrap();
        assert_eq!(dec, msg);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let _g = crate::test_util::age_test_lock();
        let enc = encrypt(b"data", "right").unwrap();
        let res = decrypt(&enc, "wrong");
        assert!(res.is_err());
    }

    #[test]
    fn random_salt_yields_different_ciphertexts() {
        let _g = crate::test_util::age_test_lock();
        let a = encrypt(b"same data", "p").unwrap();
        let b = encrypt(b"same data", "p").unwrap();
        assert_ne!(a, b, "random salt/nonce should differ ciphertexts");
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let _g = crate::test_util::age_test_lock();
        let enc = encrypt(b"", "p").unwrap();
        let dec = decrypt(&enc, "p").unwrap();
        assert!(dec.is_empty());
    }

    proptest::proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 8,
            ..proptest::test_runner::Config::default()
        })]
        #[test]
        fn age_roundtrip_prop(data in ".{0,64}") {
            let _g = crate::test_util::age_test_lock();
            let enc = encrypt(data.as_bytes(), "pass").unwrap();
            let dec = decrypt(&enc, "pass").unwrap();
            proptest::prop_assert_eq!(dec, data.as_bytes());
        }
    }
}
