//! Encryption keys for OutLayer WASM components (feature `encryption-keys`)
//!
//! Symmetric keys that seal data only the component itself can open again. The
//! keystore derives each key inside the TEE, for this run only, under the same
//! rules as [signing keys](https://docs.rs/outlayer/latest/outlayer/signing_keys/):
//! the component names a key by `path` and the host encrypts, decrypts or
//! authenticates.
//!
//! ## Declaring Keys
//!
//! A component declares its keys, at most three, in its `outlayer.manifest`
//! custom section:
//!
//! ```json
//! "encryption_keys": [
//!   {"path": "records"},
//!   {"path": "inbox", "caller": "predecessor"},
//!   {"path": "vault-data", "vault": "vault.owner.near"}
//! ]
//! ```
//!
//! `bind` (`"project"` by default, or `"wasm"`), `caller` and `vault` work as for
//! signing keys. With `bind: "project"` every version of the project opens what
//! an earlier version sealed; with `bind: "wasm"` a new build cannot open what
//! the old one sealed. `path` is an input of the derivation: renaming it loses
//! the key and everything it sealed.
//!
//! A call passes the key's declared vault exactly: `None` for a key declared
//! without one, `Some(vault)` for a key declared with that vault.
//!
//! ## Binding and Naming Records
//!
//! - Pass the record's name as `aad`: a ciphertext copied onto another record
//!   then fails to decrypt instead of being read as that record's data.
//! - Store records under `mac(name)` rather than `name`: storage keys are
//!   visible to the storage operator, a tag is not readable as a name.
//!
//! [`storage::sealed`](crate::storage::sealed) does both on top of raw storage.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use outlayer::encryption_keys;
//!
//! let sealed = encryption_keys::encrypt("records", None, b"secret", b"record:42")?;
//! let opened = encryption_keys::decrypt("records", None, &sealed, b"record:42")?;
//! let tag = encryption_keys::mac("records", None, b"record:42")?;
//! ```

use crate::raw::encryption_keys as raw;

/// Encryption key error: the reason the host gave
#[derive(Debug, Clone)]
pub struct EncryptionKeyError(pub String);

impl std::fmt::Display for EncryptionKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Encryption key error: {}", self.0)
    }
}

impl std::error::Error for EncryptionKeyError {}

/// Result type for encryption key operations
pub type Result<T> = std::result::Result<T, EncryptionKeyError>;

/// Seal `plaintext` under the declared key at `path`, bound to `aad`
///
/// Output: `0x01 ‖ nonce (24 bytes) ‖ ciphertext ‖ tag (16 bytes)` —
/// XChaCha20-Poly1305 with a fresh random nonce, 41 bytes longer than the
/// plaintext. Two calls on the same input never return the same bytes.
///
/// # Arguments
/// * `plaintext` - At most 262144 bytes
/// * `aad` - Additional authenticated data, at most 262144 bytes; `decrypt`
///   needs the same bytes
///
/// # Example
/// ```rust,ignore
/// let sealed = encryption_keys::encrypt("records", None, b"secret", b"record:42")?;
/// ```
pub fn encrypt(path: &str, vault: Option<&str>, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    raw::encrypt(path, vault, plaintext, aad).map_err(EncryptionKeyError)
}

/// Open what [`encrypt`] sealed under the same `path`, `vault` and `aad`
///
/// # Returns
/// * `Ok(plaintext)` - Opened
/// * `Err(EncryptionKeyError)` - `"decryption failed"` for any failure to open
///   (another key, another `aad`, a tampered or truncated ciphertext, an unknown
///   format), or the reason a call was refused (undeclared path, another vault,
///   an input over the limit)
///
/// # Example
/// ```rust,ignore
/// let opened = encryption_keys::decrypt("records", None, &sealed, b"record:42")?;
/// ```
pub fn decrypt(path: &str, vault: Option<&str>, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    raw::decrypt(path, vault, ciphertext, aad).map_err(EncryptionKeyError)
}

/// HMAC-SHA256 of `data` (32 bytes) under a key derived from the declared key at `path`
///
/// The MAC key is derived for this purpose alone, never the key [`encrypt`]
/// uses. Deterministic: the same `data` under the same key gives the same tag in
/// every run that holds the key. At most 262144 bytes of data.
///
/// # Example
/// ```rust,ignore
/// let tag = encryption_keys::mac("records", None, b"record:42")?;
/// ```
pub fn mac(path: &str, vault: Option<&str>, data: &[u8]) -> Result<Vec<u8>> {
    raw::mac(path, vault, data).map_err(EncryptionKeyError)
}
