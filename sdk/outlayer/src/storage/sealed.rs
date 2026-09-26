//! Sealed storage: records the component encrypts itself, under names the
//! storage operator cannot read (feature `encryption-keys`)
//!
//! A record `name` sealed under the declared encryption key (`path`, `vault`) is
//! a raw record:
//!
//! - storage key: `hex(mac(path, vault, name))` — 64 lowercase hex characters
//! - value: `encrypt(path, vault, value, aad = name)`
//!
//! That is the pattern `outlayer:encryption-keys` documents, so code without
//! this module reads and writes the same records.
//!
//! What the storage operator still sees: that a record exists, when it is
//! touched, the same tag for the same name in every run, and the value's length
//! (plaintext length + 41 bytes). [`list_keys`](super::list_keys) returns tags,
//! not names; keep an index of your own if you need to enumerate records.
//!
//! The record lives in the caller's storage, like any other storage key, and
//! opens only under the same encryption key, `vault` and `name`: a ciphertext
//! copied onto another record fails to decrypt.
//!
//! ## Compare-and-Swap
//!
//! Every encryption is randomized, so two sealings of one plaintext never share
//! bytes. [`set_if_equals`] therefore compares the stored ciphertext, never a
//! plaintext: `expected` is the [`Sealed`] that [`get`] (or a failed
//! [`set_if_equals`]) returned, which carries the bytes as stored and the
//! storage key they were read from. A [`Sealed`] read from another record —
//! another `name`, `path` or `vault` — is refused with an error, never compared.
//!
//! ## Absence
//!
//! [`has`] and [`delete`] answer a plain `bool`, as the host's `has` and
//! `delete` do: `false` is also what a failed storage call answers, so it is not
//! proof that no record exists. [`get`] tells the two apart.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use outlayer::storage::sealed;
//!
//! sealed::set("records", None, "balance:alice", b"100")?;
//!
//! let mut current = sealed::get("records", None, "balance:alice")?.ok_or("missing")?;
//! loop {
//!     let next = update(current.plaintext());
//!     match sealed::set_if_equals("records", None, "balance:alice", &current, &next)? {
//!         (true, _) => break,
//!         (false, Some(actual)) => current = actual, // changed by another run
//!         (false, None) => return Err("deleted".into()),
//!     }
//! }
//! ```

use super::{Result, StorageError};
use crate::encryption_keys::{self, EncryptionKeyError};

/// A record as read: its plaintext, the ciphertext as stored, and the storage
/// key it was read from
///
/// Pass it as `expected` to [`set_if_equals`] for the same record. It cannot be
/// built by hand, so a compare-and-swap always compares bytes that were actually
/// stored under the key it writes.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    plaintext: Vec<u8>,
    stored: Vec<u8>,
    key: String,
}

impl Sealed {
    /// The opened value
    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }

    /// The opened value, by move
    pub fn into_plaintext(self) -> Vec<u8> {
        self.plaintext
    }

    /// The ciphertext as stored
    pub fn stored_bytes(&self) -> &[u8] {
        &self.stored
    }

    /// The storage key it was read from: [`storage_key`] of its `path`, `vault`
    /// and `name`
    pub fn storage_key(&self) -> &str {
        &self.key
    }
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("plaintext_len", &self.plaintext.len())
            .field("stored_len", &self.stored.len())
            .finish()
    }
}

/// The storage key a sealed record `name` is stored under: `hex(mac(path, vault, name))`
///
/// # Example
/// ```rust,ignore
/// let key = sealed::storage_key("records", None, "balance:alice")?;
/// assert_eq!(key.len(), 64);
/// ```
pub fn storage_key(path: &str, vault: Option<&str>, name: &str) -> Result<String> {
    let tag = encryption_keys::mac(path, vault, name.as_bytes()).map_err(key_error)?;
    Ok(storage_key_from_tag(&tag))
}

/// Seal `value` and store it as record `name`
///
/// # Returns
/// * `Ok(())` - Value stored successfully
/// * `Err(StorageError)` - Encryption key or storage operation failed
///
/// # Example
/// ```rust,ignore
/// sealed::set("records", None, "balance:alice", b"100")?;
/// ```
pub fn set(path: &str, vault: Option<&str>, name: &str, value: &[u8]) -> Result<()> {
    let key = storage_key(path, vault, name)?;
    let stored = seal(path, vault, name, value)?;
    super::set_raw(&key, &stored)
}

/// Read and open record `name`
///
/// # Returns
/// * `Ok(Some(Sealed))` - Record found and opened
/// * `Ok(None)` - No such record
/// * `Err(StorageError)` - Encryption key or storage operation failed, or the
///   stored bytes do not open under this key and name
///
/// # Example
/// ```rust,ignore
/// if let Some(record) = sealed::get("records", None, "balance:alice")? {
///     println!("{:?}", record.plaintext());
/// }
/// ```
pub fn get(path: &str, vault: Option<&str>, name: &str) -> Result<Option<Sealed>> {
    let key = storage_key(path, vault, name)?;
    match super::get_raw(&key)? {
        Some(stored) => open(path, vault, name, key, stored).map(Some),
        None => Ok(None),
    }
}

/// Seal `value` and store it as record `name` only if no record is stored there
///
/// # Returns
/// * `Ok(true)` - Value was inserted
/// * `Ok(false)` - A record already existed (value not changed)
/// * `Err(StorageError)` - Encryption key or storage operation failed
///
/// # Example
/// ```rust,ignore
/// sealed::set_if_absent("records", None, "balance:alice", b"0")?;
/// ```
pub fn set_if_absent(path: &str, vault: Option<&str>, name: &str, value: &[u8]) -> Result<bool> {
    let key = storage_key(path, vault, name)?;
    let stored = seal(path, vault, name, value)?;
    super::set_if_absent_raw(&key, &stored)
}

/// Replace record `name` only if it still holds exactly the ciphertext `expected` was read from
///
/// `expected` must have been read from this record — the same `path`, `vault`
/// and `name`. One read from another record is an error, and nothing is written
/// or compared.
///
/// # Returns
/// * `Ok((true, None))` - Value was updated
/// * `Ok((false, Some(current)))` - The record changed; returns it, opened, for retry
/// * `Ok((false, None))` - No such record
/// * `Err(StorageError)` - `expected` belongs to another record, the encryption
///   key or storage operation failed, or the current bytes do not open under
///   this key and name
///
/// # Example
/// ```rust,ignore
/// let current = sealed::get("records", None, "balance:alice")?.ok_or("missing")?;
/// let (updated, _) = sealed::set_if_equals("records", None, "balance:alice", &current, b"90")?;
/// ```
pub fn set_if_equals(
    path: &str,
    vault: Option<&str>,
    name: &str,
    expected: &Sealed,
    new_value: &[u8],
) -> Result<(bool, Option<Sealed>)> {
    let key = storage_key(path, vault, name)?;
    check_same_record(expected, &key)?;
    let stored = seal(path, vault, name, new_value)?;
    match super::set_if_equals_raw(&key, &expected.stored, &stored)? {
        (true, _) => Ok((true, None)),
        (false, Some(current)) => Ok((false, Some(open(path, vault, name, key, current)?))),
        (false, None) => Ok((false, None)),
    }
}

/// Delete record `name`
///
/// # Returns
/// * `Ok(true)` - Record existed and was deleted
/// * `Ok(false)` - No record was deleted: none existed, **or the storage call
///   failed** — the host answers both with `false`, so this is not proof of
///   absence. Read the record with [`get`] to tell them apart.
/// * `Err(StorageError)` - Encryption key operation failed
pub fn delete(path: &str, vault: Option<&str>, name: &str) -> Result<bool> {
    Ok(super::delete(&storage_key(path, vault, name)?))
}

/// Check whether record `name` exists
///
/// # Returns
/// * `Ok(true)` - A record is stored under this name
/// * `Ok(false)` - No record was found: none exists, **or the storage call
///   failed** — the host answers both with `false`, so this is not proof of
///   absence. Use [`get`], which returns a failed call as `Err`, where absence
///   decides anything.
/// * `Err(StorageError)` - Encryption key operation failed
pub fn has(path: &str, vault: Option<&str>, name: &str) -> Result<bool> {
    Ok(super::has(&storage_key(path, vault, name)?))
}

fn seal(path: &str, vault: Option<&str>, name: &str, value: &[u8]) -> Result<Vec<u8>> {
    encryption_keys::encrypt(path, vault, value, aad(name)).map_err(key_error)
}

fn open(path: &str, vault: Option<&str>, name: &str, key: String, stored: Vec<u8>) -> Result<Sealed> {
    let plaintext = encryption_keys::decrypt(path, vault, &stored, aad(name)).map_err(key_error)?;
    Ok(Sealed { plaintext, stored, key })
}

/// Refuse a handle read from a record other than the one stored under `key`:
/// compared against this record's bytes it could only ever lose, which reads
/// as endless contention
fn check_same_record(expected: &Sealed, key: &str) -> Result<()> {
    if expected.key == key {
        Ok(())
    } else {
        Err(StorageError(
            "set_if_equals: `expected` was read from another record (another name, path or vault); \
             pass what `get` returned for this record"
                .to_string(),
        ))
    }
}

/// The additional authenticated data a record is sealed under: its name's bytes
fn aad(name: &str) -> &[u8] {
    name.as_bytes()
}

/// Lowercase hex of a MAC tag
fn storage_key_from_tag(tag: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut key = String::with_capacity(tag.len() * 2);
    for byte in tag {
        key.push(HEX[(byte >> 4) as usize] as char);
        key.push(HEX[(byte & 0x0f) as usize] as char);
    }
    key
}

fn key_error(e: EncryptionKeyError) -> StorageError {
    StorageError(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_key_is_lowercase_hex_of_the_tag() {
        let tag: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(37).wrapping_add(0xa5)).collect();
        let key = storage_key_from_tag(&tag);
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let decoded: Vec<u8> = (0..key.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&key[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(decoded, tag);
    }

    #[test]
    fn storage_key_known_values() {
        assert_eq!(storage_key_from_tag(&[]), "");
        assert_eq!(storage_key_from_tag(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(storage_key_from_tag(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn aad_is_the_name_bytes() {
        assert_eq!(aad("balance:alice"), b"balance:alice");
        assert_eq!(aad(""), b"");
        assert_eq!(aad("ключ"), "ключ".as_bytes());
        assert_ne!(aad("a"), aad("b"));
    }

    #[test]
    fn debug_hides_the_plaintext() {
        let record = Sealed { plaintext: b"secret".to_vec(), stored: vec![1; 47], key: "ab".repeat(32) };
        let shown = format!("{:?}", record);
        assert!(!shown.contains("secret"));
        assert_eq!(shown, "Sealed { plaintext_len: 6, stored_len: 47 }");
    }

    #[test]
    fn a_handle_is_accepted_only_for_the_record_it_was_read_from() {
        let key_a = storage_key_from_tag(&[0xaa; 32]);
        let key_b = storage_key_from_tag(&[0xbb; 32]);
        let from_a = Sealed { plaintext: b"1".to_vec(), stored: vec![7; 42], key: key_a.clone() };
        assert_eq!(from_a.storage_key(), key_a);
        assert!(check_same_record(&from_a, &key_a).is_ok());
        let err = check_same_record(&from_a, &key_b).expect_err("another record");
        assert!(err.0.contains("read from another record"), "{err}");
        assert!(!err.0.contains(&key_a) && !err.0.contains(&key_b), "the message names no key");
    }

    #[test]
    fn handles_of_one_ciphertext_under_two_keys_differ() {
        let a = Sealed { plaintext: b"1".to_vec(), stored: vec![7; 42], key: "aa".repeat(32) };
        let b = Sealed { key: "bb".repeat(32), ..a.clone() };
        assert_ne!(a, b);
    }
}
