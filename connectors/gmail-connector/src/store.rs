//! Every record this connector keeps, sealed under the encryption key [`PATH`]
//! (declared in `manifest.json`, bound to the project, derived for the caller)
//! with the platform's host functions: the value is encrypted inside the run and
//! stored raw, so no storage operation calls the keystore, and the storage
//! operator sees a keyed tag and a ciphertext — never a record's name or value.
//! Records written without sealing are not read.

use ::outlayer::storage::sealed;
use ::outlayer::storage::{Result, StorageError};

/// The encryption key every record is sealed under.
pub const PATH: &str = "records";

/// How many times [`increment`] retries a counter another call changed first.
const INCREMENT_ATTEMPTS: usize = 16;

/// Record `name`, opened; `None` when there is none.
pub fn get(name: &str) -> Result<Option<Vec<u8>>> {
    Ok(sealed::get(PATH, None, name)?.map(|s| s.into_plaintext()))
}

pub fn set(name: &str, value: &[u8]) -> Result<()> {
    sealed::set(PATH, None, name, value)
}

/// Add `delta` to counter `name` and answer the new value, atomically: a
/// compare-and-set on the sealed record, retried while another call changed it
/// first. A missing counter starts at zero; `delta` 0 reads it.
pub fn increment(name: &str, delta: i64) -> Result<i64> {
    for _ in 0..INCREMENT_ATTEMPTS {
        match sealed::get(PATH, None, name)? {
            None => {
                if delta == 0 {
                    return Ok(0);
                }
                if sealed::set_if_absent(PATH, None, name, delta.to_string().as_bytes())? {
                    return Ok(delta);
                }
            }
            Some(current) => {
                let now: i64 = std::str::from_utf8(current.plaintext())
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| StorageError(format!("counter {name} does not hold a number")))?;
                if delta == 0 {
                    return Ok(now);
                }
                let next = now + delta;
                let (written, _) = sealed::set_if_equals(PATH, None, name, &current, next.to_string().as_bytes())?;
                if written {
                    return Ok(next);
                }
            }
        }
    }
    Err(StorageError(format!(
        "counter {name} kept changing under concurrent calls ({INCREMENT_ATTEMPTS} attempts)"
    )))
}
