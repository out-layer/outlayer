//! Persistent storage API for OutLayer WASM components
//!
//! Storage is persisted across executions. For projects, storage is shared
//! across all versions. `set`/`get` and the conditional writes store records
//! encrypted by the keystore; the `_raw` functions store the component's bytes
//! as given. Each record keeps the mode it was written in, and a function of the
//! other mode refuses it with an error.
//!
//! ## Basic Usage
//!
//! ```rust,ignore
//! use outlayer::storage;
//!
//! // Store a value
//! storage::set("my-key", b"my-value")?;
//!
//! // Retrieve a value
//! if let Some(value) = storage::get("my-key")? {
//!     println!("Got: {:?}", value);
//! }
//!
//! // Check if key exists
//! if storage::has("my-key") {
//!     println!("Key exists!");
//! }
//!
//! // Delete a key
//! storage::delete("my-key");
//!
//! // List keys with prefix
//! let keys = storage::list_keys("prefix:")?;
//! ```
//!
//! ## Whose cell
//!
//! Every function outside the `_worker` ones reads and writes one account's
//! cell of the project, and no function takes an account: the worker fixes it
//! before the run starts, from the manifest's `storage_account` and the job.
//! `"signer"` (the default) is the transaction's signer on chain and the
//! payment key's owner over HTTPS. `"predecessor"` is the account that called
//! the contract on chain — a relaying contract, not the user who signed — and
//! the payment key's owner over HTTPS; a run with no predecessor is refused.
//! Records sealed with a `caller: "predecessor"` encryption key belong in the
//! `"predecessor"` cell, so the key and the cell name one account.
//!
//! ```json
//! { "storage_account": "predecessor" }
//! ```
//!
//! ## Worker-Private Storage
//!
//! Worker-private storage is only accessible from within WASM code, not by the user.
//! Use this for internal state that shouldn't be exposed.
//!
//! ```rust,ignore
//! use outlayer::storage;
//!
//! // Store worker-private data
//! storage::set_worker("internal-state", b"secret")?;
//!
//! // Retrieve worker-private data
//! let state = storage::get_worker("internal-state")?;
//! ```
//!
//! ## Version Migration
//!
//! When upgrading your WASM, you can read data from a previous version:
//!
//! ```rust,ignore
//! use outlayer::storage;
//!
//! // Read from previous WASM version (by its SHA256 hash)
//! let old_data = storage::get_by_version("my-key", "abc123...")?;
//! ```
//!
//! ## Raw Storage
//!
//! [`set_raw`], [`get_raw`], [`set_if_absent_raw`] and [`set_if_equals_raw`]
//! store bytes as given, in the same per-account storage and key namespace as
//! [`set`]/[`get`], with no keystore call. The key name and the value are stored
//! in plaintext and the operator can read both: encrypt the value first (with
//! `encryption_keys`) and keep secrets out of key names. `storage::sealed`
//! (feature `encryption-keys`) does both.
//!
//! A key holds one record in one mode: [`get_raw`] on a key written with [`set`]
//! (or [`get`] on a key written with [`set_raw`]) is an error, and no write
//! converts a record from one mode to the other — delete it first. [`has`],
//! [`delete`] and [`list_keys`] work on records of both modes.
//!
//! ```rust,ignore
//! use outlayer::storage;
//!
//! storage::set_raw("blob", &ciphertext)?;
//! let blob = storage::get_raw("blob")?;
//! ```

use crate::near::storage::api as raw;

#[cfg(feature = "encryption-keys")]
pub mod sealed;

/// Storage error
#[derive(Debug, Clone)]
pub struct StorageError(pub String);

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Storage error: {}", self.0)
    }
}

impl std::error::Error for StorageError {}

/// Result type for storage operations
pub type Result<T> = std::result::Result<T, StorageError>;

/// Store a value by key
///
/// # Arguments
/// * `key` - The key to store the value under
/// * `value` - The value to store (as bytes)
///
/// # Returns
/// * `Ok(())` - Value stored successfully
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// storage::set("user:123", b"Alice")?;
/// storage::set("config", serde_json::to_vec(&config)?)?;
/// ```
pub fn set(key: &str, value: &[u8]) -> Result<()> {
    let error = raw::set(key, value);
    if error.is_empty() {
        Ok(())
    } else {
        Err(StorageError(error))
    }
}

/// Get a value by key
///
/// # Arguments
/// * `key` - The key to retrieve
///
/// # Returns
/// * `Ok(Some(bytes))` - Value found
/// * `Ok(None)` - Key doesn't exist
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// if let Some(data) = storage::get("user:123")? {
///     let name = String::from_utf8(data)?;
///     println!("User name: {}", name);
/// }
/// ```
pub fn get(key: &str) -> Result<Option<Vec<u8>>> {
    let (data, error) = raw::get(key);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    if data.is_empty() {
        Ok(None)
    } else {
        Ok(Some(data))
    }
}

/// Check if a key exists
///
/// # Arguments
/// * `key` - The key to check
///
/// # Returns
/// * `true` - Key exists
/// * `false` - Key doesn't exist, **or the storage call failed**: the host
///   answers both with `false`, so this is not proof of absence. Where absence
///   decides anything, read the key with [`get`] or [`get_raw`], which return a
///   failed call as `Err`.
///
/// # Example
/// ```rust,ignore
/// if storage::has("session:abc") {
///     // Session exists, continue
/// } else {
///     // Create new session
/// }
/// ```
pub fn has(key: &str) -> bool {
    raw::has(key)
}

/// Delete a key
///
/// # Arguments
/// * `key` - The key to delete
///
/// # Returns
/// * `true` - Key existed and was deleted
/// * `false` - Nothing was deleted: the key didn't exist, **or the storage call
///   failed** — the host answers both with `false`, so this is not proof that
///   the key is gone. Read it back with [`get`] or [`get_raw`] where that
///   matters.
///
/// # Example
/// ```rust,ignore
/// if storage::delete("session:abc") {
///     println!("Session deleted");
/// }
/// ```
pub fn delete(key: &str) -> bool {
    raw::delete(key)
}

/// List all keys with optional prefix filter
///
/// # Arguments
/// * `prefix` - Prefix to filter keys (empty string for all keys)
///
/// # Returns
/// * `Ok(Vec<String>)` - List of matching keys
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// // List all keys
/// let all_keys = storage::list_keys("")?;
///
/// // List only user keys
/// let user_keys = storage::list_keys("user:")?;
/// for key in user_keys {
///     println!("Found user key: {}", key);
/// }
/// ```
pub fn list_keys(prefix: &str) -> Result<Vec<String>> {
    let (keys_json, error) = raw::list_keys(prefix);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    serde_json::from_str(&keys_json)
        .map_err(|e| StorageError(format!("Failed to parse keys list: {}", e)))
}

/// Store worker-private data
///
/// Worker-private storage is only accessible from within WASM code.
/// The user cannot read this data through the API.
///
/// # Arguments
/// * `key` - The key to store the value under
/// * `value` - The value to store (as bytes)
///
/// # Returns
/// * `Ok(())` - Value stored successfully
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// // Store internal state that user shouldn't see
/// storage::set_worker("last_run_timestamp", &timestamp.to_le_bytes())?;
/// ```
pub fn set_worker(key: &str, value: &[u8]) -> Result<()> {
    set_worker_with_options(key, value, None)
}

/// Store worker data with encryption control
///
/// # Arguments
/// * `key` - The key to store the value under
/// * `value` - The value to store (as bytes)
/// * `is_encrypted` - None or Some(true) = encrypted (default), Some(false) = plaintext (readable by other projects)
///
/// # Example
/// ```rust,ignore
/// // Store public data that other projects can read (e.g., oracle price feed)
/// storage::set_worker_with_options("price:ETH", price_bytes, Some(false))?;
/// ```
pub fn set_worker_with_options(key: &str, value: &[u8], is_encrypted: Option<bool>) -> Result<()> {
    let error = raw::set_worker(key, value, is_encrypted);
    if error.is_empty() {
        Ok(())
    } else {
        Err(StorageError(error))
    }
}

/// Get worker-private data
///
/// # Arguments
/// * `key` - The key to retrieve
///
/// # Returns
/// * `Ok(Some(bytes))` - Value found
/// * `Ok(None)` - Key doesn't exist
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// if let Some(data) = storage::get_worker("last_run_timestamp")? {
///     let timestamp = u64::from_le_bytes(data.try_into()?);
///     println!("Last run: {}", timestamp);
/// }
/// ```
pub fn get_worker(key: &str) -> Result<Option<Vec<u8>>> {
    get_worker_from_project(key, None)
}

/// Get worker data from another project (public data only)
///
/// # Arguments
/// * `key` - The key to retrieve
/// * `project` - None = current project; Some(project) = read public data from
///   another project, named either by its name `"owner.near/project-name"` or by
///   its uuid `"p0000000000000001"` (`p` + 16 lowercase hex; the project's own
///   code sees it as `OUTLAYER_PROJECT_UUID`)
///
/// # Returns
/// * `Ok(Some(bytes))` - Value found
/// * `Ok(None)` - Key doesn't exist, or (cross-project) no such project
/// * `Err(StorageError)` - Storage operation failed; cross-project, also a key
///   stored encrypted (not public) and a project in neither form
///
/// # Example
/// ```rust,ignore
/// // Read a public oracle price from another project, by name
/// if let Some(price_data) = storage::get_worker_from_project("price:ETH", Some("oracle.near/price-feed"))? {
///     let price = f64::from_le_bytes(price_data.try_into()?);
///     println!("ETH price: ${}", price);
/// }
/// // ...or by uuid
/// let same = storage::get_worker_from_project("price:ETH", Some("p0000000000000042"))?;
/// ```
pub fn get_worker_from_project(key: &str, project: Option<&str>) -> Result<Option<Vec<u8>>> {
    let (data, error) = raw::get_worker(key, project);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    if data.is_empty() {
        Ok(None)
    } else {
        Ok(Some(data))
    }
}

/// Get data from a specific WASM version (for migration)
///
/// Use this when upgrading your WASM to read data written by a previous version.
///
/// # Arguments
/// * `key` - The key to retrieve
/// * `wasm_hash` - SHA256 hash of the previous WASM version
///
/// # Returns
/// * `Ok(Some(bytes))` - Value found
/// * `Ok(None)` - Key doesn't exist for that version
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// // Migrate data from previous version
/// const OLD_VERSION_HASH: &str = "abc123...";
///
/// if let Some(old_data) = storage::get_by_version("config", OLD_VERSION_HASH)? {
///     // Transform old data format to new format
///     let new_data = migrate_config(old_data);
///     storage::set("config", &new_data)?;
/// }
/// ```
pub fn get_by_version(key: &str, wasm_hash: &str) -> Result<Option<Vec<u8>>> {
    let (data, error) = raw::get_by_version(key, wasm_hash);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    if data.is_empty() {
        Ok(None)
    } else {
        Ok(Some(data))
    }
}

/// Clear all storage of the current project in this run's account cell
///
/// **WARNING**: This deletes ALL data. Use with caution!
///
/// # Returns
/// * `Ok(())` - Storage cleared successfully
/// * `Err(StorageError)` - Operation failed
///
/// # Example
/// ```rust,ignore
/// // Clear all storage (dangerous!)
/// storage::clear_all()?;
/// ```
pub fn clear_all() -> Result<()> {
    let error = raw::clear_all();
    if error.is_empty() {
        Ok(())
    } else {
        Err(StorageError(error))
    }
}

/// Clear storage written by a specific WASM version
///
/// Use this to clean up data from old versions after migration.
///
/// # Arguments
/// * `wasm_hash` - SHA256 hash of the WASM version to clear
///
/// # Returns
/// * `Ok(())` - Storage cleared successfully
/// * `Err(StorageError)` - Operation failed
///
/// # Example
/// ```rust,ignore
/// // After successful migration, clear old version's data
/// storage::clear_version("abc123...")?;
/// ```
pub fn clear_version(wasm_hash: &str) -> Result<()> {
    let error = raw::clear_version(wasm_hash);
    if error.is_empty() {
        Ok(())
    } else {
        Err(StorageError(error))
    }
}

// ==================== Convenience Functions ====================

/// Store a string value
///
/// Convenience wrapper around `set()` for string values.
///
/// # Example
/// ```rust,ignore
/// storage::set_string("name", "Alice")?;
/// ```
pub fn set_string(key: &str, value: &str) -> Result<()> {
    set(key, value.as_bytes())
}

/// Get a string value
///
/// Convenience wrapper around `get()` that returns a String.
///
/// # Returns
/// * `Ok(Some(String))` - Value found and valid UTF-8
/// * `Ok(None)` - Key doesn't exist
/// * `Err(StorageError)` - Storage error or invalid UTF-8
///
/// # Example
/// ```rust,ignore
/// if let Some(name) = storage::get_string("name")? {
///     println!("Hello, {}!", name);
/// }
/// ```
pub fn get_string(key: &str) -> Result<Option<String>> {
    match get(key)? {
        Some(data) => {
            String::from_utf8(data)
                .map(Some)
                .map_err(|e| StorageError(format!("Invalid UTF-8: {}", e)))
        }
        None => Ok(None),
    }
}

/// Store a JSON-serializable value
///
/// Serializes the value to JSON and stores it.
///
/// # Example
/// ```rust,ignore
/// #[derive(Serialize)]
/// struct Config {
///     max_retries: u32,
///     timeout_ms: u64,
/// }
///
/// let config = Config { max_retries: 3, timeout_ms: 5000 };
/// storage::set_json("config", &config)?;
/// ```
pub fn set_json<T: serde::Serialize>(key: &str, value: &T) -> Result<()> {
    let json = serde_json::to_vec(value)
        .map_err(|e| StorageError(format!("JSON serialization failed: {}", e)))?;
    set(key, &json)
}

/// Get a JSON-deserializable value
///
/// Retrieves the value and deserializes from JSON.
///
/// # Returns
/// * `Ok(Some(T))` - Value found and deserialized
/// * `Ok(None)` - Key doesn't exist
/// * `Err(StorageError)` - Storage error or JSON parse error
///
/// # Example
/// ```rust,ignore
/// #[derive(Deserialize)]
/// struct Config {
///     max_retries: u32,
///     timeout_ms: u64,
/// }
///
/// if let Some(config) = storage::get_json::<Config>("config")? {
///     println!("Max retries: {}", config.max_retries);
/// }
/// ```
pub fn get_json<T: serde::de::DeserializeOwned>(key: &str) -> Result<Option<T>> {
    match get(key)? {
        Some(data) => {
            serde_json::from_slice(&data)
                .map(Some)
                .map_err(|e| StorageError(format!("JSON deserialization failed: {}", e)))
        }
        None => Ok(None),
    }
}

// ==================== Raw Operations ====================

/// Store bytes as given, with no keystore encryption
///
/// The key name and the value are stored in plaintext: the storage operator can
/// read both. Encrypt the value first (with `encryption_keys`, or use
/// `storage::sealed`) and keep secrets out of key names.
///
/// # Returns
/// * `Ok(())` - Value stored successfully
/// * `Err(StorageError)` - Storage operation failed, or the key holds a record
///   written with [`set`]
///
/// # Example
/// ```rust,ignore
/// storage::set_raw("blob", &ciphertext)?;
/// ```
pub fn set_raw(key: &str, value: &[u8]) -> Result<()> {
    let error = raw::set_raw(key, value);
    if error.is_empty() {
        Ok(())
    } else {
        Err(StorageError(error))
    }
}

/// Get the bytes stored by [`set_raw`]
///
/// # Returns
/// * `Ok(Some(bytes))` - Value found
/// * `Ok(None)` - Key doesn't exist
/// * `Err(StorageError)` - Storage operation failed, or the key holds a record
///   written with [`set`]
///
/// # Example
/// ```rust,ignore
/// if let Some(blob) = storage::get_raw("blob")? {
///     // decrypt blob
/// }
/// ```
pub fn get_raw(key: &str) -> Result<Option<Vec<u8>>> {
    let (data, error) = raw::get_raw(key);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    if data.is_empty() {
        Ok(None)
    } else {
        Ok(Some(data))
    }
}

/// Store bytes as given only if the key holds no record, in either mode
///
/// The key name and the value are stored in plaintext, as with [`set_raw`].
///
/// # Returns
/// * `Ok(true)` - Value was inserted
/// * `Ok(false)` - Key already held a record (value not changed)
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// if storage::set_if_absent_raw("blob", &ciphertext)? {
///     println!("Stored");
/// }
/// ```
pub fn set_if_absent_raw(key: &str, value: &[u8]) -> Result<bool> {
    let (inserted, error) = raw::set_if_absent_raw(key, value);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    Ok(inserted)
}

/// Compare-and-swap on raw bytes: replace the value only if the stored bytes
/// equal `expected` exactly
///
/// The key name and the value are stored in plaintext, as with [`set_raw`].
/// Ciphertexts from `encryption_keys::encrypt` are randomized, so `expected`
/// must be the stored bytes as read, never a fresh encryption of the same
/// plaintext.
///
/// # Returns
/// * `Ok((true, None))` - Value was updated
/// * `Ok((false, Some(current)))` - Stored bytes didn't match; returns them for retry
/// * `Ok((false, None))` - Key doesn't exist
/// * `Err(StorageError)` - Storage operation failed, or the key holds a record
///   written with [`set`]
///
/// # Example
/// ```rust,ignore
/// let current = storage::get_raw("blob")?.unwrap_or_default();
/// match storage::set_if_equals_raw("blob", &current, &next)? {
///     (true, _) => {}                   // Updated
///     (false, Some(actual)) => { /* retry with actual */ }
///     (false, None) => { /* key was deleted */ }
/// }
/// ```
pub fn set_if_equals_raw(key: &str, expected: &[u8], new_value: &[u8]) -> Result<(bool, Option<Vec<u8>>)> {
    let (success, current, error) = raw::set_if_equals_raw(key, expected, new_value);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    if success {
        Ok((true, None))
    } else if current.is_empty() {
        Ok((false, None))
    } else {
        Ok((false, Some(current)))
    }
}

// ==================== Conditional Write Operations ====================

/// Set a key only if it doesn't already exist
///
/// # Arguments
/// * `key` - The key to store the value under
/// * `value` - The value to store (as bytes)
///
/// # Returns
/// * `Ok(true)` - Value was inserted (key didn't exist)
/// * `Ok(false)` - Key already existed (value not changed)
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// // Initialize counter only if not exists
/// if storage::set_if_absent("counter", &0i64.to_le_bytes())? {
///     println!("Counter initialized to 0");
/// } else {
///     println!("Counter already exists");
/// }
/// ```
pub fn set_if_absent(key: &str, value: &[u8]) -> Result<bool> {
    let (inserted, error) = raw::set_if_absent(key, value);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    Ok(inserted)
}

/// Set a key only if current value equals expected (compare-and-swap)
///
/// This is useful for atomic updates when multiple processes might be
/// modifying the same key concurrently.
///
/// # Arguments
/// * `key` - The key to update
/// * `expected` - The expected current value
/// * `new_value` - The new value to set if current matches expected
///
/// # Returns
/// * `Ok((true, None))` - Value was updated
/// * `Ok((false, Some(current)))` - Current value didn't match, returns actual current value for retry
/// * `Ok((false, None))` - Key doesn't exist
/// * `Err(StorageError)` - Storage operation failed
///
/// # Example
/// ```rust,ignore
/// // Atomically update a value
/// loop {
///     let current = storage::get("balance")?.unwrap_or(vec![0; 8]);
///     let balance = i64::from_le_bytes(current.clone().try_into().unwrap());
///     let new_balance = balance + 100;
///
///     match storage::set_if_equals("balance", &current, &new_balance.to_le_bytes())? {
///         (true, _) => break,  // Success
///         (false, Some(actual)) => continue,  // Retry with actual value
///         (false, None) => break,  // Key was deleted
///     }
/// }
/// ```
pub fn set_if_equals(key: &str, expected: &[u8], new_value: &[u8]) -> Result<(bool, Option<Vec<u8>>)> {
    let (success, current, error) = raw::set_if_equals(key, expected, new_value);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    if success {
        Ok((true, None))
    } else if current.is_empty() {
        Ok((false, None))
    } else {
        Ok((false, Some(current)))
    }
}

/// Atomically increment a numeric value
///
/// If the key doesn't exist, creates it with delta as the initial value.
/// Uses compare-and-swap internally with automatic retries.
///
/// # Arguments
/// * `key` - The key to increment
/// * `delta` - The amount to add (can be negative)
///
/// # Returns
/// * `Ok(new_value)` - The new value after increment
/// * `Err(StorageError)` - Storage operation failed or value is not a valid i64
///
/// # Example
/// ```rust,ignore
/// // Increment a counter
/// let new_count = storage::increment("page_views", 1)?;
/// println!("Page views: {}", new_count);
///
/// // Decrement (using negative delta)
/// let remaining = storage::increment("credits", -10)?;
/// println!("Remaining credits: {}", remaining);
/// ```
pub fn increment(key: &str, delta: i64) -> Result<i64> {
    let (new_value, error) = raw::increment(key, delta);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    Ok(new_value)
}

/// Atomically decrement a numeric value
///
/// If the key doesn't exist, creates it with -delta as the initial value.
/// This is equivalent to `increment(key, -delta)`.
///
/// # Arguments
/// * `key` - The key to decrement
/// * `delta` - The amount to subtract
///
/// # Returns
/// * `Ok(new_value)` - The new value after decrement
/// * `Err(StorageError)` - Storage operation failed or value is not a valid i64
///
/// # Example
/// ```rust,ignore
/// // Decrement inventory
/// let remaining = storage::decrement("stock:item123", 1)?;
/// if remaining < 0 {
///     println!("Out of stock!");
/// }
/// ```
pub fn decrement(key: &str, delta: i64) -> Result<i64> {
    let (new_value, error) = raw::decrement(key, delta);
    if !error.is_empty() {
        return Err(StorageError(error));
    }
    Ok(new_value)
}
