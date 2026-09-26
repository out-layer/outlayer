//! HTTP client for Coordinator storage API with Keystore encryption
//!
//! This client handles communication with:
//! - Keystore: encrypt/decrypt data
//! - Coordinator: store/retrieve records
//!
//! Encrypted records are encrypted and decrypted by the keystore (TEE), not
//! locally. Raw records (`*_raw`) hold the caller's key name and bytes as given
//! and never reach the keystore. A record is read and written only in the mode
//! it was written in; the coordinator refuses a write in the other mode.

use anyhow::{Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{debug, error, warn};

/// Storage client configuration
#[derive(Clone)]
pub struct StorageConfig {
    /// Coordinator API base URL
    pub coordinator_url: String,
    /// Auth token for coordinator API
    pub coordinator_token: String,
    /// Keystore API base URL
    pub keystore_url: String,
    /// Auth token for keystore API
    pub keystore_token: String,
    /// Project UUID - required for storage
    pub project_uuid: String,
    /// WASM hash (SHA256 of current WASM binary)
    pub wasm_hash: String,
    /// Account ID of the signer (NEAR account)
    pub account_id: String,
    /// Keystore TEE session ID (set after challenge-response registration)
    pub keystore_tee_session_id: Option<String>,
}

/// The mode a record is stored in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Encrypted by the keystore (`is_encrypted = true`).
    Encrypted,
    /// The caller's bytes as given (`is_encrypted = false`).
    Raw,
}

impl Mode {
    fn of(is_encrypted: bool) -> Self {
        if is_encrypted {
            Mode::Encrypted
        } else {
            Mode::Raw
        }
    }

    fn written(self) -> &'static str {
        match self {
            Mode::Encrypted => "encrypted",
            Mode::Raw => "raw",
        }
    }
}

/// The error for a call made in the other mode than the stored record's.
fn wrong_mode(stored: Mode, advice: &str) -> anyhow::Error {
    anyhow::anyhow!("the record at this key was written {}; {}", stored.written(), advice)
}

/// The coordinator's 409 body for a write refused because the stored record is
/// in the other mode.
#[derive(Deserialize)]
struct ModeMismatchBody {
    error: ModeMismatchCode,
    stored_is_encrypted: bool,
}

#[derive(Deserialize)]
enum ModeMismatchCode {
    #[serde(rename = "storage_mode_mismatch")]
    StorageModeMismatch,
}

/// The stored record's mode, when `status`/`body` is the coordinator refusing a
/// write for being in the other mode.
fn refused_mode(status: reqwest::StatusCode, body: &str) -> Option<Mode> {
    if status != reqwest::StatusCode::CONFLICT {
        return None;
    }
    let parsed: ModeMismatchBody = serde_json::from_str(body).ok()?;
    match parsed.error {
        ModeMismatchCode::StorageModeMismatch => Some(Mode::of(parsed.stored_is_encrypted)),
    }
}

/// `/storage/get` answer.
#[derive(Deserialize)]
struct GetResponse {
    exists: bool,
    encrypted_key: Option<Vec<u8>>,
    encrypted_value: Option<Vec<u8>>,
    #[serde(default = "default_true")]
    is_encrypted: bool,
}

fn default_true() -> bool {
    true
}

/// HTTP client for coordinator storage API
pub struct StorageClient {
    client: reqwest::blocking::Client,
    config: StorageConfig,
}

impl StorageClient {
    /// Create a new storage client
    pub fn new(config: StorageConfig) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self { client, config })
    }

    /// Build a keystore request with auth headers (Bearer token + optional X-TEE-Session)
    fn keystore_request(&self, method: reqwest::Method, path: &str) -> reqwest::blocking::RequestBuilder {
        let mut req = self
            .client
            .request(method, format!("{}{}", self.config.keystore_url, path))
            .header("Authorization", format!("Bearer {}", self.config.keystore_token))
            .header("Content-Type", "application/json");
        if let Some(ref session_id) = self.config.keystore_tee_session_id {
            req = req.header("X-TEE-Session", session_id.as_str());
        }
        req
    }

    /// POST a JSON body to a coordinator storage endpoint
    fn coordinator_post(&self, path: &str, body: &serde_json::Value) -> reqwest::Result<reqwest::blocking::Response> {
        self.client
            .post(format!("{}{}", self.config.coordinator_url, path))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(body)
            .send()
    }

    /// Hash a key for storage lookup
    fn hash_key(&self, key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Encrypt data via keystore
    fn encrypt_via_keystore(&self, key: &str, value: &[u8], account_id: &str) -> Result<EncryptedData> {
        let body = serde_json::json!({
            "project_uuid": self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": account_id,
            "key": key,
            "value_base64": base64_encode(value),
        });

        let response = self
            .keystore_request(reqwest::Method::POST, "/storage/encrypt")
            .json(&body)
            .send()
            .context("Failed to send keystore encrypt request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            error!("Keystore encrypt failed: {} - {}", status, error_text);
            anyhow::bail!("Keystore encrypt failed: {} - {}", status, error_text);
        }

        #[derive(Deserialize)]
        struct EncryptResponse {
            encrypted_key_base64: String,
            encrypted_value_base64: String,
            key_hash: String,
        }

        let resp: EncryptResponse = response.json().context("Failed to parse keystore encrypt response")?;

        Ok(EncryptedData {
            encrypted_key: base64_decode(&resp.encrypted_key_base64)?,
            encrypted_value: base64_decode(&resp.encrypted_value_base64)?,
            key_hash: resp.key_hash,
        })
    }

    /// Decrypt data via keystore
    fn decrypt_via_keystore(&self, encrypted_key: &[u8], encrypted_value: &[u8], account_id: &str) -> Result<DecryptedData> {
        let body = serde_json::json!({
            "project_uuid": self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": account_id,
            "encrypted_key_base64": base64_encode(encrypted_key),
            "encrypted_value_base64": base64_encode(encrypted_value),
        });

        let response = self
            .keystore_request(reqwest::Method::POST, "/storage/decrypt")
            .json(&body)
            .send()
            .context("Failed to send keystore decrypt request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            error!("Keystore decrypt failed: {} - {}", status, error_text);
            anyhow::bail!("Keystore decrypt failed: {} - {}", status, error_text);
        }

        #[derive(Deserialize)]
        struct DecryptResponse {
            key: String,
            value_base64: String,
        }

        let resp: DecryptResponse = response.json().context("Failed to parse keystore decrypt response")?;

        Ok(DecryptedData {
            key: resp.key,
            value: base64_decode(&resp.value_base64)?,
        })
    }

    /// Set a storage key-value pair
    pub fn set(&self, key: &str, value: &[u8]) -> Result<()> {
        self.set_for_account(key, value, &self.config.account_id)
    }

    /// Set a storage key-value pair for a specific account
    pub fn set_for_account(&self, key: &str, value: &[u8], account_id: &str) -> Result<()> {
        // Encrypt via keystore
        let encrypted = self.encrypt_via_keystore(key, value, account_id)?;

        debug!(
            "storage_set: key_hash={}, account={}, value_size={}",
            encrypted.key_hash,
            account_id,
            value.len()
        );

        // Store in coordinator
        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": account_id,
            "key_hash": encrypted.key_hash,
            "encrypted_key": encrypted.encrypted_key,
            "encrypted_value": encrypted.encrypted_value,
        });

        let response = self
            .client
            .post(format!("{}/storage/set", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage set request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            if let Some(stored) = refused_mode(status, &error_text) {
                return Err(wrong_mode(
                    stored,
                    "set does not convert it — write it with set-raw, or delete it first",
                ));
            }
            error!("Storage set failed: {} - {}", status, error_text);
            anyhow::bail!("Storage set failed: {} - {}", status, error_text);
        }

        Ok(())
    }

    /// Get a storage value by key
    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.get_for_account(key, &self.config.account_id)
    }

    /// Get a storage value for a specific account
    pub fn get_for_account(&self, key: &str, account_id: &str) -> Result<Option<Vec<u8>>> {
        let key_hash = self.hash_key(key);

        debug!("storage_get: key_hash={}, account={}", key_hash, account_id);

        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "account_id": account_id,
            "key_hash": key_hash,
        });

        let response = self
            .client
            .post(format!("{}/storage/get", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage get request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            error!("Storage get failed: {} - {}", status, error_text);
            anyhow::bail!("Storage get failed: {} - {}", status, error_text);
        }

        let resp: GetResponse = response.json().context("Failed to parse storage get response")?;

        if !resp.exists {
            return Ok(None);
        }
        if !resp.is_encrypted {
            return Err(wrong_mode(Mode::Raw, "read it with get-raw"));
        }

        match (resp.encrypted_key, resp.encrypted_value) {
            (Some(enc_key), Some(enc_value)) => {
                // Decrypt via keystore
                let decrypted = self.decrypt_via_keystore(&enc_key, &enc_value, account_id)?;
                Ok(Some(decrypted.value))
            }
            _ => Ok(None),
        }
    }

    /// Check if a key exists
    pub fn has(&self, key: &str) -> Result<bool> {
        let key_hash = self.hash_key(key);

        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
        });

        let response = self
            .client
            .post(format!("{}/storage/has", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage has request")?;

        if !response.status().is_success() {
            return Ok(false);
        }

        #[derive(Deserialize)]
        struct HasResponse {
            exists: bool,
        }

        let resp: HasResponse = response.json().unwrap_or(HasResponse { exists: false });
        Ok(resp.exists)
    }

    /// Delete a key
    pub fn delete(&self, key: &str) -> Result<bool> {
        let key_hash = self.hash_key(key);

        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
        });

        let response = self
            .client
            .post(format!("{}/storage/delete", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage delete request")?;

        Ok(response.status().is_success())
    }

    /// List keys with optional prefix filter
    ///
    /// Raw records carry their key name as stored; encrypted ones are decrypted
    /// by the keystore. The prefix filter applies to the key names.
    pub fn list_keys(&self, prefix: &str) -> Result<String> {
        let url = format!(
            "{}/storage/list?account_id={}&project_uuid={}",
            self.config.coordinator_url,
            self.config.account_id,
            self.config.project_uuid
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .send()
            .context("Failed to send storage list request")?;

        // A failed listing is an error, never an empty one: a guest that reads
        // "no keys" acts on records that are there.
        if !response.status().is_success() {
            anyhow::bail!("storage list failed: HTTP {}", response.status());
        }

        #[derive(Deserialize)]
        struct ListResponse {
            keys: Vec<KeyInfo>,
        }

        #[derive(Deserialize)]
        struct KeyInfo {
            key_hash: String,
            encrypted_key: Vec<u8>,
            encrypted_value: Vec<u8>,
            #[serde(default = "default_true")]
            is_encrypted: bool,
        }

        let resp: ListResponse = response.json().context("Failed to parse storage list response")?;

        // Decrypt all keys via keystore and filter by prefix
        let mut decrypted_keys: Vec<String> = Vec::new();
        let started = std::time::Instant::now();
        const LIST_KEYS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(25);
        let total_keys = resp.keys.len();
        for key_info in resp.keys {
            if started.elapsed() > LIST_KEYS_TIMEOUT {
                warn!(
                    "list_keys timed out after {}s ({}/{} keys)",
                    LIST_KEYS_TIMEOUT.as_secs(), decrypted_keys.len(), total_keys
                );
                anyhow::bail!(
                    "list_keys timed out after {}s: too many keys ({} total). \
                    Consider using prefix filter or reducing stored keys.",
                    LIST_KEYS_TIMEOUT.as_secs(), total_keys
                );
            }
            let key = if key_info.is_encrypted {
                match self.decrypt_via_keystore(&key_info.encrypted_key, &key_info.encrypted_value, &self.config.account_id) {
                    Ok(decrypted) => decrypted.key,
                    Err(e) => {
                        warn!("Failed to decrypt key during list: {}", e);
                        continue;
                    }
                }
            } else {
                match String::from_utf8(key_info.encrypted_key) {
                    Ok(key) => key,
                    Err(_) => {
                        warn!("Raw key during list is not UTF-8: key_hash={}", key_info.key_hash);
                        continue;
                    }
                }
            };
            if prefix.is_empty() || key.starts_with(prefix) {
                decrypted_keys.push(key);
            }
        }

        serde_json::to_string(&decrypted_keys).context("Failed to serialize keys")
    }

    /// Get value from a specific WASM version (for migration)
    pub fn get_by_version(&self, key: &str, wasm_hash: &str) -> Result<Option<Vec<u8>>> {
        let key_hash = self.hash_key(key);

        // The run's project scopes the read: a wasm hash alone names a version
        // that any project can run, not this project's records.
        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": wasm_hash,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
        });

        let response = self
            .client
            .post(format!("{}/storage/get-by-version", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage get-by-version request")?;

        // A failed read is an error, never "no record".
        if !response.status().is_success() {
            anyhow::bail!("storage get-by-version failed: HTTP {}", response.status());
        }

        let resp: GetResponse = response.json().context("Failed to parse response")?;

        if !resp.exists {
            return Ok(None);
        }
        if !resp.is_encrypted {
            return Err(wrong_mode(Mode::Raw, "read it with get-raw"));
        }

        match (resp.encrypted_key, resp.encrypted_value) {
            (Some(enc_key), Some(enc_value)) => {
                // For version-specific get, we need to use the old wasm_hash for decryption
                let body = serde_json::json!({
                    "project_uuid": self.config.project_uuid,
                    "wasm_hash": wasm_hash, // Use old wasm_hash
                    "account_id": self.config.account_id,
                    "encrypted_key_base64": base64_encode(&enc_key),
                    "encrypted_value_base64": base64_encode(&enc_value),
                });

                let response = self
                    .keystore_request(reqwest::Method::POST, "/storage/decrypt")
                    .json(&body)
                    .send()
                    .context("Failed to send keystore decrypt request")?;

                if !response.status().is_success() {
                    anyhow::bail!("storage get-by-version: the keystore could not decrypt the record: HTTP {}", response.status());
                }

                #[derive(Deserialize)]
                struct DecryptResponse {
                    #[allow(dead_code)]
                    key: String,
                    value_base64: String,
                }

                let resp: DecryptResponse = response.json().context("Failed to parse decrypt response")?;
                Ok(Some(base64_decode(&resp.value_base64)?))
            }
            _ => Ok(None),
        }
    }

    /// Clear all storage for this project/account
    pub fn clear_all(&self) -> Result<()> {
        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "account_id": self.config.account_id,
        });

        let response = self
            .client
            .post(format!("{}/storage/clear-all", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage clear-all request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            anyhow::bail!("Storage clear-all failed: {} - {}", status, error_text);
        }

        Ok(())
    }

    /// Clear storage for a specific WASM version
    pub fn clear_version(&self, wasm_hash: &str) -> Result<()> {
        // Scoped to the run's project, like `get_by_version`.
        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": wasm_hash,
            "account_id": self.config.account_id,
        });

        let response = self
            .client
            .post(format!("{}/storage/clear-version", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage clear-version request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            anyhow::bail!("Storage clear-version failed: {} - {}", status, error_text);
        }

        Ok(())
    }

    /// Set worker storage (account_id = "@worker")
    /// is_encrypted: true = encrypt via keystore (default, private to project)
    ///               false = store plaintext (public, readable by other projects)
    pub fn set_worker(&self, key: &str, value: &[u8], is_encrypted: bool) -> Result<()> {
        if is_encrypted {
            // Encrypted: use keystore
            self.set_for_account(key, value, "@worker")
        } else {
            // Public: store plaintext directly (no keystore)
            self.set_public(key, value)
        }
    }

    /// Set public storage (plaintext, no encryption)
    fn set_public(&self, key: &str, value: &[u8]) -> Result<()> {
        let key_hash = self.hash_key(key);

        debug!(
            "storage_set_public: key_hash={}, value_size={}",
            key_hash,
            value.len()
        );

        // Store plaintext key and value directly (no keystore encryption)
        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": "@worker",
            "key_hash": key_hash,
            "encrypted_key": key.as_bytes(),      // plaintext key
            "encrypted_value": value,              // plaintext value
            "is_encrypted": false,
        });

        let response = self
            .client
            .post(format!("{}/storage/set", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage set request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            error!("Storage set_public failed: {} - {}", status, error_text);
            anyhow::bail!("Storage set_public failed: {} - {}", status, error_text);
        }

        Ok(())
    }

    /// Get worker storage (account_id = "@worker")
    /// project: None = read from current project (private or public)
    ///          Some(project) = read public data from another project, named
    ///          by its name ("owner.near/project-name") or its uuid
    ///          ("p0000000000000001"); the coordinator resolves either form
    pub fn get_worker(&self, key: &str, project: Option<&str>) -> Result<Option<Vec<u8>>> {
        match project {
            None => {
                // Read from own project - may be encrypted or public
                self.get_worker_own(key)
            }
            Some(project) => {
                // Read from another project - only public data allowed
                self.get_worker_public(key, project)
            }
        }
    }

    /// Get worker storage from own project (handles both encrypted and public)
    fn get_worker_own(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let key_hash = self.hash_key(key);

        debug!("storage_get_worker_own: key_hash={}", key_hash);

        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "account_id": "@worker",
            "key_hash": key_hash,
        });

        let response = self
            .client
            .post(format!("{}/storage/get", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage get request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            error!("Storage get failed: {} - {}", status, error_text);
            anyhow::bail!("Storage get failed: {} - {}", status, error_text);
        }

        let resp: GetResponse = response.json().context("Failed to parse storage get response")?;

        if !resp.exists {
            return Ok(None);
        }

        match (resp.encrypted_key, resp.encrypted_value) {
            (Some(enc_key), Some(enc_value)) => {
                if resp.is_encrypted {
                    // Encrypted: decrypt via keystore
                    let decrypted = self.decrypt_via_keystore(&enc_key, &enc_value, "@worker")?;
                    Ok(Some(decrypted.value))
                } else {
                    // Public: value is plaintext
                    Ok(Some(enc_value))
                }
            }
            _ => Ok(None),
        }
    }

    /// Get public worker storage from another project, named as the guest
    /// named it (a project name or a project uuid)
    fn get_worker_public(&self, key: &str, project: &str) -> Result<Option<Vec<u8>>> {
        let key_hash = self.hash_key(key);

        debug!(
            "storage_get_worker_public: project={}, key_hash={}",
            project, key_hash
        );

        // Request public storage from coordinator
        // Coordinator resolves the project and checks is_encrypted=false before returning.
        // `project_uuid` carries the same value for a coordinator that reads only
        // that field; one that knows `project` reads `project`.
        let body = serde_json::json!({
            "project": project,
            "project_uuid": project,
            "key_hash": key_hash,
        });

        let response = self
            .client
            .post(format!("{}/storage/get-public", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage get-public request")?;

        if !response.status().is_success() {
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            if status == reqwest::StatusCode::FORBIDDEN {
                anyhow::bail!("Storage key '{}' in project '{}' is not public (encrypted)", key, project);
            }
            if status == reqwest::StatusCode::BAD_REQUEST {
                // The coordinator's message names the accepted project forms.
                anyhow::bail!("{}", response.text().unwrap_or_default());
            }
            let error_text = response.text().unwrap_or_default();
            error!("Storage get-public failed: {} - {}", status, error_text);
            anyhow::bail!("Storage get-public failed: {} - {}", status, error_text);
        }

        #[derive(Deserialize)]
        struct GetPublicResponse {
            exists: bool,
            value: Option<Vec<u8>>,
        }

        let resp: GetPublicResponse = response.json().context("Failed to parse storage get-public response")?;

        if !resp.exists {
            return Ok(None);
        }

        Ok(resp.value)
    }

    // ==================== Conditional Write Operations ====================

    /// Set a key only if it doesn't already exist
    /// Returns true if value was inserted, false if key already existed
    pub fn set_if_absent(&self, key: &str, value: &[u8]) -> Result<bool> {
        // Encrypt via keystore
        let encrypted = self.encrypt_via_keystore(key, value, &self.config.account_id)?;

        debug!(
            "storage_set_if_absent: key_hash={}, account={}, value_size={}",
            encrypted.key_hash,
            self.config.account_id,
            value.len()
        );

        // Try to insert via coordinator
        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": self.config.account_id,
            "key_hash": encrypted.key_hash,
            "encrypted_key": encrypted.encrypted_key,
            "encrypted_value": encrypted.encrypted_value,
        });

        let response = self
            .client
            .post(format!("{}/storage/set-if-absent", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .context("Failed to send storage set-if-absent request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            anyhow::bail!("Storage set-if-absent failed: {} - {}", status, error_text);
        }

        #[derive(Deserialize)]
        struct SetIfAbsentResponse {
            inserted: bool,
        }

        let resp: SetIfAbsentResponse = response.json().context("Failed to parse set-if-absent response")?;
        Ok(resp.inserted)
    }

    /// Set a key only if current value equals expected (compare-and-swap)
    /// Returns (success, current_value) where current_value is provided for retry on failure
    pub fn set_if_equals(&self, key: &str, expected: &[u8], new_value: &[u8]) -> Result<(bool, Option<Vec<u8>>)> {
        // First, get current encrypted value to pass to coordinator
        let key_hash = self.hash_key(key);

        let get_body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
        });

        let get_response = self
            .client
            .post(format!("{}/storage/get", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&get_body)
            .send()
            .context("Failed to send storage get request for set_if_equals")?;

        if !get_response.status().is_success() {
            anyhow::bail!("Storage get failed during set_if_equals");
        }

        let get_resp: GetResponse = get_response.json().context("Failed to parse get response")?;

        if !get_resp.exists {
            // Key doesn't exist - can't do CAS
            return Ok((false, None));
        }
        if !get_resp.is_encrypted {
            return Err(wrong_mode(Mode::Raw, "compare it with set-if-equals-raw"));
        }

        let (current_enc_key, current_enc_value) = match (get_resp.encrypted_key, get_resp.encrypted_value) {
            (Some(k), Some(v)) => (k, v),
            _ => return Ok((false, None)),
        };

        // Decrypt current value to compare with expected
        let decrypted = self.decrypt_via_keystore(&current_enc_key, &current_enc_value, &self.config.account_id)?;

        if decrypted.value != expected {
            // Current value doesn't match expected - return current value for retry
            return Ok((false, Some(decrypted.value)));
        }

        // Values match - encrypt new value and try to update
        let new_encrypted = self.encrypt_via_keystore(key, new_value, &self.config.account_id)?;

        let update_body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
            "expected_encrypted_value": current_enc_value,
            "new_encrypted_key": new_encrypted.encrypted_key,
            "new_encrypted_value": new_encrypted.encrypted_value,
        });

        let update_response = self
            .client
            .post(format!("{}/storage/set-if-equals", self.config.coordinator_url))
            .header("Authorization", format!("Bearer {}", self.config.coordinator_token))
            .header("Content-Type", "application/json")
            .json(&update_body)
            .send()
            .context("Failed to send storage set-if-equals request")?;

        if !update_response.status().is_success() {
            let status = update_response.status();
            let error_text = update_response.text().unwrap_or_default();
            if let Some(stored) = refused_mode(status, &error_text) {
                return Err(wrong_mode(stored, "compare it with set-if-equals-raw"));
            }
            anyhow::bail!("Storage set-if-equals failed: {} - {}", status, error_text);
        }

        let update_resp: SetIfEqualsResponse = update_response.json().context("Failed to parse set-if-equals response")?;

        if update_resp.updated {
            Ok((true, None))
        } else {
            // Concurrent modification - decrypt current value for retry
            if let (Some(enc_key), Some(enc_value)) = (update_resp.current_encrypted_key, update_resp.current_encrypted_value) {
                let current = self.decrypt_via_keystore(&enc_key, &enc_value, &self.config.account_id)?;
                Ok((false, Some(current.value)))
            } else {
                Ok((false, None))
            }
        }
    }

    // ==================== Raw Operations ====================
    //
    // The key name and value are stored as given, under the same account,
    // project and key hash as the encrypted operations, with
    // `is_encrypted = false`. No keystore call is made.

    /// Store bytes as given
    pub fn set_raw(&self, key: &str, value: &[u8]) -> Result<()> {
        let key_hash = self.hash_key(key);
        debug!(
            "storage_set_raw: key_hash={}, account={}, value_size={}",
            key_hash,
            self.config.account_id,
            value.len()
        );

        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
            "encrypted_key": key.as_bytes(),
            "encrypted_value": value,
            "is_encrypted": false,
        });

        let response = self
            .coordinator_post("/storage/set", &body)
            .context("Failed to send storage set-raw request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            if let Some(stored) = refused_mode(status, &error_text) {
                return Err(wrong_mode(
                    stored,
                    "set-raw does not convert it — write it with set, or delete it first",
                ));
            }
            anyhow::bail!("Storage set-raw failed: {} - {}", status, error_text);
        }

        Ok(())
    }

    /// Get the bytes stored by `set_raw`
    pub fn get_raw(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let key_hash = self.hash_key(key);
        debug!("storage_get_raw: key_hash={}, account={}", key_hash, self.config.account_id);

        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
        });

        let response = self
            .coordinator_post("/storage/get", &body)
            .context("Failed to send storage get-raw request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            anyhow::bail!("Storage get-raw failed: {} - {}", status, error_text);
        }

        let resp: GetResponse = response.json().context("Failed to parse storage get response")?;

        if !resp.exists {
            return Ok(None);
        }
        if resp.is_encrypted {
            return Err(wrong_mode(Mode::Encrypted, "read it with get"));
        }
        Ok(resp.encrypted_value)
    }

    /// Store bytes as given only if the key holds no record, in either mode.
    /// Returns true if the value was inserted.
    pub fn set_if_absent_raw(&self, key: &str, value: &[u8]) -> Result<bool> {
        let key_hash = self.hash_key(key);
        debug!(
            "storage_set_if_absent_raw: key_hash={}, account={}, value_size={}",
            key_hash,
            self.config.account_id,
            value.len()
        );

        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
            "encrypted_key": key.as_bytes(),
            "encrypted_value": value,
            "is_encrypted": false,
        });

        let response = self
            .coordinator_post("/storage/set-if-absent", &body)
            .context("Failed to send storage set-if-absent-raw request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            anyhow::bail!("Storage set-if-absent-raw failed: {} - {}", status, error_text);
        }

        #[derive(Deserialize)]
        struct SetIfAbsentResponse {
            inserted: bool,
        }

        let resp: SetIfAbsentResponse = response.json().context("Failed to parse set-if-absent response")?;
        Ok(resp.inserted)
    }

    /// Compare-and-swap on raw bytes: `expected` is compared with the stored
    /// bytes themselves. Returns (success, current_value) where current_value is
    /// the stored bytes on failure (None when the key holds no record).
    pub fn set_if_equals_raw(&self, key: &str, expected: &[u8], new_value: &[u8]) -> Result<(bool, Option<Vec<u8>>)> {
        let key_hash = self.hash_key(key);
        debug!(
            "storage_set_if_equals_raw: key_hash={}, account={}, expected_len={}, new_len={}",
            key_hash,
            self.config.account_id,
            expected.len(),
            new_value.len()
        );

        let body = serde_json::json!({
            "project_uuid": &self.config.project_uuid,
            "wasm_hash": self.config.wasm_hash,
            "account_id": self.config.account_id,
            "key_hash": key_hash,
            "expected_encrypted_value": expected,
            "new_encrypted_key": key.as_bytes(),
            "new_encrypted_value": new_value,
            "is_encrypted": false,
        });

        let response = self
            .coordinator_post("/storage/set-if-equals", &body)
            .context("Failed to send storage set-if-equals-raw request")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().unwrap_or_default();
            if let Some(stored) = refused_mode(status, &error_text) {
                return Err(wrong_mode(stored, "compare it with set-if-equals"));
            }
            anyhow::bail!("Storage set-if-equals-raw failed: {} - {}", status, error_text);
        }

        let resp: SetIfEqualsResponse = response.json().context("Failed to parse set-if-equals response")?;

        if resp.updated {
            Ok((true, None))
        } else {
            Ok((false, resp.current_encrypted_value))
        }
    }

    /// Atomically increment a numeric value
    /// If key doesn't exist, creates it with delta as initial value
    /// Returns the new value after increment
    pub fn increment(&self, key: &str, delta: i64) -> Result<i64> {
        // MAX_RETRIES needed for CAS (compare-and-swap) pattern: if another execution
        // modifies the same key concurrently, our expected value won't match and we
        // retry with the new value. Common for worker storage shared across executions.
        const MAX_RETRIES: usize = 5;

        for attempt in 0..MAX_RETRIES {
            // Get current value
            let current_opt = self.get(key)?;

            match current_opt {
                None => {
                    // Key doesn't exist - try to create with initial value
                    let new_value = delta;
                    let value_bytes = new_value.to_le_bytes().to_vec();

                    if self.set_if_absent(key, &value_bytes)? {
                        debug!("increment: created key={} with initial value={}", key, new_value);
                        return Ok(new_value);
                    }
                    // Key was created by someone else - retry
                    debug!("increment: concurrent create detected, retrying (attempt {})", attempt + 1);
                }
                Some(current_bytes) => {
                    // Parse current value as i64
                    let current_value = if current_bytes.len() == 8 {
                        i64::from_le_bytes(current_bytes.clone().try_into().unwrap())
                    } else {
                        anyhow::bail!("increment: invalid value format, expected 8 bytes (i64), got {}", current_bytes.len());
                    };

                    let new_value = current_value.checked_add(delta)
                        .context("increment: overflow")?;
                    let new_bytes = new_value.to_le_bytes().to_vec();

                    let (success, _) = self.set_if_equals(key, &current_bytes, &new_bytes)?;
                    if success {
                        debug!("increment: updated key={} from {} to {}", key, current_value, new_value);
                        return Ok(new_value);
                    }
                    // Concurrent modification - retry
                    debug!("increment: concurrent modification detected, retrying (attempt {})", attempt + 1);
                }
            }
        }

        anyhow::bail!("increment: max retries ({}) exceeded for key={}", MAX_RETRIES, key)
    }

    /// Atomically decrement a numeric value
    /// If key doesn't exist, creates it with -delta as initial value
    /// Returns the new value after decrement
    pub fn decrement(&self, key: &str, delta: i64) -> Result<i64> {
        // decrement(delta) is just increment(-delta)
        self.increment(key, -delta)
    }
}

/// `/storage/set-if-equals` answer.
#[derive(Deserialize)]
struct SetIfEqualsResponse {
    updated: bool,
    current_encrypted_value: Option<Vec<u8>>,
    current_encrypted_key: Option<Vec<u8>>,
}

/// Encrypted data from keystore
struct EncryptedData {
    encrypted_key: Vec<u8>,
    encrypted_value: Vec<u8>,
    key_hash: String,
}

/// Decrypted data from keystore
struct DecryptedData {
    key: String,
    value: Vec<u8>,
}

// Base64 helpers
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(data: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(data)
        .context("Invalid base64")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outlayer_storage::fake_http::{bytes_json, config, key_hash, mode_mismatch, serve, untouched_keystore};
    use serde_json::json;

    fn exists(value: &[u8], stored_key: &[u8], is_encrypted: bool) -> (u16, String) {
        (
            200,
            json!({
                "exists": true,
                "encrypted_key": stored_key,
                "encrypted_value": value,
                "wasm_hash": "wasm-test",
                "is_encrypted": is_encrypted,
            })
            .to_string(),
        )
    }

    fn absent() -> (u16, String) {
        (200, json!({ "exists": false, "is_encrypted": true }).to_string())
    }

    /// A coordinator that fails a listing or a version read gives the guest an
    /// error, never "no keys" or "no record".
    #[test]
    fn a_failed_listing_or_version_read_is_an_error_not_an_absence() {
        let coordinator = serve(|_, _| (503, json!({ "error": "the database is temporarily unavailable" }).to_string()));
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let err = client.list_keys("").unwrap_err().to_string();
        assert!(err.contains("storage list failed: HTTP 503"), "{err}");
        let err = client.get_by_version("k", "wasm-old").unwrap_err().to_string();
        assert!(err.contains("storage get-by-version failed: HTTP 503"), "{err}");
        assert!(keystore.seen().is_empty());
    }

    /// A version read whose record the keystore cannot open is an error too.
    #[test]
    fn a_version_read_the_keystore_cannot_open_is_an_error() {
        let coordinator = serve(|_, _| exists(b"cipher", b"key", true));
        let keystore = serve(|_, _| (500, json!({ "error": "boom" }).to_string()));
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let err = client.get_by_version("k", "wasm-old").unwrap_err().to_string();
        assert!(err.contains("the keystore could not decrypt the record"), "{err}");
    }

    /// set-raw sends the key name and the bytes as given, under the SHA-256 key
    /// hash, flagged raw, and never calls the keystore.
    #[test]
    fn set_raw_stores_the_key_and_bytes_as_given_without_the_keystore() {
        let coordinator = serve(|_, _| (200, String::new()));
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        client.set_raw("sealed/1", b"\x00cipher\xff").unwrap();

        let seen = coordinator.seen();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].path, "/storage/set");
        assert_eq!(
            seen[0].body,
            json!({
                "project_uuid": "p-test",
                "wasm_hash": "wasm-test",
                "account_id": "agent.near",
                "key_hash": key_hash("sealed/1"),
                "encrypted_key": bytes_json(b"sealed/1"),
                "encrypted_value": bytes_json(b"\x00cipher\xff"),
                "is_encrypted": false,
            })
        );
        assert!(keystore.seen().is_empty(), "no keystore call on a raw write");
    }

    /// set-raw over an encrypted record comes back as a mode error naming the
    /// stored mode.
    #[test]
    fn set_raw_over_an_encrypted_record_is_refused() {
        let coordinator = serve(|_, _| mode_mismatch(true));
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let err = client.set_raw("k", b"v").unwrap_err().to_string();
        assert!(err.starts_with("the record at this key was written encrypted;"), "{err}");
        assert!(keystore.seen().is_empty());
    }

    /// get-raw returns the stored bytes, None for no record, and an error for
    /// an encrypted record — without decrypting anything.
    #[test]
    fn get_raw_reads_raw_records_only() {
        let coordinator = serve(|_, body| {
            let hash = body["key_hash"].as_str().unwrap_or_default().to_string();
            if hash == key_hash("raw") {
                exists(b"\x01\x02", b"raw", false)
            } else if hash == key_hash("enc") {
                exists(b"CIPHER", b"ENCKEY", true)
            } else {
                absent()
            }
        });
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        assert_eq!(client.get_raw("raw").unwrap(), Some(vec![1, 2]));
        assert_eq!(client.get_raw("missing").unwrap(), None);
        let err = client.get_raw("enc").unwrap_err().to_string();
        assert_eq!(err, "the record at this key was written encrypted; read it with get");

        let seen = coordinator.seen();
        assert!(seen.iter().all(|s| s.path == "/storage/get"));
        assert_eq!(seen[0].body["account_id"], "agent.near");
        assert_eq!(seen[0].body["project_uuid"], "p-test");
        assert!(keystore.seen().is_empty());
    }

    /// A coordinator answer without the mode is an encrypted record, as every
    /// record was before raw storage.
    #[test]
    fn a_get_answer_without_the_mode_is_an_encrypted_record() {
        let coordinator = serve(|_, _| {
            (200, json!({ "exists": true, "encrypted_key": [1], "encrypted_value": [2] }).to_string())
        });
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let err = client.get_raw("k").unwrap_err().to_string();
        assert!(err.contains("written encrypted"), "{err}");
    }

    /// get on a raw record is an error, and the raw bytes never go to the
    /// keystore for decryption.
    #[test]
    fn get_on_a_raw_record_is_refused_without_decrypting() {
        let coordinator = serve(|_, _| exists(b"plain", b"k", false));
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let err = client.get("k").unwrap_err().to_string();
        assert_eq!(err, "the record at this key was written raw; read it with get-raw");
        assert!(keystore.seen().is_empty(), "raw bytes are never sent for decryption");
    }

    /// An encrypted set over a raw record comes back as a mode error.
    #[test]
    fn set_over_a_raw_record_is_refused() {
        let coordinator = serve(|_, _| mode_mismatch(false));
        let keystore = serve(|path, _| match path {
            "/storage/encrypt" => (
                200,
                json!({
                    "encrypted_key_base64": base64_encode(b"ENCKEY"),
                    "encrypted_value_base64": base64_encode(b"ENCVAL"),
                    "key_hash": key_hash("k"),
                })
                .to_string(),
            ),
            _ => (404, String::new()),
        });
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let err = client.set("k", b"v").unwrap_err().to_string();
        assert!(err.starts_with("the record at this key was written raw;"), "{err}");
        assert_eq!(coordinator.seen()[0].body["is_encrypted"], serde_json::Value::Null, "an encrypted set keeps its body");
    }

    /// set-if-absent-raw sends the raw mode and reports what the coordinator
    /// decided.
    #[test]
    fn set_if_absent_raw_sends_the_raw_mode() {
        let coordinator = serve(|_, body| {
            let inserted = body["key_hash"] == key_hash("fresh");
            (200, json!({ "inserted": inserted }).to_string())
        });
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        assert!(client.set_if_absent_raw("fresh", b"v").unwrap());
        assert!(!client.set_if_absent_raw("taken", b"v").unwrap());

        let seen = coordinator.seen();
        assert_eq!(seen[0].path, "/storage/set-if-absent");
        assert_eq!(seen[0].body["is_encrypted"], false);
        assert_eq!(seen[0].body["encrypted_key"], bytes_json(b"fresh"));
        assert_eq!(seen[0].body["encrypted_value"], bytes_json(b"v"));
        assert!(keystore.seen().is_empty());
    }

    /// set-if-equals-raw hands the expected bytes to the coordinator to compare
    /// with the stored ones: a match wins, a mismatch loses with the current
    /// bytes, no record loses with none, and an encrypted record is a mode error.
    #[test]
    fn set_if_equals_raw_compares_the_stored_bytes() {
        let coordinator = serve(|_, body| {
            if body["key_hash"] == key_hash("enc") {
                return mode_mismatch(true);
            }
            if body["key_hash"] == key_hash("missing") {
                return (200, json!({ "updated": false }).to_string());
            }
            if body["expected_encrypted_value"] == bytes_json(b"v1") {
                (200, json!({ "updated": true }).to_string())
            } else {
                (
                    200,
                    json!({ "updated": false, "current_encrypted_value": [9], "current_encrypted_key": b"c" }).to_string(),
                )
            }
        });
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        assert_eq!(client.set_if_equals_raw("c", b"v1", b"v2").unwrap(), (true, None));
        assert_eq!(client.set_if_equals_raw("c", b"stale", b"v3").unwrap(), (false, Some(vec![9])));
        assert_eq!(client.set_if_equals_raw("missing", b"", b"x").unwrap(), (false, None));
        let err = client.set_if_equals_raw("enc", b"x", b"y").unwrap_err().to_string();
        assert_eq!(
            err,
            "the record at this key was written encrypted; compare it with set-if-equals"
        );

        let first = &coordinator.seen()[0];
        assert_eq!(first.path, "/storage/set-if-equals");
        assert_eq!(
            first.body,
            json!({
                "project_uuid": "p-test",
                "wasm_hash": "wasm-test",
                "account_id": "agent.near",
                "key_hash": key_hash("c"),
                "expected_encrypted_value": bytes_json(b"v1"),
                "new_encrypted_key": bytes_json(b"c"),
                "new_encrypted_value": bytes_json(b"v2"),
                "is_encrypted": false,
            })
        );
        assert!(keystore.seen().is_empty());
    }

    /// An encrypted compare-and-swap on a raw record stops at the read, before
    /// any keystore call.
    #[test]
    fn set_if_equals_on_a_raw_record_is_refused_before_the_keystore() {
        let coordinator = serve(|_, _| exists(b"plain", b"k", false));
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let err = client.set_if_equals("k", b"plain", b"new").unwrap_err().to_string();
        assert_eq!(err, "the record at this key was written raw; compare it with set-if-equals-raw");
        assert!(keystore.seen().is_empty());
        assert!(coordinator.seen().iter().all(|s| s.path == "/storage/get"), "nothing is written");
    }

    /// list-keys returns raw key names as stored and sends only the encrypted
    /// records to the keystore; the prefix applies to both.
    #[test]
    fn list_keys_mixes_raw_names_and_decrypted_ones() {
        let coordinator = serve(|_, _| {
            (
                200,
                json!({
                    "keys": [
                        { "key_hash": key_hash("raw/a"), "encrypted_key": b"raw/a", "encrypted_value": [1], "wasm_hash": "w", "is_encrypted": false },
                        { "key_hash": key_hash("enc/a"), "encrypted_key": b"ENCKEY", "encrypted_value": b"ENCVAL", "wasm_hash": "w", "is_encrypted": true },
                        { "key_hash": key_hash("raw/b"), "encrypted_key": b"raw/b", "encrypted_value": [2], "wasm_hash": "w", "is_encrypted": false },
                    ],
                    "total": 3,
                })
                .to_string(),
            )
        });
        let keystore = serve(|path, _| match path {
            "/storage/decrypt" => (
                200,
                json!({ "key": "enc/a", "value_base64": base64_encode(b"v") }).to_string(),
            ),
            _ => (404, String::new()),
        });
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let all: Vec<String> = serde_json::from_str(&client.list_keys("").unwrap()).unwrap();
        assert_eq!(all, vec!["raw/a", "enc/a", "raw/b"]);
        assert_eq!(keystore.seen().len(), 1, "only the encrypted record is decrypted");
        assert_eq!(keystore.seen()[0].body["encrypted_key_base64"], base64_encode(b"ENCKEY"));

        let raw_only: Vec<String> = serde_json::from_str(&client.list_keys("raw/").unwrap()).unwrap();
        assert_eq!(raw_only, vec!["raw/a", "raw/b"]);
    }
    /// A cross-project read passes the project exactly as the guest gave it —
    /// a name or a uuid — and never touches the keystore.
    #[test]
    fn get_worker_from_another_project_sends_the_project_as_given() {
        let coordinator = serve(|_, body| match body["project"].as_str() {
            Some("oracle.near/prices") | Some("p0000000000000001") => {
                if body["key_hash"] == key_hash("price:ETH") {
                    (200, json!({ "exists": true, "value": bytes_json(b"4200") }).to_string())
                } else if body["key_hash"] == key_hash("secret") {
                    (403, String::new())
                } else {
                    (200, json!({ "exists": false, "value": null }).to_string())
                }
            }
            Some("bad") => (400, "Invalid project 'bad': expected a project name".to_string()),
            _ => (200, json!({ "exists": false, "value": null }).to_string()),
        });
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        for project in ["oracle.near/prices", "p0000000000000001"] {
            assert_eq!(client.get_worker("price:ETH", Some(project)).unwrap(), Some(b"4200".to_vec()), "{project}");
            assert_eq!(client.get_worker("absent", Some(project)).unwrap(), None, "{project}");
            let err = client.get_worker("secret", Some(project)).unwrap_err().to_string();
            assert!(err.contains("is not public"), "{project}: {err}");
        }
        assert_eq!(client.get_worker("price:ETH", Some("nobody.near/none")).unwrap(), None);
        let err = client.get_worker("price:ETH", Some("bad")).unwrap_err().to_string();
        assert!(err.starts_with("Invalid project 'bad'"), "the coordinator's reason reaches the guest: {err}");

        let seen = coordinator.seen();
        assert!(seen.iter().all(|s| s.path == "/storage/get-public"));
        assert_eq!(
            seen[0].body,
            json!({
                "project": "oracle.near/prices",
                "project_uuid": "oracle.near/prices",
                "key_hash": key_hash("price:ETH"),
            }),
            "the project goes as given, under `project` and under the field every coordinator reads"
        );
        assert_eq!(seen[3].body["project"], "p0000000000000001");
        assert!(keystore.seen().is_empty());
    }

    /// Version-addressed reads and clears carry the run's project: a wasm hash
    /// is public and runs under any project, so it never scopes records alone.
    #[test]
    fn version_requests_are_scoped_to_the_runs_project() {
        let coordinator = serve(|path, _| match path {
            "/storage/get-by-version" => absent(),
            _ => (200, String::new()),
        });
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        assert_eq!(client.get_by_version("k", "old-wasm").unwrap(), None);
        client.clear_version("old-wasm").unwrap();

        let seen = coordinator.seen();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].path, "/storage/get-by-version");
        assert_eq!(
            seen[0].body,
            json!({
                "project_uuid": "p-test",
                "wasm_hash": "old-wasm",
                "account_id": "agent.near",
                "key_hash": key_hash("k"),
            })
        );
        assert_eq!(seen[1].path, "/storage/clear-version");
        assert_eq!(
            seen[1].body,
            json!({ "project_uuid": "p-test", "wasm_hash": "old-wasm", "account_id": "agent.near" })
        );
        assert!(keystore.seen().is_empty());
    }

    /// A coordinator refusal of a clear reaches the guest with its reason.
    #[test]
    fn a_refused_clear_version_is_an_error() {
        let coordinator = serve(|_, _| (400, "project_uuid is required".to_string()));
        let keystore = untouched_keystore();
        let client = StorageClient::new(config(&coordinator, &keystore)).unwrap();

        let err = client.clear_version("old-wasm").unwrap_err().to_string();
        assert!(err.contains("400") && err.contains("project_uuid is required"), "{err}");
    }
}
