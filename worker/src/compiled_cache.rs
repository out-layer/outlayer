//! Compiled WASM Component Cache
//!
//! Caches pre-compiled wasmtime components to avoid JIT compilation on every execution.
//! Compilation takes ~11 seconds for large WASM files, deserialization takes ~100-200ms.
//!
//! ## Security
//!
//! Compiled code is signed with worker's ed25519 key (stored in TEE RAM).
//! On load, signature is verified before deserializing to prevent code injection.
//!
//! File format:
//! - `{checksum}.compiled` - serialized native code
//! - `{checksum}.sig` - ed25519 signature of (checksum || sha256(compiled_bytes))

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{debug, info, warn};
use wasmtime::component::Component;
use wasmtime::Engine;

/// Cache entry metadata
struct CacheEntry {
    /// Size of compiled file in bytes
    compiled_size: u64,
    /// Last access time for LRU eviction
    last_used: Instant,
}

/// Compiled WASM component cache with cryptographic integrity protection
pub struct CompiledCache {
    /// Cache directory
    dir: PathBuf,
    /// Signing key (stored in TEE RAM)
    signing_key: SigningKey,
    /// Verifying key (derived from signing key)
    verifying_key: VerifyingKey,
    /// Cache entries: wasm_checksum -> metadata
    entries: HashMap<String, CacheEntry>,
    /// Maximum cache size in bytes
    max_size_bytes: u64,
    /// Current total size
    total_size: u64,
}

impl CompiledCache {
    /// Create new compiled cache
    ///
    /// # Arguments
    /// * `cache_dir` - Directory to store compiled files
    /// * `max_size_mb` - Maximum cache size in megabytes
    /// * `secret_key_bytes` - 32-byte ed25519 secret key (from worker registration)
    pub fn new(cache_dir: PathBuf, max_size_mb: u64, secret_key_bytes: &[u8; 32]) -> Result<Self> {
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create compiled cache dir: {:?}", cache_dir))?;

        let signing_key = SigningKey::from_bytes(secret_key_bytes);
        let verifying_key = signing_key.verifying_key();

        let mut cache = Self {
            dir: cache_dir,
            signing_key,
            verifying_key,
            entries: HashMap::new(),
            max_size_bytes: max_size_mb * 1024 * 1024,
            total_size: 0,
        };

        cache.load_existing_entries();

        Ok(cache)
    }

    /// Load existing cache entries from disk
    ///
    /// Scans for .compiled files and validates their signatures.
    /// Invalid entries are removed.
    fn load_existing_entries(&mut self) {
        let entries = match fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("Failed to read compiled cache dir: {}", e);
                return;
            }
        };

        let mut loaded = 0;
        let mut removed = 0;

        for entry in entries.flatten() {
            let path = entry.path();

            // Only process .compiled files
            if path.extension().map(|e| e != "compiled").unwrap_or(true) {
                continue;
            }

            // Extract checksum from filename
            let checksum = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };

            // Check if signature file exists
            let sig_path = self.dir.join(format!("{}.sig", checksum));
            if !sig_path.exists() {
                warn!("Missing signature for {}, removing", checksum);
                let _ = fs::remove_file(&path);
                removed += 1;
                continue;
            }

            // Verify signature
            let compiled_bytes = match fs::read(&path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let sig_bytes = match fs::read(&sig_path) {
                Ok(b) => b,
                Err(_) => continue,
            };

            if !self.verify_signature(&checksum, &compiled_bytes, &sig_bytes) {
                warn!("Invalid signature for {}, removing", checksum);
                let _ = fs::remove_file(&path);
                let _ = fs::remove_file(&sig_path);
                removed += 1;
                continue;
            }

            // Add to entries
            let size = compiled_bytes.len() as u64;
            self.entries.insert(
                checksum,
                CacheEntry {
                    compiled_size: size,
                    last_used: Instant::now(),
                },
            );
            self.total_size += size;
            loaded += 1;
        }

        if loaded > 0 || removed > 0 {
            info!(
                "⚡ Compiled cache: loaded {} entries ({}MB), removed {} invalid",
                loaded,
                self.total_size / 1024 / 1024,
                removed
            );
        }

        // Evict if over limit
        self.evict_if_needed();
    }

    /// Get compiled component from cache
    ///
    /// Returns None if:
    /// - Not in cache
    /// - Signature invalid
    /// - Deserialization failed (engine config mismatch)
    pub fn get(&mut self, wasm_checksum: &str, engine: &Engine) -> Option<Component> {
        // Check if in memory index
        if !self.entries.contains_key(wasm_checksum) {
            return None;
        }

        let compiled_path = self.dir.join(format!("{}.compiled", wasm_checksum));
        let sig_path = self.dir.join(format!("{}.sig", wasm_checksum));

        // Read files
        let compiled_bytes = match fs::read(&compiled_path) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to read compiled cache file: {}", e);
                self.remove_entry(wasm_checksum);
                return None;
            }
        };
        let sig_bytes = match fs::read(&sig_path) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to read signature file: {}", e);
                self.remove_entry(wasm_checksum);
                return None;
            }
        };

        // Verify signature
        if !self.verify_signature(wasm_checksum, &compiled_bytes, &sig_bytes) {
            warn!("⚠️ Invalid signature for compiled cache: {}", wasm_checksum);
            self.remove_entry(wasm_checksum);
            let _ = fs::remove_file(&compiled_path);
            let _ = fs::remove_file(&sig_path);
            return None;
        }

        // Deserialize component (unsafe: loads native code)
        let component = match unsafe { Component::deserialize(engine, &compiled_bytes) } {
            Ok(c) => c,
            Err(e) => {
                // This can happen if engine config changed (wasmtime version, features)
                debug!(
                    "Failed to deserialize compiled component (engine mismatch?): {}",
                    e
                );
                self.remove_entry(wasm_checksum);
                let _ = fs::remove_file(&compiled_path);
                let _ = fs::remove_file(&sig_path);
                return None;
            }
        };

        // Update last used time
        if let Some(entry) = self.entries.get_mut(wasm_checksum) {
            entry.last_used = Instant::now();
        }

        debug!("⚡ Compiled cache hit: {}", wasm_checksum);
        Some(component)
    }

    /// Store compiled component in cache
    ///
    /// Serializes the component and signs it with worker key.
    pub fn put(&mut self, wasm_checksum: &str, component: &Component) -> Result<()> {
        // Serialize component to native code
        let compiled_bytes = component
            .serialize()
            .context("Failed to serialize component")?;

        let size = compiled_bytes.len() as u64;

        // Skip if too large for cache
        if size > self.max_size_bytes {
            debug!(
                "Compiled component too large for cache: {}MB > {}MB",
                size / 1024 / 1024,
                self.max_size_bytes / 1024 / 1024
            );
            return Ok(());
        }

        // Evict old entries to make room
        while self.total_size + size > self.max_size_bytes && !self.entries.is_empty() {
            self.evict_oldest();
        }

        // Sign: message = checksum || sha256(compiled_bytes)
        let signature = self.create_signature(wasm_checksum, &compiled_bytes);

        // Write files
        let compiled_path = self.dir.join(format!("{}.compiled", wasm_checksum));
        let sig_path = self.dir.join(format!("{}.sig", wasm_checksum));

        fs::write(&compiled_path, &compiled_bytes)
            .with_context(|| format!("Failed to write compiled cache: {:?}", compiled_path))?;
        fs::write(&sig_path, signature.to_bytes())
            .with_context(|| format!("Failed to write signature: {:?}", sig_path))?;

        // Update metadata (remove old entry if exists)
        if let Some(old) = self.entries.remove(wasm_checksum) {
            self.total_size = self.total_size.saturating_sub(old.compiled_size);
        }

        self.entries.insert(
            wasm_checksum.to_string(),
            CacheEntry {
                compiled_size: size,
                last_used: Instant::now(),
            },
        );
        self.total_size += size;

        debug!(
            "⚡ Cached compiled component: {} ({}MB, total: {}MB)",
            wasm_checksum,
            size / 1024 / 1024,
            self.total_size / 1024 / 1024
        );

        Ok(())
    }

    /// Create signature for compiled bytes
    fn create_signature(&self, wasm_checksum: &str, compiled_bytes: &[u8]) -> Signature {
        let message = Self::build_message(wasm_checksum, compiled_bytes);
        self.signing_key.sign(&message)
    }

    /// Verify signature for compiled bytes
    fn verify_signature(
        &self,
        wasm_checksum: &str,
        compiled_bytes: &[u8],
        sig_bytes: &[u8],
    ) -> bool {
        // Parse signature (64 bytes)
        let sig_array: [u8; 64] = match sig_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => return false,
        };
        let signature = Signature::from_bytes(&sig_array);

        // Verify
        let message = Self::build_message(wasm_checksum, compiled_bytes);
        self.verifying_key.verify_strict(&message, &signature).is_ok()
    }

    /// Build message for signing: checksum || sha256(compiled_bytes)
    fn build_message(wasm_checksum: &str, compiled_bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(compiled_bytes);
        let compiled_hash = hasher.finalize();

        let mut message = wasm_checksum.as_bytes().to_vec();
        message.extend_from_slice(&compiled_hash);
        message
    }

    /// Remove entry from memory index
    fn remove_entry(&mut self, checksum: &str) {
        if let Some(entry) = self.entries.remove(checksum) {
            self.total_size = self.total_size.saturating_sub(entry.compiled_size);
        }
    }

    /// Evict oldest (LRU) entry
    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| k.clone());

        if let Some(checksum) = oldest {
            debug!("⚡ Evicting compiled cache entry: {}", checksum);

            if let Some(entry) = self.entries.remove(&checksum) {
                self.total_size = self.total_size.saturating_sub(entry.compiled_size);
            }

            let compiled_path = self.dir.join(format!("{}.compiled", checksum));
            let sig_path = self.dir.join(format!("{}.sig", checksum));
            let _ = fs::remove_file(&compiled_path);
            let _ = fs::remove_file(&sig_path);
        }
    }

    /// Evict entries if over size limit
    fn evict_if_needed(&mut self) {
        while self.total_size > self.max_size_bytes && !self.entries.is_empty() {
            self.evict_oldest();
        }
    }

    /// Get cache statistics: (entries, total_size_bytes, max_size_bytes)
    #[allow(dead_code)]
    pub fn stats(&self) -> (usize, u64, u64) {
        (self.entries.len(), self.total_size, self.max_size_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wasmtime::Config;

    fn create_test_engine() -> Engine {
        let mut config = Config::new();
        config.wasm_component_model(true);
        config.async_support(true);
        config.consume_fuel(true);
        Engine::new(&config).unwrap()
    }

    fn create_test_key() -> [u8; 32] {
        [42u8; 32] // Deterministic test key
    }

    #[test]
    fn test_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cache =
            CompiledCache::new(temp_dir.path().to_path_buf(), 100, &create_test_key()).unwrap();

        assert_eq!(cache.entries.len(), 0);
        assert_eq!(cache.total_size, 0);
    }

    #[test]
    fn test_signature_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let cache =
            CompiledCache::new(temp_dir.path().to_path_buf(), 100, &create_test_key()).unwrap();

        let checksum = "abc123";
        let data = b"test compiled data";

        let sig = cache.create_signature(checksum, data);
        assert!(cache.verify_signature(checksum, data, &sig.to_bytes()));

        // Tampered data should fail
        assert!(!cache.verify_signature(checksum, b"tampered", &sig.to_bytes()));

        // Wrong checksum should fail
        assert!(!cache.verify_signature("wrong", data, &sig.to_bytes()));
    }

    #[test]
    fn test_cache_miss() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache =
            CompiledCache::new(temp_dir.path().to_path_buf(), 100, &create_test_key()).unwrap();

        let engine = create_test_engine();
        let result = cache.get("nonexistent", &engine);
        assert!(result.is_none());
    }

}
