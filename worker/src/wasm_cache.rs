//! WASM LRU Cache
//!
//! Local cache of raw wasm bytes so a re-run does not re-download them from the
//! coordinator. LRU eviction by total size (`WASM_CACHE_MAX_SIZE_MB`).
//!
//! Keyed by the job's `wasm_checksum`, which is not always a content hash: for
//! a WasmUrl publish it is the sha256 of the bytes, for a GitHub build it is
//! the sha256 of `repo:commit:target`, and two binaries built from one commit
//! share it. The cache therefore never trusts the key to authenticate a file.
//!
//! Security: the sha256 of the bytes is recorded IN MEMORY when they are
//! stored — computed from the buffer the coordinator served — and every read
//! is checked against that record. The cache directory may be reachable by a
//! guest (the `/tmp` fallback is inside a P2 component's preopen), so a file
//! on disk can be corrupted or replaced; the record cannot, and a mismatch is
//! a miss followed by a fresh download. Across a restart the in-memory record
//! is gone, so only self-authenticating files — named by their own content
//! hash — are readmitted; anything else on disk is removed.
//!
//! Freshness: a coordinates-keyed entry is served only when the coordinator's
//! current `content_hash` for the key equals the recorded one. A rebuild of
//! the same commit keeps the key and changes the bytes; the coordinator's
//! hash follows the bytes, so the stale copy misses. A content-keyed entry
//! cannot be stale — the key is the bytes.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{debug, info, warn};

/// Cache entry metadata
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Path to cached WASM file
    path: PathBuf,
    /// File size in bytes
    size: u64,
    /// sha256 of the bytes that were stored, recorded from the coordinator's
    /// buffer. The file is verified against THIS on every read, never against
    /// the key; and for a key that is not the content hash, THIS is compared
    /// with what the coordinator reports holding now.
    content_sha256: String,
    /// Last access time (for LRU eviction)
    last_used: Instant,
}

/// WASM LRU Cache with size-based eviction
pub struct WasmCache {
    /// Cache directory
    dir: PathBuf,
    /// Maximum cache size in bytes
    max_size_bytes: u64,
    /// Cache entries: checksum -> entry
    entries: HashMap<String, CacheEntry>,
    /// Current total size
    total_size: u64,
}

impl WasmCache {
    /// Create new cache with specified max size in MB
    ///
    /// # Arguments
    /// * `cache_dir` - Directory to store cached files
    /// * `max_size_mb` - Maximum cache size in megabytes
    pub fn new(cache_dir: PathBuf, max_size_mb: u64) -> Result<Self> {
        // Create cache directory if it doesn't exist
        fs::create_dir_all(&cache_dir)
            .with_context(|| format!("Failed to create cache directory: {:?}", cache_dir))?;

        let max_size_bytes = max_size_mb * 1024 * 1024;

        info!(
            "📦 WASM cache initialized: dir={:?}, max_size={}MB",
            cache_dir, max_size_mb
        );

        let mut cache = Self {
            dir: cache_dir,
            max_size_bytes,
            entries: HashMap::new(),
            total_size: 0,
        };

        // Load existing cache entries from disk
        cache.load_existing_entries()?;

        Ok(cache)
    }

    /// Load existing cache entries from disk on startup
    fn load_existing_entries(&mut self) -> Result<()> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) => {
                warn!("Failed to read cache directory: {}", e);
                return Ok(());
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();

            // Skip non-WASM files
            if path.extension().map(|e| e != "wasm").unwrap_or(true) {
                continue;
            }

            // Extract checksum from filename (format: {checksum}.wasm)
            let checksum = match path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };

            // Get file size
            let metadata = match fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let size = metadata.len();

            // Verify file hash matches filename
            let actual_hash = match Self::compute_file_hash(&path) {
                Ok(h) => h,
                Err(e) => {
                    warn!("Failed to compute hash for {:?}: {}, removing", path, e);
                    let _ = fs::remove_file(&path);
                    continue;
                }
            };

            if actual_hash != checksum {
                warn!(
                    "Cache file hash mismatch: expected {}, got {}, removing",
                    checksum, actual_hash
                );
                let _ = fs::remove_file(&path);
                continue;
            }

            // Self-authenticating: the name is the content hash, so no
            // in-memory record is needed to trust it.
            self.entries.insert(
                checksum.clone(),
                CacheEntry {
                    path,
                    size,
                    content_sha256: checksum,
                    last_used: Instant::now(),
                },
            );
            self.total_size += size;
        }

        info!(
            "📦 Loaded {} cached WASM files ({}MB)",
            self.entries.len(),
            self.total_size / 1024 / 1024
        );

        // Evict if over limit
        self.evict_if_needed();

        Ok(())
    }

    /// Get WASM from cache if available and valid
    ///
    /// # Arguments
    /// * `checksum` - The job's `wasm_checksum` (the key)
    /// * `current_content_hash` - sha256 of the bytes the coordinator holds
    ///   under that key right now; for a key that is not a content hash the
    ///   entry is served only if it was stored from those same bytes
    ///
    /// # Returns
    /// * `Some(bytes)` - Cached WASM bytes (verified against the recorded hash)
    /// * `None` - Cache miss, stale, or verification failed
    pub fn get(&mut self, checksum: &str, current_content_hash: Option<&str>) -> Option<Vec<u8>> {
        let entry = self.entries.get_mut(checksum)?;

        // Update last used time
        entry.last_used = Instant::now();

        // A coordinates-keyed entry is only as fresh as the bytes it was
        // stored from. A coordinator that does not report a hash is a miss,
        // not a match.
        let content_keyed = entry.content_sha256 == checksum;
        if !content_keyed && current_content_hash != Some(entry.content_sha256.as_str()) {
            debug!("WASM cache entry for {} is from another build, dropping", checksum);
            let entry = self.entries.remove(checksum)?;
            self.total_size = self.total_size.saturating_sub(entry.size);
            let _ = fs::remove_file(&entry.path);
            return None;
        }

        // Read file
        let bytes = match fs::read(&entry.path) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to read cached file {:?}: {}", entry.path, e);
                // Remove invalid entry
                let entry = self.entries.remove(checksum)?;
                self.total_size = self.total_size.saturating_sub(entry.size);
                let _ = fs::remove_file(&entry.path);
                return None;
            }
        };

        // Verify against the hash recorded when the bytes were stored — the
        // one thing on this path a guest with access to the directory cannot
        // rewrite.
        let actual_hash = Self::compute_hash(&bytes);
        if actual_hash != entry.content_sha256 {
            crate::ops_events::record(crate::ops_events::Code::WasmCacheTampered, crate::ops_events::Route::Download);
            warn!(
                "⚠️ Cache integrity check failed for {}! Expected {}, got {}. File may be corrupted or tampered.",
                checksum, entry.content_sha256, actual_hash
            );
            // Remove corrupted entry
            let entry = self.entries.remove(checksum)?;
            self.total_size = self.total_size.saturating_sub(entry.size);
            let _ = fs::remove_file(&entry.path);
            return None;
        }

        debug!("✅ WASM cache hit: {} ({}KB)", checksum, bytes.len() / 1024);
        Some(bytes)
    }

    /// Store WASM in cache
    ///
    /// # Arguments
    /// * `checksum` - The job's `wasm_checksum` (the key; not verified against
    ///   the bytes, since for a GitHub build it is not their hash)
    /// * `bytes` - WASM binary data, as served by the coordinator
    ///
    /// # Returns
    /// * `Ok(())` - Successfully cached
    /// * `Err(_)` - Write failed
    pub fn put(&mut self, checksum: &str, bytes: &[u8]) -> Result<()> {
        let content_sha256 = Self::compute_hash(bytes);
        let size = bytes.len() as u64;

        // Skip if single file is larger than max cache size
        if size > self.max_size_bytes {
            warn!(
                "WASM file too large for cache: {}MB > {}MB max",
                size / 1024 / 1024,
                self.max_size_bytes / 1024 / 1024
            );
            return Ok(());
        }

        // Evict old entries until we have space
        while self.total_size + size > self.max_size_bytes && !self.entries.is_empty() {
            self.evict_oldest();
        }

        // Write to disk
        let path = self.dir.join(format!("{}.wasm", checksum));
        fs::write(&path, bytes)
            .with_context(|| format!("Failed to write cache file: {:?}", path))?;

        // Update entry
        if let Some(old_entry) = self.entries.remove(checksum) {
            self.total_size = self.total_size.saturating_sub(old_entry.size);
        }

        self.entries.insert(
            checksum.to_string(),
            CacheEntry {
                path,
                size,
                content_sha256,
                last_used: Instant::now(),
            },
        );
        self.total_size += size;

        debug!(
            "📦 Cached WASM: {} ({}KB, total: {}MB/{}MB)",
            checksum,
            size / 1024,
            self.total_size / 1024 / 1024,
            self.max_size_bytes / 1024 / 1024
        );

        Ok(())
    }

    /// Evict oldest entry (LRU)
    fn evict_oldest(&mut self) {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(_, e)| e.last_used)
            .map(|(k, _)| k.clone());

        if let Some(checksum) = oldest {
            if let Some(entry) = self.entries.remove(&checksum) {
                debug!(
                    "🗑️ Evicting cached WASM: {} ({}KB)",
                    checksum,
                    entry.size / 1024
                );
                self.total_size = self.total_size.saturating_sub(entry.size);
                let _ = fs::remove_file(&entry.path);
            }
        }
    }

    /// Evict entries if over size limit
    fn evict_if_needed(&mut self) {
        while self.total_size > self.max_size_bytes && !self.entries.is_empty() {
            self.evict_oldest();
        }
    }

    /// Compute SHA256 hash of bytes
    fn compute_hash(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    /// Compute SHA256 hash of file
    fn compute_file_hash(path: &PathBuf) -> Result<String> {
        let bytes = fs::read(path)?;
        Ok(Self::compute_hash(&bytes))
    }

    /// Get cache statistics
    #[allow(dead_code)]
    pub fn stats(&self) -> (usize, u64, u64) {
        (self.entries.len(), self.total_size, self.max_size_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_wasm() -> Vec<u8> {
        // Simple valid WASM module (magic number + version)
        vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
    }

    #[test]
    fn test_cache_put_get() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = WasmCache::new(temp_dir.path().to_path_buf(), 10).unwrap();

        let wasm = create_test_wasm();
        let checksum = WasmCache::compute_hash(&wasm);

        cache.put(&checksum, &wasm).unwrap();

        let cached = cache.get(&checksum, None);
        assert!(cached.is_some());
        assert_eq!(cached.unwrap(), wasm);
    }

    #[test]
    fn test_cache_miss() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = WasmCache::new(temp_dir.path().to_path_buf(), 10).unwrap();

        assert!(cache.get("nonexistent", None).is_none());
    }

    #[test]
    fn a_file_is_verified_against_the_hash_recorded_in_memory_not_the_key() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = WasmCache::new(temp_dir.path().to_path_buf(), 10).unwrap();

        // A GitHub build: the key is a hash of coordinates, not of the bytes.
        let wasm = create_test_wasm();
        let content = WasmCache::compute_hash(&wasm);
        let key = "sha256-of-repo-commit-target";
        cache.put(key, &wasm).unwrap();
        assert_eq!(cache.get(key, Some(&content)).unwrap(), wasm);

        // A guest reaching the directory rewrites the file: the record in
        // memory still says what the coordinator served, so this is a miss.
        let path = temp_dir.path().join(format!("{}.wasm", key));
        fs::write(&path, b"tampered").unwrap();
        assert!(cache.get(key, Some(&content)).is_none());
        assert!(!path.exists(), "a tampered file is removed");

        // Same for a content-keyed entry.
        let checksum = WasmCache::compute_hash(&wasm);
        cache.put(&checksum, &wasm).unwrap();
        fs::write(temp_dir.path().join(format!("{}.wasm", checksum)), b"tampered").unwrap();
        assert!(cache.get(&checksum, None).is_none());
    }

    #[test]
    fn a_rebuilt_project_is_not_served_from_the_previous_build() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = WasmCache::new(temp_dir.path().to_path_buf(), 10).unwrap();

        let key = "sha256-of-repo-commit-target";
        let build_1 = create_test_wasm();
        let build_2 = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00];
        cache.put(key, &build_1).unwrap();
        // The coordinator now holds a rebuild under the same key.
        assert!(cache.get(key, Some(&WasmCache::compute_hash(&build_2))).is_none());

        cache.put(key, &build_2).unwrap();
        assert_eq!(cache.get(key, Some(&WasmCache::compute_hash(&build_2))).unwrap(), build_2);
        // ...and a coordinator that reports no hash gets a miss, not a guess.
        assert!(cache.get(key, None).is_none());

        // A content-keyed entry cannot be stale: the key IS the bytes.
        let checksum = WasmCache::compute_hash(&build_1);
        cache.put(&checksum, &build_1).unwrap();
        assert!(cache.get(&checksum, Some("anything")).is_some());
        assert!(cache.get(&checksum, None).is_some());
    }

    #[test]
    fn only_self_authenticating_files_survive_a_restart() {
        let temp_dir = TempDir::new().unwrap();
        let wasm = create_test_wasm();
        let checksum = WasmCache::compute_hash(&wasm);
        {
            let mut cache = WasmCache::new(temp_dir.path().to_path_buf(), 10).unwrap();
            cache.put(&checksum, &wasm).unwrap();
            cache.put("sha256-of-repo-commit-target", &wasm).unwrap();
        }
        // The in-memory records are gone with the process; a file whose name
        // is not its own hash has nothing left to vouch for it.
        let mut cache = WasmCache::new(temp_dir.path().to_path_buf(), 10).unwrap();
        assert!(cache.get(&checksum, None).is_some());
        assert!(cache.get("sha256-of-repo-commit-target", Some(&checksum)).is_none());
        assert!(!temp_dir.path().join("sha256-of-repo-commit-target.wasm").exists());
    }

    #[test]
    fn test_lru_eviction() {
        let temp_dir = TempDir::new().unwrap();
        // Very small cache: 1KB
        let mut cache = WasmCache::new(temp_dir.path().to_path_buf(), 0).unwrap();
        cache.max_size_bytes = 1024; // Override for test

        let wasm1 = vec![0u8; 500];
        let wasm2 = vec![1u8; 500];
        let wasm3 = vec![2u8; 500];

        let checksum1 = WasmCache::compute_hash(&wasm1);
        let checksum2 = WasmCache::compute_hash(&wasm2);
        let checksum3 = WasmCache::compute_hash(&wasm3);

        cache.put(&checksum1, &wasm1).unwrap();
        cache.put(&checksum2, &wasm2).unwrap();

        // Access first one to make it more recent
        cache.get(&checksum1, None);

        // Put third - should evict second (least recently used)
        cache.put(&checksum3, &wasm3).unwrap();

        assert!(cache.get(&checksum1, None).is_some());
        assert!(cache.get(&checksum2, None).is_none());
        assert!(cache.get(&checksum3, None).is_some());
    }
}
