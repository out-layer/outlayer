//! Cryptographic operations for keystore
//!
//! Uses master secret + HMAC-SHA256 to derive repo-specific keypairs.
//! Each repository (with owner) gets a unique keypair derived from the same master secret.
//! All operations are designed to be TEE-safe (no key material leaves secure enclave).
//!
//! Encryption: ECIES with X25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305
//! - Asymmetric: encrypt with public key, only TEE can decrypt with private key
//! - Format v1: [0x01 | ephemeral_x25519_pubkey (32) | nonce (12) | ciphertext | auth_tag (16)]
//! - Legacy format: [nonce (12) | ciphertext | auth_tag (16)] (symmetric, deprecated)

use anyhow::{Context, Result};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use near_primitives::types::AccountId;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

/// Maximum size for encrypted data (10 MB)
const MAX_ENCRYPTED_SIZE: usize = 10 * 1024 * 1024;

/// Keystore holds master secrets and caches derived keypairs.
///
/// The single `master_secret` is split into:
///
/// * `default_master` — the shared OutLayer master, used for Category B
///   (operational) data and any caller that does not name a customer.
///   This is what every legacy secret was encrypted against and what
///   the worker still falls back to when `customer = None`.
/// * `masters` — per-customer (per-vault) masters, populated lazily on
///   first request. `add_customer` inserts; `evict_customer` removes.
///   The map is wrapped in `Arc<RwLock<…>>` so the keystore can be
///   cloned cheaply across handler tasks (read-mostly, write-rare).
///
/// Lookup convention:
///   * `customer = None` ⇒ use `default_master` (legacy / Category B).
///   * `customer = Some(c)` ⇒ require an entry in `masters` for `c`;
///     panic-bail otherwise so callers must `add_customer` first
///     (the lazy-load code path lives one layer up in `mpc_ckd.rs`).
///
/// **Clone semantics — IMPORTANT for the lazy-load gate.** `Clone`
/// duplicates `default_master` byte-for-byte (Copy) but *shares* the
/// `Arc<RwLock<…>>` fields with the original. Snapshotting the
/// keystore via `.clone()` (e.g. inside `AppState::ensure_customer_loaded`)
/// is therefore safe: inserts into the snapshot's `masters` propagate
/// back to all other clones, and reads see whatever the latest writer
/// produced. **Any future field added to this struct that is not
/// `Arc`-shared will break that invariant** — e.g. a per-keystore
/// generation counter would need to be `Arc<AtomicU64>` rather than
/// a plain `u64`. Treat this as a hard constraint when extending.
#[derive(Debug, Clone)]
pub struct Keystore {
    /// Shared OutLayer master (32 bytes, NEVER leaves TEE memory).
    default_master: [u8; 32],

    /// Per-customer masters keyed by vault account id. Populated by
    /// [`Keystore::add_customer`] (typically called from the
    /// `mpc_ckd.rs` lazy-load path after a fresh `vault.add_customer`
    /// MPC CKD round-trip).
    masters: Arc<RwLock<HashMap<AccountId, [u8; 32]>>>,

    /// Cache of derived keypairs. Keyed by `(customer, seed)` so
    /// customer A's keypair for `seed=alice/repo` cannot collide with
    /// customer B's keypair for the same seed.
    keypair_cache: Arc<RwLock<HashMap<(Option<AccountId>, String), (SigningKey, VerifyingKey)>>>,
}

impl Keystore {
    /// Generate a new keystore with random master secret
    ///
    /// In production TEE:
    /// - Master secret is generated using TEE hardware RNG
    /// - Sealed to TEE persistent storage
    /// - Only accessible within the same TEE enclave
    pub fn generate() -> Self {
        let mut default_master = [0u8; 32];
        OsRng.fill_bytes(&mut default_master);

        tracing::info!("Generated new keystore with random default master secret");

        Self {
            default_master,
            masters: Arc::new(RwLock::new(HashMap::new())),
            keypair_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load keystore from existing master secret (hex encoded)
    pub fn from_master_secret_hex(master_secret_hex: &str) -> Result<Self> {
        let bytes = hex::decode(master_secret_hex)
            .context("Invalid hex encoding for master secret")?;

        if bytes.len() != 32 {
            anyhow::bail!("Master secret must be 32 bytes, got {}", bytes.len());
        }

        let mut master_secret = [0u8; 32];
        master_secret.copy_from_slice(&bytes);

        Self::from_master_secret(&master_secret)
    }

    /// Create keystore from master secret bytes
    pub fn from_master_secret(master_secret: &[u8; 32]) -> Result<Self> {
        // Log hash of master secret for debugging (if enabled)
        if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_else(|_| "false".to_string()) == "true" {
            let mut hasher = Sha256::new();
            hasher.update(master_secret);
            let hash = hasher.finalize();
            tracing::warn!("🔑 MASTER KEY HASH (SHA256): {}", hex::encode(hash));
            tracing::warn!("   This is for debugging only! Remove LOG_MASTER_KEY_HASH in production!");
        }

        tracing::info!("Loaded keystore from default master secret");

        Ok(Self {
            default_master: *master_secret,
            masters: Arc::new(RwLock::new(HashMap::new())),
            keypair_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Export the default master as hex (for backup / persistence).
    ///
    /// **WARNING:** only for initial setup or backup. Per-customer
    /// (per-vault) masters are NOT included — they are re-derivable
    /// lazily through MPC CKD on demand and never persisted to disk.
    /// The name says `default_master_hex` deliberately so a future
    /// reader can't confuse this with "back up everything"; backing
    /// this up only restores the OutLayer master, not customer state.
    pub fn default_master_hex(&self) -> String {
        hex::encode(self.default_master)
    }

    // =========================================================================
    // Per-customer master management
    // =========================================================================

    /// Insert a per-customer (per-vault) master. Called by
    /// `mpc_ckd.rs::add_customer` after a successful Layer-2 CKD
    /// round-trip materialises the per-vault master inside the TEE.
    ///
    /// Idempotent: re-inserting the same master overwrites the entry.
    /// The keypair cache is invalidated for this customer so any
    /// previously-cached keypairs (which would have been derived from
    /// a stale master) are dropped.
    pub fn add_customer(&self, customer: AccountId, master: [u8; 32]) {
        {
            let mut masters = self.masters.write().unwrap();
            masters.insert(customer.clone(), master);
        }
        self.evict_customer_cache(&customer);
        tracing::info!(
            customer = %customer,
            "Per-customer master loaded into keystore"
        );
    }

    /// Remove a per-customer master and drop any cached keypairs for
    /// it. Called from the `/admin/evict-customer` endpoint when the
    /// monitoring service detects a vault should no longer operate
    /// (race-attack ban, etc.). Subsequent derive_* calls for this
    /// customer will fail until `add_customer` is called again.
    pub fn evict_customer(&self, customer: &AccountId) {
        {
            let mut masters = self.masters.write().unwrap();
            masters.remove(customer);
        }
        self.evict_customer_cache(customer);
        tracing::info!(customer = %customer, "Per-customer master evicted");
    }

    /// Returns `true` if a per-customer master is currently loaded.
    /// Used by the lazy-load gate to decide whether to skip MPC CKD.
    pub fn has_customer(&self, customer: &AccountId) -> bool {
        self.masters.read().unwrap().contains_key(customer)
    }

    /// Vault ids whose master is currently in memory — addresses only, never key material.
    ///
    /// Operational visibility for `/admin/loaded-vaults`: the map is rebuilt from scratch after
    /// every restart, one on-chain CKD derivation per vault, so this is also the record of which
    /// vaults have paid that cost since this instance came up.
    pub fn loaded_customers(&self) -> Vec<AccountId> {
        let mut ids: Vec<AccountId> = self.masters.read().unwrap().keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Drop every cache entry whose key references the given customer.
    fn evict_customer_cache(&self, customer: &AccountId) {
        let mut cache = self.keypair_cache.write().unwrap();
        cache.retain(|(c, _), _| c.as_ref() != Some(customer));
    }

    /// Resolve a `customer` parameter to the master bytes that should
    /// be used as the HMAC key for derivation.
    ///
    /// * `None` ⇒ `default_master`.
    /// * `Some(c)` ⇒ master from the `masters` map; bail with a
    ///   diagnostic error if missing — the lazy-load layer must run
    ///   `add_customer` before invoking any derive_* method.
    fn master_for(&self, customer: Option<&AccountId>) -> Result<[u8; 32]> {
        let masters = self.masters.read().unwrap();
        Self::master_from_loaded(self.default_master, &masters, customer)
    }

    /// Same resolution as [`Self::master_for`], but reading from a guard the caller already
    /// holds. Exists so [`Self::derive_keypair`] can keep the `masters` read lock from the
    /// lookup until after it has written the derived keypair into the cache — see the lock
    /// discipline note there. One implementation so the two cannot answer differently.
    fn master_from_loaded(
        default_master: [u8; 32],
        masters: &HashMap<AccountId, [u8; 32]>,
        customer: Option<&AccountId>,
    ) -> Result<[u8; 32]> {
        match customer {
            None => Ok(default_master),
            Some(c) => masters.get(c).copied().ok_or_else(|| {
                anyhow::anyhow!(
                    "per-customer master not loaded for {c}; \
                     run mpc_ckd::add_customer first"
                )
            }),
        }
    }

    /// Derive an Ed25519 keypair from `(customer, seed)`.
    ///
    /// `customer = None` uses the OutLayer default master; `Some(c)`
    /// uses customer `c`'s per-vault master (must be loaded via
    /// [`Keystore::add_customer`] first — otherwise this returns an
    /// error). Different `customer` values produce disjoint keyspaces
    /// for the SAME seed — that is the customer-isolation invariant.
    ///
    /// Seed format examples:
    /// - `"github.com/alice/project:alice.near"` (all branches)
    /// - `"github.com/alice/project:alice.near:main"` (specific branch)
    ///
    /// Uses `HMAC-SHA256(master, seed)`; deterministic for any
    /// fixed `(master, seed)` pair.
    ///
    /// # Domain separation
    ///
    /// This method (and [`Keystore::derive_secp256k1_keypair`]) feed
    /// `seed` directly into HMAC without a curve-tag. Cross-curve
    /// safety relies on caller convention: every chain uses a
    /// distinct seed suffix (`wallet:{id}:near` vs
    /// `wallet:{id}:eth`, etc.), so the HMAC inputs never collide
    /// in practice.
    ///
    /// **For future maintainers adding a new curve / KDF use-case:**
    /// always prepend a unique curve-domain prefix to the HMAC input
    /// (`mac.update(b"ed448:")` or similar). Don't copy this bare
    /// pattern. Pin a `(master, seed) → pubkey` regression fixture
    /// alongside the new method so accidental input changes surface
    /// as test failures.
    ///
    /// # ⚠ Domain separation: bare HMAC, intentional
    ///
    /// This method does NOT prepend a curve-tag (e.g. `b"ed25519:"`)
    /// to the HMAC input. [`Keystore::derive_secp256k1_keypair`] uses
    /// the same bare pattern. [`Keystore::derive_x25519_keypair`]
    /// (ECIES) does prepend `b"ecies:"`.
    ///
    /// The asymmetry is a historical artifact preserved deliberately:
    /// adding a curve-tag here would change the HMAC output for every
    /// existing `(master, seed)` pair, which would rotate every
    /// already-derived NEAR / EVM address ever served to a customer.
    /// Funds parked at those addresses would become unsignable from
    /// the keystore (the new derivation produces different scalars).
    /// Migrating safely requires a multi-week dual-derivation rollout
    /// and customer-side asset moves; it is not a single-PR fix.
    ///
    /// **Cross-curve safety today** rests on caller convention:
    /// every chain uses a distinct seed suffix
    /// (`wallet:{id}:near` for Ed25519, `wallet:{id}:eth` for
    /// secp256k1, `check:{counter}` for ephemerals, etc.), so the
    /// HMAC inputs never collide across curves in practice. This is
    /// enforced by code review, not by the type system.
    ///
    /// **For future maintainers adding a new curve / KDF use:**
    ///   1. Always include a unique curve-domain prefix in the HMAC
    ///      input — `mac.update(b"ed448:")` or similar — even if you
    ///      "know" your seed already varies. Don't copy the bare
    ///      pattern of this method.
    ///   2. Add a regression test pinning a known `(master, seed) →
    ///      pubkey` fixture so an accidental input change shows up
    ///      as a test failure rather than a silent address rotation.
    ///      See the existing fixtures in the `tests` module below.
    ///
    /// See `SECURITY.md` and audit report M-1 for the full background
    /// and the migration plan template.
    pub fn derive_keypair(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
    ) -> Result<(SigningKey, VerifyingKey)> {
        let cache_key = (customer.cloned(), seed.to_string());
        // Check cache first
        {
            let cache = self.keypair_cache.read().unwrap();
            if let Some(keypair) = cache.get(&cache_key) {
                return Ok(keypair.clone());
            }
        }

        // Derive keypair using HMAC-SHA256 over the appropriate master.
        //
        // LOCK DISCIPLINE: the `masters` read guard is held from the lookup until AFTER the
        // cache insert below, and this is load-bearing. `evict_customer` removes the master
        // and THEN purges this cache, as two separate critical sections. If the guard were
        // released here (as it was before), an eviction could land in between and the insert
        // would put a live `SigningKey` for that vault back into the cache — surviving the
        // very purge the eviction exists to perform, and leaving usable key material in TEE
        // memory for a vault that is no longer ours to serve. Holding the guard makes the two
        // orders the only possible ones: either we insert first and the eviction's purge
        // catches it, or the eviction wins and the lookup below fails, so nothing is inserted.
        //
        // Deadlock-free because the order is always `masters` → `keypair_cache`, the same as
        // in `add_customer`/`evict_customer`, and nothing takes `masters` while holding the
        // cache. The section contains no `.await` and no fallible allocation — only an HMAC
        // over 32 bytes — so a writer waits microseconds.
        let masters = self.masters.read().unwrap();
        let master = Self::master_from_loaded(self.default_master, &masters, customer)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&master)
            .expect("HMAC can take key of any size");
        mac.update(seed.as_bytes());
        let derived_bytes = mac.finalize().into_bytes();

        // Use first 32 bytes as Ed25519 secret key
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&derived_bytes[..32]);

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();

        tracing::debug!(
            customer = ?customer,
            "Derived keypair for seed='{}', pubkey={}",
            seed,
            hex::encode(verifying_key.as_bytes())
        );

        // Cache the result — still under the `masters` guard taken above.
        {
            let mut cache = self.keypair_cache.write().unwrap();
            cache.insert(cache_key, (signing_key.clone(), verifying_key));
        }
        drop(masters);

        Ok((signing_key, verifying_key))
    }

    /// Get Ed25519 public key for `(customer, seed)`.
    pub fn get_public_key_for_seed(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
    ) -> Result<VerifyingKey> {
        let (_signing_key, verifying_key) = self.derive_keypair(customer, seed)?;
        Ok(verifying_key)
    }

    /// Derive X25519 keypair from `(customer, seed)` (for ECIES).
    ///
    /// Domain-separated `HMAC-SHA256(master, "ecies:" || seed)` so the
    /// encryption keys are independent from Ed25519 signing keys.
    fn derive_x25519_keypair(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
    ) -> Result<(StaticSecret, X25519PublicKey)> {
        let master = self.master_for(customer)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&master)
            .expect("HMAC can take key of any size");
        mac.update(b"ecies:");
        mac.update(seed.as_bytes());
        let derived_bytes = mac.finalize().into_bytes();

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&derived_bytes[..32]);

        let static_secret = StaticSecret::from(secret_bytes);
        let public_key = X25519PublicKey::from(&static_secret);
        Ok((static_secret, public_key))
    }

    /// Derive a deterministic string from `(customer, seed)` suitable for
    /// use as the MPC CKD `derivation_path` argument.
    ///
    /// Produces a 64-char lowercase hex digest of `HMAC-SHA256(master, "secret-path:" || seed)`.
    ///
    /// **Why this matters (Layer 2 of per-vault master derivation):** the
    /// per-customer master is requested from MPC by signing FROM the
    /// customer's vault account. The MPC contract derives a per-app key
    /// from `SHA3(prefix || predecessor || derivation_path)`. If the
    /// derivation_path were customer-controllable (e.g. literally `vault.id`
    /// or empty string), a malicious customer with a backup vault key could
    /// pre-empt the worker and call MPC themselves before vault-checker
    /// runs, getting the same master.
    ///
    /// **Race-window protection, not forever-secret.** Before the worker's
    /// first MPC call, the path is unguessable without OutLayer master
    /// access — that's the property that buys us the race-window. After
    /// the worker submits the tx, the path goes on-chain in plaintext as
    /// part of the tx args; from that moment it is publicly visible. The
    /// race-attack mitigation is therefore *first-write-wins*: an
    /// off-chain indexer watches for duplicate `(predecessor, path)`
    /// pairs and bans vaults that race the worker. Pair this with the
    /// guarantee that a customer can't compute the path before the
    /// worker uses it, and the attack surface collapses to a few-block
    /// window that the indexer covers.
    ///
    /// Recovery flow still works: any approved TEE has the default
    /// master, can re-derive the same path, and gets the same master
    /// back from MPC.
    ///
    /// Domain separator `"secret-path:"` keeps this output disjoint from
    /// `derive_keypair`/`derive_x25519_keypair`/etc. for the same seed.
    pub fn derive_secret_string(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
    ) -> Result<String> {
        let master = self.master_for(customer)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&master)
            .expect("HMAC can take key of any size");
        mac.update(b"secret-path:");
        mac.update(seed.as_bytes());
        let digest = mac.finalize().into_bytes();
        Ok(hex::encode(digest))
    }

    /// The 32-byte seed of one signing key: `HMAC-SHA256(master, input)`.
    ///
    /// `input` is a [`crate::signing_keys::DerivationInput`], which only the
    /// signing-keys module can build, from validated fields, under the
    /// `signing-key:v1:` root — so this method cannot be made to derive under
    /// any other seed. `vault = None` is the default master; `Some(v)` is that
    /// vault's master and fails if it is not loaded — never the default master
    /// in its place.
    ///
    /// Not cached: the seed is returned to the caller in a buffer that is
    /// wiped when dropped, and no copy stays in this keystore.
    pub fn derive_signing_key_seed(
        &self,
        vault: Option<&AccountId>,
        input: &crate::signing_keys::DerivationInput,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let master = zeroize::Zeroizing::new(self.master_for(vault)?);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(master.as_ref())
            .expect("HMAC can take key of any size");
        mac.update(input.as_bytes());
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&mac.finalize().into_bytes());
        Ok(seed)
    }

    /// Get X25519 public key as hex string for `(customer, seed)`
    /// (the key returned by `/pubkey`). Safe to expose publicly — it
    /// can only encrypt, not decrypt. Only the TEE holds the private key.
    pub fn public_key_hex(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
    ) -> Result<String> {
        let (_, x25519_pub) = self.derive_x25519_keypair(customer, seed)?;
        Ok(hex::encode(x25519_pub.as_bytes()))
    }

    /// Get Ed25519 public key as base58 string (NEAR format) for
    /// `(customer, seed)`.
    #[allow(dead_code)]
    pub fn public_key_base58(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
    ) -> Result<String> {
        let verifying_key = self.get_public_key_for_seed(customer, seed)?;
        Ok(bs58::encode(verifying_key.as_bytes()).into_string())
    }

    /// HKDF info string — must be identical across all implementations (Rust, TypeScript)
    const HKDF_INFO: &'static [u8] = b"outlayer-keystore-v1";

    /// Version byte for ECIES format
    const ECIES_VERSION: u8 = 0x01;

    /// Decrypt data that was encrypted for a specific seed
    ///
    /// Supports both formats:
    /// - ECIES v1: [0x01 | ephemeral_x25519_pubkey (32) | nonce (12) | ciphertext | tag (16)]
    /// - Legacy:   [nonce (12) | ciphertext | tag (16)] (symmetric, pubkey as ChaCha20 key)
    pub fn decrypt(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        if encrypted_data.len() > MAX_ENCRYPTED_SIZE {
            anyhow::bail!("Encrypted data too large: {} bytes", encrypted_data.len());
        }

        // Minimum legacy size: 12 (nonce) + 16 (tag) = 28 bytes
        if encrypted_data.len() < 28 {
            anyhow::bail!(
                "Encrypted data too short: {} bytes (minimum 28)",
                encrypted_data.len()
            );
        }

        // Try ECIES v1 format: [0x01 | ephemeral_pub(32) | nonce(12) | ciphertext | tag(16)]
        // Minimum ECIES size: 1 + 32 + 12 + 16 = 61 bytes
        if encrypted_data[0] == Self::ECIES_VERSION && encrypted_data.len() >= 61 {
            match self.decrypt_ecies(customer, seed, encrypted_data) {
                Ok(plaintext) => return Ok(plaintext),
                Err(e) => {
                    // AEAD failure could mean this is legacy data that happens to start with 0x01
                    tracing::debug!("ECIES decrypt failed, trying legacy format: {}", e);
                }
            }
        }

        // Legacy format: [nonce(12) | ciphertext | tag(16)]
        self.decrypt_legacy(customer, seed, encrypted_data)
    }

    /// Decrypt ECIES v1 format
    fn decrypt_ecies(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        let ephemeral_pub_bytes: [u8; 32] = encrypted_data[1..33]
            .try_into()
            .context("Invalid ephemeral public key")?;
        let ephemeral_pub = X25519PublicKey::from(ephemeral_pub_bytes);

        let (x25519_secret, _) = self.derive_x25519_keypair(customer, seed)?;
        let shared_secret = x25519_secret.diffie_hellman(&ephemeral_pub);

        let sym_key = Self::hkdf_derive_key(shared_secret.as_bytes())?;
        let cipher = ChaCha20Poly1305::new((&sym_key).into());

        let nonce = Nonce::from_slice(&encrypted_data[33..45]);
        let ciphertext_with_tag = &encrypted_data[45..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|e| anyhow::anyhow!("ECIES decryption failed: {}", e))?;

        Ok(plaintext)
    }

    /// Decrypt legacy format (symmetric, Ed25519 pubkey as ChaCha20 key)
    /// TODO: Remove after migration of all secrets to ECIES format
    fn decrypt_legacy(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
        encrypted_data: &[u8],
    ) -> Result<Vec<u8>> {
        let (_signing_key, verifying_key) = self.derive_keypair(customer, seed)?;

        let key_bytes = verifying_key.to_bytes();
        let cipher = ChaCha20Poly1305::new((&key_bytes).into());

        let nonce = Nonce::from_slice(&encrypted_data[0..12]);
        let ciphertext_with_tag = &encrypted_data[12..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext_with_tag)
            .map_err(|e| anyhow::anyhow!("Legacy decryption failed (data tampered or wrong key): {}", e))?;

        Ok(plaintext)
    }

    /// Encrypt plaintext for `(customer, seed)` using ECIES.
    ///
    /// Uses ephemeral X25519 keypair + ECDH + HKDF-SHA256 + ChaCha20-Poly1305.
    /// Returns: `[0x01 | ephemeral_x25519_pubkey (32) | nonce (12) | ciphertext | auth_tag (16)]`.
    pub fn encrypt(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_ENCRYPTED_SIZE {
            anyhow::bail!("Plaintext too large: {} bytes", plaintext.len());
        }

        let (_, recipient_pub) = self.derive_x25519_keypair(customer, seed)?;

        // Generate ephemeral X25519 keypair
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pub = X25519PublicKey::from(&ephemeral_secret);

        // ECDH shared secret
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_pub);

        // Derive symmetric key via HKDF-SHA256
        let sym_key = Self::hkdf_derive_key(shared_secret.as_bytes())?;
        let cipher = ChaCha20Poly1305::new((&sym_key).into());

        // Generate random 12-byte nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

        // Encrypt
        let ciphertext_with_tag = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Format: [0x01 | ephemeral_pub(32) | nonce(12) | ciphertext | tag(16)]
        let mut result = Vec::with_capacity(1 + 32 + 12 + ciphertext_with_tag.len());
        result.push(Self::ECIES_VERSION);
        result.extend_from_slice(ephemeral_pub.as_bytes());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext_with_tag);

        Ok(result)
    }

    /// Derive 32-byte symmetric key from ECDH shared secret using HKDF-SHA256
    fn hkdf_derive_key(shared_secret: &[u8]) -> Result<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; 32];
        hkdf.expand(Self::HKDF_INFO, &mut key)
            .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;
        Ok(key)
    }

    /// Sign a message with the Ed25519 private key for `(customer, seed)`.
    #[allow(dead_code)]
    pub fn sign(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
        message: &[u8],
    ) -> Result<Signature> {
        let (signing_key, _) = self.derive_keypair(customer, seed)?;
        Ok(signing_key.sign(message))
    }

    /// Verify an Ed25519 signature for `(customer, seed)`.
    #[allow(dead_code)]
    pub fn verify(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        let (_, verifying_key) = self.derive_keypair(customer, seed)?;
        verifying_key
            .verify(message, signature)
            .context("Signature verification failed")
    }

    // =========================================================================
    // secp256k1 (Ethereum/Base/EVM chains)
    // See: docs/MULTI_CHAIN.md for integration guide
    // =========================================================================

    /// Derive a secp256k1 keypair from `(customer, seed)` (for EVM chains).
    ///
    /// Same HMAC-SHA256 derivation as Ed25519, with the 32-byte output
    /// interpreted as a secp256k1 scalar.
    ///
    /// Note: like [`Keystore::derive_keypair`], this feeds `seed` into
    /// HMAC without a curve-tag prefix. See that method's `Domain
    /// separation` doc-section for the convention any future curve
    /// addition MUST follow.
    pub fn derive_secp256k1_keypair(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
    ) -> Result<(k256::ecdsa::SigningKey, k256::elliptic_curve::PublicKey<k256::Secp256k1>)> {
        let master = self.master_for(customer)?;
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&master)
            .expect("HMAC can take key of any size");
        mac.update(seed.as_bytes());
        let derived_bytes = mac.finalize().into_bytes();

        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&derived_bytes[..32]);
        let signing_key = k256::ecdsa::SigningKey::from_slice(&secret_bytes)
            .context("Derived bytes are not a valid secp256k1 scalar (astronomically unlikely)")?;
        let public_key = signing_key.verifying_key().into();

        Ok((signing_key, public_key))
    }

    /// Derive Ethereum address from `(customer, seed)`:
    /// `keccak256(uncompressed_pubkey[1..65])[12..32]`.
    pub fn derive_eth_address(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
    ) -> Result<(String, String)> {
        let (_, public_key) = self.derive_secp256k1_keypair(customer, seed)?;

        // Uncompressed public key = 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes
        let uncompressed = public_key.to_encoded_point(false);
        let pubkey_bytes = &uncompressed.as_bytes()[1..]; // skip 0x04 prefix

        use sha3::{Digest as Sha3Digest, Keccak256};
        let hash = Keccak256::digest(pubkey_bytes);
        let address = format!("0x{}", hex::encode(&hash[12..]));

        // Return compressed public key (33 bytes) for on-chain storage
        let compressed = public_key.to_encoded_point(true);
        let pubkey_hex = hex::encode(compressed.as_bytes());

        Ok((address, pubkey_hex))
    }

    // NOTE: the old `sign_secp256k1` (k256 default Signer — SHA-256 prehash,
    // non-recoverable 64-byte r‖s, no `v`) was REMOVED. It was never an EVM
    // signer and had no remaining callers once Op::Raw EVM was retired in favor
    // of the /wallet/evm/* endpoints. All EVM signing goes through
    // [`Keystore::sign_secp256k1_prehash`] (keccak prehash, recoverable r‖s‖v).

    /// Sign a **32-byte keccak256 prehash** with secp256k1 ECDSA for
    /// `(customer, seed)`, returning a recoverable Ethereum signature.
    ///
    /// This is the EVM signing primitive. The caller supplies the
    /// already-computed digest (the EIP-712 signing hash, the EIP-191
    /// `personal_sign` hash, or an EIP-1559 tx sighash) — this method
    /// signs it **without any further hashing**.
    ///
    /// Returns 65 bytes: `r (32) ‖ s (32) ‖ v (1)`, where `s` is
    /// low-S normalized (EIP-2) and `v ∈ {27, 28}` (legacy EVM
    /// convention; the caller adds the EIP-155 chain offset for raw
    /// transactions if/when those are supported). `ecrecover` over
    /// `digest` with this signature returns the address from
    /// [`Keystore::derive_eth_address`] for the same `(customer, seed)`.
    ///
    /// Deterministic: `k256` uses an RFC-6979 nonce, so the signature
    /// is a pure function of `(master, seed, digest)`.
    pub fn sign_secp256k1_prehash(
        &self,
        customer: Option<&AccountId>,
        seed: &str,
        digest: &[u8; 32],
    ) -> Result<[u8; 65]> {
        let (signing_key, _) = self.derive_secp256k1_keypair(customer, seed)?;
        // `sign_prehash_recoverable` normalizes `s` to the low half and
        // returns the recovery id that matches the normalized signature.
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(digest)
            .context("secp256k1 recoverable signing failed")?;
        // recovery_id is 0/1 in practice; bit 1 (x-coordinate reduced mod n) is
        // set only when k·G's x ≥ the curve order — probability ~2^-128, and not
        // grindable (RFC-6979 nonce is fixed per (key,digest)). If it ever fires,
        // `v` would be 29/30, which no `ecrecover` accepts, so fail closed rather
        // than return a signature that breaks the documented `v ∈ {27,28}`.
        if recovery_id.to_byte() >= 2 {
            anyhow::bail!(
                "secp256k1 recovery id {} has a reduced x-coordinate; cannot produce v in {{27,28}}",
                recovery_id.to_byte()
            );
        }
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&signature.to_bytes());
        out[64] = 27 + recovery_id.to_byte();
        Ok(out)
    }

    /// Generate VRF output and proof for the given alpha bytes.
    ///
    /// Uses Ed25519 deterministic signature (RFC 8032) as VRF:
    /// - Proof = Ed25519 signature of alpha (deterministic: same key + same alpha = same signature)
    /// - Output = SHA256(signature) (random bytes derived from proof)
    ///
    /// Verification: `ed25519_verify(vrf_pubkey, alpha, signature)` — works on-chain in NEAR contracts.
    /// The VRF key is derived from master_secret with fixed seed "vrf-key".
    ///
    /// Returns (output_hex, signature_hex).
    ///
    /// **Always uses the OutLayer default master**, regardless of which
    /// customer is calling. VRF is Category B (operational randomness)
    /// per the per-vault master plan — its lifetime is tied to the
    /// coordinator, not to any individual customer/vault.
    pub fn vrf_generate(&self, alpha: &[u8]) -> Result<(String, String)> {
        let (signing_key, _) = self.derive_keypair(None, "vrf-key")?;
        let signature = signing_key.sign(alpha);

        let mut hasher = Sha256::new();
        hasher.update(signature.to_bytes());
        let output = hasher.finalize();

        Ok((hex::encode(output), hex::encode(signature.to_bytes())))
    }

    /// Get the VRF public key as hex string. Always derived from the
    /// default master (Category B).
    pub fn vrf_public_key_hex(&self) -> Result<String> {
        let (_, verifying_key) = self.derive_keypair(None, "vrf-key")?;
        Ok(hex::encode(verifying_key.as_bytes()))
    }

    /// Clear the keypair cache (for testing or memory management)
    #[allow(dead_code)]
    pub fn clear_cache(&self) {
        let mut cache = self.keypair_cache.write().unwrap();
        cache.clear();
        tracing::debug!("Cleared keypair cache");
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn test_keystore_generation() {
        let keystore = Keystore::generate();
        let pubkey = keystore.public_key_hex(None, "test-seed").unwrap();
        assert_eq!(pubkey.len(), 64); // 32 bytes = 64 hex chars
    }

    /// Eviction must actually remove key material, even under concurrent derivation.
    ///
    /// `evict_customer` drops the master and then purges the keypair cache, as two separate
    /// critical sections. A derivation that had already read the master could slip between
    /// them and insert a live `SigningKey` for the evicted vault back into the cache, where it
    /// would stay until the process restarted — defeating `/admin/evict-customer`, which the
    /// race-attack monitor calls precisely to get that key material out of TEE memory.
    ///
    /// The property under test: once `evict_customer` has returned, NOTHING may put a key for
    /// that vault back into the cache, because there is no longer a master to derive from.
    /// The test cannot fail spuriously — the fixed code makes that state unreachable — but it
    /// samples a race, so it is deliberately run over many rounds. Verified to catch the
    /// original code.
    #[test]
    fn eviction_cannot_be_outrun_by_an_in_flight_derivation() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let keystore = Keystore::generate();
        let vault: AccountId = "vault.alice.testnet".parse().unwrap();
        let stop = Arc::new(AtomicBool::new(false));

        // Hammer derivations for this vault. Each uses a fresh seed so every call misses the
        // cache and reaches the master lookup — that is the window being tested.
        let hammers: Vec<_> = (0..4)
            .map(|t| {
                let keystore = keystore.clone();
                let vault = vault.clone();
                let stop = stop.clone();
                std::thread::spawn(move || {
                    let mut i = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let _ = keystore.derive_keypair(Some(&vault), &format!("wallet:{t}:{i}"));
                        i += 1;
                    }
                })
            })
            .collect();

        for round in 0..200u32 {
            keystore.add_customer(vault.clone(), [round as u8; 32]);
            // Leave the master in place long enough for the hammering threads to be somewhere
            // inside a derivation when the eviction below lands.
            std::thread::sleep(std::time::Duration::from_micros(200));
            keystore.evict_customer(&vault);

            for _ in 0..50 {
                let leaked: Vec<String> = keystore
                    .keypair_cache
                    .read()
                    .unwrap()
                    .keys()
                    .filter(|(c, _)| c.as_ref() == Some(&vault))
                    .map(|(_, seed)| seed.clone())
                    .collect();
                assert!(
                    leaked.is_empty(),
                    "round {round}: signing keys for an evicted vault survived in the cache: {leaked:?}"
                );
            }
        }

        stop.store(true, Ordering::Relaxed);
        for h in hammers {
            h.join().expect("hammer thread");
        }
    }

    #[test]
    fn test_deterministic_derivation() {
        let keystore = Keystore::generate();

        let pubkey1 = keystore.public_key_hex(None, "github.com/alice/project:alice.near").unwrap();
        let pubkey2 = keystore.public_key_hex(None, "github.com/alice/project:alice.near").unwrap();

        assert_eq!(pubkey1, pubkey2, "Same seed should produce same key");
    }

    #[test]
    fn test_different_seeds_different_keys() {
        let keystore = Keystore::generate();

        let pubkey_alice = keystore.public_key_hex(None, "github.com/alice/project:alice.near").unwrap();
        let pubkey_bob = keystore.public_key_hex(None, "github.com/alice/project:bob.near").unwrap();

        assert_ne!(pubkey_alice, pubkey_bob, "Different seeds should produce different keys");
    }

    #[test]
    fn test_encrypt_decrypt_ecies() {
        let keystore = Keystore::generate();
        let seed = "github.com/alice/project:alice.near";
        let plaintext = b"my secret API key: sk-1234567890";

        let encrypted = keystore.encrypt(None, seed, plaintext).unwrap();

        // Verify ECIES format: starts with version byte
        assert_eq!(encrypted[0], Keystore::ECIES_VERSION);
        // Minimum size: 1 + 32 + 12 + 16 = 61 (+ plaintext)
        assert!(encrypted.len() >= 61);

        let decrypted = keystore.decrypt(None, seed, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Lock-down for the /wallet/sign-policy oracle (audit round 2, #1): the endpoint must
    /// DECRYPT-VALIDATE `encrypted_data` before it signs anything with the wallet's `:near`
    /// tx key. This mirrors that gate against a real Keystore and proves: (a) arbitrary bytes
    /// / a tx_hash / another wallet's ciphertext FAIL decryption → never reach signing (so a
    /// transaction can't be forged); (d) a genuine policy ciphertext passes and signs.
    ///
    /// The MESSAGE is no longer the bare `sha256(encrypted_data)` — the contract now verifies
    /// a domain-separated string naming the caller, pinned by `the_policy_store_message_format_is_pinned`
    /// in `api.rs`. What is exercised here is the gate, which is orthogonal to the message and
    /// still the reason a caller cannot choose the bytes being signed.
    #[test]
    fn sign_policy_decrypt_validation_blocks_tx_forging_and_keeps_legit_flow() {
        use sha2::{Digest, Sha256};

        let ks = Keystore::generate();
        let wid = "wallet-abc";
        let policy_seed = format!("wallet-policy:{}", wid);
        let near_seed = format!("wallet:{}:near", wid);
        let b64 = base64::engine::general_purpose::STANDARD;

        // ── legit policy ciphertext ──────────────────────────────────────────────
        let policy_json = br#"{"rules":{"transaction_types":["transfer"]}}"#;
        let ct = ks.encrypt(None, &policy_seed, policy_json).unwrap();
        let encrypted_data = b64.encode(&ct); // the `encrypted_data` string the handler gets

        // (a)+ : decrypt-validate succeeds for the genuine ciphertext (the gate passes).
        let pt = ks.decrypt(None, &policy_seed, &b64.decode(&encrypted_data).unwrap()).unwrap();
        assert_eq!(pt, policy_json, "genuine policy must decrypt to its plaintext");

        // (d): a blob that passed the gate can be signed and verified with the wallet's
        // `:near` key. The exact preimage is the message builder's business — see
        // `api.rs` — so this signs the blob's hash as a stand-in and checks the key round
        // trip, which is what this file is about.
        let msg_hash = Sha256::digest(encrypted_data.as_bytes());
        let sig = ks.sign(None, &near_seed, &msg_hash).unwrap();
        assert!(
            ks.verify(None, &near_seed, &msg_hash, &sig).is_ok(),
            "a policy that passed the gate must sign and verify under the wallet's own key"
        );

        // (a): the EXACT original attack — encrypted_data = borsh(tx) (arbitrary bytes). The
        // AEAD auth tag can't verify for non-ciphertext, so decrypt FAILS → the handler
        // refuses → no signature → no forged tx_hash signed.
        let fake_tx = vec![0x07u8; 180]; // stand-in for borsh(SignedTransaction)
        assert!(
            ks.decrypt(None, &policy_seed, &fake_tx).is_err(),
            "arbitrary bytes (borsh(tx)) MUST fail decryption — never signed"
        );

        // (b): a raw 32-byte value (a real tx_hash, the old pre-computed-hash input) is not a
        // valid ciphertext → fails decryption → rejected.
        let tx_hash = vec![0x09u8; 32];
        assert!(
            ks.decrypt(None, &policy_seed, &tx_hash).is_err(),
            "a raw 32-byte tx_hash MUST fail decryption — never signed"
        );

        // wrong-wallet ciphertext (encrypted under a different policy key) also fails.
        let other_ct = ks.encrypt(None, "wallet-policy:other", policy_json).unwrap();
        assert!(
            ks.decrypt(None, &policy_seed, &other_ct).is_err(),
            "another wallet's policy ciphertext MUST fail this wallet's decrypt"
        );
    }

    #[test]
    fn test_decrypt_legacy_format() {
        let keystore = Keystore::generate();
        let seed = "github.com/alice/project:alice.near";
        let plaintext = b"legacy secret data";

        // Manually create legacy format: [nonce(12) | ciphertext | tag(16)]
        let (_, verifying_key) = keystore.derive_keypair(None, seed).unwrap();
        let key_bytes = verifying_key.to_bytes();
        let cipher = ChaCha20Poly1305::new((&key_bytes).into());
        let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);
        let ciphertext_with_tag = cipher.encrypt(&nonce, &plaintext[..]).unwrap();
        let mut legacy_encrypted = Vec::new();
        legacy_encrypted.extend_from_slice(&nonce);
        legacy_encrypted.extend_from_slice(&ciphertext_with_tag);

        // decrypt() should handle the legacy format via fallback
        let decrypted = keystore.decrypt(None, seed, &legacy_encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ecies_pubkey_cannot_decrypt() {
        let keystore = Keystore::generate();
        let seed = "github.com/alice/project:alice.near";
        let plaintext = b"secret";

        let encrypted = keystore.encrypt(None, seed, plaintext).unwrap();
        let pubkey_hex = keystore.public_key_hex(None, seed).unwrap();
        let pubkey_bytes = hex::decode(&pubkey_hex).unwrap();

        // Try using the public key as a ChaCha20 symmetric key (the old vulnerable way)
        let cipher = ChaCha20Poly1305::new_from_slice(&pubkey_bytes).unwrap();
        // With ECIES format, nonce starts at byte 33
        let nonce = Nonce::from_slice(&encrypted[33..45]);
        let result = cipher.decrypt(nonce, &encrypted[45..]);

        // Must fail — public key is not the encryption key anymore
        assert!(result.is_err(), "Public key must NOT be able to decrypt ECIES data");
    }

    #[test]
    fn test_ecies_different_ciphertext_each_time() {
        let keystore = Keystore::generate();
        let seed = "test-seed";
        let plaintext = b"same plaintext";

        let enc1 = keystore.encrypt(None, seed, plaintext).unwrap();
        let enc2 = keystore.encrypt(None, seed, plaintext).unwrap();

        // Ephemeral keypair is random, so ciphertexts must differ
        assert_ne!(enc1, enc2);

        // But both decrypt to same plaintext
        assert_eq!(keystore.decrypt(None, seed, &enc1).unwrap(), plaintext);
        assert_eq!(keystore.decrypt(None, seed, &enc2).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_seed_cannot_decrypt() {
        let keystore = Keystore::generate();
        let encrypted = keystore.encrypt(None, "seed-a", b"secret").unwrap();
        let result = keystore.decrypt(None, "seed-b", &encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn test_sign_verify() {
        let keystore = Keystore::generate();
        let seed = "github.com/alice/project:alice.near";
        let message = b"hello world";

        let signature = keystore.sign(None, seed, message).unwrap();
        keystore.verify(None, seed, message, &signature).unwrap();
    }

    #[test]
    fn test_vrf_deterministic() {
        let keystore = Keystore::generate();
        let alpha = b"vrf:42:my-seed";

        let (output1, sig1) = keystore.vrf_generate(alpha).unwrap();
        let (output2, sig2) = keystore.vrf_generate(alpha).unwrap();

        assert_eq!(output1, output2, "Same alpha must produce same output");
        assert_eq!(sig1, sig2, "Same alpha must produce same signature");
    }

    #[test]
    fn test_vrf_different_alpha_different_output() {
        let keystore = Keystore::generate();

        let (out_a, _) = keystore.vrf_generate(b"vrf:1:seed-a").unwrap();
        let (out_b, _) = keystore.vrf_generate(b"vrf:1:seed-b").unwrap();

        assert_ne!(out_a, out_b, "Different alphas must produce different outputs");
    }

    #[test]
    fn test_vrf_self_verify() {
        let keystore = Keystore::generate();
        let alpha = b"vrf:100:test";

        let (_, sig_hex) = keystore.vrf_generate(alpha).unwrap();

        // Reconstruct signature and verify with public key
        let sig_bytes: [u8; 64] = hex::decode(&sig_hex).unwrap().try_into().unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        let vrf_pubkey = keystore.get_public_key_for_seed(None, "vrf-key").unwrap();

        vrf_pubkey.verify(alpha, &signature).expect("VRF signature must verify");
    }

    #[test]
    fn test_vrf_pubkey_stable() {
        let keystore = Keystore::generate();

        let pk1 = keystore.vrf_public_key_hex().unwrap();
        let pk2 = keystore.vrf_public_key_hex().unwrap();

        assert_eq!(pk1, pk2);
        assert_eq!(pk1.len(), 64); // 32-byte Ed25519 pubkey = 64 hex chars
    }

    #[test]
    fn test_vrf_same_master_secret_same_output() {
        let ks1 = Keystore::generate();
        let master_hex = ks1.default_master_hex();
        let ks2 = Keystore::from_master_secret_hex(&master_hex).unwrap();

        let alpha = b"vrf:1:test";
        let (out1, _) = ks1.vrf_generate(alpha).unwrap();
        let (out2, _) = ks2.vrf_generate(alpha).unwrap();

        assert_eq!(out1, out2, "Same master secret must produce same VRF output");
        assert_eq!(ks1.vrf_public_key_hex().unwrap(), ks2.vrf_public_key_hex().unwrap());
    }

    #[test]
    fn test_master_secret_persistence() {
        let keystore1 = Keystore::generate();
        let seed = "github.com/test/repo:test.near";
        let pubkey1 = keystore1.public_key_hex(None, seed).unwrap();

        // Serialize master secret (in production, this would be sealed storage)
        let master_secret_hex = hex::encode(&keystore1.default_master);

        // Load from same master secret
        let keystore2 = Keystore::from_master_secret_hex(&master_secret_hex).unwrap();
        let pubkey2 = keystore2.public_key_hex(None, seed).unwrap();

        assert_eq!(pubkey1, pubkey2, "Same master secret should produce same derived keys");
    }

    // ======================= Wallet subkey derivation tests ====================
    // Convention: "wallet:{id}:{chain}:{sub_path}" for sub-keys under a wallet

    #[test]
    fn test_wallet_subkey_deterministic() {
        let ks = Keystore::generate();
        let seed = "wallet:abc:near:check:0";
        let (sk1, vk1) = ks.derive_keypair(None, seed).unwrap();
        let (sk2, vk2) = ks.derive_keypair(None, seed).unwrap();
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert_eq!(vk1.as_bytes(), vk2.as_bytes());
    }

    #[test]
    fn test_wallet_subkey_differs_by_sub_path() {
        let ks = Keystore::generate();
        let (_, vk0) = ks.derive_keypair(None, "wallet:abc:near:check:0").unwrap();
        let (_, vk1) = ks.derive_keypair(None, "wallet:abc:near:check:1").unwrap();
        assert_ne!(vk0.as_bytes(), vk1.as_bytes());
    }

    #[test]
    fn test_wallet_subkey_differs_from_main_key() {
        let ks = Keystore::generate();
        let (_, wallet_vk) = ks.derive_keypair(None, "wallet:test-id:near").unwrap();
        let (_, sub_vk) = ks.derive_keypair(None, "wallet:test-id:near:check:0").unwrap();
        assert_ne!(wallet_vk.as_bytes(), sub_vk.as_bytes());
    }

    #[test]
    fn test_wallet_subkey_implicit_account_is_64_hex() {
        let ks = Keystore::generate();
        let (_, vk) = ks.derive_keypair(None, "wallet:abc:near:check:42").unwrap();
        assert_eq!(hex::encode(vk.as_bytes()).len(), 64);
    }

    // ======================= Policy signing key tests ==========================
    // After ECIES migration, public_key_hex() returns X25519 (encryption) key,
    // while get_public_key_for_seed() returns Ed25519 (signing) key.
    // The contract's store_wallet_policy needs Ed25519 for ed25519_verify.

    #[test]
    fn test_public_key_hex_and_ed25519_are_different_keys() {
        let ks = Keystore::generate();
        let seed = "wallet:test-id:near";

        // public_key_hex returns X25519 (encryption key)
        let x25519_hex = ks.public_key_hex(None, seed).unwrap();

        // get_public_key_for_seed returns Ed25519 (signing key)
        let ed25519_vk = ks.get_public_key_for_seed(None, seed).unwrap();
        let ed25519_hex = hex::encode(ed25519_vk.as_bytes());

        // Both are 32 bytes (64 hex chars) but different keys
        assert_eq!(x25519_hex.len(), 64);
        assert_eq!(ed25519_hex.len(), 64);
        assert_ne!(
            x25519_hex, ed25519_hex,
            "X25519 and Ed25519 keys must differ for the same seed"
        );
    }

    #[test]
    fn test_sign_verify_with_ed25519_pubkey() {
        let ks = Keystore::generate();
        let seed = "wallet:test-id:near";
        let message = b"test message for policy";

        let signature = ks.sign(None, seed, message).unwrap();
        let ed25519_vk = ks.get_public_key_for_seed(None, seed).unwrap();

        // Verification with correct Ed25519 key must succeed
        ed25519_vk
            .verify(message, &signature)
            .expect("Ed25519 verify must succeed with matching key");
    }

    #[test]
    fn test_ed25519_verify_fails_with_x25519_pubkey() {
        let ks = Keystore::generate();
        let seed = "wallet:test-id:near";
        let message = b"test message for policy";

        // Sign with Ed25519 key
        let signature = ks.sign(None, seed, message).unwrap();

        // Get X25519 key (what public_key_hex returns after ECIES migration)
        let x25519_hex = ks.public_key_hex(None, seed).unwrap();
        let x25519_bytes: [u8; 32] = hex::decode(&x25519_hex)
            .unwrap()
            .try_into()
            .unwrap();

        // Try to use X25519 bytes as Ed25519 verifying key — this is what the
        // contract does when sign-policy returns the wrong public_key_hex.
        // It must fail: either VerifyingKey::from_bytes rejects the point,
        // or verify() returns an error.
        let result = VerifyingKey::from_bytes(&x25519_bytes)
            .and_then(|vk| vk.verify(message, &signature));
        assert!(
            result.is_err(),
            "Verification with X25519 key as Ed25519 must fail"
        );
    }

    #[test]
    fn test_sign_policy_flow_end_to_end() {
        let ks = Keystore::generate();
        let wallet_seed = "wallet:test-id:near";
        let policy_seed = "wallet-policy:test-id";

        // Step 1: Encrypt policy (uses separate policy seed)
        let policy_json = br#"{"version":1,"frozen":false,"rules":{}}"#;
        let encrypted = ks.encrypt(None, policy_seed, policy_json).unwrap();
        let encrypted_base64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        // Step 2: SHA256 of encrypted_data string (what contract does)
        let mut hasher = Sha256::new();
        hasher.update(encrypted_base64.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();

        // Step 3: Sign hash with wallet key
        let signature = ks.sign(None, wallet_seed, &hash).unwrap();

        // Step 4: Verify with Ed25519 key — must succeed
        let ed25519_vk = ks.get_public_key_for_seed(None, wallet_seed).unwrap();
        ed25519_vk
            .verify(&hash, &signature)
            .expect("Verify with Ed25519 key must succeed");

        // Step 5: Verify with X25519 key — must fail (reproduces the bug)
        let x25519_hex = ks.public_key_hex(None, wallet_seed).unwrap();
        let x25519_bytes: [u8; 32] = hex::decode(&x25519_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let result = VerifyingKey::from_bytes(&x25519_bytes)
            .and_then(|vk| vk.verify(&hash, &signature));
        assert!(
            result.is_err(),
            "Verify with X25519 key must fail — this is the bug"
        );
    }

    // ============== derive_secret_string (MPC CKD path) ==============
    // Used as the MPC CKD `derivation_path` argument when adding a
    // per-customer master. Must be (a) deterministic for replay across
    // worker restarts, (b) dependent on the master so a customer cannot
    // forge it without OutLayer master access, (c) domain-separated from
    // keypair derivation, (d) hex-encoded and exactly 64 chars.

    #[test]
    fn test_derive_secret_string_deterministic() {
        let ks = Keystore::generate();
        let s1 = ks.derive_secret_string(None, "vault-master:vault.alice.testnet").unwrap();
        let s2 = ks.derive_secret_string(None, "vault-master:vault.alice.testnet").unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 64, "HMAC-SHA256 hex must be 64 chars");
        assert!(s1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_derive_secret_string_seed_separates() {
        let ks = Keystore::generate();
        let a = ks.derive_secret_string(None, "vault-master:vault.alice.testnet").unwrap();
        let b = ks.derive_secret_string(None, "vault-master:vault.bob.testnet").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_derive_secret_string_master_dependent() {
        // Different masters → different paths for the same seed.
        // Critical for the unforgeability story — a customer cannot
        // compute the path without the OutLayer master.
        let ks1 = Keystore::generate();
        let ks2 = Keystore::generate();
        let seed = "vault-master:vault.alice.testnet";
        let s1 = ks1.derive_secret_string(None, seed).unwrap();
        let s2 = ks2.derive_secret_string(None, seed).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_derive_secret_string_domain_separated_from_keypair() {
        // The output must NOT be derivable as a side-effect of any
        // existing derive_* method, otherwise a leak of the keypair
        // bytes would reveal the path. Different domain prefix means
        // different HMAC, which means different output even for the
        // same seed string.
        let ks = Keystore::generate();
        let seed = "vault.alice.testnet";
        let path = ks.derive_secret_string(None, seed).unwrap();
        let (_, vk) = ks.derive_keypair(None, seed).unwrap();
        assert_ne!(path, hex::encode(vk.as_bytes()));
    }

    // ============== Multi-customer isolation ==============
    // These tests pin the customer-isolation invariant at the CRYPTO
    // layer — anything above (api handlers, MPC CKD) is built on top
    // of these guarantees, so if the crypto layer leaks across
    // customers, every higher layer leaks too.
    //
    // Each test loads two distinct per-customer masters with KNOWN
    // bytes (so test failures aren't blamed on RNG); HMAC is
    // deterministic, so the test is fully reproducible.
    use std::str::FromStr;

    fn ks_with_two_customers() -> (Keystore, AccountId, AccountId) {
        let ks = Keystore::generate();
        let alice = AccountId::from_str("vault.alice.testnet").unwrap();
        let bob = AccountId::from_str("vault.bob.testnet").unwrap();
        // Use distinct, well-known masters so any leak surfaces.
        ks.add_customer(alice.clone(), [0xAA; 32]);
        ks.add_customer(bob.clone(), [0xBB; 32]);
        (ks, alice, bob)
    }

    #[test]
    fn isolation_ed25519_pubkeys_disjoint_per_customer() {
        let (ks, alice, bob) = ks_with_two_customers();
        let seed = "wallet:abc:near";
        let (_, vk_a) = ks.derive_keypair(Some(&alice), seed).unwrap();
        let (_, vk_b) = ks.derive_keypair(Some(&bob), seed).unwrap();
        let (_, vk_default) = ks.derive_keypair(None, seed).unwrap();
        assert_ne!(vk_a.as_bytes(), vk_b.as_bytes());
        assert_ne!(vk_a.as_bytes(), vk_default.as_bytes());
        assert_ne!(vk_b.as_bytes(), vk_default.as_bytes());
    }

    #[test]
    fn isolation_x25519_pubkeys_disjoint_per_customer() {
        let (ks, alice, bob) = ks_with_two_customers();
        let seed = "wallet-policy:abc";
        let pub_a = ks.public_key_hex(Some(&alice), seed).unwrap();
        let pub_b = ks.public_key_hex(Some(&bob), seed).unwrap();
        let pub_default = ks.public_key_hex(None, seed).unwrap();
        assert_ne!(pub_a, pub_b);
        assert_ne!(pub_a, pub_default);
        assert_ne!(pub_b, pub_default);
    }

    #[test]
    fn isolation_eth_addresses_disjoint_per_customer() {
        let (ks, alice, bob) = ks_with_two_customers();
        let seed = "wallet:abc:ethereum";
        let (addr_a, _) = ks.derive_eth_address(Some(&alice), seed).unwrap();
        let (addr_b, _) = ks.derive_eth_address(Some(&bob), seed).unwrap();
        let (addr_default, _) = ks.derive_eth_address(None, seed).unwrap();
        assert_ne!(addr_a, addr_b);
        assert_ne!(addr_a, addr_default);
        assert_ne!(addr_b, addr_default);
    }

    #[test]
    fn isolation_encrypt_a_cannot_decrypt_b() {
        // The custody-grade guarantee: a ciphertext encrypted under
        // customer A's master is unreadable under customer B's master.
        // Even if a malicious caller submits B's vault_id alongside
        // ciphertext encrypted to A, the decrypt fails — no plaintext
        // recovered.
        let (ks, alice, bob) = ks_with_two_customers();
        let seed = "user:secret-payload";
        let plaintext = b"alice's hardcoded api key";
        let ciphertext = ks.encrypt(Some(&alice), seed, plaintext).unwrap();

        // B can't decrypt A's ciphertext.
        let result_b = ks.decrypt(Some(&bob), seed, &ciphertext);
        assert!(result_b.is_err(), "customer B must NOT be able to decrypt customer A's secret");

        // Default master can't decrypt A's ciphertext.
        let result_default = ks.decrypt(None, seed, &ciphertext);
        assert!(result_default.is_err(), "default master must NOT be able to decrypt customer A's secret");

        // Sanity: A still can.
        let recovered = ks.decrypt(Some(&alice), seed, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn isolation_signature_verifies_only_under_correct_customer() {
        let (ks, alice, bob) = ks_with_two_customers();
        let seed = "wallet:abc:near";
        let msg = b"transfer 1 NEAR";
        let sig_a = ks.sign(Some(&alice), seed, msg).unwrap();

        // A's pubkey verifies A's signature.
        ks.verify(Some(&alice), seed, msg, &sig_a).unwrap();

        // B's pubkey does NOT verify A's signature.
        let result_b = ks.verify(Some(&bob), seed, msg, &sig_a);
        assert!(result_b.is_err(), "B's key must NOT verify A's signature");
    }

    #[test]
    fn isolation_secp256k1_keys_disjoint_per_customer() {
        let (ks, alice, bob) = ks_with_two_customers();
        let seed = "wallet:abc:base";
        let (sk_a, _) = ks.derive_secp256k1_keypair(Some(&alice), seed).unwrap();
        let (sk_b, _) = ks.derive_secp256k1_keypair(Some(&bob), seed).unwrap();
        // Different scalars (the secret key is the salient bit).
        assert_ne!(sk_a.to_bytes(), sk_b.to_bytes());
    }

    #[test]
    fn isolation_secret_path_disjoint_per_customer() {
        let (ks, alice, bob) = ks_with_two_customers();
        // Even given the same input string, customer's master gates
        // the path. If a customer somehow guesses another customer's
        // seed, they still can't compute the path.
        let s = "vault-master:vault.eve.testnet";
        let path_a = ks.derive_secret_string(Some(&alice), s).unwrap();
        let path_b = ks.derive_secret_string(Some(&bob), s).unwrap();
        let path_default = ks.derive_secret_string(None, s).unwrap();
        assert_ne!(path_a, path_b);
        assert_ne!(path_a, path_default);
    }

    #[test]
    fn isolation_evict_then_re_derive_fails_without_master() {
        // Plan: "/admin/evict-customer: banned vault triggers eviction
        // → next call fails verify check". At the crypto layer the
        // evict-then-derive shape is: after evict, derive_* fails
        // with the master-not-loaded error. The lazy-load gate
        // (mpc_ckd) is what tries to refresh on top — but if the
        // gate is bypassed (e.g. cached customer assumption broken),
        // the crypto layer must still refuse.
        let ks = Keystore::generate();
        let alice = AccountId::from_str("vault.alice.testnet").unwrap();
        ks.add_customer(alice.clone(), [0xAA; 32]);
        assert!(ks.has_customer(&alice));

        // Eviction.
        ks.evict_customer(&alice);
        assert!(!ks.has_customer(&alice));

        // Now any derive_* for alice must fail. We use derive_keypair
        // as the canonical path; all other derive_* paths funnel
        // through `master_for(customer)` which produces the same
        // error.
        let result = ks.derive_keypair(Some(&alice), "wallet:abc:near");
        assert!(result.is_err());
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("per-customer master not loaded"),
            "evict must surface a 'master not loaded' error, got: {msg}"
        );
    }

    // ============== Restart determinism ==============
    // The "auto re-derive" path goes through MPC CKD at runtime, but
    // the CRYPTO-LAYER guarantee — that loading the same default
    // master in a fresh Keystore reproduces every derivation —
    // doesn't need MPC. These tests verify the keystore restart
    // produces bit-identical output.

    #[test]
    fn restart_default_master_path_reproduces_all_derivations() {
        // First instance: derive a battery of representative outputs
        // under the default master.
        let ks1 = Keystore::generate();
        let master_hex = ks1.default_master_hex();
        let seed = "wallet:test-restart:near";

        let (_, vk1) = ks1.derive_keypair(None, seed).unwrap();
        let pub_x25519_1 = ks1.public_key_hex(None, seed).unwrap();
        let (eth_addr_1, _) = ks1.derive_eth_address(None, seed).unwrap();
        let path_1 = ks1.derive_secret_string(None, "vault-master:vault.alice.testnet").unwrap();

        // Restart: load identical default master, re-derive everything.
        let ks2 = Keystore::from_master_secret_hex(&master_hex).unwrap();
        let (_, vk2) = ks2.derive_keypair(None, seed).unwrap();
        let pub_x25519_2 = ks2.public_key_hex(None, seed).unwrap();
        let (eth_addr_2, _) = ks2.derive_eth_address(None, seed).unwrap();
        let path_2 = ks2.derive_secret_string(None, "vault-master:vault.alice.testnet").unwrap();

        assert_eq!(vk1.as_bytes(), vk2.as_bytes());
        assert_eq!(pub_x25519_1, pub_x25519_2);
        assert_eq!(eth_addr_1, eth_addr_2);
        assert_eq!(path_1, path_2);
    }

    #[test]
    fn restart_per_customer_master_reproduces_under_known_master() {
        // The lazy-load path provides the per-customer master via
        // MPC CKD; once loaded, it stays in memory. After restart
        // the master must be re-loadable (Layer 2 secret_path is
        // deterministic, so MPC CKD returns the same bytes). At the
        // crypto layer we can verify: given the SAME per-customer
        // master bytes loaded into a fresh Keystore, every derived
        // key matches.
        let ks1 = Keystore::generate();
        let alice = AccountId::from_str("vault.alice.testnet").unwrap();
        let alice_master = [0xCC; 32];
        ks1.add_customer(alice.clone(), alice_master);

        let seed = "wallet:abc:near";
        let (sk1, vk1) = ks1.derive_keypair(Some(&alice), seed).unwrap();
        let path_1 = ks1.derive_secret_string(Some(&alice), "anything").unwrap();

        // Simulate restart: keep default_master; re-load alice's
        // master (in production this comes from MPC CKD).
        let master_hex = ks1.default_master_hex();
        let ks2 = Keystore::from_master_secret_hex(&master_hex).unwrap();
        ks2.add_customer(alice.clone(), alice_master);

        let (sk2, vk2) = ks2.derive_keypair(Some(&alice), seed).unwrap();
        let path_2 = ks2.derive_secret_string(Some(&alice), "anything").unwrap();

        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert_eq!(vk1.as_bytes(), vk2.as_bytes());
        assert_eq!(path_1, path_2);
    }

    // ============ Pinned-pubkey regression fixtures ============
    //
    // Trip-wires for accidental changes to the HMAC input shape used
    // by `derive_keypair` (Ed25519) and `derive_secp256k1_keypair`.
    // Both methods feed the seed directly into HMAC without a
    // curve-tag prefix; that's the documented contract on the
    // method-level doc comments. If anyone "fixes" the missing
    // prefix here, every customer's NEAR / EVM address rotates —
    // these tests fail before the change can ship.
    //
    // Master is a fixed 32-byte string so the fixtures are
    // reproducible across machines.
    fn fixed_master() -> [u8; 32] {
        let mut m = [0u8; 32];
        for (i, b) in b"M-1 regression fixture .........".iter().enumerate() {
            m[i] = *b;
        }
        m
    }

    #[test]
    fn ed25519_pinned_fixture_for_known_master_seed() {
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let (_, vk) = ks.derive_keypair(None, "wallet:fixed:near").unwrap();
        // If this fails: someone changed the HMAC input for
        // `derive_keypair`. Don't update the fixture — read the
        // method's `Domain separation` doc-section first. Changing
        // the input rotates every customer's NEAR address.
        assert_eq!(
            hex::encode(vk.as_bytes()),
            "124d4dc445d7e1699bc95e94461540a21e605acf993b04e86da59cb046059f13",
        );
    }

    #[test]
    fn secp256k1_pinned_fixture_for_known_master_seed() {
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let (_, pk) = ks.derive_secp256k1_keypair(None, "wallet:fixed:eth").unwrap();
        // If this fails: someone changed the HMAC input for
        // `derive_secp256k1_keypair`. Same warning as the Ed25519
        // fixture above — changing the input rotates every
        // customer's EVM address.
        assert_eq!(
            hex::encode(pk.to_encoded_point(true).as_bytes()),
            "03ffd4869b507336699943453906991fe29fac4764f5a77410cbffea9496a6b420",
        );
    }

    #[test]
    fn secp256k1_recoverable_sig_recovers_to_derived_address() {
        // The EVM signing primitive must produce a recoverable
        // signature whose `ecrecover` returns the address we derive for
        // the same (customer, seed). This is the acceptance criterion
        // the integration partner validates (ecrecover == address).
        // Fully self-contained — no external vector needed.
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let seed = "wallet:fixed:evm";
        let (addr, _) = ks.derive_eth_address(None, seed).unwrap();

        // Arbitrary 32-byte keccak prehash (stands in for an EIP-712 /
        // EIP-191 digest — this primitive does NOT re-hash).
        let digest: [u8; 32] = {
            use sha3::{Digest as _, Keccak256};
            let mut d = [0u8; 32];
            d.copy_from_slice(&Keccak256::digest(b"outlayer evm prehash"));
            d
        };

        let sig = ks.sign_secp256k1_prehash(None, seed, &digest).unwrap();
        assert_eq!(sig.len(), 65);
        assert!(sig[64] == 27 || sig[64] == 28, "v must be 27/28, got {}", sig[64]);

        // Reconstruct and recover.
        let recid = k256::ecdsa::RecoveryId::from_byte(sig[64] - 27).unwrap();
        let signature = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &signature, recid)
            .expect("recover must succeed");

        let uncompressed = vk.to_encoded_point(false);
        let recovered_addr = {
            use sha3::{Digest as _, Keccak256};
            let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
            format!("0x{}", hex::encode(&hash[12..]))
        };
        assert_eq!(recovered_addr, addr, "ecrecover must return the derived EVM address");

        // Determinism (RFC-6979): same inputs → same signature.
        let sig2 = ks.sign_secp256k1_prehash(None, seed, &digest).unwrap();
        assert_eq!(sig, sig2, "recoverable signing must be deterministic");
    }

    /// `ecrecover`: recover the 0x address that produced a 65-byte r‖s‖v
    /// signature over `digest`. Mirrors what an EVM verifier (or
    /// `ecrecover` precompile) does on-chain.
    fn recover_evm_addr(digest: &[u8; 32], sig: &[u8; 65]) -> String {
        assert!(sig[64] == 27 || sig[64] == 28, "v must be 27/28, got {}", sig[64]);
        let recid = k256::ecdsa::RecoveryId::from_byte(sig[64] - 27).unwrap();
        let signature = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
        let vk = k256::ecdsa::VerifyingKey::recover_from_prehash(digest, &signature, recid)
            .expect("recover must succeed");
        use sha3::{Digest as _, Keccak256};
        let uncompressed = vk.to_encoded_point(false);
        let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
        format!("0x{}", hex::encode(&hash[12..]))
    }

    // End-to-end (at the crypto layer) for each of the three EVM endpoints:
    // build the digest exactly as the handler does, sign, then `ecrecover` and
    // assert the recovered address == the wallet's derived EVM address.

    #[test]
    fn evm_eip191_message_sign_and_verify() {
        // POST /wallet/evm/sign-message path: EIP-191 personal_sign digest.
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let seed = "wallet:fixed:evm";
        let (addr, _) = ks.derive_eth_address(None, seed).unwrap();
        let digest = crate::eip712::eip191_digest_for("Sign in to Polymarket", false).unwrap();
        let sig = ks.sign_secp256k1_prehash(None, seed, &digest).unwrap();
        assert_eq!(
            recover_evm_addr(&digest, &sig),
            addr,
            "EIP-191 personal_sign must ecrecover to the wallet's EVM address"
        );
    }

    #[test]
    fn evm_eip712_typed_data_sign_and_verify() {
        // POST /wallet/evm/sign-typed-data path: EIP-712 v4 digest (the
        // canonical spec "Mail" example, full eth_signTypedData_v4 shape).
        use serde_json::json;
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let seed = "wallet:fixed:evm";
        let (addr, _) = ks.derive_eth_address(None, seed).unwrap();
        let typed = json!({
            "domain": { "name": "Ether Mail", "version": "1", "chainId": 1,
                        "verifyingContract": "0xcccccccccccccccccccccccccccccccccccccccc" },
            "types": {
                "EIP712Domain": [
                    { "name": "name", "type": "string" }, { "name": "version", "type": "string" },
                    { "name": "chainId", "type": "uint256" }, { "name": "verifyingContract", "type": "address" }
                ],
                "Person": [ { "name": "name", "type": "string" }, { "name": "wallet", "type": "address" } ],
                "Mail": [ { "name": "from", "type": "Person" }, { "name": "to", "type": "Person" },
                          { "name": "contents", "type": "string" } ]
            },
            "primaryType": "Mail",
            "message": {
                "from": { "name": "Cow", "wallet": "0xcd2a3d9f938e13cd947ec05abc7fe734df8dd826" },
                "to": { "name": "Bob", "wallet": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
                "contents": "Hello, Bob!"
            }
        });
        let digest = crate::eip712::eip712_digest(&typed).unwrap();
        let sig = ks.sign_secp256k1_prehash(None, seed, &digest).unwrap();
        assert_eq!(
            recover_evm_addr(&digest, &sig),
            addr,
            "EIP-712 typed-data must ecrecover to the wallet's EVM address"
        );
    }

    #[test]
    fn evm_raw_transaction_sign_and_verify() {
        // POST /wallet/evm/sign-transaction path: keccak256 of the supplied
        // serialized unsigned tx (here a real EIP-1559 `0x02‖rlp(...)` blob).
        use sha3::{Digest as _, Keccak256};
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let seed = "wallet:fixed:evm";
        let (addr, _) = ks.derive_eth_address(None, seed).unwrap();
        let unsigned_tx = hex::decode(
            "02f86c0180843b9aca00851bf08eb000825208\
             94abababababababababababababababababababab880de0b6b3a764000080c0",
        )
        .unwrap();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Keccak256::digest(&unsigned_tx));
        let sig = ks.sign_secp256k1_prehash(None, seed, &digest).unwrap();
        assert_eq!(
            recover_evm_addr(&digest, &sig),
            addr,
            "raw-tx signing hash must ecrecover to the wallet's EVM address"
        );
    }

    #[test]
    fn hmac_inputs_diverge_across_curves_in_practice() {
        // Co-pinned with the production caller convention: NEAR uses
        // `wallet:{id}:near` and EVM uses `wallet:{id}:eth`. The two
        // seeds MUST produce distinct HMAC outputs (and therefore
        // distinct private scalars on each curve). This test would
        // fail if a future caller-side bug normalised both chains
        // onto the same seed string.
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let (sk_near, _) = ks.derive_keypair(None, "wallet:fixed:near").unwrap();
        let (sk_eth, _) = ks.derive_secp256k1_keypair(None, "wallet:fixed:eth").unwrap();
        assert_ne!(
            sk_near.to_bytes().as_slice(),
            sk_eth.to_bytes().as_slice(),
            "NEAR and EVM seeds must not share an HMAC input"
        );
    }

    // ============== Signing keys ==============

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    const P1: &str = "p0000000000000001";
    const P2: &str = "p0000000000000002";
    /// Project `alice.near/app`, uuid P1 on the contract.
    const APP: Option<(&str, &str)> = Some(("alice.near/app", P1));

    /// The derivation string for one key, as the run its binding allows asks
    /// for it: a `project` key on a run through `project` (its id and its
    /// on-chain uuid), a `wasm` key on a direct run of build `wasm` (which
    /// names no project). `signer` is the job's `user_account_id`,
    /// `predecessor` its `predecessor_id`; `caller` picks which one the key
    /// belongs to.
    fn signing_key_input_as(
        project: Option<(&str, &str)>,
        caller: crate::signing_keys::CallerKind,
        signer: &str,
        predecessor: Option<&str>,
        wasm: &str,
        bind: crate::signing_keys::KeyBinding,
        path: &str,
    ) -> crate::signing_keys::DerivationInput {
        use crate::signing_keys::{KeyBinding, ProjectUuid};
        let request = crate::signing_keys::SigningKeyRequest {
            path: path.to_string(),
            key_type: crate::signing_keys::SigningKeyType::Ed25519,
            bind,
            caller,
            vault: None,
        };
        let (project_id, uuid) = match bind {
            KeyBinding::Project => {
                let (id, uuid) = project.expect("a project key needs its project");
                (Some(id), Some(ProjectUuid::parse(uuid).unwrap()))
            }
            KeyBinding::Wasm => {
                assert!(project.is_none(), "a wasm key is issued only to a direct run, which has no project");
                (None, None)
            }
        };
        crate::signing_keys::validate_request(project_id, signer, predecessor, Some(wasm), &[request])
            .unwrap()
            .bind(uuid)
            .unwrap()
            .keys
            .remove(0)
            .input
    }

    /// A `signer` key of `account`, the run's signer.
    fn signing_key_input(
        project: Option<(&str, &str)>,
        account: &str,
        wasm: &str,
        bind: crate::signing_keys::KeyBinding,
        path: &str,
    ) -> crate::signing_keys::DerivationInput {
        signing_key_input_as(project, crate::signing_keys::CallerKind::Signer, account, None, wasm, bind, path)
    }

    fn signing_seed_hex(ks: &Keystore, input: &crate::signing_keys::DerivationInput) -> String {
        hex::encode(ks.derive_signing_key_seed(None, input).unwrap().as_ref())
    }

    /// Pinned vectors: the seeds were computed with an independent HMAC-SHA256
    /// and the public keys with an independent ed25519 implementation, over the
    /// exact strings shown. A failure means the derivation changed — which
    /// changes every signing key and every signature made with one. Do not
    /// update the vectors; find what changed.
    #[test]
    fn signing_key_pinned_vectors() {
        use crate::signing_keys::CallerKind::{Predecessor, Signer};
        use crate::signing_keys::KeyBinding::{Project, Wasm};
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let cases = [
            (
                signing_key_input(APP, "bob.near", H1, Project, "records"),
                format!("signing-key:v1:ed25519:project:{P1}:signer:bob.near:records"),
                "f6f531d0b454d922a8e1f530f41f3a1cd008c56c496e36c958f2d4013358ac3d",
                "c602d489e1818fba7a7964fd85e288404201a66efe76fadb91aa3a8941b573c2",
            ),
            (
                signing_key_input(None, "bob.near", H1, Wasm, "records"),
                format!("signing-key:v1:ed25519:wasm:{H1}:signer:bob.near:records"),
                "c5ab41608101f4088be8bf73c83d37004744976cf2a15cc49b2e882dbc44ee16",
                "a3568e4eb52ba412642546466db09264652d77e1f6c4ecee63ae2dd129b1fe65",
            ),
            (
                signing_key_input(None, "bob.near", H2, Wasm, "records"),
                format!("signing-key:v1:ed25519:wasm:{H2}:signer:bob.near:records"),
                "97ed687fa7b55c4558ea87122334e0c856104e755a1c62cc08fa61989f6680ad",
                "57a2ffb80c011b813bb8d379d83e185fd55d55e38dc7d7fac635dc8eb8c07d85",
            ),
            (
                signing_key_input(Some(("carol.near/app", P2)), "bob.near", H1, Project, "records"),
                format!("signing-key:v1:ed25519:project:{P2}:signer:bob.near:records"),
                "a893de461a75e2e846a7d7fd3b3839e4aa747c529101d1806ddadc2a5578ce8f",
                "96a8495ebd25243b247e7881fd5b1008583b3cfc71525177263b638eeb4604be",
            ),
            (
                signing_key_input(APP, "dave.near", H1, Project, "records"),
                format!("signing-key:v1:ed25519:project:{P1}:signer:dave.near:records"),
                "20c6e49370bef527cc995a8ecd502c4b1c03f0f6890fe7745db88073a26faf0a",
                "50aa94c01dc34a6dcad551a545c02e466d50821089ac0c726b853085fda03306",
            ),
            // A predecessor key: bob signed, the DAO called; the key is the DAO's.
            (
                signing_key_input_as(APP, Predecessor, "bob.near", Some("dao.near"), H1, Project, "records"),
                format!("signing-key:v1:ed25519:project:{P1}:predecessor:dao.near:records"),
                "564cad06f84721e12d167b6860c46170ec342f4c309a700bbfe8f7b25f7da397",
                "ef698d816a8736b37d43f1c1eac73d1ee88776bb2f7ddb9496f00c498ced949b",
            ),
            // The same account as signer and as predecessor: two keys.
            (
                signing_key_input_as(APP, Predecessor, "bob.near", Some("bob.near"), H1, Project, "records"),
                format!("signing-key:v1:ed25519:project:{P1}:predecessor:bob.near:records"),
                "978a4ab49ca4f60607132ef5189ffcdf064f23c7e4517e166ff7dafeb927d533",
                "aab7a891a1635655f4d288d665c8c31b72ed5b7d14a94609cf86596d183c7fef",
            ),
            (
                signing_key_input_as(APP, Signer, "bob.near", Some("dao.near"), H1, Project, "records"),
                format!("signing-key:v1:ed25519:project:{P1}:signer:bob.near:records"),
                "f6f531d0b454d922a8e1f530f41f3a1cd008c56c496e36c958f2d4013358ac3d",
                "c602d489e1818fba7a7964fd85e288404201a66efe76fadb91aa3a8941b573c2",
            ),
        ];
        for (input, string, seed, public_key) in cases {
            assert_eq!(input.as_str(), string);
            let derived = ks.derive_signing_key_seed(None, &input).unwrap();
            assert_eq!(hex::encode(derived.as_ref()), seed, "{string}");
            let vk = SigningKey::from_bytes(&derived).verifying_key();
            assert_eq!(hex::encode(vk.as_bytes()), public_key, "{string}");
        }
    }

    #[test]
    fn two_projects_and_two_callers_get_different_project_keys() {
        use crate::signing_keys::KeyBinding::Project;
        let ks = Keystore::generate();
        let k = |p: (&str, &str), a: &str, n: &str| signing_seed_hex(&ks, &signing_key_input(Some(p), a, H1, Project, n));
        let all = [
            k(("alice.near/app", P1), "bob.near", "k"),
            // The same name, created again: another uuid, another key.
            k(("alice.near/app", P2), "bob.near", "k"),
            k(("carol.near/app", "p0000000000000003"), "bob.near", "k"),
            k(("alice.near/app", P1), "dave.near", "k"),
            k(("alice.near/app", P1), "bob.near", "k2"),
        ];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "two different tuples derived one key");
            }
        }
    }

    #[test]
    fn two_callers_and_two_builds_get_different_wasm_keys() {
        use crate::signing_keys::KeyBinding::Wasm;
        let ks = Keystore::generate();
        let k = |a: &str, h: &str, n: &str| signing_seed_hex(&ks, &signing_key_input(None, a, h, Wasm, n));
        let all = [k("bob.near", H1, "k"), k("dave.near", H1, "k"), k("bob.near", H2, "k"), k("bob.near", H1, "k2")];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "two different tuples derived one key");
            }
        }
    }

    #[test]
    fn the_binding_decides_what_the_key_follows() {
        use crate::signing_keys::KeyBinding::{Project, Wasm};
        let ks = Keystore::generate();
        let seed = |p: Option<(&str, &str)>, h: &str, b| signing_seed_hex(&ks, &signing_key_input(p, "bob.near", h, b, "k"));
        let app = APP;
        // One (type, account, path), two bindings: two keys.
        assert_ne!(seed(app, H1, Project), seed(None, H1, Wasm));
        // A wasm key is the build's: the same build is the same key, another
        // build another key.
        assert_eq!(seed(None, H1, Wasm), seed(None, H1, Wasm));
        assert_ne!(seed(None, H1, Wasm), seed(None, H2, Wasm));
        // A project key is the project's: a new build keeps it.
        assert_eq!(seed(app, H1, Project), seed(app, H2, Project));
    }

    #[test]
    fn a_signing_key_uses_the_vaults_master_and_never_falls_back() {
        use crate::signing_keys::KeyBinding::Project;
        let ks = Keystore::generate();
        let vault: AccountId = "vault.alice.near".parse().unwrap();
        let input = signing_key_input(APP, "bob.near", H1, Project, "k");

        // Not loaded: refused, not the default master's key.
        assert!(ks.derive_signing_key_seed(Some(&vault), &input).is_err());

        ks.add_customer(vault.clone(), [9u8; 32]);
        let under_vault = hex::encode(ks.derive_signing_key_seed(Some(&vault), &input).unwrap().as_ref());
        let under_default = signing_seed_hex(&ks, &input);
        assert_ne!(under_vault, under_default, "a vault key must come from the vault's master");

        ks.evict_customer(&vault);
        assert!(
            ks.derive_signing_key_seed(Some(&vault), &input).is_err(),
            "an evicted vault must refuse, never fall back to the default master"
        );
    }

    #[test]
    fn a_signing_key_signs_and_verifies() {
        use crate::signing_keys::KeyBinding::Project;
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let input = signing_key_input(APP, "bob.near", H1, Project, "records");
        let seed = ks.derive_signing_key_seed(None, &input).unwrap();
        let sk = SigningKey::from_bytes(&seed);
        let sig = sk.sign(b"record #1");
        assert!(sk.verifying_key().verify(b"record #1", &sig).is_ok());
        assert!(sk.verifying_key().verify(b"record #2", &sig).is_err());
        // The same signature an independent ed25519 implementation makes.
        assert_eq!(
            hex::encode(sig.to_bytes()),
            "44383725b38816424b14d0f8d8d020b9de480c3631ad7a9ba675c56d67fbaa28447814aac6e1e37659828e426bab2d9a44a67df7a998b68c2e0b71632a61450a"
        );
    }

    /// A signing key is never cached: nothing of it stays in the keystore.
    #[test]
    fn a_signing_key_leaves_no_copy_in_the_cache() {
        use crate::signing_keys::KeyBinding::{Project, Wasm};
        let ks = Keystore::generate();
        for (project, bind) in [(APP, Project), (None, Wasm)] {
            let input = signing_key_input(project, "bob.near", H1, bind, "k");
            let _ = ks.derive_signing_key_seed(None, &input).unwrap();
        }
        assert!(ks.keypair_cache.read().unwrap().is_empty());
    }

    /// Derivation at trace level logs nothing of the seed or the master.
    #[test]
    fn deriving_a_signing_key_logs_nothing_of_the_seed() {
        use crate::signing_keys::KeyBinding::{Project, Wasm};
        let buf = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = {
            let buf = buf.clone();
            move || LogSink(buf.clone())
        };
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(writer)
            .finish();
        let ks = Keystore::from_master_secret(&fixed_master()).unwrap();
        let mut seeds = Vec::new();
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("capture is live");
            for (project, bind) in [(APP, Project), (None, Wasm)] {
                let input = signing_key_input(project, "bob.near", H1, bind, "records");
                seeds.push(hex::encode(ks.derive_signing_key_seed(None, &input).unwrap().as_ref()));
            }
        });
        let logged = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("capture is live"), "the capture must be working: {logged:?}");
        for seed in seeds {
            assert!(!logged.contains(&seed[..16]), "a seed reached the log");
        }
        assert!(!logged.contains(&hex::encode(fixed_master())[..16]), "the master reached the log");
    }

    struct LogSink(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for LogSink {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
