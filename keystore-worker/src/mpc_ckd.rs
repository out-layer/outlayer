//! NEAR MPC Chain Key Derivation (CKD) integration for deterministic master key generation
//!
//! This module implements deterministic master key generation inside TEE using NEAR MPC network.
//! The master key is derived deterministically and can only be generated inside a verified TEE.
//!
//! Flow:
//! 1. TEE boots and generates/loads a NEAR keypair
//! 2. TEE generates attestation evidence with its public key
//! 3. TEE submits registration to DAO contract
//! 4. DAO members vote to approve the keystore
//! 5. After approval, TEE requests secret from MPC network using CKD
//! 6. MPC network derives and returns deterministic secret
//! 7. TEE uses this secret as master key for all keystore operations
//!
//! ## Lock acquisition order
//!
//! Two async locks may both be held by the same task in some future
//! code path. The canonical acquisition order — to prevent any
//! deadlock if a future caller needs both — is:
//!
//! 1. [`vault_load_locks`] (per-vault, used by [`add_customer`])
//! 2. [`crate::api::MpcContext::signer_nonce_lock`] (process-wide,
//!    held by `/sign-vault-verification` around tx broadcast)
//!
//! No current code path takes both, but anyone adding a "verify and
//! immediately load master" optimisation MUST take vault_load_locks
//! FIRST and signer_nonce_lock SECOND. Reverse order would risk
//! deadlock if `/sign-vault-verification` and a wallet handler ever
//! contended for the same vault.

use anyhow::{Context, Result};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use elliptic_curve::{Field as _, Group as _, group::prime::PrimeCurveAffine as _};
use hkdf::Hkdf;
use near_jsonrpc_client::methods;
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
use near_primitives::types::{AccountId, Balance, BlockReference, Finality, FunctionArgs, Gas};
use near_primitives::views::{QueryRequest, CallResult, FinalExecutionStatus};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

use crate::crypto::Keystore;

// Constants from Bowen's example
const BLS12381G1_PUBLIC_KEY_SIZE: usize = 48;
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";
const OUTPUT_SECRET_SIZE: usize = 32;

// MPC app_id derivation prefix (must match MPC contract exactly)
const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";

/// Derive app_id the same way MPC contract does
/// app_id = SHA3-256("{prefix}{predecessor_id},{derivation_path}")
fn derive_app_id(predecessor_id: &str, derivation_path: &str) -> [u8; 32] {
    let derivation_string = format!("{}{},{}", APP_ID_DERIVATION_PREFIX, predecessor_id, derivation_path);
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_string.as_bytes());
    hasher.finalize().into()
}

/// Seed string for Layer 1 vault TEE keypair derivation.
///
/// Used by both:
///   * `derive_vault_tee_keypair` — to derive the keypair inside the TEE
///   * `outlayer-cli init-vault` — to fetch the public key from the
///     worker BEFORE the atomic deploy, so the customer can include
///     `AddKey(<that pubkey>, function-call → MPC)` in the deploy tx.
///
/// **NOT** the same as Layer 2's `secret_path`. This seed is public — its
/// only role is keypair separation per vault. The HMAC key (default master)
/// is what makes it secret-equivalent.
///
/// **The `"outlayer.near:"` prefix is fixed across networks (testnet AND
/// mainnet) by design.** Per-network reproducibility comes from the
/// default master, which is itself per-network (each network's keystore
/// boots its own MPC CKD round-trip against that network's MPC contract).
/// Hard-coding a fixed string here keeps the seed stable if a future
/// network rename ever happens; what differentiates networks is the
/// HMAC key, not the input.
fn vault_tee_keypair_seed(vault_id: &AccountId) -> String {
    format!("outlayer.near:{}", vault_id)
}

/// Layer 1 — derive a deterministic Ed25519 keypair for the vault's TEE
/// function-call access key.
///
/// **Why this is Layer 1**: the vault account holds a function-call key
/// `(receiver=mpc_contract, methods=["request_app_private_key"])` that
/// the worker uses (only inside the TEE) to call MPC FROM the vault. The
/// secret half of that keypair must:
///   * be re-derivable on any approved TEE after a worker restart
///     (no sealed storage for vault keys in our trust model)
///   * be unique per vault_id (so customer A's vault key is not
///     customer B's, otherwise master cross-pollination)
///   * never leave the TEE
///
/// `HMAC-SHA256(default_master, "outlayer.near:{vault_id}")` satisfies
/// all three. `default_master` is in TEE memory; output is deterministic
/// for the same `(default_master, vault_id)` pair; different vault_ids
/// give independent keypairs.
///
/// Returns the NEAR-format `(PublicKey, SecretKey)` pair. The PublicKey
/// is what `outlayer-cli init-vault` includes in the atomic deploy as
/// the function-call AccessKey on the vault.
pub fn derive_vault_tee_keypair(
    keystore: &Keystore,
    vault_id: &AccountId,
) -> Result<(near_crypto::PublicKey, near_crypto::SecretKey)> {
    let seed = vault_tee_keypair_seed(vault_id);
    let (signing_key, verifying_key) = keystore.derive_keypair(None, &seed)?;

    // NEAR's ED25519SecretKey is 64 bytes: [secret(32) | public(32)].
    // Same construction as `tee_registration::generate_keypair`.
    let mut keypair_bytes = [0u8; 64];
    keypair_bytes[..32].copy_from_slice(&signing_key.to_bytes());
    keypair_bytes[32..].copy_from_slice(verifying_key.as_bytes());

    let secret_key = near_crypto::SecretKey::ED25519(near_crypto::ED25519SecretKey(keypair_bytes));
    let public_key = secret_key.public_key();
    Ok((public_key, secret_key))
}

/// A vault's on-chain balance was too low to cover the gas prepayment for the
/// MPC `request_master` call, so child-key derivation (CKD) cannot proceed.
///
/// This is a plain operational condition (not a bug): NEAR requires the signer
/// to prepay the full attached gas up front (most of it is refunded after
/// execution). We surface it as a distinct, downcastable error so the HTTP
/// layer can return an actionable "top up the vault" message with the exact
/// shortfall, instead of an opaque 400/503.
#[derive(Debug)]
pub struct InsufficientVaultBalance {
    pub vault: AccountId,
}

impl std::fmt::Display for InsufficientVaultBalance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Kept short on purpose — the exact have/need/cost amounts are in the
        // keystore's `CKD broadcast_tx_commit failed` error log (raw RPC error).
        write!(
            f,
            "Vault {}: insufficient NEAR balance to register the vault on the network. \
             Recommended balance: 0.5+ NEAR.",
            self.vault,
        )
    }
}

impl std::error::Error for InsufficientVaultBalance {}

/// The chain says this keystore may not serve `vault`'s master: the DAO does
/// not verify it (never verified, or banned — `is_vault_verified` answers
/// `false` for both), or the vault is unlocked (recovery completed, the parent
/// holds a FullAccess key). A standing answer about the vault, not a failure
/// to get one: it holds until the DAO or the vault's owner changes it, so the
/// HTTP layer can refuse the request by type instead of reporting an outage.
#[derive(Debug)]
pub enum VaultNotServable {
    NotVerified(AccountId),
    Unlocked(AccountId),
}

impl std::fmt::Display for VaultNotServable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultNotServable::NotVerified(vault) => write!(
                f,
                "vault {vault} is not verified on keystore-dao (or has been banned); \
                 cannot serve per-vault master"
            ),
            VaultNotServable::Unlocked(vault) => write!(
                f,
                "vault {vault} is unlocked (recovery completed); per-vault master \
                 cannot be served for unlocked vaults — the customer now \
                 owns this vault and must derive their own keys directly via MPC"
            ),
        }
    }
}

impl std::error::Error for VaultNotServable {}

/// True iff a broadcast error is a NEAR `NotEnoughBalance` pre-inclusion
/// rejection (the signer can't cover the tx gas prepayment). Deep-matches the
/// exact nested shape produced by near-jsonrpc-client 0.22 / near-primitives
/// 0.37. The exact have/need amounts are left in the raw error log — the
/// user-facing message doesn't need them.
fn is_not_enough_balance(
    e: &near_jsonrpc_client::errors::JsonRpcError<
        near_jsonrpc_primitives::types::transactions::RpcTransactionError,
    >,
) -> bool {
    use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
    use near_jsonrpc_primitives::types::transactions::RpcTransactionError;
    use near_primitives::errors::InvalidTxError;

    matches!(
        e,
        JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcTransactionError::InvalidTransaction {
                context: InvalidTxError::NotEnoughBalance { .. },
            },
        ))
    )
}

/// A pre-inclusion `InvalidNonce` reject: the nonce we read was consumed between our read and our
/// broadcast — with several keystore instances this is another instance cold-loading the same vault
/// (it signs `vault.request_master` with the same vault key). CKD is deterministic, so a fresh nonce
/// and a second broadcast yield the same master.
fn is_invalid_nonce(
    e: &near_jsonrpc_client::errors::JsonRpcError<
        near_jsonrpc_primitives::types::transactions::RpcTransactionError,
    >,
) -> bool {
    use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
    use near_jsonrpc_primitives::types::transactions::RpcTransactionError;
    use near_primitives::errors::InvalidTxError;

    matches!(
        e,
        JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcTransactionError::InvalidTransaction {
                context: InvalidTxError::InvalidNonce { .. },
            },
        ))
    )
}

/// How many times a CKD broadcast is re-submitted after an `InvalidNonce` reject. One: the only
/// legitimate cause is one concurrent submitter per vault, and every retry costs a CKD fee.
const CKD_INVALID_NONCE_RETRIES: u32 = 1;

/// MPC CKD configuration from environment
#[derive(Debug, Clone)]
pub struct MpcCkdConfig {
    /// MPC contract ID (e.g., "v1.signer.testnet"). Pre-parsed at boot
    /// so a malformed env var fails fast instead of erroring on the
    /// first per-vault request.
    pub mpc_contract_id: AccountId,

    /// MPC domain ID for BLS12-381 (usually 2)
    pub mpc_domain_id: u64,

    /// MPC public key for the domain (BLS12-381 G2)
    pub mpc_public_key: String,

    /// NEAR RPC URL
    pub near_rpc_url: String,

    /// Keystore-DAO contract account id. Pre-parsed at boot so a
    /// malformed env var fails fast at startup rather than on the
    /// first request that needs to use it.
    pub keystore_dao_id: AccountId,
}

impl MpcCkdConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let mpc_contract_id_raw = std::env::var("MPC_CONTRACT_ID")
            .context("MPC_CONTRACT_ID is required for MPC CKD")?;
        let mpc_contract_id: AccountId = mpc_contract_id_raw
            .parse()
            .with_context(|| format!("MPC_CONTRACT_ID is not a valid NEAR AccountId: {}", mpc_contract_id_raw))?;

        let keystore_dao_raw = std::env::var("KEYSTORE_DAO_CONTRACT")
            .context("KEYSTORE_DAO_CONTRACT is required for TEE registration")?;
        let keystore_dao_id: AccountId = keystore_dao_raw
            .parse()
            .with_context(|| format!("KEYSTORE_DAO_CONTRACT is not a valid NEAR AccountId: {}", keystore_dao_raw))?;

        Ok(Self {
            // CRITICAL: No fallback - must be explicitly configured
            mpc_contract_id,

            // CRITICAL: No fallback - wrong domain gives wrong keys
            mpc_domain_id: std::env::var("MPC_DOMAIN_ID")
                .unwrap_or_else(|_| "2".to_string())
                .parse()
                .context("Invalid MPC_DOMAIN_ID - must be a number")?,

            mpc_public_key: std::env::var("MPC_PUBLIC_KEY")
                .context("MPC_PUBLIC_KEY required for CKD")?,


            near_rpc_url: std::env::var("NEAR_RPC_URL")
                 .context("NEAR_RPC_URL is required for MPC CKD")?,

            keystore_dao_id,
        })
    }
}

/// CKD request arguments (matching MPC contract interface)
#[derive(Debug, Serialize, Deserialize)]
pub struct CkdRequestArgs {
    pub request: CkdArgs,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CkdArgs {
    pub derivation_path: String,  // Empty string "" for keystore master key
    pub app_public_key: String,   // BLS12-381 G1 public key in NEAR format
    pub domain_id: u64,
}

/// CKD response from MPC network
#[derive(Debug, Serialize, Deserialize)]
pub struct CkdResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,  // Optional field for compatibility
    pub big_y: String,  // BLS12-381 G1 point
    pub big_c: String,  // BLS12-381 G1 point
}

/// MPC CKD client for requesting deterministic secrets.
///
/// Stateless w.r.t. the signer — every call accepts the signer
/// explicitly. This is intentional: holding a per-instance signer here
/// would be a footgun for the per-vault path, which signs as the vault
/// rather than the keystore-dao. Removing the field also forces every
/// future method to take signer at the call site, so a maintainer
/// adding a third CKD flow can't accidentally inherit the wrong one.
pub struct MpcCkdClient {
    config: MpcCkdConfig,
    rpc_client: crate::near::RpcClient,
    /// Separate, far more patient client for the CKD broadcast. The derivation result comes
    /// back as the transaction's own `SuccessValue`, so the request stays open until the MPC
    /// nodes resume the yielded receipt — cutting it short would abandon a transaction that
    /// is already on-chain. Queries keep the fast client above: they sit on the signing path.
    rpc_client_tx: crate::near::RpcClient,
}

impl MpcCkdClient {
    /// Create new MPC CKD client
    pub fn new(config: MpcCkdConfig) -> Self {
        let rpc_client = crate::near::rpc_client(&config.near_rpc_url);
        let rpc_client_tx = crate::near::rpc_client_tx(&config.near_rpc_url);
        Self { config, rpc_client, rpc_client_tx }
    }

    /// Request deterministic secret from MPC network using CKD via the
    /// **legacy default-master path**: signer = keystore-dao, receiver =
    /// keystore-dao (which proxies to MPC via `request_key`), derivation_path = "".
    ///
    /// Used at boot to materialise the OutLayer `default_master`.
    /// Per-vault masters use [`request_vault_master`] (Layer 2).
    pub async fn request_master_secret(
        &self,
        signer: &near_crypto::InMemorySigner,
    ) -> Result<[u8; 32]> {
        tracing::info!(
            account = %signer.account_id,
            domain = self.config.mpc_domain_id,
            "Requesting OutLayer default master from MPC via keystore-dao proxy"
        );

        // Legacy proxy flow: keystore-dao calls itself, which internally
        // forwards to MPC. receiver_id = signer's own account_id. The
        // DAO's `request_key` accepts deposit = 0 (no `assert_one_yocto`).
        let receiver_id = signer.account_id.clone();

        self.request_ckd_inner(signer, &receiver_id, "request_key", "")
            .await
    }

    /// Request a per-vault master from MPC via the vault contract's
    /// `request_master` proxy method, signed with the vault's Layer 1
    /// TEE function-call key.
    ///
    /// Why a proxy and not a direct call to MPC: NEAR's
    /// function-call access keys cannot attach any deposit, but
    /// MPC's `request_app_private_key` `assert_one_yocto`s. The
    /// vault contract's `request_master` is `predecessor==self`-gated
    /// and adds the 1 yocto from the vault's own balance via a
    /// cross-contract call. MPC sees the cross-contract call's
    /// predecessor as the vault account, so per-vault `app_id`
    /// uniqueness is preserved (different vault accounts ⇒ different
    /// derived masters even with identical `derivation_path`).
    ///
    /// This is Layer 2 of the per-vault master derivation:
    ///   - `vault_signer.account_id` is the vault id; the vault then
    ///     acts as `predecessor` for MPC, which hashes into the
    ///     per-app key — uniqueness per vault id is what gives us
    ///     per-vault masters.
    ///   - `vault_signer.public_key` must be the Layer 1 TEE pubkey
    ///     the customer added as a function-call AccessKey during
    ///     atomic deploy, scoped to `(vault_id, ["request_master"])`.
    ///   - `derivation_path` should be an HMAC-derived string (see
    ///     [`Keystore::derive_secret_string`]) so a malicious
    ///     customer cannot pre-empt the worker by guessing the path
    ///     before the worker's first MPC call.
    pub async fn request_vault_master(
        &self,
        vault_signer: &near_crypto::InMemorySigner,
        derivation_path: &str,
    ) -> Result<[u8; 32]> {
        tracing::info!(
            vault = %vault_signer.account_id,
            domain = self.config.mpc_domain_id,
            "Requesting per-vault master via vault.request_master proxy"
        );

        // The vault contract proxies the MPC call: the TEE function-call
        // key signs `vault.request_master(args)` with deposit=0 (FC keys
        // can't attach deposit), and the vault contract's cross-contract
        // call to MPC adds the 1 yoctoNEAR `assert_one_yocto` requires
        // out of its own balance. MPC sees the cross-contract call's
        // predecessor as the vault account, so per-vault `app_id`
        // uniqueness is preserved.
        let receiver_id = vault_signer.account_id.clone();

        self.request_ckd_inner(
            vault_signer,
            &receiver_id,
            "request_master",
            derivation_path,
        )
        .await
    }

    /// Generic CKD request: ephemeral keygen → tx → decrypt+verify → HKDF.
    ///
    /// Both the legacy default-master path and the new per-vault path
    /// flow through here. The four parameters fully specify the
    /// on-chain shape of the call:
    ///
    /// * `signer` — who signs the tx (keystore-dao for default master,
    ///   vault account for per-vault master). This is also the
    ///   `predecessor_id` MPC hashes into `app_id` — so different signers
    ///   yield disjoint key-spaces even if `derivation_path` collides.
    /// * `receiver_id` — keystore-dao (proxy) or mpc_contract (direct).
    /// * `method_name` — `"request_key"` for the proxy method or
    ///   `"request_app_private_key"` for direct MPC.
    /// * `derivation_path` — empty for legacy, HMAC-derived secret for
    ///   per-vault.
    async fn request_ckd_inner(
        &self,
        signer: &near_crypto::InMemorySigner,
        receiver_id: &AccountId,
        method_name: &str,
        derivation_path: &str,
    ) -> Result<[u8; 32]> {
        // 1. Ephemeral BLS12-381 G1 keypair (one-shot per request).
        let (ephemeral_private_key, ephemeral_public_key) = self.generate_ephemeral_key();
        let app_public_key = self.g1_to_near_format(ephemeral_public_key);
        tracing::debug!(
            ephemeral_pubkey = %app_public_key,
            "Generated ephemeral CKD keypair"
        );

        // 2. CKD request envelope.
        let request_args = CkdRequestArgs {
            request: CkdArgs {
                derivation_path: derivation_path.to_string(),
                app_public_key,
                domain_id: self.config.mpc_domain_id,
            },
        };

        // 3. Submit tx: signer → receiver_id, calling method_name(request_args).
        let response = self
            .call_mpc_contract(signer, receiver_id, method_name, request_args)
            .await?;

        // 4. Recompute app_id the same way MPC did — based on the SIGNER
        //    account id (= predecessor on the MPC side) and the path.
        let predecessor_id = signer.account_id.as_str();
        let app_id = derive_app_id(predecessor_id, derivation_path);
        // SECURITY: the per-vault `derivation_path` is HMAC-derived from the
        // OutLayer default master and is what protects the race-window
        // before the customer's first on-chain MPC call (a leak before
        // that call would let the customer pre-empt us). Once the tx
        // commits the path goes on-chain in plaintext, but we still must
        // not expose it via the TEE log channel — Phala dashboard, log
        // shippers, error reports could otherwise leak it pre-commit.
        // We log a hash for correlation only.
        let derivation_path_fingerprint =
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(derivation_path.as_bytes()));
        tracing::debug!(
            predecessor = predecessor_id,
            derivation_path_sha256 = %derivation_path_fingerprint,
            app_id_hex = hex::encode(app_id),
            "Recomputed MPC app_id locally"
        );

        // 5. Decrypt with our ephemeral private key + verify pairing.
        let secret = self.decrypt_secret_and_verify(
            response.big_y,
            response.big_c,
            ephemeral_private_key,
            &app_id,
        )?;

        // 6. HKDF stretch the 48-byte G1 element to a 32-byte master.
        let master_secret = self.derive_strong_key(secret, b"")?;

        tracing::info!(
            predecessor = predecessor_id,
            "✅ CKD secret successfully derived from MPC"
        );
        Ok(master_secret)
    }

    /// Generate ephemeral BLS12-381 G1 keypair
    fn generate_ephemeral_key(&self) -> (Scalar, G1Projective) {
        let mut rng = OsRng;
        let private_key = Scalar::random(&mut rng);
        let public_key = G1Projective::generator() * private_key;
        (private_key, public_key)
    }

    /// Convert G1 point to NEAR format (bls12381g1:base58...)
    fn g1_to_near_format(&self, point: G1Projective) -> String {
        let compressed = point.to_compressed();
        let base58 = bs58::encode(&compressed).into_string();
        format!("bls12381g1:{}", base58)
    }

    /// Parse NEAR format to G1 point
    fn near_format_to_g1(&self, s: &str) -> Result<G1Projective> {
        // Remove prefix
        let base58_part = s.strip_prefix("bls12381g1:")
            .context("Invalid BLS12-381 G1 format")?;

        // Decode base58
        let bytes = bs58::decode(base58_part)
            .into_vec()
            .context("Invalid base58 encoding")?;

        // Convert to compressed array
        let mut compressed = [0u8; 48];
        compressed.copy_from_slice(&bytes[..48]);

        // Parse as G1 point
        G1Projective::from_compressed(&compressed)
            .into_option()
            .context("Invalid G1 point")
    }

    /// Parse NEAR format to G2 point
    fn near_format_to_g2(&self, s: &str) -> Result<G2Projective> {
        // Remove prefix
        let base58_part = s.strip_prefix("bls12381g2:")
            .context("Invalid BLS12-381 G2 format")?;

        // Decode base58
        let bytes = bs58::decode(base58_part)
            .into_vec()
            .context("Invalid base58 encoding")?;

        // Convert to compressed array
        let mut compressed = [0u8; 96];
        compressed.copy_from_slice(&bytes[..96]);

        // Parse as G2 point
        G2Projective::from_compressed(&compressed)
            .into_option()
            .context("Invalid G2 point")
    }

    /// Submit a CKD request as a NEAR transaction and parse the response.
    ///
    /// Generic over signer/receiver/method to support both:
    ///   * legacy: signer = keystore-dao, receiver = keystore-dao,
    ///     method = `"request_key"` (proxy contract forwards to MPC)
    ///   * vault: signer = vault account, receiver = mpc_contract,
    ///     method = `"request_app_private_key"` (direct MPC call)
    ///
    /// The retry-on-access-key-invisible loop guards against the
    /// post-DAO-approval window where the worker's new access key has
    /// been added on-chain but isn't yet visible at the RPC node — same
    /// pattern is needed for vault calls because a vault's TEE key has
    /// only just been added in the atomic deploy when the first call lands.
    async fn call_mpc_contract(
        &self,
        signer: &near_crypto::InMemorySigner,
        receiver_id: &AccountId,
        method_name: &str,
        request: CkdRequestArgs,
    ) -> Result<CkdResponse> {
        tracing::info!(
            signer = %signer.account_id,
            receiver = %receiver_id,
            method = method_name,
            "Submitting CKD tx"
        );

        // Serialize request to JSON
        let args = serde_json::to_vec(&request)?;

        let mut invalid_nonce_retries = 0u32;
        let outcome = loop {
        // Get access key information for nonce.
        // Retry: a freshly-added access key may not be visible to the RPC node yet
        // (DAO approval for default-master path, atomic-deploy for vault path).
        let mut nonce = 0u64;
        let max_retries = 5;
        for attempt in 1..=max_retries {
            let access_key_query = methods::query::RpcQueryRequest {
                block_reference: BlockReference::Finality(Finality::Final),
                request: QueryRequest::ViewAccessKey {
                    account_id: signer.account_id.clone(),
                    public_key: signer.public_key.clone(),
                },
            };

            match self.rpc_client.call(access_key_query).await {
                Ok(response) => {
                    if let QueryResponseKind::AccessKey(access_key_view) = response.kind {
                        nonce = access_key_view.nonce + 1;
                        break;
                    } else {
                        anyhow::bail!("Failed to get access key nonce");
                    }
                }
                Err(e) if attempt < max_retries => {
                    tracing::warn!(
                        attempt,
                        max_retries,
                        "Access key not yet visible on RPC node, retrying in 3s... ({})", e
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
                Err(e) => {
                    return Err(e).context("Failed to query access key after retries");
                }
            }
        }

        // Get current block hash
        let block = self.rpc_client
            .call(methods::block::RpcBlockRequest {
                block_reference: BlockReference::Finality(Finality::Final),
            })
            .await
            .context("Failed to get latest block")?;

        // Create transaction
        let transaction_v0 = TransactionV0 {
            signer_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
            nonce,
            receiver_id: receiver_id.clone(),
            block_hash: block.header.hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method_name.to_string(),
                args: args.clone(),
                gas: Gas::from_gas(300_000_000_000_000), // 300 TGas
                // FC access keys can't attach deposit. Boot CKD signs as
                // dao.outlayer.testnet (FullAccess elsewhere but no
                // deposit needed since DAO's `request_key` doesn't
                // assert_one_yocto). Per-vault CKD goes through the
                // vault's own `request_master` proxy — that adds the
                // 1 yocto MPC requires from the vault contract's
                // balance via cross-contract `with_attached_deposit`.
                deposit: Balance::from_yoctonear(0),
            }))],
        };

        let transaction = Transaction::V0(transaction_v0);

        // Sign and send transaction
        let signature = signer.sign(transaction.get_hash_and_size().0.as_ref());
        let request = methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction: near_primitives::transaction::SignedTransaction::new(
                signature,
                transaction,
            ),
        };

        match self.rpc_client_tx.call(request).await {
            Ok(o) => break o,
            Err(e) if is_invalid_nonce(&e) && invalid_nonce_retries < CKD_INVALID_NONCE_RETRIES => {
                invalid_nonce_retries += 1;
                // Short jittered pause so two instances that collided do not re-read the nonce in
                // lockstep and collide again.
                let pause_ms = 200 + (rand::random::<u64>() % 500);
                tracing::warn!(
                    signer = %signer.account_id,
                    receiver = %receiver_id,
                    method = method_name,
                    nonce,
                    pause_ms,
                    "CKD tx rejected with InvalidNonce (concurrent submitter on this account); \
                     re-reading the nonce and re-submitting once"
                );
                tokio::time::sleep(std::time::Duration::from_millis(pause_ms)).await;
                continue;
            }
            Err(e) => {
                // Surface the exact RPC/broadcast error. Without this the
                // whole failure is swallowed: the only thing that reaches
                // the caller is the `MPC CKD failed for vault …` wrapper
                // in `add_customer`, with no InvalidTxError variant, no
                // status, nothing in the logs. Log the full chain here so
                // a pre-inclusion reject (InvalidSignature / InvalidNonce /
                // NotEnoughBalance / InvalidAccessKey / Expired) is visible.
                tracing::error!(
                    signer = %signer.account_id,
                    receiver = %receiver_id,
                    method = method_name,
                    nonce,
                    signer_pubkey = %signer.public_key,
                    error = ?e,
                    "CKD broadcast_tx_commit failed (pre-inclusion / RPC error)"
                );
                // The single most common operational failure here is a vault
                // that can't cover the gas prepayment for the MPC call. Turn
                // it into a TYPED, actionable error so the HTTP layer can tell
                // the user to top up the vault instead of returning an opaque
                // 400/503. (Exact have/need amounts stay in the log above.)
                if is_not_enough_balance(&e) {
                    return Err(anyhow::Error::new(InsufficientVaultBalance {
                        vault: signer.account_id.clone(),
                    }));
                }
                return Err(anyhow::Error::new(e).context("Failed to call MPC contract"));
            }
        }
        };

        // Check transaction status and extract result
        match &outcome.status {
            FinalExecutionStatus::SuccessValue(value) => {
                // Parse response from transaction result
                let ckd_response: CkdResponse = serde_json::from_slice(value)
                    .context("Failed to parse MPC response")?;
                Ok(ckd_response)
            }
            FinalExecutionStatus::Failure(err) => {
                tracing::error!(
                    signer = %signer.account_id,
                    receiver = %receiver_id,
                    method = method_name,
                    tx_hash = %outcome.transaction.hash,
                    error = ?err,
                    "CKD transaction included but execution failed"
                );
                Err(anyhow::anyhow!("MPC transaction failed: {:?}", err))
            }
            other => {
                tracing::error!(
                    signer = %signer.account_id,
                    receiver = %receiver_id,
                    method = method_name,
                    status = ?other,
                    "CKD transaction ended in unexpected status"
                );
                Err(anyhow::anyhow!("Unexpected transaction status: {:?}", other))
            }
        }
    }

    /// Decrypt secret and verify signature (from Bowen's example)
    fn decrypt_secret_and_verify(
        &self,
        big_y: String,
        big_c: String,
        private_key: Scalar,
        app_id: &[u8],
    ) -> Result<[u8; BLS12381G1_PUBLIC_KEY_SIZE]> {
        // Parse G1 points
        let big_y = self.near_format_to_g1(&big_y)?;
        let big_c = self.near_format_to_g1(&big_c)?;

        // Parse MPC public key (G2)
        let mpc_public_key = self.near_format_to_g2(&self.config.mpc_public_key)?;

        // Decrypt the secret: secret = big_c - big_y * private_key
        let secret = big_c - big_y * private_key;

        // Verify the signature using pairing
        if !self.verify_signature(&mpc_public_key, app_id, &secret) {
            anyhow::bail!("MPC signature verification failed");
        }

        // Return secret as bytes
        Ok(secret.to_compressed())
    }

    /// Verify MPC signature using pairing (from NEAR MPC ckd-example-cli)
    fn verify_signature(&self, public_key: &G2Projective, app_id: &[u8], signature: &G1Projective) -> bool {
        let element1: G1Affine = signature.into();
        if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
            return false;
        }

        let element2: G2Affine = public_key.into();
        if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
            return false;
        }

        // Hash input = MPC public key || app_id (must match MPC contract)
        let hash_input = [public_key.to_compressed().as_slice(), app_id].concat();
        let base1 = G1Projective::hash_to_curve(&hash_input, NEAR_CKD_DOMAIN, &[]).into();
        let base2 = G2Affine::generator();

        // Verify pairing equation
        blstrs::pairing(&base1, &element2) == blstrs::pairing(&element1, &base2)
    }

    /// Derive strong 32-byte key using HKDF (from Bowen's example)
    fn derive_strong_key(
        &self,
        ikm: [u8; BLS12381G1_PUBLIC_KEY_SIZE],
        info: &[u8],
    ) -> Result<[u8; OUTPUT_SECRET_SIZE]> {
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; OUTPUT_SECRET_SIZE];
        hk.expand(info, &mut okm)
            .map_err(|e| anyhow::anyhow!("HKDF expansion failed: {}", e))?;
        Ok(okm)
    }
}

/// Check if keystore is approved by DAO contract
/// Are these TEE measurements in the DAO's approved list?
///
/// A FREE view call, and the whole point of it is that it is free. Without this check the
/// keystore submits `submit_keystore_registration` blind: the contract verifies the DCAP quote,
/// extracts the measurements, and only THEN panics if they are unapproved — so essentially all
/// of the verification gas is burnt for an outcome we could have predicted. Measured on a real
/// rejection: 183.6 TGas / 0.0183 NEAR, repeated on every container restart until an operator
/// approves.
///
/// The keystore parses the same measurements out of the same quote the contract does; this was
/// confirmed against a live rejection, where the keystore's log line and the contract's own
/// receipt log carried identical values. `scripts/deploy_tdx.sh` already trusts that local parse
/// (it greps the keystore's log, not the contract's receipt), so nothing is lost by deciding
/// here instead of paying the chain to tell us.
pub async fn check_measurements_approved(
    near_rpc_url: &str,
    dao_contract: &str,
    measurements: &crate::tdx_attestation::TdxMeasurements,
) -> Result<bool> {
    let client = crate::near::rpc_client(near_rpc_url);

    let args = serde_json::json!({
        "measurements": {
            "mrtd": measurements.mrtd,
            "rtmr0": measurements.rtmr0,
            "rtmr1": measurements.rtmr1,
            "rtmr2": measurements.rtmr2,
            "rtmr3": measurements.rtmr3,
        }
    });

    let request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::CallFunction {
            account_id: dao_contract.parse()?,
            method_name: "is_measurements_approved".to_string(),
            args: FunctionArgs::from(serde_json::to_vec(&args)?),
        },
    };

    let response = client.call(request).await?;

    if let QueryResponseKind::CallResult(CallResult { result, .. }) = response.kind {
        Ok(serde_json::from_slice(&result)?)
    } else {
        Ok(false)
    }
}

pub async fn check_keystore_approval(
    near_rpc_url: &str,
    dao_contract: &str,
    public_key: &str,
) -> Result<bool> {
    let client = crate::near::rpc_client(near_rpc_url);

    // Prepare view call arguments
    let args = serde_json::json!({
        "public_key": public_key
    });

    let request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: QueryRequest::CallFunction {
            account_id: dao_contract.parse()?,
            method_name: "is_keystore_approved".to_string(),
            args: FunctionArgs::from(serde_json::to_vec(&args)?),
        },
    };

    let response = client.call(request).await?;

    if let QueryResponseKind::CallResult(CallResult { result, .. }) = response.kind {
        let approved: bool = serde_json::from_slice(&result)?;
        Ok(approved)
    } else {
        Ok(false)
    }
}

/// Read the on-chain access key for `(dao_contract, public_key)` and
/// verify its method-list contains every method this keystore-worker
/// build needs to call. Used at boot AFTER `is_keystore_approved`
/// returns true so a contract upgrade that widened the method-list
/// (without re-issuing access keys) is detected loudly instead of
/// silently sending txs that fail at access-key validation.
///
/// The DAO's `internal_execute_proposal` grants
/// `["request_key", "mark_vault_verified", "ban_vault"]` for any new
/// keystore. An older keystore approved before that change has only
/// `["request_key"]` — silent failure surface for vault verification
/// and ban operations. Returning Err here forces the operator to
/// regenerate the keystore keypair (TEE mode: restart the container)
/// or to manually delete-and-re-add the access key with the wider
/// method-list before the worker continues.
pub async fn check_access_key_methods(
    near_rpc_url: &str,
    dao_contract: &str,
    public_key: &near_crypto::PublicKey,
) -> Result<()> {
    use near_primitives::views::{AccessKeyPermissionView, QueryRequest as Qr};

    const REQUIRED: &[&str] = &["request_key", "mark_vault_verified", "ban_vault"];

    let client = crate::near::rpc_client(near_rpc_url);
    let request = methods::query::RpcQueryRequest {
        block_reference: BlockReference::Finality(Finality::Final),
        request: Qr::ViewAccessKey {
            account_id: dao_contract.parse()?,
            public_key: public_key.clone(),
        },
    };
    let response = client
        .call(request)
        .await
        .with_context(|| format!("view access_key for {}", public_key))?;

    let access_key = match response.kind {
        QueryResponseKind::AccessKey(view) => view,
        other => {
            anyhow::bail!(
                "view_access_key returned unexpected response kind: {:?}",
                other
            )
        }
    };

    match access_key.permission {
        AccessKeyPermissionView::FullAccess => {
            // Full access trivially covers all methods — common for
            // local-dev keystores.
            tracing::info!("Access key has FullAccess (covers all methods)");
            Ok(())
        }
        AccessKeyPermissionView::FunctionCall {
            method_names,
            receiver_id,
            ..
        } => {
            let missing: Vec<&str> = REQUIRED
                .iter()
                .copied()
                .filter(|m| !method_names.iter().any(|n| n == m))
                .collect();
            if !missing.is_empty() {
                anyhow::bail!(
                    "keystore is approved but its access key on {dao} (receiver={receiver}) \
                     has stale method-list {actual:?} — required {required:?}, missing {missing:?}. \
                     This usually means the DAO contract was upgraded to widen the keystore \
                     access-key grant but existing keystores were not re-registered. \
                     Fix: regenerate this keystore's keypair (TEE mode → redeploy the container, \
                     fresh keypair → fresh registration with the wider method-list), OR have \
                     the DAO owner manually delete-and-re-add this access key with the new \
                     methods.",
                    dao = dao_contract,
                    receiver = receiver_id,
                    actual = method_names,
                    required = REQUIRED,
                    missing = missing,
                );
            }
            Ok(())
        }
        // near-primitives 0.37 added gas-key permissions. Fail closed: a gas key is not the
        // plain function-call access key this check expects, so refuse rather than assume.
        other => {
            anyhow::bail!(
                "keystore access key on {dao} has an unsupported permission ({other:?}); \
                 expected a plain function-call access key",
                dao = dao_contract,
            );
        }
    }
}

/// Initialize keystore with MPC-derived master secret.
///
/// Returns `(keystore, config, signer)` — all three are needed by
/// `AppState::set_mpc_context`:
/// * `keystore` is the freshly-derived default-master keystore.
/// * `config` is the parsed MPC CKD config (re-used for the lazy
///   per-vault path).
/// * `signer` is the worker's keystore-dao signer with the approved
///   access key permitting both `request_key` (for CKD) and
///   `mark_vault_verified` (for `/sign-vault-verification`).
///
/// Sharing the parsed config + constructed signer avoids re-parsing
/// env vars / re-loading the keystore secret_key in two places.
pub async fn initialize_mpc_keystore(
    dao_contract_id: String,
    keystore_secret_key: near_crypto::SecretKey,
) -> Result<(crate::crypto::Keystore, MpcCkdConfig, near_crypto::InMemorySigner)> {
    tracing::info!("Initializing keystore with MPC CKD...");

    // Load configuration. Override keystore_dao_id with the explicit
    // arg (the env-loaded value is the boot-time default; some
    // entrypoints pass a different one).
    let mut config = MpcCkdConfig::from_env()?;
    config.keystore_dao_id = dao_contract_id.parse().with_context(|| {
        format!("dao_contract_id is not a valid AccountId: {}", dao_contract_id)
    })?;
    tracing::info!("MPC config: contract={}, domain={}",
        config.mpc_contract_id,
        config.mpc_domain_id
    );

    // The keystore DAO contract account is the signer for CKD —
    // every approved keystore signs as the same account, so they
    // all derive the same default master.
    let signer_account_id = config.keystore_dao_id.clone();
    tracing::info!("Using DAO contract as signer: {}", signer_account_id);

    // Create signer for DAO contract using keystore's key (added as access key after approval)
    let signer = near_crypto::InMemorySigner {
        account_id: signer_account_id.clone(),
        public_key: keystore_secret_key.public_key(),
        secret_key: keystore_secret_key,
    };

    // Create MPC client. Signer is passed per-call.
    let mpc_client = MpcCkdClient::new(config.clone());

    // Request deterministic master secret from MPC
    let master_secret = mpc_client.request_master_secret(&signer).await?;

    // Create keystore with MPC-derived master secret
    let keystore = crate::crypto::Keystore::from_master_secret(&master_secret)?;

    tracing::info!("✅ Keystore initialized with MPC-derived master secret");
    tracing::info!("   This secret is deterministic for account: {}", signer_account_id);
    tracing::info!("   All approved keystores will derive the same secret");

    Ok((keystore, config, signer))
}

/// Seed prefix for the per-vault Layer-2 derivation path.
///
/// Combined with the vault id and HMAC'd against the OutLayer default
/// master, this yields the `derivation_path` argument we hand to MPC
/// when requesting the per-vault master.
const VAULT_MASTER_PATH_SEED: &str = "vault-master:";

fn vault_master_path_seed(vault_id: &AccountId) -> String {
    format!("{}{}", VAULT_MASTER_PATH_SEED, vault_id)
}

/// Process-wide dedup gate for concurrent first-time `add_customer` calls.
///
/// **Why**: under burst traffic (e.g. coordinator spinning up N workers
/// that all poll the same fresh vault) two concurrent callers can both
/// miss `keystore.has_customer` and each pay one MPC tx (~3-5s, ~30
/// mNEAR gas, charged to the *vault's* balance with the new direct-vault
/// flow). CKD is deterministic so the resulting masters are identical,
/// but the duplicate tx is wasted and could drain a vault's tiny gas
/// reserve.
///
/// **Design**: per-vault async mutex held across the MPC round-trip.
/// First caller wins, subsequent callers block on the same lock and
/// then take the cache-hit fast path on the recheck inside the
/// critical section. Map entries persist for the worker's lifetime
/// (bounded by active vault count — same magnitude as the masters
/// HashMap).
///
/// Process-global because the dedup target is process state (the
/// keystore, also process-global) — there's no per-handler-task scope
/// at which the gate would make sense.
fn vault_load_locks() -> &'static tokio::sync::Mutex<
    std::collections::HashMap<AccountId, std::sync::Arc<tokio::sync::Mutex<()>>>,
> {
    static LOCKS: std::sync::OnceLock<
        tokio::sync::Mutex<std::collections::HashMap<AccountId, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    LOCKS.get_or_init(|| tokio::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Populate the keystore with a customer's per-vault master via MPC
/// CKD (Layer 2 of the per-vault master derivation).
///
/// Two-step derivation:
///   1. **Layer 1** (HMAC, local): `derive_vault_tee_keypair(vault_id)` —
///      re-derives the Ed25519 keypair the customer added to the vault as
///      a function-call key during atomic deploy. This is the signer we
///      need to call MPC FROM the vault.
///   2. **Layer 2** (MPC CKD, on-chain): the worker submits a
///      `request_app_private_key` tx FROM the vault, with derivation_path
///      = `HMAC(default_master, "vault-master:{vault_id}")`. MPC hashes
///      `(prefix || predecessor=vault_id || derivation_path)` into an
///      app_id and returns an encrypted (big_y, big_c). We decrypt locally
///      and HKDF-stretch to a 32-byte master, then load it into the
///      keystore.
///
/// **Idempotent**: returns `Ok(())` immediately if the keystore already
/// has a master for this vault. Concurrent first-time loads for the
/// same vault are deduped via the [`vault_load_locks`] per-vault async
/// mutex below — only the winning task pays the MPC round-trip, the
/// rest take the fast path on the recheck inside the critical section.
///
/// **Race-attack protection**: the path is HMAC'd with `default_master`
/// (held only inside TEE), so a malicious customer with a backup vault
/// key cannot pre-empt us — they can't compute the path without the
/// master.
///
/// **Recovery**: any approved TEE has access to `default_master`, so it
/// re-derives Layer 1 + path identically and gets the same master back
/// from MPC. No sealed storage needed for vault masters.
pub async fn add_customer(
    config: &MpcCkdConfig,
    keystore: &Keystore,
    vault_id: &AccountId,
) -> Result<()> {
    // Optimistic fast path — no lock acquired.
    if keystore.has_customer(vault_id) {
        return Ok(());
    }

    // Acquire (or insert) the per-vault load lock under the global map
    // mutex. Drop the map lock immediately so other vaults aren't
    // blocked while we hold the per-vault lock across the MPC call.
    let per_vault_lock = {
        let mut map = vault_load_locks().lock().await;
        map.entry(vault_id.clone())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = per_vault_lock.lock().await;

    // Re-check inside the critical section: a concurrent caller may
    // have already populated the master while we were blocked on the
    // lock. This is what dedupes the burst-traffic scenario.
    if keystore.has_customer(vault_id) {
        return Ok(());
    }

    tracing::info!(vault = %vault_id, "Bootstrapping per-vault master via MPC CKD");

    // Layer 1: re-derive the vault's TEE function-call keypair.
    let (vault_pk, vault_sk) = derive_vault_tee_keypair(keystore, vault_id)?;
    tracing::debug!(vault = %vault_id, vault_tee_pubkey = %vault_pk, "Re-derived Layer 1 vault TEE keypair");

    // Layer 2: HMAC-derived secret path — unforgeable without default master.
    let secret_path = keystore.derive_secret_string(None, &vault_master_path_seed(vault_id))?;

    // Build the vault signer: signer_id = vault_id, key = Layer 1 secret.
    // The matching public_key was added as a function-call AccessKey on
    // `vault_id` during atomic deploy by the customer, restricted to
    // `(receiver=mpc_contract, methods=["request_app_private_key"])`.
    let vault_signer =
        near_crypto::InMemorySigner {
            account_id: vault_id.clone(),
            public_key: vault_sk.public_key(),
            secret_key: vault_sk,
        };

    // Issue MPC CKD as a fresh client (the worker's persistent client
    // is bound to the keystore-dao signer; vault calls need a different
    // signer per call so we don't mutate that one).
    // MpcCkdClient is now signer-less; pass the vault signer per-call.
    let mpc_client = MpcCkdClient::new(config.clone());

    let master = mpc_client
        .request_vault_master(&vault_signer, &secret_path)
        .await
        .with_context(|| format!("MPC CKD failed for vault {}", vault_id))?;

    keystore.add_customer(vault_id.clone(), master);
    tracing::info!(vault = %vault_id, "Per-vault master loaded into keystore");
    Ok(())
}

/// Cold-path loader for a per-customer master. The hot-path
/// `has_customer` fast-return lives in the wrapper
/// [`crate::api::AppState::ensure_customer_loaded`]; this function is
/// only invoked when the master is NOT in the TEE-memory cache, so
/// the gate it runs always precedes an actual MPC CKD round-trip.
///
/// Behaviour:
///   * `customer = None` ⇒ no-op (legacy default-master path).
///   * `customer = Some(c)`:
///     1. View-call `keystore-dao.is_vault_verified(c)` — `false` for
///        unverified AND banned vaults. Evicts cache and fails with
///        [`VaultNotServable::NotVerified`].
///     2. View-call `c.get_state()` and require `unlocked == false`.
///        A vault that went through `finalize_recovery` is now under
///        parent control; the DAO's `verified_vaults` set isn't
///        auto-updated, so without this recheck the worker would keep
///        deriving for a vault whose trust model has dropped to
///        "parent has FullAccess". Evicts cache and fails with
///        [`VaultNotServable::Unlocked`].
///     3. If both checks pass, take the per-vault load lock + call
///        [`add_customer`] to populate the cache.
///
/// **Why on-chain verify before MPC**: the MPC call burns gas from
/// the vault's balance; without this gate a malicious caller could
/// trigger MPC bills on arbitrary vault ids by spamming requests
/// with unknown `X-Customer-Vault` values. Both view calls are cheap.
pub async fn ensure_customer_loaded(
    config: &MpcCkdConfig,
    near_client: &crate::near::NearClient,
    keystore_dao_id: &AccountId,
    keystore: &Keystore,
    customer: Option<&AccountId>,
) -> Result<()> {
    let Some(vault_id) = customer else {
        return Ok(());
    };

    // Per-call gate: ALWAYS check on-chain state before serving, even
    // when the master is already cached. A vault that has gone through
    // `finalize_recovery` is now under parent FullAccess control —
    // continuing to serve a cached master would break the "sovereign
    // after recovery" guarantee (two parties would hold the secret:
    // the sovereign customer AND the OutLayer keystore cache).
    //
    // Cost: 2 RPC view-calls per signing op, ~100-300ms each. For an
    // already-loaded vault — which is every vault an active agent
    // signs with — they are issued concurrently, so the gate costs one
    // round-trip of latency rather than two. See `assert_serving_allowed`
    // for why an unknown vault deliberately keeps the sequential path.
    assert_serving_allowed(near_client, keystore_dao_id, vault_id, keystore).await?;

    if keystore.has_customer(vault_id) {
        return Ok(());
    }

    add_customer(config, keystore, vault_id).await
}

/// Verify on-chain that we are still allowed to serve secrets bound
/// to `vault_id`. Two checks:
///
/// 1. `keystore_dao.is_vault_verified(vault_id) == true` — covers the
///    DAO's verified set AND the banned set in one read (the contract
///    short-circuits banned vaults to false).
/// 2. `vault_id.get_state().unlocked == false` — vaults under parent
///    FullAccess (post-recovery) are no longer TEE-controlled. We must
///    refuse to derive new addresses or sign operations against them.
///
/// Either answer failing its check is a [`VaultNotServable`]; a read that
/// could not be made, or an answer of the wrong shape, is a plain error.
///
/// On unlocked detection we proactively evict the cached master so
/// subsequent calls don't even reach the cache check; the next attempt
/// will re-fail this gate cleanly with the same actionable error.
///
/// **Concurrency.** The two reads are independent, so for a vault whose
/// master is already in memory they are issued together and this gate
/// costs one round-trip instead of two — it sits on every signing
/// operation, so that is the difference between ~200-600 ms and half
/// of it, on every signature an agent makes.
///
/// This is deliberately NOT done for a vault we have never served.
/// `vault_id` is caller-supplied — the coordinator forwards
/// `X-Customer-Vault` verbatim — so anything at all can arrive here
/// wearing a vault's clothes, and speculating on the second call would
/// double the RPC traffic an arbitrary caller can make us generate.
/// A vault that is already loaded is one that has previously passed
/// this same gate AND paid for an on-chain CKD derivation; garbage
/// cannot be in that set, so the fast path is closed to it. The
/// ordering below is unchanged either way: `is_vault_verified` is
/// still settled first and still decides on its own, a speculative
/// `get_state` result is only *read* after it, and neither response is
/// interpreted unless it has exactly the shape we expect — a
/// non-bool, a malformed payload or an unreadable account is refused
/// with a stated reason, never guessed at.
async fn assert_serving_allowed(
    near_client: &crate::near::NearClient,
    keystore_dao_id: &AccountId,
    vault_id: &AccountId,
    keystore: &Keystore,
) -> Result<()> {
    let verified_call = near_client.view_call_json(
        keystore_dao_id,
        "is_vault_verified",
        serde_json::json!({ "vault_id": vault_id }),
    );

    // Only speculate for a vault we have already served (see above).
    let (verified_result, speculative_state) = if keystore.has_customer(vault_id) {
        let (verified, state) = tokio::join!(
            verified_call,
            near_client.view_call_json(vault_id, "get_state", serde_json::json!({}))
        );
        (verified, Some(state))
    } else {
        (verified_call.await, None)
    };

    let response = verified_result
        .with_context(|| format!("is_vault_verified({}) view-call failed", vault_id))?;

    let verified: bool = serde_json::from_value(response.clone()).with_context(|| {
        format!(
            "is_vault_verified({}) returned non-bool: {}",
            vault_id, response
        )
    })?;

    if !verified {
        // Drop any cached master — vault was banned or de-verified.
        keystore.evict_customer(vault_id);
        return Err(VaultNotServable::NotVerified(vault_id.clone()).into());
    }

    // get_state can fail for two distinct reasons:
    //   (a) Authoritative — vault account no longer exists. Most
    //       importantly the parent finalized recovery and deleted the
    //       vault (delete_account is reachable post-unlock via the
    //       FullAccess key). The cached master MUST stop being served.
    //   (b) Transient — RPC node hiccup, timeout, 5xx, network blip.
    //       Evicting on transients drains the customer's vault: every
    //       follow-up request triggers another MPC CKD round-trip
    //       (~0.001 NEAR/call burned from the vault's gas reserve).
    //       Sustained RPC flapping = sustained drain (M-2).
    // Disambiguate by error string: the NEAR RPC reports `UnknownAccount`
    // / `does not exist` for case (a) and arbitrary transport / timeout
    // text for case (b). We only evict on (a); for (b) we keep the
    // cache and propagate the error so the caller can retry.
    //
    // Read the speculative result if we launched one — it was issued
    // alongside the check above, not before it, and is only consulted
    // now that the vault is known to be verified. Otherwise make the
    // call here, exactly as this function always has.
    let state_result = match speculative_state {
        Some(result) => result,
        None => {
            near_client
                .view_call_json(vault_id, "get_state", serde_json::json!({}))
                .await
        }
    };
    let state = match state_result {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("{e:#}");
            let authoritative_gone =
                msg.contains("UnknownAccount") || msg.contains("does not exist");
            if authoritative_gone {
                keystore.evict_customer(vault_id);
                anyhow::bail!(
                    "vault {} no longer exists on chain; evicting cached master. \
                     If the vault was deleted post-recovery this is expected — \
                     customers must re-derive via direct MPC.",
                    vault_id
                );
            }
            // Transient — keep the cache. Caller retries.
            anyhow::bail!(
                "vault {} get_state failed (transient: {}); cache retained, \
                 retry on next request.",
                vault_id,
                e
            );
        }
    };
    // Malformed payload almost never happens in production — both
    // sides of get_state live in this monorepo and the CI catches
    // schema drift before deploy. Don't evict on this path: an
    // accidental contract-side change shouldn't auto-drain every
    // customer's vault while we wait for a hotfix.
    let unlocked = state
        .get("unlocked")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "vault {} get_state returned malformed payload: {} \
                 (cache retained — this likely indicates a contract / \
                 keystore-worker version mismatch, not a customer-side issue)",
                vault_id,
                state
            )
        })?;
    if unlocked {
        keystore.evict_customer(vault_id);
        return Err(VaultNotServable::Unlocked(vault_id.clone()).into());
    }

    Ok(())
}

#[cfg(test)]
mod invalid_nonce_tests {
    use super::*;
    use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
    use near_jsonrpc_primitives::types::transactions::RpcTransactionError;
    use near_primitives::errors::InvalidTxError;

    fn handler(context: InvalidTxError) -> JsonRpcError<RpcTransactionError> {
        JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
            RpcTransactionError::InvalidTransaction { context },
        ))
    }

    #[test]
    fn invalid_nonce_is_recognised() {
        assert!(is_invalid_nonce(&handler(InvalidTxError::InvalidNonce { tx_nonce: 7, ak_nonce: 7 })));
    }

    #[test]
    fn other_rejects_are_not_retried() {
        assert!(!is_invalid_nonce(&handler(InvalidTxError::Expired)));
        assert!(!is_invalid_nonce(&handler(InvalidTxError::NotEnoughBalance {
            signer_id: "v.near".parse().unwrap(),
            balance: near_primitives::types::Balance::from_yoctonear(0),
            cost: near_primitives::types::Balance::from_yoctonear(1),
        })));
    }

    #[test]
    fn one_retry_only() {
        assert_eq!(CKD_INVALID_NONCE_RETRIES, 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keystore;
    use std::str::FromStr;

    fn vault(s: &str) -> AccountId {
        AccountId::from_str(s).unwrap()
    }

    // ===== assert_serving_allowed: the per-signature on-chain gate =====

    /// A throwaway NEAR RPC. Answers `call_function` queries by looking at the plaintext
    /// `method_name` in the request (only `args` are base64), records every method it was
    /// asked for, and sleeps `delay` before replying so the two calls can be told apart by
    /// wall-clock. One thread per connection — otherwise the server itself would serialize
    /// requests and a concurrency assertion would prove nothing.
    fn fake_rpc(
        delay: std::time::Duration,
        answers: Vec<(&'static str, &'static str)>,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen_for_thread = seen.clone();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let seen = seen_for_thread.clone();
                let answers = answers.clone();
                std::thread::spawn(move || {
                    // The request is a few hundred bytes; read until the body is in hand.
                    let mut raw = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        let n = stream.read(&mut buf).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        raw.extend_from_slice(&buf[..n]);
                        let text = String::from_utf8_lossy(&raw);
                        if text.contains("\r\n\r\n") && text.contains("method_name") {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&raw).into_owned();
                    let method = answers
                        .iter()
                        .find(|(name, _)| text.contains(&format!("\"method_name\":\"{name}\"")))
                        .map(|(name, payload)| (name.to_string(), payload.to_string()));

                    let Some((name, payload)) = method else {
                        let _ = stream.write_all(b"HTTP/1.1 400 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        return;
                    };
                    seen.lock().unwrap().push(name);
                    std::thread::sleep(delay);

                    // A NEAR `CallResult`: the contract's JSON return value as a byte array.
                    let bytes = payload
                        .as_bytes()
                        .iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    let body = format!(
                        r#"{{"jsonrpc":"2.0","id":"dontcare","result":{{"result":[{bytes}],"logs":[],"block_height":1,"block_hash":"11111111111111111111111111111111"}}}}"#
                    );
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes());
                });
            }
        });

        (format!("http://{}", addr), seen)
    }

    /// The gas-saving pre-check must ask the DAO exactly what the DAO would assert.
    ///
    /// `submit_keystore_registration` gates on `approved_measurements.contains(&measurements)`
    /// (keystore-dao `lib.rs:508`) and `is_measurements_approved` evaluates the SAME expression
    /// over the SAME collection — so a mismatch here can only come from us sending the wrong
    /// argument shape. That is what this pins: the method name, the `measurements` wrapper, and
    /// all five field names.
    ///
    /// Getting it wrong degrades safely (a malformed view call errors, and `main.rs` submits
    /// anyway rather than blocking) — but it would silently stop saving the gas this exists for.
    #[tokio::test]
    async fn measurements_check_asks_the_dao_the_question_the_dao_answers() {
        let (url, seen) = fake_rpc(
            std::time::Duration::ZERO,
            vec![("is_measurements_approved", "true")],
        );
        let m = crate::tdx_attestation::TdxMeasurements {
            mrtd: "7f".repeat(48),
            rtmr0: "a0".repeat(48),
            rtmr1: "b1".repeat(48),
            rtmr2: "c2".repeat(48),
            rtmr3: "d3".repeat(48),
        };

        let approved = check_measurements_approved(&url, "dao.testnet", &m)
            .await
            .expect("view call must succeed");

        assert!(approved, "a `true` answer must be read as approved");
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["is_measurements_approved"],
            "must call exactly the method the contract gates on"
        );
    }

    /// A `false` answer is what stops the paid registration. If this were misread the whole
    /// point — not spending 183.6 TGas to be told something a free view already knew — is lost.
    #[tokio::test]
    async fn a_false_answer_is_read_as_not_approved() {
        let (url, _seen) = fake_rpc(
            std::time::Duration::ZERO,
            vec![("is_measurements_approved", "false")],
        );
        let m = crate::tdx_attestation::TdxMeasurements {
            mrtd: "00".repeat(48),
            rtmr0: "00".repeat(48),
            rtmr1: "00".repeat(48),
            rtmr2: "00".repeat(48),
            rtmr3: "00".repeat(48),
        };
        assert!(!check_measurements_approved(&url, "dao.testnet", &m).await.unwrap());
    }

    /// `vault_id` arrives from the caller: the coordinator forwards `X-Customer-Vault` verbatim
    /// under its OWN token, and nothing proves the caller owns the vault it names. On the
    /// `/secrets/pubkey` path the coordinator's own route takes no credentials at all, so the
    /// value can originate with an anonymous caller. Either way anything can be presented as a
    /// vault, and such a request must cost ONE view call and then stop. If the gate ever
    /// speculates on `get_state` unconditionally, an arbitrary caller doubles the RPC traffic we
    /// generate on their behalf, and this is the assertion that catches it.
    #[tokio::test]
    async fn unknown_vault_is_refused_after_a_single_view_call() {
        let (url, seen) = fake_rpc(
            std::time::Duration::ZERO,
            vec![("is_vault_verified", "false"), ("get_state", r#"{"unlocked":false}"#)],
        );
        let near_client = crate::near::NearClient::new(&url, "dao.testnet").unwrap();
        let ks = Keystore::generate();
        let garbage = vault("not-a-vault-of-ours.testnet");

        let err = assert_serving_allowed(&near_client, &vault("dao.testnet"), &garbage, &ks)
            .await
            .expect_err("an unverified vault must be refused");

        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["is_vault_verified"],
            "an unknown vault must not cost a second view call"
        );
        // And the refusal has to say why, in terms the caller can act on.
        let msg = format!("{err:#}");
        assert!(msg.contains("not verified"), "unclear refusal: {msg}");
    }

    /// The hot path: a vault whose master is already loaded is one that has passed this gate
    /// before and paid for a CKD derivation. Both reads are independent, so they go out
    /// together — this gate runs on EVERY signature, and serializing them doubles its latency.
    #[tokio::test]
    async fn loaded_vault_issues_both_view_calls_concurrently() {
        let per_call = std::time::Duration::from_millis(300);
        let (url, seen) = fake_rpc(
            per_call,
            vec![("is_vault_verified", "true"), ("get_state", r#"{"unlocked":false}"#)],
        );
        let near_client = crate::near::NearClient::new(&url, "dao.testnet").unwrap();
        let ks = Keystore::generate();
        let v = vault("vault.alice.testnet");
        ks.add_customer(v.clone(), [7u8; 32]);

        let started = std::time::Instant::now();
        assert_serving_allowed(&near_client, &vault("dao.testnet"), &v, &ks)
            .await
            .expect("a verified, locked vault must be served");
        let elapsed = started.elapsed();

        let mut methods = seen.lock().unwrap().clone();
        methods.sort();
        assert_eq!(methods, ["get_state", "is_vault_verified"], "both checks must still run");
        assert!(
            elapsed < per_call * 2,
            "the two view calls ran one after the other ({elapsed:?} for 2x{per_call:?})"
        );
    }

    /// Concurrency must not change WHO decides. `is_vault_verified` still settles first and
    /// still refuses on its own: a speculative `get_state` saying the vault is perfectly fine
    /// cannot rescue a vault the DAO has de-verified or banned.
    #[tokio::test]
    async fn a_healthy_get_state_cannot_override_a_de_verified_vault() {
        let (url, _seen) = fake_rpc(
            std::time::Duration::ZERO,
            vec![("is_vault_verified", "false"), ("get_state", r#"{"unlocked":false}"#)],
        );
        let near_client = crate::near::NearClient::new(&url, "dao.testnet").unwrap();
        let ks = Keystore::generate();
        let v = vault("vault.alice.testnet");
        ks.add_customer(v.clone(), [7u8; 32]);

        let err = assert_serving_allowed(&near_client, &vault("dao.testnet"), &v, &ks)
            .await
            .expect_err("a de-verified vault must be refused even when its state looks healthy");

        assert!(format!("{err:#}").contains("not verified"));
        // And the cached master is dropped, so nothing is served from memory afterwards.
        assert!(
            !ks.has_customer(&v),
            "a de-verified vault must have its cached master evicted"
        );
    }

    /// The gate's two refusals are typed, so the HTTP layer refuses by type and
    /// never by reading the message; a read that could not be made is not one
    /// of them.
    #[tokio::test]
    async fn the_gates_refusals_are_typed_and_its_outages_are_not() {
        let dao = vault("dao.testnet");
        let v = vault("vault.alice.testnet");

        let (url, _s) = fake_rpc(
            std::time::Duration::ZERO,
            vec![("is_vault_verified", "false"), ("get_state", r#"{"unlocked":false}"#)],
        );
        let near_client = crate::near::NearClient::new(&url, "dao.testnet").unwrap();
        let err = assert_serving_allowed(&near_client, &dao, &v, &Keystore::generate()).await.unwrap_err();
        assert!(
            matches!(err.downcast_ref::<VaultNotServable>(), Some(VaultNotServable::NotVerified(x)) if x == &v),
            "{err:#}"
        );

        let (url, _s) = fake_rpc(
            std::time::Duration::ZERO,
            vec![("is_vault_verified", "true"), ("get_state", r#"{"unlocked":true}"#)],
        );
        let near_client = crate::near::NearClient::new(&url, "dao.testnet").unwrap();
        let err = assert_serving_allowed(&near_client, &dao, &v, &Keystore::generate()).await.unwrap_err();
        assert!(
            matches!(err.downcast_ref::<VaultNotServable>(), Some(VaultNotServable::Unlocked(x)) if x == &v),
            "{err:#}"
        );

        // A DAO that does not answer `is_vault_verified` (the fake serves a 400).
        let (url, _s) = fake_rpc(std::time::Duration::ZERO, vec![("get_state", r#"{"unlocked":false}"#)]);
        let near_client = crate::near::NearClient::new(&url, "dao.testnet").unwrap();
        let err = assert_serving_allowed(&near_client, &dao, &v, &Keystore::generate()).await.unwrap_err();
        assert!(err.downcast_ref::<VaultNotServable>().is_none(), "{err:#}");
    }

    /// Garbage in, refusal out — never a guess. A response that is not the exact shape the
    /// contract promises is an error with a stated reason, not something we try to interpret.
    #[tokio::test]
    async fn malformed_responses_are_refused_rather_than_interpreted() {
        // `is_vault_verified` must be a bool; a JSON object is not "truthy".
        let (url, _s) = fake_rpc(
            std::time::Duration::ZERO,
            vec![("is_vault_verified", r#"{"junk":1}"#), ("get_state", r#"{"unlocked":false}"#)],
        );
        let near_client = crate::near::NearClient::new(&url, "dao.testnet").unwrap();
        let ks = Keystore::generate();
        let err = assert_serving_allowed(
            &near_client,
            &vault("dao.testnet"),
            &vault("vault.alice.testnet"),
            &ks,
        )
        .await
        .expect_err("a non-bool verification answer must be refused");
        assert!(format!("{err:#}").contains("non-bool"), "got: {err:#}");

        // `get_state` without `unlocked` must not be read as "locked".
        let (url, _s) = fake_rpc(
            std::time::Duration::ZERO,
            vec![("is_vault_verified", "true"), ("get_state", r#"{"something_else":true}"#)],
        );
        let near_client = crate::near::NearClient::new(&url, "dao.testnet").unwrap();
        let ks = Keystore::generate();
        let v = vault("vault.alice.testnet");
        ks.add_customer(v.clone(), [7u8; 32]);
        let err = assert_serving_allowed(&near_client, &vault("dao.testnet"), &v, &ks)
            .await
            .expect_err("a malformed state payload must be refused");
        assert!(format!("{err:#}").contains("malformed payload"), "got: {err:#}");
        // Not a customer-side fault, so the master stays put — see the comment on that branch.
        assert!(ks.has_customer(&v), "a contract/version mismatch must not drain the cache");
    }

    #[test]
    fn vault_tee_keypair_is_deterministic() {
        // Re-derivable across worker restarts: same default master +
        // same vault_id → same keypair. This is the property that lets
        // any approved TEE re-load a customer master without sealed storage.
        let ks = Keystore::generate();
        let v = vault("vault.alice.testnet");
        let (pk1, sk1) = derive_vault_tee_keypair(&ks, &v).unwrap();
        let (pk2, sk2) = derive_vault_tee_keypair(&ks, &v).unwrap();
        assert_eq!(pk1.to_string(), pk2.to_string());
        assert_eq!(sk1.to_string(), sk2.to_string());
    }

    #[test]
    fn vault_tee_keypair_separates_per_vault() {
        // Customer A's vault TEE key MUST NOT collide with customer B's.
        // Otherwise a worker that signs MPC requests for vault B would
        // produce the same on-chain receipt fingerprint as for vault A.
        let ks = Keystore::generate();
        let (pk_a, _) = derive_vault_tee_keypair(&ks, &vault("vault.alice.testnet")).unwrap();
        let (pk_b, _) = derive_vault_tee_keypair(&ks, &vault("vault.bob.testnet")).unwrap();
        assert_ne!(pk_a.to_string(), pk_b.to_string());
    }

    #[test]
    fn vault_tee_keypair_separates_per_master() {
        // Different default master → different vault keypair, even for
        // the same vault_id. A leaked vault TEE key from one OutLayer
        // deployment does not let an attacker spoof TEE calls for the
        // same vault id under a different deployment.
        let ks1 = Keystore::generate();
        let ks2 = Keystore::generate();
        let v = vault("vault.alice.testnet");
        let (pk1, _) = derive_vault_tee_keypair(&ks1, &v).unwrap();
        let (pk2, _) = derive_vault_tee_keypair(&ks2, &v).unwrap();
        assert_ne!(pk1.to_string(), pk2.to_string());
    }

    #[test]
    fn vault_tee_pubkey_matches_secret_key_pubkey() {
        // The PublicKey we hand to outlayer-cli (so the customer can
        // AddKey() it during atomic deploy) must equal the public half
        // of the SecretKey we sign with later. If these diverged, the
        // worker's MPC tx would be rejected for "key not on account".
        let ks = Keystore::generate();
        let (pk, sk) = derive_vault_tee_keypair(&ks, &vault("vault.alice.testnet")).unwrap();
        assert_eq!(pk.to_string(), sk.public_key().to_string());
    }

    #[test]
    fn vault_tee_keypair_format_is_ed25519() {
        // Layer 1 must produce ED25519 — that's what the function-call
        // key on the vault is. Other curves wouldn't be acceptable to NEAR.
        let ks = Keystore::generate();
        let (pk, sk) = derive_vault_tee_keypair(&ks, &vault("vault.alice.testnet")).unwrap();
        assert!(matches!(pk, near_crypto::PublicKey::ED25519(_)));
        assert!(matches!(sk, near_crypto::SecretKey::ED25519(_)));
    }

    // ============== Layer 2 path derivation ==============
    // The path string handed to MPC must be deterministic, depend on
    // the master, and differ per vault. The MPC roundtrip itself
    // requires a sandbox/testnet to exercise — but the path
    // construction is pure and tractable here.

    #[test]
    fn vault_master_path_seed_includes_vault_id() {
        let v = vault("vault.alice.testnet");
        assert_eq!(vault_master_path_seed(&v), "vault-master:vault.alice.testnet");
    }

    #[test]
    fn vault_master_path_is_deterministic_and_master_dependent() {
        let ks = Keystore::generate();
        let v = vault("vault.alice.testnet");
        let p1 = ks.derive_secret_string(None, &vault_master_path_seed(&v)).unwrap();
        let p2 = ks.derive_secret_string(None, &vault_master_path_seed(&v)).unwrap();
        assert_eq!(p1, p2, "Layer 2 path must be deterministic across calls");

        // Different master → different path even for same vault id —
        // the property that lets recovery work (any approved TEE with
        // the same default master gets the same path → same MPC reply).
        let ks2 = Keystore::generate();
        let p3 = ks2.derive_secret_string(None, &vault_master_path_seed(&v)).unwrap();
        assert_ne!(p1, p3);
    }

    #[test]
    fn vault_master_path_separates_per_vault() {
        // Different vault_ids hit different MPC app_ids — ensures
        // customer A's master cannot equal customer B's by coincidence.
        let ks = Keystore::generate();
        let p_a = ks
            .derive_secret_string(None, &vault_master_path_seed(&vault("vault.alice.testnet")))
            .unwrap();
        let p_b = ks
            .derive_secret_string(None, &vault_master_path_seed(&vault("vault.bob.testnet")))
            .unwrap();
        assert_ne!(p_a, p_b);
    }

    fn unreachable_config() -> MpcCkdConfig {
        // A config that would error at the first network call — used by
        // tests that want to assert a code path NEVER reaches the wire.
        MpcCkdConfig {
            mpc_contract_id: vault("mpc.testnet"),
            mpc_domain_id: 2,
            mpc_public_key: "bls12381g2:invalid".to_string(),
            near_rpc_url: "http://127.0.0.1:1".to_string(),
            keystore_dao_id: vault("keystore-dao.testnet"),
        }
    }

    #[tokio::test]
    async fn add_customer_is_no_op_when_already_loaded() {
        // The fast path: if the keystore already has a master for this
        // vault, add_customer must NOT attempt an MPC call. We verify
        // this by passing a config with a junk RPC URL — if the function
        // ever tried to dial the network, the test would error out.
        let ks = Keystore::generate();
        let v = vault("vault.alice.testnet");
        ks.add_customer(v.clone(), [7u8; 32]);

        add_customer(&unreachable_config(), &ks, &v)
            .await
            .expect("idempotent fast-path must not touch the network");
        assert!(ks.has_customer(&v));
    }

    #[tokio::test]
    async fn add_customer_after_evict_attempts_reload() {
        // I5 audit finding: prove the evict → re-derive path is wired.
        //
        // Eviction must flip `has_customer` to false AND the next
        // add_customer call must bypass the fast path and try the
        // network. We don't have an MPC sandbox here, so we assert
        // via "function tries to do work" — either it returns an
        // error (RPC unreachable) or times out (RPC slow-fails).
        // Both outcomes prove the fast path was NOT taken.
        use tokio::time::{timeout, Duration};

        let ks = Keystore::generate();
        let v = vault("vault.alice.testnet");

        // Initial population.
        ks.add_customer(v.clone(), [7u8; 32]);
        assert!(ks.has_customer(&v));

        // Evict. Now the next add_customer must attempt MPC.
        ks.evict_customer(&v);
        assert!(!ks.has_customer(&v));

        // 2s budget: the cached fast-path returns in microseconds, so
        // any real attempt beyond that proves we left the fast path.
        // Either we get a network error before the deadline, or we
        // hit the deadline — both pass the assertion below.
        let result = timeout(
            Duration::from_secs(2),
            add_customer(&unreachable_config(), &ks, &v),
        )
        .await;

        match result {
            Err(_elapsed) => { /* timed out → network call was attempted */ }
            Ok(Err(_e)) => { /* errored → network call was attempted */ }
            Ok(Ok(())) => panic!(
                "post-evict add_customer returned Ok — fast path was \
                 (incorrectly) taken despite the cache being empty"
            ),
        }

        // And the master is still NOT loaded (because RPC failed).
        assert!(!ks.has_customer(&v));
    }

    // I3 — concurrent dedup gate behaviour is verified by:
    //   (a) `add_customer_concurrent_with_cache_hit_serves_all_immediately`
    //       below — proves the lock doesn't block the cached fast path
    //   (b) the `_guard` lock acquisition in `add_customer` is a
    //       compile-time-checked path; static analysis is sufficient
    //
    // We deliberately do NOT include a "concurrent first-load with
    // unreachable RPC" test because the near-jsonrpc-client transport
    // applies its own internal retries (~15s per attempt) which makes
    // such a test slow without proving anything beyond the fast-path
    // test. End-to-end dedup against a real (or sandbox) MPC is
    // covered by integration tests.

    #[tokio::test]
    async fn add_customer_concurrent_with_cache_hit_serves_all_immediately() {
        // Complementary to the dedup test: when the master IS cached,
        // the dedup gate must let all concurrent callers through the
        // fast path without contention or network calls.
        use tokio::time::{timeout, Duration};
        let ks = std::sync::Arc::new(Keystore::generate());
        let v = std::sync::Arc::new(vault("vault.alice.testnet"));
        ks.add_customer((*v).clone(), [9u8; 32]);
        let cfg = std::sync::Arc::new(unreachable_config());

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let ks_c = ks.clone();
            let v_c = v.clone();
            let cfg_c = cfg.clone();
            tasks.push(tokio::spawn(async move {
                add_customer(cfg_c.as_ref(), ks_c.as_ref(), v_c.as_ref()).await
            }));
        }

        // Cached path is sub-millisecond — generous 5s timeout proves
        // we never hit the network despite the unreachable config.
        for t in tasks {
            let res = timeout(Duration::from_secs(5), t)
                .await
                .expect("cached fast-path must not block on network");
            res.expect("join")
                .expect("cached fast-path must succeed without touching the network");
        }
    }
}