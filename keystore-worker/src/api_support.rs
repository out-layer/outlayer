use super::*;

/// Secret accessor type - matches contract's SecretAccessor enum
///
/// IMPORTANT: When adding new accessor types:
/// 1. Add variant here in keystore-worker
/// 2. Add variant in coordinator/src/handlers/github.rs (SecretAccessor enum)
/// 3. Add variant in contract/src/lib.rs (SecretAccessor enum)
/// 4. Update seed generation in `decrypt_handler` (`api.rs`)
/// 5. Update near.rs get_secrets methods if needed
/// 6. Update worker/src/keystore_client.rs decrypt methods
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SecretAccessor {
    /// Secrets bound to a GitHub repository
    Repo {
        repo: String,
        #[serde(default)]
        branch: Option<String>,
    },
    /// Secrets bound to a specific WASM hash
    WasmHash {
        hash: String,
    },
    /// Secrets bound to a project (available to all versions)
    Project {
        project_id: String,
    },
    /// System secrets (Payment Keys for HTTPS API)
    System {
        secret_type: SystemSecretType,
    },
}

/// System secret types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemSecretType {
    /// Payment Key for HTTPS API
    PaymentKey,
}

impl SystemSecretType {
    /// Contract-side representation (CamelCase, matches NEAR's default
    /// JSON serialisation of the contract's `SystemSecretType` enum
    /// variants). Used by `accessor_to_contract_json` when forwarding
    /// the variant to a contract view method. **Centralised here so a
    /// future variant addition is one match arm**, not five scattered
    /// call sites.
    pub(super) fn as_contract_str(&self) -> &'static str {
        match self {
            SystemSecretType::PaymentKey => "PaymentKey",
        }
    }

    /// Seed-string representation (snake_case, matches the seed
    /// convention used at write time by all storage paths). Used inside
    /// derived secret seeds for decrypt/encrypt of System secrets.
    pub(super) fn as_seed_str(&self) -> &'static str {
        match self {
            SystemSecretType::PaymentKey => "payment_key",
        }
    }
}

/// Request to decrypt secrets from contract
#[derive(Debug, Deserialize)]
pub struct DecryptRequest {
    /// What code can access these secrets
    pub accessor: SecretAccessor,

    /// Profile name (e.g., "default", "production")
    pub profile: String,

    /// Owner account ID (who owns the secrets)
    pub owner: String,

    /// User account ID (who is requesting execution)
    /// This is used for access control validation
    pub user_account_id: String,

    /// Optional task ID for logging
    pub task_id: Option<String>,

    /// SHA-256 of the WebAssembly bytes the worker is about to run, measured
    /// by the worker on the buffer it loaded. What a `WasmHash` access
    /// condition is judged against. Absent on a request from a worker that
    /// predates it, which leaves such a condition UNKNOWN: refused, unless some
    /// other branch of the tree admits on its own.
    #[serde(default)]
    pub executed_wasm_sha256: Option<String>,

    /// The account that called the contract: on chain the receipt's
    /// predecessor, as the contract's own event names it; over HTTPS the
    /// payer, since no contract relays that call. What a `Predecessor`
    /// access condition is judged against. Absent on a request from a
    /// worker that predates it, which leaves such a condition UNKNOWN:
    /// refused, unless some other branch of the tree admits on its own.
    #[serde(default)]
    pub predecessor_id: Option<String>,
}

/// Response with decrypted secrets
#[derive(Debug, Serialize)]
pub struct DecryptResponse {
    /// Decrypted secrets (base64 encoded)
    /// Base64 is used to safely transport binary data over JSON
    pub plaintext_secrets: String,
}

/// A `/decrypt` request that names declared keys: the job's secret row, if it
/// has one, and the signing and encryption keys its artefact declares,
/// answered together.
///
/// Only a request whose body carries a `signing_keys` or `encryption_keys`
/// member (other than `null` or `[]`) is read as this; every other request is
/// a [`DecryptRequest`] and is answered exactly as it always was. Here too a
/// `null` list is an empty one, so the other family may be `null`. `accessor` +
/// `profile` + `owner` name one secret row, all three or none; at least one of
/// the two key lists must be non-empty. The two lists are two namespaces: the
/// same path may appear in both, and names two unrelated keys.
#[derive(Debug, Deserialize)]
pub struct KeyedDecryptRequest {
    #[serde(default)]
    pub accessor: Option<SecretAccessor>,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,

    /// Who requested execution: the account a secret's access condition is
    /// judged for, and the account every `signer` key is bound to.
    pub user_account_id: String,
    pub task_id: Option<String>,

    /// SHA-256 of the bytes the worker is about to run. Required: a
    /// `wasm`-bound key is derived from it, and for a project run it must be a
    /// version of `project_id` on the contract.
    #[serde(default)]
    pub executed_wasm_sha256: Option<String>,

    /// As in [`DecryptRequest`]: what a `Predecessor` condition is judged against.
    #[serde(default)]
    pub predecessor_id: Option<String>,

    /// The project the job runs, as the worker read it off the job the
    /// coordinator gave it. Present: a project run, which holds `project` keys
    /// only, and whose build must be a WasmUrl version of this project on the
    /// contract. Absent: a direct run of a wasm URL, which holds `wasm` keys
    /// only. A `project` key is bound to the project's on-chain uuid, read
    /// through `get_project(project_id)`.
    #[serde(default)]
    pub project_id: Option<String>,

    /// The signing keys the running artefact's manifest declares. `null` is
    /// no keys, as an absent member is.
    #[serde(default, deserialize_with = "null_as_no_keys")]
    pub signing_keys: Vec<crate::signing_keys::SigningKeyRequest>,

    /// The encryption keys the running artefact's manifest declares. `null` is
    /// no keys, as an absent member is.
    #[serde(default, deserialize_with = "null_as_no_keys")]
    pub encryption_keys: Vec<crate::encryption_keys::EncryptionKeyRequest>,
}

/// A key list read as the dispatch probe reads it: `null` names no keys.
fn null_as_no_keys<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// The answer to a [`KeyedDecryptRequest`]: independent parts.
///
/// `signing_keys` is present exactly when the request named signing keys, and
/// `encryption_keys` exactly when it named encryption keys — so the answer to
/// a request naming signing keys alone is the answer it always was. A request
/// whose keys cannot be served is refused whole, with the
/// `signing_keys_refused` code, and nothing else is returned. `secrets` is
/// present exactly when the request named a secret row.
#[derive(Debug, Serialize)]
pub struct KeyedDecryptResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsOutcome>,
    /// One 32-byte signing-key seed per requested key, hex, by key path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_keys: Option<std::collections::BTreeMap<String, crate::signing_keys::SeedHex>>,
    /// One 32-byte encryption key per requested encryption key, hex, by key
    /// path. The key has no type: the worker's host picks the algorithm that
    /// uses it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_keys: Option<std::collections::BTreeMap<String, crate::signing_keys::SeedHex>>,
}

/// What became of the secret row a keyed request named.
///
/// A row that does not exist — the outcome a [`DecryptRequest`] answers with
/// `ApiError::SecretsNotFound`, the one 400 the worker runs on past — is
/// reported here rather than failing the request, so the keys still arrive.
/// Every other failure of the row fails the request, with the same status and
/// message a [`DecryptRequest`] gets.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SecretsOutcome {
    /// Decrypted secrets, base64 — as `plaintext_secrets` in [`DecryptResponse`].
    Decrypted { plaintext_secrets: String },
    /// No secret to decrypt; the keystore's reason.
    NotFound { error: String },
}

/// Request to get public key (includes secrets for validation)
#[derive(Debug, Deserialize)]
pub struct PubkeyRequest {
    /// Seed for deriving keypair (format: "repo:owner[:branch]")
    pub seed: String,
    /// Secrets as JSON string for validation (e.g., '{"API_KEY":"value"}')
    pub secrets_json: String,
    /// Optional vault id: when set, the returned pubkey is
    /// derived from the per-vault master so the resulting on-chain
    /// secret is encrypted under the correct customer scope. Absent
    /// (or null/empty) ⇒ default OutLayer master, legacy behaviour.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Response with public key
#[derive(Debug, Serialize)]
pub struct PubkeyResponse {
    /// Public key in hex format
    pub pubkey: String,
}

/// Request to add generated secrets to existing encrypted secrets
#[derive(Debug, Deserialize)]
pub struct AddGeneratedSecretRequest {
    /// Seed for deriving keypair (format: "repo:owner[:branch]")
    pub seed: String,

    /// Existing encrypted secrets (base64, can be empty for first generation)
    /// If empty, starts with empty secrets object
    pub encrypted_secrets_base64: Option<String>,

    /// New secrets to generate
    pub new_secrets: Vec<GeneratedSecretSpec>,

    /// Optional vault id: scope the encrypt/decrypt calls to a
    /// per-vault master. MUST match the scope under which
    /// `encrypted_secrets_base64` was originally encrypted, otherwise
    /// the decrypt step will fail. Absent ⇒ default OutLayer master.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Specification for a secret to generate
#[derive(Debug, Deserialize)]
pub struct GeneratedSecretSpec {
    /// Secret name (key in JSON)
    pub name: String,

    /// Generation type (hex32, ed25519, password, etc.)
    pub generation_type: String,
}

/// Response after adding generated secrets
#[derive(Debug, Serialize)]
pub struct AddGeneratedSecretResponse {
    /// Updated encrypted secrets (base64)
    pub encrypted_data_base64: String,

    /// List of ALL secret key names after merge (for verification)
    pub all_keys: Vec<String>,
}

/// Mode for updating user secrets
#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateMode {
    /// Add/update secrets, keeping existing ones
    Append,
    /// Replace all non-PROTECTED secrets
    Reset,
}

/// Request to update user secrets (with NEAR signature)
#[derive(Debug, Deserialize)]
pub struct UpdateUserSecretsRequest {
    /// Current accessor for the secrets
    pub accessor: SecretAccessor,

    /// Optional new accessor (for migration)
    pub new_accessor: Option<SecretAccessor>,

    /// Profile name
    pub profile: String,

    /// Owner account ID
    pub owner: String,

    /// Update mode
    pub mode: UpdateMode,

    /// User secrets to add/update (cannot contain PROTECTED_ prefix)
    /// Values can be strings, numbers, booleans, or null - preserved as-is
    pub secrets: std::collections::HashMap<String, serde_json::Value>,

    /// Optional PROTECTED_ secrets to generate
    pub generate_protected: Option<Vec<GeneratedSecretSpec>>,

    /// Signed message (format: "Update Outlayer secrets for owner:profile")
    pub signed_message: String,

    /// Ed25519 signature
    pub signature: String,

    /// Public key (ed25519:base58...)
    pub public_key: String,

    /// Nonce for NEP-413
    pub nonce: String,

    /// Recipient for NEP-413 signature verification
    pub recipient: String,

    /// Optional vault id: scope the encrypt/decrypt calls to
    /// a per-vault master. MUST match the scope under which the existing
    /// secrets were encrypted (when in Append mode reading current
    /// state). Absent ⇒ default OutLayer master.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Response after updating user secrets
#[derive(Debug, Serialize)]
pub struct UpdateUserSecretsResponse {
    /// Updated encrypted secrets (base64) for storing in contract
    pub encrypted_secrets_base64: String,

    /// Summary of changes
    pub summary: UpdateSummary,
}

#[derive(Debug, Serialize)]
pub struct UpdateSummary {
    /// PROTECTED_ keys that were preserved
    pub protected_keys_preserved: Vec<String>,

    /// Keys that were updated/added
    pub updated_keys: Vec<String>,

    /// Keys that were removed (only in reset mode)
    pub removed_keys: Vec<String>,

    /// Total number of secrets after update
    pub total_keys: usize,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub tee_mode: String,
}

// ==================== Storage Encryption API ====================

/// Request to encrypt data for persistent storage
#[derive(Debug, Deserialize)]
pub struct StorageEncryptRequest {
    /// Project UUID (None for standalone WASM - use wasm_hash instead)
    pub project_uuid: Option<String>,
    /// WASM hash (used when project_uuid is None)
    pub wasm_hash: String,
    /// Account ID (user account or "@worker" for private storage)
    pub account_id: String,
    /// Plaintext key (will be encrypted)
    pub key: String,
    /// Plaintext value (base64 encoded)
    pub value_base64: String,
}

/// Response with encrypted storage data
#[derive(Debug, Serialize)]
pub struct StorageEncryptResponse {
    /// Encrypted key (base64)
    pub encrypted_key_base64: String,
    /// Encrypted value (base64)
    pub encrypted_value_base64: String,
    /// Key hash for unique constraint (SHA256 of plaintext key)
    pub key_hash: String,
}

/// Request to decrypt data from persistent storage
#[derive(Debug, Deserialize)]
pub struct StorageDecryptRequest {
    /// Project UUID (None for standalone WASM - use wasm_hash instead)
    pub project_uuid: Option<String>,
    /// WASM hash (used when project_uuid is None)
    pub wasm_hash: String,
    /// Account ID (user account or "@worker" for private storage)
    pub account_id: String,
    /// Encrypted key (base64)
    pub encrypted_key_base64: String,
    /// Encrypted value (base64)
    pub encrypted_value_base64: String,
}

/// Response with decrypted storage data
#[derive(Debug, Serialize)]
pub struct StorageDecryptResponse {
    /// Decrypted key
    pub key: String,
    /// Decrypted value (base64)
    pub value_base64: String,
}

// ==================== Generic Encryption API (for TopUp flow) ====================

/// Request to generate VRF output
#[derive(Debug, Deserialize)]
pub struct VrfGenerateRequest {
    /// Alpha string (VRF pre-image). Format: "vrf:{request_id}:{user_seed}"
    pub alpha: String,
}

/// Response with VRF output and signature (proof)
#[derive(Debug, Serialize)]
pub struct VrfGenerateResponse {
    /// VRF output: SHA256(Ed25519_signature), 32 bytes hex
    pub output_hex: String,
    /// VRF proof: Ed25519 signature, 64 bytes hex
    pub signature_hex: String,
}

/// Response with VRF public key
#[derive(Debug, Serialize)]
pub struct VrfPublicKeyResponse {
    /// VRF public key (Ed25519), 32 bytes hex
    pub vrf_public_key_hex: String,
}

/// `GET /admin/loaded-vaults` response.
#[derive(Debug, Serialize)]
pub struct LoadedVaultsResponse {
    /// Vault ids whose master is in memory right now — addresses only, no key material.
    pub vaults: Vec<String>,
    /// How many of them there are.
    pub count: usize,
    /// TEE handshakes since boot — NOT live workers. Sessions are never expired (`created_at` is
    /// unread), so this only ever climbs until a restart; two workers reconnecting concurrently
    /// add two. Reported here rather than on the public `/health` so that reading it requires a
    /// token checked by real auth middleware, which also logs failures.
    pub tee_sessions: usize,
}

/// `GET /admin/loaded-vaults` — which vaults this instance has derived a master for.
///
/// Every entry cost one on-chain CKD derivation (~30 mNEAR of that vault's balance). The map
/// lives in memory only, so a restart or a version upgrade empties it and the first request per
/// vault pays again — expected, once per instance lifetime. This endpoint makes that visible:
/// after a restart it answers "who has come back", and an entry for a vault nobody expected is
/// the signal that someone probed it.
pub(super) async fn admin_loaded_vaults_handler(
    State(state): State<AppState>,
) -> Result<Json<LoadedVaultsResponse>, ApiError> {
    let vaults: Vec<String> = state
        .keystore
        .read()
        .await
        .loaded_customers()
        .into_iter()
        .map(|id| id.to_string())
        .collect();
    let tee_sessions = state.tee_sessions.lock().map(|s| s.len()).unwrap_or(0);

    Ok(Json(LoadedVaultsResponse {
        count: vaults.len(),
        vaults,
        tee_sessions,
    }))
}

/// `POST /admin/evict-customer` request body.
#[derive(Debug, Deserialize)]
pub struct AdminEvictCustomerRequest {
    /// Vault account id whose per-customer master should be dropped
    /// from cache. Must parse as `AccountId`.
    pub vault_id: String,
    /// Free-form reason logged for audit visibility (e.g.
    /// `"duplicate_mpc_call_after_init"`, `"manual_dao_ban"`). Not
    /// validated against any whitelist — operators set the
    /// convention.
    pub reason: String,
}

/// `POST /admin/evict-customer` response. `ok = true` always; the
/// endpoint is idempotent and signals no error states.
#[derive(Debug, Serialize)]
pub struct AdminEvictCustomerResponse {
    pub ok: bool,
}

/// `POST /admin/ban-vault` request body.
///
/// Called by the race-attack monitoring service when it
/// detects more than one MPC `request_app_private_key` call from the
/// same vault account within the dedup window. The keystore-worker
/// submits `keystore_dao.ban_vault(vault_id, reason)` on chain (its
/// access key on the keystore-DAO contract is approved for this
/// method) and ALSO evicts the per-customer master from cache so the
/// ban takes effect within milliseconds rather than waiting for the
/// next worker restart.
#[derive(Debug, Deserialize)]
pub struct AdminBanVaultRequest {
    pub vault_id: String,
    /// Free-form reason recorded in the on-chain `vault_banned` log
    /// event (max 256 bytes per the contract). Operators choose the
    /// convention; typical values:
    /// `"duplicate_mpc_call_after_init"`,
    /// `"manual_admin_action"`,
    /// `"phase8_monitor_alert_<id>"`.
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct AdminBanVaultResponse {
    /// Tx hash of the on-chain `ban_vault` submission. `None` if the
    /// vault is already banned (idempotent short-circuit).
    pub tx_hash: Option<String>,
    /// `true` when the keystore short-circuited because
    /// `is_vault_banned == true` already.
    pub already_banned: bool,
}

/// `POST /sign-vault-verification` request body.
///
/// Sent by the public `outlayer.near/vault-checker` WASI agent after
/// it has verified the vault state itself. The keystore-worker
/// re-runs the SAME 5 RPC checks (defense-in-depth) and only then
/// signs+broadcasts `keystore_dao.mark_vault_verified(vault_id)`.
#[derive(Debug, Deserialize)]
pub struct SignVaultVerificationRequest {
    /// Vault account id to mark as verified.
    pub vault_id: String,
}

/// `POST /sign-vault-verification` response.
///
/// * `tx_hash = Some(_)` — the worker submitted a fresh
///   `mark_vault_verified` tx; the value is the base58 NEAR tx hash.
/// * `tx_hash = None`, `already_verified = true` — the vault was
///   already verified on-chain; the worker SHORT-CIRCUITED without
///   spending gas or a nonce. Audit noteC3: spamming
///   `/sign-vault-verification` against an already-verified vault
///   would otherwise burn the worker's per-tx nonce and gas budget.
///
/// **Idempotency contract (Audit noteC1):** a 5xx
/// response from this endpoint MUST be treated as ambiguous by the
/// caller — the tx may or may not have landed. Caller MUST query
/// `keystore_dao.is_vault_verified(vault_id)` independently before
/// retrying; a retry without that check could trip a NEAR
/// `InvalidNonce` if the original tx silently committed.
#[derive(Debug, Serialize)]
pub struct SignVaultVerificationResponse {
    /// Base58-encoded tx hash of the `mark_vault_verified` call, or
    /// `None` when `already_verified = true`.
    pub tx_hash: Option<String>,
    /// `true` if the vault was already verified at request time.
    /// `false` if a fresh tx was submitted (and `tx_hash` is `Some`).
    #[serde(default)]
    pub already_verified: bool,
}

/// `POST /derive-vault-tee-key` request body.
///
/// Used by `outlayer-cli init-vault` to fetch the public
/// half of the Layer-1 TEE keypair BEFORE submitting the atomic
/// deploy that adds it as a function-call AccessKey on the new vault.
/// The keypair is HMAC-derived from the OutLayer default master with
/// seed `outlayer.near:{vault_id}` (Layer 1 of the per-vault master derivation) — deterministic,
/// re-derivable on any approved TEE, never leaves the enclave's
/// memory in private form.
#[derive(Debug, Deserialize)]
pub struct DeriveVaultTeeKeyRequest {
    pub vault_id: String,
}

/// `POST /derive-vault-tee-key` response.
///
/// Returns ONLY the public key — the private key never leaves the TEE
/// (it's used by the worker to sign Layer-2 MPC CKD calls FROM the
/// vault). The caller (CLI) embeds `public_key` in an `AddKey` action
/// inside the atomic deploy tx; afterwards anyone reading
/// `view_access_key_list(vault_id)` sees that exact pubkey, which
/// `vault-checker` and `vault_verifier.rs` then assert against.
#[derive(Debug, Serialize)]
pub struct DeriveVaultTeeKeyResponse {
    /// NEAR-format public key, e.g. `"ed25519:<base58>"`.
    pub public_key: String,
}

/// Request to encrypt plaintext data
/// Used by workers to re-encrypt secrets after TopUp
#[derive(Debug, Deserialize)]
pub struct EncryptRequest {
    /// Seed for deriving keypair (format depends on secret type)
    /// For Payment Key: "system:payment_key:{owner}:{nonce}"
    pub seed: String,
    /// Plaintext data to encrypt (base64 encoded)
    pub plaintext_base64: String,
}

/// Response with encrypted data
#[derive(Debug, Serialize)]
pub struct EncryptResponse {
    /// Encrypted data (base64)
    pub encrypted_base64: String,
}

// ==================== Wallet API ====================

/// Request to derive a wallet address for a specific chain
#[derive(Debug, Deserialize)]
pub struct WalletDeriveAddressRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Optional sub-key under the wallet's EVM key — see [`validate_sub_path`].
    /// Absent or empty: the wallet's own key.
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// Response with derived address and public key
#[derive(Debug, Serialize)]
pub struct WalletDeriveAddressResponse {
    pub address: String,
    pub public_key: String,
}

/// Request to sign EIP-712 typed data with the wallet's EVM (secp256k1) key.
#[derive(Debug, Deserialize)]
pub struct WalletEvmSignTypedDataRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Full `eth_signTypedData_v4` object: `{ domain, types, primaryType, message }`.
    pub typed_data: serde_json::Value,
    /// Sign with this sub-key of the wallet's EVM key instead of the key
    /// itself — see [`validate_sub_path`].
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// Request to sign an EIP-191 `personal_sign` message with the wallet's EVM key.
#[derive(Debug, Deserialize)]
pub struct WalletEvmSignMessageRequest {
    pub wallet_id: String,
    pub chain: String,
    /// The message to sign; interpreted per `encoding`.
    pub message: String,
    /// `"utf8"` (default) signs the UTF-8 bytes of `message`; `"hex"` treats
    /// `message` as hex and signs the decoded bytes. No content sniffing.
    #[serde(default)]
    pub encoding: Option<String>,
    /// Sign with this sub-key of the wallet's EVM key — see [`validate_sub_path`].
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// Request to sign a raw EVM transaction with the wallet's EVM key.
///
/// The caller supplies the **serialized unsigned transaction** (e.g. viem
/// `serializeTransaction(tx)` — `0x02‖rlp(...)` for EIP-1559). The keystore
/// keccak256-hashes it and signs — it does NOT parse or assemble the tx, manage
/// nonce/gas, or broadcast. Gated by the `evm_sign.raw_tx` sub-capability.
#[derive(Debug, Deserialize)]
pub struct WalletEvmSignTransactionRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Serialized unsigned transaction, `0x`-hex.
    pub unsigned_tx: String,
    /// Sign with this sub-key of the wallet's EVM key — see [`validate_sub_path`].
    #[serde(default)]
    pub sub_path: Option<String>,
}

/// A 65-byte recoverable EVM signature, `0x`-hex (`r‖s‖v`, `v ∈ {27,28}`).
#[derive(Debug, Serialize)]
pub struct WalletEvmSignResponse {
    pub signature: String,
}

/// Request to sign an off-chain message with the wallet's Solana (ed25519) key.
///
/// The raw decoded bytes are signed as-is (Solana convention — verifiable
/// with `nacl.sign.detached.verify`), EXCEPT bytes that parse as a valid
/// Solana transaction message, which are rejected (use
/// `/wallet/solana/sign-transaction`, gated by `solana_sign.raw_tx`).
#[derive(Debug, Deserialize)]
pub struct WalletSolanaSignMessageRequest {
    pub wallet_id: String,
    pub chain: String,
    /// The message to sign; interpreted per `encoding`.
    pub message: String,
    /// `"utf8"` (default) signs the UTF-8 bytes of `message`; `"hex"` /
    /// `"base64"` decode `message` first and sign the decoded bytes.
    /// No content sniffing.
    #[serde(default)]
    pub encoding: Option<String>,
}

/// Request to sign a Solana transaction message with the wallet's Solana key.
///
/// The caller supplies the **serialized unsigned transaction message** (what
/// the signature covers on Solana: web3.js `tx.serializeMessage()` /
/// `versionedTx.message.serialize()`), base64. The keystore signs the bytes
/// as-is — it does NOT parse or assemble the transaction, pick a blockhash,
/// or broadcast. Gated by the `solana_sign.raw_tx` sub-capability.
#[derive(Debug, Deserialize)]
pub struct WalletSolanaSignTransactionRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Serialized unsigned transaction message, base64.
    pub unsigned_tx: String,
}

/// A 64-byte ed25519 signature, base58 (Solana convention).
#[derive(Debug, Serialize)]
pub struct WalletSolanaSignResponse {
    pub signature: String,
}

/// Request to sign encrypted policy data (for on-chain store_wallet_policy)
#[derive(Debug, Deserialize)]
pub struct WalletSignPolicyRequest {
    pub wallet_id: String,
    /// The encrypted policy blob (base64 ciphertext), NOT a pre-computed hash. The keystore
    /// DECRYPT-VALIDATES it (AEAD) before signing — a caller-supplied
    /// raw hash, or any non-ciphertext, is rejected (it would be a tx-signing oracle).
    pub encrypted_data: String,
    /// The NEAR account that will SEND `store_wallet_policy`. Part of the
    /// signed message, so the signature is good for that account and no other —
    /// which is what stops a signature lifted off the chain being filed by a
    /// stranger.
    pub caller: String,
}

/// Request for POST /wallet/sign-secret-store.
#[derive(Debug, Deserialize)]
pub struct SignSecretStoreRequest {
    pub wallet_id: String,
    /// The connector's project. Used to REBUILD the seed here rather than take
    /// one from the caller — that is what makes a mis-sealed secret impossible
    /// rather than merely unlikely.
    ///
    /// Exactly one of this and `wasm_hash`. See [`AgentSecretTarget`].
    #[serde(default)]
    pub project_id: Option<String>,
    /// One exact WASM binary instead of a project: the secret is then readable
    /// only by that build, and a rebuild that changes a byte cannot open it.
    #[serde(default)]
    pub wasm_hash: Option<String>,
    /// The sealed secret (base64 ciphertext), NOT a hash. Decrypt-validated
    /// before anything is signed — see the handler.
    pub encrypted_secrets_base64: String,
    /// The account that will send the transaction and stake the storage. Part of
    /// the signed message, so the signature cannot be replayed by anyone else.
    pub payer: String,
    /// Who may obtain a decryption of this secret. **Signed**, because consent
    /// to a ciphertext is not consent to an audience: with this outside the
    /// signature, the payer chose the readers after the owner had signed and
    /// the signature still verified.
    pub access: crate::types::AccessCondition,
    /// Which per-customer master the secret is sealed to, if any. Signed for
    /// the same reason as the accessor: it decides which key decrypts, so it is
    /// part of what is being authorised.
    #[serde(default)]
    pub vault_id: Option<String>,
}

/// Response with the signature the contract's `store_agent_secret` verifies.
#[derive(Debug, Serialize)]
pub struct SignSecretStoreResponse {
    pub signature_hex: String,
    /// `ed25519:<hex>` — the form the contract takes.
    pub wallet_pubkey: String,
    /// The agent's implicit account: both the owner of the secret and its name.
    pub agent_account: String,
}

/// Request for POST /wallet/sign-secret-delete.
///
/// No ciphertext, because a delete names a secret rather than carrying one —
/// which also removes the decrypt-validation this endpoint's sibling relies on.
/// What authorises it instead is the same thing that authorises every other
/// wallet operation: the caller reached here holding the wallet's key, and the
/// signature covers the agent, the accessor, the profile and the payer, so it
/// destroys one named secret on behalf of one named submitter and nothing else.
#[derive(Debug, Deserialize)]
pub struct SignSecretDeleteRequest {
    pub wallet_id: String,
    /// Exactly one of this and `wasm_hash`, exactly as for the store — the
    /// signature must name the accessor the secret is filed under.
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub wasm_hash: Option<String>,
    /// The account that will send the transaction, and the one the storage
    /// deposit comes back to.
    pub payer: String,
}

/// Response with the signature the contract's `delete_agent_secret` verifies.
#[derive(Debug, Serialize)]
pub struct SignSecretDeleteResponse {
    pub signature_hex: String,
    pub wallet_pubkey: String,
    pub agent_account: String,
}

/// Response with ed25519 signature + public key for contract verification
#[derive(Debug, Serialize)]
pub struct WalletSignPolicyResponse {
    pub signature_hex: String,  // ed25519 signature (64 bytes hex)
    pub public_key_hex: String, // ed25519 public key (32 bytes hex)
}

/// A single approver's NEP-413 signature over `approve:{approval_id}:{wallet_pubkey}:{request_hash}`.
#[derive(Debug, Deserialize)]
pub struct ApproverSig {
    pub approver_id: String, // NEAR account id; must be in the wallet policy's approvers
    pub public_key: String,  // ed25519:base58
    pub signature: String,   // base64 (64 bytes)
    pub nonce: String,       // base64 (32 bytes) — the NEP-413 nonce the approver used
}

/// Approval bundle forwarded by the coordinator. It carries the real approver
/// signatures (not just names) so the keystore verifies them itself — the
/// coordinator transports them but cannot forge them. The keystore derives the
/// `request_hash` itself from the canonical `op` (binding is automatic), so the
/// coordinator can neither pick the hash nor bind approvals to a different op.
#[derive(Debug, Deserialize)]
pub struct ApprovalInfo {
    pub approval_id: String,
    /// NEP-413 `recipient` the approvers signed against; asserted == this keystore's contract.
    pub recipient: String,
    /// YES votes — NEP-413 sigs over `approve:{approval_id}:{wallet_pubkey}:{request_hash}`.
    pub approvals: Vec<ApproverSig>,
    /// NO votes (vetoes) — NEP-413 sigs over `reject:{approval_id}:{wallet_pubkey}:{request_hash}`. Any
    /// vote from a REAL policy approver (valid sig + on-chain key + in approver set)
    /// vetoes the operation; non-approver rejections are ignored. Symmetric with approvals.
    #[serde(default)]
    pub rejections: Vec<ApproverSig>,
}

/// Unified wallet signing request (the single `/wallet/sign` endpoint).
///
/// `op` is the canonical operation. The keystore derives
/// `request_hash = sha256(canonical_json(op))`, evaluates the on-chain policy,
/// verifies approver signatures when required, then produces the artifact per the
/// op's bind mode — for `Built` kinds it CONSTRUCTS the artifact from the op (never
/// accepts a ready one), so what it signs always equals what was approved.
#[derive(Debug, Deserialize)]
pub struct WalletSignRequest {
    pub wallet_id: String,
    pub op: shared_tee_helpers::wallet_policy::Op,
    #[serde(default)]
    pub approval_info: Option<ApprovalInfo>,
    /// Supplementary material the keystore cannot derive from `op`:
    /// - Hash-pinned `raw`: the exact bytes to sign (`bytes_base64`); signed iff
    ///   `sha256(bytes) == op.payload_hash`.
    /// - Hash-pinned `sign_message`: the plaintext `message` + `nonce_base64`. The
    ///   recipient comes from `op` (bound into the signature → domain separation).
    /// - Trusted `swap`/`confidential`: the externally-generated NEP-413 `message`
    ///   + `nonce_base64` + `recipient` (artifact can't exist at approval time).
    #[serde(default)]
    pub artifact: Option<SignArtifact>,
    /// Stateful usage state (per-token daily/hourly/monthly spend + hourly_tx_count),
    /// in the coordinator's `current_usage` JSON shape. The keystore is the sole policy
    /// evaluator; the coordinator merely SUPPLIES this state (it cannot decrypt the
    /// policy). Absent → only the stateless subset is enforced. Trusted: a compromised
    /// coordinator can under-report usage, but the keystore still enforces the stateless
    /// rules + multisig independently.
    #[serde(default)]
    pub usage: Option<serde_json::Value>,
    /// Agent Connect: which binding mode the coordinator believes this wallet
    /// operates in, and — for the leased mode — the DECODER the coordinator
    /// resolved for the bound account's implementation version through its
    /// `hos_impl_versions` table. Both are CLAIMS: the enclave has no chain
    /// access, so it cannot check them, only refuse what it cannot evaluate —
    /// and it evaluates by decoder, not by partner version, so a partner
    /// release that changes nothing on the wire never reaches this image. See
    /// `binding::signing_version_gate` for what that buys.
    #[serde(default)]
    pub binding_kind: Option<String>,
    #[serde(default)]
    pub decoder_version: Option<u32>,
}

/// Supplementary signing material — see `WalletSignRequest::artifact`.
#[derive(Debug, Default, Deserialize)]
pub struct SignArtifact {
    #[serde(default)]
    pub bytes_base64: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub nonce_base64: Option<String>,
    #[serde(default)]
    pub recipient: Option<String>,
}

/// Unified wallet signing response. Fields are populated per bind mode; the
/// `request_hash` is always the canonical hash the keystore signed under.
#[derive(Debug, Serialize)]
pub struct WalletSignResponse {
    pub request_hash: String,
    // --- Built NEAR transaction (transfer / call / delete) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_tx_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    // --- NEP-413 intent / message (withdraw / sign_message / swap / confidential) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_base58: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    // --- Raw signature (hash-pinned cross-chain) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_base64: Option<String>,
    // --- Auth (raw ed25519 over the coordinator auth string) ---
    /// The exact signed auth string (`<prefix>:<seed>:<ts>[:<vault>]`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_message: Option<String>,
    /// The fresh timestamp the keystore embedded in `auth_message`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_timestamp: Option<u64>,
    /// Raw ed25519 signature, base58 (no `ed25519:` prefix) — what the coordinator's
    /// `verify_near_auth_fields` `bs58::decode`s.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_signature_base58: Option<String>,
    // public_key applies to every signing mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl WalletSignResponse {
    pub(super) fn new(request_hash: String) -> Self {
        WalletSignResponse {
            request_hash,
            signed_tx_base64: None,
            tx_hash: None,
            signer_id: None,
            nonce: None,
            signature_base58: None,
            message: None,
            nonce_base64: None,
            recipient: None,
            signature_base64: None,
            auth_message: None,
            auth_timestamp: None,
            auth_signature_base58: None,
            public_key: None,
        }
    }
}

/// Pre-flight policy check for a canonical `op` (the same engine `/wallet/sign` uses).
/// The keystore is the SOLE policy evaluator; the coordinator supplies `usage`.
#[derive(Debug, Deserialize)]
pub struct WalletCheckPolicyRequest {
    pub wallet_id: String,
    pub op: shared_tee_helpers::wallet_policy::Op,
    /// Stateful usage state (coordinator `current_usage` shape). Absent → stateless only.
    #[serde(default)]
    pub usage: Option<serde_json::Value>,
    /// Optional: encrypted policy data (base64) for local/test policy override.
    /// When provided, skips fetching from NEAR contract.
    #[serde(default)]
    pub encrypted_policy_data: Option<String>,
    /// See `WalletSignRequest::binding_kind`. The pre-flight check must answer
    /// what the signature would, or a caller could be told "allowed" and then
    /// refused at signing.
    #[serde(default)]
    pub binding_kind: Option<String>,
    #[serde(default)]
    pub decoder_version: Option<u32>,
}

/// Response from policy check. The decrypted policy is NEVER returned — it does not
/// leave the keystore.
#[derive(Debug, Serialize)]
pub struct WalletCheckPolicyResponse {
    pub allowed: bool,
    pub frozen: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_approvals: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Canonical request hash the dashboard signs (`approve:{id}:{wallet_pubkey}:{request_hash}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<String>,
    /// Narrow carve-out: the owner's event-delivery URL (NOT a secret). The rest of the
    /// decrypted policy never leaves the keystore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
}

/// Request to encrypt a wallet policy
#[derive(Debug, Deserialize)]
pub struct WalletEncryptPolicyRequest {
    pub wallet_id: String,
    pub policy_json: String,
}

/// Response with encrypted policy
#[derive(Debug, Serialize)]
pub struct WalletEncryptPolicyResponse {
    pub encrypted_base64: String,
}

/// Request to DECRYPT a wallet policy for owner-view / config sync (NOT the signing
/// decision path — `/check-policy` and `/wallet/sign` never return the policy). The
/// coordinator already caches the result in `wallet_accounts.policy_json`.
#[derive(Debug, Deserialize)]
pub struct WalletDecryptPolicyRequest {
    pub wallet_id: String,
    /// Encrypted policy blob (base64) read from chain by the caller.
    pub encrypted_policy_data: String,
}

/// Response with the decrypted policy JSON.
#[derive(Debug, Serialize)]
pub struct WalletDecryptPolicyResponse {
    pub policy: serde_json::Value,
}

/// POST /vrf/generate — Generate VRF output for alpha (worker-only)
pub(super) async fn vrf_generate_handler(
    State(state): State<AppState>,
    Json(req): Json<VrfGenerateRequest>,
) -> Result<Json<VrfGenerateResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    if req.alpha.is_empty() {
        return Err(ApiError::BadRequest("alpha must not be empty".to_string()));
    }

    let keystore = state.keystore.read().await;
    let (output_hex, signature_hex) = keystore
        .vrf_generate(req.alpha.as_bytes())
        .map_err(|e| ApiError::InternalError(format!("VRF generation failed: {}", e)))?;

    tracing::info!(alpha = %req.alpha, "VRF generated");

    Ok(Json(VrfGenerateResponse { output_hex, signature_hex }))
}

/// GET /vrf/pubkey — Get VRF public key (public, no auth)
pub(super) async fn vrf_pubkey_handler(
    State(state): State<AppState>,
) -> Result<Json<VrfPublicKeyResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    let keystore = state.keystore.read().await;
    let vrf_public_key_hex = keystore
        .vrf_public_key_hex()
        .map_err(|e| ApiError::InternalError(format!("VRF public key derivation failed: {}", e)))?;

    Ok(Json(VrfPublicKeyResponse { vrf_public_key_hex }))
}

/// `POST /admin/evict-customer` — drop the cached per-customer master.
///
/// Called by the monitoring service when it detects a vault should
/// no longer operate (race-attack ban, manual DAO ban). The next
/// `derive_*` call for this vault will fail because the lazy-load
/// gate re-checks `keystore-dao.is_vault_verified` which now
/// returns false-when-banned.
///
/// Without this endpoint a banned vault would continue operating
/// until the next keystore-worker restart drops the in-memory cache.
///
/// **Auth:** worker token. Same boundary as `/decrypt` — anything
/// inside the operator's TEE network can evict. The endpoint is NOT
/// exposed to coordinator or external clients.
///
/// **Idempotent:** evicting a customer that was never loaded is a
/// no-op. Returns `{ ok: true }` either way.
pub(super) async fn admin_evict_customer_handler(
    State(state): State<AppState>,
    Json(req): Json<AdminEvictCustomerRequest>,
) -> Result<Json<AdminEvictCustomerResponse>, ApiError> {
    let customer: near_primitives::types::AccountId = req.vault_id.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid vault_id account: {e}"))
    })?;
    let keystore = state.keystore.read().await;
    keystore.evict_customer(&customer);
    tracing::info!(
        vault_id = %customer,
        reason = %req.reason,
        "admin: evicted per-customer master from cache"
    );
    Ok(Json(AdminEvictCustomerResponse { ok: true }))
}

/// `POST /admin/ban-vault` — submit `keystore_dao.ban_vault(vault_id,
/// reason)` and evict the cached per-customer master in one shot.
///
/// Called by the race-attack monitoring service when it
/// detects more than one MPC `request_app_private_key` call for the
/// same vault within the dedup window. Side effects (in order):
///   1. Short-circuit if `keystore_dao.is_vault_banned(vault_id)` is
///      already true — no need to spend another nonce + log line.
///   2. Submit `ban_vault` via the worker's keystore-DAO function-call
///      access key (same key that `mark_vault_verified` uses; the DAO
///      whitelists the method-list). 300 TGas, no deposit. Serialized
///      through `signer_nonce_lock` so this can run concurrently with
///      `/sign-vault-verification`.
///   3. Evict the in-memory per-customer master so the ban takes
///      effect within ms — the `is_vault_verified` check on the
///      next-derive-call already returns false-when-banned (the DAO
///      view reads `verified - banned`).
///
/// **Auth:** worker token. Same boundary as `/admin/evict-customer`.
pub(super) async fn admin_ban_vault_handler(
    State(state): State<AppState>,
    Json(req): Json<AdminBanVaultRequest>,
) -> Result<Json<AdminBanVaultResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string(),
        ));
    }

    let vault_id: near_primitives::types::AccountId = req.vault_id.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid vault_id account: {e}"))
    })?;

    if req.reason.is_empty() {
        return Err(ApiError::BadRequest(
            "reason is required (operators set the convention; see the handler docs)".to_string(),
        ));
    }
    if req.reason.len() > 256 {
        return Err(ApiError::BadRequest(format!(
            "reason must be at most 256 bytes (got {})",
            req.reason.len()
        )));
    }

    let ctx = state.mpc_context.get().ok_or_else(|| {
        ApiError::InternalError(
            "MPC CKD context not configured — worker booted in non-TEE mode".to_string(),
        )
    })?;
    let near_client = state.near_client.as_ref().ok_or_else(|| {
        ApiError::InternalError("NEAR client not configured".to_string())
    })?;

    // 1. Short-circuit if already banned.
    let is_banned = near_client
        .view_call_json(
            &ctx.mpc_ckd_config.keystore_dao_id,
            "is_vault_banned",
            serde_json::json!({ "vault_id": vault_id }),
        )
        .await
        .map_err(|e| {
            ApiError::InternalError(format!("is_vault_banned view-call failed: {e}"))
        })?;
    if is_banned.as_bool() == Some(true) {
        // Still evict — the cache may have stale state if a different
        // operator banned via DAO vote and this monitor is catching up.
        let keystore = state.keystore.read().await;
        keystore.evict_customer(&vault_id);
        tracing::info!(
            vault_id = %vault_id,
            "Skipping ban_vault tx — already banned on chain. Cache evicted."
        );
        return Ok(Json(AdminBanVaultResponse {
            tx_hash: None,
            already_banned: true,
        }));
    }

    // 2. Submit ban_vault tx, serialized through signer_nonce_lock to
    //    avoid racing /sign-vault-verification on the keystore-DAO
    //    access key's nonce.
    let outcome = {
        let _guard = ctx.signer_nonce_lock.lock().await;
        near_client
            .submit_function_call(
                &ctx.keystore_dao_signer,
                &ctx.mpc_ckd_config.keystore_dao_id,
                "ban_vault",
                serde_json::json!({ "vault_id": vault_id, "reason": req.reason }),
                300_000_000_000_000,
                0,
            )
            .await
    }
    .map_err(|e| {
        tracing::error!(
            vault_id = %vault_id,
            reason = %req.reason,
            error = %e,
            "ban_vault tx submission failed"
        );
        let msg = format!("{e:#}");
        // Concurrent ban via DAO vote = treat as "already banned"
        // (idempotent end state). The contract panics with a generic
        // require! message so we match permissively.
        if msg.contains("already") {
            ApiError::Forbidden(format!("vault {} already banned (race): {}", vault_id, msg))
        } else {
            ApiError::InternalError(format!("tx submission failed: {msg}"))
        }
    })?;

    // 3. Evict the cached master so existing in-flight derive_* calls
    //    on this vault stop succeeding immediately. Does not need the
    //    on-chain tx to land first — the lazy-load gate re-checks
    //    `is_vault_verified` (which factors in `banned_vaults`) on the
    //    NEXT call after eviction, by which point the tx is final.
    {
        let keystore = state.keystore.read().await;
        keystore.evict_customer(&vault_id);
    }

    tracing::warn!(
        vault_id = %vault_id,
        reason = %req.reason,
        tx_hash = %outcome.tx_hash,
        "ban_vault tx landed; per-customer master evicted from cache"
    );

    Ok(Json(AdminBanVaultResponse {
        tx_hash: Some(outcome.tx_hash),
        already_banned: false,
    }))
}

/// `POST /sign-vault-verification` — re-verify a vault and submit
/// `mark_vault_verified` on chain.
///
/// Called by the public
/// `outlayer.near/vault-checker` WASI agent after it has run the
/// same 5 checks itself. The keystore-worker:
///
/// 1. Re-runs all 5 checks via [`crate::vault_verifier::verify_vault_for_signing`]
///    (defense in depth — independent code from the WASI agent).
/// 2. If everything passes, submits `keystore_dao.mark_vault_verified(vault_id)`
///    using the worker's approved access key on the keystore-dao
///    contract (set up at TEE registration time).
/// 3. Returns the broadcast tx hash. The agent does NOT need to wait
///    for finality on the worker side — `broadcast_tx_commit` already
///    waits, and the response only returns once the tx is final.
///
/// **Critically NOT done here:** MPC CKD for the vault's master.
/// That's lazy on first wallet-request via [`crate::mpc_ckd::add_customer`]
/// (lazy MPC CKD). Materialising masters at verification time would
/// charge gas to the vault account before any wallet operation is
/// requested — an unnecessary upfront cost.
///
/// **Auth:** worker token. The vault-checker WASI runs in OutLayer's
/// TEE workers and forwards its worker token; an external caller with
/// a worker token (i.e. an operator) can also drive this endpoint.
/// The auth boundary is intentionally permissive because the security
/// guarantee is the in-process re-verification, not the auth.
///
/// **Idempotent:** if `vault_id` is already verified on chain, the
/// `mark_vault_verified` tx is still submitted — the contract is
/// expected to no-op on re-mark. We don't short-circuit here because
/// we want the canonical tx hash to return either way.
pub(super) async fn sign_vault_verification_handler(
    State(state): State<AppState>,
    Json(req): Json<SignVaultVerificationRequest>,
) -> Result<Json<SignVaultVerificationResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string(),
        ));
    }

    let vault_id: near_primitives::types::AccountId = req.vault_id.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid vault_id account: {e}"))
    })?;

    // All required context lives in one OnceLock — atomicity
    // invariant means no half-set state can be observed.
    let ctx = state.mpc_context.get().ok_or_else(|| {
        ApiError::InternalError(
            "MPC CKD context not configured — worker booted in non-TEE mode".to_string(),
        )
    })?;
    let near_client = state.near_client.as_ref().ok_or_else(|| {
        ApiError::InternalError("NEAR client not configured".to_string())
    })?;

    // 0. Short-circuit if already verified on-chain. The
    //    `mark_vault_verified` contract method is
    //    idempotent (insert into UnorderedSet is no-op if present), so
    //    skipping the tx is purely an optimisation — but a meaningful
    //    one: every `mark_vault_verified` consumes a nonce and ~0.001
    //    NEAR from the worker's keystore-dao access-key allowance,
    //    and an attacker with a worker token could DoS the nonce by
    //    spamming this endpoint against verified vaults.
    let is_verified = near_client
        .view_call_json(
            &ctx.mpc_ckd_config.keystore_dao_id,
            "is_vault_verified",
            serde_json::json!({ "vault_id": vault_id }),
        )
        .await
        .map_err(|e| {
            ApiError::InternalError(format!("is_vault_verified view-call failed: {e}"))
        })?;
    if is_verified.as_bool() == Some(true) {
        tracing::info!(
            vault_id = %vault_id,
            "Skipping mark_vault_verified — vault already verified on chain"
        );
        return Ok(Json(SignVaultVerificationResponse {
            tx_hash: None,
            already_verified: true,
        }));
    }

    // 1. Defense-in-depth re-verification of all 5 checks. If any
    //    fails, classify caller-side vs worker-side and surface an
    //    appropriate status (see `map_verify_error`).
    crate::vault_verifier::verify_vault_for_signing(
        near_client.as_ref(),
        &ctx.mpc_ckd_config.keystore_dao_id,
        &ctx.mpc_ckd_config.mpc_contract_id,
        &vault_id,
    )
    .await
    .map_err(|e| {
        tracing::warn!(
            vault_id = %vault_id,
            error = %e,
            "Refusing to sign mark_vault_verified — re-verification failed"
        );
        map_verify_error(&vault_id, e)
    })?;

    // 2. Submit mark_vault_verified tx, serializing through the
    //    per-signer nonce lock so concurrent /sign-vault-verification
    //    calls (and /admin/ban-vault) don't race for the same nonce.
    //    Lock is held only across the build+broadcast critical
    //    section; the response wait is inside broadcast_tx_commit so
    //    we cannot release earlier without losing the tx_hash.
    //    300 TGas, no deposit.
    let outcome = {
        let _guard = ctx.signer_nonce_lock.lock().await;
        near_client
            .submit_function_call(
                &ctx.keystore_dao_signer,
                &ctx.mpc_ckd_config.keystore_dao_id,
                "mark_vault_verified",
                serde_json::json!({ "vault_id": vault_id }),
                300_000_000_000_000,
                0,
            )
            .await
    }
    .map_err(|e| {
        tracing::error!(
            vault_id = %vault_id,
            error = %e,
            "mark_vault_verified tx submission failed"
        );
        // A vault that gets banned between vault-checker's own
        // check and our signing window will surface as a
        // contract-side panic with a recognisable message. Map it
        // to 409 Conflict so the caller doesn't retry indefinitely
        // treating it as a transient failure.
        let msg = format!("{e:#}");
        // Match only the exact contract-side panic phrase. The earlier
        // loose `|| msg.contains("banned")` also fired on words like
        // "unbanned" / "rebanned" / any future error mentioning the
        // root, mis-mapping unrelated failures to 403 Forbidden.
        if msg.contains("vault is banned") {
            ApiError::Forbidden(format!(
                "vault {} is banned (likely banned between check and sign): {}",
                vault_id, msg
            ))
        } else {
            ApiError::InternalError(format!("tx submission failed: {msg}"))
        }
    })?;

    tracing::info!(
        vault_id = %vault_id,
        tx_hash = %outcome.tx_hash,
        "mark_vault_verified tx landed"
    );

    Ok(Json(SignVaultVerificationResponse {
        tx_hash: Some(outcome.tx_hash),
        already_verified: false,
    }))
}

/// `POST /derive-vault-tee-key` — return the Layer-1 vault TEE
/// public key for a given `vault_id`.
///
/// `outlayer-cli init-vault` flow: the customer needs the
/// pubkey BEFORE submitting the atomic deploy that adds it as a
/// function-call AccessKey on the new vault. The keypair is
/// [HMAC-derived from the OutLayer default master](mpc_ckd::derive_vault_tee_keypair),
/// so the worker can answer this query without any state — it's
/// read-only and doesn't trigger MPC CKD.
///
/// **Auth:** worker token (admin lane). The CLI is operator-bundled
/// or run by the customer through coordinator's auth proxy; either
/// way the caller has the worker token (or a coordinator token,
/// per the same `worker_auth_middleware` allowlist as
/// `/admin/evict-customer` and `/sign-vault-verification`).
///
/// **Idempotent / pure:** does NOT touch the keystore_dao_signer,
/// does NOT acquire any locks. Two concurrent calls for the same
/// vault_id return identical pubkeys.
pub(super) async fn derive_vault_tee_key_handler(
    State(state): State<AppState>,
    Json(req): Json<DeriveVaultTeeKeyRequest>,
) -> Result<Json<DeriveVaultTeeKeyResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string(),
        ));
    }

    let vault_id: near_primitives::types::AccountId = req.vault_id.parse().map_err(|e| {
        ApiError::BadRequest(format!("invalid vault_id: {e}"))
    })?;

    let keystore = state.keystore.read().await;
    let (public_key, _secret_key) =
        crate::mpc_ckd::derive_vault_tee_keypair(&keystore, &vault_id).map_err(|e| {
            ApiError::InternalError(format!("Layer-1 keypair derivation failed: {e}"))
        })?;

    Ok(Json(DeriveVaultTeeKeyResponse {
        public_key: public_key.to_string(),
    }))
}

/// Map [`crate::vault_verifier::VerifyError`] into the right HTTP
/// status. The split is:
///
/// * **4xx (caller-side / vault-state issue)** — the caller submitted
///   a bad request OR pointed at a vault that fails the protocol's
///   security invariants. Caller should surface to its end-user, not
///   retry transparently.
/// * **5xx (worker-side / RPC-down)** — something between the worker
///   and chain or contract is misbehaving. Caller MAY retry with
///   exponential backoff.
pub(super) fn map_verify_error(
    vault_id: &near_primitives::types::AccountId,
    e: crate::vault_verifier::VerifyError,
) -> ApiError {
    use crate::vault_verifier::VerifyError as V;
    let msg = format!("vault {vault_id} re-verification failed: {e}");
    match e {
        // Caller-/vault-side problems → 4xx
        V::AlreadyBanned => ApiError::Forbidden(msg),
        V::CodeHashNotApproved { .. }
        | V::CodeHashMissing
        | V::FullAccessKeyPresent
        | V::FunctionCallKeyMisconfigured { .. }
        | V::UnexpectedAccessKeyCount { .. }
        | V::KeystoreDaoMismatch { .. }
        | V::MpcContractMismatch { .. }
        | V::VaultUnlocked
        | V::VaultRecoveryInProgress => ApiError::BadRequest(msg),
        // AccountNotFound is ambiguous (vault doesn't exist OR rpc
        // flake) — bias toward "caller pointed at something invalid"
        // because that's the dominant case; the error message still
        // surfaces the underlying RPC error for ops triage.
        V::AccountNotFound(_) => ApiError::BadRequest(msg),
        // Worker-/system-side problems → 5xx so callers can retry.
        V::KeystoreDaoUnreachable(_)
        | V::AccessKeyListUnreachable(_)
        | V::VaultStateUnreachable(_) => ApiError::InternalError(msg),
        // Contract returning unexpected response shape — that's a
        // contract version mismatch, NOT a caller-side bug.
        V::KeystoreDaoMalformed { .. } | V::VaultStateInvalid(_) => ApiError::InternalError(msg),
    }
}

/// Request to decrypt raw encrypted data directly
#[derive(Debug, Deserialize)]
pub struct DecryptRawRequest {
    /// Seed for key derivation
    pub seed: String,
    /// Base64-encoded encrypted data
    pub encrypted_base64: String,
}

/// Response with decrypted data
#[derive(Debug, Serialize)]
pub struct DecryptRawResponse {
    /// Base64-encoded plaintext data
    pub plaintext_base64: String,
}

// ==================== Storage Encryption Handlers ====================

/// Encrypt data for persistent storage
///
/// Uses derived key from: `storage:{project_uuid|wasm_hash}:{account_id}`
/// This keeps encryption keys isolated per project/wasm and per account.
pub(super) async fn storage_encrypt_handler(
    State(state): State<AppState>,
    Json(req): Json<StorageEncryptRequest>,
) -> Result<Json<StorageEncryptResponse>, ApiError> {
    // Check if keystore is ready
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    // Build seed for key derivation
    // For projects: storage:{project_uuid}:{account_id}
    // For standalone WASM: storage:wasm:{wasm_hash}:{account_id}
    let seed = if let Some(ref project_uuid) = req.project_uuid {
        format!("storage:{}:{}", project_uuid, req.account_id)
    } else {
        format!("storage:wasm:{}:{}", req.wasm_hash, req.account_id)
    };

    tracing::debug!(
        seed = %seed,
        project_uuid = ?req.project_uuid,
        wasm_hash = %req.wasm_hash,
        account_id = %req.account_id,
        key = %req.key,
        "Encrypting storage data"
    );

    // Decode value from base64
    let value_bytes = base64::decode(&req.value_base64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in value: {}", e)))?;

    // Encrypt key and value
    let keystore = state.keystore.read().await;

    let encrypted_key = keystore
        .encrypt(None, &seed, req.key.as_bytes())
        .map_err(|e| ApiError::InternalError(format!("Failed to encrypt key: {}", e)))?;

    let encrypted_value = keystore
        .encrypt(None, &seed, &value_bytes)
        .map_err(|e| ApiError::InternalError(format!("Failed to encrypt value: {}", e)))?;

    // Calculate key hash for unique constraint
    use sha2::{Sha256, Digest};
    let key_hash = hex::encode(Sha256::digest(req.key.as_bytes()));

    tracing::info!(
        project_uuid = ?req.project_uuid,
        wasm_hash = %req.wasm_hash,
        account_id = %req.account_id,
        key_hash = %key_hash,
        encrypted_key_len = encrypted_key.len(),
        encrypted_value_len = encrypted_value.len(),
        "Successfully encrypted storage data"
    );

    Ok(Json(StorageEncryptResponse {
        encrypted_key_base64: base64::encode(&encrypted_key),
        encrypted_value_base64: base64::encode(&encrypted_value),
        key_hash,
    }))
}

/// Decrypt data from persistent storage
pub(super) async fn storage_decrypt_handler(
    State(state): State<AppState>,
    Json(req): Json<StorageDecryptRequest>,
) -> Result<Json<StorageDecryptResponse>, ApiError> {
    // Check if keystore is ready
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(
            "Keystore not ready. Waiting for DAO approval and master key from MPC.".to_string()
        ));
    }

    // Build seed for key derivation (same as encrypt)
    let seed = if let Some(ref project_uuid) = req.project_uuid {
        format!("storage:{}:{}", project_uuid, req.account_id)
    } else {
        format!("storage:wasm:{}:{}", req.wasm_hash, req.account_id)
    };

    // Decode encrypted data from base64
    let encrypted_key = base64::decode(&req.encrypted_key_base64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in encrypted_key: {}", e)))?;

    let encrypted_value = base64::decode(&req.encrypted_value_base64)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 in encrypted_value: {}", e)))?;

    // Decrypt key and value
    let keystore = state.keystore.read().await;

    let key_bytes = keystore
        .decrypt(None, &seed, &encrypted_key)
        .map_err(|e| ApiError::InternalError(format!("Failed to decrypt key: {}", e)))?;

    let value_bytes = keystore
        .decrypt(None, &seed, &encrypted_value)
        .map_err(|e| ApiError::InternalError(format!("Failed to decrypt value: {}", e)))?;

    // Convert key to string
    let key = String::from_utf8(key_bytes)
        .map_err(|e| ApiError::InternalError(format!("Decrypted key is not valid UTF-8: {}", e)))?;

    tracing::debug!(
        project_uuid = ?req.project_uuid,
        wasm_hash = %req.wasm_hash,
        account_id = %req.account_id,
        key = %key,
        "Successfully decrypted storage data"
    );

    Ok(Json(StorageDecryptResponse {
        key,
        value_base64: base64::encode(&value_bytes),
    }))
}

// =========================================================================
// TEE Challenge-Response Endpoints
// =========================================================================

/// Generate a TEE challenge for worker registration
///
/// Worker calls this to get a random nonce, then signs it with their TEE private key.
pub(super) async fn tee_challenge_handler(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let challenge = shared_tee_helpers::generate_challenge();

    // Store challenge in memory with timestamp
    {
        let mut challenges = state.tee_challenges.lock().unwrap();

        // Clean up expired challenges (>60 seconds old)
        challenges.retain(|_, c| c.created_at.elapsed().as_secs() < 60);

        challenges.insert(challenge.clone(), TeeChallenge {
            created_at: std::time::Instant::now(),
        });
    }

    tracing::debug!("TEE challenge generated: {}...", &challenge[..16]);

    Ok(Json(serde_json::json!({ "challenge": challenge })))
}

/// Request body for TEE registration
#[derive(Debug, Deserialize)]
pub(super) struct RegisterTeeRequest {
    public_key: String,
    challenge: String,
    signature: String,
}

/// Register a TEE session after challenge-response verification
///
/// 1. Verify challenge exists and is not expired
/// 2. Verify ed25519 signature
/// 3. Check public key exists on register-contract via NEAR RPC
/// 4. Create session and return session_id
pub(super) async fn register_tee_handler(
    State(state): State<AppState>,
    Json(req): Json<RegisterTeeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // 1. Find and remove challenge (one-time use)
    {
        let mut challenges = state.tee_challenges.lock().unwrap();
        let challenge = challenges.remove(&req.challenge).ok_or_else(|| {
            ApiError::BadRequest("Invalid or expired challenge".to_string())
        })?;

        // Check expiration (60 seconds)
        if challenge.created_at.elapsed().as_secs() > 60 {
            return Err(ApiError::BadRequest("Challenge expired".to_string()));
        }
    }

    // 2. Verify signature
    shared_tee_helpers::verify_signature(&req.public_key, &req.challenge, &req.signature, state.config.tee_allowed_key_types)
        .map_err(|e| ApiError::BadRequest(format!("Signature verification failed: {}", e)))?;

    // 3. Check key on operator account via NEAR RPC (with retry for finality lag)
    let operator_account_id = state.config.operator_account_id.as_ref().ok_or_else(|| {
        ApiError::InternalError("OPERATOR_ACCOUNT_ID not configured on keystore".to_string())
    })?;

    let key_exists = shared_tee_helpers::check_access_key_with_retry(
        &state.config.near_rpc_url,
        operator_account_id,
        &req.public_key,
    )
    .await
    .map_err(|e| ApiError::InternalError(format!("NEAR RPC check failed: {}", e)))?;

    if !key_exists {
        return Err(ApiError::Unauthorized(format!(
            "Public key {} not found on operator account {}",
            req.public_key, operator_account_id
        )));
    }

    // 4. Create session
    let session_id = uuid::Uuid::new_v4();
    {
        let mut sessions = state.tee_sessions.lock().unwrap();
        sessions.insert(session_id, TeeSession {
            worker_public_key: req.public_key.clone(),
            created_at: std::time::Instant::now(),
        });
    }

    tracing::info!(
        session_id = %session_id,
        public_key = %crate::near::key_for_display(&req.public_key),
        "TEE session registered on keystore"
    );

    Ok(Json(serde_json::json!({ "session_id": session_id.to_string() })))
}
