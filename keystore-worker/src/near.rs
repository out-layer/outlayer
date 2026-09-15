//! NEAR blockchain client
//!
//! Handles reading secrets from NEAR contract (read-only).

use anyhow::{Context, Result};
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::types::{AccountId, Balance, BlockReference, Gas};
use serde_json::json;
use std::str::FromStr;

/// Pooled client for the handcrafted JSON-RPC calls in this module.
///
/// A few queries bypass the typed `near-jsonrpc-client` bindings (NEP-591 global-contract
/// fields the bindings cannot decode) and post raw JSON. They used `raw_rpc_client()`,
/// i.e. a fresh connection and NO timeout, which is the same silent-hang exposure
/// [`rpc_client`] exists to close — a stalled connection here pins the handler that called it.
/// Same 30s ceiling as the query client for that reason.
fn raw_rpc_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to build raw JSON-RPC client")
    })
}

/// Read-path RPC client: view calls, access keys, block queries.
///
/// `JsonRpcClient::connect` builds its reqwest client with headers only and **no timeout**
/// (near-jsonrpc-client 0.22, `lib.rs:364`), and reqwest without an explicit timeout waits
/// forever. A connection that is established but never answered would hang the signing request
/// that triggered it, and through it the coordinator handler waiting on us. A provider that
/// load-balances internally does not help: the failure mode is a silent connection, not an
/// error response.
///
/// 30s is far above a healthy view call (~100-300ms) and these sit on the signing hot path, so
/// they should fail fast rather than hold a request open.
pub fn rpc_client(rpc_url: &str) -> JsonRpcClient {
    build_rpc_client(rpc_url, 30)
}

/// Transaction-path RPC client: `broadcast_tx_commit`.
///
/// Deliberately far more patient than [`rpc_client`]. The MPC CKD call returns its result as
/// the `SuccessValue` of the transaction itself, so this request stays open until the MPC
/// nodes resume the yielded receipt — the protocol allows that to take up to ~200 blocks.
/// A short timeout here would abort a derivation whose transaction is already on-chain and
/// will succeed: the caller would see a failure, the vault would be charged gas, and the
/// keystore would derive again on the next attempt.
pub fn rpc_client_tx(rpc_url: &str) -> JsonRpcClient {
    build_rpc_client(rpc_url, 240)
}

/// Both clients are built once per (url, timeout) and cloned afterwards: `JsonRpcClient` is
/// cheap to clone and keeps its connection pool, whereas building one allocates a fresh TLS
/// connector and pool that is then thrown away. Callers construct these per cold-vault load.
fn build_rpc_client(rpc_url: &str, timeout_secs: u64) -> JsonRpcClient {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<Vec<(String, u64, JsonRpcClient)>>> =
        std::sync::OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(Vec::new()));

    let mut entries = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, _, client)) = entries
        .iter()
        .find(|(url, secs, _)| url == rpc_url && *secs == timeout_secs)
    {
        return client.clone();
    }

    // `JsonRpcClient::with` takes the client verbatim: unlike `JsonRpcClient::connect`, which
    // goes through the crate's own `new_client()`, it sets no default headers — and the crate
    // sends its payload with `.body()`, not `.json()`. Without this header every NEAR RPC call
    // answers HTTP 415, i.e. the keystore cannot read the chain at all. Covered by
    // `rpc_client_sends_json_content_type`.
    let mut headers = reqwest_rpc::header::HeaderMap::with_capacity(1);
    headers.insert(
        reqwest_rpc::header::CONTENT_TYPE,
        reqwest_rpc::header::HeaderValue::from_static("application/json"),
    );

    let http = reqwest_rpc::Client::builder()
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("Failed to build NEAR RPC HTTP client");
    let client = JsonRpcClient::with(http).connect(rpc_url);
    entries.push((rpc_url.to_string(), timeout_secs, client.clone()));
    client
}

// NOTE: a weaker `normalize_repo_url` lived here pre-Phase-4.3. It was
// strictly less complete than `crate::utils::normalize_repo_url` (no
// ssh://, no git@, no .git stripping) — keeping two normalisers risked
// secrets stored via one and looked up via the other producing
// different on-chain keys. With the Phase 4.3 refactor of
// `decrypt_handler` and `update_user_secrets_handler` to a single
// `get_secret_with_vault` call, the duplicate normaliser had no callers
// and was deleted. All accessor-JSON construction now lives in
// `api.rs::accessor_to_contract_json`, which uses
// `crate::utils::normalize_repo_url` exclusively.

/// Result of a successful function-call transaction submission.
#[derive(Debug, Clone)]
pub struct FunctionCallOutcome {
    /// Base58-encoded NEAR tx hash. Suitable for log/explorer use.
    pub tx_hash: String,
    /// Raw bytes returned by the contract method (for view-style
    /// methods this is JSON; for state-mutating methods it's typically
    /// empty or a small status struct).
    #[allow(dead_code)] // not consumed today; kept for future endpoints
    pub success_value: Vec<u8>,
}

/// Combined return of [`NearClient::get_secret_with_vault`] — both
/// fields independently `None`-able so the caller can distinguish
/// "secret missing" from "secret exists with default-master scope".
#[derive(Debug, Clone)]
pub struct SecretWithVault {
    /// Raw `SecretProfileView` JSON returned by the contract, or
    /// `None` if no secret exists for `(accessor, profile, owner)`.
    /// Caller is responsible for typed deserialization.
    pub profile: Option<serde_json::Value>,
    /// On-chain vault binding for the secret, or `None` if the
    /// secret was stored under the default OutLayer master.
    pub vault_id: Option<String>,
}

/// NEAR client for reading secrets from contract (read-only)
pub struct NearClient {
    /// JSON-RPC client for queries
    rpc_client: JsonRpcClient,
    /// Patient client for `broadcast_tx_commit`. `mark_vault_verified` / `ban_vault` are plain
    /// calls that normally land in seconds, but giving up early on a transaction that is
    /// already included reports a failure for work that succeeded — and consumes the signer
    /// nonce either way. Waiting for the real answer is strictly more informative.
    rpc_client_tx: JsonRpcClient,
    /// Raw RPC URL — kept around for handcrafted JSON-RPC calls that
    /// the typed `near-primitives 0.26` bindings can't decode (NEP-591
    /// global-contract account fields).
    rpc_url: String,
    /// Contract account ID
    contract_id: AccountId,
}

impl NearClient {
    /// Create new NEAR client (read-only)
    ///
    /// Only needs RPC URL and contract ID - no private key required for reading.
    pub fn new(rpc_url: &str, contract_id: &str) -> Result<Self> {
        let rpc_client = rpc_client(rpc_url);
        let rpc_client_tx = rpc_client_tx(rpc_url);

        let contract_id = AccountId::from_str(contract_id)
            .context("Invalid contract ID")?;

        Ok(Self {
            rpc_client,
            rpc_client_tx,
            rpc_url: rpc_url.to_string(),
            contract_id,
        })
    }

    /// The contract this keystore reads wallet policy from — also the NEP-413
    /// `recipient` that wallet approvers sign their approval messages against.
    pub fn contract_id(&self) -> &AccountId {
        &self.contract_id
    }

    // NOTE (Phase 4.3): the four `get_secrets`, `get_secrets_by_wasm_hash`,
    // `get_secrets_by_project`, and `get_secrets_by_system` methods that
    // used to live here were superseded by [`Self::get_secret_with_vault`]
    // below. That single method returns both the profile and the
    // on-chain vault binding in one round-trip; the per-accessor
    // dispatch now lives in `api.rs::accessor_to_contract_json`.
    // Keeping the dispatch in one place avoids serialisation drift
    // between the worker-side enum and the contract-side enum.

    /// Get account NEAR balance in yoctoNEAR
    pub async fn get_account_balance(&self, account_id: &str) -> Result<u128> {
        let account_id_parsed = AccountId::from_str(account_id)
            .context("Invalid account ID")?;

        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::ViewAccount {
                account_id: account_id_parsed,
            },
        };

        let response = self
            .rpc_client
            .call(query)
            .await
            .context("Failed to query account")?;

        match response.kind {
            QueryResponseKind::ViewAccount(account_view) => Ok(account_view.amount.as_yoctonear()),
            _ => anyhow::bail!("Unexpected query response"),
        }
    }

    /// Get fungible token balance
    ///
    /// Calls: ft_contract.ft_balance_of({"account_id": account_id})
    /// Returns: Balance as u128 (from JSON string)
    pub async fn get_ft_balance(&self, ft_contract: &str, account_id: &str) -> Result<u128> {
        let ft_contract_id = AccountId::from_str(ft_contract)
            .context("Invalid FT contract ID")?;

        let args = json!({
            "account_id": account_id,
        });

        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: ft_contract_id,
                method_name: "ft_balance_of".to_string(),
                args: args.to_string().into_bytes().into(),
            },
        };

        let response = self
            .rpc_client
            .call(query)
            .await
            .context("Failed to query FT balance")?;

        let result = match response.kind {
            QueryResponseKind::CallResult(result) => result.result,
            _ => anyhow::bail!("Unexpected query response"),
        };

        // FT balance is returned as JSON string: "123456789"
        let balance_str: String = serde_json::from_slice(&result)
            .context("Failed to parse FT balance response")?;

        balance_str.parse::<u128>()
            .context("Failed to parse balance as u128")
    }

    /// Check if account owns NFT(s) from given contract
    ///
    /// If token_id is Some("123"), checks ownership of that specific token
    /// If token_id is None, checks if account owns any token from this contract
    ///
    /// Calls:
    /// - token_id = Some: nft_contract.nft_token({"token_id": "123"})
    /// - token_id = None: nft_contract.nft_tokens_for_owner({"account_id": account_id, "limit": 1})
    pub async fn check_nft_ownership(&self, nft_contract: &str, account_id: &str, token_id: Option<&str>) -> Result<bool> {
        let nft_contract_id = AccountId::from_str(nft_contract)
            .context("Invalid NFT contract ID")?;

        if let Some(specific_token_id) = token_id {
            // Check specific token ownership
            let args = json!({
                "token_id": specific_token_id,
            });

            let query = methods::query::RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: near_primitives::views::QueryRequest::CallFunction {
                    account_id: nft_contract_id,
                    method_name: "nft_token".to_string(),
                    args: args.to_string().into_bytes().into(),
                },
            };

            let response = self
                .rpc_client
                .call(query)
                .await
                .context("Failed to query specific NFT token")?;

            let result = match response.kind {
                QueryResponseKind::CallResult(result) => result.result,
                _ => anyhow::bail!("Unexpected query response"),
            };

            // NFT standard returns: {token_id, owner_id, ...} or null if not found
            let token: Option<serde_json::Value> = serde_json::from_slice(&result)
                .context("Failed to parse NFT token response")?;

            match token {
                // The standard's answer for a token that does not exist.
                None => Ok(false),
                Some(token_data) => match token_data.get("owner_id").and_then(|v| v.as_str()) {
                    Some(owner_id) => Ok(owner_id == account_id),
                    // A token that exists and states no owner is an answer we
                    // cannot read, not an answer of "no". Under `Not` a false
                    // here would ADMIT, so it is an error at every combinator.
                    None => anyhow::bail!(
                        "NftOwned cannot be evaluated: {nft_contract} answered token {specific_token_id:?} with no owner_id"
                    ),
                },
            }
        } else {
            // Check if owns any token from this contract
            let args = json!({
                "account_id": account_id,
                "limit": 1,  // We only need to check if at least one NFT exists
            });

            let query = methods::query::RpcQueryRequest {
                block_reference: BlockReference::latest(),
                request: near_primitives::views::QueryRequest::CallFunction {
                    account_id: nft_contract_id,
                    method_name: "nft_tokens_for_owner".to_string(),
                    args: args.to_string().into_bytes().into(),
                },
            };

            let response = self
                .rpc_client
                .call(query)
                .await
                .context("Failed to query NFT ownership")?;

            let result = match response.kind {
                QueryResponseKind::CallResult(result) => result.result,
                _ => anyhow::bail!("Unexpected query response"),
            };

            // NFT standard returns array of tokens: [{token_id, owner_id, ...}, ...]
            let tokens: Vec<serde_json::Value> = serde_json::from_slice(&result)
                .context("Failed to parse NFT tokens response")?;

            Ok(!tokens.is_empty())
        }
    }

    // (Removed Phase 4.3): get_secrets_by_wasm_hash / by_project /
    // by_system. Their callers in api.rs were rewritten to use
    // [`Self::get_secret_with_vault`] which folds all four accessor
    // variants into one helper plus the on-chain vault binding. See the
    // top-of-file comment.

    /// Check if account is member of DAO role (Sputnik v2 compatible)
    ///
    /// Calls: dao_contract.get_policy()
    /// Returns: Policy { roles: [...], ... }
    ///
    /// Role kinds:
    /// - "Everyone" - all users
    /// - "Group" - explicit list of accounts { "kind": { "Group": ["alice.near", ...] } }
    /// - "Member" - token holders with balance >= threshold { "kind": { "Member": "1000000" } }
    pub async fn check_dao_membership(&self, dao_contract: &str, account_id: &str, role_name: &str) -> Result<bool> {
        let dao_contract_id = AccountId::from_str(dao_contract)
            .context("Invalid DAO contract ID")?;

        tracing::debug!(
            dao_contract = %dao_contract,
            account_id = %account_id,
            role_name = %role_name,
            "Checking DAO membership"
        );

        // Call get_policy()
        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: dao_contract_id,
                method_name: "get_policy".to_string(),
                args: vec![].into(), // no arguments
            },
        };

        let response = self
            .rpc_client
            .call(query)
            .await
            .context("Failed to query DAO policy")?;

        let result = match response.kind {
            QueryResponseKind::CallResult(result) => result.result,
            _ => anyhow::bail!("Unexpected query response"),
        };

        // Parse policy response
        let policy: serde_json::Value = serde_json::from_slice(&result)
            .context("Failed to parse DAO policy response")?;

        tracing::debug!(
            policy_json = %serde_json::to_string_pretty(&policy).unwrap_or_default(),
            "Received DAO policy"
        );

        // Find role by name in policy.roles array
        let roles = policy
            .get("roles")
            .and_then(|v| v.as_array())
            .context("Policy missing 'roles' array")?;

        for role in roles {
            let name = role.get("name").and_then(|v| v.as_str());
            if name != Some(role_name) {
                continue; // Not the role we're looking for
            }

            tracing::debug!(
                role_name = %role_name,
                role_data = %serde_json::to_string(role).unwrap_or_default(),
                "Found matching role"
            );

            // Check role kind
            let kind = role.get("kind").context("Role missing 'kind' field")?;

            // Check if it's "Everyone" (unit variant as string)
            if kind.is_string() && kind.as_str() == Some("Everyone") {
                tracing::debug!("Role kind is Everyone - access granted");
                return Ok(true);
            }

            // Check if it's "Group" variant { "Group": ["alice.near", ...] }
            if let Some(group_accounts) = kind.get("Group").and_then(|v| v.as_array()) {
                let is_member = group_accounts.iter().any(|acc| {
                    acc.as_str() == Some(account_id)
                });

                tracing::debug!(
                    kind = "Group",
                    accounts_count = group_accounts.len(),
                    is_member = %is_member,
                    "Checked Group membership"
                );

                return Ok(is_member);
            }

            // "Member" variant requires token balance check - not supported
            // Use "Group" role with explicit account list instead
            if kind.get("Member").is_some() {
                anyhow::bail!(
                    "DAO role '{}' uses Member kind which requires token balance checking. \
                    This is not supported. Please use a Group role with explicit account list instead.",
                    role_name
                );
            }

            // A role whose kind this build does not understand is an answer we
            // cannot read. Under `Not` a false here would ADMIT everyone, so it
            // refuses at every combinator instead.
            anyhow::bail!(
                "DaoMember cannot be evaluated: role '{}' on {} has kind {}, which this keystore does not understand",
                role_name,
                dao_contract,
                serde_json::to_string(kind).unwrap_or_default()
            );
        }

        // Role not found in policy
        tracing::debug!(
            role_name = %role_name,
            available_roles = ?roles.iter()
                .filter_map(|r| r.get("name").and_then(|v| v.as_str()))
                .collect::<Vec<_>>(),
            "Role not found in DAO policy"
        );

        Ok(false)
    }

    /// Get wallet policy from contract
    ///
    /// Calls: contract.get_wallet_policy(wallet_pubkey)
    /// Returns: Option<WalletPolicyView> { owner, encrypted_data, frozen, updated_at }
    pub async fn get_wallet_policy(
        &self,
        wallet_pubkey: &str,
    ) -> Result<Option<serde_json::Value>> {
        tracing::debug!(
            contract = %self.contract_id,
            wallet_pubkey = %wallet_pubkey,
            "Reading wallet policy from contract"
        );

        let args = json!({
            "wallet_pubkey": wallet_pubkey,
        });

        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: self.contract_id.clone(),
                method_name: "get_wallet_policy".to_string(),
                args: args.to_string().into_bytes().into(),
            },
        };

        let response = self
            .rpc_client
            .call(query)
            .await
            .context("Failed to query wallet policy")?;

        let result = match response.kind {
            QueryResponseKind::CallResult(result) => result.result,
            _ => anyhow::bail!("Unexpected query response"),
        };

        let policy: Option<serde_json::Value> = serde_json::from_slice(&result)
            .context("Failed to parse wallet policy response")?;

        Ok(policy)
    }

    /// Query access key nonce for transaction construction.
    ///
    /// Returns (nonce, block_hash) needed to build a NEAR transaction.
    pub async fn query_access_key(
        &self,
        account_id: &str,
        public_key: &near_crypto::PublicKey,
    ) -> Result<(u64, near_primitives::hash::CryptoHash)> {
        use near_primitives::types::Finality;

        let account_id_parsed = AccountId::from_str(account_id)
            .context("Invalid account ID")?;

        // Optimistic finality (most-recent block), NOT Final. Final lags ~1-2 blocks
        // behind, so a caller that broadcasts a tx with `broadcast_tx_commit` and then
        // immediately re-signs (e.g. the coordinator's sequential create_payment_key
        // store→storage→ft_transfer chain) would read the PRE-increment nonce under Final
        // and collide. Optimistic reflects the just-committed nonce. This does NOT
        // reintroduce a caller-chosen nonce — the signer still uses rpc_nonce+1, so the
        // one-approval-one-tx property holds.
        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::Finality(Finality::None),
            request: near_primitives::views::QueryRequest::ViewAccessKey {
                account_id: account_id_parsed,
                public_key: public_key.clone(),
            },
        };

        let response = self
            .rpc_client
            .call(query)
            .await
            .context("Failed to query access key")?;

        let nonce = match response.kind {
            QueryResponseKind::AccessKey(access_key) => access_key.nonce,
            _ => anyhow::bail!("Unexpected query response"),
        };

        let block_hash = response.block_hash;

        Ok((nonce, block_hash))
    }

    /// Combined secret + vault binding lookup (Phase 4 plan, Mechanism 2).
    ///
    /// Replaces the four `get_secrets*` calls when the keystore-worker
    /// also needs the per-secret vault binding (which it does for
    /// Phase 4 multi-customer decryption). One round-trip instead of
    /// two; the contract's `get_secret_with_vault` view returns both
    /// fields atomically.
    ///
    /// `accessor_json` is the externally-tagged contract-form JSON of
    /// the accessor (e.g. `{"Repo": {"repo": ..., "branch": ...}}`).
    /// Caller is responsible for whatever normalisation the underlying
    /// accessor type requires (e.g. `normalize_repo_url` for Repo);
    /// this method does NOT normalise — keeping it transparent matches
    /// the existing per-accessor `get_secrets*` behaviour.
    ///
    /// Returns a [`SecretWithVault`] with two independently-`None`-able
    /// fields:
    /// * `profile` — the SecretProfile JSON value if the secret exists,
    ///   `None` if not found (same fallback rules as the contract's
    ///   `get_secrets`, including Repo wildcard).
    /// * `vault_id` — the on-chain vault binding for that secret,
    ///   `None` if the secret is on the default OutLayer master.
    pub async fn get_secret_with_vault(
        &self,
        accessor_json: serde_json::Value,
        profile: &str,
        owner: &str,
    ) -> Result<SecretWithVault> {
        let args = json!({
            "accessor": accessor_json,
            "profile": profile,
            "owner": owner,
        });

        let response = self
            .view_call_json(&self.contract_id.clone(), "get_secret_with_vault", args)
            .await?;

        // SecretWithVault { profile: Option<SecretProfile>, vault_id: Option<AccountId> }
        let profile = response
            .get("profile")
            .cloned()
            .and_then(|v| if v.is_null() { None } else { Some(v) });
        let vault_id = response
            .get("vault_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(SecretWithVault { profile, vault_id })
    }

    /// Fetch the contract hash of an account.
    ///
    /// Returns the base58-encoded sha256 of the WASM code the account
    /// will execute, regardless of whether the bytes were deployed
    /// inline (`DeployContract`) or referenced from on-chain storage
    /// (NEP-591 `UseGlobalContract`). For inline deploys the value
    /// comes from `code_hash`; for global-contract deploys NEAR leaves
    /// `code_hash` at the all-zeros sentinel
    /// (`11111111111111111111111111111111`) and stores the real hash
    /// in `global_contract_hash`. We surface both as the same opaque
    /// string so the DAO whitelist (which keys on the WASM hash) can
    /// validate either deploy shape.
    ///
    /// Returns `None` when the account has neither — typically a
    /// not-deployed account.
    ///
    /// Implementation note: `near-primitives 0.26` predates NEP-591, so
    /// its `AccountView` doesn't carry the `global_contract_hash` field.
    /// We hit JSON-RPC directly with `reqwest` and parse both fields
    /// from the raw response instead of bumping the toolchain just for
    /// this one read.
    pub async fn view_account_code_hash(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<String>> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": "view_account",
            "method": "query",
            "params": {
                "request_type": "view_account",
                "finality": "final",
                "account_id": account_id.as_str(),
            },
        });
        let resp: serde_json::Value = raw_rpc_client()
            .post(&self.rpc_url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("view_account({account_id}): RPC POST failed"))?
            .json()
            .await
            .with_context(|| format!("view_account({account_id}): RPC body not JSON"))?;

        if let Some(err) = resp.get("error") {
            anyhow::bail!("view_account({account_id}) RPC error: {err}");
        }

        let result = resp
            .get("result")
            .with_context(|| format!("view_account({account_id}): no result field"))?;

        let inline = result
            .get("code_hash")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let global = result
            .get("global_contract_hash")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // Inline DeployContract → code_hash holds the real WASM hash.
        // UseGlobalContract → code_hash is the all-zeros sentinel, the
        //                     real hash is in global_contract_hash.
        let chosen = match (inline.as_deref(), global) {
            (Some(s), Some(g)) if s == "11111111111111111111111111111111" => Some(g),
            (Some(s), _) if s == "11111111111111111111111111111111" => None,
            (Some(s), _) => Some(s.to_string()),
            (None, g) => g,
        };

        Ok(chosen)
    }

    /// Fetch the typed access-key list for an account.
    ///
    /// Returns the full `AccessKeyInfoView` array — caller inspects
    /// `permission` (FullAccess vs FunctionCall) and policy fields.
    pub async fn view_access_key_list_typed(
        &self,
        account_id: &AccountId,
    ) -> Result<Vec<near_primitives::views::AccessKeyInfoView>> {
        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::ViewAccessKeyList {
                account_id: account_id.clone(),
            },
        };
        let response = self
            .rpc_client
            .call(query)
            .await
            .with_context(|| format!("view_access_key_list({account_id})"))?;

        match response.kind {
            QueryResponseKind::AccessKeyList(list) => Ok(list.keys),
            _ => anyhow::bail!("Unexpected response kind for view_access_key_list"),
        }
    }

    /// Submit a function-call transaction signed by `signer`, calling
    /// `receiver.method(args)`. Waits for finality (`broadcast_tx_commit`)
    /// and returns the tx hash + raw success-value bytes.
    ///
    /// Used by `/sign-vault-verification` (and future `/admin/ban-vault`)
    /// to land a tx via the worker's approved access key on the
    /// keystore-dao contract. NOT for CKD requests — those go through
    /// `mpc_ckd::MpcCkdClient::request_*_secret`, which hand-decodes
    /// the BLS-encrypted CkdResponse.
    ///
    /// **CONCURRENCY (Phase 4.4 audit C1)**: this method does NOT
    /// internally serialize callers. NEAR access keys carry a
    /// monotonic nonce; concurrent calls with the same `signer` race
    /// to read nonce N and submit txs with `nonce = N+1`, of which
    /// only one wins. The loser surfaces an opaque `InvalidNonce`.
    /// Callers using a SHARED signer (e.g. `MpcContext::keystore_dao_signer`,
    /// which is bound to one access key on keystore-dao) MUST acquire
    /// the corresponding `MpcContext::signer_nonce_lock` for the
    /// build+broadcast critical section. Callers with a per-call
    /// fresh signer (e.g. `mpc_ckd::add_customer`'s vault signer)
    /// don't need the lock — each vault has its own access key.
    pub async fn submit_function_call(
        &self,
        signer: &near_crypto::InMemorySigner,
        receiver_id: &AccountId,
        method_name: &str,
        args: serde_json::Value,
        gas: u64,
        deposit: u128,
    ) -> Result<FunctionCallOutcome> {
        use near_primitives::transaction::{Action, FunctionCallAction, Transaction, TransactionV0};
        use near_primitives::types::Finality;

        let args_bytes = serde_json::to_vec(&args)
            .context("Failed to serialize args for function call")?;

        // Get nonce (with retry — same justification as in
        // mpc_ckd::call_mpc_contract: a freshly-added access key may
        // not be visible to the RPC node yet).
        let mut nonce = 0u64;
        let max_retries = 5;
        for attempt in 1..=max_retries {
            let access_key_query = methods::query::RpcQueryRequest {
                block_reference: BlockReference::Finality(Finality::Final),
                request: near_primitives::views::QueryRequest::ViewAccessKey {
                    account_id: signer.account_id.clone(),
                    public_key: signer.public_key.clone(),
                },
            };
            match self.rpc_client.call(access_key_query).await {
                Ok(response) => {
                    if let QueryResponseKind::AccessKey(view) = response.kind {
                        nonce = view.nonce + 1;
                        break;
                    } else {
                        anyhow::bail!("Failed to get access key nonce");
                    }
                }
                Err(e) if attempt < max_retries => {
                    tracing::warn!(
                        attempt,
                        max_retries,
                        "Access key not visible at RPC, retrying in 3s... ({e})"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                }
                Err(e) => {
                    return Err(anyhow::Error::from(e))
                        .context("Failed to query access key after retries")
                }
            }
        }

        let block = self
            .rpc_client
            .call(methods::block::RpcBlockRequest {
                block_reference: BlockReference::Finality(Finality::Final),
            })
            .await
            .context("Failed to get latest block")?;

        let transaction_v0 = TransactionV0 {
            signer_id: signer.account_id.clone(),
            public_key: signer.public_key.clone(),
            nonce,
            receiver_id: receiver_id.clone(),
            block_hash: block.header.hash,
            actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
                method_name: method_name.to_string(),
                args: args_bytes,
                gas: Gas::from_gas(gas),
                deposit: Balance::from_yoctonear(deposit),
            }))],
        };
        let transaction = Transaction::V0(transaction_v0);
        let tx_hash = transaction.get_hash_and_size().0;
        let signature = signer.sign(tx_hash.as_ref());
        let signed = near_primitives::transaction::SignedTransaction::new(signature, transaction);

        let request = methods::broadcast_tx_commit::RpcBroadcastTxCommitRequest {
            signed_transaction: signed,
        };
        let outcome = self
            .rpc_client_tx
            .call(request)
            .await
            .with_context(|| format!("broadcast_tx_commit for {receiver_id}.{method_name}"))?;

        match &outcome.status {
            near_primitives::views::FinalExecutionStatus::SuccessValue(value) => {
                Ok(FunctionCallOutcome {
                    tx_hash: tx_hash.to_string(),
                    success_value: value.clone(),
                })
            }
            near_primitives::views::FinalExecutionStatus::Failure(err) => {
                anyhow::bail!("{receiver_id}.{method_name} tx failed: {err:?}")
            }
            other => {
                anyhow::bail!("{receiver_id}.{method_name} tx unexpected status: {other:?}")
            }
        }
    }

    /// Generic view-call against an arbitrary contract.
    ///
    /// Returns the raw JSON response value. Caller is responsible for
    /// `serde_json::from_value` into the expected shape.
    ///
    /// Used for cross-contract reads where the target is **not** the
    /// secrets contract bound to this client (e.g. reading
    /// `is_vault_verified` from `keystore-dao`, or `get_secret_with_vault`
    /// once Phase 4.3 lands and we want a single round-trip combined view).
    pub async fn view_call_json(
        &self,
        contract_id: &AccountId,
        method_name: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value> {
        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::CallFunction {
                account_id: contract_id.clone(),
                method_name: method_name.to_string(),
                args: args.to_string().into_bytes().into(),
            },
        };

        let response = self
            .rpc_client
            .call(query)
            .await
            .with_context(|| format!("view_call_json {}.{}", contract_id, method_name))?;

        let result_bytes = match response.kind {
            QueryResponseKind::CallResult(result) => result.result,
            _ => anyhow::bail!("Unexpected query response for {}.{}", contract_id, method_name),
        };

        serde_json::from_slice(&result_bytes).with_context(|| {
            format!(
                "view_call_json: response from {}.{} was not valid JSON: {}",
                contract_id,
                method_name,
                String::from_utf8_lossy(&result_bytes)
            )
        })
    }

    /// Verify that a public key belongs to an account
    ///
    /// Calls: view_access_key_list for account_id
    /// Returns: Ok(()) if public_key is found, Err if not found or RPC error
    pub async fn verify_access_key_owner(
        &self,
        account_id: &str,
        public_key: &str,
    ) -> Result<()> {
        let account_id_parsed = AccountId::from_str(account_id)
            .context("Invalid account ID")?;

        tracing::debug!(
            account_id = %account_id,
            public_key = %public_key,
            "Verifying access key ownership"
        );

        let query = methods::query::RpcQueryRequest {
            block_reference: BlockReference::latest(),
            request: near_primitives::views::QueryRequest::ViewAccessKeyList {
                account_id: account_id_parsed,
            },
        };

        let response = self
            .rpc_client
            .call(query)
            .await
            .context("Failed to query access keys")?;

        let access_keys = match response.kind {
            QueryResponseKind::AccessKeyList(list) => list.keys,
            _ => anyhow::bail!("Unexpected query response"),
        };

        // Check if public_key is in the access key list
        let key_found = access_keys.iter().any(|key| {
            key.public_key.to_string() == public_key
        });

        if key_found {
            tracing::debug!(
                account_id = %account_id,
                public_key = %public_key,
                "✅ Access key verified"
            );
            Ok(())
        } else {
            tracing::warn!(
                account_id = %account_id,
                public_key = %public_key,
                keys_count = access_keys.len(),
                "❌ Access key not found for account"
            );
            anyhow::bail!(
                "Public key {} does not belong to account {}",
                public_key, account_id
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RPC client must send `Content-Type: application/json`.
    ///
    /// `JsonRpcClient::with()` — which we use to attach a timeout — does NOT set it, unlike
    /// `JsonRpcClient::connect()`, and the crate sends its payload with `.body()`. Omitting it
    /// makes every NEAR RPC call return HTTP 415, i.e. the keystore cannot read the chain at
    /// all: no secrets, no policies, no CKD. This test talks to a throwaway socket and asserts
    /// on the bytes we actually put on the wire.
    #[tokio::test]
    async fn rpc_client_sends_json_content_type() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });

        // The response is deliberately not valid JSON-RPC; only the request matters here.
        let client = rpc_client(&format!("http://{}", addr));
        let _ = client.call(methods::status::RpcStatusRequest).await;

        let request = server.join().expect("server thread");
        assert!(
            request.to_lowercase().contains("content-type: application/json"),
            "RPC request is missing Content-Type: application/json — NEAR answers 415:\n{request}"
        );
    }
}
