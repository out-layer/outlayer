//! Configuration management for keystore worker
//!
//! Loads configuration from environment variables with validation.

use anyhow::{Context, Result};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct Config {
    /// Server bind address
    pub server_addr: SocketAddr,

    /// NEAR network (testnet, mainnet)
    #[allow(dead_code)]
    pub near_network: String,

    /// The one URL every read of the chain goes through: the worker-key check, the DAO, the
    /// secrets, CKD. Fixed in code for a production DAO; see [`resolve_chain`].
    pub near_rpc_url: RpcUrl,

    /// Contract the secrets and their access conditions are read from. Fixed in code for a
    /// production DAO; see [`resolve_chain`].
    pub near_contract_id: Option<String>,

    /// OffchainVM contract account ID
    pub offchainvm_contract_id: String,

    /// Allowed worker token hashes (SHA256) - for TEE workers only
    /// Grants access to: /decrypt, /encrypt, /decrypt-raw, /storage/*
    pub allowed_worker_token_hashes: Vec<String>,

    /// Allowed coordinator token hashes (SHA256) - for coordinator only
    /// Grants access to: /add_generated_secret, /update_user_secrets
    pub allowed_coordinator_token_hashes: Vec<String>,

    /// TEE mode (outlayer_tee, none)
    pub tee_mode: TeeMode,

    /// Operator account where TEE worker keys are registered as access keys (e.g., "worker.outlayer.testnet").
    /// Fixed in code for a production DAO; see [`resolve_chain`].
    pub operator_account_id: Option<String>,

    /// Signature scheme for the keystore's own registration key.
    /// ed25519 (default) or ml-dsa-65 (FIPS-204 post-quantum). Set via KEYSTORE_KEY_TYPE.
    /// Note: per-vault TEE keys (mpc_ckd Layer 1) stay ed25519 — they are derived
    /// deterministically from the master secret and are a separate concern.
    pub keystore_key_type: near_crypto::KeyType,

    /// Which WORKER signature schemes this keystore accepts for TEE-session challenge-response.
    /// Set via TEE_ALLOWED_KEY_TYPES, e.g. "ed25519,ml-dsa-65". Default: ed25519 only.
    pub tee_allowed_key_types: shared_tee_helpers::AllowedKeyTypes,
}

/// A NEAR RPC URL that may carry an API key. It is never printed: `Debug` shows the origin and
/// whether a key is on it, and there is no `Display`.
#[derive(Clone, PartialEq, Eq)]
pub struct RpcUrl(String);

impl RpcUrl {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The URL up to its query, i.e. without the key.
    pub fn public(&self) -> &str {
        self.0.split('?').next().unwrap_or_default()
    }
}

impl std::fmt::Debug for RpcUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keyed = self.0.contains('?');
        write!(f, "RpcUrl({}{})", self.public(), if keyed { ", keyed" } else { "" })
    }
}

impl From<&str> for RpcUrl {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for RpcUrl {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// What a production keystore DAO fixes in code.
///
/// The env is not part of a keystore's measurement, so an operator restarts the same approved
/// build with any env it likes. Three values decide who is admitted and what is decrypted:
/// - the operator account: a session opens for a FunctionCall key found on it;
/// - the RPC: it answers that check, and every other read of the chain — a proxy would answer
///   "FunctionCall" for the operator's own key;
/// - the secrets contract: its access conditions decide who gets a plaintext — a copy of a real
///   blob in another contract, under a condition that admits anyone, would decrypt with the real
///   master, because the encryption seed does not name the contract.
///
/// The DAO is the anchor because replacing it gains nothing: CKD derives the master for the DAO
/// account, so another DAO opens no real secret. The RPC host cannot be read from the DAO: that
/// read needs an RPC, and a proxy would return its own URL.
struct ProdDao {
    dao: &'static str,
    operator_account: &'static str,
    near_contract: &'static str,
    rpc_host: &'static str,
}

const PROD_DAOS: [ProdDao; 2] = [
    ProdDao {
        dao: "dao.outlayer.near",
        operator_account: "worker.outlayer.near",
        near_contract: "outlayer.near",
        rpc_host: "https://rpc.mainnet.fastnear.com",
    },
    ProdDao {
        dao: "dao.outlayer.testnet",
        operator_account: "worker.outlayer.testnet",
        near_contract: "outlayer.testnet",
        rpc_host: "https://rpc.testnet.fastnear.com",
    },
];

/// The env values [`resolve_chain`] reads.
#[derive(Default)]
pub struct ChainEnv {
    pub keystore_dao: Option<String>,
    pub near_rpc_url: Option<String>,
    pub near_rpc_api_key: Option<String>,
    pub operator_account_id: Option<String>,
    pub near_contract_id: Option<String>,
}

impl ChainEnv {
    fn from_env() -> Self {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        Self {
            keystore_dao: var("KEYSTORE_DAO_CONTRACT"),
            near_rpc_url: var("NEAR_RPC_URL"),
            near_rpc_api_key: var("NEAR_RPC_API_KEY"),
            operator_account_id: var("OPERATOR_ACCOUNT_ID"),
            near_contract_id: var("NEAR_CONTRACT_ID"),
        }
    }
}

/// Where the keystore reads the chain, and about which accounts.
#[derive(Debug)]
pub struct Chain {
    pub rpc_url: RpcUrl,
    pub operator_account_id: Option<String>,
    pub near_contract_id: Option<String>,
    /// A production DAO with no `NEAR_RPC_API_KEY`: the fixed host is used without a key.
    pub unkeyed_prod: bool,
}

/// Resolve the chain settings.
///
/// For a production DAO ([`PROD_DAOS`]) the operator account, the secrets contract and the RPC
/// host are the ones fixed in code. The env may only repeat the two accounts, may not set
/// `NEAR_RPC_URL` at all, and passes the RPC key as `NEAR_RPC_API_KEY`. Any other DAO, or none,
/// takes all of them from the env.
pub fn resolve_chain(env: &ChainEnv) -> Result<Chain> {
    let prod = env
        .keystore_dao
        .as_deref()
        .and_then(|dao| PROD_DAOS.iter().find(|p| p.dao == dao.trim()));

    let Some(prod) = prod else {
        if env.near_rpc_api_key.is_some() {
            anyhow::bail!(
                "NEAR_RPC_API_KEY is read only for the production keystore DAOs; for this DAO put \
                 the whole URL in NEAR_RPC_URL"
            );
        }
        let rpc_url = env.near_rpc_url.clone().context("NEAR_RPC_URL is required")?;
        return Ok(Chain {
            rpc_url: rpc_url.into(),
            operator_account_id: env.operator_account_id.clone(),
            near_contract_id: env.near_contract_id.clone(),
            unkeyed_prod: false,
        });
    };

    if env.near_rpc_url.is_some() {
        // The value is not quoted: it may carry a key.
        anyhow::bail!(
            "NEAR_RPC_URL cannot be set for {}: this keystore reads the chain only through {}. \
             Remove it and pass the API key as NEAR_RPC_API_KEY",
            prod.dao,
            prod.rpc_host
        );
    }
    for (name, given, fixed) in [
        ("OPERATOR_ACCOUNT_ID", &env.operator_account_id, prod.operator_account),
        ("NEAR_CONTRACT_ID", &env.near_contract_id, prod.near_contract),
    ] {
        if let Some(given) = given {
            if given.trim() != fixed {
                anyhow::bail!(
                    "{name}={} does not match {fixed}, the account fixed for {}. Remove it from \
                     the env",
                    given.trim(),
                    prod.dao
                );
            }
        }
    }

    let key = env.near_rpc_api_key.as_deref().map(str::trim);
    let rpc_url = match key {
        Some(key) => {
            if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~".contains(&b)) {
                // The value is not quoted: it is a secret.
                anyhow::bail!(
                    "NEAR_RPC_API_KEY has characters an API key does not (allowed: letters, \
                     digits, - _ . ~)"
                );
            }
            format!("{}/?apiKey={}", prod.rpc_host, key)
        }
        None => prod.rpc_host.to_string(),
    };
    Ok(Chain {
        rpc_url: rpc_url.into(),
        operator_account_id: Some(prod.operator_account.to_string()),
        near_contract_id: Some(prod.near_contract.to_string()),
        unkeyed_prod: key.is_none(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeMode {
    /// OutLayer TEE: TDX hardware + challenge-response sessions
    OutlayerTee,
    /// No TEE (dev mode)
    None,
}

impl std::fmt::Display for TeeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TeeMode::OutlayerTee => write!(f, "outlayer_tee"),
            TeeMode::None => write!(f, "none"),
        }
    }
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = std::env::var("SERVER_PORT")
            .unwrap_or_else(|_| "8081".to_string())
            .parse::<u16>()
            .context("Invalid SERVER_PORT")?;

        let server_addr = format!("{}:{}", host, port)
            .parse()
            .context("Invalid server address")?;

        let near_network = std::env::var("NEAR_NETWORK").unwrap_or_else(|_| "testnet".to_string());
        let chain = resolve_chain(&ChainEnv::from_env())?;
        if chain.unkeyed_prod {
            tracing::warn!(
                rpc = %chain.rpc_url.public(),
                "⚠️ NEAR_RPC_API_KEY is not set: the keystore reads the chain through the fixed \
                 RPC host WITHOUT a key. The unkeyed host is rate-limited; set NEAR_RPC_API_KEY"
            );
        }
        let offchainvm_contract_id = std::env::var("OFFCHAINVM_CONTRACT_ID")
            .context("OFFCHAINVM_CONTRACT_ID is required")?;

        let allowed_worker_token_hashes = std::env::var("ALLOWED_WORKER_TOKEN_HASHES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let allowed_coordinator_token_hashes = std::env::var("ALLOWED_COORDINATOR_TOKEN_HASHES")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let tee_mode_raw = std::env::var("TEE_MODE").unwrap_or_else(|_| "none".to_string());
        let tee_mode = match tee_mode_raw.trim().trim_matches('"').trim_matches('\'').to_lowercase().as_str() {
            "outlayer_tee" => TeeMode::OutlayerTee,
            "none" => TeeMode::None,
            other => anyhow::bail!("Invalid TEE_MODE: '{}' (raw: '{}'). Must be 'outlayer_tee' or 'none'", other, tee_mode_raw),
        };


        // Keystore registration key scheme (ed25519 | ml-dsa-65). Default ed25519.
        let keystore_key_type = {
            let s = std::env::var("KEYSTORE_KEY_TYPE").unwrap_or_else(|_| "ed25519".to_string());
            let s = s.trim().trim_matches('"').trim_matches('\'');
            s.parse::<near_crypto::KeyType>().map_err(|e| {
                anyhow::anyhow!("Invalid KEYSTORE_KEY_TYPE '{}': {} (use 'ed25519' or 'ml-dsa-65')", s, e)
            })?
        };

        // Which worker schemes this keystore admits for TEE-session auth (default ed25519).
        let tee_allowed_key_types = shared_tee_helpers::AllowedKeyTypes::from_csv(
            &std::env::var("TEE_ALLOWED_KEY_TYPES").unwrap_or_else(|_| "ed25519".to_string()),
        );

        Ok(Config {
            server_addr,
            near_network,
            near_rpc_url: chain.rpc_url,
            near_contract_id: chain.near_contract_id,
            offchainvm_contract_id,
            allowed_worker_token_hashes,
            allowed_coordinator_token_hashes,
            tee_mode,
            operator_account_id: chain.operator_account_id,
            keystore_key_type,
            tee_allowed_key_types,
        })
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.allowed_worker_token_hashes.is_empty() {
            tracing::warn!("No worker token hashes configured - worker endpoints will reject all requests");
        }

        if self.allowed_coordinator_token_hashes.is_empty() {
            tracing::warn!("No coordinator token hashes configured - coordinator endpoints will reject all requests");
        }

        if self.tee_mode == TeeMode::OutlayerTee && self.operator_account_id.is_none() {
            anyhow::bail!("TEE_MODE=outlayer_tee requires OPERATOR_ACCOUNT_ID to be set");
        }

        Ok(())
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    const KEY: &str = "ks-test-key_0123";

    fn prod(dao: &str) -> ChainEnv {
        ChainEnv { keystore_dao: Some(dao.to_string()), ..Default::default() }
    }

    fn err(env: &ChainEnv) -> String {
        format!("{:#}", resolve_chain(env).unwrap_err())
    }

    #[test]
    fn a_production_dao_reads_the_chain_through_the_fixed_host_about_the_fixed_accounts() {
        for (dao, host, operator, contract) in [
            ("dao.outlayer.near", "https://rpc.mainnet.fastnear.com", "worker.outlayer.near", "outlayer.near"),
            ("dao.outlayer.testnet", "https://rpc.testnet.fastnear.com", "worker.outlayer.testnet", "outlayer.testnet"),
        ] {
            let chain = resolve_chain(&ChainEnv { near_rpc_api_key: Some(KEY.into()), ..prod(dao) }).unwrap();
            assert_eq!(chain.rpc_url.as_str(), format!("{host}/?apiKey={KEY}"));
            assert_eq!(chain.operator_account_id.as_deref(), Some(operator));
            assert_eq!(chain.near_contract_id.as_deref(), Some(contract));
            assert!(!chain.unkeyed_prod);

            // The env may repeat the fixed accounts.
            let same = ChainEnv {
                operator_account_id: Some(operator.into()),
                near_contract_id: Some(contract.into()),
                ..prod(dao)
            };
            assert!(resolve_chain(&same).is_ok());
        }
    }

    #[test]
    fn a_production_dao_refuses_another_operator_account_naming_both() {
        let e = err(&ChainEnv { operator_account_id: Some("evil.near".into()), ..prod("dao.outlayer.near") });
        assert!(e.contains("OPERATOR_ACCOUNT_ID=evil.near") && e.contains("worker.outlayer.near"), "{e}");
    }

    #[test]
    fn a_production_dao_refuses_another_secrets_contract_naming_both() {
        let e = err(&ChainEnv { near_contract_id: Some("copy.near".into()), ..prod("dao.outlayer.near") });
        assert!(e.contains("NEAR_CONTRACT_ID=copy.near") && e.contains("outlayer.near"), "{e}");
    }

    #[test]
    fn a_production_dao_refuses_near_rpc_url_without_quoting_it() {
        let url = format!("https://proxy.example/?apiKey={KEY}");
        let e = err(&ChainEnv { near_rpc_url: Some(url), ..prod("dao.outlayer.testnet") });
        assert!(e.contains("NEAR_RPC_URL cannot be set for dao.outlayer.testnet"), "{e}");
        assert!(!e.contains("proxy.example") && !e.contains(KEY), "the value leaked: {e}");
    }

    #[test]
    fn a_production_dao_without_a_key_uses_the_fixed_host_unkeyed() {
        let chain = resolve_chain(&prod("dao.outlayer.near")).unwrap();
        assert_eq!(chain.rpc_url.as_str(), "https://rpc.mainnet.fastnear.com");
        assert!(chain.unkeyed_prod);
    }

    #[test]
    fn a_key_that_could_change_the_url_is_refused_without_quoting_it() {
        for bad in ["a&b=c", "a#frag", "a/b", "a b", "@evil.example"] {
            let e = err(&ChainEnv { near_rpc_api_key: Some(bad.into()), ..prod("dao.outlayer.near") });
            assert!(!e.contains(bad), "the value leaked: {e}");
        }
    }

    #[test]
    fn any_other_dao_takes_everything_from_the_env() {
        let env = ChainEnv {
            keystore_dao: Some("tod3.outlayer-alice.testnet".into()),
            near_rpc_url: Some("https://rpc.example/".into()),
            operator_account_id: Some("worker.tod3.outlayer-alice.testnet".into()),
            near_contract_id: Some("main.tod3.outlayer-alice.testnet".into()),
            ..Default::default()
        };
        let chain = resolve_chain(&env).unwrap();
        assert_eq!(chain.rpc_url.as_str(), "https://rpc.example/");
        assert_eq!(chain.operator_account_id.as_deref(), Some("worker.tod3.outlayer-alice.testnet"));
        assert_eq!(chain.near_contract_id.as_deref(), Some("main.tod3.outlayer-alice.testnet"));

        // No DAO at all (dev, no TEE): the same.
        let dev = ChainEnv { near_rpc_url: Some("http://localhost:3030".into()), ..Default::default() };
        assert_eq!(resolve_chain(&dev).unwrap().rpc_url.as_str(), "http://localhost:3030");

        // An env-configured DAO still needs its URL, and a key alone is not read.
        let e = err(&ChainEnv { keystore_dao: Some("tod3.outlayer-alice.testnet".into()), ..Default::default() });
        assert!(e.contains("NEAR_RPC_URL is required"), "{e}");
        let e = err(&ChainEnv { near_rpc_api_key: Some(KEY.into()), ..env });
        assert!(e.contains("NEAR_RPC_API_KEY is read only for the production"), "{e}");
    }

    #[test]
    fn the_rpc_url_is_never_printed_with_its_key() {
        let chain = resolve_chain(&ChainEnv { near_rpc_api_key: Some(KEY.into()), ..prod("dao.outlayer.near") }).unwrap();
        let shown = format!("{:?} {:?}", chain.rpc_url, chain);
        assert!(!shown.contains(KEY), "{shown}");
        assert!(shown.contains("https://rpc.mainnet.fastnear.com/") && shown.contains("keyed"), "{shown}");
    }
}
