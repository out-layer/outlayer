//! NEAR RPC Proxy for WASM host functions
//!
//! This module provides RPC proxy functionality that allows WASM code
//! to make NEAR RPC calls through host functions, with the worker
//! adding API keys and enforcing rate limits.
//!
//! ## Architecture
//!
//! ```text
//! WASM Code (near-rpc-guest crate)
//!     │ extern "C" calls
//!     ▼
//! Host Functions (host_functions.rs)
//!     │ calls RpcProxy
//!     ▼
//! RpcProxy (this module)
//!     │ HTTP with API key
//!     ▼
//! Real NEAR RPC (Pagoda/Infura/etc)
//! ```
//!
//! ## Security
//!
//! - API key is never exposed to WASM code
//! - Rate limiting prevents abuse
//! - Transaction methods can be disabled via config
//! - WASM must provide its own signing keys for transactions

pub mod methods;
//pub mod host_functions;  // Old async implementation
pub mod host_functions_sync;  // Working sync implementation

pub use host_functions_sync::{add_rpc_to_linker, RpcHostState};

use anyhow::{Context, Result};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

use crate::config::RpcProxyConfig;

/// RPC Proxy client with rate limiting
pub struct RpcProxy {
    /// HTTP client for RPC requests
    client: reqwest::Client,
    /// RPC URL (with API key embedded)
    rpc_url: String,
    /// Configuration
    config: RpcProxyConfig,
    /// Call counter for rate limiting (per execution)
    call_count: Arc<AtomicU32>,
}

impl RpcProxy {
    /// Create a new RPC proxy
    ///
    /// # Arguments
    /// * `config` - RPC proxy configuration
    /// * `fallback_rpc_url` - Fallback RPC URL if config.rpc_url is None
    pub fn new(config: RpcProxyConfig, fallback_rpc_url: &str) -> Result<Self> {
        let rpc_url = config.rpc_url.clone().unwrap_or_else(|| fallback_rpc_url.to_string());

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            client,
            rpc_url,
            config,
            call_count: Arc::new(AtomicU32::new(0)),
        })
    }

    /// Reset call counter (call at start of each WASM execution)
    #[allow(dead_code)]
    pub fn reset_call_count(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }

    /// Get current call count
    pub fn get_call_count(&self) -> u32 {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Check if proxy is enabled
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Check if transactions are allowed
    #[allow(dead_code)]
    pub fn allows_transactions(&self) -> bool {
        self.config.allow_transactions
    }

    /// Check rate limit and increment counter
    fn check_rate_limit(&self) -> Result<()> {
        let count = self.call_count.fetch_add(1, Ordering::SeqCst);
        if count >= self.config.max_calls_per_execution {
            anyhow::bail!(
                "RPC rate limit exceeded: {} calls (max: {})",
                count + 1,
                self.config.max_calls_per_execution
            );
        }
        Ok(())
    }

    /// Send raw JSON-RPC request to NEAR RPC
    ///
    /// This is the low-level method used by all RPC methods.
    pub async fn send_rpc_request(&self, request_body: &str) -> Result<String> {
        self.check_rate_limit()?;

        debug!("RPC request #{}: {}", self.get_call_count(),
            if request_body.len() > 200 { &request_body[..200] } else { request_body });

        let response = self
            .client
            .post(&self.rpc_url)
            .header("Content-Type", "application/json")
            .body(request_body.to_string())
            .send()
            .await
            .context("Failed to send RPC request")?;

        let status = response.status();
        if !status.is_success() {
            let error_text = response.text().await.unwrap_or_default();
            anyhow::bail!("RPC returned status {}: {}", status, error_text);
        }

        let body = response.text().await.context("Failed to read RPC response")?;

        debug!("RPC response: {}",
            if body.len() > 500 { &body[..500] } else { &body });

        Ok(body)
    }

    /// Send JSON-RPC request with method and params
    pub async fn call_method(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value> {
        // Check if this is a transaction method
        let is_tx_method = matches!(
            method,
            "send_tx" | "broadcast_tx_async" | "broadcast_tx_commit"
        );

        if is_tx_method && !self.config.allow_transactions {
            anyhow::bail!(
                "Transaction method '{}' is disabled. Set RPC_PROXY_ALLOW_TRANSACTIONS=true to enable.",
                method
            );
        }

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "proxy",
            "method": method,
            "params": params
        });

        let request_body = serde_json::to_string(&request)?;
        let response_body = self.send_rpc_request(&request_body).await?;

        let response: serde_json::Value = serde_json::from_str(&response_body)
            .context("Failed to parse RPC response as JSON")?;

        // Check for RPC error
        if let Some(error) = response.get("error") {
            warn!("RPC error: {}", error);
            // Return the error as part of response (let WASM handle it)
        }

        Ok(response)
    }

    /// Get RPC URL (for debugging, without exposing API key)
    /// Get RPC URL (INTERNAL USE ONLY - includes API key)
    pub(crate) fn get_rpc_url(&self) -> &str {
        &self.rpc_url
    }

    pub fn get_rpc_url_masked(&self) -> String {
        rpc_url_public(&self.rpc_url)
    }
}

/// The RPC endpoint as it may be said aloud: scheme, host, and whether a key is
/// on it. Never the query string, and never any `user:password@`.
///
/// This is deliberately not a redaction filter. A filter runs on a value that is
/// already whole, so one spelling it does not know prints the secret in full —
/// which is what happened: it matched `api_key=` and `apikey=` and never
/// `apiKey=`, FastNEAR's spelling, so every worker start-up logged a live key.
/// Building the safe half instead cannot fail that way, because the secret is
/// never in the string it builds.
pub fn rpc_url_public(url: &str) -> String {
    let (before_query, query) = match url.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (url, None),
    };

    // Drop any `user:password@` from the authority, then keep scheme://host.
    let (scheme, rest) = match before_query.split_once("://") {
        Some((s, r)) => (s, r),
        None => ("", before_query),
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let base = if scheme.is_empty() {
        host.to_string()
    } else {
        format!("{scheme}://{host}")
    };

    // Any query at all is treated as carrying a credential unless it plainly
    // does not mention one — erring towards saying less about it.
    let keyed = query
        .map(|q| !q.is_empty())
        .unwrap_or(false);

    if keyed {
        format!("{base} (keyed)")
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> RpcProxyConfig {
        RpcProxyConfig {
            enabled: true,
            rpc_url: None,
            max_calls_per_execution: 10,
            allow_transactions: false,
        }
    }

    #[test]
    fn test_outlayer_rpc_creation() {
        let config = create_test_config();
        let proxy = RpcProxy::new(config, "https://rpc.testnet.near.org").unwrap();

        assert!(proxy.is_enabled());
        assert!(!proxy.allows_transactions());
        assert_eq!(proxy.get_call_count(), 0);
    }

    #[test]
    fn test_rate_limiting() {
        let config = RpcProxyConfig {
            enabled: true,
            rpc_url: None,
            max_calls_per_execution: 3,
            allow_transactions: false,
        };
        let proxy = RpcProxy::new(config, "https://rpc.testnet.near.org").unwrap();

        // First 3 calls should succeed
        assert!(proxy.check_rate_limit().is_ok());
        assert!(proxy.check_rate_limit().is_ok());
        assert!(proxy.check_rate_limit().is_ok());

        // 4th call should fail
        assert!(proxy.check_rate_limit().is_err());
    }

    #[test]
    fn test_reset_call_count() {
        let config = create_test_config();
        let proxy = RpcProxy::new(config, "https://rpc.testnet.near.org").unwrap();

        proxy.check_rate_limit().unwrap();
        proxy.check_rate_limit().unwrap();
        assert_eq!(proxy.get_call_count(), 2);

        proxy.reset_call_count();
        assert_eq!(proxy.get_call_count(), 0);
    }

    #[test]
    fn test_url_masking() {
        let config = RpcProxyConfig {
            enabled: true,
            rpc_url: Some("https://rpc.near.org?api_key=secret123&other=value".to_string()),
            max_calls_per_execution: 100,
            allow_transactions: false,
        };
        let proxy = RpcProxy::new(config, "https://fallback.near.org").unwrap();

        // The whole query goes, not just the parameter a filter recognised.
        // What is left says which endpoint it is and that a credential is on it.
        let shown = proxy.get_rpc_url_masked();
        assert!(!shown.contains("secret123"));
        assert_eq!(shown, "https://rpc.near.org (keyed)");
    }
}

/// A live API key reached a terminal because a redaction filter did not know
/// FastNEAR's spelling of the parameter. These pin the replacement: it builds
/// the safe half rather than trying to subtract the unsafe one.
#[cfg(test)]
mod the_endpoint_can_be_said_aloud {
    use super::rpc_url_public;

    #[test]
    fn a_key_never_survives_in_any_spelling() {
        const SECRET: &str = "OutLayerRPCsecretvalue";
        for url in [
            format!("https://rpc.testnet.fastnear.com?apiKey={SECRET}"),
            format!("https://rpc.testnet.fastnear.com?api_key={SECRET}"),
            format!("https://rpc.testnet.fastnear.com?apikey={SECRET}"),
            format!("https://rpc.testnet.fastnear.com/?APIKEY={SECRET}&x=1"),
            format!("https://rpc.mainnet.fastnear.com/v1?token={SECRET}"),
            format!("https://user:{SECRET}@rpc.testnet.fastnear.com/"),
        ] {
            let shown = rpc_url_public(&url);
            assert!(
                !shown.contains(SECRET),
                "the key survived in {shown:?} (from a url spelled {url:?})"
            );
        }
    }

    #[test]
    fn it_still_says_which_endpoint_and_whether_it_is_keyed() {
        assert_eq!(
            rpc_url_public("https://rpc.testnet.fastnear.com?apiKey=abc"),
            "https://rpc.testnet.fastnear.com (keyed)"
        );
        assert_eq!(
            rpc_url_public("https://rpc.testnet.fastnear.com"),
            "https://rpc.testnet.fastnear.com"
        );
        assert_eq!(
            rpc_url_public("https://rpc.testnet.fastnear.com/path"),
            "https://rpc.testnet.fastnear.com",
            "the path is not the endpoint's identity and may carry a token of its own"
        );
    }

    #[test]
    fn an_unkeyed_endpoint_is_not_reported_as_keyed() {
        // The suites read this to decide whether they may run at all; calling an
        // unkeyed host "keyed" would let a rate-limited run be read as product
        // failure.
        assert!(!rpc_url_public("http://localhost:3030").contains("keyed"));
    }
}
