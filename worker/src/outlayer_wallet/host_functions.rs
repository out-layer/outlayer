//! Wallet host functions for WASM components
//!
//! Implements the `outlayer:wallet/api` WIT interface.
//! Proxies wallet operations to the coordinator's wallet REST API.

use anyhow::Result;
use tracing::debug;
use wasmtime::component::Linker;

// Generate bindings from WIT
wasmtime::component::bindgen!({
    path: "wit",
    world: "outlayer:wallet/wallet-host",
});

/// Result type: (json_result, error)
type WalletResult = (String, String);

/// Host-call budget per execution. A trading connector makes several
/// signatures plus status polls per run; the budget is there so a guest stuck
/// in a loop cannot hammer the coordinator, not to be the limit a working
/// connector meets first.
const MAX_CALLS: u32 = 200;

/// The sub-key an empty label names.
///
/// Every EVM key a guest can reach is a sub-key: the empty label is not "the
/// wallet's own key" but this one, so a module that names no label still signs
/// under `connector.{id}.default` and the wallet's own `wallet:{id}:evm` is
/// unreachable from inside a guest by construction — the path builder returns
/// a `String`, never an option. The wallet's own key is signable only from
/// outside, through the HTTPS wallet API, by the holder of the wallet's
/// credential.
const DEFAULT_LABEL: &str = "default";

/// Shape of a sub-key label: `[a-z0-9][a-z0-9_-]{0,31}`.
///
/// No `.` — it is the segment separator of the path the label becomes part of
/// (`connector.{id}.{label}`), so a label carrying one could spell a deeper
/// segment; no `:` — the keystore refuses it in any path. The shape is
/// validated, never normalised.
fn is_valid_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= 32
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && rest
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

/// The keystore path of a connector's sub-key.
///
/// Built HERE, from the `connector_id` of the verified manifest, never from
/// anything the guest sends: the guest names a label, the worker names the
/// connector. That is what keeps one connector from signing with another's
/// key under the same wallet.
fn sub_path(connector_id: &str, label: &str) -> String {
    format!("connector.{connector_id}.{label}")
}

/// Turn a coordinator error body into the one string a guest gets back.
///
/// `"<code>: <message>"`, plus `key=value` for anything the caller has to ACT
/// on. That shape is what `wallet.wit` documents (`"policy_denied: ..."`), and
/// a guest needs the code far more than the prose: `wallet_busy` clears by
/// itself and is worth retrying, `policy_denied` never will be. A guest handed
/// only a sentence has to match on wording, and wording changes.
///
/// Appended fields are the ones that change what to do next, not everything in
/// the body:
/// * `terminal` — retrying an Agent Connect refusal that is terminal spins
///   forever while the owner is never told to act;
/// * `in_flight_request_id` — what to poll instead of retrying blindly;
/// * `in_flight_operation` — what to wait FOR. It is set even when there is no
///   id yet, and it is the difference between retrying at once and backing off:
///   a transfer clears in seconds, a cross-chain withdraw can run for minutes.
///
/// A body that is not the expected JSON comes back verbatim: inventing a code
/// for it would be worse than passing on what the server actually said.
fn guest_error(body: &str) -> String {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return body.to_string();
    };
    let Some(code) = json["error"].as_str() else {
        // No code to lead with; the message alone still beats raw JSON.
        return json["message"].as_str().unwrap_or(body).to_string();
    };
    let message = json["message"].as_str().unwrap_or_default();

    let mut out = if message.is_empty() {
        code.to_string()
    } else {
        format!("{code}: {message}")
    };
    if let Some(terminal) = json["terminal"].as_bool() {
        out.push_str(&format!(" terminal={terminal}"));
    }
    if let Some(id) = json["in_flight_request_id"].as_str() {
        out.push_str(&format!(" in_flight_request_id={id}"));
    }
    // LAST, and the order is load-bearing: the guest reads these fields off the
    // END and truncates the message at each one it takes. Appended after the
    // id, it is removed along with it; appended before, it would be left
    // dangling in the message text once the id was stripped.
    if let Some(op) = json["in_flight_operation"].as_str() {
        out.push_str(&format!(" in_flight_operation={op}"));
    }
    out
}


/// A non-2xx answer as the guest's error string — never empty.
///
/// An empty error IS success under the `(result, error)` contract, so a
/// refusal that arrived with an empty body (a proxy, a timeout page stripped
/// to nothing) would read as a call that worked and returned nothing. The
/// status is the one fact such an answer still carries, so it becomes the code.
fn coordinator_failure(status: u16, body: &str) -> String {
    let described = guest_error(body);
    if described.trim().is_empty() {
        format!("http_{status}: the coordinator answered {status} with an empty body")
    } else {
        described
    }
}

/// Host state for wallet functions
pub struct WalletHostState {
    /// Wallet ID from execution context (e.g. "ed25519:abc...")
    wallet_id: String,
    /// Blocking HTTP client for coordinator wallet API calls
    http_client: reqwest::blocking::Client,
    /// Coordinator base URL (e.g. "http://localhost:8080")
    coordinator_url: String,
    /// Wallet signature for authenticating requests
    /// Pre-computed by the worker using the keystore
    wallet_auth_token: String,
    /// Call counter for rate limiting
    call_count: u32,
    /// Max wallet calls per execution
    max_calls: u32,
    /// `connector_id` from the running artefact's verified manifest. `None` for
    /// an ordinary project, which then has no sub-keys.
    connector_id: Option<String>,
}

impl WalletHostState {
    /// Create wallet host state
    ///
    /// `wallet_id` is the wallet pubkey identifier from X-Wallet-Id header.
    /// `coordinator_url` is the coordinator base URL.
    /// `wallet_auth_token` is the internal auth token for coordinator wallet API.
    /// `connector_id` is the running artefact's connector identity from its
    /// verified manifest, or `None` for a project that has none.
    pub fn new(
        wallet_id: &str,
        coordinator_url: &str,
        wallet_auth_token: &str,
        connector_id: Option<&str>,
    ) -> Self {
        let http_client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build wallet HTTP client");

        Self {
            wallet_id: wallet_id.to_string(),
            http_client,
            coordinator_url: coordinator_url.to_string(),
            wallet_auth_token: wallet_auth_token.to_string(),
            call_count: 0,
            max_calls: MAX_CALLS,
            connector_id: connector_id.map(str::to_string),
        }
    }

    /// The keystore path for `label` (the empty label is [`DEFAULT_LABEL`]).
    ///
    /// Always a sub-key path: there is no label that names the wallet's own
    /// key. Refusals carry a machine code like every other wallet error:
    /// `invalid_label` for a label of the wrong shape, `sub_key_unavailable`
    /// when this project is not a connector (no `connector_id` in its
    /// manifest) or its id cannot form a valid path.
    fn sub_path_for_label(&self, label: &str) -> Result<String, String> {
        let label = if label.is_empty() { DEFAULT_LABEL } else { label };
        if !is_valid_label(label) {
            // The label itself is not echoed: it is caller text, and a guest
            // reads trailing `key=value` fields off the end of this string.
            return Err(
                "invalid_label: a sub-key label must match [a-z0-9][a-z0-9_-]{0,31}".to_string(),
            );
        }
        let Some(connector_id) = self.connector_id.as_deref() else {
            return Err(
                "sub_key_unavailable: this project is not a connector (its manifest names no \
                 connector_id), so it has no EVM keys of its own; the wallet's own key is \
                 signable only through the HTTPS wallet API, never from inside a module"
                    .to_string(),
            );
        };
        let path = sub_path(connector_id, label);
        if !shared_tee_helpers::is_valid_sub_path(&path) {
            return Err(
                "sub_key_unavailable: this connector's id and the label do not form a valid \
                 sub-key path ([a-z0-9][a-z0-9._-]{0,63}); shorten the label"
                    .to_string(),
            );
        }
        Ok(path)
    }

    /// `/wallet/v1/address` for a sub-key on `chain`.
    fn address_path(chain: &str, sub_path: &str) -> String {
        format!(
            "/wallet/v1/address?chain={}&sub_path={}",
            urlencoding::encode(chain),
            urlencoding::encode(sub_path)
        )
    }

    /// `{chain, sub_path, …extra}` — the body every EVM signing request shares.
    fn evm_body(chain: &str, sub_path: String, extra: serde_json::Value) -> serde_json::Value {
        let mut body = extra;
        body["chain"] = serde_json::Value::String(chain.to_string());
        body["sub_path"] = serde_json::Value::String(sub_path);
        body
    }

    /// `/wallet/v1/balance` for the wallet's intents balance of `token`.
    fn intents_balance_path(token: &str) -> String {
        format!(
            "/wallet/v1/balance?chain=near&source=intents&token={}",
            urlencoding::encode(token)
        )
    }

    /// `/wallet/v1/confidential/balance`, for one asset or all of them.
    fn confidential_balance_path(token: &str) -> String {
        if token.is_empty() {
            "/wallet/v1/confidential/balance".to_string()
        } else {
            format!("/wallet/v1/confidential/balance?token={}", urlencoding::encode(token))
        }
    }

    /// `/wallet/v1/intents/deposit/cross-chain` body: `{chain, amount, token?}` — the
    /// coordinator fills in the destination (NEAR USDC on intents) and the
    /// refund address (the wallet's own on `chain`).
    fn deposit_intent_body(chain: &str, token: &str, amount: &str) -> serde_json::Value {
        let mut body = serde_json::json!({ "chain": chain, "amount": amount });
        if !token.is_empty() {
            body["token"] = serde_json::Value::String(token.to_string());
        }
        body
    }

    /// Check rate limit, returns error string if exceeded
    fn check_rate_limit(&mut self) -> Option<String> {
        if self.call_count >= self.max_calls {
            Some(format!(
                "Wallet rate limit exceeded: {} calls (max: {})",
                self.call_count + 1,
                self.max_calls
            ))
        } else {
            self.call_count += 1;
            None
        }
    }

    /// Make an internal wallet API call to the coordinator
    fn call_coordinator(
        &self,
        method: &str,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> WalletResult {
        let url = format!("{}{}", self.coordinator_url, path);

        let mut request_builder = match method {
            "GET" => self.http_client.get(&url),
            "POST" => self.http_client.post(&url),
            _ => return (String::new(), format!("Unsupported HTTP method: {}", method)),
        };

        // Add internal auth headers
        request_builder = request_builder
            .header("X-Wallet-Id", &self.wallet_id)
            .header("X-Internal-Wallet-Auth", &self.wallet_auth_token);

        if let Some(json_body) = body {
            request_builder = request_builder.json(json_body);
        }

        match request_builder.send() {
            Ok(response) => {
                let status = response.status();
                match response.text() {
                    Ok(text) => {
                        if status.is_success() {
                            (text, String::new())
                        } else {
                            (String::new(), coordinator_failure(status.as_u16(), &text))
                        }
                    }
                    Err(e) => (String::new(), format!("Failed to read response: {}", e)),
                }
            }
            Err(e) => (String::new(), format!("Wallet request failed: {}", e)),
        }
    }
}

impl outlayer::wallet::api::Host for WalletHostState {
    fn get_id(&mut self) -> WalletResult {
        debug!("wallet::get_id wallet_id={}", self.wallet_id);
        (self.wallet_id.clone(), String::new())
    }

    fn get_address(&mut self, chain: String) -> WalletResult {
        debug!("wallet::get_address chain={}, wallet_id={}", chain, self.wallet_id);

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        if chain.is_empty() {
            return (String::new(), "chain parameter is required".to_string());
        }

        let path = format!("/wallet/v1/address?chain={}", urlencoding::encode(&chain));
        self.call_coordinator("GET", &path, None)
    }

    fn get_sub_key_address(&mut self, chain: String, label: String) -> WalletResult {
        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        if chain.is_empty() {
            return (String::new(), "chain parameter is required".to_string());
        }
        // The label is caller text and is logged only once it has a shape.
        let sub_path = match self.sub_path_for_label(&label) {
            Ok(p) => p,
            Err(e) => return (String::new(), e),
        };
        debug!("wallet::get_sub_key_address chain={}, sub_path={}, wallet_id={}", chain, sub_path, self.wallet_id);

        let path = Self::address_path(&chain, &sub_path);
        self.call_coordinator("GET", &path, None)
    }

    fn evm_sign_typed_data(&mut self, chain: String, typed_data: String, label: String) -> WalletResult {
        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        if chain.is_empty() {
            return (String::new(), "chain parameter is required".to_string());
        }
        let sub_path = match self.sub_path_for_label(&label) {
            Ok(p) => p,
            Err(e) => return (String::new(), e),
        };
        debug!("wallet::evm_sign_typed_data chain={}, sub_path={}, wallet_id={}", chain, sub_path, self.wallet_id);
        // Parsed here only to forward a JSON object, not a string — the digest
        // is the keystore's to compute.
        let typed: serde_json::Value = match serde_json::from_str(&typed_data) {
            Ok(v @ serde_json::Value::Object(_)) => v,
            Ok(_) => return (String::new(), "invalid_typed_data: typed-data must be a JSON object {domain, types, primaryType, message}".to_string()),
            Err(e) => return (String::new(), format!("invalid_typed_data: {e}")),
        };

        let body = Self::evm_body(&chain, sub_path, serde_json::json!({ "typed_data": typed }));
        self.call_coordinator("POST", "/wallet/v1/evm/sign-typed-data", Some(&body))
    }

    fn evm_sign_message(&mut self, chain: String, message: String, encoding: String, label: String) -> WalletResult {
        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        if chain.is_empty() {
            return (String::new(), "chain parameter is required".to_string());
        }
        let sub_path = match self.sub_path_for_label(&label) {
            Ok(p) => p,
            Err(e) => return (String::new(), e),
        };
        debug!("wallet::evm_sign_message chain={}, encoding={}, sub_path={}, wallet_id={}", chain, encoding, sub_path, self.wallet_id);

        let mut extra = serde_json::json!({ "message": message });
        if !encoding.is_empty() {
            extra["encoding"] = serde_json::Value::String(encoding);
        }
        let body = Self::evm_body(&chain, sub_path, extra);
        self.call_coordinator("POST", "/wallet/v1/evm/sign-message", Some(&body))
    }

    fn evm_sign_transaction(&mut self, chain: String, unsigned_tx: String, label: String) -> WalletResult {
        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        if chain.is_empty() {
            return (String::new(), "chain parameter is required".to_string());
        }
        let sub_path = match self.sub_path_for_label(&label) {
            Ok(p) => p,
            Err(e) => return (String::new(), e),
        };
        debug!("wallet::evm_sign_transaction chain={}, sub_path={}, wallet_id={}", chain, sub_path, self.wallet_id);

        let body = Self::evm_body(&chain, sub_path, serde_json::json!({ "unsigned_tx": unsigned_tx }));
        self.call_coordinator("POST", "/wallet/v1/evm/sign-transaction", Some(&body))
    }

    fn withdraw(&mut self, chain: String, to: String, amount: String, token: String) -> WalletResult {
        debug!(
            "wallet::withdraw chain={}, to={}, amount={}, token={}, wallet_id={}",
            chain, to, amount, token, self.wallet_id
        );

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        if chain.is_empty() || to.is_empty() || amount.is_empty() {
            return (String::new(), "chain, to, and amount are required".to_string());
        }

        let body = serde_json::json!({
            "chain": chain,
            "to": to,
            "amount": amount,
            "token": if token.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(token) },
        });

        self.call_coordinator("POST", "/wallet/v1/intents/withdraw", Some(&body))
    }

    fn withdraw_dry_run(&mut self, chain: String, to: String, amount: String, token: String) -> WalletResult {
        debug!(
            "wallet::withdraw_dry_run chain={}, to={}, amount={}, token={}, wallet_id={}",
            chain, to, amount, token, self.wallet_id
        );

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        if chain.is_empty() || to.is_empty() || amount.is_empty() {
            return (String::new(), "chain, to, and amount are required".to_string());
        }

        let body = serde_json::json!({
            "chain": chain,
            "to": to,
            "amount": amount,
            "token": if token.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(token) },
        });

        self.call_coordinator("POST", "/wallet/v1/intents/withdraw/dry-run", Some(&body))
    }

    fn get_request_status(&mut self, request_id: String) -> WalletResult {
        debug!(
            "wallet::get_request_status request_id={}, wallet_id={}",
            request_id, self.wallet_id
        );

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        if request_id.is_empty() {
            return (String::new(), "request_id is required".to_string());
        }

        let path = format!("/wallet/v1/requests/{}", urlencoding::encode(&request_id));
        self.call_coordinator("GET", &path, None)
    }

    fn list_tokens(&mut self) -> WalletResult {
        debug!("wallet::list_tokens wallet_id={}", self.wallet_id);

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        self.call_coordinator("GET", "/wallet/v1/tokens", None)
    }

    fn transfer(&mut self, chain: String, to: String, amount: String) -> WalletResult {
        debug!(
            "wallet::transfer chain={}, to={}, amount={}, wallet_id={}",
            chain, to, amount, self.wallet_id
        );

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        if to.is_empty() || amount.is_empty() {
            return (String::new(), "to and amount are required".to_string());
        }

        let body = serde_json::json!({
            "chain": if chain.is_empty() { "near".to_string() } else { chain },
            "to": to,
            "amount": amount,
        });

        self.call_coordinator("POST", "/wallet/v1/transfer", Some(&body))
    }

    fn get_balance(&mut self, chain: String, token: String) -> WalletResult {
        debug!(
            "wallet::get_balance chain={}, token={}, wallet_id={}",
            chain, token, self.wallet_id
        );

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        let chain_param = if chain.is_empty() { "near" } else { &chain };
        let path = if token.is_empty() {
            format!("/wallet/v1/balance?chain={}", chain_param)
        } else {
            format!(
                "/wallet/v1/balance?chain={}&token={}",
                chain_param,
                urlencoding::encode(&token)
            )
        };

        self.call_coordinator("GET", &path, None)
    }

    fn get_intents_balance(&mut self, token: String) -> WalletResult {
        debug!("wallet::get_intents_balance token={}, wallet_id={}", token, self.wallet_id);

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        if token.is_empty() {
            return (String::new(), "token parameter is required: intents balances are per asset (e.g. \"nep141:wrap.near\")".to_string());
        }
        let path = Self::intents_balance_path(&token);
        self.call_coordinator("GET", &path, None)
    }

    fn deposit_intent(&mut self, chain: String, token: String, amount: String) -> WalletResult {
        debug!("wallet::deposit_intent chain={}, token={}, amount={}, wallet_id={}", chain, token, amount, self.wallet_id);

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        if chain.is_empty() {
            return (String::new(), "chain parameter is required".to_string());
        }
        if amount.is_empty() {
            return (String::new(), "amount parameter is required".to_string());
        }
        let body = Self::deposit_intent_body(&chain, &token, &amount);
        self.call_coordinator("POST", "/wallet/v1/intents/deposit/cross-chain", Some(&body))
    }

    fn get_confidential_balance(&mut self, token: String) -> WalletResult {
        debug!("wallet::get_confidential_balance token={}, wallet_id={}", token, self.wallet_id);

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        let path = Self::confidential_balance_path(&token);
        self.call_coordinator("GET", &path, None)
    }

    fn confidential_withdraw(&mut self, chain: String, to: String, amount: String, token: String) -> WalletResult {
        debug!(
            "wallet::confidential_withdraw chain={}, to={}, amount={}, token={}, wallet_id={}",
            chain, to, amount, token, self.wallet_id
        );

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        if chain.is_empty() || to.is_empty() || amount.is_empty() {
            return (String::new(), "chain, to, and amount are required".to_string());
        }
        let body = serde_json::json!({
            "chain": chain,
            "to": to,
            "amount": amount,
            "token": if token.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(token) },
        });
        self.call_coordinator("POST", "/wallet/v1/confidential/withdraw", Some(&body))
    }

    fn confidential_deposit_intent(&mut self, chain: String, token: String, amount: String) -> WalletResult {
        debug!("wallet::confidential_deposit_intent chain={}, token={}, amount={}, wallet_id={}", chain, token, amount, self.wallet_id);

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }
        if chain.is_empty() {
            return (String::new(), "chain parameter is required".to_string());
        }
        if amount.is_empty() {
            return (String::new(), "amount parameter is required".to_string());
        }
        let body = Self::deposit_intent_body(&chain, &token, &amount);
        self.call_coordinator("POST", "/wallet/v1/confidential/deposit/cross-chain", Some(&body))
    }

    fn intents_deposit(&mut self, token: String, amount: String) -> WalletResult {
        debug!(
            "wallet::intents_deposit token={}, amount={}, wallet_id={}",
            token, amount, self.wallet_id
        );

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        if token.is_empty() || amount.is_empty() {
            return (String::new(), "token and amount are required".to_string());
        }

        let body = serde_json::json!({
            "token": token,
            "amount": amount,
        });

        self.call_coordinator("POST", "/wallet/v1/intents/deposit", Some(&body))
    }

    fn swap(
        &mut self,
        token_in: String,
        token_out: String,
        amount_in: String,
        min_amount_out: String,
    ) -> WalletResult {
        debug!(
            "wallet::swap token_in={}, token_out={}, amount_in={}, min_amount_out={}, wallet_id={}",
            token_in, token_out, amount_in, min_amount_out, self.wallet_id
        );

        if let Some(err) = self.check_rate_limit() {
            return (String::new(), err);
        }

        if token_in.is_empty() || token_out.is_empty() || amount_in.is_empty() {
            return (
                String::new(),
                "token_in, token_out, and amount_in are required".to_string(),
            );
        }

        let body = serde_json::json!({
            "token_in": token_in,
            "token_out": token_out,
            "amount_in": amount_in,
            "min_amount_out": if min_amount_out.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(min_amount_out) },
        });

        self.call_coordinator("POST", "/wallet/v1/intents/swap", Some(&body))
    }
}

/// Add wallet host functions to a wasmtime component linker
pub fn add_wallet_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut WalletHostState + Send + Sync + Copy + 'static,
) -> Result<()> {
    outlayer::wallet::api::add_to_linker(linker, get_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> WalletHostState {
        state_for(Some("mercury"))
    }

    fn state_for(connector_id: Option<&str>) -> WalletHostState {
        WalletHostState {
            wallet_id: "ed25519:abc123".to_string(),
            http_client: reqwest::blocking::Client::new(),
            coordinator_url: "http://localhost:9999".to_string(),
            wallet_auth_token: "test-token".to_string(),
            call_count: 0,
            max_calls: MAX_CALLS,
            connector_id: connector_id.map(str::to_string),
        }
    }

    #[test]
    fn a_label_becomes_this_connectors_path_and_nobody_elses() {
        let s = state_for(Some("mercury"));
        // The empty label is a sub-key too — `default` — so no label a guest can
        // pass names the wallet's own key.
        assert_eq!(s.sub_path_for_label("").unwrap(), "connector.mercury.default");
        assert_eq!(s.sub_path_for_label("default").unwrap(), "connector.mercury.default");
        assert_eq!(s.sub_path_for_label("trading").unwrap(), "connector.mercury.trading");
        assert_eq!(s.sub_path_for_label("bridge-2").unwrap(), "connector.mercury.bridge-2");
        // The guest cannot spell another connector into the path: every
        // character that could end a segment is refused in the label.
        for bad in ["Trading", "a.b", "a:b", "hl.trading", "near-email.send", "with space", ".x", "-x", &"a".repeat(33)] {
            let err = s.sub_path_for_label(bad).unwrap_err();
            assert!(err.starts_with("invalid_label:"), "{bad:?} → {err}");
        }
    }

    #[test]
    fn an_ordinary_project_has_no_evm_keys_at_all() {
        // Not even through the empty label: the wallet's own key is never a
        // guest's to sign with, and a non-connector has no sub-keys.
        let s = state_for(None);
        for label in ["", "default", "trading"] {
            let err = s.sub_path_for_label(label).unwrap_err();
            assert!(err.starts_with("sub_key_unavailable:"), "{label:?} → {err}");
        }
    }

    #[test]
    fn a_connector_id_that_cannot_form_a_path_is_refused_not_bent() {
        // An id the manifest parser let through but the keystore's path rule
        // would not: refused with the same code, never rewritten.
        for bad_id in ["Mercury", "a:b", &"m".repeat(60)] {
            let s = state_for(Some(bad_id));
            let err = s.sub_path_for_label("trading").unwrap_err();
            assert!(err.starts_with("sub_key_unavailable:"), "{bad_id:?} → {err}");
        }
    }

    #[test]
    fn label_and_path_lengths_are_exact_at_the_boundary() {
        let s = state_for(Some("mercury"));
        assert!(s.sub_path_for_label(&"a".repeat(32)).is_ok());
        assert!(s.sub_path_for_label(&"a".repeat(33)).unwrap_err().starts_with("invalid_label:"));
        // "connector." (10) + id + "." (1) + label: a 21-char id with a 32-char
        // label is exactly 64 and passes; one more character on the id is 65.
        let fits = state_for(Some(&"m".repeat(21)));
        assert!(fits.sub_path_for_label(&"a".repeat(32)).is_ok());
        let over = state_for(Some(&"m".repeat(22)));
        assert!(over.sub_path_for_label(&"a".repeat(32)).unwrap_err().starts_with("sub_key_unavailable:"));
    }

    #[test]
    fn a_refusal_never_echoes_the_label() {
        let s = state_for(Some("mercury"));
        let err = s.sub_path_for_label("x terminal=true").unwrap_err();
        assert!(!err.contains("terminal="), "{err}");
    }

    #[test]
    fn the_address_path_encodes_both_parameters() {
        assert_eq!(
            WalletHostState::address_path("base", "connector.mercury.trading"),
            "/wallet/v1/address?chain=base&sub_path=connector.mercury.trading"
        );
        assert_eq!(
            WalletHostState::address_path("a b", "x/y"),
            "/wallet/v1/address?chain=a%20b&sub_path=x%2Fy"
        );
    }

    #[test]
    fn typed_data_that_is_not_an_object_is_refused_before_any_request() {
        use outlayer::wallet::api::Host;
        // The coordinator URL is unreachable, so a request would fail with a
        // transport error; the refusal below must come from the parser instead.
        let mut s = state_for(Some("mercury"));
        for bad in ["not json", "[]", "\"x\"", "42"] {
            let (out, err) = s.evm_sign_typed_data("base".into(), bad.into(), "trading".into());
            assert!(out.is_empty());
            assert!(err.starts_with("invalid_typed_data:"), "{bad:?} → {err}");
        }
    }

    #[test]
    fn a_failure_with_an_empty_body_is_still_a_failure() {
        assert_eq!(
            coordinator_failure(502, ""),
            "http_502: the coordinator answered 502 with an empty body"
        );
        assert_eq!(coordinator_failure(400, "   "), "http_400: the coordinator answered 400 with an empty body");
        assert_eq!(
            coordinator_failure(403, r#"{"error":"policy_denied","message":"no"}"#),
            "policy_denied: no"
        );
    }

    #[test]
    fn every_evm_body_carries_a_sub_path() {
        let body = WalletHostState::evm_body("base", "connector.mercury.trading".into(), serde_json::json!({ "message": "hi" }));
        assert_eq!(body["chain"], "base");
        assert_eq!(body["sub_path"], "connector.mercury.trading");
        assert_eq!(body["message"], "hi");
        let tx = WalletHostState::evm_body("base", "connector.mercury.default".into(), serde_json::json!({ "unsigned_tx": "0x02" }));
        assert_eq!(tx["sub_path"], "connector.mercury.default");
        assert_eq!(tx["unsigned_tx"], "0x02");
    }

    #[test]
    fn the_intents_balance_path_names_the_source_and_the_asset() {
        assert_eq!(
            WalletHostState::intents_balance_path("nep141:wrap.near"),
            "/wallet/v1/balance?chain=near&source=intents&token=nep141%3Awrap.near"
        );
        // A bare contract id is passed as-is; the coordinator prefixes `nep141:`.
        assert_eq!(
            WalletHostState::intents_balance_path("wrap.near"),
            "/wallet/v1/balance?chain=near&source=intents&token=wrap.near"
        );
    }

    #[test]
    fn a_deposit_intent_body_carries_the_token_only_when_given() {
        let with = WalletHostState::deposit_intent_body("base", "USDC", "1000000");
        assert_eq!(with["chain"], "base");
        assert_eq!(with["token"], "USDC");
        assert_eq!(with["amount"], "1000000");
        let without = WalletHostState::deposit_intent_body("arbitrum", "", "5");
        assert!(without.get("token").is_none());
        assert_eq!(without["amount"], "5");
    }

    #[test]
    fn an_intents_balance_needs_an_asset_and_a_deposit_intent_needs_chain_and_amount() {
        use outlayer::wallet::api::Host;
        let mut s = state_for(Some("mercury"));
        let (_, err) = s.get_intents_balance(String::new());
        assert!(err.starts_with("token parameter is required"), "{err}");
        let (_, err) = s.deposit_intent(String::new(), "USDC".into(), "1".into());
        assert!(err.starts_with("chain parameter is required"), "{err}");
        let (_, err) = s.deposit_intent("base".into(), "USDC".into(), String::new());
        assert!(err.starts_with("amount parameter is required"), "{err}");
    }

    #[test]
    fn the_confidential_balance_path_is_all_or_one_asset() {
        assert_eq!(WalletHostState::confidential_balance_path(""), "/wallet/v1/confidential/balance");
        assert_eq!(
            WalletHostState::confidential_balance_path("nep141:usdc.near"),
            "/wallet/v1/confidential/balance?token=nep141%3Ausdc.near"
        );
    }

    #[test]
    fn confidential_moves_need_the_same_arguments_as_plain_ones() {
        use outlayer::wallet::api::Host;
        let mut s = state_for(Some("hyperliquid"));
        let (_, err) = s.confidential_withdraw("base".into(), String::new(), "1".into(), String::new());
        assert!(err.starts_with("chain, to, and amount are required"), "{err}");
        let (_, err) = s.confidential_deposit_intent(String::new(), "USDC".into(), "1".into());
        assert!(err.starts_with("chain parameter is required"), "{err}");
        let (_, err) = s.confidential_deposit_intent("base".into(), String::new(), String::new());
        assert!(err.starts_with("amount parameter is required"), "{err}");
    }

    #[test]
    fn test_rate_limit_under_max() {
        let mut state = make_state();
        for _ in 0..MAX_CALLS {
            assert!(state.check_rate_limit().is_none());
        }
    }

    #[test]
    fn test_rate_limit_at_max() {
        let mut state = make_state();
        for _ in 0..MAX_CALLS {
            assert!(state.check_rate_limit().is_none());
        }
        // The call past the budget fails.
        let err = state.check_rate_limit();
        assert!(err.is_some());
        assert!(err.unwrap().contains("rate limit"));
    }

    #[test]
    fn test_get_id_returns_wallet_id() {
        use outlayer::wallet::api::Host;
        let mut state = make_state();
        let (id, err) = state.get_id();
        assert_eq!(id, "ed25519:abc123");
        assert!(err.is_empty());
    }
}

#[cfg(test)]
mod guest_error_tests {
    use super::guest_error;

    /// The code comes FIRST, because that is the only part a guest can route
    /// on. `wallet.wit` documents this shape (`"policy_denied: ..."`), and a
    /// guest handed prose alone would have to match on wording.
    #[test]
    fn the_code_leads_and_the_message_follows() {
        let body = r#"{"error":"policy_denied","message":"daily limit exceeded"}"#;
        assert_eq!(guest_error(body), "policy_denied: daily limit exceeded");
    }

    /// Busy clears by itself, so the guest's move is to wait — and it is told
    /// exactly what to wait for rather than retrying blindly.
    #[test]
    fn busy_carries_the_operation_to_poll() {
        let body = r#"{"error":"wallet_busy",
                       "message":"another operation is using this wallet",
                       "in_flight_request_id":"req-42",
                       "in_flight_operation":"swap"}"#;
        let out = guest_error(body);
        assert!(out.starts_with("wallet_busy: "), "{out}");
        assert!(out.contains("in_flight_request_id=req-42"), "{out}");
        assert!(out.contains("in_flight_operation=swap"), "{out}");
        assert!(
            out.find("in_flight_request_id=").unwrap() < out.find("in_flight_operation=").unwrap(),
            "the operation must come after the id — the guest strips fields from the end and \
             truncates at each, so a field before the id is orphaned in the message: {out}"
        );

        // No id yet, which is the case the operation exists for: the wallet was
        // taken a moment ago and the row is not written. The guest must still
        // learn what it is waiting for.
        let pending = r#"{"error":"wallet_busy",
                          "message":"a transfer is using this wallet and has not written its request yet",
                          "in_flight_request_id":null,
                          "in_flight_operation":"transfer"}"#;
        let out = guest_error(pending);
        assert!(!out.contains("in_flight_request_id="), "no id may be implied: {out}");
        assert!(out.contains("in_flight_operation=transfer"), "{out}");
    }

    /// The field that decides whether retrying is pointless at all. An agent
    /// that retries a terminal refusal spins forever while its owner is never
    /// told to act.
    #[test]
    fn a_refusal_says_whether_retrying_is_pointless() {
        let body = r#"{"error":"agent_connect_denied","message":"the grant is spent",
                       "class":"grant_exhausted","terminal":true}"#;
        let out = guest_error(body);
        assert!(out.starts_with("agent_connect_denied: "), "{out}");
        assert!(out.contains("terminal=true"), "{out}");
    }

    /// Anything that is not the expected JSON is passed on WHOLE. Inventing a
    /// code for it would be worse than repeating what the server said.
    #[test]
    fn an_unexpected_body_is_passed_on_verbatim() {
        assert_eq!(guest_error("502 Bad Gateway"), "502 Bad Gateway");
        assert_eq!(guest_error(r#"{"detail":"nope"}"#), r#"{"detail":"nope"}"#);
        // JSON with only a message still beats handing back raw JSON.
        assert_eq!(guest_error(r#"{"message":"plain"}"#), "plain");
    }
}
