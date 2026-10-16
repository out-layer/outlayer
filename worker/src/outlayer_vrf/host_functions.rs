//! VRF host functions for WASM components
//!
//! Implements the `near:vrf/api` WIT interface.
//! Uses Ed25519 deterministic signatures via keystore-worker.

use anyhow::Result;
use tracing::debug;
use wasmtime::component::Linker;

// Generate bindings from WIT
// A published interface version never changes a type: a changed signature is
// a new package version, registered next to the old one (wit/README.md).
wasmtime::component::bindgen!({
    path: "wit",
    world: "near:vrf/vrf-host",
});

/// VRF result: (output_hex, signature_hex, alpha, error)
type VrfResult = (String, String, String, String);
/// Pubkey result: (pubkey_hex, error)
type PubkeyResult = (String, String);

/// Host state for VRF functions
pub struct VrfHostState {
    /// Request ID from the execution context (auto-prepended to seed)
    request_id: u64,
    /// Signer account ID (included in alpha for per-user VRF binding)
    sender_id: String,
    /// Blocking HTTP client for keystore calls
    http_client: reqwest::blocking::Client,
    /// Keystore base URL
    keystore_url: String,
    /// Auth token for keystore
    auth_token: String,
    /// TEE session ID (provides actual auth via X-TEE-Session header)
    tee_session_id: Option<String>,
    /// Call counter for rate limiting
    call_count: u32,
    /// Max VRF calls per execution
    max_calls: u32,
}

impl VrfHostState {
    /// Create VRF host state
    ///
    /// `tee_session_id` carries the auth: the keystore validates the session, nothing else in
    /// the body identifies the caller.
    pub fn new(
        request_id: u64,
        sender_id: &str,
        keystore_url: &str,
        auth_token: &str,
        tee_session_id: Option<String>,
    ) -> Self {
        let http_client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("failed to build VRF HTTP client");

        Self {
            request_id,
            sender_id: sender_id.to_string(),
            http_client,
            keystore_url: keystore_url.to_string(),
            auth_token: auth_token.to_string(),
            tee_session_id,
            call_count: 0,
            max_calls: 10,
        }
    }
}

impl near::vrf::api::Host for VrfHostState {
    fn generate(&mut self, user_seed: String) -> VrfResult {
        debug!(
            "vrf::generate user_seed={}, request_id={}",
            user_seed, self.request_id
        );

        // Reject ':' in user_seed — alpha uses ':' as delimiter
        if user_seed.contains(':') {
            return (
                String::new(),
                String::new(),
                String::new(),
                "user_seed must not contain ':'".to_string(),
            );
        }

        // Rate limit
        if self.call_count >= self.max_calls {
            return (
                String::new(),
                String::new(),
                String::new(),
                format!(
                    "VRF rate limit exceeded: {} calls (max: {})",
                    self.call_count + 1,
                    self.max_calls
                ),
            );
        }
        self.call_count += 1;

        // Construct alpha with auto-prepended request_id and sender_id
        let alpha = format!("vrf:{}:{}:{}", self.request_id, self.sender_id, user_seed);

        let url = format!("{}/vrf/generate", self.keystore_url);

        let mut request = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .json(&serde_json::json!({
                "alpha": alpha,
            }));

        if let Some(ref session_id) = self.tee_session_id {
            request = request.header("X-TEE-Session", session_id.as_str());
        }

        match request.send() {
            Ok(response) => {
                if !response.status().is_success() {
                    let status = response.status();
                    let error = response.text().unwrap_or_default();
                    return (
                        String::new(),
                        String::new(),
                        alpha,
                        format!("Keystore VRF failed ({}): {}", status, error),
                    );
                }

                match response.json::<serde_json::Value>() {
                    Ok(json) => {
                        let output_hex = json["output_hex"].as_str().unwrap_or("").to_string();
                        let signature_hex =
                            json["signature_hex"].as_str().unwrap_or("").to_string();
                        debug!(
                            "vrf::generate success, output_len={}",
                            output_hex.len()
                        );
                        (output_hex, signature_hex, alpha, String::new())
                    }
                    Err(e) => (
                        String::new(),
                        String::new(),
                        alpha,
                        format!("Failed to parse VRF response: {}", e),
                    ),
                }
            }
            Err(e) => (
                String::new(),
                String::new(),
                alpha,
                format!("VRF request failed: {}", e),
            ),
        }
    }

    fn pubkey(&mut self) -> PubkeyResult {
        debug!("vrf::pubkey");

        let url = format!("{}/vrf/pubkey", self.keystore_url);

        match self.http_client.get(&url).send() {
            Ok(response) => {
                if !response.status().is_success() {
                    let status = response.status();
                    let error = response.text().unwrap_or_default();
                    return (String::new(), format!("Keystore VRF pubkey failed ({}): {}", status, error));
                }

                match response.json::<serde_json::Value>() {
                    Ok(json) => {
                        let pubkey_hex = json["vrf_public_key_hex"].as_str().unwrap_or("").to_string();
                        debug!("vrf::pubkey success, key={}", pubkey_hex);
                        (pubkey_hex, String::new())
                    }
                    Err(e) => (String::new(), format!("Failed to parse VRF pubkey response: {}", e)),
                }
            }
            Err(e) => (String::new(), format!("VRF pubkey request failed: {}", e)),
        }
    }
}

/// Add VRF host functions to a wasmtime component linker
pub fn add_vrf_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut VrfHostState + Send + Sync + Copy + 'static,
) -> Result<()> {
    near::vrf::api::add_to_linker(linker, get_state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(request_id: u64, sender_id: &str) -> VrfHostState {
        VrfHostState {
            request_id,
            sender_id: sender_id.to_string(),
            http_client: reqwest::blocking::Client::new(),
            keystore_url: "http://localhost:0".to_string(),
            auth_token: String::new(),
            tee_session_id: None,
            call_count: 0,
            max_calls: 10,
        }
    }

    #[test]
    fn test_alpha_format() {
        let state = make_state(42, "alice.near");
        let alpha = format!("vrf:{}:{}:{}", state.request_id, state.sender_id, "my-seed");
        assert_eq!(alpha, "vrf:42:alice.near:my-seed");
        // Parseable: split by ':' → ["vrf", request_id, sender_id, user_seed]
        let parts: Vec<&str> = alpha.splitn(4, ':').collect();
        assert_eq!(parts, vec!["vrf", "42", "alice.near", "my-seed"]);
    }

    #[test]
    fn test_colon_in_seed_rejected() {
        let mut state = make_state(1, "bob.near");
        let (_, _, _, error) = near::vrf::api::Host::generate(&mut state, "bad:seed".to_string());
        assert_eq!(error, "user_seed must not contain ':'");
    }

    #[test]
    fn test_rate_limit() {
        let mut state = make_state(1, "alice.near");
        state.max_calls = 0;
        let (_, _, _, error) = near::vrf::api::Host::generate(&mut state, "seed".to_string());
        assert!(error.contains("rate limit"), "expected rate limit error, got: {}", error);
    }
}
