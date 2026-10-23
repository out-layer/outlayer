//! A run on the Defuse worker beside ours: its one-time token and its stdin envelope.
//!
//! That guest has no env vars and none of our host functions, so what the env
//! carried arrives in `meta` on stdin, and the guest reaches storage over HTTPS
//! with a token minted here for this run alone. The token is registered with the
//! coordinator by its hash, over this worker's own attested channel, with the
//! run's scope; it is revoked when the run ends. Only the hash leaves this process
//! other than inside the guest's stdin.

use std::collections::HashMap;

use anyhow::{Context, Result};
use base64::Engine;
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::api_client::ApiClient;
use crate::keystore_client::KeystoreClient;

pub const PREFIX: &str = "act_";

/// The custom section a component built for this engine carries (the SDK's
/// `defuse-engine` feature writes it). Only such a component gets the envelope: any
/// other reads stdin as the caller's input and must never be handed secrets in it.
pub const ENGINE_SECTION: &str = "outlayer.engine";
pub const ENGINE_MARK: &[u8] = b"defuse-worker";

pub fn built_for_engine(wasm: &[u8]) -> bool {
    wasmparser::Parser::new(0).parse_all(wasm).any(|payload| match payload {
        Ok(wasmparser::Payload::CustomSection(reader)) => reader.name() == ENGINE_SECTION && reader.data() == ENGINE_MARK,
        _ => false,
    })
}

/// Added to the run's time limit so the token outlives a run that ends on time.
const TTL_MARGIN_SECONDS: u64 = 60;

/// The longest registration the coordinator and the keystore accept.
const MAX_TTL_SECONDS: u64 = 3600;

fn ttl_for(max_execution_seconds: u64) -> u64 {
    max_execution_seconds.saturating_add(TTL_MARGIN_SECONDS).min(MAX_TTL_SECONDS)
}

/// What the guest may touch: the same project and account the host functions
/// would have named on its behalf.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Scope {
    pub project_uuid: Option<String>,
    pub project_id: Option<String>,
    pub wasm_hash: String,
    pub account_id: String,
    pub wallet_id: Option<String>,
    pub connector_id: Option<String>,
    pub call_id: Option<String>,
    pub request_id: Option<u64>,
}

/// The keystore's view of the scope: what a storage record's seed is built from.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct KeystoreScope {
    pub project_uuid: Option<String>,
    pub wasm_hash: String,
    pub account_id: String,
    pub call_id: Option<String>,
}

impl Scope {
    fn for_keystore(&self) -> KeystoreScope {
        KeystoreScope {
            project_uuid: self.project_uuid.clone(),
            wasm_hash: self.wasm_hash.clone(),
            account_id: self.account_id.clone(),
            call_id: self.call_id.clone(),
        }
    }
}

pub struct CallToken {
    token: String,
}

impl CallToken {
    pub fn mint() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { token: format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)) }
    }

    pub fn hash(&self) -> String {
        hex::encode(Sha256::digest(self.token.as_bytes()))
    }
}

/// A registered token: minted, registered with the coordinator and, when there is
/// one, the keystore; revoked from both by [`AppCall::end`].
pub struct AppCall {
    token: CallToken,
    hash: String,
    at_keystore: bool,
}

impl AppCall {
    /// Mints and registers a token for a run of `scope` that may last
    /// `max_execution_seconds`. `None` when the run has no caller identity: there is
    /// nothing a token could be scoped to, and the guest gets no token.
    pub async fn begin(
        api_client: &ApiClient,
        keystore_client: Option<&KeystoreClient>,
        scope: Scope,
        max_execution_seconds: u64,
    ) -> Result<Option<Self>> {
        if scope.account_id.is_empty() {
            return Ok(None);
        }
        let token = CallToken::mint();
        let hash = token.hash();
        let ttl = ttl_for(max_execution_seconds);
        api_client
            .register_app_call(&hash, ttl, &scope)
            .await
            .context("register the run's call token with the coordinator")?;
        let at_keystore = match keystore_client {
            Some(ks) => {
                if let Err(e) = ks.register_app_call(&hash, ttl, &scope.for_keystore()).await {
                    // The coordinator half is live, so revoke it rather than run with a
                    // token one service honours and the other does not.
                    let _ = api_client.revoke_app_call(&hash).await;
                    return Err(e.context("register the run's call token with the keystore"));
                }
                true
            }
            None => false,
        };
        Ok(Some(Self { token, hash, at_keystore }))
    }

    /// The run is over; the token must not open anything after it. A revocation
    /// that fails is logged: the registration's TTL ends it anyway.
    pub async fn end(self, api_client: &ApiClient, keystore_client: Option<&KeystoreClient>) {
        if let Err(e) = api_client.revoke_app_call(&self.hash).await {
            warn!("call token not revoked at the coordinator (its TTL will end it): {e:#}");
        }
        if let (true, Some(ks)) = (self.at_keystore, keystore_client) {
            if let Err(e) = ks.revoke_app_call(&self.hash).await {
                warn!("call token not revoked at the keystore (its TTL will end it): {e:#}");
            }
        }
    }

    pub fn token(&self) -> &str {
        &self.token.token
    }
}

/// stdin for the guest: `{"meta": {...}, "input": <the caller's input>}`.
///
/// `meta` is the env map as the guest would have seen it, plus `OUTLAYER_API_BASE`
/// and, when the run has one, `OUTLAYER_CALL_TOKEN`. The input is carried as a
/// string when it is UTF-8, as `input_base64` otherwise, so any byte sequence
/// survives the trip.
pub fn envelope(meta: &HashMap<String, String>, api_base: &str, call_token: Option<&str>, input: &[u8]) -> Vec<u8> {
    let mut meta: serde_json::Map<String, serde_json::Value> =
        meta.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect();
    meta.insert("OUTLAYER_API_BASE".to_string(), serde_json::Value::String(api_base.to_string()));
    if let Some(token) = call_token {
        meta.insert("OUTLAYER_CALL_TOKEN".to_string(), serde_json::Value::String(token.to_string()));
    }
    let mut envelope = serde_json::Map::new();
    envelope.insert("meta".to_string(), serde_json::Value::Object(meta));
    match std::str::from_utf8(input) {
        Ok(text) => envelope.insert("input".to_string(), serde_json::Value::String(text.to_string())),
        Err(_) => envelope.insert(
            "input_base64".to_string(),
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(input)),
        ),
    };
    serde_json::to_vec(&serde_json::Value::Object(envelope)).expect("an object of strings serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ttl_is_the_run_plus_a_margin_and_never_above_the_services_cap() {
        assert_eq!(ttl_for(180), 240);
        assert_eq!(ttl_for(3540), 3600);
        assert_eq!(ttl_for(u64::MAX), 3600);
    }

    #[test]
    fn a_token_is_prefixed_random_and_hashed() {
        let a = CallToken::mint();
        let b = CallToken::mint();
        assert!(a.token.starts_with(PREFIX) && a.token.len() == PREFIX.len() + 43);
        assert_ne!(a.token, b.token);
        assert_eq!(a.hash().len(), 64);
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn the_envelope_carries_meta_and_the_input_verbatim() {
        let meta: HashMap<String, String> = [("NEAR_SENDER_ID".to_string(), "bob.testnet".to_string())].into();
        let bytes = envelope(&meta, "https://api.example", Some("act_x"), br#"{"op":"echo"}"#);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["meta"]["NEAR_SENDER_ID"], "bob.testnet");
        assert_eq!(v["meta"]["OUTLAYER_API_BASE"], "https://api.example");
        assert_eq!(v["meta"]["OUTLAYER_CALL_TOKEN"], "act_x");
        assert_eq!(v["input"], r#"{"op":"echo"}"#);
        assert!(v.get("input_base64").is_none());
    }

    #[test]
    fn a_run_without_a_token_has_no_token_field_and_bytes_survive() {
        let bytes = envelope(&HashMap::new(), "u", None, &[0xff, 0xfe]);
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(v["meta"].get("OUTLAYER_CALL_TOKEN").is_none());
        assert!(v.get("input").is_none());
        assert_eq!(v["input_base64"], "//4=");
    }
}
