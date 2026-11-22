//! Ephemeral key derivation — RETURNS PRIVATE KEYS.
//!
//! This module is intentionally separate from the wallet signing endpoints in api.rs.
//!
//! ## Security model difference
//!
//! Regular wallet endpoints (`derive-address`, `sign-*`) NEVER expose private keys.
//! All signing happens inside the TEE, and only signatures/public keys leave.
//!
//! Ephemeral keys are different: the private key IS the product. For example,
//! payment check keys are bearer tokens — Agent A derives an ephemeral key,
//! locks tokens on its implicit account, and hands the private key (`check_key`)
//! to Agent B, who uses it to claim funds.
//!
//! The TEE still provides value here:
//! - **No key storage** — keys are derived deterministically from (master_secret, seed),
//!   so the coordinator never stores private keys in its database.
//! - **Recoverable** — the creator can re-derive the key for reclaim even if the
//!   original `check_key` is lost.
//! - **Unified derivation** — all wallet keys (main + ephemeral) come from the same
//!   master secret via HMAC-SHA256, maintaining a single trust root.
//!
//! ## Seed convention
//!
//! Ephemeral keys use a sub-path under the wallet's chain key:
//! ```text
//! wallet:{wallet_id}:{chain}:{sub_path}
//! ```
//! Example: `wallet:abc123:near:check:0` for payment check #0.
//!
//! The main wallet key (`wallet:{wallet_id}:{chain}`) is never served through this
//! module — only seeds with a non-empty sub_path are accepted.

use axum::{
    extract::State,
    response::Json,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};

use crate::api::{AppState, ApiError};

// ============================================================================
// Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct DeriveEphemeralKeyRequest {
    pub wallet_id: String,
    pub chain: String,
    /// Sub-path under the wallet key, e.g. "check:0". Must not be empty.
    pub sub_path: String,
}

#[derive(Debug, Serialize)]
pub struct DeriveEphemeralKeyResponse {
    pub public_key: String,
    pub private_key: String,
    pub implicit_account_id: String,
}

// ============================================================================
// Routes
// ============================================================================

/// Returns a Router with ephemeral key endpoints.
/// Must be merged into the coordinator-only route group (requires coordinator auth).
pub fn ephemeral_key_routes() -> Router<AppState> {
    Router::new()
        .route("/wallet/derive-ephemeral-key", post(derive_ephemeral_key_handler))
}

// ============================================================================
// Handler
// ============================================================================

pub(crate) async fn derive_ephemeral_key_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<DeriveEphemeralKeyRequest>,
) -> Result<Json<DeriveEphemeralKeyResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized("Keystore not ready.".to_string()));
    }

    crate::api::validate_wallet_id(&req.wallet_id)?;
    if req.sub_path.is_empty() {
        return Err(ApiError::BadRequest(
            "sub_path must not be empty — use derive-address for main wallet keys".to_string(),
        ));
    }

    // The ephemeral key MUST derive from the same master as
    // `derive-address` returns for the same wallet. If we hard-coded
    // `customer = None` here, vault-bound wallets would get their
    // ephemeral keys from the DEFAULT master — not the per-vault
    // master — and funds deposited at the resulting address would be
    // unrecoverable through the customer's vault path.
    let customer = crate::api::extract_customer_from_header(&headers)?;
    state
        .ensure_customer_loaded(customer.as_ref())
        .await
        // Underfunded vault → 402 with a top-up message; anything else → 400.
        .map_err(ApiError::from_customer_load)?;

    let seed = format!(
        "wallet:{}:{}:{}",
        req.wallet_id,
        req.chain.to_lowercase(),
        req.sub_path
    );

    let keystore = state.keystore.read().await;
    let (signing_key, verifying_key) = keystore
        .derive_keypair(customer.as_ref(), &seed)
        .map_err(|e| ApiError::InternalError(format!("Ephemeral key derivation failed: {}", e)))?;

    let pubkey_hex = hex::encode(verifying_key.as_bytes());
    let privkey_hex = hex::encode(signing_key.to_bytes());

    Ok(Json(DeriveEphemeralKeyResponse {
        public_key: format!("ed25519:{}", pubkey_hex),
        private_key: privkey_hex,
        implicit_account_id: pubkey_hex,
    }))
}
