//! The `outlayer:crypto` family: signing for guests of the Defuse Outlayer core.
//!
//! The core's host scopes every guest path by App ID and hands its signer a
//! 32-byte path. The worker's signer forwards that path here; the keys are the
//! core's own `InMemorySigner` over [`Keystore::derive_app_crypto_seed`], so a
//! public key derived anywhere from [`root_public_keys`] matches what this
//! keystore signs with. Child private keys exist only inside this process.
//!
//! [`Keystore::derive_app_crypto_seed`]: crate::crypto::Keystore::derive_app_crypto_seed

use axum::{
    extract::State,
    response::Json,
    routing::{get, post},
    Router,
};
use defuse_outlayer_signer::{
    kdf::{
        crypto::{ed25519::Ed25519, secp256k1::Secp256k1},
        DeriveSigner, RecoverableDeriveSigner,
    },
    InMemorySigner,
};
use serde::{Deserialize, Serialize};

use crate::api::{ApiError, AppState};
use crate::crypto::Keystore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Curve {
    Ed25519,
    Secp256k1,
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub curve: Curve,
    /// The scoped 32-byte path, hex.
    pub path: String,
    /// Hex. For secp256k1, a 32-byte prehash.
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignResponse {
    /// Hex: 64 bytes, `r || s` for secp256k1.
    pub signature: String,
    /// secp256k1 only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_id: Option<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootPublicKeys {
    /// Hex, 32 bytes.
    pub ed25519: String,
    /// Hex, SEC1 compressed, 33 bytes.
    pub secp256k1: String,
}

/// Worker-only: merged under the worker auth and TEE session layers.
pub fn worker_routes() -> Router<AppState> {
    Router::new().route("/crypto/sign", post(sign_handler))
}

/// Public: the root public keys are what anyone derives an app's keys from.
pub fn public_routes() -> Router<AppState> {
    Router::new().route("/crypto/root-public-keys", get(root_public_keys_handler))
}

fn signer(keystore: &Keystore) -> InMemorySigner {
    InMemorySigner::from_seed(keystore.derive_app_crypto_seed().as_ref())
}

pub fn root_public_keys(keystore: &Keystore) -> RootPublicKeys {
    let signer = signer(keystore);
    RootPublicKeys {
        ed25519: hex::encode(signer.ed25519_master_public_key().as_bytes()),
        secp256k1: hex::encode(signer.secp256k1_master_public_key().to_sec1_bytes()),
    }
}

pub async fn sign(keystore: &Keystore, req: &SignRequest) -> Result<SignResponse, ApiError> {
    let path: [u8; 32] = hex::decode(&req.path)
        .ok()
        .and_then(|p| p.try_into().ok())
        .ok_or_else(|| ApiError::BadRequest("path must be 32 bytes of hex".to_string()))?;
    let message = hex::decode(&req.message)
        .map_err(|_| ApiError::BadRequest("message must be hex".to_string()))?;
    let signer = signer(keystore);
    match req.curve {
        Curve::Ed25519 => {
            let signature = DeriveSigner::<Ed25519, _>::derive_sign(&signer, path, &message)
                .await
                .map_err(|e| ApiError::InternalError(format!("ed25519 signing failed: {e}")))?;
            Ok(SignResponse { signature: hex::encode(signature.to_bytes()), recovery_id: None })
        }
        Curve::Secp256k1 => {
            if message.len() != 32 {
                return Err(ApiError::BadRequest(format!(
                    "secp256k1 signs a 32-byte prehash, got {} bytes",
                    message.len()
                )));
            }
            let (signature, recovery_id) =
                RecoverableDeriveSigner::<Secp256k1, _>::derive_sign_recoverable(&signer, path, &message)
                    .await
                    .map_err(|e| ApiError::InternalError(format!("secp256k1 signing failed: {e}")))?;
            Ok(SignResponse {
                signature: hex::encode(signature.to_bytes()),
                recovery_id: Some(recovery_id.to_byte()),
            })
        }
    }
}

const NOT_READY: &str = "Keystore not ready. Waiting for DAO approval and master key from MPC.";

async fn sign_handler(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(NOT_READY.to_string()));
    }
    let keystore = state.keystore.read().await;
    Ok(Json(sign(&keystore, &req).await?))
}

async fn root_public_keys_handler(
    State(state): State<AppState>,
) -> Result<Json<RootPublicKeys>, ApiError> {
    if !state.is_ready() {
        return Err(ApiError::Unauthorized(NOT_READY.to_string()));
    }
    let keystore = state.keystore.read().await;
    Ok(Json(root_public_keys(&keystore)))
}

#[cfg(test)]
mod tests {
    use defuse_outlayer_signer::{
        kdf::{
            crypto::{ed25519::ed25519_dalek, secp256k1::k256, Curve as _, RecoverableCurve as _},
            Schema,
        },
        MasterSchema,
    };

    use super::*;

    fn keystore() -> Keystore {
        Keystore::from_master_secret(&[7u8; 32]).unwrap()
    }

    /// Pinned from an independent computation of the same chain (HKDF-Extract, then
    /// the core's HKDF-SHA3-512). A change here rotates every app's keys.
    #[test]
    fn root_public_keys_have_not_changed() {
        let roots = root_public_keys(&keystore());
        assert_eq!(roots.ed25519, "3280048d3e0eb8218e070c5ee055dae2707d1bf297283d89d02686f3b1321f4b");
        assert_eq!(roots.secp256k1, "02dddff6227233d1c11e02764abbb9e5b5d5f3ad33532bb8e73dfd75038cd9b0ba");
    }

    #[tokio::test]
    async fn ed25519_signature_verifies_under_the_offline_derived_key() {
        let ks = keystore();
        let roots = root_public_keys(&ks);
        let root = ed25519_dalek::VerifyingKey::from_bytes(
            &hex::decode(&roots.ed25519).unwrap().try_into().unwrap(),
        )
        .unwrap();
        let path = [3u8; 32];
        let res = sign(
            &ks,
            &SignRequest { curve: Curve::Ed25519, path: hex::encode(path), message: hex::encode(b"msg") },
        )
        .await
        .unwrap();
        let derived = MasterSchema::<Ed25519>::new(root).derive(path);
        let signature = ed25519_dalek::Signature::from_slice(&hex::decode(res.signature).unwrap()).unwrap();
        assert!(Ed25519::verify(&derived, b"msg", &signature));
    }

    #[tokio::test]
    async fn secp256k1_signature_recovers_the_offline_derived_key() {
        let ks = keystore();
        let roots = root_public_keys(&ks);
        let root = k256::ecdsa::VerifyingKey::from_sec1_bytes(&hex::decode(&roots.secp256k1).unwrap()).unwrap();
        let path = [5u8; 32];
        let prehash = [9u8; 32];
        let res = sign(
            &ks,
            &SignRequest { curve: Curve::Secp256k1, path: hex::encode(path), message: hex::encode(prehash) },
        )
        .await
        .unwrap();
        let derived = MasterSchema::<Secp256k1>::new(root).derive(path);
        let signature = k256::ecdsa::Signature::from_slice(&hex::decode(res.signature).unwrap()).unwrap();
        let recovery_id = k256::ecdsa::RecoveryId::from_byte(res.recovery_id.unwrap()).unwrap();
        assert!(Secp256k1::verify(&derived, &prehash, &signature));
        assert_eq!(Secp256k1::recover(&prehash, &signature, recovery_id), Some(derived));
    }

    #[tokio::test]
    async fn secp256k1_refuses_a_message_that_is_not_a_prehash() {
        let res = sign(
            &keystore(),
            &SignRequest { curve: Curve::Secp256k1, path: hex::encode([0u8; 32]), message: hex::encode(b"short") },
        )
        .await;
        assert!(matches!(res, Err(ApiError::BadRequest(_))));
    }

    #[test]
    fn the_seed_is_not_any_hmac_of_the_master() {
        let ks = keystore();
        let seed = ks.derive_app_crypto_seed();
        let (sk, _) = ks.derive_keypair(None, "outlayer-crypto:v1").unwrap();
        assert_ne!(seed.as_ref(), sk.as_bytes());
    }
}
