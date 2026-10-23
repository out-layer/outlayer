//! `outlayer:crypto` for the Defuse Outlayer core, backed by the keystore.
//!
//! The core's host scopes each guest path by App ID and calls its `Signer` with
//! the scoped 32-byte path. [`KeystoreSigner`] derives public keys here, from the
//! keystore's root public keys with the core's own [`MasterSchema`], and sends
//! every signature to the keystore's `/crypto/sign`. No private key of the
//! family is ever in this process.

use std::sync::Arc;

use anyhow::{Context, Result};
use defuse_outlayer_signer::{
    kdf::{
        crypto::{
            ed25519::{ed25519_dalek, Ed25519},
            secp256k1::{k256, Secp256k1},
            Curve, RecoverableCurve,
        },
        DeriveSigner, RecoverableDeriveSigner,
    },
    MasterSchema,
};
use serde::{Deserialize, Serialize};

use crate::keystore_client::KeystoreClient;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CurveName {
    Ed25519,
    Secp256k1,
}

#[derive(Debug, Serialize)]
pub struct SignRequest {
    pub curve: CurveName,
    /// Hex, 32 bytes.
    pub path: String,
    /// Hex.
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct SignResponse {
    /// Hex, 64 bytes.
    pub signature: String,
    pub recovery_id: Option<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RootPublicKeys {
    /// Hex, 32 bytes.
    pub ed25519: String,
    /// Hex, SEC1.
    pub secp256k1: String,
}

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SignError(String);

impl From<anyhow::Error> for SignError {
    fn from(e: anyhow::Error) -> Self {
        Self(format!("{e:#}"))
    }
}

pub struct KeystoreSigner {
    keystore: Arc<KeystoreClient>,
    ed25519: MasterSchema<Ed25519>,
    secp256k1: MasterSchema<Secp256k1>,
}

impl KeystoreSigner {
    pub async fn connect(keystore: Arc<KeystoreClient>) -> Result<Self> {
        let roots = keystore.app_crypto_root_public_keys().await?;
        Self::new(keystore, &roots)
    }

    pub fn new(keystore: Arc<KeystoreClient>, roots: &RootPublicKeys) -> Result<Self> {
        let ed25519: [u8; 32] = hex::decode(&roots.ed25519)
            .ok()
            .and_then(|b| b.try_into().ok())
            .context("ed25519 root public key must be 32 bytes of hex")?;
        let ed25519 = ed25519_dalek::VerifyingKey::from_bytes(&ed25519)
            .context("ed25519 root public key is not a curve point")?;
        let secp256k1 = k256::ecdsa::VerifyingKey::from_sec1_bytes(
            &hex::decode(&roots.secp256k1).context("secp256k1 root public key must be hex")?,
        )
        .context("secp256k1 root public key is not a SEC1 point")?;
        Ok(Self {
            keystore,
            ed25519: MasterSchema::new(ed25519),
            secp256k1: MasterSchema::new(secp256k1),
        })
    }

    async fn sign(&self, curve: CurveName, path: [u8; 32], msg: &[u8]) -> Result<SignResponse> {
        let req = SignRequest { curve, path: hex::encode(path), message: hex::encode(msg) };
        self.keystore.app_crypto_sign(&req).await
    }
}

fn signature_bytes(res: &SignResponse) -> Result<Vec<u8>> {
    hex::decode(&res.signature).context("keystore signature is not hex")
}

impl DeriveSigner<Ed25519, [u8; 32]> for KeystoreSigner {
    type Error = SignError;

    type Schema<'a>
        = MasterSchema<Ed25519>
    where
        Self: 'a;

    fn schema(&self) -> Self::Schema<'_> {
        self.ed25519.clone()
    }

    async fn derive_sign(
        &self,
        path: [u8; 32],
        msg: &[u8],
    ) -> Result<<Ed25519 as Curve>::Signature, Self::Error> {
        let res = self.sign(CurveName::Ed25519, path, msg).await?;
        Ok(ed25519_dalek::Signature::from_slice(&signature_bytes(&res)?)
            .map_err(|e| SignError(format!("keystore ed25519 signature: {e}")))?)
    }
}

impl DeriveSigner<Secp256k1, [u8; 32]> for KeystoreSigner {
    type Error = SignError;

    type Schema<'a>
        = MasterSchema<Secp256k1>
    where
        Self: 'a;

    fn schema(&self) -> Self::Schema<'_> {
        self.secp256k1.clone()
    }

    async fn derive_sign(
        &self,
        path: [u8; 32],
        msg: &[u8],
    ) -> Result<<Secp256k1 as Curve>::Signature, Self::Error> {
        Ok(self.derive_sign_recoverable(path, msg).await?.0)
    }
}

impl RecoverableDeriveSigner<Secp256k1, [u8; 32]> for KeystoreSigner {
    async fn derive_sign_recoverable(
        &self,
        path: [u8; 32],
        msg: &[u8],
    ) -> Result<(<Secp256k1 as Curve>::Signature, <Secp256k1 as RecoverableCurve>::RecoveryId), Self::Error>
    {
        let res = self.sign(CurveName::Secp256k1, path, msg).await?;
        let signature = k256::ecdsa::Signature::from_slice(&signature_bytes(&res)?)
            .map_err(|e| SignError(format!("keystore secp256k1 signature: {e}")))?;
        let recovery_id = res
            .recovery_id
            .and_then(k256::ecdsa::RecoveryId::from_byte)
            .ok_or_else(|| SignError("keystore secp256k1 signature has no valid recovery id".to_string()))?;
        Ok((signature, recovery_id))
    }
}
