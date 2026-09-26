//! Signing keys for OutLayer WASM components (feature `signing-keys`)
//!
//! The keystore derives each key inside the TEE, for this run only, from how the
//! code is run and the account that called for the run. The component never sees
//! a key: it names one by `path` and the host signs.
//!
//! ## Declaring Keys
//!
//! A component declares its keys, at most three, in its `outlayer.manifest`
//! custom section:
//!
//! ```json
//! "signing_keys": [
//!   {"path": "records", "type": "ed25519"},
//!   {"path": "votes", "type": "ed25519", "caller": "predecessor"},
//!   {"path": "payouts", "type": "secp256k1", "vault": "vault.owner.near"}
//! ]
//! ```
//!
//! - `bind: "project"` (the default): the key belongs to the project and the
//!   caller, and every version of the project signs with it. Issued only to a
//!   run through a project whose running version is published as a WasmUrl.
//! - `bind: "wasm"`: the key belongs to this exact build and the caller. Issued
//!   only to a direct run of a wasm URL.
//! - `caller`: `"signer"` (the default) or `"predecessor"`.
//! - `vault` (only with `bind: "project"`): derive from that vault's master.
//!
//! A call passes the key's declared vault exactly: `None` for a key declared
//! without one, `Some(vault)` for a key declared with that vault. An undeclared
//! path, another vault, or a message the key's type does not take is an error.
//!
//! ## Never Sign Caller-Supplied Bytes
//!
//! An ed25519 public key is a NEAR implicit account; a secp256k1 key is an EVM
//! address. A signature over bytes the caller chose is a signature over whatever
//! those bytes are — a transaction, a permit, a login. Sign only messages this
//! component composes itself, from fields it has parsed and checked, under a
//! fixed prefix or structure of its own. Any contract the signer transacts with
//! can start a run under the signer's key with input of its own choosing, so the
//! input is never the signer's intent.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use outlayer::signing_keys;
//!
//! let public_key = signing_keys::public_key("records", None)?;
//! let message = format!("myapp:record:v1:{}", record_id);
//! let signature = signing_keys::sign("records", None, message.as_bytes())?;
//!
//! // NEP-413 (NEAR `signMessage`); the host builds the signed bytes
//! let nonce = [0u8; 32];
//! let signed = signing_keys::sign_nep413("records", None, "login", "myapp.near", &nonce, None)?;
//! println!("{} {} {}", signed.account_id, signed.public_key, signed.signature);
//! ```

use crate::raw::signing_keys as raw;

/// Signing key error: the reason the host gave
#[derive(Debug, Clone)]
pub struct SigningKeyError(pub String);

impl std::fmt::Display for SigningKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signing key error: {}", self.0)
    }
}

impl std::error::Error for SigningKeyError {}

/// Result type for signing key operations
pub type Result<T> = std::result::Result<T, SigningKeyError>;

/// A NEP-413 signature in the shape a NEAR wallet's `signMessage` answers
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nep413Signature {
    /// The key's NEAR implicit account: its 32-byte public key, lowercase hex
    /// (64 characters)
    pub account_id: String,
    /// `ed25519:` followed by the base58 of the 32-byte public key
    pub public_key: String,
    /// The 64-byte ed25519 signature, standard base64 with padding
    pub signature: String,
}

/// Get the public key of the declared key at `path`
///
/// # Returns
/// * ed25519: the 32-byte public key
/// * secp256k1: 64 bytes, `x ‖ y` — the uncompressed SEC1 point without its
///   `0x04` prefix. The EVM address is the last 20 bytes of keccak256 of these
///   64 bytes.
///
/// # Example
/// ```rust,ignore
/// let public_key = signing_keys::public_key("records", None)?;
/// ```
pub fn public_key(path: &str, vault: Option<&str>) -> Result<Vec<u8>> {
    raw::public_key(path, vault).map_err(SigningKeyError)
}

/// Sign `message` with the declared key at `path`
///
/// # Arguments
/// * `path` - The declared key's path
/// * `vault` - The key's declared vault, `None` if it has none
/// * `message` - ed25519: the raw message, at most 65536 bytes (no prehash, no
///   prefix). secp256k1: exactly 32 bytes, a prehash signed as it is.
///
/// # Returns
/// * ed25519: a 64-byte RFC 8032 signature
/// * secp256k1: 65 bytes, `r ‖ s ‖ v` — low `s`, `v` the recovery id 0 or 1
///   (EVM wants `v + 27`); RFC 6979 nonce, so one prehash gives one signature
///
/// # Example
/// ```rust,ignore
/// let message = format!("myapp:record:v1:{}", record_id);
/// let signature = signing_keys::sign("records", None, message.as_bytes())?;
/// ```
pub fn sign(path: &str, vault: Option<&str>, message: &[u8]) -> Result<Vec<u8>> {
    raw::sign(path, vault, message).map_err(SigningKeyError)
}

/// Sign a NEP-413 message (NEAR `signMessage`) with the declared ed25519 key at `path`
///
/// The host builds the signed bytes: `sha256(borsh(2^31 + 413) ‖ borsh(payload))`
/// with the payload `{message, nonce, recipient, callback_url}`, and signs the
/// hash. Anything that verifies a wallet's NEP-413 signature verifies this one.
///
/// A caller-chosen `message` and `recipient` is a login, as the key's account,
/// to whatever site the caller names: compose both here.
///
/// # Arguments
/// * `message` - At most 65536 bytes
/// * `recipient` - At most 2048 bytes
/// * `nonce` - 32 bytes
/// * `callback_url` - At most 2048 bytes
///
/// # Returns
/// * `Ok(Nep413Signature)` - Account, public key and signature
/// * `Err(SigningKeyError)` - Undeclared path, another vault, a key that is not
///   ed25519, or an input over its limit
///
/// # Example
/// ```rust,ignore
/// let signed = signing_keys::sign_nep413("records", None, "login", "myapp.near", &nonce, None)?;
/// ```
pub fn sign_nep413(
    path: &str,
    vault: Option<&str>,
    message: &str,
    recipient: &str,
    nonce: &[u8; 32],
    callback_url: Option<&str>,
) -> Result<Nep413Signature> {
    let signed = raw::sign_nep413(path, vault, message, recipient, nonce, callback_url)
        .map_err(SigningKeyError)?;
    Ok(Nep413Signature {
        account_id: signed.account_id,
        public_key: signed.public_key,
        signature: signed.signature,
    })
}
