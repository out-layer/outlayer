//! OutLayer SDK for WASM components
//!
//! This crate provides a high-level API for OutLayer off-chain WASM execution on NEAR.
//!
//! ## Features
//!
//! - **Storage**: Persistent encrypted storage across executions
//! - **Environment**: Access to execution context (signer, input/output)
//! - **VRF**: Verifiable random function (Ed25519 signatures, on-chain verification)
//! - **Signing keys** (feature `signing-keys`): sign with keys the keystore derives
//!   for the project or build and the caller; the component never sees a key
//! - **Encryption keys** (feature `encryption-keys`): seal data only the component
//!   can open again, and the sealed storage helpers in `storage::sealed`
//!
//! ## Cargo Features
//!
//! A component imports only the host interfaces whose functions it calls, so a
//! feature adds functions to the SDK and changes no import of a component that
//! does not call them.
//!
//! - `signing-keys` - the `signing_keys` module (`outlayer:signing-keys`)
//! - `encryption-keys` - the `encryption_keys` module and `storage::sealed`
//!   (`outlayer:encryption-keys`)
//!
//! Both need keys declared in the component's `outlayer.manifest`; a call on a
//! path the manifest does not declare returns an error.
//!
//! ## Requirements
//!
//! OutLayer SDK requires **wasm32-wasip2** target (WASI Preview 2 / Component Model).
//! WASI Preview 1 (wasm32-wasip1) is NOT supported for storage and RPC features.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use outlayer::{storage, env};
//!
//! fn main() {
//!     // Get input from execution request
//!     let input = env::input();
//!
//!     // Use persistent storage
//!     storage::set("counter", b"42").unwrap();
//!     let value = storage::get("counter").unwrap();
//!
//!     // Return output
//!     env::output(b"result");
//! }
//! ```
//!
//! ## Compile-Time Target Check
//!
//! This crate will fail to compile if you target wasm32-wasip1:
//!
//! ```bash
//! # Correct - will work:
//! cargo build --target wasm32-wasip2 --release
//!
//! # Wrong - will fail to compile:
//! cargo build --target wasm32-wasip1 --release
//! ```

// Compile-time check: OutLayer SDK requires wasm32-wasip2
#[cfg(all(
    target_arch = "wasm32",
    target_os = "wasi",
    not(target_env = "p2")
))]
compile_error!(
    "OutLayer SDK requires wasm32-wasip2 target (WASI Preview 2). You are compiling with wasm32-wasip1 which does not support OutLayer host functions."
);

// Generate bindings from WIT
wit_bindgen::generate!({
    world: "outlayer-host",
    path: "wit",
    with: {
        "near:storage/api@0.1.0": generate,
        "near:vrf/api@0.1.0": generate,
    },
});

// Each opt-in interface is generated from its own world, so a build without the
// feature carries no trace of it.
#[cfg(feature = "signing-keys")]
mod signing_keys_bindings {
    wit_bindgen::generate!({
        world: "outlayer:signing-keys/signing-keys-host",
        path: "wit",
    });
}

#[cfg(feature = "encryption-keys")]
mod encryption_keys_bindings {
    wit_bindgen::generate!({
        world: "outlayer:encryption-keys/encryption-keys-host",
        path: "wit",
    });
}

pub mod storage;
pub mod env;
pub mod vrf;
#[cfg(feature = "signing-keys")]
pub mod signing_keys;
#[cfg(feature = "encryption-keys")]
pub mod encryption_keys;

/// Low-level access to generated WIT bindings
///
/// Most users should use the high-level `storage`, `env`, `vrf`, `signing_keys`
/// and `encryption_keys` modules instead.
pub mod raw {
    pub use super::near::rpc::api as rpc;
    pub use super::near::storage::api as storage;
    pub use super::near::vrf::api as vrf;
    #[cfg(feature = "signing-keys")]
    pub use super::signing_keys_bindings::outlayer::signing_keys::api as signing_keys;
    #[cfg(feature = "encryption-keys")]
    pub use super::encryption_keys_bindings::outlayer::encryption_keys::api as encryption_keys;
}
