//! The `outlayer:signing-keys/api` host interface (`wit/deps/signing-keys.wit`).
//!
//! Every call answers with a `result`: an undeclared path, a vault other than
//! the declared one, a key of a type the call does not serve, or a message over
//! the limit is an `err` the guest can read, never a trap.

use anyhow::Result;
use tracing::debug;
use wasmtime::component::Linker;

use super::SigningKeys;

wasmtime::component::bindgen!({
    path: "wit",
    world: "outlayer:signing-keys/signing-keys-host",
});

/// Host state for one execution: that run's keys, and nothing else.
pub struct SigningKeysHostState {
    keys: SigningKeys,
}

impl SigningKeysHostState {
    pub fn new(keys: SigningKeys) -> Self {
        Self { keys }
    }
}

impl outlayer::signing_keys::api::Host for SigningKeysHostState {
    fn public_key(&mut self, path: String, vault: Option<String>) -> Result<Vec<u8>, String> {
        let answer = self.keys.public_key(&path, vault.as_deref());
        debug!(path = ?super::shown(&path), vault = ?vault.as_deref().map(super::shown), ok = answer.is_ok(), "signing_keys::public_key");
        answer
    }

    fn sign(&mut self, path: String, vault: Option<String>, message: Vec<u8>) -> Result<Vec<u8>, String> {
        let answer = self.keys.sign(&path, vault.as_deref(), &message);
        debug!(
            path = ?super::shown(&path),
            vault = ?vault.as_deref().map(super::shown),
            message_len = message.len(),
            ok = answer.is_ok(),
            "signing_keys::sign"
        );
        answer
    }
}

/// Add the signing-keys host functions to a component linker.
pub fn add_signing_keys_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut SigningKeysHostState + Send + Sync + Copy + 'static,
) -> Result<()> {
    outlayer::signing_keys::api::add_to_linker(linker, get_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_keys::{declared_signing_keys, RunSource, SeedHex};
    use outlayer::signing_keys::api::Host;

    const SEED: &str = "b5ca092c9bb7c321f2d6f69c6eb147907d5df9fcc2309552786e7502706a7493";

    fn state() -> SigningKeysHostState {
        let manifest: crate::connector_manifest::ProjectManifest = serde_json::from_value(
            serde_json::json!({ "signing_keys": [{ "path": "records", "type": "ed25519" }] }),
        )
        .unwrap();
        let source = crate::api_client::CodeSource::WasmUrl {
            url: "https://x/y.wasm".into(),
            hash: "ab".repeat(32),
            build_target: "wasm32-wasip2".into(),
        };
        let declared = declared_signing_keys(Some(&manifest), &RunSource::of_job(Some("alice.near/app"), &source, None)).unwrap();
        let seeds = serde_json::from_value::<std::collections::BTreeMap<String, SeedHex>>(
            serde_json::json!({ "records": SEED }),
        )
        .unwrap();
        SigningKeysHostState::new(SigningKeys::from_keystore(&declared, seeds).unwrap())
    }

    /// Every call answers a result, never a trap; and with debug logging on, a
    /// run of calls logs paths and nothing of the seed. One test on purpose:
    /// `tracing` caches whether a call site is enabled process-wide, and a
    /// second test reaching the same call sites without a subscriber, in
    /// parallel, could switch the capture below off mid-run.
    #[test]
    fn the_host_answers_results_and_logs_nothing_of_the_seed() {
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = {
            let buf = buf.clone();
            move || Sink(buf.clone())
        };
        let subscriber = tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).with_writer(writer).finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut s = state();
            assert_eq!(s.public_key("records".into(), None).unwrap().len(), 32);
            assert_eq!(s.sign("records".into(), None, b"payload".to_vec()).unwrap().len(), 64);
            assert!(s.public_key("other".into(), None).is_err());
            assert!(s.sign("nope".into(), None, b"payload".to_vec()).is_err());
            assert!(s.sign("records".into(), Some("vault.alice.near".into()), b"payload".to_vec()).is_err());
            assert!(s.sign("records".into(), None, vec![0; crate::signing_keys::MAX_SIGN_MESSAGE_BYTES + 1]).is_err());
            tracing::debug!(keys = ?s.keys, "keys of the run");
        });
        let logged = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("signing_keys::sign") && logged.contains("records"), "{logged}");
        assert!(!logged.contains(&SEED[..16]), "a seed reached the log: {logged}");
    }
}
