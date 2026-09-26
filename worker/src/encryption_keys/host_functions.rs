//! The `outlayer:encryption-keys/api` host interface
//! (`wit/deps/encryption-keys.wit`).
//!
//! Every call answers with a `result`: an undeclared path, a vault other than
//! the declared one, an input over the limit, or a ciphertext that does not
//! open is an `err` the guest can read, never a trap. Logs name the path and
//! the sizes, never a byte of a key, a plaintext or a tag.

use anyhow::Result;
use tracing::debug;
use wasmtime::component::Linker;

use super::EncryptionKeys;
use crate::signing_keys::shown;

wasmtime::component::bindgen!({
    path: "wit",
    world: "outlayer:encryption-keys/encryption-keys-host",
});

/// Host state for one execution: that run's encryption keys, and nothing else.
pub struct EncryptionKeysHostState {
    keys: EncryptionKeys,
}

impl EncryptionKeysHostState {
    pub fn new(keys: EncryptionKeys) -> Self {
        Self { keys }
    }
}

impl outlayer::encryption_keys::api::Host for EncryptionKeysHostState {
    fn encrypt(&mut self, path: String, vault: Option<String>, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, String> {
        let answer = self.keys.encrypt(&path, vault.as_deref(), &plaintext, &aad);
        debug!(
            path = ?shown(&path),
            vault = ?vault.as_deref().map(shown),
            plaintext_len = plaintext.len(),
            aad_len = aad.len(),
            ok = answer.is_ok(),
            "encryption_keys::encrypt"
        );
        answer
    }

    fn decrypt(&mut self, path: String, vault: Option<String>, ciphertext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, String> {
        let answer = self.keys.decrypt(&path, vault.as_deref(), &ciphertext, &aad);
        debug!(
            path = ?shown(&path),
            vault = ?vault.as_deref().map(shown),
            ciphertext_len = ciphertext.len(),
            aad_len = aad.len(),
            ok = answer.is_ok(),
            "encryption_keys::decrypt"
        );
        answer
    }

    fn mac(&mut self, path: String, vault: Option<String>, data: Vec<u8>) -> Result<Vec<u8>, String> {
        let answer = self.keys.mac(&path, vault.as_deref(), &data);
        debug!(
            path = ?shown(&path),
            vault = ?vault.as_deref().map(shown),
            data_len = data.len(),
            ok = answer.is_ok(),
            "encryption_keys::mac"
        );
        answer
    }
}

/// Add the encryption-keys host functions to a component linker.
pub fn add_encryption_keys_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut EncryptionKeysHostState + Send + Sync + Copy + 'static,
) -> Result<()> {
    outlayer::encryption_keys::api::add_to_linker(linker, get_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption_keys::{declared_encryption_keys, MAX_CRYPT_INPUT_BYTES};
    use crate::signing_keys::{RunSource, SeedHex};
    use outlayer::encryption_keys::api::Host;

    const KEY: &str = "4324b148cb409d9a56e27a37c0cfbc4787481db4dec90cfcd2219a091c4a5d0a";

    fn state() -> EncryptionKeysHostState {
        let manifest: crate::connector_manifest::ProjectManifest = serde_json::from_value(
            serde_json::json!({ "encryption_keys": [{ "path": "records" }] }),
        )
        .unwrap();
        let source = crate::api_client::CodeSource::WasmUrl {
            url: "https://x/y.wasm".into(),
            hash: "ab".repeat(32),
            build_target: "wasm32-wasip2".into(),
        };
        let declared =
            declared_encryption_keys(Some(&manifest), &RunSource::of_job(Some("alice.near/app"), &source, None)).unwrap();
        let keys = serde_json::from_value::<std::collections::BTreeMap<String, SeedHex>>(serde_json::json!({ "records": KEY }))
            .unwrap();
        EncryptionKeysHostState::new(EncryptionKeys::from_keystore(&declared, keys).unwrap())
    }

    /// Every call answers a result, never a trap; and with debug logging on, a
    /// run of calls logs paths and sizes and nothing of the key, the
    /// plaintext or the tag. One test on purpose, as for the signing keys:
    /// `tracing` caches call-site interest process-wide.
    #[test]
    fn the_host_answers_results_and_logs_nothing_secret() {
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
        let plaintext = b"PLAINTEXT-MARKER-7f3a".to_vec();
        let mut tag = Vec::new();
        tracing::subscriber::with_default(subscriber, || {
            let mut s = state();
            let ct = s.encrypt("records".into(), None, plaintext.clone(), b"row".to_vec()).unwrap();
            assert_eq!(s.decrypt("records".into(), None, ct.clone(), b"row".to_vec()).unwrap(), plaintext);
            assert_eq!(s.decrypt("records".into(), None, ct, b"other".to_vec()).unwrap_err(), "decryption failed");
            tag = s.mac("records".into(), None, b"name".to_vec()).unwrap();
            assert_eq!(tag.len(), 32);
            assert!(s.encrypt("nope".into(), None, vec![], vec![]).is_err());
            assert!(s.mac("records".into(), Some("vault.alice.near".into()), vec![]).is_err());
            assert!(s.encrypt("records".into(), None, vec![0; MAX_CRYPT_INPUT_BYTES + 1], vec![]).is_err());
            tracing::debug!(keys = ?s.keys, "keys of the run");
        });
        let logged = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("encryption_keys::encrypt") && logged.contains("records"), "{logged}");
        assert!(!logged.contains(&KEY[..16]), "a key reached the log: {logged}");
        assert!(!logged.contains("PLAINTEXT-MARKER"), "a plaintext reached the log: {logged}");
        assert!(!logged.contains(&hex::encode(&tag)[..16]), "a tag reached the log: {logged}");
    }
}
