//! Storage host functions for WASM components
//!
//! Implements the `near:storage/api` WIT interface in both published versions.
//! A component carries the exact types of the interface it imports, so every
//! version a deployed binary may import stays registered, each in its own
//! shape: `@0.2.0` (`wit/deps/storage.wit`, the SDK's current one) and `@0.1.0`
//! (`wit/storage-v0_1/storage.wit`, binaries built on SDK 0.1). How to add a
//! version: `wit/README.md`.

use anyhow::Result;
use tracing::debug;
use wasmtime::component::Linker;

use super::client::{StorageClient, StorageConfig};

// `near:storage/api@0.2.0`.
wasmtime::component::bindgen!({
    path: "wit",
    world: "near:storage/storage-host",
});

/// `near:storage/api@0.1.0`. Published, so its shape never changes: `has` and
/// `delete` answer a bare bool (false also when the storage call fails) and
/// `has-checked` / `delete-checked` carry the error. Every other function is
/// the same as in `@0.2.0`.
mod v0_1 {
    wasmtime::component::bindgen!({
        path: "wit/storage-v0_1",
        world: "near:storage/storage-host",
    });
}

/// Host state for storage functions
pub struct StorageHostState {
    client: StorageClient,
}

impl StorageHostState {
    /// Create new storage host state from config
    #[allow(dead_code)]
    pub fn new(config: StorageConfig) -> Result<Self> {
        let client = StorageClient::new(config)?;
        Ok(Self { client })
    }

    /// Create new storage host state from existing client
    pub fn from_client(client: StorageClient) -> Self {
        Self { client }
    }
}

impl near::storage::api::Host for StorageHostState {
    fn set(&mut self, key: String, value: Vec<u8>) -> String {
        debug!("storage::set key={}, value_len={}", key, value.len());
        match self.client.set(&key, &value) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    fn get(&mut self, key: String) -> (Vec<u8>, String) {
        debug!("storage::get key={}", key);
        match self.client.get(&key) {
            Ok(Some(value)) => (value, String::new()),
            Ok(None) => (Vec::new(), String::new()),
            Err(e) => (Vec::new(), e.to_string()),
        }
    }

    fn has(&mut self, key: String) -> (bool, String) {
        debug!("storage::has key={}", key);
        match self.client.has(&key) {
            Ok(exists) => (exists, String::new()),
            Err(e) => (false, e.to_string()),
        }
    }

    fn delete(&mut self, key: String) -> (bool, String) {
        debug!("storage::delete key={}", key);
        match self.client.delete(&key) {
            Ok(deleted) => (deleted, String::new()),
            Err(e) => (false, e.to_string()),
        }
    }

    fn list_keys(&mut self, prefix: String) -> (String, String) {
        debug!("storage::list_keys prefix={}", prefix);
        match self.client.list_keys(&prefix) {
            Ok(keys) => (keys, String::new()),
            Err(e) => (String::from("[]"), e.to_string()),
        }
    }

    fn set_worker(&mut self, key: String, value: Vec<u8>, is_encrypted: Option<bool>) -> String {
        let encrypted = is_encrypted.unwrap_or(true);
        debug!("storage::set_worker key={}, value_len={}, is_encrypted={}", key, value.len(), encrypted);
        match self.client.set_worker(&key, &value, encrypted) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    fn get_worker(&mut self, key: String, project: Option<String>) -> (Vec<u8>, String) {
        debug!("storage::get_worker key={}, project={:?}", key, project);
        match self.client.get_worker(&key, project.as_deref()) {
            Ok(Some(value)) => (value, String::new()),
            Ok(None) => (Vec::new(), String::new()),
            Err(e) => (Vec::new(), e.to_string()),
        }
    }

    fn get_by_version(&mut self, key: String, wasm_hash: String) -> (Vec<u8>, String) {
        debug!("storage::get_by_version key={}, wasm_hash={}", key, wasm_hash);
        match self.client.get_by_version(&key, &wasm_hash) {
            Ok(Some(value)) => (value, String::new()),
            Ok(None) => (Vec::new(), String::new()),
            Err(e) => (Vec::new(), e.to_string()),
        }
    }

    fn clear_all(&mut self) -> String {
        debug!("storage::clear_all");
        match self.client.clear_all() {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    fn clear_version(&mut self, wasm_hash: String) -> String {
        debug!("storage::clear_version wasm_hash={}", wasm_hash);
        match self.client.clear_version(&wasm_hash) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    // ==================== Conditional Write Operations ====================

    fn set_if_absent(&mut self, key: String, value: Vec<u8>) -> (bool, String) {
        debug!("storage::set_if_absent key={}, value_len={}", key, value.len());
        match self.client.set_if_absent(&key, &value) {
            Ok(inserted) => (inserted, String::new()),
            Err(e) => (false, e.to_string()),
        }
    }

    fn set_if_equals(&mut self, key: String, expected: Vec<u8>, new_value: Vec<u8>) -> (bool, Vec<u8>, String) {
        debug!("storage::set_if_equals key={}, expected_len={}, new_len={}", key, expected.len(), new_value.len());
        match self.client.set_if_equals(&key, &expected, &new_value) {
            Ok((success, current)) => (success, current.unwrap_or_default(), String::new()),
            Err(e) => (false, Vec::new(), e.to_string()),
        }
    }

    // ==================== Raw Operations ====================

    fn set_raw(&mut self, key: String, value: Vec<u8>) -> String {
        debug!("storage::set_raw key={}, value_len={}", key, value.len());
        match self.client.set_raw(&key, &value) {
            Ok(()) => String::new(),
            Err(e) => e.to_string(),
        }
    }

    fn get_raw(&mut self, key: String) -> (Vec<u8>, String) {
        debug!("storage::get_raw key={}", key);
        match self.client.get_raw(&key) {
            Ok(Some(value)) => (value, String::new()),
            Ok(None) => (Vec::new(), String::new()),
            Err(e) => (Vec::new(), e.to_string()),
        }
    }

    fn set_if_absent_raw(&mut self, key: String, value: Vec<u8>) -> (bool, String) {
        debug!("storage::set_if_absent_raw key={}, value_len={}", key, value.len());
        match self.client.set_if_absent_raw(&key, &value) {
            Ok(inserted) => (inserted, String::new()),
            Err(e) => (false, e.to_string()),
        }
    }

    fn set_if_equals_raw(&mut self, key: String, expected: Vec<u8>, new_value: Vec<u8>) -> (bool, Vec<u8>, String) {
        debug!("storage::set_if_equals_raw key={}, expected_len={}, new_len={}", key, expected.len(), new_value.len());
        match self.client.set_if_equals_raw(&key, &expected, &new_value) {
            Ok((success, current)) => (success, current.unwrap_or_default(), String::new()),
            Err(e) => (false, Vec::new(), e.to_string()),
        }
    }

    fn increment(&mut self, key: String, delta: i64) -> (i64, String) {
        debug!("storage::increment key={}, delta={}", key, delta);
        match self.client.increment(&key, delta) {
            Ok(new_value) => (new_value, String::new()),
            Err(e) => (0, e.to_string()),
        }
    }

    fn decrement(&mut self, key: String, delta: i64) -> (i64, String) {
        debug!("storage::decrement key={}, delta={}", key, delta);
        match self.client.decrement(&key, delta) {
            Ok(new_value) => (new_value, String::new()),
            Err(e) => (0, e.to_string()),
        }
    }
}

impl v0_1::near::storage::api::Host for StorageHostState {
    fn has(&mut self, key: String) -> bool {
        debug!("storage::has@0.1.0 key={}", key);
        self.client.has(&key).unwrap_or(false)
    }

    fn has_checked(&mut self, key: String) -> (bool, String) {
        <Self as near::storage::api::Host>::has(self, key)
    }

    fn delete(&mut self, key: String) -> bool {
        debug!("storage::delete@0.1.0 key={}", key);
        self.client.delete(&key).unwrap_or(false)
    }

    fn delete_checked(&mut self, key: String) -> (bool, String) {
        <Self as near::storage::api::Host>::delete(self, key)
    }

    fn set(&mut self, key: String, value: Vec<u8>) -> String {
        <Self as near::storage::api::Host>::set(self, key, value)
    }

    fn get(&mut self, key: String) -> (Vec<u8>, String) {
        <Self as near::storage::api::Host>::get(self, key)
    }

    fn list_keys(&mut self, prefix: String) -> (String, String) {
        <Self as near::storage::api::Host>::list_keys(self, prefix)
    }

    fn set_worker(&mut self, key: String, value: Vec<u8>, is_encrypted: Option<bool>) -> String {
        <Self as near::storage::api::Host>::set_worker(self, key, value, is_encrypted)
    }

    fn get_worker(&mut self, key: String, project: Option<String>) -> (Vec<u8>, String) {
        <Self as near::storage::api::Host>::get_worker(self, key, project)
    }

    fn get_by_version(&mut self, key: String, wasm_hash: String) -> (Vec<u8>, String) {
        <Self as near::storage::api::Host>::get_by_version(self, key, wasm_hash)
    }

    fn clear_all(&mut self) -> String {
        <Self as near::storage::api::Host>::clear_all(self)
    }

    fn clear_version(&mut self, wasm_hash: String) -> String {
        <Self as near::storage::api::Host>::clear_version(self, wasm_hash)
    }

    fn set_if_absent(&mut self, key: String, value: Vec<u8>) -> (bool, String) {
        <Self as near::storage::api::Host>::set_if_absent(self, key, value)
    }

    fn set_if_equals(&mut self, key: String, expected: Vec<u8>, new_value: Vec<u8>) -> (bool, Vec<u8>, String) {
        <Self as near::storage::api::Host>::set_if_equals(self, key, expected, new_value)
    }

    fn set_raw(&mut self, key: String, value: Vec<u8>) -> String {
        <Self as near::storage::api::Host>::set_raw(self, key, value)
    }

    fn get_raw(&mut self, key: String) -> (Vec<u8>, String) {
        <Self as near::storage::api::Host>::get_raw(self, key)
    }

    fn set_if_absent_raw(&mut self, key: String, value: Vec<u8>) -> (bool, String) {
        <Self as near::storage::api::Host>::set_if_absent_raw(self, key, value)
    }

    fn set_if_equals_raw(&mut self, key: String, expected: Vec<u8>, new_value: Vec<u8>) -> (bool, Vec<u8>, String) {
        <Self as near::storage::api::Host>::set_if_equals_raw(self, key, expected, new_value)
    }

    fn increment(&mut self, key: String, delta: i64) -> (i64, String) {
        <Self as near::storage::api::Host>::increment(self, key, delta)
    }

    fn decrement(&mut self, key: String, delta: i64) -> (i64, String) {
        <Self as near::storage::api::Host>::decrement(self, key, delta)
    }
}

/// Add storage host functions to a wasmtime component linker: both versions
/// of `near:storage/api`.
pub fn add_storage_to_linker<T: Send + 'static>(
    linker: &mut Linker<T>,
    get_state: impl Fn(&mut T) -> &mut StorageHostState + Send + Sync + Copy + 'static,
) -> Result<()> {
    near::storage::api::add_to_linker(linker, get_state)?;
    v0_1::near::storage::api::add_to_linker(linker, get_state)
}

#[cfg(test)]
mod tests {
    use super::near::storage::api::Host;
    use super::*;
    use crate::outlayer_storage::fake_http::{bytes_json, config, key_hash, mode_mismatch, serve, untouched_keystore};
    use serde_json::json;

    fn host(coordinator: &crate::outlayer_storage::fake_http::FakeServer) -> StorageHostState {
        let keystore = untouched_keystore();
        StorageHostState::new(config(coordinator, &keystore)).unwrap()
    }

    /// The raw functions map the client's answers onto the WIT shapes: empty
    /// string / empty list for success and absence, the message for an error.
    #[test]
    fn raw_functions_answer_in_the_wit_shapes() {
        let coordinator = serve(|path, body| {
            let hash = body["key_hash"].as_str().unwrap_or_default().to_string();
            match path {
                "/storage/set" if hash == key_hash("enc") => mode_mismatch(true),
                "/storage/set" => (200, String::new()),
                "/storage/get" if hash == key_hash("raw") => (
                    200,
                    json!({ "exists": true, "encrypted_key": b"raw", "encrypted_value": [7, 8], "is_encrypted": false }).to_string(),
                ),
                "/storage/get" if hash == key_hash("enc") => (
                    200,
                    json!({ "exists": true, "encrypted_key": [1], "encrypted_value": [2], "is_encrypted": true }).to_string(),
                ),
                "/storage/get" => (200, json!({ "exists": false }).to_string()),
                "/storage/set-if-absent" => (200, json!({ "inserted": hash == key_hash("fresh") }).to_string()),
                "/storage/set-if-equals" if body["expected_encrypted_value"] == bytes_json(b"v1") => {
                    (200, json!({ "updated": true }).to_string())
                }
                "/storage/set-if-equals" if hash == key_hash("missing") => (200, json!({ "updated": false }).to_string()),
                "/storage/set-if-equals" => (
                    200,
                    json!({ "updated": false, "current_encrypted_value": [5], "current_encrypted_key": b"c" }).to_string(),
                ),
                _ => (404, String::new()),
            }
        });
        let mut state = host(&coordinator);

        assert_eq!(state.set_raw("k".into(), b"v".to_vec()), "");
        assert!(state.set_raw("enc".into(), b"v".to_vec()).starts_with("the record at this key was written encrypted;"));

        assert_eq!(state.get_raw("raw".into()), (vec![7, 8], String::new()));
        assert_eq!(state.get_raw("missing".into()), (Vec::new(), String::new()));
        assert_eq!(
            state.get_raw("enc".into()),
            (Vec::new(), "the record at this key was written encrypted; read it with get".to_string())
        );

        assert_eq!(state.set_if_absent_raw("fresh".into(), b"v".to_vec()), (true, String::new()));
        assert_eq!(state.set_if_absent_raw("taken".into(), b"v".to_vec()), (false, String::new()));

        assert_eq!(state.set_if_equals_raw("c".into(), b"v1".to_vec(), b"v2".to_vec()), (true, Vec::new(), String::new()));
        assert_eq!(state.set_if_equals_raw("c".into(), b"old".to_vec(), b"v2".to_vec()), (false, vec![5], String::new()));
        assert_eq!(state.set_if_equals_raw("missing".into(), Vec::new(), b"v".to_vec()), (false, Vec::new(), String::new()));
    }

    /// `@0.1.0` answers in its published shapes: a bare bool for `has` and
    /// `delete`, false also when the call fails; the `-checked` forms carry
    /// the error.
    #[test]
    fn v0_1_answers_in_its_published_shapes() {
        use super::v0_1::near::storage::api::Host as V0_1;
        let coordinator = serve(|path, body| {
            let hash = body["key_hash"].as_str().unwrap_or_default().to_string();
            match path {
                _ if hash == key_hash("broken") => (500, String::new()),
                "/storage/has" => (200, json!({ "exists": hash == key_hash("here") }).to_string()),
                "/storage/delete" if hash == key_hash("here") => (200, String::new()),
                "/storage/delete" => (404, String::new()),
                _ => (404, String::new()),
            }
        });
        let mut state = host(&coordinator);

        assert!(V0_1::has(&mut state, "here".into()));
        assert!(!V0_1::has(&mut state, "gone".into()));
        assert!(!V0_1::has(&mut state, "broken".into()));
        assert_eq!(V0_1::has_checked(&mut state, "here".into()), (true, String::new()));
        assert_eq!(V0_1::has_checked(&mut state, "broken".into()), (false, "storage has failed: HTTP 500 Internal Server Error".to_string()));

        assert!(V0_1::delete(&mut state, "here".into()));
        assert!(!V0_1::delete(&mut state, "gone".into()));
        assert!(!V0_1::delete(&mut state, "broken".into()));
        assert_eq!(V0_1::delete_checked(&mut state, "gone".into()), (false, String::new()));
        assert_eq!(
            V0_1::delete_checked(&mut state, "broken".into()),
            (false, "storage delete failed: HTTP 500 Internal Server Error".to_string())
        );
    }

    /// Whether a component importing `near:storage/api` in the given version
    /// and shape links against the worker's storage functions.
    fn links(version: &str, functions: &str) -> std::result::Result<(), String> {
        let engine = wasmtime::Engine::new(wasmtime::Config::new().wasm_component_model(true)).unwrap();
        let wat = format!(r#"(component (import "near:storage/api@{version}" (instance {functions})))"#);
        let component = wasmtime::component::Component::new(&engine, wat::parse_str(&wat).unwrap()).unwrap();
        let mut linker: Linker<StorageHostState> = Linker::new(&engine);
        add_storage_to_linker(&mut linker, |s| s).unwrap();
        linker.instantiate_pre(&component).map(|_| ()).map_err(|e| format!("{e:#}"))
    }

    /// Both published versions link in their own shapes, and neither in the
    /// other's: `@0.1.0` is the SDK 0.1 interface, `@0.2.0` the current one.
    #[test]
    fn each_published_version_links_in_its_own_shape() {
        const BOOL_FORMS: &str = r#"
            (export "has" (func (param "key" string) (result bool)))
            (export "has-checked" (func (param "key" string) (result (tuple bool string))))
            (export "delete" (func (param "key" string) (result bool)))
            (export "delete-checked" (func (param "key" string) (result (tuple bool string))))
            (export "set-worker" (func (param "key" string) (param "value" (list u8)) (param "is-encrypted" (option bool)) (result string)))"#;
        const TUPLE_FORMS: &str = r#"
            (export "has" (func (param "key" string) (result (tuple bool string))))
            (export "delete" (func (param "key" string) (result (tuple bool string))))
            (export "set-worker" (func (param "key" string) (param "value" (list u8)) (param "is-encrypted" (option bool)) (result string)))"#;

        links("0.1.0", BOOL_FORMS).unwrap();
        links("0.2.0", TUPLE_FORMS).unwrap();
        assert!(links("0.1.0", TUPLE_FORMS).unwrap_err().contains("wrong type"));
        assert!(links("0.2.0", BOOL_FORMS).is_err());
    }

    /// get on a raw record reaches the guest as an error naming get-raw.
    #[test]
    fn get_on_a_raw_record_reaches_the_guest_as_an_error() {
        let coordinator = serve(|_, _| {
            (200, json!({ "exists": true, "encrypted_key": b"k", "encrypted_value": [1], "is_encrypted": false }).to_string())
        });
        let mut state = host(&coordinator);

        assert_eq!(
            state.get("k".into()),
            (Vec::new(), "the record at this key was written raw; read it with get-raw".to_string())
        );
    }
}
