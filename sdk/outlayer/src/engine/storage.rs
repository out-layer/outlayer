//! Storage over HTTPS with the run's call token, shaped like
//! `near:storage/api@0.2.0` so that `crate::storage` wraps it unchanged.
//!
//! The same two services the host functions talk to, with the same bodies: the
//! keystore seals and opens records (`/storage/encrypt`, `/storage/decrypt`), the
//! coordinator stores them (`/storage/*`). The token opens exactly the cell the
//! worker registered — `OUTLAYER_PROJECT_UUID`, `OUTLAYER_STORAGE_ACCOUNT`,
//! `OUTLAYER_STORAGE_WASM_HASH` — so a request outside it is refused by the
//! service, not merely unsent. Every function returns the host interface's
//! shape: an error string, empty when the call succeeded.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{http, var};

struct Cell {
    api: String,
    keystore: String,
    token: String,
    project_uuid: String,
    wasm_hash: String,
    account: String,
}

fn cell() -> Result<Cell, String> {
    let need = |k: &str| var(k).filter(|v| !v.is_empty()).ok_or_else(|| format!("storage is not available to this run: {k} is not set"));
    Ok(Cell {
        api: need("OUTLAYER_API_BASE")?,
        keystore: need("OUTLAYER_KEYSTORE_BASE")?,
        token: need("OUTLAYER_CALL_TOKEN")?,
        project_uuid: need("OUTLAYER_PROJECT_UUID")?,
        wasm_hash: need("OUTLAYER_STORAGE_WASM_HASH")?,
        account: need("OUTLAYER_STORAGE_ACCOUNT")?,
    })
}

fn hash_key(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn un_b64(text: &str, what: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(text).map_err(|e| format!("{what}: bad base64: {e}"))
}

#[derive(Deserialize)]
struct GetResponse {
    exists: bool,
    encrypted_key: Option<Vec<u8>>,
    encrypted_value: Option<Vec<u8>>,
    #[serde(default = "default_true")]
    is_encrypted: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct ModeMismatch {
    stored_is_encrypted: bool,
}

/// The services' refusal of a write in the wrong mode (409 with a body naming the
/// stored mode), as the host's own wording.
fn refusal(reply: &http::Reply, advice: &str) -> String {
    if reply.status == 409 {
        if let Ok(m) = serde_json::from_slice::<ModeMismatch>(&reply.body) {
            let stored = if m.stored_is_encrypted { "encrypted" } else { "raw" };
            return format!("the record at this key was written {stored}; {advice}");
        }
    }
    format!("storage: HTTP {}: {}", reply.status, reply.text())
}

struct Sealed {
    key: Vec<u8>,
    value: Vec<u8>,
    key_hash: String,
}

fn seal(c: &Cell, key: &str, value: &[u8]) -> Result<Sealed, String> {
    let body = serde_json::json!({
        "project_uuid": c.project_uuid,
        "wasm_hash": c.wasm_hash,
        "account_id": c.account,
        "key": key,
        "value_base64": b64(value),
    });
    let reply = http::post_json(&format!("{}/storage/encrypt", c.keystore), &c.token, &body)?;
    if !reply.ok() {
        return Err(format!("keystore encrypt: HTTP {}: {}", reply.status, reply.text()));
    }
    #[derive(Deserialize)]
    struct R {
        encrypted_key_base64: String,
        encrypted_value_base64: String,
        key_hash: String,
    }
    let r: R = reply.json("keystore encrypt")?;
    Ok(Sealed {
        key: un_b64(&r.encrypted_key_base64, "keystore encrypt")?,
        value: un_b64(&r.encrypted_value_base64, "keystore encrypt")?,
        key_hash: r.key_hash,
    })
}

fn open(c: &Cell, encrypted_key: &[u8], encrypted_value: &[u8]) -> Result<(String, Vec<u8>), String> {
    let body = serde_json::json!({
        "project_uuid": c.project_uuid,
        "wasm_hash": c.wasm_hash,
        "account_id": c.account,
        "encrypted_key_base64": b64(encrypted_key),
        "encrypted_value_base64": b64(encrypted_value),
    });
    let reply = http::post_json(&format!("{}/storage/decrypt", c.keystore), &c.token, &body)?;
    if !reply.ok() {
        return Err(format!("keystore decrypt: HTTP {}: {}", reply.status, reply.text()));
    }
    #[derive(Deserialize)]
    struct R {
        key: String,
        value_base64: String,
    }
    let r: R = reply.json("keystore decrypt")?;
    Ok((r.key, un_b64(&r.value_base64, "keystore decrypt")?))
}

fn record(c: &Cell, key_hash: &str) -> Result<Option<(Vec<u8>, Vec<u8>, bool)>, String> {
    let body = serde_json::json!({ "project_uuid": c.project_uuid, "account_id": c.account, "key_hash": key_hash });
    let reply = http::post_json(&format!("{}/storage/get", c.api), &c.token, &body)?;
    if !reply.ok() {
        return Err(format!("storage get: HTTP {}: {}", reply.status, reply.text()));
    }
    let r: GetResponse = reply.json("storage get")?;
    Ok(match (r.exists, r.encrypted_key, r.encrypted_value) {
        (true, Some(k), Some(v)) => Some((k, v, r.is_encrypted)),
        _ => None,
    })
}

fn write(c: &Cell, key_hash: &str, key_bytes: &[u8], value: &[u8], is_encrypted: bool) -> Result<(), String> {
    let body = serde_json::json!({
        "project_uuid": c.project_uuid,
        "wasm_hash": c.wasm_hash,
        "account_id": c.account,
        "key_hash": key_hash,
        "encrypted_key": key_bytes,
        "encrypted_value": value,
        "is_encrypted": is_encrypted,
    });
    let reply = http::post_json(&format!("{}/storage/set", c.api), &c.token, &body)?;
    if !reply.ok() {
        let advice = if is_encrypted { "write it with set-raw or delete it first" } else { "write it with set or delete it first" };
        return Err(refusal(&reply, advice));
    }
    Ok(())
}

fn ok_or<T>(r: Result<T, String>, empty: T) -> (T, String) {
    match r {
        Ok(v) => (v, String::new()),
        Err(e) => (empty, e),
    }
}

// ==================== Basic Storage ====================

pub fn set(key: &str, value: &[u8]) -> String {
    let run = || {
        let c = cell()?;
        let s = seal(&c, key, value)?;
        write(&c, &s.key_hash, &s.key, &s.value, true)
    };
    run().err().unwrap_or_default()
}

pub fn get(key: &str) -> (Vec<u8>, String) {
    let run = || {
        let c = cell()?;
        match record(&c, &hash_key(key))? {
            None => Ok(Vec::new()),
            Some((_, _, false)) => Err("the record at this key was written raw; read it with get-raw".to_string()),
            Some((k, v, true)) => Ok(open(&c, &k, &v)?.1),
        }
    };
    ok_or(run(), Vec::new())
}

pub fn has(key: &str) -> (bool, String) {
    let run = || {
        let c = cell()?;
        let body = serde_json::json!({ "project_uuid": c.project_uuid, "account_id": c.account, "key_hash": hash_key(key) });
        let reply = http::post_json(&format!("{}/storage/has", c.api), &c.token, &body)?;
        if !reply.ok() {
            return Err(format!("storage has: HTTP {}: {}", reply.status, reply.text()));
        }
        #[derive(Deserialize)]
        struct R {
            exists: bool,
        }
        Ok(reply.json::<R>("storage has")?.exists)
    };
    ok_or(run(), false)
}

pub fn delete(key: &str) -> (bool, String) {
    let run = || {
        let c = cell()?;
        let body = serde_json::json!({ "project_uuid": c.project_uuid, "account_id": c.account, "key_hash": hash_key(key) });
        let reply = http::post_json(&format!("{}/storage/delete", c.api), &c.token, &body)?;
        match reply.status {
            s if (200..300).contains(&s) => Ok(true),
            404 => Ok(false),
            s => Err(format!("storage delete: HTTP {s}: {}", reply.text())),
        }
    };
    ok_or(run(), false)
}

pub fn list_keys(prefix: &str) -> (String, String) {
    let run = || {
        let c = cell()?;
        let url = format!(
            "{}/storage/list?account_id={}&project_uuid={}",
            c.api,
            percent(&c.account),
            percent(&c.project_uuid)
        );
        let reply = http::get(&url, &c.token)?;
        if !reply.ok() {
            return Err(format!("storage list: HTTP {}: {}", reply.status, reply.text()));
        }
        #[derive(Deserialize)]
        struct R {
            keys: Vec<Item>,
        }
        #[derive(Deserialize)]
        struct Item {
            encrypted_key: Vec<u8>,
            encrypted_value: Vec<u8>,
            #[serde(default = "default_true")]
            is_encrypted: bool,
        }
        let r: R = reply.json("storage list")?;
        let mut keys = Vec::new();
        for item in r.keys {
            let key = if item.is_encrypted {
                match open(&c, &item.encrypted_key, &item.encrypted_value) {
                    Ok((k, _)) => k,
                    Err(_) => continue,
                }
            } else {
                match String::from_utf8(item.encrypted_key) {
                    Ok(k) => k,
                    Err(_) => continue,
                }
            };
            if key.starts_with(prefix) {
                keys.push(key);
            }
        }
        serde_json::to_string(&keys).map_err(|e| e.to_string())
    };
    ok_or(run(), String::new())
}

fn percent(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// ==================== Conditional Writes ====================

pub fn set_if_absent(key: &str, value: &[u8]) -> (bool, String) {
    let run = || {
        let c = cell()?;
        let s = seal(&c, key, value)?;
        insert_if_absent(&c, &s.key_hash, &s.key, &s.value, true)
    };
    ok_or(run(), false)
}

fn insert_if_absent(c: &Cell, key_hash: &str, key_bytes: &[u8], value: &[u8], is_encrypted: bool) -> Result<bool, String> {
    let body = serde_json::json!({
        "project_uuid": c.project_uuid,
        "wasm_hash": c.wasm_hash,
        "account_id": c.account,
        "key_hash": key_hash,
        "encrypted_key": key_bytes,
        "encrypted_value": value,
        "is_encrypted": is_encrypted,
    });
    let reply = http::post_json(&format!("{}/storage/set-if-absent", c.api), &c.token, &body)?;
    if !reply.ok() {
        return Err(format!("storage set-if-absent: HTTP {}: {}", reply.status, reply.text()));
    }
    #[derive(Deserialize)]
    struct R {
        inserted: bool,
    }
    Ok(reply.json::<R>("storage set-if-absent")?.inserted)
}

pub fn set_if_equals(key: &str, expected: &[u8], new_value: &[u8]) -> (bool, Vec<u8>, String) {
    let run = || -> Result<(bool, Vec<u8>), String> {
        let c = cell()?;
        let key_hash = hash_key(key);
        let (cur_k, cur_v) = match record(&c, &key_hash)? {
            None => return Ok((false, Vec::new())),
            Some((_, _, false)) => return Err("the record at this key was written raw; compare it with set-if-equals-raw".to_string()),
            Some((k, v, true)) => (k, v),
        };
        let (_, current) = open(&c, &cur_k, &cur_v)?;
        if current != expected {
            return Ok((false, current));
        }
        let s = seal(&c, key, new_value)?;
        let body = serde_json::json!({
            "project_uuid": c.project_uuid,
            "wasm_hash": c.wasm_hash,
            "account_id": c.account,
            "key_hash": key_hash,
            "expected_encrypted_value": cur_v,
            "new_encrypted_key": s.key,
            "new_encrypted_value": s.value,
            "is_encrypted": true,
        });
        let reply = http::post_json(&format!("{}/storage/set-if-equals", c.api), &c.token, &body)?;
        if !reply.ok() {
            return Err(refusal(&reply, "compare it with set-if-equals-raw"));
        }
        #[derive(Deserialize)]
        struct R {
            updated: bool,
            current_encrypted_key: Option<Vec<u8>>,
            current_encrypted_value: Option<Vec<u8>>,
        }
        let r: R = reply.json("storage set-if-equals")?;
        if r.updated {
            return Ok((true, Vec::new()));
        }
        match (r.current_encrypted_key, r.current_encrypted_value) {
            (Some(k), Some(v)) => Ok((false, open(&c, &k, &v)?.1)),
            _ => Ok((false, Vec::new())),
        }
    };
    match run() {
        Ok((updated, current)) => (updated, current, String::new()),
        Err(e) => (false, Vec::new(), e),
    }
}

// ==================== Raw Storage ====================

pub fn set_raw(key: &str, value: &[u8]) -> String {
    let run = || {
        let c = cell()?;
        write(&c, &hash_key(key), key.as_bytes(), value, false)
    };
    run().err().unwrap_or_default()
}

pub fn get_raw(key: &str) -> (Vec<u8>, String) {
    let run = || {
        let c = cell()?;
        match record(&c, &hash_key(key))? {
            None => Ok(Vec::new()),
            Some((_, _, true)) => Err("the record at this key was written encrypted; read it with get".to_string()),
            Some((_, v, false)) => Ok(v),
        }
    };
    ok_or(run(), Vec::new())
}

pub fn set_if_absent_raw(key: &str, value: &[u8]) -> (bool, String) {
    let run = || {
        let c = cell()?;
        insert_if_absent(&c, &hash_key(key), key.as_bytes(), value, false)
    };
    ok_or(run(), false)
}

pub fn set_if_equals_raw(key: &str, expected: &[u8], new_value: &[u8]) -> (bool, Vec<u8>, String) {
    let run = || -> Result<(bool, Vec<u8>), String> {
        let c = cell()?;
        let key_hash = hash_key(key);
        let body = serde_json::json!({
            "project_uuid": c.project_uuid,
            "wasm_hash": c.wasm_hash,
            "account_id": c.account,
            "key_hash": key_hash,
            "expected_encrypted_value": expected,
            "new_encrypted_key": key.as_bytes(),
            "new_encrypted_value": new_value,
            "is_encrypted": false,
        });
        let reply = http::post_json(&format!("{}/storage/set-if-equals", c.api), &c.token, &body)?;
        if !reply.ok() {
            return Err(refusal(&reply, "compare it with set-if-equals"));
        }
        #[derive(Deserialize)]
        struct R {
            updated: bool,
            current_encrypted_value: Option<Vec<u8>>,
        }
        let r: R = reply.json("storage set-if-equals")?;
        Ok((r.updated, if r.updated { Vec::new() } else { r.current_encrypted_value.unwrap_or_default() }))
    };
    match run() {
        Ok((updated, current)) => (updated, current, String::new()),
        Err(e) => (false, Vec::new(), e),
    }
}

pub fn increment(key: &str, delta: i64) -> (i64, String) {
    const MAX_RETRIES: usize = 5;
    let run = || -> Result<i64, String> {
        for _ in 0..MAX_RETRIES {
            let (current, error) = get(key);
            if !error.is_empty() {
                return Err(error);
            }
            if current.is_empty() {
                let (inserted, error) = set_if_absent(key, &delta.to_le_bytes());
                if !error.is_empty() {
                    return Err(error);
                }
                if inserted {
                    return Ok(delta);
                }
                continue;
            }
            let bytes: [u8; 8] = current
                .clone()
                .try_into()
                .map_err(|_| format!("increment: invalid value format, expected 8 bytes (i64), got {}", current.len()))?;
            let next = i64::from_le_bytes(bytes).checked_add(delta).ok_or("increment: overflow")?;
            let (updated, _, error) = set_if_equals(key, &current, &next.to_le_bytes());
            if !error.is_empty() {
                return Err(error);
            }
            if updated {
                return Ok(next);
            }
        }
        Err(format!("increment: max retries ({MAX_RETRIES}) exceeded for key={key}"))
    };
    ok_or(run(), 0)
}

pub fn decrement(key: &str, delta: i64) -> (i64, String) {
    match delta.checked_neg() {
        Some(neg) => increment(key, neg),
        None => (0, "decrement: delta out of range".to_string()),
    }
}

// ==================== Worker Storage ====================

/// The `@worker` cell is the host's own, outside what a call token opens.
pub fn set_worker(_key: &str, _value: &[u8], _is_encrypted: Option<bool>) -> String {
    "worker storage is not available on the Defuse engine: the call token opens the caller's cell only".to_string()
}

pub fn get_worker(key: &str, project: Option<&str>) -> (Vec<u8>, String) {
    let Some(project) = project else {
        return (Vec::new(), "worker storage is not available on the Defuse engine: the call token opens the caller's cell only".to_string());
    };
    let run = || {
        let c = cell()?;
        let body = serde_json::json!({ "project": project, "key_hash": hash_key(key) });
        let reply = http::post_json(&format!("{}/storage/get-public", c.api), &c.token, &body)?;
        if !reply.ok() {
            return Err(format!("storage get-public: HTTP {}: {}", reply.status, reply.text()));
        }
        #[derive(Deserialize)]
        struct R {
            exists: bool,
            value: Option<Vec<u8>>,
        }
        let r: R = reply.json("storage get-public")?;
        Ok(if r.exists { r.value.unwrap_or_default() } else { Vec::new() })
    };
    ok_or(run(), Vec::new())
}

// ==================== Version Migration ====================

pub fn get_by_version(key: &str, wasm_hash: &str) -> (Vec<u8>, String) {
    let run = || {
        let c = cell()?;
        let body = serde_json::json!({
            "project_uuid": c.project_uuid,
            "wasm_hash": wasm_hash,
            "account_id": c.account,
            "key_hash": hash_key(key),
        });
        let reply = http::post_json(&format!("{}/storage/get-by-version", c.api), &c.token, &body)?;
        if !reply.ok() {
            return Err(format!("storage get-by-version: HTTP {}: {}", reply.status, reply.text()));
        }
        let r: GetResponse = reply.json("storage get-by-version")?;
        match (r.exists, r.encrypted_key, r.encrypted_value, r.is_encrypted) {
            (true, Some(k), Some(v), true) => Ok(open(&c, &k, &v)?.1),
            (true, Some(_), Some(_), false) => Err("the record at this key was written raw; read it with get-raw".to_string()),
            _ => Ok(Vec::new()),
        }
    };
    ok_or(run(), Vec::new())
}

// ==================== Cleanup ====================

pub fn clear_all() -> String {
    let run = || {
        let c = cell()?;
        let body = serde_json::json!({ "project_uuid": c.project_uuid, "account_id": c.account });
        let reply = http::post_json(&format!("{}/storage/clear-all", c.api), &c.token, &body)?;
        if !reply.ok() {
            return Err(format!("storage clear-all: HTTP {}: {}", reply.status, reply.text()));
        }
        Ok(())
    };
    run().err().unwrap_or_default()
}

pub fn clear_version(wasm_hash: &str) -> String {
    let run = || {
        let c = cell()?;
        let body = serde_json::json!({ "project_uuid": c.project_uuid, "wasm_hash": wasm_hash, "account_id": c.account });
        let reply = http::post_json(&format!("{}/storage/clear-version", c.api), &c.token, &body)?;
        if !reply.ok() {
            return Err(format!("storage clear-version: HTTP {}: {}", reply.status, reply.text()));
        }
        Ok(())
    };
    run().err().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_token_every_call_says_why() {
        super::super::preset(Default::default(), Vec::new());
        assert!(set("k", b"v").contains("OUTLAYER_API_BASE is not set"));
        assert!(get("k").1.contains("is not set"));
        assert!(set_worker("k", b"v", None).contains("caller's cell only"));
    }

    #[test]
    fn keys_hash_as_the_host_hashes_them() {
        // sha256("a"), hex: the host's `hash_key`.
        assert_eq!(hash_key("a"), "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
        assert_eq!(percent("alice.testnet/x y"), "alice.testnet%2Fx%20y");
    }
}
