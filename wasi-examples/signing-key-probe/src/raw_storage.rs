//! The `encryption` build's storage operations: raw records (`raw_*`), the
//! encrypted mode for comparison (`enc_set`, `enc_get`), `storage_has` /
//! `storage_delete` / `storage_list`, `sealed_put` / `sealed_get` — encryption
//! with `outlayer:encryption-keys` over raw records — and the attacks on the
//! two modes (`raw_attack`, `raw_attacks`).
//!
//! Every answer is the probe's usual `{status, message, …}`; an error from the
//! host is an answer, and the run itself succeeds.

use serde_json::{json, Value};

use super::{encryption_keys, err, ok, storage, Input};

pub fn run(input: &Input) -> Value {
    match input.operation.as_str() {
        "raw_set" => with_key(input, |key| match hex_of("value_hex", &input.value_hex) {
            Ok(value) => match storage::set_raw(key, &value) {
                e if e.is_empty() => ok(format!("stored {} bytes raw", value.len()), json!({ "key": key })),
                e => err(e),
            },
            Err(e) => err(e),
        }),
        "raw_get" => with_key(input, |key| match storage::get_raw(key) {
            (_, e) if !e.is_empty() => err(e),
            (value, _) => ok(
                "read raw",
                json!({ "key": key, "found": !value.is_empty() || storage::has(key), "value_hex": hex::encode(value) }),
            ),
        }),
        "raw_set_if_absent" => with_key(input, |key| match hex_of("value_hex", &input.value_hex) {
            Ok(value) => match storage::set_if_absent_raw(key, &value) {
                (_, e) if !e.is_empty() => err(e),
                (inserted, _) => ok(
                    if inserted { "inserted raw" } else { "not inserted: the key holds a record" },
                    json!({ "key": key, "inserted": inserted }),
                ),
            },
            Err(e) => err(e),
        }),
        "raw_set_if_equals" => with_key(input, |key| {
            match (hex_of("expected_hex", &input.expected_hex), hex_of("new_hex", &input.new_hex)) {
                (Ok(expected), Ok(new)) => match storage::set_if_equals_raw(key, &expected, &new) {
                    (_, _, e) if !e.is_empty() => err(e),
                    (updated, current, _) => ok(
                        if updated { "replaced: the stored bytes were the expected ones" } else { "not replaced" },
                        json!({ "key": key, "updated": updated, "current_hex": hex::encode(current) }),
                    ),
                },
                (Err(e), _) | (_, Err(e)) => err(e),
            }
        }),
        "enc_set" => with_key(input, |key| match hex_of("value_hex", &input.value_hex) {
            Ok(value) => match storage::set(key, &value) {
                e if e.is_empty() => ok(format!("stored {} bytes encrypted", value.len()), json!({ "key": key })),
                e => err(e),
            },
            Err(e) => err(e),
        }),
        "enc_get" => with_key(input, |key| match storage::get(key) {
            (_, e) if !e.is_empty() => err(e),
            (value, _) => ok(
                "read encrypted",
                json!({ "key": key, "found": !value.is_empty() || storage::has(key), "value_hex": hex::encode(value) }),
            ),
        }),
        "storage_has" => with_key(input, |key| ok("asked", json!({ "key": key, "exists": storage::has(key) }))),
        "storage_delete" => with_key(input, |key| ok("asked", json!({ "key": key, "deleted": storage::delete(key) }))),
        "storage_list" => match storage::list_keys(input.prefix.as_deref().unwrap_or_default()) {
            (_, e) if !e.is_empty() => err(e),
            (keys, _) => match serde_json::from_str::<Vec<String>>(&keys) {
                Ok(keys) => ok(format!("{} keys", keys.len()), json!({ "keys": keys })),
                Err(e) => err(format!("list-keys answered something that is not a JSON array of names: {e}")),
            },
        },
        "sealed_put" => with_sealed(input, |path, vault, name| {
            let value = input.value.as_deref().unwrap_or_default();
            let name = match storage_name(path, vault, name) {
                Ok(n) => n,
                Err(e) => return err(e),
            };
            match encryption_keys::encrypt(path, vault, value.as_bytes(), name.as_bytes()) {
                Ok(ct) => match storage::set_raw(&name, &ct) {
                    e if e.is_empty() => ok(
                        "sealed under the key, bound to the record's name, and stored raw under the mac of the name",
                        json!({ "path": path, "vault": vault, "storage_key": name, "stored_len": ct.len() }),
                    ),
                    e => err(e),
                },
                Err(e) => err(e),
            }
        }),
        "sealed_get" => with_sealed(input, |path, vault, name| {
            let name = match storage_name(path, vault, name) {
                Ok(n) => n,
                Err(e) => return err(e),
            };
            match storage::get_raw(&name) {
                (_, e) if !e.is_empty() => err(e),
                (ct, _) if ct.is_empty() => {
                    ok("no record under the mac of this name", json!({ "path": path, "storage_key": name, "found": false }))
                }
                (ct, _) => match encryption_keys::decrypt(path, vault, &ct, name.as_bytes()) {
                    Ok(pt) => ok(
                        "read raw and opened",
                        json!({
                            "path": path, "vault": vault, "storage_key": name, "found": true,
                            "value": String::from_utf8_lossy(&pt), "value_hex": hex::encode(&pt),
                        }),
                    ),
                    Err(e) => err(e),
                },
            }
        }),
        "raw_attack" => match input.name.as_deref() {
            Some(name) => attack(name, &prefix_of(input)),
            None => err("raw_attack needs a `name`; `raw_attacks` runs them all".to_string()),
        },
        "raw_attacks" => attacks(&prefix_of(input)),
        other => err(format!("unknown storage operation {other:?}")),
    }
}

fn with_key(input: &Input, f: impl FnOnce(&str) -> Value) -> Value {
    match input.key.as_deref() {
        Some(key) => f(key),
        None => err("this operation needs a `key`".to_string()),
    }
}

fn with_sealed(input: &Input, f: impl FnOnce(&str, Option<&str>, &str) -> Value) -> Value {
    match (input.path.as_deref(), input.key.as_deref()) {
        (Some(path), Some(key)) => f(path, input.vault.as_deref(), key),
        _ => err("this operation needs a `path` (the encryption key) and a `key` (the record's name)".to_string()),
    }
}

fn hex_of(field: &str, value: &Option<String>) -> Result<Vec<u8>, String> {
    hex::decode(value.as_deref().unwrap_or_default()).map_err(|e| format!("{field} is not hex: {e}"))
}

/// The name a record called `name` is stored under: the hex of its mac under
/// the encryption key at `path`. The same name is always the same storage
/// key, and the storage's operator cannot tell which name it is.
fn storage_name(path: &str, vault: Option<&str>, name: &str) -> Result<String, String> {
    encryption_keys::mac(path, vault, name.as_bytes()).map(hex::encode)
}

fn prefix_of(input: &Input) -> String {
    input.key.clone().unwrap_or_else(|| "raw-attacks".to_string())
}

const ATTACKS: &[&str] = &[
    "get_raw_on_encrypted",
    "get_on_raw",
    "set_raw_over_encrypted",
    "set_over_raw",
    "cas_raw_on_encrypted",
    "cas_on_raw",
    "increment_on_raw",
    "set_if_absent_raw_on_encrypted",
    "set_if_absent_on_raw",
    "set_if_absent_raw_on_raw",
    "cas_raw_lose",
    "cas_raw_absent",
    "cas_raw_win",
    "delete_raw",
    "list_shows_raw_name",
];

fn attacks(prefix: &str) -> Value {
    let results: Vec<Value> = ATTACKS
        .iter()
        .map(|name| {
            let mut one = attack(name, prefix);
            one["name"] = json!(name);
            one
        })
        .collect();
    ok(format!("{} storage attacks, each answered", results.len()), json!({ "results": results }))
}

/// A record in one mode at `key`, whatever was there before.
fn put(key: &str, raw: bool, value: &[u8]) -> Result<(), String> {
    storage::delete(key);
    let e = if raw { storage::set_raw(key, value) } else { storage::set(key, value) };
    if e.is_empty() {
        Ok(())
    } else {
        Err(format!("setup: writing the {} record failed: {e}", if raw { "raw" } else { "encrypted" }))
    }
}

/// Whether `key` still holds `value` in its mode.
fn holds(key: &str, raw: bool, value: &[u8]) -> bool {
    let (stored, e) = if raw { storage::get_raw(key) } else { storage::get(key) };
    e.is_empty() && stored == value
}

/// One attack against records it writes under `<prefix>/<name>` and deletes
/// afterwards. `status` is what the host answered: `err` with the host's
/// message for an error, `err` with what happened for a conditional write
/// that did not write; `ok` for an answer (for the positive checks, `ok` means
/// the property held); `setup_failed` when the record the attack needs could
/// not be written. `unchanged`, where present, says the stored record is the
/// one written before the attack.
pub fn attack(name: &str, prefix: &str) -> Value {
    let key = format!("{prefix}/{name}");
    let out = run_attack(name, &key).unwrap_or_else(|e| json!({ "status": "setup_failed", "message": e }));
    storage::delete(&key);
    out
}

fn answered(e: String, what: &str) -> Value {
    if e.is_empty() {
        json!({ "status": "ok", "message": format!("the host {what}") })
    } else {
        json!({ "status": "err", "message": e })
    }
}

fn run_attack(name: &str, key: &str) -> Result<Value, String> {
    const ENC: &[u8] = b"encrypted value";
    const RAW: &[u8] = b"raw value";
    Ok(match name {
        "get_raw_on_encrypted" => {
            put(key, false, ENC)?;
            let (value, e) = storage::get_raw(key);
            let mut out = answered(e, &format!("read an encrypted record raw ({} bytes)", value.len()));
            out["unchanged"] = json!(holds(key, false, ENC));
            out
        }
        "get_on_raw" => {
            put(key, true, RAW)?;
            let (value, e) = storage::get(key);
            let mut out = answered(e, &format!("read a raw record as encrypted ({} bytes)", value.len()));
            out["unchanged"] = json!(holds(key, true, RAW));
            out
        }
        "set_raw_over_encrypted" => {
            put(key, false, ENC)?;
            let mut out = answered(storage::set_raw(key, RAW), "wrote raw over an encrypted record");
            out["unchanged"] = json!(holds(key, false, ENC));
            out
        }
        "set_over_raw" => {
            put(key, true, RAW)?;
            let mut out = answered(storage::set(key, ENC), "wrote encrypted over a raw record");
            out["unchanged"] = json!(holds(key, true, RAW));
            out
        }
        "cas_raw_on_encrypted" => {
            put(key, false, ENC)?;
            let (updated, _, e) = storage::set_if_equals_raw(key, ENC, RAW);
            let mut out = answered(e, &format!("answered a raw compare-and-swap on an encrypted record (updated={updated})"));
            out["unchanged"] = json!(holds(key, false, ENC));
            out
        }
        "cas_on_raw" => {
            put(key, true, RAW)?;
            let (updated, _, e) = storage::set_if_equals(key, RAW, ENC);
            let mut out = answered(e, &format!("answered a compare-and-swap on a raw record (updated={updated})"));
            out["unchanged"] = json!(holds(key, true, RAW));
            out
        }
        "increment_on_raw" => {
            put(key, true, &1i64.to_le_bytes())?;
            let (value, e) = storage::increment(key, 1);
            let mut out = answered(e, &format!("incremented a raw record to {value}"));
            out["unchanged"] = json!(holds(key, true, &1i64.to_le_bytes()));
            out
        }
        "set_if_absent_raw_on_encrypted" | "set_if_absent_on_raw" | "set_if_absent_raw_on_raw" => {
            let (stored_raw, stored) = match name {
                "set_if_absent_raw_on_encrypted" => (false, ENC),
                _ => (true, RAW),
            };
            put(key, stored_raw, stored)?;
            let (inserted, e) = if name == "set_if_absent_on_raw" {
                storage::set_if_absent(key, ENC)
            } else {
                storage::set_if_absent_raw(key, b"another value")
            };
            let mut out = match (inserted, e) {
                (_, e) if !e.is_empty() => json!({ "status": "err", "message": e }),
                (false, _) => json!({ "status": "err", "message": "not inserted: the key holds a record" }),
                (true, _) => json!({ "status": "ok", "message": "inserted over a record that was there" }),
            };
            out["unchanged"] = json!(holds(key, stored_raw, stored));
            out
        }
        "cas_raw_lose" => {
            put(key, true, b"v1")?;
            let (updated, current, e) = storage::set_if_equals_raw(key, b"v0", b"v2");
            let mut out = match (updated, e) {
                (_, e) if !e.is_empty() => json!({ "status": "err", "message": e }),
                (false, _) => json!({ "status": "err", "message": "not replaced: the stored bytes are not the expected ones" }),
                (true, _) => json!({ "status": "ok", "message": "replaced although the expected bytes were stale" }),
            };
            out["current_is_stored"] = json!(current == b"v1");
            out["unchanged"] = json!(holds(key, true, b"v1"));
            out
        }
        "cas_raw_absent" => {
            storage::delete(key);
            let (updated, current, e) = storage::set_if_equals_raw(key, b"", b"v");
            let mut out = match (updated, e) {
                (_, e) if !e.is_empty() => json!({ "status": "err", "message": e }),
                (false, _) => json!({ "status": "err", "message": "not replaced: no record at the key" }),
                (true, _) => json!({ "status": "ok", "message": "replaced a record that was not there" }),
            };
            out["current_empty"] = json!(current.is_empty());
            out["unchanged"] = json!(!storage::has(key));
            out
        }
        "cas_raw_win" => {
            put(key, true, b"v1")?;
            match storage::set_if_equals_raw(key, b"v1", b"v2") {
                (_, _, e) if !e.is_empty() => json!({ "status": "err", "message": e }),
                (true, _, _) if holds(key, true, b"v2") => json!({ "status": "ok", "message": "replaced, and the new bytes are stored" }),
                (true, _, _) => json!({ "status": "err", "message": "answered replaced, and the new bytes are not what is stored" }),
                (false, current, _) => json!({ "status": "err", "message": format!("not replaced; the host holds {} bytes", current.len()) }),
            }
        }
        "delete_raw" => {
            put(key, true, RAW)?;
            match (storage::has(key), storage::delete(key), storage::has(key), storage::get_raw(key)) {
                (true, true, false, (v, e)) if v.is_empty() && e.is_empty() => {
                    json!({ "status": "ok", "message": "has, then deleted, then gone" })
                }
                (had, deleted, has, (v, e)) => json!({
                    "status": "err",
                    "message": format!("has={had} deleted={deleted} has_after={has} get_raw_after={} bytes {e}", v.len()),
                }),
            }
        }
        "list_shows_raw_name" => {
            put(key, true, RAW)?;
            match storage::list_keys(key) {
                (_, e) if !e.is_empty() => json!({ "status": "err", "message": e }),
                (keys, _) => match serde_json::from_str::<Vec<String>>(&keys) {
                    Ok(keys) if keys.iter().any(|k| k == key) => json!({ "status": "ok", "message": "the raw name is listed as written" }),
                    Ok(keys) => json!({ "status": "err", "message": format!("{} names listed, the raw one not among them", keys.len()) }),
                    Err(e) => json!({ "status": "err", "message": format!("list-keys is not a JSON array: {e}") }),
                },
            }
        }
        other => json!({ "status": "err", "message": format!("unknown storage attack {other:?}; one of {}", ATTACKS.join(", ")) }),
    })
}
