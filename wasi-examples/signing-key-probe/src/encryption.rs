//! The encryption builds' operations: `encrypt`, `decrypt`, `mac`,
//! `encrypt_and_decrypt`, `all_encryption_keys`, and the attacks on
//! `outlayer:encryption-keys` (`enc_attack`, `enc_attacks`).
//!
//! Every answer is the probe's usual `{status, message, …}`; a refusal from the
//! host is an answer, and the run itself succeeds.

use serde_json::{json, Value};

use super::{declared, declared_in, encryption_keys, err, ok, signing_keys, with_path, Input};

/// The host's limit on one plaintext, data or aad (`encryption-keys.wit`).
const MAX_INPUT: usize = 262_144;

/// What a ciphertext adds to its plaintext: format marker, nonce, tag.
const OVERHEAD: usize = 1 + 24 + 16;

/// The first byte of every ciphertext the host seals today: its format marker
/// (`encryption-keys.wit`).
const FORMAT_MARKER: u8 = 0x01;

/// The one error every failure to open answers with.
const DECRYPTION_FAILED: &str = "decryption failed";

pub fn run(input: &Input) -> Value {
    match input.operation.as_str() {
        "encrypt" => with_path(input, |path, vault| match (hex_of(&input.plaintext_hex), hex_of(&input.aad_hex)) {
            (Ok(pt), Ok(aad)) => match encryption_keys::encrypt(path, vault, &pt, &aad) {
                Ok(ct) => ok(format!("sealed {} bytes", pt.len()), json!({ "path": path, "vault": vault, "ciphertext": hex::encode(ct) })),
                Err(e) => err(e),
            },
            (Err(e), _) | (_, Err(e)) => err(e),
        }),
        "decrypt" => with_path(input, |path, vault| match (hex_of(&input.ciphertext_hex), hex_of(&input.aad_hex)) {
            (Ok(ct), Ok(aad)) => match encryption_keys::decrypt(path, vault, &ct, &aad) {
                Ok(pt) => ok(format!("opened {} bytes", pt.len()), json!({ "path": path, "vault": vault, "plaintext": hex::encode(pt) })),
                Err(e) => err(e),
            },
            (Err(e), _) | (_, Err(e)) => err(e),
        }),
        "mac" => with_path(input, |path, vault| match hex_of(&input.plaintext_hex) {
            Ok(data) => match encryption_keys::mac(path, vault, &data) {
                Ok(tag) => ok("the host answered with the mac", json!({ "path": path, "vault": vault, "mac": hex::encode(tag) })),
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }),
        "encrypt_and_decrypt" => with_path(input, |path, vault| encrypt_and_decrypt(path, vault, input)),
        "all_encryption_keys" => all_encryption_keys(),
        "enc_attack" => match input.name.as_deref() {
            Some(name) => attack(name),
            None => err("enc_attack needs a `name`; `enc_attacks` runs them all".to_string()),
        },
        "enc_attacks" => attacks(),
        other => err(format!("unknown encryption operation {other:?}")),
    }
}

fn hex_of(field: &Option<String>) -> Result<Vec<u8>, String> {
    hex::decode(field.as_deref().unwrap_or_default()).map_err(|e| format!("a hex field is not hex: {e}"))
}

/// Seal, open, and check inside the guest: the plaintext comes back, a second
/// seal of the same input is other bytes, and another aad does not open.
fn encrypt_and_decrypt(path: &str, vault: Option<&str>, input: &Input) -> Value {
    let (pt, aad) = match (hex_of(&input.plaintext_hex), hex_of(&input.aad_hex)) {
        (Ok(pt), Ok(aad)) => (pt, aad),
        (Err(e), _) | (_, Err(e)) => return err(e),
    };
    let (first, second) = match (encryption_keys::encrypt(path, vault, &pt, &aad), encryption_keys::encrypt(path, vault, &pt, &aad)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return err(e),
    };
    let opened = encryption_keys::decrypt(path, vault, &first, &aad);
    let mut other_aad = aad.clone();
    other_aad.push(0);
    let fields = json!({
        "path": path, "vault": vault,
        "round_trip": opened.as_deref() == Ok(pt.as_slice()),
        "fresh_nonce": first != second && first[1..25] != second[1..25],
        "other_aad_refused": encryption_keys::decrypt(path, vault, &first, &other_aad).err().as_deref() == Some(DECRYPTION_FAILED),
        "length": first.len() == pt.len() + OVERHEAD,
        "format": first.first() == Some(&FORMAT_MARKER),
    });
    if ["round_trip", "fresh_nonce", "other_aad_refused", "length", "format"].iter().all(|k| fields[k] == json!(true)) {
        ok("sealed and opened inside the guest; another seal differs, another aad does not open", fields)
    } else {
        let mut out = err("an in-guest check failed".to_string());
        if let (Value::Object(map), Value::Object(extra)) = (&mut out, fields) {
            map.extend(extra);
        }
        out
    }
}

/// Every declared encryption key answers: the mac of a fixed string under
/// each — the same in every run that holds the key.
fn all_encryption_keys() -> Value {
    let mut keys = serde_json::Map::new();
    let mut failures = Vec::new();
    for (path, vault) in declared_in("encryption_keys") {
        match encryption_keys::mac(&path, vault.as_deref(), b"all_encryption_keys") {
            Ok(tag) => {
                keys.insert(path, json!({ "vault": vault, "mac": hex::encode(tag) }));
            }
            Err(e) => failures.push(format!("{path}: {e}")),
        }
    }
    if failures.is_empty() {
        ok(format!("{} declared encryption keys, each answered", keys.len()), json!({ "keys": keys }))
    } else {
        let mut out = err(failures.join("; "));
        out["keys"] = Value::Object(keys);
        out
    }
}

/// Use every declared encryption key once, for `what_i_can_see`.
pub fn exercise_all() -> Vec<Value> {
    declared_in("encryption_keys")
        .into_iter()
        .map(|(path, vault)| {
            let v = vault.as_deref();
            let sealed = encryption_keys::encrypt(&path, v, b"what_i_can_see", b"aad");
            let opened = sealed.as_ref().ok().map(|ct| encryption_keys::decrypt(&path, v, ct, b"aad").is_ok());
            let mac = encryption_keys::mac(&path, v, b"what_i_can_see").is_ok();
            json!({ "encryption_path": path, "encrypt": sealed.is_ok(), "decrypt": opened, "mac": mac })
        })
        .collect()
}

const ATTACKS: &[&str] = &[
    "undeclared_path",
    "empty_path",
    "colon_path",
    "wrong_aad",
    "tampered_tag",
    "tampered_body",
    "tampered_nonce",
    "bad_format_marker",
    "truncated",
    "shorter_than_overhead",
    "empty_ciphertext",
    "cross_path",
    "oversized_plaintext",
    "oversized_aad",
    "oversized_data",
    "oversized_ciphertext",
    "plaintext_at_cap",
    "vault_when_none_declared",
    "vault_missing_when_declared",
    "vault_wrong_when_declared",
    "mac_determinism",
    "mac_separation",
    "signing_path_is_not_an_encryption_path",
    "encryption_path_is_not_a_signing_path",
];

fn attacks() -> Value {
    let results: Vec<Value> = ATTACKS
        .iter()
        .map(|name| {
            let mut one = attack(name);
            one["name"] = json!(name);
            one
        })
        .collect();
    ok(format!("{} attacks, each answered", results.len()), json!({ "results": results }))
}

/// One attack. `status` is what the host answered (`err` for a refusal, `ok`
/// for an answer — for the positive checks, `ok` means the property held),
/// `n/a` when this build declares no key the attack needs.
pub fn attack(name: &str) -> Value {
    let keys = declared_in("encryption_keys");
    let first = keys.first().cloned();
    let unvaulted = keys.iter().find(|(_, v)| v.is_none()).cloned();
    let vaulted = keys.iter().find(|(_, v)| v.is_some()).cloned();
    let answered = |r: Result<Vec<u8>, String>, what: &str| match r {
        Err(e) => json!({ "status": "err", "message": e }),
        Ok(bytes) => json!({ "status": "ok", "message": format!("the host answered {what} ({} bytes)", bytes.len()) }),
    };
    let na = |why: &str| json!({ "status": "n/a", "message": why });
    let Some((path, vault)) = first else {
        return na("this build declares no encryption key");
    };
    let v = vault.as_deref();
    let sealed = match encryption_keys::encrypt(&path, v, b"record #1", b"row-1") {
        Ok(ct) => ct,
        Err(e) => return json!({ "status": "err", "message": format!("the setup seal failed: {e}") }),
    };
    let open = |ct: &[u8], aad: &[u8], what: &str| answered(encryption_keys::decrypt(&path, v, ct, aad), what);
    let flipped = |at: usize| {
        let mut ct = sealed.clone();
        ct[at] ^= 1;
        ct
    };
    match name {
        "undeclared_path" => answered(encryption_keys::encrypt("undeclared", None, b"x", b""), "for an undeclared path"),
        "empty_path" => answered(encryption_keys::mac("", None, b"x"), "for an empty path"),
        "colon_path" => answered(encryption_keys::mac(&format!("{path}:x"), v, b"x"), "for a path with ':'"),
        "wrong_aad" => open(&sealed, b"row-2", "under another aad"),
        "tampered_tag" => open(&flipped(sealed.len() - 1), b"row-1", "a changed tag"),
        "tampered_body" => open(&flipped(25), b"row-1", "a changed body"),
        "tampered_nonce" => open(&flipped(3), b"row-1", "a changed nonce"),
        "bad_format_marker" => open(&flipped(0), b"row-1", "another format marker"),
        "truncated" => open(&sealed[..sealed.len() - 1], b"row-1", "a truncated ciphertext"),
        "shorter_than_overhead" => open(&sealed[..OVERHEAD - 1], b"row-1", "a ciphertext shorter than its overhead"),
        "empty_ciphertext" => open(&[], b"row-1", "an empty ciphertext"),
        "cross_path" => match keys.iter().find(|(p, _)| p != &path) {
            Some((other, other_vault)) => answered(
                encryption_keys::decrypt(other, other_vault.as_deref(), &sealed, b"row-1"),
                "another path's ciphertext",
            ),
            None => na("this build declares one encryption key"),
        },
        "oversized_plaintext" => answered(encryption_keys::encrypt(&path, v, &vec![0u8; MAX_INPUT + 1], b""), "a plaintext over the cap"),
        "oversized_aad" => answered(encryption_keys::encrypt(&path, v, b"x", &vec![0u8; MAX_INPUT + 1]), "an aad over the cap"),
        "oversized_data" => answered(encryption_keys::mac(&path, v, &vec![0u8; MAX_INPUT + 1]), "data over the cap"),
        "oversized_ciphertext" => open(&vec![1u8; MAX_INPUT + OVERHEAD + 1], b"", "a ciphertext over the cap"),
        "plaintext_at_cap" => {
            let pt = vec![0x61u8; MAX_INPUT];
            match encryption_keys::encrypt(&path, v, &pt, b"cap").and_then(|ct| encryption_keys::decrypt(&path, v, &ct, b"cap")) {
                Ok(back) if back == pt => json!({ "status": "ok", "message": format!("sealed and opened exactly {MAX_INPUT} bytes") }),
                Ok(_) => json!({ "status": "err", "message": "opened at the cap, and the plaintext differs" }),
                Err(e) => json!({ "status": "err", "message": e }),
            }
        }
        "vault_when_none_declared" => match &unvaulted {
            Some((p, _)) => answered(encryption_keys::encrypt(p, Some("vault.attacker.near"), b"x", b""), "with a vault the key does not declare"),
            None => na("this build declares no encryption key without a vault"),
        },
        "vault_missing_when_declared" => match &vaulted {
            Some((p, _)) => answered(encryption_keys::mac(p, None, b"x"), "without the key's declared vault"),
            None => na("this build declares no encryption key with a vault"),
        },
        "vault_wrong_when_declared" => match &vaulted {
            Some((p, _)) => answered(encryption_keys::decrypt(p, Some("vault.attacker.near"), &sealed, b"row-1"), "with another vault"),
            None => na("this build declares no encryption key with a vault"),
        },
        "mac_determinism" => match (encryption_keys::mac(&path, v, b"name"), encryption_keys::mac(&path, v, b"name"), encryption_keys::mac(&path, v, b"other")) {
            (Ok(a), Ok(b), Ok(c)) if a == b && a != c && a.len() == 32 => {
                json!({ "status": "ok", "message": "one name, one tag; another name, another tag" })
            }
            (Ok(_), Ok(_), Ok(_)) => json!({ "status": "err", "message": "the mac is not deterministic, or not separating" }),
            (Err(e), ..) | (_, Err(e), _) | (.., Err(e)) => json!({ "status": "err", "message": e }),
        },
        // A tag never opens as a ciphertext, nor a ciphertext's bytes as a
        // tag: what `mac` answers says nothing that `decrypt` accepts.
        "mac_separation" => match encryption_keys::mac(&path, v, &sealed) {
            Ok(tag) => {
                let mut as_ct = vec![1u8];
                as_ct.extend_from_slice(&[0u8; 24]);
                as_ct.extend_from_slice(&tag);
                match encryption_keys::decrypt(&path, v, &as_ct, b"") {
                    Err(e) if e == DECRYPTION_FAILED && tag.as_slice() != &sealed[sealed.len() - 32..] => {
                        json!({ "status": "ok", "message": "a tag is not a ciphertext, and not the ciphertext's tail" })
                    }
                    Err(e) => json!({ "status": "err", "message": e }),
                    Ok(_) => json!({ "status": "err", "message": "a tag opened as a ciphertext" }),
                }
            }
            Err(e) => json!({ "status": "err", "message": e }),
        },
        // `beta` is an encryption path only; asking the signing interface for
        // it is an undeclared path there.
        "encryption_path_is_not_a_signing_path" => match keys.iter().find(|(p, _)| !declared().iter().any(|(s, _)| s == p)) {
            Some((p, pv)) => answered(signing_keys::sign(p, pv.as_deref(), b"x"), "a signing call at an encryption-only path"),
            None => na("every encryption path here is also a signing path"),
        },
        "signing_path_is_not_an_encryption_path" => match declared().iter().find(|(s, _)| !keys.iter().any(|(p, _)| p == s)) {
            Some((p, pv)) => answered(encryption_keys::mac(p, pv.as_deref(), b"x"), "an encryption call at a signing-only path"),
            None => na("every signing path here is also an encryption path"),
        },
        other => json!({ "status": "err", "message": format!("unknown attack {other:?}; one of {}", ATTACKS.join(", ")) }),
    }
}
