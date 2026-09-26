//! Encryption keys: symmetric keys a WebAssembly artefact declares in its
//! manifest, derived here from a master and handed to the worker for the one
//! job that asked.
//!
//! An artefact declares the keys it seals data with (`"encryption_keys":
//! [{"path": "records"}]`); the worker sends those declarations in the run's
//! `/decrypt` request beside any signing keys (`KeyedDecryptRequest`,
//! `api_support.rs`), and this keystore derives each key under one of two
//! bindings — no other binding exists:
//!
//! ```text
//! bind "project": HMAC-SHA256(master, "encryption-key:v1:project:{project_uuid}:{caller}:{account_id}:{path}")
//! bind "wasm":    HMAC-SHA256(master, "encryption-key:v1:wasm:{wasm_sha256}:{caller}:{account_id}:{path}")
//! ```
//!
//! **An encryption key has no type.** It is 32 bytes, and which algorithm uses
//! them is the platform's choice, made by the worker's host
//! (`worker/src/encryption_keys`), which marks every ciphertext with its
//! format; a later format uses the same key. So the declaration names no
//! algorithm, the request carries none — a `type` member is refused as an
//! unknown field — and the string has no segment for one. The host never
//! uses the 32 bytes as they are for anything but its AEAD; its `mac` derives
//! a subkey from them first.
//!
//! **The security model is the signing keys', rule for rule** (see
//! `crate::signing_keys`, whose validation this family shares through
//! [`crate::signing_keys::KeyDeclaration`]): a `project` key only on a run
//! through its project whose build is a WasmUrl version of it, bound to the
//! project's on-chain uuid; a `wasm` key only on a direct run, bound to the
//! measured build; nothing for code built from a GitHub repository; `caller`
//! picks the job's signer or predecessor, a segment of the string; a `vault`
//! only on a `project` key, named under the project's owner and owned by it
//! on chain, and never the default master in its place; at most
//! [`MAX_ENCRYPTION_KEYS`] keys, every path of one shape and named once; a
//! placeholder caller refused by name. One key that fails refuses the whole
//! request — both families — under the one refusal code
//! `signing_keys_refused` (`api.rs`), because a request is judged whole: the
//! project and vault checks are shared, and a refusal that named one family
//! would misname the other.
//!
//! **A namespace of its own.** Encryption paths are not signing paths: one
//! request may name `records` in both lists, and the two keys are derived
//! under two roots. The root is chosen by the key's kind
//! ([`crate::signing_keys::KeyKind::family`]) — the list the key was parsed
//! from — never by a field the request writes, so no request can ask for a
//! signing key's string under the encryption family or the other way round.
//! No other fixed root starts `encryption-key:v1:` or is started by it —
//! `signing-key:v1:` included — and the segment after it is always the
//! binding, `project` or `wasm`, never a signing key's type (pinned in
//! `api_tests`). The seeds a caller spells — a raw seed sent to `/pubkey`,
//! `/encrypt` or `/add_generated_secret`, and a `Repo` accessor's
//! `{repo}:{owner}[:{branch}]` — are refused when they start with
//! `encryption-key:` or `signing-key:` (`api.rs`, `DECLARED_KEY_ROOTS`), so no
//! other seed this keystore derives starts with `encryption-key:v1:`.
//!
//! `v1` names the scheme: this string, `HMAC-SHA256` under the master, and 32
//! bytes out. It never changes: changing it changes every key, and everything
//! a key ever sealed would no longer open. A different scheme would be added
//! beside it as `encryption-key:v2:`.

use serde::{Deserialize, Serialize};

use crate::signing_keys::{CallerKind, KeyBinding, KeyDeclaration, KeyFamily, KeyKind};

/// The root of every encryption-key derivation string.
pub const ENCRYPTION_KEY_LABEL: &str = "encryption-key:v1:";

/// How many encryption keys one request may name — the manifest's own limit,
/// counted apart from the signing keys.
pub const MAX_ENCRYPTION_KEYS: usize = 3;

/// One encryption key as the worker asks for it, copied from the running
/// artefact's manifest. Unknown fields are refused, as for a signing key: a
/// misspelled `vault` would otherwise derive from the default master. `type`
/// is one of them — an encryption key has none.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptionKeyRequest {
    /// An input of the derivation: the same path is the same key forever, a
    /// renamed path is a different key.
    pub path: String,
    #[serde(default)]
    pub bind: KeyBinding,
    #[serde(default)]
    pub caller: CallerKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

impl KeyDeclaration for EncryptionKeyRequest {
    const FAMILY: KeyFamily = KeyFamily::Encryption;
    fn path(&self) -> &str {
        &self.path
    }
    fn kind(&self) -> KeyKind {
        KeyKind::Encryption
    }
    fn bind(&self) -> KeyBinding {
        self.bind
    }
    fn caller(&self) -> CallerKind {
        self.caller
    }
    fn vault(&self) -> Option<&str> {
        self.vault.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing_keys::{
        validate_request, BoundKeys, ProjectUuid, SigningKeyRequest, SigningKeyType, ValidatedKeys, SIGNING_KEY_LABEL,
    };

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const P1: &str = "p0000000000000001";
    const P2: &str = "p0000000000000002";

    fn uuid(s: &str) -> ProjectUuid {
        ProjectUuid::parse(s).unwrap()
    }

    fn req(path: &str) -> EncryptionKeyRequest {
        EncryptionKeyRequest {
            path: path.to_string(),
            bind: KeyBinding::Project,
            caller: CallerKind::Signer,
            vault: None,
        }
    }

    fn wasm_req(path: &str) -> EncryptionKeyRequest {
        EncryptionKeyRequest { bind: KeyBinding::Wasm, ..req(path) }
    }

    fn pred_req(path: &str) -> EncryptionKeyRequest {
        EncryptionKeyRequest { caller: CallerKind::Predecessor, ..req(path) }
    }

    fn signing(path: &str, bind: KeyBinding) -> SigningKeyRequest {
        SigningKeyRequest { path: path.into(), key_type: SigningKeyType::Ed25519, bind, caller: CallerKind::Signer, vault: None }
    }

    /// A run through project `alice.near/app` as `bob.near`, on build H1.
    fn validate(keys: &[EncryptionKeyRequest]) -> Result<ValidatedKeys, String> {
        validate_request(Some("alice.near/app"), "bob.near", None, Some(H1), keys)
    }

    fn bound(keys: &[EncryptionKeyRequest]) -> Result<BoundKeys, String> {
        validate(keys)?.bind(Some(uuid(P1)))
    }

    /// A direct run of build H1 as `bob.near`.
    fn validate_direct(keys: &[EncryptionKeyRequest]) -> Result<ValidatedKeys, String> {
        validate_request(None, "bob.near", None, Some(H1), keys)
    }

    fn bound_direct(keys: &[EncryptionKeyRequest]) -> Result<BoundKeys, String> {
        validate_direct(keys)?.bind(None)
    }

    #[test]
    fn the_derivation_strings_have_the_pinned_shapes() {
        let v = bound(&[req("records")]).unwrap();
        assert_eq!(v.family, KeyFamily::Encryption);
        assert_eq!(
            v.keys[0].input.as_str(),
            "encryption-key:v1:project:p0000000000000001:signer:bob.near:records"
        );
        assert_eq!(v.keys[0].input.family(), KeyFamily::Encryption);
        assert_eq!(v.keys[0].kind, KeyKind::Encryption);
        let w = bound_direct(&[wasm_req("session")]).unwrap();
        assert_eq!(w.keys[0].input.as_str(), format!("encryption-key:v1:wasm:{H1}:signer:bob.near:session"));
        let d = validate_request(Some("alice.near/app"), "bob.near", Some("dao.near"), Some(H1), &[pred_req("inbox")])
            .unwrap()
            .bind(Some(uuid(P1)))
            .unwrap();
        assert_eq!(
            d.keys[0].input.as_str(),
            "encryption-key:v1:project:p0000000000000001:predecessor:dao.near:inbox"
        );
    }

    /// The two families never spell one string: the same path, binding, caller
    /// and run give two strings under two roots — the signing one with its
    /// type after the root, the encryption one with none — and each input
    /// knows its family.
    #[test]
    fn the_same_path_in_both_families_is_two_strings() {
        let enc = bound(&[req("records")]).unwrap().keys.remove(0).input;
        let sig = validate_request(Some("alice.near/app"), "bob.near", None, Some(H1), &[signing("records", KeyBinding::Project)])
            .unwrap()
            .bind(Some(uuid(P1)))
            .unwrap()
            .keys
            .remove(0)
            .input;
        assert_ne!(enc, sig);
        assert!(enc.as_str().starts_with(ENCRYPTION_KEY_LABEL) && sig.as_str().starts_with(SIGNING_KEY_LABEL));
        assert_eq!(sig.family(), KeyFamily::Signing);
        // Identical after the root and the signing type: the roots separate them.
        assert_eq!(
            enc.as_str().strip_prefix(ENCRYPTION_KEY_LABEL).unwrap(),
            sig.as_str().strip_prefix(SIGNING_KEY_LABEL).unwrap().strip_prefix("ed25519:").unwrap()
        );
        // Neither root is a prefix of the other.
        assert!(!ENCRYPTION_KEY_LABEL.starts_with(SIGNING_KEY_LABEL) && !SIGNING_KEY_LABEL.starts_with(ENCRYPTION_KEY_LABEL));
    }

    /// The bind ↔ run rules of the signing keys, unchanged.
    #[test]
    fn a_key_is_issued_only_to_the_run_its_binding_names() {
        assert!(validate(&[req("k")]).is_ok());
        assert!(validate_direct(&[wasm_req("k")]).is_ok());
        let e = validate(&[wasm_req("k")]).unwrap_err();
        assert!(e.contains("bound to the build") && e.contains("only to a direct run"), "{e}");
        let e = validate_direct(&[req("k")]).unwrap_err();
        assert!(e.contains("bound to the project") && e.contains("direct wasm run"), "{e}");
        assert!(validate(&[req("a"), wasm_req("b")]).is_err());
        assert!(validate_direct(&[wasm_req("a"), req("b")]).is_err());
    }

    #[test]
    fn the_caller_rules_are_the_signing_keys() {
        let e = validate(&[pred_req("k")]).unwrap_err();
        assert!(e.contains("carries no predecessor_id"), "{e}");
        let e = validate_request(Some("alice.near/app"), "anonymous", None, Some(H1), &[req("k")]).unwrap_err();
        assert!(e.contains("an encryption key needs a real caller"), "{e}");
        let e = validate_request(Some("alice.near/app"), "bob.near", Some("anonymous"), Some(H1), &[req("k")]).unwrap_err();
        assert!(e.contains("predecessor") && e.contains("needs a real caller"), "{e}");
        let signer = bound(&[req("k")]).unwrap().keys.remove(0).input;
        let pred = validate_request(Some("alice.near/app"), "bob.near", Some("bob.near"), Some(H1), &[pred_req("k")])
            .unwrap()
            .bind(Some(uuid(P1)))
            .unwrap()
            .keys
            .remove(0)
            .input;
        assert_ne!(signer, pred, "one account as signer and as predecessor: two keys");
    }

    #[test]
    fn the_vault_rules_are_the_signing_keys() {
        let mut w = wasm_req("k");
        w.vault = Some("vault.alice.near".into());
        assert!(validate_direct(&[w]).unwrap_err().contains("cannot name a vault"));
        let mut p = req("k");
        p.vault = Some("vault.alice.near".into());
        let v = validate(&[p]).unwrap();
        assert_eq!(v.vaults(), vec!["vault.alice.near".parse::<near_primitives::types::AccountId>().unwrap()]);
        for bad in ["", "VAULT", "vault.alice.near:x"] {
            let mut r = req("k");
            r.vault = Some(bad.into());
            assert!(validate(&[r]).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn three_keys_are_accepted_and_four_refused() {
        assert_eq!(MAX_ENCRYPTION_KEYS, 3);
        let three: Vec<_> = (0..3).map(|i| req(&format!("k{i}"))).collect();
        assert_eq!(bound(&three).unwrap().keys.len(), 3);
        let four: Vec<_> = (0..4).map(|i| req(&format!("k{i}"))).collect();
        let e = validate(&four).unwrap_err();
        assert!(e.contains("4 encryption keys") && e.contains("at most 3"), "{e}");
        assert!(validate(&[]).unwrap_err().contains("no encryption keys"));
        assert!(validate(&[req("k"), req("k")]).is_err());
    }

    #[test]
    fn shapes_and_colons_are_refused() {
        for bad in ["", "A", "a:b", "../a", &"a".repeat(33)] {
            assert!(validate(&[req(bad)]).is_err(), "{bad:?}");
        }
        assert!(validate_request(Some("alice.near/app"), "bob.near:x", None, Some(H1), &[req("k")]).is_err());
        assert!(validate_request(Some("alice.near/app"), "bob.near", None, None, &[req("k")]).is_err());
        assert!(validate_request(Some("alice.near/app"), "bob.near", None, Some(&H1[1..]), &[req("k")]).is_err());
        let e = validate_request(Some("alice.near/app"), "bob.near", None, None, &[req("k")]).unwrap_err();
        assert!(e.contains("encryption keys need"), "{e}");
    }

    #[test]
    fn a_wasm_key_follows_the_build_and_a_project_key_the_uuid() {
        let direct = |h: &str| validate_request(None, "bob.near", None, Some(h), &[wasm_req("k")]).unwrap().bind(None).unwrap().keys.remove(0).input;
        assert_eq!(direct(H1), direct(H1));
        assert_ne!(direct(H1), direct(H2));
        let project = |h: &str, u: &str| {
            validate_request(Some("alice.near/app"), "bob.near", None, Some(h), &[req("k")]).unwrap().bind(Some(uuid(u))).unwrap().keys.remove(0).input
        };
        assert_eq!(project(H1, P1), project(H2, P1));
        assert_ne!(project(H1, P1), project(H1, P2));
    }

    #[test]
    fn the_request_parses_strictly() {
        let ok: EncryptionKeyRequest = serde_json::from_str(r#"{"path":"k"}"#).unwrap();
        assert_eq!(ok.bind, KeyBinding::Project);
        assert_eq!(ok.caller, CallerKind::Signer);
        assert_eq!(ok.kind(), KeyKind::Encryption);
        for body in [
            r#"{}"#,
            r#"{"path":"k","valut":"vault.alice.near"}"#,
            r#"{"path":"k","bind":"hash"}"#,
            r#"{"path":"k","caller":"sender"}"#,
            r#"{"name":"k"}"#,
        ] {
            assert!(serde_json::from_str::<EncryptionKeyRequest>(body).is_err(), "{body}");
        }
        // An encryption key has no type: any `type` is an unknown field, and
        // the refusal says which fields there are.
        for ty in [r#""xchacha20poly1305""#, r#""ed25519""#, r#""aes-256-gcm""#, "null", "1"] {
            let body = format!(r#"{{"path":"k","type":{ty}}}"#);
            let e = serde_json::from_str::<EncryptionKeyRequest>(&body).unwrap_err().to_string();
            assert!(e.contains("unknown field `type`") && e.contains("expected one of `path`, `bind`, `caller`, `vault`"), "{body}: {e}");
        }
        // An encryption key is no signing key: without a type, the signing
        // request refuses it.
        assert!(serde_json::from_str::<SigningKeyRequest>(r#"{"path":"k"}"#).is_err());
        assert_eq!(serde_json::to_value(ok).unwrap(), serde_json::json!({"path":"k","bind":"project","caller":"signer"}));
    }
}
