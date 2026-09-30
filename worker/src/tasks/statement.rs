//! A device's statement, checked before anything is encrypted to the device.
//!
//! The owner's wallet signs one sentence (NEP-413, recipient: the OutLayer
//! contract) naming the public key of a key pair their browser made:
//!
//! > Sign in to OutLayer as `alice.near`. Device key: `p256:<base64url>`. Valid until `2026-10-29T12:00:00Z`.
//!
//! The coordinator keeps the statement and hands it to this host with the
//! owner's other devices. The coordinator is where the row is stored, not
//! what makes it true: a row is a device of the owner only if
//!
//! 1. it is for the owner's account, and its deadline has not passed;
//! 2. the sentence rebuilt from its account, device key and deadline is what
//!    the signature signs;
//! 3. the key that signed is an access key of the owner's account ON CHAIN,
//!    at the final block.
//!
//! A row that fails 1 or 2, or whose signer is not the account's key, is not
//! a device, and nothing is encrypted to it. A chain that cannot be asked is
//! not an answer: the whole call is refused as unavailable, never served as
//! if the owner had no device.

use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// NEP-413's tag: 2^31 + 413.
const NEP413_TAG: u32 = 2_147_484_061;

/// A device as the coordinator stores it.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceStatement {
    pub id: String,
    pub account_id: String,
    pub device_pubkey: String,
    /// `ed25519:<base58>`.
    pub signer_pubkey: String,
    /// Base64, 64 bytes.
    pub signature: String,
    /// Base64, 32 bytes.
    pub nonce: String,
    /// Unix seconds.
    pub valid_until: i64,
}

/// A device whose statement held: its id in the store and its key.
#[derive(Debug, Clone)]
pub struct Device {
    pub id: String,
    pub key: p256::PublicKey,
}

/// Why the chain gave no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainUnavailable(pub String);

/// The sentence, rebuilt from its three facts.
pub fn sentence(account: &str, device_pubkey: &str, valid_until: i64) -> Option<String> {
    Some(format!(
        "Sign in to OutLayer as {account}. Device key: {device_pubkey}. Valid until {}.",
        iso8601_utc(valid_until)?
    ))
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`. Civil-from-days after Howard
/// Hinnant. `None` before the epoch or past the year 9999.
fn iso8601_utc(secs: i64) -> Option<String> {
    if !(0..253_402_300_800).contains(&secs) {
        return None;
    }
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some(format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z"))
}

#[derive(borsh::BorshSerialize)]
struct Nep413Payload {
    message: String,
    nonce: [u8; 32],
    recipient: String,
    callback_url: Option<String>,
}

/// The longest a session lasts: the coordinator's bound, held here as well,
/// so a statement the coordinator would not have taken vouches for no device.
pub const MAX_SESSION_SECS: i64 = 30 * 24 * 60 * 60;
/// By how much a statement's deadline may exceed the longest session.
pub const DEADLINE_SLACK_SECS: i64 = 10 * 60;

/// Does `statement` hold for `owner` at `now`, by what can be checked without
/// the chain (1 and 2 above)? The device's key on success.
pub fn signed_by_its_signer(
    statement: &DeviceStatement,
    owner: &str,
    now: i64,
    recipient: &str,
) -> Result<p256::PublicKey, String> {
    use ed25519_dalek::Verifier;
    if statement.account_id != owner {
        return Err("the statement is for another account".to_string());
    }
    if statement.valid_until <= now {
        return Err("the statement's deadline has passed".to_string());
    }
    if statement.valid_until > now.saturating_add(MAX_SESSION_SECS + DEADLINE_SLACK_SECS) {
        return Err("the statement is valid for longer than a session lasts".to_string());
    }
    let device = super::crypto::read_pubkey(&statement.device_pubkey)?;
    let message = sentence(&statement.account_id, &statement.device_pubkey, statement.valid_until)
        .ok_or("the deadline is not a time")?;

    let signer = statement
        .signer_pubkey
        .strip_prefix("ed25519:")
        .and_then(|key| bs58::decode(key).into_vec().ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
        .ok_or("the signer's key is not `ed25519:` and 32 bytes of base58")?;
    let standard = base64::engine::general_purpose::STANDARD;
    let signature = standard
        .decode(statement.signature.as_bytes())
        .ok()
        .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
        .map(|bytes| ed25519_dalek::Signature::from_bytes(&bytes))
        .ok_or("the signature is not 64 bytes of base64")?;
    let nonce = standard
        .decode(statement.nonce.as_bytes())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or("the nonce is not 32 bytes of base64")?;

    let payload = Nep413Payload { message, nonce, recipient: recipient.to_string(), callback_url: None };
    let payload = borsh::to_vec(&payload).map_err(|_| "the statement could not be serialised".to_string())?;
    let signed = Sha256::digest([&NEP413_TAG.to_le_bytes()[..], &payload].concat());
    signer.verify(&signed, &signature).map_err(|_| "the signature does not verify".to_string())?;
    Ok(device)
}

/// What the chain says of a key and an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnChain {
    /// A full-access key of the account.
    ItsKey,
    /// Not one: no such key on the account, no such account, or a key that
    /// may only call functions.
    NotItsKey,
}

/// Read the answer of `query` / `view_access_key`. A key vouches for a device
/// when it is a FULL-ACCESS key of the account: the answer carries the key's
/// `nonce`, the permission `FullAccess`, and no error. A function-call key is
/// held by whatever application the owner once logged into, which signs with
/// it with no wallet and no owner, so it names no device. "No such key" and
/// "no such account" are answers; anything else the node says is no answer.
pub fn read_access_key_answer(answer: &serde_json::Value) -> Result<OnChain, ChainUnavailable> {
    let no_answer = || ChainUnavailable("the chain's answer about a key could not be read".to_string());
    if let Some(error) = answer.get("error") {
        let cause = error.get("cause").and_then(|c| c.get("name")).and_then(|n| n.as_str());
        return match cause {
            Some("UNKNOWN_ACCESS_KEY" | "UNKNOWN_ACCOUNT" | "INVALID_ACCOUNT") => Ok(OnChain::NotItsKey),
            _ => Err(no_answer()),
        };
    }
    let result = answer.get("result").ok_or_else(no_answer)?;
    match result.get("error").and_then(|e| e.as_str()) {
        Some(said) if said.contains("does not exist") => Ok(OnChain::NotItsKey),
        Some(_) => Err(no_answer()),
        None if result.get("nonce").is_some() => match result.get("permission") {
            Some(serde_json::Value::String(full)) if full == "FullAccess" => Ok(OnChain::ItsKey),
            // A key that is not a full-access key vouches for no device,
            // whatever else it is: a permission this build does not know is
            // not full access.
            Some(serde_json::Value::String(_) | serde_json::Value::Object(_)) => Ok(OnChain::NotItsKey),
            _ => Err(no_answer()),
        },
        None => Err(no_answer()),
    }
}

/// Asks the chain whose a key is.
///
/// The RPC node is trusted as the platform trusts it everywhere: what it
/// says of a key is taken as the chain's word, not checked against a second
/// node and not proved by a light client. A node that lies about whose a
/// key is can name a device the owner never signed in; that is the RPC's
/// standing on this platform, and it is not argued with here.
pub trait Chain {
    fn access_key(&self, account: &str, public_key: &str) -> Result<OnChain, ChainUnavailable>;
}

/// The chain over JSON-RPC, at the final block.
pub struct RpcChain {
    client: reqwest::blocking::Client,
    rpc_url: String,
}

impl RpcChain {
    pub fn new(rpc_url: String) -> Result<Self, ChainUnavailable> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .map_err(|_| ChainUnavailable("no client for the chain could be made".to_string()))?;
        Ok(Self { client, rpc_url })
    }
}

impl Chain for RpcChain {
    fn access_key(&self, account: &str, public_key: &str) -> Result<OnChain, ChainUnavailable> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "tasks",
            "method": "query",
            "params": {
                "request_type": "view_access_key",
                "finality": "final",
                "account_id": account,
                "public_key": public_key,
            }
        });
        // The URL may carry a key: no error of the transport is quoted.
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .map_err(|_| ChainUnavailable("the chain did not answer".to_string()))?;
        if !response.status().is_success() {
            return Err(ChainUnavailable(format!("the chain answered {}", response.status().as_u16())));
        }
        let answer: serde_json::Value =
            response.json().map_err(|_| ChainUnavailable("the chain's answer is not JSON".to_string()))?;
        read_access_key_answer(&answer)
    }
}

/// The owner's devices among `statements`: every row that holds, by all
/// three checks. A row that does not hold is passed over; a chain that gives
/// no answer fails the whole. The chain is asked of a key once, however many
/// statements that key signed.
pub fn devices_in_force(
    statements: &[DeviceStatement],
    owner: &str,
    now: i64,
    recipient: &str,
    chain: &dyn Chain,
) -> Result<Vec<Device>, ChainUnavailable> {
    let mut devices = Vec::new();
    let mut asked: Vec<(&str, OnChain)> = Vec::new();
    for statement in statements {
        let key = match signed_by_its_signer(statement, owner, now, recipient) {
            Ok(key) => key,
            Err(why) => {
                tracing::warn!(device = %statement.id, "a device's statement does not hold: {why}");
                continue;
            }
        };
        let signer = statement.signer_pubkey.as_str();
        let on_chain = match asked.iter().find(|(key, _)| *key == signer) {
            Some((_, answered)) => *answered,
            None => {
                let answered = chain.access_key(owner, signer)?;
                asked.push((signer, answered));
                answered
            }
        };
        match on_chain {
            OnChain::ItsKey => devices.push(Device { id: statement.id.clone(), key }),
            OnChain::NotItsKey => {
                tracing::warn!(device = %statement.id, "a device's statement was signed by a key that is not the account's");
            }
        }
    }
    Ok(devices)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const RECIPIENT: &str = "outlayer.testnet";
    pub(crate) const NOW: i64 = 1_790_000_000;

    /// A chain that answers from a list of the keys it holds for an account.
    pub(crate) struct FakeChain {
        pub keys: Vec<(String, String)>,
        pub down: bool,
        pub asked: std::sync::atomic::AtomicUsize,
    }

    impl FakeChain {
        pub(crate) fn holding(keys: &[(&str, &str)]) -> Self {
            Self {
                keys: keys.iter().map(|(a, k)| (a.to_string(), k.to_string())).collect(),
                down: false,
                asked: Default::default(),
            }
        }
    }

    impl Chain for FakeChain {
        fn access_key(&self, account: &str, public_key: &str) -> Result<OnChain, ChainUnavailable> {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.down {
                return Err(ChainUnavailable("the chain did not answer".to_string()));
            }
            match self.keys.iter().any(|(a, k)| a == account && k == public_key) {
                true => Ok(OnChain::ItsKey),
                false => Ok(OnChain::NotItsKey),
            }
        }
    }

    /// A chain whose node says one thing of every key, read as the node's answers
    /// are read.
    pub(crate) struct Saying(pub serde_json::Value);

    impl Chain for Saying {
        fn access_key(&self, _account: &str, _public_key: &str) -> Result<OnChain, ChainUnavailable> {
            read_access_key_answer(&self.0)
        }
    }

    /// The owner's wallet key, by a seed.
    pub(crate) fn wallet(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    pub(crate) fn near_key(wallet: &ed25519_dalek::SigningKey) -> String {
        format!("ed25519:{}", bs58::encode(wallet.verifying_key().as_bytes()).into_string())
    }

    /// A statement as the wallet signs it and the coordinator stores it.
    pub(crate) fn signed(
        id: &str,
        account: &str,
        device: &p256::PublicKey,
        valid_until: i64,
        wallet: &ed25519_dalek::SigningKey,
        recipient: &str,
    ) -> DeviceStatement {
        use ed25519_dalek::Signer;
        let device_pubkey = crate::tasks::crypto::write_pubkey(device);
        let nonce = [3u8; 32];
        let payload = Nep413Payload {
            message: sentence(account, &device_pubkey, valid_until).unwrap(),
            nonce,
            recipient: recipient.to_string(),
            callback_url: None,
        };
        let signed = Sha256::digest([&NEP413_TAG.to_le_bytes()[..], &borsh::to_vec(&payload).unwrap()].concat());
        let standard = base64::engine::general_purpose::STANDARD;
        DeviceStatement {
            id: id.to_string(),
            account_id: account.to_string(),
            device_pubkey,
            signer_pubkey: near_key(wallet),
            signature: standard.encode(wallet.sign(&signed).to_bytes()),
            nonce: standard.encode(nonce),
            valid_until,
        }
    }

    pub(crate) fn device_key() -> p256::SecretKey {
        p256::SecretKey::random(&mut rand::rngs::OsRng)
    }

    #[test]
    fn the_sentence_is_the_coordinators() {
        assert_eq!(
            sentence("alice.near", "p256:abc", 1_793_275_200).unwrap(),
            "Sign in to OutLayer as alice.near. Device key: p256:abc. Valid until 2026-10-29T12:00:00Z."
        );
        assert_eq!(iso8601_utc(0).unwrap(), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(951_782_400).unwrap(), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601_utc(1_709_251_199).unwrap(), "2024-02-29T23:59:59Z");
        assert!(iso8601_utc(-1).is_none());
    }

    #[test]
    fn a_statement_the_wallet_signed_names_the_device() {
        let device = device_key().public_key();
        let statement = signed("d1", "owner.testnet", &device, NOW + 60, &wallet(1), RECIPIENT);
        assert_eq!(signed_by_its_signer(&statement, "owner.testnet", NOW, RECIPIENT).unwrap(), device);
    }

    /// Signed by the page's side (`tests/lib/tasks_page.mjs`, `signStatement`)
    /// on WebCrypto: the wallet key of seed `01 … 01`, the device of the
    /// golden vectors, the nonce `03 … 03`.
    #[test]
    fn the_statement_the_page_signs_holds() {
        let statement: DeviceStatement = serde_json::from_value(serde_json::json!({
            "id": "d1",
            "account_id": "owner.testnet",
            "device_pubkey": "p256:BFFcPW6545a5BNP-yn9U_c0MwemXvzddylFa0KbDtANfRTa-OlDzGPv5pUdZAqIhUCvvDVfgjFOyzApW8X2fk1Q",
            "signer_pubkey": "ed25519:AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9",
            "signature": "nP0kjWpQdNVZMcFlJBqstitEFOlIZDx8inTw92JL0hxdCm98hhBntjrDR/yHIFHpgefMZWjzlPWBzK3lbaytAA==",
            "nonce": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
            "valid_until": 4_000_000_000i64,
        }))
        .unwrap();
        let signed_for = 4_000_000_000i64;
        signed_by_its_signer(&statement, "owner.testnet", signed_for - 60, RECIPIENT)
            .expect("the page's statement holds");
        assert_eq!(statement.signer_pubkey, near_key(&wallet(1)));
        // The longest a session lasts, and no longer: a statement the
        // coordinator would not have taken vouches for no device.
        let longest = MAX_SESSION_SECS + DEADLINE_SLACK_SECS;
        assert!(signed_by_its_signer(&statement, "owner.testnet", signed_for - longest, RECIPIENT).is_ok());
        assert_eq!(
            signed_by_its_signer(&statement, "owner.testnet", signed_for - longest - 1, RECIPIENT).unwrap_err(),
            "the statement is valid for longer than a session lasts"
        );
    }

    #[test]
    fn a_statement_that_was_changed_or_is_anothers_or_is_over_does_not_hold() {
        let device = device_key().public_key();
        let good = || signed("d1", "owner.testnet", &device, NOW + 60, &wallet(1), RECIPIENT);
        let refusal = |s: DeviceStatement| signed_by_its_signer(&s, "owner.testnet", NOW, RECIPIENT).unwrap_err();

        assert!(refusal(DeviceStatement { account_id: "other.testnet".into(), ..good() }).contains("another account"));
        assert!(refusal(signed("d1", "owner.testnet", &device, NOW, &wallet(1), RECIPIENT)).contains("has passed"));
        // A row that names another device, or another deadline, than the one signed.
        let another = crate::tasks::crypto::write_pubkey(&device_key().public_key());
        assert!(refusal(DeviceStatement { device_pubkey: another, ..good() }).contains("does not verify"));
        assert!(refusal(DeviceStatement { valid_until: NOW + 3600, ..good() }).contains("does not verify"));
        // A row that names another signer than the one that signed.
        assert!(refusal(DeviceStatement { signer_pubkey: near_key(&wallet(2)), ..good() }).contains("does not verify"));
        // Signed for another account by the same key, and presented as this one's.
        let anothers = signed("d1", "other.testnet", &device, NOW + 60, &wallet(1), RECIPIENT);
        assert!(refusal(DeviceStatement { account_id: "owner.testnet".into(), ..anothers }).contains("does not verify"));
        // Signed for another recipient.
        assert!(refusal(signed("d1", "owner.testnet", &device, NOW + 60, &wallet(1), "other.testnet")).contains("does not verify"));
        assert!(refusal(DeviceStatement { signature: "AAAA".into(), ..good() }).contains("64 bytes"));
        assert!(refusal(DeviceStatement { nonce: "AAAA".into(), ..good() }).contains("32 bytes"));
        assert!(refusal(DeviceStatement { signer_pubkey: "secp256k1:abc".into(), ..good() }).contains("ed25519"));
        assert!(refusal(DeviceStatement { device_pubkey: "p256:AAAA".into(), ..good() }).contains("uncompressed"));
    }

    #[test]
    fn a_device_is_in_force_only_when_its_signer_is_the_accounts_key_on_chain() {
        let (mine, forged, lapsed) = (device_key().public_key(), device_key().public_key(), device_key().public_key());
        let statements = vec![
            signed("mine", "owner.testnet", &mine, NOW + 60, &wallet(1), RECIPIENT),
            // Signed, correctly, by a key that is not the owner's: what whoever
            // holds the store would write to add a device of their own.
            signed("forged", "owner.testnet", &forged, NOW + 60, &wallet(9), RECIPIENT),
            signed("lapsed", "owner.testnet", &lapsed, NOW - 1, &wallet(1), RECIPIENT),
        ];
        let chain = FakeChain::holding(&[("owner.testnet", &near_key(&wallet(1)))]);
        let devices = devices_in_force(&statements, "owner.testnet", NOW, RECIPIENT, &chain).unwrap();
        assert_eq!(devices.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), vec!["mine"]);
        assert_eq!(devices[0].key, mine);
        assert_eq!(chain.asked.load(std::sync::atomic::Ordering::SeqCst), 2, "a statement that does not hold costs no read of the chain");

        // The key was removed from the account since.
        let chain = FakeChain::holding(&[]);
        assert!(devices_in_force(&statements, "owner.testnet", NOW, RECIPIENT, &chain).unwrap().is_empty());
    }

    #[test]
    fn the_chain_is_asked_of_a_key_once_however_many_statements_it_signed() {
        let count = |chain: &FakeChain| chain.asked.load(std::sync::atomic::Ordering::SeqCst);
        let statements: Vec<DeviceStatement> = ["d1", "d2", "d3"]
            .iter()
            .map(|id| signed(id, "owner.testnet", &device_key().public_key(), NOW + 60, &wallet(1), RECIPIENT))
            .chain([
                signed("forged-1", "owner.testnet", &device_key().public_key(), NOW + 60, &wallet(9), RECIPIENT),
                signed("d4", "owner.testnet", &device_key().public_key(), NOW + 60, &wallet(2), RECIPIENT),
                signed("forged-2", "owner.testnet", &device_key().public_key(), NOW + 60, &wallet(9), RECIPIENT),
            ])
            .collect();
        let chain =
            FakeChain::holding(&[("owner.testnet", &near_key(&wallet(1))), ("owner.testnet", &near_key(&wallet(2)))]);
        let devices = devices_in_force(&statements, "owner.testnet", NOW, RECIPIENT, &chain).unwrap();
        assert_eq!(devices.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), vec!["d1", "d2", "d3", "d4"]);
        assert_eq!(count(&chain), 3, "three keys signed six statements");

        // Each call asks for itself: what one call heard is not the next call's.
        devices_in_force(&statements[..2], "owner.testnet", NOW, RECIPIENT, &chain).unwrap();
        assert_eq!(count(&chain), 4);
    }

    #[test]
    fn a_statement_valid_for_longer_than_a_session_lasts_is_no_device_and_costs_no_read_of_the_chain() {
        let longest = NOW + MAX_SESSION_SECS + DEADLINE_SLACK_SECS;
        let chain = FakeChain::holding(&[("owner.testnet", &near_key(&wallet(1)))]);
        // Signed by the owner's own wallet, whose key is the account's.
        let beyond = vec![
            signed("a-second-over", "owner.testnet", &device_key().public_key(), longest + 1, &wallet(1), RECIPIENT),
            signed("a-year", "owner.testnet", &device_key().public_key(), NOW + 365 * 86_400, &wallet(1), RECIPIENT),
            signed("the-last-year", "owner.testnet", &device_key().public_key(), 253_402_300_799, &wallet(1), RECIPIENT),
        ];
        assert!(devices_in_force(&beyond, "owner.testnet", NOW, RECIPIENT, &chain).unwrap().is_empty());
        assert_eq!(chain.asked.load(std::sync::atomic::Ordering::SeqCst), 0);

        // The longest a session lasts is a device, and those beside it are not.
        let within = signed("the-longest", "owner.testnet", &device_key().public_key(), longest, &wallet(1), RECIPIENT);
        let statements = [beyond, vec![within]].concat();
        let devices = devices_in_force(&statements, "owner.testnet", NOW, RECIPIENT, &chain).unwrap();
        assert_eq!(devices.iter().map(|d| d.id.as_str()).collect::<Vec<_>>(), vec!["the-longest"]);
        assert_eq!(chain.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn a_key_of_a_permission_this_build_does_not_know_vouches_for_no_device_and_fails_nothing() {
        use serde_json::json;
        let statements =
            vec![signed("mine", "owner.testnet", &device_key().public_key(), NOW + 60, &wallet(1), RECIPIENT)];
        for permission in [
            json!("SomethingNew"),
            json!({"SomethingNew": {}}),
            json!({"FunctionCall": {"allowance": null, "receiver_id": "app.near", "method_names": []}}),
        ] {
            let chain = Saying(json!({"result": {"nonce": 5, "permission": permission, "block_height": 1}}));
            let devices = devices_in_force(&statements, "owner.testnet", NOW, RECIPIENT, &chain);
            assert!(devices.expect("an answer, not a chain that is down").is_empty(), "{permission}");
        }
        let chain = Saying(json!({"result": {"nonce": 5, "permission": "FullAccess", "block_height": 1}}));
        assert_eq!(devices_in_force(&statements, "owner.testnet", NOW, RECIPIENT, &chain).unwrap().len(), 1);
    }

    #[test]
    fn a_chain_that_gives_no_answer_is_not_an_owner_without_devices() {
        let statements =
            vec![signed("mine", "owner.testnet", &device_key().public_key(), NOW + 60, &wallet(1), RECIPIENT)];
        let mut chain = FakeChain::holding(&[("owner.testnet", &near_key(&wallet(1)))]);
        chain.down = true;
        assert!(devices_in_force(&statements, "owner.testnet", NOW, RECIPIENT, &chain).is_err());
        // With no statement to check, nothing is asked and nothing fails.
        assert!(devices_in_force(&[], "owner.testnet", NOW, RECIPIENT, &chain).unwrap().is_empty());
    }

    #[test]
    fn the_chains_answer_is_a_key_no_key_or_no_answer() {
        use serde_json::json;
        let read = |v: serde_json::Value| read_access_key_answer(&v);
        assert_eq!(read(json!({"result": {"nonce": 5, "permission": "FullAccess", "block_height": 1}})), Ok(OnChain::ItsKey));
        assert_eq!(
            read(json!({"result": {"error": "access key ed25519:x does not exist while viewing", "block_height": 1, "logs": []}})),
            Ok(OnChain::NotItsKey)
        );
        assert_eq!(
            read(json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_ACCESS_KEY", "info": {}}}})),
            Ok(OnChain::NotItsKey)
        );
        assert_eq!(
            read(json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": "UNKNOWN_ACCOUNT", "info": {}}}})),
            Ok(OnChain::NotItsKey)
        );
        // A key that may only call functions is held by an application, not by
        // the owner's wallet: it vouches for no device.
        assert_eq!(
            read(json!({"result": {"nonce": 5, "block_height": 1, "permission": {"FunctionCall": {
                "allowance": "250000000000000000000000", "receiver_id": "app.near", "method_names": []
            }}}})),
            Ok(OnChain::NotItsKey)
        );
        for unknown in [json!("SomethingNew"), json!({"SomethingNew": {}})] {
            assert_eq!(
                read(json!({"result": {"nonce": 5, "permission": unknown, "block_height": 1}})),
                Ok(OnChain::NotItsKey)
            );
        }
        for no_answer in [
            json!({"error": {"name": "HANDLER_ERROR", "cause": {"name": "NO_SYNCED_BLOCKS"}}}),
            json!({"error": {"name": "INTERNAL_ERROR", "cause": {"name": "INTERNAL_ERROR"}}}),
            json!({"error": "rate limited"}),
            json!({"result": {"error": "something else", "block_height": 1}}),
            json!({"result": {"block_height": 1}}),
            json!({"result": {"nonce": 5, "block_height": 1}}),
            json!({"result": {"nonce": 5, "permission": 7, "block_height": 1}}),
            json!({}),
        ] {
            assert!(read(no_answer.clone()).is_err(), "{no_answer}");
        }
    }
}
