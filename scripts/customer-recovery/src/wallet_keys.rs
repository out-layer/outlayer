//! `derive-wallet-key` — every key of a wallet, from the master it was derived from.
//!
//! The keystore derives each key of a wallet as `HMAC-SHA256(master, seed)` and uses the 32
//! bytes as the key material: an ed25519 seed for NEAR and Solana, a secp256k1 scalar for EVM.
//! The seeds, byte for byte (`keystore-worker/src/api.rs` `wallet_seed`, `subkey_seed`;
//! `keystore-worker/src/ephemeral_keys.rs`):
//!
//! | Key | Seed |
//! |---|---|
//! | NEAR | `wallet:{id}:near` |
//! | EVM, every EVM network | `wallet:{id}:evm` |
//! | Solana (`sol` is the same key) | `wallet:{id}:solana` |
//! | EVM sub-key | `subkey:{id}:evm:{sub_path}` |
//! | payment check `n` | `wallet:{id}:near:check:{n}` |
//!
//! The vector in `tests` is the keystore's own (`keystore-worker/src/api_tests.rs`,
//! `recovery_tool_vector`): both sides assert the same literals, so a change to either
//! derivation fails a test on both.

use anyhow::{anyhow, bail, Result};
use hmac::{Hmac, Mac};
use serde::Serialize;
use std::io::Write;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<sha2::Sha256>;

/// The EVM network names the keystore takes for the one EVM key
/// (`shared_tee_helpers::is_evm_chain`).
const EVM_CHAINS: &[&str] = &[
    "ethereum", "eth", "polygon", "pol", "matic", "base", "arbitrum", "arb", "optimism", "op",
    "bsc", "avalanche", "avax", "hyperevm", "hood",
];

/// A wallet's own key on one chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Chain {
    Near,
    Evm,
    Solana,
}

impl Chain {
    pub(crate) const ALL: [Chain; 3] = [Chain::Near, Chain::Evm, Chain::Solana];

    fn name(self) -> &'static str {
        match self {
            Chain::Near => "near",
            Chain::Evm => "evm",
            Chain::Solana => "solana",
        }
    }

    /// The chains a `--chain` value names: `all`, `near`, `evm` or any EVM network name the
    /// keystore takes, `solana` or `sol`.
    pub(crate) fn parse(raw: &str) -> Result<Vec<Chain>> {
        let c = raw.to_ascii_lowercase();
        Ok(match c.as_str() {
            "all" => Chain::ALL.to_vec(),
            "near" => vec![Chain::Near],
            "evm" => vec![Chain::Evm],
            "solana" | "sol" => vec![Chain::Solana],
            _ if EVM_CHAINS.contains(&c.as_str()) => vec![Chain::Evm],
            _ => bail!(
                "unknown chain '{raw}': a wallet has keys on near, evm (one key for every EVM network: {}) \
                 and solana; 'all' is the three",
                EVM_CHAINS.join(", ")
            ),
        })
    }
}

/// One key to derive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Key {
    /// The wallet's own key on a chain.
    Wallet(Chain),
    /// An EVM sub-key; the path is already validated.
    SubKey(String),
    /// The key of the wallet's payment check number `n`.
    Check(u64),
}

/// A wallet id the keystore derives for: non-empty, no `:` (`validate_wallet_id`). Every
/// seed uses `:` as its separator, so an id carrying one names no wallet.
pub(crate) fn validate_wallet_id(wallet_id: &str) -> Result<()> {
    if wallet_id.is_empty() || wallet_id.contains(':') {
        bail!("--wallet-id must be non-empty and must not contain ':' (the keystore derives no key for such an id)");
    }
    Ok(())
}

/// A sub-key path as the keystore takes it (`shared_tee_helpers::is_valid_sub_path`):
/// `[a-z0-9][a-z0-9._-]{0,63}`. Validated, never normalised: another spelling is another
/// key.
pub(crate) fn validate_sub_path(path: &str) -> Result<()> {
    if path.is_empty() {
        bail!("--sub-path is empty: the empty path is the wallet's own EVM key, which --chain evm prints");
    }
    let bytes = path.as_bytes();
    let first = bytes[0];
    let ok = bytes.len() <= 64
        && (first.is_ascii_lowercase() || first.is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'));
    if !ok {
        bail!(
            "--sub-path '{path}' is refused: a sub_path must match [a-z0-9][a-z0-9._-]{{0,63}} \
             (lowercase letters, digits, '.', '_', '-'; at most 64 characters; it starts with a letter or digit), \
             and the keystore derives no key for any other"
        );
    }
    Ok(())
}

fn seed_of(wallet_id: &str, key: &Key) -> String {
    match key {
        Key::Wallet(chain) => format!("wallet:{wallet_id}:{}", chain.name()),
        Key::SubKey(path) => format!("subkey:{wallet_id}:evm:{path}"),
        Key::Check(n) => format!("wallet:{wallet_id}:near:check:{n}"),
    }
}

/// One derived key, as printed.
#[derive(Serialize)]
pub(crate) struct Derived {
    pub chain: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check: Option<u64>,
    pub seed: String,
    pub address: String,
    pub public_key: String,
    #[serde(serialize_with = "serialize_secret")]
    pub private_key: Zeroizing<String>,
}

fn serialize_secret<S: serde::Serializer>(v: &Zeroizing<String>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.as_str())
}

fn hmac(master: &[u8; 32], seed: &str) -> Zeroizing<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(master).expect("HMAC takes a key of any size");
    mac.update(seed.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// `prefix` + base58 of `bytes`, in a buffer that is wiped on drop.
fn secret_b58(prefix: &str, bytes: &[u8]) -> Zeroizing<String> {
    let encoded = Zeroizing::new(bs58::encode(bytes).into_string());
    let mut s = Zeroizing::new(String::with_capacity(prefix.len() + encoded.len()));
    s.push_str(prefix);
    s.push_str(&encoded);
    s
}

/// `0x` + hex of `bytes`, in a buffer that is wiped on drop.
fn secret_hex(bytes: &[u8; 32]) -> Zeroizing<String> {
    let mut buf = Zeroizing::new([0u8; 64]);
    hex::encode_to_slice(bytes, &mut *buf).expect("64 bytes hold 32 in hex");
    let mut s = Zeroizing::new(String::with_capacity(66));
    s.push_str("0x");
    s.push_str(std::str::from_utf8(&*buf).expect("hex is ASCII"));
    s
}

/// The ed25519 key of `secret`: its public key and the 64-byte `seed ‖ public key` form.
fn ed25519(secret: &[u8; 32]) -> ([u8; 32], Zeroizing<[u8; 64]>) {
    let signing = ed25519_dalek::SigningKey::from_bytes(secret);
    let public = signing.verifying_key().to_bytes();
    let mut keypair = Zeroizing::new([0u8; 64]);
    keypair[..32].copy_from_slice(secret);
    keypair[32..].copy_from_slice(&public);
    (public, keypair)
}

/// Derive one key of `wallet_id` from `master`.
///
/// - NEAR (and a payment check, a NEAR implicit account): address = hex of the ed25519 public
///   key; `public_key` `ed25519:<base58>`; `private_key` `ed25519:<base58 of seed ‖ public>`,
///   the form near-cli and NEAR wallets import.
/// - EVM: address = `0x` + the last 20 bytes of keccak256 of the uncompressed public key, lower
///   case as the keystore serves it; `public_key` `secp256k1:<hex of the compressed point>`, as
///   the coordinator serves it; `private_key` the 32-byte scalar as `0x` hex, the form MetaMask
///   and every EVM wallet import.
/// - Solana: address = `public_key` = base58 of the ed25519 public key; `private_key` the base58
///   of the 64-byte `seed ‖ public` keypair, the form Phantom, Solflare and Backpack import (its
///   first 32 bytes are the seed; solana-cli's keypair file is the same 64 bytes as a JSON array).
pub(crate) fn derive(master: &[u8; 32], wallet_id: &str, key: &Key) -> Result<Derived> {
    let seed = seed_of(wallet_id, key);
    let secret = hmac(master, &seed);
    let (chain, sub_path, check) = match key {
        Key::Wallet(c) => (*c, None, None),
        Key::SubKey(p) => (Chain::Evm, Some(p.clone()), None),
        Key::Check(n) => (Chain::Near, None, Some(*n)),
    };
    let (address, public_key, private_key) = match chain {
        Chain::Near => {
            let (public, keypair) = ed25519(&secret);
            (
                hex::encode(public),
                format!("ed25519:{}", bs58::encode(public).into_string()),
                secret_b58("ed25519:", &*keypair),
            )
        }
        Chain::Solana => {
            let (public, keypair) = ed25519(&secret);
            let address = bs58::encode(public).into_string();
            (address.clone(), address, secret_b58("", &*keypair))
        }
        Chain::Evm => {
            use sha3::{Digest, Keccak256};
            let signing = k256::ecdsa::SigningKey::from_slice(&*secret)
                .map_err(|_| anyhow!("the derived bytes for {seed} are not a valid secp256k1 scalar"))?;
            let verifying = signing.verifying_key();
            let uncompressed = verifying.to_encoded_point(false);
            let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
            (
                format!("0x{}", hex::encode(&hash[12..])),
                format!("secp256k1:{}", hex::encode(verifying.to_encoded_point(true).as_bytes())),
                secret_hex(&secret),
            )
        }
    };
    Ok(Derived { chain: chain.name(), sub_path, check, seed, address, public_key, private_key })
}

/// The 32-byte master from its hex form.
pub(crate) fn parse_master(master_hex: &str) -> Result<Zeroizing<[u8; 32]>> {
    let bytes = Zeroizing::new(
        hex::decode(master_hex.trim()).map_err(|_| anyhow!("the master must be hex-encoded (32 bytes)"))?,
    );
    if bytes.len() != 32 {
        bail!("the master must decode to 32 bytes, got {}", bytes.len());
    }
    let mut master = Zeroizing::new([0u8; 32]);
    master.copy_from_slice(&bytes);
    Ok(master)
}

/// The keys `--chain`, `--sub-path` and `--checks` ask for, in print order: the wallet's own
/// keys (near, evm, solana), then each sub-key in the order given, then checks 0..n.
pub(crate) fn keys_asked(chains: &[String], sub_paths: &[String], checks: Option<u64>) -> Result<Vec<Key>> {
    let mut own: Vec<Chain> = Vec::new();
    for raw in chains {
        own.extend(Chain::parse(raw)?);
    }
    own.sort();
    own.dedup();
    let mut keys: Vec<Key> = own.into_iter().map(Key::Wallet).collect();
    for p in sub_paths {
        validate_sub_path(p)?;
        let k = Key::SubKey(p.clone());
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    if let Some(n) = checks {
        keys.extend((0..n).map(Key::Check));
    }
    Ok(keys)
}

/// `derive-wallet-key`. With none of `--chain`, `--sub-path`, `--checks`: the NEAR key, as
/// `{wallet_id, near_address, public_key, private_key}`. With any of them:
/// `{wallet_id, keys: [{chain, sub_path?, check?, seed, address, public_key, private_key}]}`.
pub(crate) fn run(
    master_hex: &str,
    wallet_id: &str,
    chains: &[String],
    sub_paths: &[String],
    checks: Option<u64>,
) -> Result<()> {
    validate_wallet_id(wallet_id)?;
    let master = parse_master(master_hex)?;
    let mut out = std::io::stdout().lock();

    if chains.is_empty() && sub_paths.is_empty() && checks.is_none() {
        let near = derive(&master, wallet_id, &Key::Wallet(Chain::Near))?;
        #[derive(Serialize)]
        struct Near<'a> {
            wallet_id: &'a str,
            near_address: &'a str,
            public_key: &'a str,
            private_key: &'a str,
        }
        crate::warn_sensitive_stdout(&format!("the wallet ({}) private key", near.address));
        serde_json::to_writer_pretty(
            &mut out,
            &Near {
                wallet_id,
                near_address: &near.address,
                public_key: &near.public_key,
                private_key: near.private_key.as_str(),
            },
        )?;
        writeln!(out)?;
        return Ok(());
    }

    let keys = keys_asked(chains, sub_paths, checks)?;
    if keys.is_empty() {
        bail!("--checks 0 asks for no key");
    }
    let derived = keys.iter().map(|k| derive(&master, wallet_id, k)).collect::<Result<Vec<_>>>()?;
    #[derive(Serialize)]
    struct All<'a> {
        wallet_id: &'a str,
        keys: &'a [Derived],
    }
    crate::warn_sensitive_stdout(&format!(
        "{} private key{} of wallet {wallet_id}",
        derived.len(),
        if derived.len() == 1 { "" } else { "s" }
    ));
    serde_json::to_writer_pretty(&mut out, &All { wallet_id, keys: &derived })?;
    writeln!(out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The keystore's vector (`keystore-worker/src/api_tests.rs`, `recovery_tool_vector`):
    // master 11…11, this wallet id, through the keystore's own handlers.
    const MASTER: [u8; 32] = [0x11; 32];
    const WALLET: &str = "9c3c9e10-1c1f-4f5e-9c4a-1d7b9a8f3c20";
    const SUB_PATH: &str = "connector.hyperliquid.trading";
    const NEAR_ADDRESS: &str = "11d8a01bd1ec8da7e9657fc667def1b119c9134d9f0bd598d0e892acbb509dfb";
    const EVM_ADDRESS: &str = "0x67f9b3a0e9b86bbe94467bb1de36c260e278c00d";
    const EVM_PUBLIC_KEY: &str = "secp256k1:03e643b847b56471ee68bafba8c9339ae5e8a8a5851baa64638afc136799305873";
    const SOLANA_ADDRESS: &str = "4DzrREz9YM3DZACSLDjkFiWziMsAkMUCr53wnerAm6PD";
    const SUB_ADDRESS: &str = "0x1b75687a0450a6629f889f18c8b597a48a63afa7";
    const SUB_PUBLIC_KEY: &str = "secp256k1:03a9da0d0b49df5a17141b677f19103367d078b54305f595cfc55813cdcf4ca525";
    const CHECK0_ADDRESS: &str = "bc5d6d6f64c649aa870de36fb2bb0b87fdd37558b0160361dc792e56b7e6991e";
    const CHECK7_ADDRESS: &str = "88d52f62edc329eec3513eacfab405ad6d634140fad7d734daa7bf8507d82540";

    fn get(key: Key) -> Derived {
        derive(&MASTER, WALLET, &key).unwrap()
    }

    #[test]
    fn the_keystores_wallet_keys_are_derived_here() {
        let near = get(Key::Wallet(Chain::Near));
        assert_eq!(near.seed, format!("wallet:{WALLET}:near"));
        assert_eq!(near.address, NEAR_ADDRESS);
        let evm = get(Key::Wallet(Chain::Evm));
        assert_eq!(evm.seed, format!("wallet:{WALLET}:evm"));
        assert_eq!((evm.address.as_str(), evm.public_key.as_str()), (EVM_ADDRESS, EVM_PUBLIC_KEY));
        let sol = get(Key::Wallet(Chain::Solana));
        assert_eq!(sol.seed, format!("wallet:{WALLET}:solana"));
        assert_eq!((sol.address.as_str(), sol.public_key.as_str()), (SOLANA_ADDRESS, SOLANA_ADDRESS));
        let sub = get(Key::SubKey(SUB_PATH.into()));
        assert_eq!(sub.seed, format!("subkey:{WALLET}:evm:{SUB_PATH}"));
        assert_eq!((sub.chain, sub.address.as_str(), sub.public_key.as_str()), ("evm", SUB_ADDRESS, SUB_PUBLIC_KEY));
        assert_eq!(get(Key::Check(0)).address, CHECK0_ADDRESS);
        assert_eq!(get(Key::Check(7)).address, CHECK7_ADDRESS);
    }

    #[test]
    fn each_private_key_is_the_key_of_its_address() {
        // NEAR: ed25519:<base58 of seed ‖ public>, and near-crypto reads it as this account's key.
        let near = get(Key::Wallet(Chain::Near));
        let sk: near_crypto::SecretKey = near.private_key.parse().unwrap();
        assert_eq!(sk.public_key().to_string(), near.public_key);
        assert_eq!(hex::encode(sk.public_key().key_data()), near.address);

        // EVM: 0x + 32-byte scalar, whose address is the one printed.
        let evm = get(Key::Wallet(Chain::Evm));
        assert!(evm.private_key.starts_with("0x") && evm.private_key.len() == 66);
        let scalar = hex::decode(&evm.private_key[2..]).unwrap();
        let sk = k256::ecdsa::SigningKey::from_slice(&scalar).unwrap();
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(&sk.verifying_key().to_encoded_point(false).as_bytes()[1..]);
        assert_eq!(format!("0x{}", hex::encode(&hash[12..])), evm.address);
        assert_eq!(evm.address, evm.address.to_lowercase());

        // Solana: base58 of 64 bytes, seed ‖ public; the public half is the address.
        let sol = get(Key::Wallet(Chain::Solana));
        let kp = bs58::decode(sol.private_key.as_str()).into_vec().unwrap();
        assert_eq!(kp.len(), 64);
        let seed: [u8; 32] = kp[..32].try_into().unwrap();
        let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        assert_eq!(&kp[32..], &public);
        assert_eq!(bs58::encode(public).into_string(), sol.address);
    }

    #[test]
    fn every_evm_network_is_the_one_evm_key_and_sol_is_solana() {
        for c in EVM_CHAINS.iter().chain(["evm", "EVM", "Base"].iter()) {
            assert_eq!(Chain::parse(c).unwrap(), vec![Chain::Evm], "{c}");
        }
        assert_eq!(Chain::parse("sol").unwrap(), vec![Chain::Solana]);
        assert_eq!(Chain::parse("all").unwrap(), Chain::ALL.to_vec());
        for bad in ["bitcoin", "hypercore", "", "near:check", "evm:x"] {
            assert!(Chain::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_sub_path_is_taken_as_the_keystore_takes_it() {
        for ok in ["0", "a", "connector.hl.trading", "a-b_c.d", &"a".repeat(64)] {
            assert!(validate_sub_path(ok).is_ok(), "{ok}");
        }
        for bad in ["", "A", ".a", "-a", "_a", "a:b", "a/b", "a b", "é", &"a".repeat(65), "Connector.x"] {
            let e = validate_sub_path(bad).unwrap_err().to_string();
            assert!(e.contains("--sub-path"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_wallet_id_with_a_colon_names_no_wallet() {
        assert!(validate_wallet_id("a:evm").is_err());
        assert!(validate_wallet_id("").is_err());
        assert!(validate_wallet_id(WALLET).is_ok());
    }

    #[test]
    fn keys_come_in_one_order_each_once() {
        let keys = keys_asked(
            &["solana".into(), "base".into(), "all".into(), "ethereum".into()],
            &["b".into(), "a".into(), "b".into()],
            Some(2),
        )
        .unwrap();
        assert_eq!(
            keys,
            vec![
                Key::Wallet(Chain::Near),
                Key::Wallet(Chain::Evm),
                Key::Wallet(Chain::Solana),
                Key::SubKey("b".into()),
                Key::SubKey("a".into()),
                Key::Check(0),
                Key::Check(1),
            ]
        );
        assert!(keys_asked(&[], &["Bad".into()], None).is_err());
        assert!(keys_asked(&["btc".into()], &[], None).is_err());
    }

    #[test]
    fn the_master_is_32_bytes_of_hex() {
        assert!(parse_master(&"11".repeat(32)).is_ok());
        assert!(parse_master(&format!(" {}\n", "11".repeat(32))).is_ok());
        assert!(parse_master(&"11".repeat(31)).is_err());
        assert!(parse_master("zz").is_err());
    }
}
