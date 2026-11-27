//! An owner who has left acts on a wallet contract alone.
//!
//! A wallet contract (Agent On-chain custody) executes a request under two
//! signatures: the agent's key and the wallet's TEE key. After an exit the
//! owner holds both: the TEE key comes from the owner's master
//! (`owner-exit claim`), the agent's key from one signature of the owner's
//! own NEAR key. This file derives the two, builds a request, signs both
//! halves and prints the call any NEAR account can send. It talks to no
//! service and to no chain.
//!
//! The bytes are `custody_core`'s, the same crate the enclave builds and signs
//! with.

use anyhow::{anyhow, bail, Context, Result};
use custody_core::{
    halves::{proof, sign_half, PublicKeyPair, Role},
    keys::{agent_key, agent_key_message, tee_key, AGENT_KEY_NONCE, AGENT_KEY_RECIPIENT},
    moves::{build, Context as MoveContext, Move},
};
use ed25519_dalek::SigningKey;

/// The published two-key wallet contract, by its code hash
/// (`651XC7DH8J4Xczf8JKXH9pyveBY8ZuNCfy5HZ3SvuSiL`): the build a setup with a
/// new account installs.
const WALLET_CONTRACT_BUILD: [u8; 32] = [
    0x4b, 0x51, 0x58, 0xb0, 0xd1, 0xe9, 0x11, 0xe8, 0x65, 0x75, 0xec, 0x7a, 0xa3, 0xcd, 0x07, 0xd5,
    0xdf, 0x23, 0xb5, 0xaa, 0x55, 0x72, 0x54, 0x4a, 0xa9, 0x81, 0xb5, 0xe1, 0x54, 0xeb, 0x67, 0x71,
];

const USAGE: &str = "\
Usage:
  customer-recovery wallet-contract agent-key-request --owner <account> --wallet-id <id>
      What the owner's NEAR key signs (NEP-413) for the agent's key.

  customer-recovery wallet-contract keys --owner <account> --wallet-id <id> [--build <code hash>]
      The pair of public keys of the wallet contract, and the 0s address (NEP-616)
      of a wallet contract of that pair on the build (base58; the published one
      by default), for a setup that made a new account with no key.

  customer-recovery wallet-contract request --owner <account> --wallet-id <id>
      --contract <account> --network mainnet|testnet [--nonce <n>] <move>
      A request with both halves, as the call `w_execute_signed` takes it.
      <move> is one of:
        --transfer-to <account> --amount <yoctoNEAR>
        --call-to <account> --method <name> --args-base64 <b64> --gas <gas> --deposit <yoctoNEAR>
        --intents-transfer-to <account> --token <token id> --amount <units>
        --intents-withdraw-to <account> --token <NEP-141 account> --amount <units>

Environment (never on the command line):
  CUSTOMER_RECOVERY_MASTER   the owner's master, 64 hex characters (`owner-exit claim`)
  AGENT_KEY_SIGNATURE        the owner's signature over the agent-key request, 128 hex
                             characters or base64";

/// `--name value` pairs.
struct Flags(Vec<(String, String)>);

/// The flags each command takes beside `--owner` and `--wallet-id`; for
/// `request`, the first of each move is what selects it.
/// How far back a request is dated, in seconds: the wallet contract refuses
/// one from its future, and a block's time lags.
const DATED_BACK_SECS: u64 = 60;

/// How long a request can still be sent after it is made.
const VALID_FOR_SECS: u64 = custody_core::TIMEOUT_SECS as u64 - DATED_BACK_SECS;

const REQUEST_FLAGS: [&str; 3] = ["--contract", "--network", "--nonce"];
const MOVES: [&[&str]; 4] = [
    &["--transfer-to", "--amount"],
    &["--call-to", "--method", "--args-base64", "--gas", "--deposit"],
    &["--intents-transfer-to", "--token", "--amount"],
    &["--intents-withdraw-to", "--token", "--amount"],
];

impl Flags {
    fn parse(args: &[String]) -> Result<Self> {
        let mut flags: Vec<(String, String)> = Vec::new();
        for pair in args.chunks(2) {
            match pair {
                [name, value] if name.starts_with("--") => {
                    if flags.iter().any(|(seen, _)| seen == name) {
                        bail!("{name} is given twice");
                    }
                    flags.push((name.clone(), value.clone()));
                }
                _ => bail!("expected `--flag value` pairs\n{USAGE}"),
            }
        }
        Ok(Self(flags))
    }

    /// Refuse a flag the command does not take: a mistyped or a leftover one
    /// would otherwise change nothing, silently.
    fn only(&self, allowed: &[&str]) -> Result<()> {
        match self.0.iter().find(|(name, _)| !allowed.contains(&name.as_str())) {
            Some((name, _)) => bail!("{name} is not a flag of this command\n{USAGE}"),
            None => Ok(()),
        }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(flag, _)| flag == name).map(|(_, value)| value.as_str())
    }

    fn need(&self, name: &str) -> Result<&str> {
        self.get(name).ok_or_else(|| anyhow!("{name} is required\n{USAGE}"))
    }

    fn number<T: std::str::FromStr>(&self, name: &str) -> Result<T> {
        let text = self.need(name)?;
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            bail!("{name} is not a decimal number");
        }
        text.parse().map_err(|_| anyhow!("{name} is out of range"))
    }
}

fn tee(wallet_id: &str) -> Result<SigningKey> {
    let master = std::env::var("CUSTOMER_RECOVERY_MASTER")
        .context("CUSTOMER_RECOVERY_MASTER is not set: the owner's master from `owner-exit claim`")?;
    tee_from(&master, wallet_id)
}

/// The enclave's key of a wallet contract, from the owner's master as `owner-exit claim` prints it.
fn tee_from(master: &str, wallet_id: &str) -> Result<SigningKey> {
    let master = crate::wallet_keys::parse_master(master)?;
    Ok(tee_key(&master, wallet_id))
}

fn agent(owner: &str, wallet_id: &str) -> Result<SigningKey> {
    let text = std::env::var("AGENT_KEY_SIGNATURE").context(
        "AGENT_KEY_SIGNATURE is not set: the owner's signature over `wallet-contract agent-key-request`",
    )?;
    agent_from(&text, owner, wallet_id)
}

/// The agent's key, from the owner's 64-byte signature in hex or in base64.
fn agent_from(text: &str, owner: &str, wallet_id: &str) -> Result<SigningKey> {
    let text = text.trim();
    let bytes = match hex::decode(text) {
        Ok(bytes) => bytes,
        Err(_) => base64::Engine::decode(&base64::engine::general_purpose::STANDARD, text)
            .context("AGENT_KEY_SIGNATURE is neither hex nor base64")?,
    };
    let signature: [u8; 64] =
        bytes.try_into().map_err(|_| anyhow!("AGENT_KEY_SIGNATURE is not a 64-byte signature"))?;
    Ok(agent_key(&signature, owner, wallet_id))
}

fn the_move(flags: &Flags) -> Result<Move> {
    // one move, and no flag of another
    let chosen: Vec<&&[&str]> = MOVES.iter().filter(|mv| flags.get(mv[0]).is_some()).collect();
    let [mv] = chosen.as_slice() else {
        bail!("exactly one move is required\n{USAGE}");
    };
    let allowed: Vec<&str> =
        ["--owner", "--wallet-id"].iter().chain(REQUEST_FLAGS.iter()).chain(mv.iter()).copied().collect();
    flags.only(&allowed)?;

    let text = |name: &str| flags.need(name).map(str::to_string);
    Ok(if let Some(to) = flags.get("--transfer-to") {
        Move::NearTransfer { to: to.to_string(), amount: flags.number("--amount")? }
    } else if let Some(to) = flags.get("--call-to") {
        Move::Call {
            to: to.to_string(),
            method: text("--method")?,
            args: base64::Engine::decode(&base64::engine::general_purpose::STANDARD, flags.need("--args-base64")?)
                .context("--args-base64 is not base64")?,
            gas: flags.number("--gas")?,
            deposit: flags.number("--deposit")?,
        }
    } else if let Some(to) = flags.get("--intents-transfer-to") {
        Move::IntentsTransfer { to: to.to_string(), token_id: text("--token")?, amount: flags.number("--amount")? }
    } else if let Some(to) = flags.get("--intents-withdraw-to") {
        Move::IntentsWithdraw { token: text("--token")?, to: to.to_string(), amount: flags.number("--amount")? }
    } else {
        bail!("a move is required\n{USAGE}");
    })
}

/// The request for the flags, with both halves, at `now_ns`.
fn request(flags: &Flags, agent: &SigningKey, tee: &SigningKey, now_ns: u64) -> Result<serde_json::Value> {
    let network = flags.need("--network")?;
    if !matches!(network, "mainnet" | "testnet") {
        bail!("--network is mainnet or testnet");
    }
    let contract = flags.need("--contract")?;
    let nonce = match flags.get("--nonce") {
        Some(_) => flags.number("--nonce")?,
        // any number the contract has not seen within its timeout: the second it is made in
        None => (now_ns / 1_000_000_000) as u32,
    };
    let message = build(
        &the_move(flags)?,
        &MoveContext {
            chain_id: network.to_string(),
            wallet_contract: contract.to_string(),
            intents_contract: "intents.near".to_string(),
            nonce,
            // the contract refuses a request from its future, and a block's time lags
            created_at_ns: now_ns.saturating_sub(DATED_BACK_SECS * 1_000_000_000),
        },
    )
    .map_err(|refusal| anyhow!("{refusal}"))?;

    let proof = proof(&sign_half(Role::Agent, agent, &message), &sign_half(Role::Tee, tee, &message));
    let pair = PublicKeyPair { agent: agent.verifying_key().to_bytes(), tee: tee.verifying_key().to_bytes() };
    if !pair.verify(&message, &proof) {
        bail!("the proof does not verify against its own keys");
    }
    let args = String::from_utf8(message.execute_signed_args(&proof)).expect("the arguments are JSON");
    Ok(serde_json::json!({
        "contract": contract,
        "method": "w_execute_signed",
        "args": serde_json::from_str::<serde_json::Value>(&args)?,
        "gas": "300000000000000",
        "deposit": "0",
        "public_key": pair.to_string(),
        "valid_for_seconds": VALID_FOR_SECS,
        "network": network,
    }))
}

/// A word for a POSIX shell: single-quoted, with each `'` inside written as `'\''`.
fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// The near-cli command that sends a request made by [`request`].
fn send_command(made: &serde_json::Value) -> String {
    let field = |name: &str| made[name].as_str().unwrap_or_default();
    format!(
        "near contract call-function as-transaction {} w_execute_signed json-args {} prepaid-gas '300 Tgas' \
         attached-deposit '0 NEAR' sign-as <account> network-config {} sign-with-keychain send",
        shell_word(field("contract")),
        shell_word(&made["args"].to_string()),
        shell_word(field("network")),
    )
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let Some((command, rest)) = args.split_first() else {
        bail!("{USAGE}");
    };
    let flags = Flags::parse(rest)?;
    let (owner, wallet_id) = (flags.need("--owner")?, flags.need("--wallet-id")?);
    crate::wallet_keys::validate_wallet_id(wallet_id)?;

    let out = match command.as_str() {
        "agent-key-request" => {
            flags.only(&["--owner", "--wallet-id"])?;
            serde_json::json!({
            "message": agent_key_message(owner, wallet_id),
            "recipient": AGENT_KEY_RECIPIENT,
            "nonce_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, AGENT_KEY_NONCE),
            "sign_with": "the owner account's own key, as a NEP-413 message; put the signature in AGENT_KEY_SIGNATURE",
            })
        }
        "keys" => {
            flags.only(&["--owner", "--wallet-id", "--build"])?;
            let build: [u8; 32] = match flags.get("--build") {
                None => WALLET_CONTRACT_BUILD,
                Some(b58) => bs58::decode(b58)
                    .into_vec()
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| anyhow!("--build is a code hash: 32 bytes in base58"))?,
            };
            let (agent, tee) = (agent(owner, wallet_id)?, tee(wallet_id)?);
            let pair = PublicKeyPair { agent: agent.verifying_key().to_bytes(), tee: tee.verifying_key().to_bytes() };
            serde_json::json!({
                "agent_public_key": hex::encode(pair.agent),
                "tee_public_key": hex::encode(pair.tee),
                "public_key": pair.to_string(),
                "check": "`public_key` is what the wallet contract's `w_public_key` answers",
                // where a wallet contract of this pair is, when the setup made a new account
                // with no key (NEP-616); a sub-account or the owner's own account is named
                "deterministic_account": custody_core::deterministic::deterministic_account(&build, &pair),
                "build": bs58::encode(build).into_string(),
            })
        }
        "request" => {
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("the clock reads before 1970")?
                .as_nanos() as u64;
            let made = request(&flags, &agent(owner, wallet_id)?, &tee(wallet_id)?, now_ns)?;
            // The command goes to stderr, apart from the JSON, quoted for a shell.
            eprintln!("Send it from any account of yours:\n{}", send_command(&made));
            made
        }
        other => bail!("unknown wallet-contract command `{other}`\n{USAGE}"),
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `0s` address the tool prints is custody-core's for the published build.
    #[test]
    fn keys_name_the_deterministic_account_of_the_pair() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/deterministic.json"))
                .unwrap();
        assert_eq!(hex::encode(WALLET_CONTRACT_BUILD), vectors["code_hash_hex"].as_str().unwrap());
        for case in vectors["cases"].as_array().unwrap() {
            let bytes = hex::decode(case["pair"].as_str().unwrap()).unwrap();
            let pair = PublicKeyPair { agent: bytes[..32].try_into().unwrap(), tee: bytes[32..].try_into().unwrap() };
            assert_eq!(
                custody_core::deterministic::deterministic_account(&WALLET_CONTRACT_BUILD, &pair),
                case["account_id"].as_str().unwrap()
            );
        }
    }

    /// The signature is taken in hex or in base64, with space around it, and is the
    /// agent key custody-core derives; anything that is not 64 bytes is refused, so a
    /// truncated paste never becomes another key.
    #[test]
    fn the_agents_key_is_the_one_of_the_owners_signature_in_either_spelling() {
        use base64::Engine;
        let signature = [0x51u8; 64];
        let want = agent_key(&signature, "alice.near", "w-1").verifying_key();
        let b64 = base64::engine::general_purpose::STANDARD.encode(signature);
        for text in [hex::encode(signature), format!("  {b64}\n")] {
            assert_eq!(agent_from(&text, "alice.near", "w-1").unwrap().verifying_key(), want, "{text}");
        }
        assert_ne!(agent_from(&b64, "alice.near", "w-2").unwrap().verifying_key(), want, "another wallet");
        assert_ne!(agent_from(&b64, "bob.near", "w-1").unwrap().verifying_key(), want, "another owner");
        for bad in [hex::encode([0x51u8; 63]), hex::encode([0x51u8; 65]), "not a signature!".to_string(), String::new()] {
            assert!(agent_from(&bad, "alice.near", "w-1").is_err(), "{bad:?}");
        }
    }

    /// The enclave's key follows from the master and the wallet's id alone, and a
    /// master that is not one is refused.
    #[test]
    fn the_enclaves_key_is_the_one_of_the_master_and_the_wallet() {
        let master = [0x4du8; 32];
        let want = tee_key(&master, "w-1").verifying_key();
        assert_eq!(tee_from(&hex::encode(master), "w-1").unwrap().verifying_key(), want);
        assert_ne!(tee_from(&hex::encode(master), "w-2").unwrap().verifying_key(), want);
        for bad in ["", "zz", &hex::encode([0x4du8; 31])] {
            assert!(tee_from(bad, "w-1").is_err(), "{bad:?}");
        }
    }

    fn flags(pairs: &[&str]) -> Flags {
        Flags::parse(&pairs.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    const NOW_NS: u64 = 1_800_000_000_000_000_000;

    fn keys() -> (SigningKey, SigningKey) {
        (agent_key(&[0x51; 64], "alice.near", "w-1"), tee_key(&[0x4d; 32], "w-1"))
    }

    #[test]
    fn a_request_carries_both_halves_and_the_call_to_send() {
        let (agent, tee) = keys();
        let made = request(
            &flags(&[
                "--network", "mainnet", "--contract", "trader.alice.near", "--nonce", "9",
                "--transfer-to", "alice.near", "--amount", "1000",
            ]),
            &agent,
            &tee,
            NOW_NS,
        )
        .unwrap();

        assert_eq!(made["contract"], "trader.alice.near");
        assert_eq!(made["args"]["msg"]["signer_id"], "trader.alice.near");
        assert_eq!(made["args"]["msg"]["nonce"], 9);
        assert_eq!(made["args"]["msg"]["created_at"], "2027-01-15T07:59:00.000000000Z");
        assert_eq!(
            made["args"]["msg"]["request"]["external"][0],
            serde_json::json!({ "receiver_id": "alice.near", "actions": [{ "action": "transfer", "payload": { "amount": "1000" } }] })
        );
        assert_eq!(made["args"]["proof"].as_str().unwrap().len(), 256);
        let command = send_command(&made);
        assert!(command.contains("w_execute_signed") && command.contains("network-config 'mainnet'"));
    }

    #[test]
    fn each_move_is_built_and_a_missing_one_is_refused() {
        let (agent, tee) = keys();
        let base = ["--network", "testnet", "--contract", "trader.alice.testnet"];
        let moves: [&[&str]; 4] = [
            &["--transfer-to", "alice.testnet", "--amount", "1"],
            &["--call-to", "app.testnet", "--method", "do", "--args-base64", "e30=", "--gas", "30000000000000", "--deposit", "0"],
            &["--intents-transfer-to", "alice.testnet", "--token", "nep141:wrap.near", "--amount", "5"],
            &["--intents-withdraw-to", "alice.testnet", "--token", "wrap.near", "--amount", "5"],
        ];
        for mv in moves {
            let all: Vec<&str> = base.iter().chain(mv.iter()).copied().collect();
            assert!(request(&flags(&all), &agent, &tee, NOW_NS).is_ok(), "{mv:?}");
        }
        assert!(request(&flags(&base), &agent, &tee, NOW_NS).is_err());
        let to_itself: Vec<&str> =
            base.iter().chain(["--transfer-to", "trader.alice.testnet", "--amount", "1"].iter()).copied().collect();
        assert!(request(&flags(&to_itself), &agent, &tee, NOW_NS).is_err());
    }

    #[test]
    fn a_word_is_quoted_for_a_shell() {
        assert_eq!(shell_word("plain"), "'plain'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word("$(id) `id` \"x\""), "'$(id) `id` \"x\"'");
    }

    #[test]
    fn a_flag_of_another_move_a_repeated_or_an_unknown_one_is_refused() {
        let (agent, tee) = keys();
        let base = ["--network", "testnet", "--contract", "trader.alice.testnet"];
        let with = |extra: &[&str]| -> Vec<String> { base.iter().chain(extra.iter()).map(|s| s.to_string()).collect() };
        for extra in [
            // a transfer of NEAR with a token named: not a token transfer
            &["--transfer-to", "alice.testnet", "--amount", "1", "--token", "nep141:wrap.near"][..],
            &["--transfer-to", "alice.testnet", "--amount", "1", "--call-to", "app.testnet"],
            &["--transfer-to", "alice.testnet", "--amount", "1", "--amont", "2"],
        ] {
            let flags = Flags::parse(&with(extra)).unwrap();
            assert!(request(&flags, &agent, &tee, NOW_NS).is_err(), "{extra:?}");
        }
        assert!(Flags::parse(&with(&["--amount", "1", "--amount", "2"])).is_err());
    }

    #[test]
    fn flags_come_in_pairs() {
        assert!(Flags::parse(&["--owner".to_string()]).is_err());
        assert!(Flags::parse(&["owner".to_string(), "alice.near".to_string()]).is_err());
        assert!(flags(&["--amount", "+5"]).number::<u128>("--amount").is_err());
    }
}
