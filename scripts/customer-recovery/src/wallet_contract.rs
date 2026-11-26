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

const USAGE: &str = "\
Usage:
  customer-recovery wallet-contract agent-key-request --owner <account> --wallet-id <id>
      What the owner's NEAR key signs (NEP-413) for the agent's key.

  customer-recovery wallet-contract keys --owner <account> --wallet-id <id>
      The pair of public keys of the wallet contract.

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

impl Flags {
    fn parse(args: &[String]) -> Result<Self> {
        let mut flags = Vec::new();
        for pair in args.chunks(2) {
            match pair {
                [name, value] if name.starts_with("--") => flags.push((name.clone(), value.clone())),
                _ => bail!("expected `--flag value` pairs\n{USAGE}"),
            }
        }
        Ok(Self(flags))
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
    let master = crate::wallet_keys::parse_master(&master)?;
    Ok(tee_key(&master, wallet_id))
}

fn agent(owner: &str, wallet_id: &str) -> Result<SigningKey> {
    let text = std::env::var("AGENT_KEY_SIGNATURE").context(
        "AGENT_KEY_SIGNATURE is not set: the owner's signature over `wallet-contract agent-key-request`",
    )?;
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
            created_at_ns: now_ns.saturating_sub(60_000_000_000),
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
        "valid_for_seconds": 3540,
        "send_with": format!(
            "near contract call-function as-transaction {contract} w_execute_signed json-args '{args}' \
             prepaid-gas '300 Tgas' attached-deposit '0 NEAR' sign-as <any account of yours> \
             network-config {network} sign-with-keychain send"
        ),
    }))
}

pub(crate) fn run(args: &[String]) -> Result<()> {
    let Some((command, rest)) = args.split_first() else {
        bail!("{USAGE}");
    };
    let flags = Flags::parse(rest)?;
    let (owner, wallet_id) = (flags.need("--owner")?, flags.need("--wallet-id")?);
    crate::wallet_keys::validate_wallet_id(wallet_id)?;

    let out = match command.as_str() {
        "agent-key-request" => serde_json::json!({
            "message": agent_key_message(owner, wallet_id),
            "recipient": AGENT_KEY_RECIPIENT,
            "nonce_base64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, AGENT_KEY_NONCE),
            "sign_with": "the owner account's own key, as a NEP-413 message; put the signature in AGENT_KEY_SIGNATURE",
        }),
        "keys" => {
            let (agent, tee) = (agent(owner, wallet_id)?, tee(wallet_id)?);
            let pair = PublicKeyPair { agent: agent.verifying_key().to_bytes(), tee: tee.verifying_key().to_bytes() };
            serde_json::json!({
                "agent_public_key": hex::encode(pair.agent),
                "tee_public_key": hex::encode(pair.tee),
                "public_key": pair.to_string(),
                "check": "`public_key` is what the wallet contract's `w_public_key` answers",
            })
        }
        "request" => {
            let now_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("the clock reads before 1970")?
                .as_nanos() as u64;
            request(&flags, &agent(owner, wallet_id)?, &tee(wallet_id)?, now_ns)?
        }
        other => bail!("unknown wallet-contract command `{other}`\n{USAGE}"),
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(made["send_with"].as_str().unwrap().contains("w_execute_signed"));
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
    fn flags_come_in_pairs() {
        assert!(Flags::parse(&["--owner".to_string()]).is_err());
        assert!(Flags::parse(&["owner".to_string(), "alice.near".to_string()]).is_err());
        assert!(flags(&["--amount", "+5"]).number::<u128>("--amount").is_err());
    }
}
