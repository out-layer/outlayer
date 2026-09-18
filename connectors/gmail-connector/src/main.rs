//! Gmail connector for OutLayer — an agent sends mail from the owner's own
//! address, under the owner's policy, without ever holding the credential.
//!
//! The owner connects an account once, at
//! <https://app.outlayer.ai/connect/gmail>: a Google consent screen, and one
//! stored value — a refresh token for their account, granted the single scope
//! `gmail.send`. This connector's own OAuth client completes it at run time and
//! never enters anyone's stored row. An owner who brings their own OAuth app
//! stores three values instead, and theirs wins.
//! Everything after that happens inside the enclave: the refresh token is
//! exchanged for an access token, the access token sends through Gmail's REST
//! API, and neither ever appears in an answer.
//!
//! | `operation` | class | what it does |
//! |---|---|---|
//! | `status` | read | whether the credential works, the policy's caps, today's send count. On chain the policy comes back only sealed to the caller's `reply_pubkey` |
//! | `send` | write | a message, policy-checked first |
//!
//! It only sends. `gmail.send` authorises sending and nothing else — not reading
//! the mailbox, not even reading back which address the credential belongs to —
//! so this connector cannot see a single message the owner has, and the agent
//! gets nothing out of the mailbox, by construction. A message goes without a
//! `From` header and Gmail fills in the connected account.
//!
//! There are no sockets in the enclave, which is why this speaks Gmail's HTTPS
//! API rather than SMTP. Two hosts, both in the manifest:
//! `oauth2.googleapis.com` for the token and `gmail.googleapis.com` for mail.

mod gmail;
mod mime;
mod oauth;
mod policy;
mod seal;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use outlayer::env;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The manifest, embedded so the on-chain hash covers it: the connector id, the
/// two hosts this module may reach, and the daily caps it declares about itself.
#[cfg(target_family = "wasm")]
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] =
    *include_bytes!("../manifest.json");

#[derive(Serialize)]
struct Envelope {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<Value>,
    logs: Vec<Value>,
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct Input {
    operation: String,
    to: Option<Value>,
    cc: Option<Value>,
    subject: Option<String>,
    body: Option<String>,
    #[serde(default)]
    attachments: Vec<mime::Attachment>,
    /// `status` only: a secp256k1 public key in hex (33 bytes compressed, as
    /// `eciesjs` gives it) to seal the policy to. Required for the policy to be
    /// shown at all when the run's output lands on chain.
    reply_pubkey: Option<String>,
}

/// Everything this connector sells. A name not here is refused with the list.
const OPERATIONS: &[&str] = &["status", "send"];

fn main() {
    // Storage is imported by being called: the token cache and the day's count
    // need a project context.
    let _ = ::outlayer::storage::has("_init");

    let raw = env::input();
    let envelope = match serde_json::from_slice::<Input>(&raw) {
        Err(e) => Envelope {
            success: false,
            operation: String::new(),
            error: Some(format!("input is not the expected JSON: {e}")),
            output: None,
            logs: Vec::new(),
        },
        Ok(input) => {
            let op = input.operation.trim().to_string();
            match run(&op, &input) {
                Ok(output) => Envelope { success: true, operation: op, error: None, output: Some(output), logs: Vec::new() },
                Err(e) => Envelope { success: false, operation: op, error: Some(e), output: None, logs: Vec::new() },
            }
        }
    };
    let _ = env::output_json(&envelope);
}

fn run(op: &str, input: &Input) -> Result<Value, String> {
    match op {
        "status" => status(input),
        "send" => send(input),
        "" => Err(format!("no `operation` in the input. This connector sells: {}", OPERATIONS.join(", "))),
        other => Err(format!("unknown operation `{other}`. This connector sells: {}", OPERATIONS.join(", "))),
    }
}

fn token() -> Result<String, String> {
    let credential = oauth::Credential::from_env()?;
    oauth::access_token(&credential, policy::now_secs())
}

/// A recipient field: an array of bare addresses, or one bare address as a
/// string. A string is never split: a comma inside it is a malformed address,
/// not a list, so there is exactly one way to name several recipients.
fn address_list(value: Option<&Value>, field: &str) -> Result<Vec<String>, String> {
    let entries: Vec<String> = match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(one)) => vec![one.clone()],
        Some(Value::Array(many)) => many
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("`{field}` must hold addresses as strings"))
            })
            .collect::<Result<_, _>>()?,
        Some(other) => {
            return Err(format!("`{field}` must be an address or an array of addresses, not {other}"))
        }
    };
    policy::mailboxes(&entries)
}

/// Is the credential alive, and what may the agent do with it? Getting an access
/// token is the proof: it is the one thing a send-only credential can show.
fn status(input: &Input) -> Result<Value, String> {
    // A key that is not one is refused before Google is asked for anything: the
    // refusal is the caller's to fix, and it should not cost a token fetch.
    if let Some(key) = input.reply_pubkey.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        seal::parse_pubkey(key)?;
    }
    token()?;
    let day = policy::day_key(policy::now_ms());
    let sent = policy::sent_today(&day).unwrap_or(0);
    let (policy, sealed) = policy_view(policy::load(), input.reply_pubkey.as_deref(), on_chain())?;
    let mut answer = json!({
        "credential": "ok",
        "scope": "gmail.send: this connector sends as the connected account and cannot read its mailbox",
        "policy": policy,
        "sent_today": sent,
        "next": "`send` with `to`, `subject` and `body`",
    });
    if let Some(sealed) = sealed {
        answer["policy_sealed"] = Value::String(sealed);
    }
    Ok(answer)
}

/// Where this run's output goes. The worker names an HTTPS run in so many
/// words; anything else is treated as public — the direction that leaks nothing
/// when the variable is missing.
fn on_chain() -> bool {
    std::env::var("OUTLAYER_EXECUTION_TYPE").map(|v| v != "HTTPS").unwrap_or(true)
}

/// The policy as `status` reports it, and — when the caller gave a key — the
/// same thing sealed to that key as base64.
///
/// Three cases, decided by two facts. With a `reply_pubkey`, the full policy is
/// sealed and the open part says only whether one exists. Without one, over
/// HTTPS the full policy goes in the clear, as the transport already is. Without
/// one on chain the fields are withheld: the output of an on-chain run sits in
/// the transaction for ever, and the policy names the people the owner's agent
/// may write to.
fn policy_view(loaded: policy::Loaded, reply_pubkey: Option<&str>, on_chain: bool) -> Result<(Value, Option<String>), String> {
    let full = match loaded {
        policy::Loaded::Some(p) => json!({
            "present": true,
            "recipient_domains": p.recipient_domains,
            "recipients": p.recipients,
            "max_per_day": p.max_per_day,
            "max_recipients": p.max_recipients,
            "max_attachment_kb": p.max_attachment_kb,
            "subject_prefix": p.subject_prefix,
        }),
        policy::Loaded::None => json!({
            "present": false,
            "effect": "nothing can be sent until the owner stores a policy",
        }),
        policy::Loaded::Unreadable(e) => json!({"present": true, "readable": false, "error": e}),
    };
    let present = full["present"].as_bool().unwrap_or(false);
    match reply_pubkey.map(str::trim).filter(|k| !k.is_empty()) {
        Some(key) => {
            let key = seal::parse_pubkey(key)?;
            let blob = seal::seal(&key, full.to_string().as_bytes())?;
            Ok((json!({"present": present, "sealed": true}), Some(BASE64.encode(blob))))
        }
        None if on_chain => Ok((
            json!({
                "present": present,
                "sealed": false,
                "note": "on chain the policy is returned only sealed: pass `reply_pubkey`, a secp256k1 \
                         public key in hex (33 bytes compressed), and read it back from `policy_sealed`",
            }),
            None,
        )),
        None => Ok((full, None)),
    }
}

fn send(input: &Input) -> Result<Value, String> {
    let rules = policy::require()?;
    let to = address_list(input.to.as_ref(), "to")?;
    let cc = address_list(input.cc.as_ref(), "cc")?;
    let subject = rules.apply_prefix(input.subject.as_deref().unwrap_or_default());
    let body = input.body.clone().unwrap_or_default();

    // Every recipient, and the attachments, before anything is built or sent.
    let mut recipients = to.clone();
    recipients.extend(cc.iter().cloned());
    rules.check_recipients(&recipients)?;
    let sizes: Vec<usize> = input
        .attachments
        .iter()
        .map(|a| mime::decode_base64(&a.data).map(|b| b.len()))
        .collect::<Result<_, _>>()
        .map_err(|e| format!("an attachment is {e}"))?;
    rules.check_attachments(&sizes)?;

    // The owner's own cap, if they set one — their guard against a runaway
    // agent on their mailbox, counted per calling wallet. It is not the
    // platform's: the manifest's `send` limit is enforced by the coordinator for
    // every wallet, and Google caps the account itself. The place in today's
    // budget is taken before anything leaves, atomically, so two calls at once
    // cannot both see room for the last message. Any return from here without
    // `keep` gives it back.
    let day = policy::day_key(policy::now_ms());
    let reservation = match rules.max_per_day {
        Some(cap) => Some(policy::reserve(&day, cap)?),
        None => None,
    };

    let token = token()?;
    let raw = mime::build(&mime::Outgoing {
        from: None,
        to: &to,
        cc: &cc,
        subject: &subject,
        body: &body,
        attachments: &input.attachments,
    })?;
    let result = gmail::send(&token, &raw)?;
    let sent_today = reservation.map(|(reservation, used)| {
        reservation.keep();
        used
    });

    Ok(json!({
        "message_id": result.get("id"),
        "thread_id": result.get("threadId"),
        "to": to,
        "cc": cc,
        "subject": subject,
        "attachments": input.attachments.len(),
        "sent_today": sent_today,
        "remaining_today": rules.max_per_day.zip(sent_today).map(|(cap, used)| cap.saturating_sub(used)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operations_this_code_runs_are_the_ones_it_advertises() {
        for bad in ["", "list", "read", "read_attachment", "delete"] {
            let err = run(bad, &Input::default()).unwrap_err();
            assert!(err.contains("This connector sells: status, send"), "{bad} → {err}");
        }
    }

    fn loaded(json: &str) -> policy::Loaded {
        match serde_json::from_str::<policy::Policy>(json) {
            Ok(p) => policy::Loaded::Some(p),
            Err(e) => policy::Loaded::Unreadable(e.to_string()),
        }
    }

    /// The policy names people. Over HTTPS it may travel in the clear; on chain
    /// it leaves only sealed, and without a key it does not leave at all.
    #[test]
    fn the_policy_reaches_the_chain_only_sealed() {
        let rules = r#"{"recipient_domains":["example.com"],"max_per_day":20}"#;

        let (open, sealed) = policy_view(loaded(rules), None, false).unwrap();
        assert_eq!(open["recipient_domains"], json!(["example.com"]), "HTTPS, no key: in the clear");
        assert!(sealed.is_none());

        let (open, sealed) = policy_view(loaded(rules), None, true).unwrap();
        assert_eq!(open, json!({"present": true, "sealed": false, "note": open["note"]}), "on chain, no key: fields withheld — {open}");
        assert!(open["note"].as_str().unwrap().contains("reply_pubkey"));
        assert!(sealed.is_none());

        let (sk, pk) = ecies::utils::generate_keypair();
        let secret = sk.serialize();
        let hex: String = pk.serialize_compressed().iter().map(|b| format!("{b:02x}")).collect();
        for on_chain in [true, false] {
            let (open, sealed) = policy_view(loaded(rules), Some(&hex), on_chain).unwrap();
            assert_eq!(open, json!({"present": true, "sealed": true}), "with a key nothing else is open");
            let blob = BASE64.decode(sealed.expect("a sealed policy")).unwrap();
            let inside: Value = serde_json::from_slice(&seal::open(&secret, &blob).unwrap()).unwrap();
            assert_eq!(inside["recipient_domains"], json!(["example.com"]));
            assert_eq!(inside["max_per_day"], json!(20));
        }

        // A broken policy's error text is withheld on chain and sealed with a
        // key, like the rest: a parse error quotes the field it choked on.
        let (open, _) = policy_view(loaded(r#"{"surprise":1}"#), None, true).unwrap();
        assert!(open.get("error").is_none(), "{open}");
        let (open, sealed) = policy_view(loaded(r#"{"surprise":1}"#), Some(&hex), true).unwrap();
        assert!(open.get("error").is_none());
        let inside: Value = serde_json::from_slice(&seal::open(&secret, &BASE64.decode(sealed.unwrap()).unwrap()).unwrap()).unwrap();
        assert!(inside["error"].as_str().unwrap().contains("surprise"));

        // A key that is not one is refused before anything is sealed.
        let err = policy_view(loaded(rules), Some("nope"), true).unwrap_err();
        assert!(err.contains("secp256k1 public key"), "{err}");
        // An empty key is no key.
        let (open, _) = policy_view(loaded(rules), Some("  "), false).unwrap();
        assert_eq!(open["present"], json!(true));
        assert!(open.get("sealed").is_none());
    }

    #[test]
    fn an_address_field_takes_one_address_or_an_array_of_them() {
        assert_eq!(address_list(Some(&json!("A@b.co")), "to").unwrap(), vec!["a@b.co"]);
        assert_eq!(address_list(Some(&json!(["a@b.co", " d@e.co "])), "to").unwrap(), vec!["a@b.co", "d@e.co"]);
        assert!(address_list(None, "cc").unwrap().is_empty());
        // A string is one address. A comma makes it a malformed one, never a list.
        assert!(address_list(Some(&json!("a@b.co, d@e.co")), "to").unwrap_err().contains("not a bare email address"));
        assert!(address_list(Some(&json!([1])), "to").unwrap_err().contains("as strings"));
        assert!(address_list(Some(&json!(7)), "to").unwrap_err().contains("array of addresses"));
    }
}
