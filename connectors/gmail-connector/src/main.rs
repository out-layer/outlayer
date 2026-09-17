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
//! | `status` | read | whether the credential works, the policy's caps, today's send count |
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
        "status" => status(),
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
fn status() -> Result<Value, String> {
    token()?;
    let day = policy::day_key(policy::now_ms());
    let sent = policy::sent_today(&day).unwrap_or(0);
    let policy = match policy::load() {
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
    Ok(json!({
        "credential": "ok",
        "scope": "gmail.send: this connector sends as the connected account and cannot read its mailbox",
        "policy": policy,
        "sent_today": sent,
        "next": "`send` with `to`, `subject` and `body`",
    }))
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
