//! A WASI module whose only job is exercising the `outlayer:wallet` host
//! functions.
//!
//! Until this existed, nothing in `wasi-examples/` imported that world at all:
//! the interface was described in `worker/wit/deps/wallet.wit`, implemented in
//! `worker/src/outlayer_wallet/host_functions.rs`, unit-tested on the worker's
//! side — and reached by no guest anywhere. A break in the guest-facing half
//! would have surfaced first in somebody's agent, in production, as a wallet
//! call that returned nothing.
//!
//! ## Why this is a separate project and not an operation in `connector-probe`
//!
//! The worker gives a component the wallet host functions only if the component
//! IMPORTS them (`has_wallet_import` in `worker/src/executor/wasi_p2.rs`). On a
//! run that names no wallet every one of them answers `no_wallet`, so the
//! import is harmless to a module that never calls them; here every operation
//! does, and `connector-probe` keeps the wallet out so that its own answers
//! stay about the connector path and nothing else.
//!
//! ## What each operation is for
//!
//! | `operation` | Moves money | What it proves |
//! |---|---|---|
//! | `whoami` | no | `wallet::get_id` answers, and its answer matches the `WALLET_ID` the environment was given. Two sources for one fact, and only the host function is authoritative |
//! | `balance` | no | the derived NEAR address and what it holds — the two reads an agent makes before deciding to spend |
//! | `transfer` | **yes** | what a REFUSAL looks like from inside a guest: the machine code, whether retrying is pointless, and which request holds the wallet. The refusal is the interesting outcome, not the failure |
//! | `request_status` | no | the id out of a `wallet_busy` refusal is one a guest can actually poll — the other half of that contract, and the half nothing else checks |
//!
//! ## What it never does
//!
//! It reaches no network of its own: `manifest.json` declares `"network": []`,
//! and the wallet calls are HOST functions — the worker makes those requests,
//! not this module. So a module that can move money here cannot talk to the
//! internet, and that is checked rather than promised.

use serde::{Deserialize, Serialize};

/// The manifest, embedded in a wasm custom section so it is covered by the wasm
/// hash the contract records for this version.
///
/// This module is NOT a connector — no `connector_id`, so nothing here opts
/// into the curated allowlist enforcement. What the section does say is
/// `"network": []`: for an ordinary project an empty list is enforced, while a
/// missing key is not, and those are different claims. See
/// `wasi-examples/CONNECTOR_MANIFEST.md`.
///
/// Only on wasm: `link_section` takes a platform-specific name and the host
/// build (`cargo test`, for the parser below) rejects this one. The artefact is
/// always wasm32, and `build.sh` greps the built wasm for the section, which is
/// what actually guarantees it is there.
#[cfg(target_arch = "wasm32")]
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] =
    *include_bytes!("../manifest.json");

/// Wallet host bindings, generated from `wit/wallet.wit` — a copy of the
/// worker's own `worker/wit/deps/wallet.wit`.
///
/// A copy rather than a path reference because `wasi-examples/` is what an
/// author copies from: an example that reaches up into the worker's tree is an
/// example nobody can lift out. When the worker's WIT changes, this file is
/// updated in the same change, and `build.sh` diffs the two so a drift is
/// reported rather than discovered.
mod wallet_host {
    wit_bindgen::generate!({
        world: "wallet-host",
        path: "wit",
    });
}
use wallet_host::outlayer::wallet::api as wallet;

#[derive(Debug, Deserialize, Default)]
struct Input {
    /// Which operation, under the same universal field name every other module
    /// here uses.
    #[serde(default)]
    operation: String,
    /// `transfer` only: who receives.
    ///
    /// Taken from the caller, and that is safe in a way a caller-chosen HTTP
    /// host would not be. A wallet host function acts as the CALLER's own
    /// custody wallet under that wallet's own policy, so the worst a caller can
    /// name here is a destination for their own money — which they can already
    /// reach through `POST /wallet/v1/transfer` without this module.
    #[serde(default)]
    to: Option<String>,
    /// `transfer` only: yoctoNEAR, as a decimal string.
    #[serde(default)]
    amount: Option<String>,
    /// `request_status` only: the request id to read back. In the case this
    /// exists for, it is the `in_flight_request_id` out of a `wallet_busy`
    /// refusal.
    #[serde(default)]
    request_id: Option<String>,
}

/// A wallet host-function error, taken apart the way an agent has to take it
/// apart.
///
/// The format is `"<code>: <message>"` followed by the fields that change what
/// to do next. Reporting the PARSED pieces rather than the raw string is the
/// point: it is the difference between an error a human can read and one a
/// program can route on, and only the second is a contract.
#[derive(Debug, Serialize, Default)]
struct ParsedError {
    /// The machine code — `wallet_busy`, `policy_denied`, … `None` when the
    /// string carries no code at all, which is itself worth seeing: it means
    /// the answer did not come from us.
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    message: String,
    /// Whether retrying is pointless. Absent is NOT "false" — a missing flag
    /// means the answer did not say, and an agent that reads absence as
    /// "retryable" will hammer a permanent refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    terminal: Option<bool>,
    /// Present on `wallet_busy`: the request that holds the wallet, to poll
    /// through `get_request_status`. Without it a busy answer is a dead end.
    #[serde(skip_serializing_if = "Option::is_none")]
    in_flight_request_id: Option<String>,
    /// What the holder is DOING, set even when there is no id to poll yet.
    /// It is what decides whether waiting is worth it: a transfer clears in
    /// seconds, a cross-chain withdraw can run for minutes.
    ///
    /// Skipped when absent for the same reason as the fields above: an agent
    /// must be able to tell "the answer did not say" from a value.
    #[serde(skip_serializing_if = "Option::is_none")]
    in_flight_operation: Option<String>,
}

/// Split `"<code>: <message>[ key=value]..."` back into its parts.
///
/// Tolerant on purpose. The worker passes a non-JSON body through unchanged (a
/// gateway's HTML, say), and a transport failure never had a code to begin
/// with — so anything that does not look like `code: message` is reported as a
/// message with no code rather than mangled into one.
///
/// The producer is `guest_error` in
/// `worker/src/outlayer_wallet/host_functions.rs`. A change on either side that
/// is not made on the other shows up in the tests at the bottom of this file.
fn parse_guest_error(raw: &str) -> ParsedError {
    let mut out = ParsedError::default();
    let head = match raw.split_once(": ") {
        // A code is one token. A prefix with a space in it is prose that
        // happened to contain a colon.
        Some((code, rest)) if !code.is_empty() && !code.contains(' ') => {
            out.code = Some(code.to_string());
            rest
        }
        _ => raw,
    };

    // The trailing fields, read off the END so they are not mistaken for part
    // of the message, and removed from it as they are read.
    let mut message = head;
    // RIGHTMOST FIRST. Each field read is cut off the end of the message, so
    // the order here has to mirror the order the host appends them in — a key
    // sought before one that sits to its right is found in a message that still
    // has the other glued on.
    for key in ["in_flight_operation=", "in_flight_request_id=", "terminal="] {
        let Some(at) = message.rfind(&format!(" {key}")) else {
            continue;
        };
        let value: String = message[at + 1 + key.len()..]
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        // A trailing `key=` with nothing after it is not a value. Reading it as
        // one would hand an agent an empty request id to poll forever.
        if value.is_empty() {
            continue;
        }
        match key {
            "in_flight_operation=" => out.in_flight_operation = Some(value),
            "in_flight_request_id=" => out.in_flight_request_id = Some(value),
            _ => out.terminal = value.parse::<bool>().ok(),
        }
        message = &message[..at];
    }
    out.message = message.trim().to_string();
    out
}

#[derive(Debug, Serialize, Default)]
struct Output {
    /// Whether the ANSWER was well formed — not whether it was yes. A refusal
    /// an agent can route on is a working interface; see `transfer`.
    ok: bool,
    operation: String,
    /// Free-text, for a human reading a failed run.
    detail: String,
    // ---- whoami ----
    /// `wallet::get_id` — authoritative.
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_id: Option<String>,
    /// The `WALLET_ID` environment variable — what the environment was TOLD.
    /// Reported next to the host function's answer because the two can only
    /// disagree if something injected a value the worker did not.
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_id_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_id: Option<String>,
    // ---- balance ----
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<String>,
    // ---- transfer / request_status ----
    /// The successful half of the tuple, verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    /// The error half, verbatim — kept beside the parse so a run shows both
    /// what arrived and what could be made of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_parsed: Option<ParsedError>,
}

fn main() {
    let raw = read_stdin();
    let input: Input = if raw.trim().is_empty() {
        Input::default()
    } else {
        match serde_json::from_str(&raw) {
            Ok(i) => i,
            Err(e) => {
                emit(&Output {
                    ok: false,
                    detail: format!("input is not JSON: {e}"),
                    ..Default::default()
                });
                return;
            }
        }
    };
    emit(&run(&input));
}

fn read_stdin() -> String {
    use std::io::Read;
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

fn emit(out: &Output) {
    use std::io::Write;
    let json = serde_json::to_string(out).unwrap_or_else(|e| {
        // Serialising our own struct cannot fail in practice, but printing
        // nothing at all would look to the caller like a module that produced
        // no output — a different fault from the one that happened. The error
        // goes through the same serialiser so a quote inside it cannot break
        // the JSON it is being reported in.
        serde_json::json!({
            "ok": false,
            "detail": format!("failed to serialise output: {e}"),
        })
        .to_string()
    });
    // Written and FLUSHED explicitly, like the SDK's `env::output` and like
    // `vault-checker` — the other module here that talks to stdout without the
    // SDK. Relying on the runtime to drain a buffered stdout as the instance
    // goes away is the kind of assumption that holds until it does not, and a
    // truncated answer reads to the caller as a module that returned nothing.
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(json.as_bytes());
    let _ = stdout.flush();
}

fn run(input: &Input) -> Output {
    let op = input.operation.trim();
    match op {
        "whoami" => whoami(op),
        "balance" => balance(op),
        "transfer" => transfer(op, input.to.as_deref(), input.amount.as_deref()),
        "request_status" => request_status(op, input.request_id.as_deref()),
        "" => Output {
            ok: false,
            operation: op.into(),
            detail: "no `operation` in the input".into(),
            ..Default::default()
        },
        other => Output {
            ok: false,
            operation: other.into(),
            detail: format!(
                "unknown operation `{other}` — this module implements whoami, balance, \
                 transfer and request_status"
            ),
            ..Default::default()
        },
    }
}

/// Do the two sources of the wallet's identity agree, and what to tell a human.
///
/// Split out of [`whoami`] so the rule can be tested: everything around it
/// needs the host functions, and a rule that can only be exercised on a live
/// stack is a rule nobody checks.
///
/// **Absent is a failure here, not a neutral result.** `WALLET_ID` is injected
/// for every run that has a wallet (`worker/src/main.rs`, beside
/// `wallet_config`), and this function is reached only once `get_id` answered
/// — on a run with no wallet it answers `no_wallet` instead. So a missing
/// variable is a system value that did not arrive on a run that must have it:
/// exactly the silent class this probe exists to surface, and reporting it as
/// success would bury it.
fn identity_verdict(id: &str, env_id: Option<&str>) -> (bool, String) {
    match env_id {
        Some(e) if e == id => (true, format!("wallet {id}; the environment agrees")),
        // The disagreement worth reporting loudly: the environment is what a
        // guest that skipped the host function would have read.
        Some(e) => (
            false,
            format!(
                "wallet {id}, but WALLET_ID in the environment says '{e}' — the host function \
                 is the authoritative one, and something injected the other"
            ),
        ),
        None => (
            false,
            format!(
                "wallet {id}, but WALLET_ID never arrived in the environment — the worker sets \
                 it for every run that has a wallet, and this run has one"
            ),
        ),
    }
}

/// Which wallet this run is authorised as, from both sources that claim to know.
///
/// A run with no wallet cannot reach this module at all — the worker refuses to
/// instantiate it — so `get_id` returning nothing here is not "no wallet
/// configured", it is the host function failing to answer.
fn whoami(op: &str) -> Output {
    let (id, err) = wallet::get_id();
    if !err.is_empty() {
        return failed(op, "wallet::get_id", err);
    }
    if id.is_empty() {
        return Output {
            ok: false,
            operation: op.into(),
            detail: "wallet::get_id returned neither an id nor an error — an empty answer is \
                     not a wallet, and a guest that reads it as one acts on nothing"
                .into(),
            ..Default::default()
        };
    }

    let env_id = std::env::var("WALLET_ID").ok();
    let (agrees, detail) = identity_verdict(&id, env_id.as_deref());

    Output {
        ok: agrees,
        operation: op.into(),
        detail,
        wallet_id: Some(id),
        wallet_id_env: env_id,
        sender_id: std::env::var("NEAR_SENDER_ID").ok(),
        ..Default::default()
    }
}

/// The two reads an agent makes before deciding to spend.
///
/// Both are reported even when one fails: an address that does not derive and a
/// balance that does not read are different faults, and collapsing them into
/// one refusal hides which happened.
fn balance(op: &str) -> Output {
    let (addr_json, addr_err) = wallet::get_address("near");
    let (bal_json, bal_err) = wallet::get_balance("near", "");

    let address = json_field(&addr_json, "address");
    let balance = json_field(&bal_json, "balance");

    let mut detail = String::new();
    match &address {
        Some(a) => detail.push_str(&format!("near address {a}")),
        None => detail.push_str(&format!("address unavailable: {addr_err}")),
    }
    match &balance {
        Some(b) => detail.push_str(&format!(", balance {b} yocto")),
        None => detail.push_str(&format!(", balance unavailable: {bal_err}")),
    }

    let error = (!addr_err.is_empty() || !bal_err.is_empty())
        .then(|| format!("{addr_err}{bal_err}").trim().to_string());
    Output {
        ok: address.is_some() && balance.is_some(),
        operation: op.into(),
        detail,
        address,
        balance,
        error_parsed: error.as_deref().map(parse_guest_error),
        error,
        ..Default::default()
    }
}

/// One `wallet::transfer`, reported as an agent must read it.
///
/// This is the only operation here that moves money, and it moves the caller's
/// own — see `Input::to`.
///
/// What it exists for is the ERROR path. A refusal arrives as a single string,
/// and everything an agent has to decide next lives inside it: which code,
/// whether to retry, and — when another operation holds the wallet — which
/// request to poll until it frees. So a refusal is not a failure of this
/// operation: `ok` follows whether the answer was well formed.
fn transfer(op: &str, to: Option<&str>, amount: Option<&str>) -> Output {
    let (Some(to), Some(amount)) = (to, amount) else {
        return Output {
            ok: false,
            operation: op.into(),
            detail: "transfer needs `to` and `amount` (yoctoNEAR, decimal string)".into(),
            ..Default::default()
        };
    };

    let (result, error) = wallet::transfer("near", to, amount);
    if error.is_empty() {
        // Both halves empty. Nothing in the tuple says what happened, and
        // treating it as success would report a transfer that may or may not
        // exist.
        if result.is_empty() {
            return Output {
                ok: false,
                operation: op.into(),
                detail: "wallet::transfer returned an empty result AND an empty error — the \
                         call said nothing, and silence is not a receipt"
                    .into(),
                ..Default::default()
            };
        }
        return Output {
            ok: true,
            operation: op.into(),
            detail: format!("transferred {amount} yocto to {to}"),
            result: Some(result),
            ..Default::default()
        };
    }

    let parsed = parse_guest_error(&error);
    let detail = match (&parsed.code, &parsed.in_flight_request_id) {
        (Some(code), Some(id)) if code == "wallet_busy" => format!(
            "refused as `{code}` — the wallet is held by request {id}. Poll it with \
             {{\"operation\":\"request_status\",\"request_id\":\"{id}\"}} and retry when it \
             finishes"
        ),
        (Some(code), _) if parsed.terminal == Some(true) => {
            format!("refused as `{code}`, terminally — retrying changes nothing")
        }
        (Some(code), _) => format!("refused as `{code}`"),
        (None, _) => format!(
            "refused with no machine code: {:?}. An agent can log this and nothing else",
            parsed.message
        ),
    };

    Output {
        // A refusal nobody can route on is the only failing case here.
        ok: parsed.code.is_some(),
        operation: op.into(),
        detail,
        error: Some(error),
        error_parsed: Some(parsed),
        ..Default::default()
    }
}

/// Read a request back — the other half of the `wallet_busy` contract.
///
/// A busy refusal names the request holding the wallet so the caller can wait
/// for it. That is only true if the id is one a guest can actually use, and
/// this is what makes the claim checkable rather than decorative.
fn request_status(op: &str, request_id: Option<&str>) -> Output {
    let Some(request_id) = request_id.filter(|s| !s.trim().is_empty()) else {
        return Output {
            ok: false,
            operation: op.into(),
            detail: "request_status needs `request_id` — in the case this exists for, the \
                     `in_flight_request_id` out of a wallet_busy refusal"
                .into(),
            ..Default::default()
        };
    };

    let (result, error) = wallet::get_request_status(request_id);
    if !error.is_empty() {
        return failed(op, "wallet::get_request_status", error);
    }
    let status = json_field(&result, "status");
    Output {
        // No status is not an answer: the caller polls until a request is
        // terminal, and a reply it cannot read leaves it polling forever.
        ok: status.is_some(),
        operation: op.into(),
        detail: match &status {
            Some(s) => format!("request {request_id} is `{s}`"),
            None => format!("request {request_id} came back without a status: {result}"),
        },
        result: Some(result),
        ..Default::default()
    }
}

/// A wallet call that failed before there was anything else to report.
fn failed(op: &str, what: &str, error: String) -> Output {
    let parsed = parse_guest_error(&error);
    Output {
        ok: false,
        operation: op.into(),
        detail: format!("{what} failed: {}", parsed.message),
        error: Some(error),
        error_parsed: Some(parsed),
        ..Default::default()
    }
}

/// One string field out of a host function's JSON, without depending on the
/// shape of the rest of it.
fn json_field(raw: &str, key: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()?
        .get(key)?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod guest_error_parse_tests {
    use super::{identity_verdict, parse_guest_error};

    /// The two sources of the wallet's identity, and what each disagreement
    /// means. A MISSING `WALLET_ID` is a failure, not a shrug — see
    /// [`identity_verdict`].
    #[test]
    fn the_identity_holds_only_when_both_sources_say_the_same_thing() {
        let (ok, detail) = identity_verdict("ed25519:abc", Some("ed25519:abc"));
        assert!(ok, "{detail}");

        let (ok, _) = identity_verdict("ed25519:abc", Some("ed25519:zzz"));
        assert!(!ok, "a forged environment value must not read as agreement");

        let (ok, detail) = identity_verdict("ed25519:abc", None);
        assert!(
            !ok,
            "an absent WALLET_ID on a run that must have one is the silent failure this \
             probe exists to catch, not a neutral result"
        );
        assert!(detail.contains("never arrived"), "{detail}");
    }

    /// The shape the worker actually produces, taken apart again.
    #[test]
    fn a_busy_wallet_yields_a_code_and_something_to_poll() {
        let p = parse_guest_error(
            "wallet_busy: another operation is using this wallet; it runs one at a time \
             so spending limits are counted correctly in_flight_request_id=9f1c-42",
        );
        assert_eq!(p.code.as_deref(), Some("wallet_busy"));
        assert_eq!(p.in_flight_request_id.as_deref(), Some("9f1c-42"));
        // The id is lifted OUT of the message, not left duplicated inside it.
        assert!(!p.message.contains("in_flight_request_id"), "{}", p.message);
        assert!(p.message.starts_with("another operation"), "{}", p.message);
    }

    #[test]
    fn both_trailing_fields_are_read_and_neither_lands_in_the_message() {
        let p = parse_guest_error("policy_denied: daily limit exceeded terminal=true");
        assert_eq!(p.code.as_deref(), Some("policy_denied"));
        assert_eq!(p.terminal, Some(true));
        assert_eq!(p.message, "daily limit exceeded");

        let p =
            parse_guest_error("agent_connect_denied: no grant terminal=false in_flight_request_id=abc");
        assert_eq!(p.terminal, Some(false));
        assert_eq!(p.in_flight_request_id.as_deref(), Some("abc"));
        assert_eq!(p.message, "no grant");
    }

    /// Absent is not false. An agent that reads a missing `terminal` as
    /// "retryable" hammers a permanent refusal; one that reads it as terminal
    /// gives up on a transient. Neither is a guess this parser gets to make.
    #[test]
    fn a_missing_flag_stays_missing() {
        let p = parse_guest_error("wallet_frozen: this wallet is frozen");
        assert_eq!(p.terminal, None);
        assert_eq!(p.in_flight_request_id, None);
    }

    /// What arrives when the answer did not come from us: a gateway's plain
    /// text, or a transport failure that never had a code. Reported as a
    /// message with NO code, which is what makes `ok: false` correct for it —
    /// there is nothing an agent can route on.
    #[test]
    fn prose_is_not_mistaken_for_a_code() {
        let p = parse_guest_error("502 Bad Gateway");
        assert_eq!(p.code, None);
        assert_eq!(p.message, "502 Bad Gateway");

        let p = parse_guest_error("Wallet request failed: error sending request for url");
        assert_eq!(p.code, None, "the prefix has a space in it, so it is not a code");
        assert_eq!(p.message, "Wallet request failed: error sending request for url");
    }

    /// A message that legitimately contains `": "` keeps all of it: the code is
    /// split off at the FIRST separator, exactly where the producer joined it.
    #[test]
    fn only_the_first_separator_splits() {
        let p = parse_guest_error("policy_denied: address not allowed: bob.near");
        assert_eq!(p.code.as_deref(), Some("policy_denied"));
        assert_eq!(p.message, "address not allowed: bob.near");
    }

    #[test]
    fn an_empty_value_is_not_a_value() {
        let p = parse_guest_error("wallet_busy: held in_flight_request_id=");
        assert_eq!(p.in_flight_request_id, None);
    }

    /// A busy answer with no id yet still says what to wait for.
    ///
    /// This is the case the field exists for: the wallet was taken a moment ago
    /// and the request row is not written, so the coordinator withholds the id
    /// rather than handing out one that answers 404. Without the operation the
    /// agent would know only "busy" and could not tell a two-second transfer
    /// from a cross-chain withdraw running for minutes.
    #[test]
    fn a_busy_answer_without_an_id_still_names_the_operation() {
        let parsed = parse_guest_error(
            "wallet_busy: a transfer is using this wallet and has not written its request yet \
             in_flight_operation=transfer",
        );
        assert_eq!(parsed.code.as_deref(), Some("wallet_busy"));
        assert_eq!(parsed.in_flight_operation.as_deref(), Some("transfer"));
        assert_eq!(parsed.in_flight_request_id, None);
        assert!(
            !parsed.message.contains("in_flight_operation"),
            "the field must be taken OUT of the message, not left glued to it: {}",
            parsed.message
        );
    }

    /// Both fields together, in the order the host appends them.
    ///
    /// The order is load-bearing: these are read off the END and the message is
    /// truncated at each one taken, so an operation appended before the id
    /// would be orphaned in the message once the id was stripped.
    #[test]
    fn an_id_and_an_operation_are_both_lifted_out() {
        let parsed = parse_guest_error(
            "wallet_busy: a swap is using this wallet in_flight_request_id=req-42 \
             in_flight_operation=swap",
        );
        assert_eq!(parsed.in_flight_request_id.as_deref(), Some("req-42"));
        assert_eq!(parsed.in_flight_operation.as_deref(), Some("swap"));
        assert_eq!(parsed.message, "wallet_busy: a swap is using this wallet".replace("wallet_busy: ", ""));
    }

}
