//! Who may run a project: the `callers` member of the manifest.
//!
//! A run reaches OutLayer through one of four doors, told apart from facts the
//! job already carries and never from anything the guest, the input or the
//! manifest says about the caller:
//!
//! | door | when | the caller |
//! |---|---|---|
//! | `https` | the job is an HTTPS call | the payment key's owner |
//! | `meta_tx` | on chain, the call reached the contract through a NEP-366 `Delegate` action another account relayed | the account that signed the delegate action |
//! | `direct` | on chain, the account that called OutLayer signed the transaction | that account |
//! | `contract` | on chain, anything else: a contract called OutLayer on the signer's behalf | the contract |
//!
//! ```jsonc
//! "callers": {
//!   "direct":   "allow" | "deny",                    // absent: allow
//!   "contract": "allow" | "deny" | {"only": [...]}, // absent: allow
//!   "https":    "allow" | "deny",                    // absent: allow
//!   "meta_tx":  "allow" | "deny"                     // absent: deny
//! }
//! ```
//!
//! **`only` names every account that may call OutLayer for this project.**
//! A run is admitted exactly when it came on chain and the account that
//! called OutLayer is on the list, whatever the door: an HTTPS call names no
//! such account, and a direct call or a meta-transaction names the user, who
//! is not a contract the author listed. A block that pairs `only` with an
//! explicit `"allow"` on another door therefore does not parse — that
//! `"allow"` could never apply.
//!
//! **No block, no rule.** A manifest without `callers` admits every door,
//! meta-transactions included. A block admits meta-transactions only when it
//! says so.
//!
//! The rule is the artefact's: bound to the version by the wasm hash, judged
//! by the worker before any keystore round trip, key derivation or execution.
//! The owner of the project gets no exception.

use serde::Deserialize;

/// Most accounts one `only` list may name.
pub const MAX_CONTRACT_ALLOWLIST: usize = 32;

/// A door that is open or shut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Door {
    Allow,
    Deny,
}

/// The `contract` door: open, shut, or open to the named accounts only.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractDoor {
    Allow,
    Deny,
    Only(Vec<String>),
}

/// The `callers` block as written, before the defaults and the rules.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Declared {
    #[serde(default)]
    direct: Option<Door>,
    #[serde(default)]
    contract: Option<ContractDoor>,
    #[serde(default)]
    https: Option<Door>,
    #[serde(default)]
    meta_tx: Option<Door>,
}

/// The `callers` block with its defaults applied and its rules checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callers {
    pub direct: Door,
    pub contract: ContractDoor,
    pub https: Door,
    pub meta_tx: Door,
}

impl Callers {
    fn from_declared(d: Declared) -> Result<Self, String> {
        let callers = Callers {
            direct: d.direct.unwrap_or(Door::Allow),
            contract: d.contract.unwrap_or(ContractDoor::Allow),
            https: d.https.unwrap_or(Door::Allow),
            meta_tx: d.meta_tx.unwrap_or(Door::Deny),
        };
        if let ContractDoor::Only(list) = &callers.contract {
            check_allowlist(list)?;
            for (name, door) in [("direct", d.direct), ("https", d.https), ("meta_tx", d.meta_tx)] {
                if door == Some(Door::Allow) {
                    return Err(format!(
                        "callers.contract.only admits only the accounts it names, so callers.{name}: \"allow\" \
                         would never apply: remove it"
                    ));
                }
            }
        }
        Ok(callers)
    }

    /// Whether an account calling OutLayer itself, signing its own
    /// transaction, is admitted — what the owner opening their tasks for a
    /// new device does (`tasks_unlock`).
    pub fn admits_direct(&self) -> bool {
        !matches!(self.contract, ContractDoor::Only(_)) && self.direct == Door::Allow
    }

    /// Whether a call over HTTPS, paid by a payment key, is admitted — what
    /// the run the platform starts for an approved task is.
    pub fn admits_https(&self) -> bool {
        !matches!(self.contract, ContractDoor::Only(_)) && self.https == Door::Allow
    }
}

fn check_allowlist(list: &[String]) -> Result<(), String> {
    if list.is_empty() {
        return Err("callers.contract.only admits nobody: write \"deny\" instead".to_string());
    }
    if list.len() > MAX_CONTRACT_ALLOWLIST {
        return Err(format!(
            "callers.contract.only names {} accounts, at most {MAX_CONTRACT_ALLOWLIST} are allowed",
            list.len()
        ));
    }
    for (i, id) in list.iter().enumerate() {
        if id.parse::<near_primitives::types::AccountId>().is_err() {
            return Err(format!("callers.contract.only: \"{id}\" is not a NEAR account id"));
        }
        if list[..i].contains(id) {
            return Err(format!("callers.contract.only names {id} twice"));
        }
    }
    Ok(())
}

/// `deserialize_with` for [`crate::connector_manifest::ProjectManifest::callers`]:
/// a block that breaks a rule does not parse, and a manifest that does not
/// parse refuses the run.
pub fn deserialize_declared<'de, D>(deserializer: D) -> Result<Option<Callers>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<Declared>::deserialize(deserializer)? {
        None => Ok(None),
        Some(d) => Callers::from_declared(d).map(Some).map_err(serde::de::Error::custom),
    }
}

/// Which door a run came through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerDoor {
    Direct,
    Contract,
    MetaTransaction,
    Https,
}

/// What the job says about how it was called: facts the worker was handed with
/// the job, never the guest's.
#[derive(Debug, Clone, Copy)]
pub struct RunCaller<'a> {
    pub is_https_call: bool,
    /// The job's `user_account_id`: on chain the account that signed — for a
    /// meta-transaction the account that signed the delegate action — and over
    /// HTTPS the payment key's owner.
    pub user_account_id: Option<&'a str>,
    /// The account that called OutLayer's contract; over HTTPS the payer.
    pub predecessor_id: Option<&'a str>,
    /// The account that signed and relayed a meta-transaction; `None` when the
    /// call was not one.
    pub relayer_id: Option<&'a str>,
}

impl RunCaller<'_> {
    /// The door this run came through, or why it cannot be told.
    pub fn door(&self) -> Result<CallerDoor, String> {
        if self.is_https_call {
            return Ok(CallerDoor::Https);
        }
        let Some(predecessor) = self.predecessor_id else {
            return Err(
                "This project's manifest declares who may call it, and this run does not say which account \
                 called OutLayer. Nothing was executed."
                    .to_string(),
            );
        };
        if self.relayer_id.is_some() {
            return Ok(CallerDoor::MetaTransaction);
        }
        if self.user_account_id == Some(predecessor) {
            Ok(CallerDoor::Direct)
        } else {
            Ok(CallerDoor::Contract)
        }
    }
}

/// Admit the run, or the sentence that refuses it. A manifest without a
/// `callers` block admits every run.
pub fn admit(callers: Option<&Callers>, run: &RunCaller<'_>) -> Result<(), String> {
    let Some(callers) = callers else {
        return Ok(());
    };
    let door = run.door()?;
    let signer = run.user_account_id.unwrap_or("an unnamed account");
    let predecessor = run.predecessor_id.unwrap_or("an unnamed account");
    let relayer = run.relayer_id.unwrap_or("an unnamed account");

    if let ContractDoor::Only(list) = &callers.contract {
        if door == CallerDoor::Https {
            return Err(
                "This project's manifest admits calls only from the contracts it names, and an HTTPS call \
                 comes through no contract. Nothing was executed."
                    .to_string(),
            );
        }
        if list.iter().any(|id| id == predecessor) {
            return Ok(());
        }
        let how = match door {
            CallerDoor::Direct => "directly".to_string(),
            CallerDoor::MetaTransaction => format!("through a meta-transaction relayed by {relayer}"),
            CallerDoor::Contract | CallerDoor::Https => format!("on behalf of {signer}"),
        };
        return Err(format!(
            "This project's manifest admits calls only from the contracts it names: OutLayer was called by \
             {predecessor} {how}, which is not one of them. Nothing was executed."
        ));
    }

    match door {
        CallerDoor::Https if callers.https == Door::Deny => Err(
            "This project's manifest does not admit HTTPS calls (callers.https is \"deny\"): call it on chain. \
             Nothing was executed."
                .to_string(),
        ),
        CallerDoor::Direct if callers.direct == Door::Deny => Err(format!(
            "This project's manifest does not admit direct calls: OutLayer was called by {predecessor}, the \
             account that signed the transaction, and callers.direct is \"deny\". Nothing was executed."
        )),
        CallerDoor::MetaTransaction if callers.meta_tx == Door::Deny => Err(format!(
            "This project's manifest does not admit meta-transactions: {predecessor} signed the call and \
             {relayer} relayed it, and a callers block admits meta-transactions only with callers.meta_tx: \
             \"allow\". Nothing was executed."
        )),
        CallerDoor::Contract if callers.contract == ContractDoor::Deny => Err(format!(
            "This project's manifest does not admit calls made through a contract: this run was signed by \
             {signer} and OutLayer was called by {predecessor}, and callers.contract is \"deny\". Nothing was \
             executed."
        )),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<Option<Callers>, String> {
        #[derive(Deserialize)]
        struct Wrap {
            #[serde(default, deserialize_with = "deserialize_declared")]
            callers: Option<Callers>,
        }
        serde_json::from_str::<Wrap>(json).map(|w| w.callers).map_err(|e| e.to_string())
    }

    fn callers(json: &str) -> Callers {
        parse(&format!(r#"{{"callers": {json}}}"#)).unwrap().unwrap()
    }

    fn refused(json: &str) -> String {
        parse(&format!(r#"{{"callers": {json}}}"#)).unwrap_err()
    }

    const ALICE: &str = "alice.testnet";
    const RELAY: &str = "relay.alice.testnet";
    const DEPUTY: &str = "deputy.alice.testnet";
    const BOB: &str = "bob.testnet";

    fn direct() -> RunCaller<'static> {
        RunCaller { is_https_call: false, user_account_id: Some(ALICE), predecessor_id: Some(ALICE), relayer_id: None }
    }
    fn through(contract: &'static str) -> RunCaller<'static> {
        RunCaller { is_https_call: false, user_account_id: Some(ALICE), predecessor_id: Some(contract), relayer_id: None }
    }
    fn meta_tx() -> RunCaller<'static> {
        RunCaller { is_https_call: false, user_account_id: Some(ALICE), predecessor_id: Some(ALICE), relayer_id: Some(BOB) }
    }
    fn https() -> RunCaller<'static> {
        RunCaller { is_https_call: true, user_account_id: Some(ALICE), predecessor_id: Some(ALICE), relayer_id: None }
    }

    #[test]
    fn defaults_open_every_door_but_meta_transactions() {
        let c = callers("{}");
        assert_eq!(c, Callers { direct: Door::Allow, contract: ContractDoor::Allow, https: Door::Allow, meta_tx: Door::Deny });
        for run in [direct(), through(RELAY), https()] {
            assert_eq!(admit(Some(&c), &run), Ok(()));
        }
        assert!(admit(Some(&c), &meta_tx()).unwrap_err().contains("meta-transactions"));
    }

    #[test]
    fn no_block_admits_everything() {
        assert_eq!(parse("{}").unwrap(), None);
        for run in [direct(), through(RELAY), https(), meta_tx()] {
            assert_eq!(admit(None, &run), Ok(()));
        }
    }

    #[test]
    fn doors_come_from_the_job() {
        assert_eq!(direct().door(), Ok(CallerDoor::Direct));
        assert_eq!(through(RELAY).door(), Ok(CallerDoor::Contract));
        assert_eq!(meta_tx().door(), Ok(CallerDoor::MetaTransaction));
        assert_eq!(https().door(), Ok(CallerDoor::Https));
        // HTTPS is judged first: its predecessor is the payer, equal to the
        // signer, and it is still not a direct call.
        let odd = RunCaller { relayer_id: Some(BOB), ..https() };
        assert_eq!(odd.door(), Ok(CallerDoor::Https));
    }

    #[test]
    fn a_run_with_no_predecessor_is_refused_only_under_a_rule() {
        let run = RunCaller { predecessor_id: None, ..direct() };
        assert!(run.door().unwrap_err().contains("does not say which account called OutLayer"));
        assert_eq!(admit(None, &run), Ok(()));
        assert!(admit(Some(&callers("{}")), &run).unwrap_err().ends_with("Nothing was executed."));
    }

    #[test]
    fn each_door_shuts_only_itself() {
        let cases: [(&str, RunCaller<'static>, &str); 4] = [
            (r#"{"direct": "deny"}"#, direct(), "does not admit direct calls"),
            (r#"{"contract": "deny"}"#, through(RELAY), "does not admit calls made through a contract"),
            (r#"{"https": "deny"}"#, https(), "does not admit HTTPS calls"),
            (r#"{"meta_tx": "deny"}"#, meta_tx(), "does not admit meta-transactions"),
        ];
        for (json, shut, sentence) in &cases {
            let c = callers(json);
            let err = admit(Some(&c), shut).unwrap_err();
            assert!(err.contains(sentence), "{json}: {err}");
            assert!(err.ends_with("Nothing was executed."), "{err}");
            for (_, other, _) in cases.iter().filter(|(j, _, _)| j != json) {
                let open = if matches!(other.door(), Ok(CallerDoor::MetaTransaction)) {
                    admit(Some(&callers(r#"{"meta_tx": "allow"}"#)), other)
                } else {
                    admit(Some(&c), other)
                };
                assert_eq!(open, Ok(()), "{json} must not shut {:?}", other.door());
            }
        }
    }

    #[test]
    fn meta_tx_allow_admits_it() {
        assert_eq!(admit(Some(&callers(r#"{"meta_tx": "allow"}"#)), &meta_tx()), Ok(()));
    }

    #[test]
    fn only_admits_the_named_callers_and_nothing_else() {
        let c = callers(&format!(r#"{{"contract": {{"only": ["{RELAY}", "game.testnet"]}}}}"#));
        assert_eq!(admit(Some(&c), &through(RELAY)), Ok(()));

        let err = admit(Some(&c), &through(DEPUTY)).unwrap_err();
        assert!(err.contains("admits calls only from the contracts it names"), "{err}");
        assert!(err.contains(DEPUTY) && err.contains(ALICE), "{err}");

        let err = admit(Some(&c), &direct()).unwrap_err();
        assert!(err.contains("called by alice.testnet directly"), "{err}");

        let err = admit(Some(&c), &meta_tx()).unwrap_err();
        assert!(err.contains("meta-transaction relayed by bob.testnet"), "{err}");

        let err = admit(Some(&c), &https()).unwrap_err();
        assert!(err.contains("an HTTPS call comes through no contract"), "{err}");

        // A refusal never lists the allowlist.
        for run in [through(DEPUTY), direct(), meta_tx(), https()] {
            let err = admit(Some(&c), &run).unwrap_err();
            assert!(!err.contains(RELAY) && !err.contains("game.testnet"), "{err}");
        }
    }

    #[test]
    fn only_admits_a_listed_account_calling_itself() {
        let c = callers(r#"{"contract": {"only": ["game.testnet"]}}"#);
        let own = RunCaller { user_account_id: Some("game.testnet"), predecessor_id: Some("game.testnet"), ..direct() };
        assert_eq!(admit(Some(&c), &own), Ok(()));
    }

    #[test]
    fn only_refuses_an_explicit_allow_elsewhere() {
        for door in ["direct", "https", "meta_tx"] {
            let err = refused(&format!(r#"{{"contract": {{"only": ["game.testnet"]}}, "{door}": "allow"}}"#));
            assert!(err.contains(&format!("callers.{door}: \"allow\" would never apply")), "{err}");
        }
        // An explicit "deny" says what only already does.
        callers(r#"{"contract": {"only": ["game.testnet"]}, "direct": "deny", "https": "deny", "meta_tx": "deny"}"#);
    }

    #[test]
    fn the_allowlist_is_bounded_and_exact() {
        assert!(refused(r#"{"contract": {"only": []}}"#).contains("admits nobody"));
        let many: Vec<String> = (0..=MAX_CONTRACT_ALLOWLIST).map(|i| format!("\"c{i}.testnet\"")).collect();
        assert!(refused(&format!(r#"{{"contract": {{"only": [{}]}}}}"#, many.join(","))).contains("at most 32"));
        let enough: Vec<String> = (0..MAX_CONTRACT_ALLOWLIST).map(|i| format!("\"c{i}.testnet\"")).collect();
        callers(&format!(r#"{{"contract": {{"only": [{}]}}}}"#, enough.join(",")));
        for bad in ["*.testnet", "Game.testnet", " game.testnet", "game..testnet", "a"] {
            let err = refused(&format!(r#"{{"contract": {{"only": ["{bad}"]}}}}"#));
            assert!(err.contains("is not a NEAR account id"), "{bad}: {err}");
        }
        assert!(refused(r#"{"contract": {"only": ["g.testnet", "g.testnet"]}}"#).contains("twice"));
    }

    #[test]
    fn misspellings_do_not_parse() {
        assert!(refused(r#"{"direct": "alow"}"#).contains("unknown variant `alow`"));
        assert!(refused(r#"{"contract": {"onl": ["g.testnet"]}}"#).contains("unknown variant `onl`"));
        assert!(refused(r#"{"metatx": "allow"}"#).contains("unknown field `metatx`"));
        let err = refused(r#"{"https": true}"#);
        assert!(err.contains("expected value"), "{err}");
    }

    #[test]
    fn admits_direct_is_what_a_task_answer_needs() {
        assert!(callers("{}").admits_direct());
        assert!(!callers(r#"{"direct": "deny"}"#).admits_direct());
        assert!(!callers(r#"{"contract": {"only": ["g.testnet"]}}"#).admits_direct());
        assert!(callers(r#"{"contract": "deny", "https": "deny"}"#).admits_direct());
    }
}
