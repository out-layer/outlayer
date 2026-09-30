//! The owner's rules for what the agent may do with their mailbox.
//!
//! This is the whole reason the connector exists rather than handing an agent a
//! Gmail token. An agent that can send from a real person's address can phish
//! in their name, so the owner says who may be written to, how much, and
//! whether attachments are allowed; the connector enforces it inside the
//! enclave, before anything reaches Google.
//!
//! Fail-closed: no policy means nothing is sent. A policy this build cannot
//! read refuses sending too — an unknown field is a parse error, not something
//! to ignore, because the field somebody added is probably the restriction
//! they cared about.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const POLICY_ENV: &str = "GMAIL_POLICY";

/// Where the owner connects an account and stores its policy.
pub const CONNECT_PAGE: &str = "https://app.outlayer.ai/connect/gmail";

/// Serialised, it is what `status` reports: every member, under the name the
/// policy spells it with.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Domains the agent may write to, e.g. `["example.com"]`. `["any"]` or
    /// absent means anywhere, which is a deliberate choice the owner makes.
    pub recipient_domains: Option<Vec<String>>,
    /// Addresses the agent may write to regardless of domain.
    pub recipients: Option<Vec<String>>,
    /// Messages a day for one agent, counted in project storage in UTC days:
    /// the sends the agent made itself in one count, the sends the owner
    /// confirmed for it in another (see [`Counted`]). Optional: absent means
    /// no cap of the owner's — the manifest's per-wallet technical ceiling
    /// still applies.
    pub max_per_day: Option<u32>,
    /// Recipients one message may carry, `to` and `cc` together.
    pub max_recipients: Option<usize>,
    /// Largest attachment the agent may send, in kilobytes. Absent: no
    /// attachments at all.
    pub max_attachment_kb: Option<usize>,
    /// Prepended to every subject when it is not already there, so a recipient
    /// can tell agent mail from its owner's.
    pub subject_prefix: Option<String>,
    /// The operations that need the owner: one listed here prepares its
    /// action and leaves it as a task, and the owner's own call carries it
    /// out. Absent or empty: none. Reported by `status` as the policy holds
    /// it, and not at all when the policy has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirm: Option<Vec<Confirmable>>,
}

/// An operation the owner may ask to confirm. A name that is not one does not
/// parse, and a policy that does not parse refuses sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirmable {
    Send,
}

pub enum Loaded {
    None,
    Unreadable(String),
    Some(Policy),
}

pub fn load() -> Loaded {
    match std::env::var(POLICY_ENV) {
        Err(_) => Loaded::None,
        Ok(raw) if raw.trim().is_empty() => Loaded::None,
        Ok(raw) => match serde_json::from_str::<Policy>(&raw) {
            Ok(policy) => Loaded::Some(policy),
            Err(e) => Loaded::Unreadable(format!(
                "policy_denied: {POLICY_ENV} could not be read ({e}). Until the owner of the \
                 secrets row stores one that can be, at {CONNECT_PAGE}, nothing is sent from \
                 this mailbox"
            )),
        },
    }
}

/// The policy as it is stored, byte for byte: what a task is made under, and
/// what an answer to it is judged against. Empty when there is none.
pub fn stored() -> Vec<u8> {
    std::env::var(POLICY_ENV).unwrap_or_default().into_bytes()
}

/// The policy a send needs, or the refusal to answer with.
pub fn require() -> Result<Policy, String> {
    required(load())
}

/// [`require`], of a policy already loaded.
pub fn required(loaded: Loaded) -> Result<Policy, String> {
    match loaded {
        Loaded::Some(policy) => Ok(policy),
        Loaded::Unreadable(e) => Err(e),
        Loaded::None => Err(format!(
            "policy_denied: the secrets row this call names holds no {POLICY_ENV}, so nothing is \
             sent from this mailbox. The OWNER of the row stores the policy beside the credential, \
             at {CONNECT_PAGE} — a JSON object naming who may be written to — and admits an agent \
             by naming its account in the row's access condition"
        )),
    }
}

/// An email address this connector will write to: `local@domain` and nothing
/// richer.
///
/// No display name, no angle brackets, no quotes, no comments, no lists, and
/// only the characters an address needs. A header built from anything richer can
/// carry a recipient the policy never judged: `victim@evil.com, <ok@good.com>` is
/// two addresses to Gmail and one to a parser that looks inside the brackets. So
/// the only form accepted is the one whose checked value IS the value sent.
pub fn mailbox(recipient: &str) -> Result<String, String> {
    const LOCAL_EXTRA: &str = "!#$%&'*+/=?^_`{|}~.-";
    let address = recipient.trim();
    // A refusal is the caller's answer, and on chain it is kept for ever: it
    // names no address, and says what an address is.
    let refuse = || {
        "the recipient is not a bare email address. Pass `name@example.com` — no display \
         name, no angle brackets, one address per entry"
            .to_string()
    };
    let (local, domain) = address.split_once('@').ok_or_else(refuse)?;
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|c| c.is_ascii_alphanumeric() || LOCAL_EXTRA.contains(c));
    let domain_ok = domain.len() <= 253
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !local_ok || !domain_ok {
        return Err(refuse());
    }
    Ok(address.to_ascii_lowercase())
}

/// Every entry of a recipient list, as the bare addresses that will be sent.
/// Every entry as a mailbox; a refusal names the entry by its place in the
/// list and not by what was written in it.
pub fn mailboxes(list: &[String]) -> Result<Vec<String>, String> {
    list.iter()
        .enumerate()
        .map(|(at, entry)| mailbox(entry).map_err(|why| format!("recipient {} of {}: {why}", at + 1, list.len())))
        .collect()
}

impl Policy {
    /// Does `operation` need the owner?
    pub fn confirms(&self, operation: Confirmable) -> bool {
        self.confirm.as_ref().is_some_and(|listed| listed.contains(&operation))
    }

    /// Every recipient, checked before a message is built. One address outside
    /// the policy refuses the whole send: a message is delivered to all of its
    /// recipients or none, so there is nothing to partially allow.
    pub fn check_recipients(&self, recipients: &[String]) -> Result<(), String> {
        if recipients.is_empty() {
            return Err("`to` is required: name at least one recipient".to_string());
        }
        if let Some(max) = self.max_recipients {
            if recipients.len() > max {
                return Err(format!(
                    "policy_denied: this message has {} recipients and the owner allows {max}",
                    recipients.len()
                ));
            }
        }
        // Every address is parsed before any of them is judged: a malformed one
        // is refused whatever the allowlist says, because what it would be
        // delivered to is not knowable from here.
        let addresses = mailboxes(recipients)?;

        let anywhere = self
            .recipient_domains
            .as_ref()
            .is_some_and(|list| list.iter().any(|d| d.eq_ignore_ascii_case("any")));
        if anywhere || (self.recipient_domains.is_none() && self.recipients.is_none()) {
            return Ok(());
        }
        for (at, address) in addresses.iter().enumerate() {
            let named = self
                .recipients
                .as_ref()
                .is_some_and(|list| list.iter().any(|r| mailbox(r).is_ok_and(|m| m == *address)));
            let domain = address.split('@').nth(1).unwrap_or_default();
            let allowed_domain = self
                .recipient_domains
                .as_ref()
                .is_some_and(|list| list.iter().any(|d| d.trim().eq_ignore_ascii_case(domain)));
            if !named && !allowed_domain {
                // The address is not repeated: the caller wrote it, and on
                // chain the refusal stays in the transaction.
                return Err(format!(
                    "policy_denied: the owner's policy does not allow writing to recipient {} of {}: \
                     neither its address nor its domain is allowed",
                    at + 1,
                    addresses.len()
                ));
            }
        }
        Ok(())
    }

    /// The subject as it will be sent.
    pub fn apply_prefix(&self, subject: &str) -> String {
        match self.subject_prefix.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            Some(prefix) if !subject.starts_with(prefix) => format!("{prefix} {subject}"),
            _ => subject.to_string(),
        }
    }

    /// Attachments, against the owner's size rule. Absent means none allowed:
    /// an owner who never mentioned attachments did not agree to them.
    pub fn check_attachments(&self, sizes_bytes: &[usize]) -> Result<(), String> {
        if sizes_bytes.is_empty() {
            return Ok(());
        }
        let Some(max_kb) = self.max_attachment_kb else {
            return Err(
                "policy_denied: the owner's policy names no max_attachment_kb, so this agent may \
                 not send attachments"
                    .to_string(),
            );
        };
        let total: usize = sizes_bytes.iter().sum();
        if total > max_kb * 1024 {
            return Err(format!(
                "policy_denied: these attachments are {} KB and the owner allows {max_kb} KB",
                total / 1024
            ));
        }
        Ok(())
    }
}

// ==================== the day's count ====================

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn now_secs() -> u64 {
    now_ms() / 1000
}

/// `YYYY-MM-DD` in UTC for a millisecond timestamp.
pub fn day_key(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// Whose count a message is taken from.
///
/// Every count is a record in the storage cell of the account that makes the
/// run, sealed under that account's key: a run reads and writes its own cell
/// and no other, so a count is kept where the run that sends can write it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Counted<'a> {
    /// A message the caller sends itself: one count a day, in the caller's
    /// cell.
    Own,
    /// A message the owner confirmed, prepared by this account: one count a
    /// day for each preparer, in the OWNER's cell. It is not the count of
    /// the preparer's own sends, which lives in the preparer's cell.
    ConfirmedFor(&'a str),
}

/// The day's count, touched only through `store::increment` — atomic
/// (compare-and-set on the sealed record, with retries). Never read and then
/// written back: two calls of one agent can run at once, and a read-then-write
/// lets both see room for one more message.
fn key(day: &str, counted: Counted) -> String {
    match counted {
        Counted::Own => format!("gm:sends:{day}"),
        Counted::ConfirmedFor(preparer) => format!("gm:sends:{day}:confirmed:{preparer}"),
    }
}

/// How the day's count is changed: the storage primitive in a run, a stand-in in
/// the tests. A plain function pointer, so a reservation can carry it into `Drop`.
type Bump = fn(&str, i64) -> Result<i64, String>;

fn storage_bump(key: &str, delta: i64) -> Result<i64, String> {
    crate::store::increment(key, delta).map_err(|e| e.to_string())
}

/// The caller's own sends counted today, including any a call in flight has
/// reserved.
pub fn sent_today(day: &str) -> Result<u32, String> {
    let count = storage_bump(&key(day, Counted::Own), 0).map_err(|e| format!("the day's send count could not be read: {e}"))?;
    Ok(count.max(0) as u32)
}

/// One message's place in today's budget, taken BEFORE the message is sent.
///
/// This is how the platform treats money too: reserve first, settle after. The
/// reservation is released when it is dropped without being kept, so every early
/// return between here and a sent message — a refused token, a message that would
/// not build, Gmail saying no — gives the place back, and the owner's budget is
/// spent only by mail that left.
pub struct Reservation {
    key: String,
    kept: bool,
    bump: Bump,
}

impl Reservation {
    /// The message was sent: the place stays taken.
    pub fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.kept {
            // A release that fails leaves the count one too high, which refuses
            // a message rather than allowing one: the safe direction.
            let _ = (self.bump)(&self.key, -1);
        }
    }
}

/// Take a place in today's budget of `counted`, or refuse if it is full.
/// Returns the count including this message.
pub fn reserve(day: &str, counted: Counted, max_per_day: u32) -> Result<(Reservation, u32), String> {
    reserve_with(storage_bump, day, counted, max_per_day)
}

fn reserve_with(bump: Bump, day: &str, counted: Counted, max_per_day: u32) -> Result<(Reservation, u32), String> {
    let key = key(day, counted);
    let after = bump(&key, 1).map_err(|e| format!("the day's send count could not be updated: {e}"))?;
    let reservation = Reservation { key, kept: false, bump };
    if after > max_per_day as i64 {
        // Dropping it gives the place back.
        drop(reservation);
        return Err(format!(
            "policy_denied: {} of the owner's {max_per_day} messages a day are used; this one would pass it",
            after - 1
        ));
    }
    Ok((reservation, after as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_domain_allowlist_reads_the_domain_after_the_last_at() {
        let p = policy(r#"{"recipient_domains":["example.com"],"max_per_day":10}"#);
        assert!(p.check_recipients(&["a@example.com".into()]).is_ok());
        assert!(p.check_recipients(&["A@Example.COM".into()]).is_ok());
        // The classic trick: a domain that only LOOKS like the allowed one.
        let err = p.check_recipients(&["victim@evil.com".into()]).unwrap_err();
        assert!(err.contains("does not allow writing to recipient 1 of 1"), "{err}");
        assert!(!err.contains("evil.com"), "a refusal names no address: {err}");
        assert!(p.check_recipients(&["a@example.com.evil.com".into()]).is_err());
        // An address with two `@` is refused outright rather than parsed: mail
        // software disagrees about which half is the domain.
        let err = p.check_recipients(&["victim@evil.com@example.com".into()]).unwrap_err();
        assert!(err.contains("not a bare email address"), "{err}");
    }

    /// The forms a display name allows are exactly the forms that smuggle a
    /// recipient past the allowlist, so none of them is accepted — found by
    /// building each one and reading the header it produced.
    #[test]
    fn a_recipient_the_policy_did_not_judge_cannot_ride_along() {
        let p = policy(r#"{"recipient_domains":["good.com"],"max_per_day":10}"#);
        for smuggled in [
            "victim@evil.com, <ok@good.com>",
            "victim@evil.com <ok@good.com>",
            "\"x\" victim@evil.com <ok@good.com>",
            "Boss <ok@good.com>",
            "ok@good.com, victim@evil.com",
            "ok@good.com;victim@evil.com",
            "(comment)ok@good.com",
        ] {
            let err = p.check_recipients(&[smuggled.to_string()]).unwrap_err();
            assert!(err.contains("not a bare email address"), "{smuggled} → {err}");
            assert!(!err.contains("evil.com") && !err.contains("good.com"), "a refusal names no address: {err}");
        }
        assert!(p.check_recipients(&["ok@good.com".into()]).is_ok());
    }

    #[test]
    fn an_address_must_be_one_bare_address() {
        assert_eq!(mailbox("  A.B+tag@Sub.Example.co  ").unwrap(), "a.b+tag@sub.example.co");
        for bad in [
            "", "a", "a@b", "a@@b.co", "a b@c.co", "a@b.co, d@e.co", "<a@b.co>", "Name <a@b.co>",
            "\"a\"@b.co", ".a@b.co", "a.@b.co", "a..b@c.co", "a@-b.co", "a@b-.co", "a@b..co",
            "a@b.co\r\nBcc: x@y.z", "адрес@пример.рф",
        ] {
            assert!(mailbox(bad).is_err(), "`{bad}` must be refused");
        }
    }

    #[test]
    fn a_named_recipient_is_allowed_whatever_its_domain() {
        let p = policy(r#"{"recipients":["boss@other.org"],"max_per_day":5}"#);
        assert!(p.check_recipients(&["boss@other.org".into()]).is_ok());
        assert!(p.check_recipients(&["BOSS@Other.ORG".into()]).is_ok(), "addresses compare case-insensitively");
        assert!(p.check_recipients(&["else@other.org".into()]).is_err());
    }

    #[test]
    fn anywhere_is_something_the_owner_has_to_write_down() {
        assert!(policy(r#"{"recipient_domains":["any"],"max_per_day":1}"#)
            .check_recipients(&["whoever@wherever.net".into()])
            .is_ok());
        // Even "anywhere" does not mean "anything": the address must be one.
        assert!(policy(r#"{"recipient_domains":["any"],"max_per_day":1}"#)
            .check_recipients(&["not-an-address".into()])
            .is_err());
        // A policy that names neither is also "anywhere" — but it still has to
        // exist, and with no policy at all nothing is sent.
        assert!(policy(r#"{"max_per_day":1}"#).check_recipients(&["x@y.z".into()]).is_ok());
        assert!(policy(r#"{"max_per_day":1}"#).check_recipients(&[]).unwrap_err().contains("`to` is required"));
    }

    #[test]
    fn recipient_and_attachment_caps_are_enforced_in_kilobytes_and_counts() {
        let p = policy(r#"{"max_recipients":2,"max_attachment_kb":10,"max_per_day":1}"#);
        assert!(p.check_recipients(&["a@b.c".into(), "d@e.f".into()]).is_ok());
        assert!(p
            .check_recipients(&["a@b.c".into(), "d@e.f".into(), "g@h.i".into()])
            .unwrap_err()
            .contains("3 recipients and the owner allows 2"));
        assert!(p.check_attachments(&[5 * 1024]).is_ok());
        assert!(p.check_attachments(&[6 * 1024, 6 * 1024]).unwrap_err().contains("12 KB"));
        // Silence about attachments is not permission.
        let silent = policy(r#"{"max_per_day":1}"#);
        assert!(silent.check_attachments(&[]).is_ok());
        assert!(silent.check_attachments(&[1]).unwrap_err().contains("max_attachment_kb"));
    }

    #[test]
    fn the_prefix_is_added_once_and_only_when_missing() {
        let p = policy(r#"{"subject_prefix":"[agent]","max_per_day":1}"#);
        assert_eq!(p.apply_prefix("Hello"), "[agent] Hello");
        assert_eq!(p.apply_prefix("[agent] Hello"), "[agent] Hello");
        assert_eq!(policy(r#"{"max_per_day":1}"#).apply_prefix("Hello"), "Hello");
    }

    #[test]
    fn a_field_this_build_does_not_know_is_a_parse_error() {
        assert!(serde_json::from_str::<Policy>(r#"{"max_per_day":5,"allow_delete":true}"#).is_err());
    }

    #[test]
    fn the_day_key_is_utc_and_changes_at_midnight() {
        assert_eq!(day_key(0), "1970-01-01");
        assert_eq!(day_key(86_400_000 - 1), "1970-01-01");
        assert_eq!(day_key(86_400_000), "1970-01-02");
        assert_eq!(day_key(1_757_600_000_000), "2025-09-11");
    }

    // ===== the reservation, against a stand-in for the atomic counter =====
    //
    // The platform's `increment` is a compare-and-swap in the coordinator. The
    // stand-in is a mutex-guarded map: atomic in the same sense, so what these
    // tests show is that the reservation logic on top of an atomic counter never
    // lets more through than the cap, and gives back what it does not use.

    use std::collections::HashMap;
    use std::sync::Mutex;

    static COUNTERS: Mutex<Option<HashMap<String, i64>>> = Mutex::new(None);

    fn test_bump(key: &str, delta: i64) -> Result<i64, String> {
        let mut guard = COUNTERS.lock().unwrap();
        let map = guard.get_or_insert_with(HashMap::new);
        let value = map.entry(key.to_string()).or_insert(0);
        *value += delta;
        Ok(*value)
    }

    fn count(day: &str) -> i64 {
        count_of(day, Counted::Own)
    }

    fn count_of(day: &str, counted: Counted) -> i64 {
        test_bump(&key(day, counted), 0).unwrap()
    }

    #[test]
    fn a_confirmed_send_is_counted_for_the_agent_that_prepared_it() {
        let day = "test-confirmed";
        let (alice, bob) = (Counted::ConfirmedFor("alice.testnet"), Counted::ConfirmedFor("bob.testnet"));
        for n in 1..=2 {
            let (reservation, after) = reserve_with(test_bump, day, alice, 2).unwrap();
            assert_eq!(after, n);
            reservation.keep();
        }
        // The cap is each agent's: one that used its own up takes nothing
        // from another, nor from what the owner sends themselves.
        let err = reserve_with(test_bump, day, alice, 2).err().expect("the third of one agent is refused");
        assert!(err.starts_with("policy_denied: 2 of the owner's 2"), "{err}");
        let (reservation, after) = reserve_with(test_bump, day, bob, 2).unwrap();
        assert_eq!(after, 1);
        reservation.keep();
        let (reservation, after) = reserve_with(test_bump, day, Counted::Own, 2).unwrap();
        assert_eq!(after, 1);
        drop(reservation);
        assert_eq!((count_of(day, alice), count_of(day, bob), count(day)), (2, 1, 0));
    }

    #[test]
    fn each_count_has_a_record_of_its_own() {
        assert_eq!(key("2026-09-30", Counted::Own), "gm:sends:2026-09-30");
        assert_eq!(
            key("2026-09-30", Counted::ConfirmedFor("agent.testnet")),
            "gm:sends:2026-09-30:confirmed:agent.testnet"
        );
        // An account id holds no `:`, so no preparer's record is another's,
        // and none is the caller's own.
        assert_ne!(key("d", Counted::ConfirmedFor("a")), key("d", Counted::ConfirmedFor("b")));
        assert_ne!(key("d", Counted::ConfirmedFor("")), key("d", Counted::Own));
    }

    #[test]
    fn a_refusal_for_want_of_a_policy_names_what_is_true_of_this_connector() {
        let none = required(Loaded::None).unwrap_err();
        assert!(none.starts_with("policy_denied: "), "{none}");
        let unread = required(Loaded::Unreadable("policy_denied: it could not be read".into())).unwrap_err();
        assert_eq!(unread, "policy_denied: it could not be read");
        assert!(none.contains(CONNECT_PAGE) && none.contains("access condition"), "{none}");
        // It sends and reads nothing, and a row is the owner's, granted by name.
        for untrue in ["read", "set-for-agent"] {
            assert!(!none.contains(untrue), "`{untrue}` in: {none}");
        }
        assert!(required(Loaded::Some(policy("{}"))).is_ok());
    }

    #[test]
    fn the_cap_admits_exactly_its_number_and_a_refusal_takes_nothing() {
        let day = "test-cap";
        let mut kept = Vec::new();
        for n in 1..=3 {
            let (reservation, after) = reserve_with(test_bump, day, Counted::Own, 3).unwrap();
            assert_eq!(after, n);
            kept.push(reservation);
        }
        let err = reserve_with(test_bump, day, Counted::Own, 3).err().expect("the fourth is refused");
        assert!(err.contains("3 of the owner's 3"), "{err}");
        assert_eq!(count(day), 3, "the refused one gave its place back");
        for reservation in kept {
            reservation.keep();
        }
        assert_eq!(count(day), 3);
    }

    #[test]
    fn a_reservation_dropped_unkept_gives_its_place_back() {
        let day = "test-release";
        {
            let (_reservation, after) = reserve_with(test_bump, day, Counted::Own, 10).unwrap();
            assert_eq!(after, 1);
            // Dropped here, as it is on any early return before a send.
        }
        assert_eq!(count(day), 0);
        let (reservation, _) = reserve_with(test_bump, day, Counted::Own, 10).unwrap();
        reservation.keep();
        assert_eq!(count(day), 1, "a kept one stays");
    }

    /// Many calls at once, the case read-then-write got wrong: every one of them
    /// read the same total and saw room. On an atomic counter exactly the cap
    /// gets through, however the threads interleave.
    #[test]
    fn parallel_callers_never_pass_the_cap() {
        let day = "test-parallel";
        let handles: Vec<_> = (0..48)
            .map(|_| {
                std::thread::spawn(move || match reserve_with(test_bump, day, Counted::Own, 5) {
                    Ok((reservation, _)) => {
                        reservation.keep();
                        true
                    }
                    Err(_) => false,
                })
            })
            .collect();
        let admitted = handles.into_iter().map(|h| h.join().unwrap()).filter(|ok| *ok).count();
        assert_eq!(admitted, 5);
        assert_eq!(count(day), 5);
    }
}

#[cfg(test)]
mod refusals_name_no_address {
    use super::*;

    #[test]
    fn a_refused_recipient_is_named_by_its_place_and_never_by_its_address() {
        let p: Policy = serde_json::from_str(r#"{"recipient_domains":["good.com"],"recipients":["one@else.com"]}"#).unwrap();
        let err = p.check_recipients(&["ok@good.com".into(), "one@else.com".into(), "victim@evil.com".into()]).unwrap_err();
        assert!(err.contains("recipient 3 of 3"), "{err}");
        let err = p.check_recipients(&["ok@good.com".into(), "Name <x@y.co>".into()]).unwrap_err();
        assert!(err.starts_with("recipient 2 of 2: "), "{err}");
        for named in ["victim", "evil", "x@y", "Name"] {
            assert!(!err.contains(named), "{named} is in {err}");
        }
    }
}
