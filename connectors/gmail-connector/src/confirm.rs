//! A send the owner asked to confirm.
//!
//! When the owner's policy lists `send` under `confirm`, the agent's `send`
//! checks the message against the policy, and instead of sending it leaves
//! it as a task: the owner is shown who it goes to, the subject and the body,
//! and is given every attachment to open. The owner's own call of `confirm`
//! takes the message and its attachments back, checks them against the
//! policy — the one the task was made under: a task made under another is
//! void — and sends them. Nothing in the task says what to do on a yes: this
//! code does.
//!
//! What the owner is shown is what is sent. So a message to be confirmed has
//! to fit what a task shows whole — a body of 50000 characters, attachments
//! of 6 MiB together — and one that does not is refused, never shown in part.
//!
//! The owner's daily cap counts a confirmed message for the agent that
//! prepared it: one count a day for each preparer, kept in the owner's
//! storage cell, because the run that sends is the owner's and a run writes
//! its own cell and no other. The sends an agent makes itself are counted in
//! the agent's cell. The cap bounds each count; neither run reads the other's.

use outlayer::tasks::{self, Display, FieldKind, WrittenBy};
use serde_json::Value;

use crate::{mime, policy};
use crate::{Input, Prepared};

/// The operation the owner calls to say yes.
const ANSWERED_BY: &str = "confirm";

/// Most characters of a body the owner is shown whole.
const MOST_BODY_CHARS: usize = 50_000;

/// The message as the owner reads it and as it is sent: line ends as `\n`.
/// The message builder writes the line ends a mail needs.
pub(crate) fn shown(message: &Prepared) -> Prepared {
    Prepared { body: message.body.replace("\r\n", "\n"), ..message.clone() }
}

/// What a body must be to be shown whole, or the refusal.
pub(crate) fn check_shown(message: &Prepared) -> Result<(), String> {
    let chars = message.body.chars().count();
    if chars > MOST_BODY_CHARS {
        return Err(format!(
            "display_invalid: the owner confirms every message, and a message to be confirmed holds at most \
             {MOST_BODY_CHARS} characters so that it is shown whole; this one holds {chars}"
        ));
    }
    Ok(())
}

fn display(message: &Prepared) -> Result<Display, String> {
    let mut display = Display::new("Send an email").list("To", &message.to, WrittenBy::Agent);
    if !message.cc.is_empty() {
        display = display.list("Cc", &message.cc, WrittenBy::Agent);
    }
    // An empty subject or body is a message's own; a field holds something.
    if !message.subject.trim().is_empty() {
        display = display.field("Subject", FieldKind::Text, &message.subject, WrittenBy::Agent);
    }
    if !message.body.trim().is_empty() {
        display = display.field("Body", FieldKind::LongText, &message.body, WrittenBy::Agent);
    }
    Ok(display)
}

/// The message without its attachments: what waits sealed as the task's
/// state. The attachments wait as the task's files, where the owner opens
/// them.
fn without_attachments(message: &Prepared) -> Prepared {
    Prepared { attachments: Vec::new(), ..message.clone() }
}

/// An attachment as a file of the task: its bytes, not their base64.
fn as_file(attachment: &mime::Attachment) -> Result<(String, String, Vec<u8>), String> {
    let data = mime::decode_base64(&attachment.data)
        .map_err(|e| format!("attachment `{}` is {e}", attachment.filename))?;
    Ok((attachment.filename.clone(), attachment.content_type.clone(), data))
}

/// A file of the task as the attachment it was.
fn as_attachment(file: &tasks::File) -> mime::Attachment {
    mime::Attachment {
        filename: file.name.clone(),
        content_type: file.content_type.clone(),
        data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &file.data),
    }
}

/// Leave `message`, which passed the owner's rules, as a task for the owner.
pub(crate) fn ask(message: &Prepared) -> Result<Value, String> {
    let message = shown(message);
    check_shown(&message)?;
    let state = serde_json::to_vec(&without_attachments(&message))
        .map_err(|e| format!("the message could not be kept: {e}"))?;
    let mut task = tasks::confirm(display(&message)?, ANSWERED_BY, &state, &policy::stored());
    for attachment in &message.attachments {
        let (name, content_type, data) = as_file(attachment)?;
        task = task.file(&name, &content_type, &data);
    }
    let opened = task.open().map_err(|e| e.refusal())?;
    Ok(tasks::awaiting_owner(&opened))
}

fn named<'a>(value: &'a Option<String>, member: &str) -> Result<&'a str, String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("task_answer_invalid: the call names no `{member}`"))
}

/// What every refusal after the answer was taken ends with.
const CLOSED: &str = "The task is closed: to send this message, prepare it again";

/// A refusal after the answer was taken, as the owner reads it: the same
/// code, and a sentence that says the task is over.
fn closed(refusal: String) -> String {
    format!("{}. {CLOSED}", refusal.trim_end().trim_end_matches('.'))
}

/// The refusal when the message left and its result could not be left for
/// the agent: the task ends as failed although the mail was sent, so the
/// sentence says which of the two is true.
fn sent_unreported(refusal: String, sent: &Value) -> String {
    let id = sent.get("message_id").and_then(Value::as_str).unwrap_or("unknown");
    format!(
        "{}. The message WAS sent (Gmail message {id}) and the task is closed without its result: \
         do not prepare it again",
        refusal.trim_end().trim_end_matches('.')
    )
}

/// What is checked before the owner's answer is taken: that the call names
/// the task and its hash, and that the owner's policy is there and readable.
fn before_answer(input: &Input, loaded: policy::Loaded) -> Result<(&str, &str, policy::Policy), String> {
    let id = named(&input.task_id, "task_id")?;
    let hash = named(&input.task_hash, "task_hash")?;
    Ok((id, hash, policy::required(loaded)?))
}

/// The message a task held: its state, and its files as the attachments
/// they were.
fn held(state: &[u8], files: &[tasks::File]) -> Result<Prepared, String> {
    let kept: Prepared =
        serde_json::from_slice(state).map_err(|_| "task_unreadable: the task does not hold a message".to_string())?;
    Ok(Prepared { attachments: files.iter().map(as_attachment).collect(), ..kept })
}

/// The owner's own call: send the message the task holds.
///
/// The message is inside the task and the host hands it over only with the
/// answer, so the answer is taken first and the message is judged and sent
/// after. Taking the answer moves the task to `answering`, and a task never
/// returns to `open`.
///
/// **Refused before the answer is taken — the task stays as it was, and an
/// open one can be confirmed again:** a call that names no `task_id` or no
/// `task_hash`; a policy that is absent or cannot be read; and everything
/// the host refuses the answer for — a task that is not this owner's or does
/// not exist, a hash that is not the task's, a task that names another
/// operation, a store that did not answer, a task already closed or past its
/// life. A task made under another policy is refused `task_void`: the
/// policy's bytes are part of the task, so the rules a message is judged by
/// here are the rules it was prepared under.
///
/// **Refused after the answer is taken — the task ends as failed, and the
/// refusal's sentence says so:** a state that is not a message; a message
/// its own rules refuse; the day's count of the agent that prepared it, full
/// or unreadable; a credential
/// Google no longer honours; a message that does not build; Google's refusal
/// of the send. What differs between preparing and confirming is the day's
/// count and Google's answer. Last, a result the host would not keep: the
/// message left, and the refusal says that instead.
pub(crate) fn confirm(input: &Input) -> Result<Value, String> {
    let (id, hash, rules) = before_answer(input, policy::load())?;
    let answer = tasks::answered(id, hash, ANSWERED_BY, &policy::stored(), None).map_err(|e| e.refusal())?;
    after_answer(&rules, &answer, crate::on_chain(), crate::deliver, |id, result| {
        tasks::report(id, result).map_err(|e| e.refusal())
    })
}

/// Everything that follows the answer: the task is `answering`, and any
/// refusal from here ends it. `send` sends and `report` leaves the result
/// for the agent — the host's doing in a run.
fn after_answer(
    rules: &policy::Policy,
    answer: &tasks::Answer,
    on_chain: bool,
    send: impl FnOnce(&policy::Policy, &Prepared, policy::Counted) -> Result<Value, String>,
    report: impl FnOnce(&str, &[u8]) -> Result<(), String>,
) -> Result<Value, String> {
    let message = held(&answer.state, &answer.files).map_err(closed)?;
    message.check(rules).map_err(closed)?;
    // Counted for the agent whose run made the task, not for the owner who
    // confirms it: the cap is the owner's bound on that agent.
    let sent = send(rules, &message, policy::Counted::ConfirmedFor(&answer.preparer)).map_err(closed)?;
    // The agent reads the whole of it, recipients and subject with the rest:
    // the host seals a report for the preparer.
    report(&answer.id, sent.to_string().as_bytes()).map_err(|e| sent_unreported(e, &sent))?;
    Ok(answered_with(&sent, &answer.id, on_chain))
}

/// What of a sent message `confirm` answers on chain: counts and Gmail's ids.
/// What `confirm` answers the owner, given what was sent: what a send
/// answers where it runs ([`crate::sent_as_answered`]), with `status` and
/// `task_id`.
fn answered_with(sent: &Value, task_id: &str, on_chain: bool) -> Value {
    let mut out = crate::sent_as_answered(sent, on_chain);
    out["status"] = serde_json::json!("done");
    out["task_id"] = serde_json::json!(task_id);
    out
}

/// The operations every project that uses tasks answers alike.
pub(crate) fn task(operation: &str, input: &Input) -> Result<Value, String> {
    let call = serde_json::json!({ "task_id": input.task_id });
    tasks::dispatch(operation, &call)
        .unwrap_or_else(|| Err(format!("unknown operation `{operation}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mime::Attachment;

    fn message(body: &str) -> Prepared {
        Prepared {
            to: vec!["bob@example.com".into()],
            cc: vec![],
            subject: "[agent] Report".into(),
            body: body.into(),
            attachments: vec![Attachment {
                filename: "report.pdf".into(),
                content_type: "application/pdf".into(),
                data: "AAAA".into(),
            }],
        }
    }

    #[test]
    fn what_is_kept_is_the_message_and_reads_back_whole() {
        let kept = serde_json::to_vec(&shown(&message("Hello,\r\nBob"))).unwrap();
        let back: Prepared = serde_json::from_slice(&kept).unwrap();
        assert_eq!(back, message("Hello,\nBob"));
        // A record with a member this build does not know is not a message:
        // nothing a task could carry besides the message is acted on.
        let mut with_more: serde_json::Value = serde_json::from_slice(&kept).unwrap();
        with_more["bcc"] = serde_json::json!(["eve@example.com"]);
        assert!(serde_json::from_value::<Prepared>(with_more).is_err());
    }

    #[test]
    fn a_body_is_shown_whole_or_the_message_is_refused() {
        check_shown(&message(&"й".repeat(MOST_BODY_CHARS))).unwrap();
        let said = check_shown(&message(&"x".repeat(MOST_BODY_CHARS + 1))).unwrap_err();
        assert!(said.starts_with("display_invalid: ") && said.contains("50001"), "{said}");
    }

    #[test]
    fn an_attachment_waits_as_a_file_and_comes_back_as_the_attachment_it_was() {
        let pdf = Attachment {
            filename: "report.pdf".into(),
            content_type: "application/pdf".into(),
            // URL-safe and unpadded, as a caller may send it.
            data: "JVBERi0xLjf_".into(),
        };
        let (name, content_type, data) = as_file(&pdf).unwrap();
        assert_eq!((name.as_str(), content_type.as_str(), data.as_slice()), ("report.pdf", "application/pdf", &b"%PDF-1.7\xff"[..]));
        let back = as_attachment(&tasks::File { name, content_type, data: data.clone() });
        assert_eq!(mime::decode_base64(&back.data).unwrap(), data);
        assert_eq!((back.filename.as_str(), back.content_type.as_str()), ("report.pdf", "application/pdf"));
        let broken = Attachment { data: "***".into(), ..pdf };
        assert!(as_file(&broken).unwrap_err().starts_with("attachment `report.pdf` is not base64"));
    }

    #[test]
    fn the_state_holds_the_message_and_none_of_its_attachments() {
        let kept = serde_json::to_string(&without_attachments(&shown(&message("Hello")))).unwrap();
        assert!(kept.contains("Hello") && !kept.contains("AAAA") && kept.contains(r#""attachments":[]"#), "{kept}");
    }

    #[test]
    fn a_policy_asks_for_the_owner_by_naming_the_operation() {
        let asks: policy::Policy = serde_json::from_str(r#"{"confirm":["send"]}"#).unwrap();
        assert!(asks.confirms(policy::Confirmable::Send));
        for quiet in [r#"{}"#, r#"{"confirm":[]}"#, r#"{"confirm":null}"#] {
            let policy: policy::Policy = serde_json::from_str(quiet).unwrap();
            assert!(!policy.confirms(policy::Confirmable::Send), "{quiet}");
        }
        // An operation that cannot be confirmed is a policy that cannot be read.
        for unread in [r#"{"confirm":["status"]}"#, r#"{"confirm":["Send"]}"#, r#"{"confirm":"send"}"#] {
            assert!(serde_json::from_str::<policy::Policy>(unread).is_err(), "{unread}");
        }
    }

    /// What a send answers, as `deliver` builds it.
    fn sent() -> Value {
        serde_json::json!({
            "message_id": "19a0c0ffee",
            "thread_id": "19a0c0ffee",
            "to": ["bob@example.com"],
            "cc": ["carol@example.com"],
            "subject": "[agent] Quarterly report",
            "attachments": 1,
            "sent_today": 3,
            "remaining_today": 17,
        })
    }

    #[test]
    fn on_chain_the_answer_names_no_person_and_no_subject() {
        let out = answered_with(&sent(), "run-0", true);
        assert_eq!(
            out,
            serde_json::json!({
                "status": "done",
                "task_id": "run-0",
                "message_id": "19a0c0ffee",
                "thread_id": "19a0c0ffee",
                "attachments": 1,
                "sent_today": 3,
                "remaining_today": 17,
            })
        );
        let text = out.to_string();
        for private in ["bob@example.com", "carol@example.com", "Quarterly", "example.com", "subject", "\"to\"", "\"cc\""] {
            assert!(!text.contains(private), "`{private}` in {text}");
        }
        // A member a send answers and this list does not name stays off the chain.
        let mut more = sent();
        more["bcc"] = serde_json::json!(["eve@example.com"]);
        assert_eq!(answered_with(&more, "run-0", true), out);
        // With no cap there is no count, and the members are there as null.
        let mut uncapped = sent();
        uncapped["sent_today"] = Value::Null;
        uncapped["remaining_today"] = Value::Null;
        let out = answered_with(&uncapped, "run-0", true);
        assert_eq!(out.as_object().unwrap().len(), 7);
        assert_eq!((&out["sent_today"], &out["remaining_today"]), (&Value::Null, &Value::Null));
    }

    #[test]
    fn over_https_the_answer_is_whole() {
        let out = answered_with(&sent(), "run-0", false);
        let mut expected = sent();
        expected["status"] = serde_json::json!("done");
        expected["task_id"] = serde_json::json!("run-0");
        assert_eq!(out, expected);
        assert_eq!(out["to"], serde_json::json!(["bob@example.com"]));
        assert_eq!(out["subject"], "[agent] Quarterly report");
    }

    #[test]
    fn a_call_that_names_no_task_is_refused_before_anything_is_asked() {
        let said = confirm(&Input::default()).unwrap_err();
        assert!(said.starts_with("task_answer_invalid: ") && said.contains("task_id"), "{said}");
        let no_hash = Input { task_id: Some("run-0".into()), ..Input::default() };
        assert!(confirm(&no_hash).unwrap_err().contains("task_hash"));
    }

    // ===== the order: what refuses before the answer is taken, and after =====

    use std::cell::RefCell;

    fn call() -> Input {
        Input { task_id: Some(" run-0 ".into()), task_hash: Some("ab".repeat(32)), ..Input::default() }
    }

    fn rules(json: &str) -> policy::Policy {
        serde_json::from_str(json).unwrap()
    }

    fn answer_holding(message: &Prepared) -> tasks::Answer {
        tasks::Answer {
            id: "run-0".into(),
            thread: "run-0".into(),
            preparer: "agent.testnet".into(),
            kind: tasks::TaskKind::Confirm,
            operation: ANSWERED_BY.into(),
            state: serde_json::to_vec(&without_attachments(message)).unwrap(),
            files: message
                .attachments
                .iter()
                .map(|a| {
                    let (name, content_type, data) = as_file(a).unwrap();
                    tasks::File { name, content_type, data }
                })
                .collect(),
            supplied: None,
        }
    }

    fn never_sends(_: &policy::Policy, _: &Prepared, _: policy::Counted) -> Result<Value, String> {
        panic!("nothing is sent")
    }

    fn never_reports(_: &str, _: &[u8]) -> Result<(), String> {
        panic!("nothing is reported")
    }

    /// A refusal from before the answer says nothing of a closed task: the
    /// task is as it was.
    #[test]
    fn before_the_answer_a_refusal_leaves_the_task_as_it_was() {
        let no_policy = before_answer(&call(), policy::Loaded::None).unwrap_err();
        assert!(no_policy.starts_with("policy_denied: "), "{no_policy}");
        let unread = before_answer(&call(), policy::Loaded::Unreadable("policy_denied: not JSON".into())).unwrap_err();
        assert_eq!(unread, "policy_denied: not JSON");
        let unnamed = before_answer(&Input::default(), policy::Loaded::Some(rules("{}"))).unwrap_err();
        assert!(unnamed.starts_with("task_answer_invalid: "), "{unnamed}");
        for said in [no_policy, unread, unnamed] {
            assert!(!said.contains("closed") && !said.contains("prepare"), "{said}");
        }
        // The call is judged before the policy is: one that names no task is
        // refused for that, whatever the policy.
        assert!(before_answer(&Input::default(), policy::Loaded::None).unwrap_err().starts_with("task_answer_invalid: "));
        let call = call();
        let (id, hash, _) = before_answer(&call, policy::Loaded::Some(rules("{}"))).unwrap();
        assert_eq!((id, hash.len()), ("run-0", 64));
    }

    #[test]
    fn after_the_answer_every_refusal_keeps_its_code_and_says_the_task_is_closed() {
        let ends = |said: &str, code: &str| {
            assert!(said.starts_with(code), "{said}");
            assert!(said.ends_with(CLOSED), "{said}");
            assert!(!said.contains(".."), "{said}");
        };

        // A state that is not a message: refused before anything is sent.
        let broken = tasks::Answer { state: b"not a message".to_vec(), ..answer_holding(&message("Hello")) };
        let said = after_answer(&rules("{}"), &broken, false, never_sends, never_reports).unwrap_err();
        ends(&said, "task_unreadable: ");

        // A message its rules refuse: an attachment, under rules that allow none.
        let said = after_answer(&rules("{}"), &answer_holding(&message("Hello")), false, never_sends, never_reports).unwrap_err();
        ends(&said, "policy_denied: ");
        assert!(said.contains("max_attachment_kb"), "{said}");

        // The day's count, the credential, Google: whatever the send refuses.
        let allows = rules(r#"{"max_attachment_kb":10}"#);
        for refusal in [
            "policy_denied: 3 of the owner's 3 messages a day are used; this one would pass it",
            "credential_expired: Google refused the refresh token (revoked); retrying will not help.",
            "rate_limited: Gmail is refusing more requests for now (quota). Wait and retry; nothing was changed.",
            "Gmail refused /messages/send: HTTP 500 oops",
        ] {
            let send = |_: &policy::Policy, _: &Prepared, _: policy::Counted| Err(refusal.to_string());
            let said = after_answer(&allows, &answer_holding(&message("Hello")), false, send, never_reports).unwrap_err();
            let code = refusal.split(' ').next().unwrap();
            ends(&said, code);
            assert!(said.starts_with(refusal.trim_end_matches('.')), "{said}");
        }
    }

    #[test]
    fn what_is_sent_is_what_the_task_held_and_what_is_reported_is_whole() {
        let allows = rules(r#"{"max_attachment_kb":10}"#);
        let (seen, reported) = (RefCell::new(None), RefCell::new(None));
        let send = |_: &policy::Policy, message: &Prepared, counted: policy::Counted| {
            // Counted for the agent that prepared it, whoever confirms.
            assert_eq!(counted, policy::Counted::ConfirmedFor("agent.testnet"));
            *seen.borrow_mut() = Some(message.clone());
            Ok(sent())
        };
        let report = |id: &str, result: &[u8]| {
            // Nothing is reported before the message left.
            assert!(seen.borrow().is_some());
            *reported.borrow_mut() = Some((id.to_string(), serde_json::from_slice::<Value>(result).unwrap()));
            Ok(())
        };
        let out = after_answer(&allows, &answer_holding(&shown(&message("Hello,\r\nBob"))), true, send, report).unwrap();

        let message = seen.into_inner().expect("a message was sent");
        assert_eq!(message.body, "Hello,\nBob");
        assert_eq!(message.attachments.len(), 1);
        assert_eq!(mime::decode_base64(&message.attachments[0].data).unwrap(), mime::decode_base64("AAAA").unwrap());

        // The agent's sealed result names the recipients and the subject; the
        // owner's answer, on chain, does not.
        let (id, result) = reported.into_inner().expect("a result was left");
        assert_eq!((id.as_str(), &result), ("run-0", &sent()));
        assert_eq!(out, answered_with(&sent(), "run-0", true));
        assert!(out.get("to").is_none() && out.get("subject").is_none());
    }

    #[test]
    fn a_message_that_left_and_was_not_reported_is_said_to_have_left() {
        let allows = rules(r#"{"max_attachment_kb":10}"#);
        let send = |_: &policy::Policy, _: &Prepared, _: policy::Counted| Ok(sent());
        let report = |_: &str, _: &[u8]| Err("task_store_unavailable: the task store did not answer".to_string());
        let said = after_answer(&allows, &answer_holding(&message("Hello")), true, send, report).unwrap_err();
        assert!(said.starts_with("task_store_unavailable: the task store did not answer. "), "{said}");
        assert!(said.contains("WAS sent") && said.contains("19a0c0ffee") && said.contains("do not prepare it again"), "{said}");
        assert!(!said.contains(CLOSED) && !said.contains("bob@example.com"), "{said}");
    }
}
