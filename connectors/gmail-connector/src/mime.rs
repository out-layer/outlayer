//! Building a message Gmail will send.
//!
//! Gmail's REST API takes a whole RFC 2822 message, base64url-encoded. It is
//! built here by hand: the format is small and fixed, and a dependency would be a
//! larger surface than the code it replaced.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// What the caller wants sent.
pub struct Outgoing<'a> {
    /// Absent for a `gmail.send` credential, which cannot read back its own
    /// address; Gmail then fills in the authenticated account.
    pub from: Option<&'a str>,
    pub to: &'a [String],
    pub cc: &'a [String],
    pub subject: &'a str,
    pub body: &'a str,
    pub attachments: &'a [Attachment],
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    /// Base64 of the file's bytes, as the caller supplied it.
    pub data: String,
}

pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64 in either alphabet, padded or not — callers send attachments in
/// whichever they have.
pub fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let normalized = cleaned.replace('-', "+").replace('_', "/");
    let padded = match normalized.len() % 4 {
        0 => normalized,
        n => format!("{normalized}{}", "=".repeat(4 - n)),
    };
    STANDARD.decode(padded.as_bytes()).map_err(|e| format!("not base64: {e}"))
}

/// A header value with the bytes that would break a header removed. A subject
/// carrying a newline could otherwise inject headers of its own — a `Bcc:` the
/// owner's policy never saw, for instance.
fn header_value(value: &str) -> String {
    value.chars().filter(|c| *c != '\r' && *c != '\n').collect()
}

/// Encode a header value that is not plain ASCII, as RFC 2047 wants it. Without
/// this a subject in Cyrillic arrives as mojibake.
fn encoded_header(value: &str) -> String {
    let clean = header_value(value);
    if clean.is_ascii() {
        return clean;
    }
    format!("=?UTF-8?B?{}?=", STANDARD.encode(clean.as_bytes()))
}

/// The whole message, ready for Gmail's `raw` field.
pub fn build(message: &Outgoing) -> Result<String, String> {
    let mut out = String::new();
    if let Some(from) = message.from {
        out.push_str(&format!("From: {}\r\n", header_value(from)));
    }
    out.push_str(&format!("To: {}\r\n", header_value(&message.to.join(", "))));
    if !message.cc.is_empty() {
        out.push_str(&format!("Cc: {}\r\n", header_value(&message.cc.join(", "))));
    }
    out.push_str(&format!("Subject: {}\r\n", encoded_header(message.subject)));
    out.push_str("MIME-Version: 1.0\r\n");

    if message.attachments.is_empty() {
        out.push_str("Content-Type: text/plain; charset=\"UTF-8\"\r\n");
        out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        out.push_str(&wrap(&STANDARD.encode(message.body.as_bytes())));
        return Ok(base64url(out.as_bytes()));
    }

    // A boundary nothing in the message can contain: it is derived from the
    // content, so a body that happens to hold another message's boundary cannot
    // truncate this one.
    let boundary = boundary_for(message);
    out.push_str(&format!("Content-Type: multipart/mixed; boundary=\"{boundary}\"\r\n\r\n"));
    out.push_str(&format!("--{boundary}\r\n"));
    out.push_str("Content-Type: text/plain; charset=\"UTF-8\"\r\n");
    out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    out.push_str(&wrap(&STANDARD.encode(message.body.as_bytes())));
    out.push_str("\r\n");

    for attachment in message.attachments {
        let bytes = decode_base64(&attachment.data)
            .map_err(|e| format!("attachment `{}` is {e}", attachment.filename))?;
        out.push_str(&format!("--{boundary}\r\n"));
        out.push_str(&format!(
            "Content-Type: {}; name=\"{}\"\r\n",
            header_value(&attachment.content_type),
            header_value(&attachment.filename)
        ));
        out.push_str(&format!(
            "Content-Disposition: attachment; filename=\"{}\"\r\n",
            header_value(&attachment.filename)
        ));
        out.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
        out.push_str(&wrap(&STANDARD.encode(&bytes)));
        out.push_str("\r\n");
    }
    out.push_str(&format!("--{boundary}--\r\n"));
    Ok(base64url(out.as_bytes()))
}

fn boundary_for(message: &Outgoing) -> String {
    // A cheap content hash: enough to be unguessable from outside the message
    // and impossible to collide with text the message itself contains.
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for part in [message.subject, message.body].iter() {
        for byte in part.bytes() {
            acc ^= byte as u64;
            acc = acc.wrapping_mul(0x100_0000_01b3);
        }
    }
    for attachment in message.attachments {
        for byte in attachment.filename.bytes().chain(attachment.data.bytes().take(64)) {
            acc ^= byte as u64;
            acc = acc.wrapping_mul(0x100_0000_01b3);
        }
    }
    format!("outlayer-{acc:016x}")
}

/// Base64 in 76-character lines, as mail transport expects.
fn wrap(encoded: &str) -> String {
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 76 * 2);
    for (i, chunk) in encoded.as_bytes().chunks(76).enumerate() {
        if i > 0 {
            out.push_str("\r\n");
        }
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outgoing<'a>(subject: &'a str, body: &'a str, to: &'a [String], attachments: &'a [Attachment]) -> Outgoing<'a> {
        Outgoing { from: Some("me@example.com"), to, cc: &[], subject, body, attachments }
    }

    fn decoded(raw: &str) -> String {
        String::from_utf8(decode_base64(raw).unwrap()).unwrap()
    }

    #[test]
    fn a_plain_message_is_a_whole_rfc822_document() {
        let to = vec!["them@example.com".to_string()];
        let text = decoded(&build(&outgoing("Hello", "Body text", &to, &[])).unwrap());
        assert!(text.starts_with("From: me@example.com\r\nTo: them@example.com\r\n"));
        assert!(text.contains("Subject: Hello\r\n"));
        assert!(text.contains("Content-Type: text/plain; charset=\"UTF-8\""));
        // The body travels base64-encoded, so no byte of it can look like a header.
        assert!(text.contains(&STANDARD.encode("Body text")));
    }

    /// A `gmail.send` credential cannot learn its own address, so the message
    /// goes without `From` and Gmail fills in the account — verified against a
    /// live mailbox on 2026-09-11.
    #[test]
    fn a_message_without_a_sender_carries_no_from_header_at_all() {
        let to = vec!["them@example.com".to_string()];
        let message = Outgoing { from: None, to: &to, cc: &[], subject: "S", body: "B", attachments: &[] };
        let text = decoded(&build(&message).unwrap());
        assert!(text.starts_with("To: them@example.com\r\n"), "{text}");
        assert!(!text.contains("From:"), "an empty From would be refused or shown blank: {text}");
    }

    /// A subject or a filename carrying a newline could otherwise add headers of
    /// its own — a `Bcc:` the owner's policy never approved, for example.
    #[test]
    fn a_header_cannot_be_used_to_smuggle_another_header() {
        let to = vec!["them@example.com".to_string()];
        let text = decoded(&build(&outgoing("Hi\r\nBcc: victim@example.com", "b", &to, &[])).unwrap());
        assert!(!text.contains("\r\nBcc:"), "the newline must be dropped so no Bcc header appears: {text}");
        assert!(text.contains("Subject: HiBcc: victim@example.com\r\n"), "it stays part of the subject");
    }

    #[test]
    fn a_non_ascii_subject_is_encoded_the_way_mail_clients_read_it() {
        let to = vec!["them@example.com".to_string()];
        let text = decoded(&build(&outgoing("Привет", "b", &to, &[])).unwrap());
        assert!(text.contains("Subject: =?UTF-8?B?"), "{text}");
        assert!(text.contains(&STANDARD.encode("Привет")));
    }

    #[test]
    fn attachments_become_a_multipart_message_with_a_boundary_nothing_collides_with() {
        let to = vec!["them@example.com".to_string()];
        let attachments = vec![Attachment {
            filename: "r.txt".into(),
            content_type: "text/plain".into(),
            data: STANDARD.encode("file bytes"),
        }];
        let text = decoded(&build(&outgoing("S", "B", &to, &attachments)).unwrap());
        let boundary = text
            .split("boundary=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap()
            .to_string();
        assert!(text.contains(&format!("--{boundary}\r\n")));
        assert!(text.ends_with(&format!("--{boundary}--\r\n")));
        assert!(text.contains("Content-Disposition: attachment; filename=\"r.txt\""));
        assert!(text.contains(&STANDARD.encode("file bytes")));
        let other = decoded(&build(&outgoing("S2", "B2", &to, &attachments)).unwrap());
        assert!(!other.contains(&boundary), "different content, different boundary");
    }

    #[test]
    fn an_attachment_that_is_not_base64_is_refused_before_anything_is_sent() {
        let to = vec!["them@example.com".to_string()];
        let attachments = vec![Attachment {
            filename: "bad.bin".into(),
            content_type: "application/octet-stream".into(),
            data: "!!!not base64!!!".into(),
        }];
        let err = build(&outgoing("S", "B", &to, &attachments)).unwrap_err();
        assert!(err.contains("bad.bin") && err.contains("not base64"), "{err}");
    }

    #[test]
    fn base64_is_read_in_either_alphabet() {
        assert_eq!(decode_base64("YWJjZA==").unwrap(), b"abcd");
        assert_eq!(decode_base64("YWJjZA").unwrap(), b"abcd");
        let tricky = [0xfbu8, 0xff, 0xbf];
        let url = base64url(&tricky);
        assert!(url.contains('-') || url.contains('_'));
        assert_eq!(decode_base64(&url).unwrap(), tricky);
        assert!(decode_base64("%%%").is_err());
    }
}
