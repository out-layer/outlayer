//! The Gmail REST client: the one call this connector makes, and nothing else.
//!
//! Every request carries the access token as a bearer header and goes to
//! `gmail.googleapis.com`, the only mail host in the manifest. Google's own
//! error text is passed through to the caller, because when Google refuses
//! something — a scope that was not granted, a quota, a message that no longer
//! exists — its words are what tell an agent whether to change the request or
//! stop.

use serde_json::{json, Value};
use std::time::Duration;
use wasi_http_client::Client as HttpClient;

const BASE: &str = "https://gmail.googleapis.com/gmail/v1/users/me";
const TIMEOUT: Duration = Duration::from_secs(30);

fn post(token: &str, path: &str, body: &Value) -> Result<Value, String> {
    let url = format!("{BASE}{path}");
    let payload = serde_json::to_vec(body).map_err(|e| format!("request encoding: {e}"))?;
    let response = HttpClient::new()
        .post(&url)
        .header("Authorization", format!("Bearer {token}").as_str())
        .header("Content-Type", "application/json")
        .body(&payload)
        .connect_timeout(TIMEOUT)
        .send()
        .map_err(|e| format!("Gmail could not be reached for {path}: {e}"))?;
    let status = response.status();
    let bytes = response.body().map_err(|e| format!("Gmail answer for {path}: {e}"))?;
    if status != 200 && status != 201 {
        return Err(describe(status, &bytes, path));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("Gmail's answer for {path} is not JSON: {e}"))
}

/// Google's refusal, in its own words, with the one reading an agent cannot work
/// out for itself: a missing scope is the owner's consent to redo, not a bug in
/// the request.
fn describe(status: u16, bytes: &[u8], path: &str) -> String {
    let value: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    let message = value
        .get("error")
        .and_then(|e| e.get("message").and_then(Value::as_str))
        .unwrap_or_else(|| std::str::from_utf8(bytes).unwrap_or("").trim())
        .chars()
        .take(300)
        .collect::<String>();
    match status {
        401 => format!(
            "credential_rejected: Gmail refused the access token for {path} ({message}). The \
             refresh token may have been revoked; store a new one."
        ),
        403 if message.to_ascii_lowercase().contains("insufficient") || message.contains("scope") => format!(
            "scope_missing: the Gmail token was not granted what {path} needs ({message}). Consent \
             again with the gmail.send scope, then store the new refresh token."
        ),
        // Before the rate-limit arm, because Google answers this with 403 too
        // and the advice is the opposite: waiting never clears it, and an agent
        // that reads `rate_limited` will retry until someone stops it.
        403 if message.contains("has not been used in project")
            || message.to_ascii_lowercase().contains("is disabled")
            || message.contains("accessNotConfigured") => format!(
            "api_disabled: the Gmail API is switched off in the Google Cloud project this \
             connector's OAuth client belongs to ({message}). Its owner enables it once, at \
             console.cloud.google.com/apis/library/gmail.googleapis.com — retrying will not help."
        ),
        403 | 429 => format!(
            "rate_limited: Gmail is refusing more requests for now ({message}). Wait and retry; \
             nothing was changed."
        ),
        _ => format!("Gmail refused {path}: HTTP {status} {message}"),
    }
}

/// Send a message that is already built. `gmail.send` authorises this and
/// nothing else — not even reading back which address the token belongs to.
pub fn send(token: &str, raw: &str) -> Result<Value, String> {
    post(token, "/messages/send", &json!({"raw": raw}))
}

/// Percent-encode a query or path segment. Gmail search strings are full of
/// spaces, colons and quotes, and an unescaped one would change which mail the
/// agent is shown.
pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_search_string_survives_the_query_intact() {
        assert_eq!(urlencode("is:unread from:a@b.c"), "is%3Aunread%20from%3Aa%40b.c");
        assert_eq!(urlencode(r#"subject:"quarterly report""#), "subject%3A%22quarterly%20report%22");
        assert_eq!(urlencode("plain-text_1.0~"), "plain-text_1.0~");
    }

    /// The reading an agent cannot work out itself: which refusals are worth
    /// retrying and which need the owner.
    #[test]
    fn googles_refusals_are_translated_into_what_to_do_about_them() {
        let scope = br#"{"error":{"message":"Request had insufficient authentication scopes."}}"#;
        assert!(describe(403, scope, "/messages").starts_with("scope_missing:"));
        let quota = br#"{"error":{"message":"User-rate limit exceeded."}}"#;
        assert!(describe(429, quota, "/messages").starts_with("rate_limited:"));
        // A project with the API switched off answers 403 as well, and telling
        // that caller to wait would have it wait for ever.
        let off = br#"{"error":{"message":"Gmail API has not been used in project 1 before or it is disabled."}}"#;
        let said = describe(403, off, "/messages");
        assert!(said.starts_with("api_disabled:"), "{said}");
        assert!(said.contains("console.cloud.google.com"), "{said}");
        assert!(describe(401, b"{}", "/profile").starts_with("credential_rejected:"));
        assert!(describe(500, b"oops", "/messages").contains("HTTP 500"));
    }
}
