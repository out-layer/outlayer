//! The text of a failed outgoing HTTP call, without its URL.
//!
//! `reqwest::Error` displays as `<kind> for url (<url>)` and keeps the cause — DNS, refused,
//! timed out, TLS, a body that did not parse — in `source()`. On our paths the URL is the
//! keystore's internal hostname or a keyed RPC endpoint, so it is stripped; the cause chain is
//! what a reader of the message or the log needs to act on.

/// The error and every cause under it, URL removed:
/// `error sending request: client error (Connect): dns error: failed to lookup address information: …`.
pub fn reason(e: reqwest::Error) -> String {
    chain(&e.without_url())
}

/// The cause chain of an error whose URL is already removed (`without_url`).
fn chain(e: &reqwest::Error) -> String {
    let mut text = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}
