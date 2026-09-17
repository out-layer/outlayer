//! The access token, from the refresh token the owner stored.
//!
//! Google's refresh token is the long-lived credential and it never leaves the
//! enclave. What leaves is one access token request to Google itself, and the
//! token it returns is cached in project storage until shortly before it
//! expires — storage is scoped by the platform to this connector and this
//! paying account, so one agent's token is not another's.
//!
//! A refresh that Google refuses is reported as what it is. `invalid_grant`
//! means the credential is gone (revoked, expired, or the OAuth client was left
//! in testing mode), and no retry will fix it; saying so is the difference
//! between a user fixing their token in a minute and an agent retrying for a
//! week.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use wasi_http_client::Client as HttpClient;

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const TIMEOUT: Duration = Duration::from_secs(20);
/// Where a credential's access token is cached. Keyed by a digest of the
/// credential itself, so a token minted from one credential is never used after
/// the owner replaced it with another: a cache that outlived its credential would
/// keep sending from the previous mailbox for up to an hour.
fn cache_key(credential: &Credential) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(credential.client_id.as_bytes());
    hasher.update([0u8]);
    hasher.update(credential.refresh_token.as_bytes());
    let digest = hasher.finalize();
    let short: String = digest.iter().take(12).map(|b| format!("{b:02x}")).collect();
    format!("gm:token:{short}")
}
/// Refreshed this long before Google's own expiry, so a token cannot die
/// between the check and the call that uses it.
const SAFETY_MARGIN_SECS: u64 = 120;

pub const CLIENT_ID_ENV: &str = "GMAIL_CLIENT_ID";
pub const CLIENT_SECRET_ENV: &str = "GMAIL_CLIENT_SECRET";
pub const REFRESH_TOKEN_ENV: &str = "GMAIL_REFRESH_TOKEN";

/// Our own OAuth client, held as this connector's AUTHOR secret so that an
/// account connected through the OutLayer app needs to store only its refresh
/// token. Deliberately not the names above: a key defined by both the author
/// and the caller refuses the run, and a user who brought their own client must
/// keep working.
pub const OUR_CLIENT_ID_ENV: &str = "GMAIL_OAUTH_CLIENT_ID";
pub const OUR_CLIENT_SECRET_ENV: &str = "GMAIL_OAUTH_CLIENT_SECRET";

/// The connector's own client, when its author stored one.
pub fn our_client() -> Option<(String, String)> {
    match (read(OUR_CLIENT_ID_ENV), read(OUR_CLIENT_SECRET_ENV)) {
        (Some(id), Some(secret)) => Some((id, secret)),
        _ => None,
    }
}

fn read(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Cached {
    access_token: String,
    /// Unix seconds at which this token stops being used here.
    good_until: u64,
}

/// The credential the owner stored. Three values, all the caller's own: this
/// connector holds no credential of ours.
pub struct Credential {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

impl Credential {
    /// The credential this run sends with.
    ///
    /// Two shapes, and the caller's OWN client wins. Someone who brought their
    /// own OAuth app keeps using it and nothing of ours enters their run. An
    /// account connected through the OutLayer app stores only a refresh token,
    /// and our client — the author secret — completes it.
    pub fn from_env() -> Result<Self, String> {
        let refresh_token = read(REFRESH_TOKEN_ENV).ok_or_else(|| {
            format!(
                "no Gmail credential reached this run. Connect an account at \
                 https://app.outlayer.ai/connect/gmail — that stores {REFRESH_TOKEN_ENV} for you — \
                 or store your own {CLIENT_ID_ENV}, {CLIENT_SECRET_ENV} and {REFRESH_TOKEN_ENV} \
                 for this connector and name that row in the call's `secrets_ref`. Nothing a \
                 caller sends in the body can stand in for them."
            )
        })?;
        if let (Some(client_id), Some(client_secret)) = (read(CLIENT_ID_ENV), read(CLIENT_SECRET_ENV)) {
            return Ok(Self { client_id, client_secret, refresh_token });
        }
        match our_client() {
            Some((client_id, client_secret)) => Ok(Self { client_id, client_secret, refresh_token }),
            None => Err(format!(
                "a refresh token reached this run with no OAuth client to use it with. A token \
                 only works with the client that issued it: store {CLIENT_ID_ENV} and \
                 {CLIENT_SECRET_ENV} beside it, or connect the account through \
                 https://app.outlayer.ai/connect/gmail, whose client this connector carries itself."
            )),
        }
    }
}

/// A usable access token: the cached one while it lasts, a fresh one otherwise.
pub fn access_token(credential: &Credential, now_secs: u64) -> Result<String, String> {
    let key = cache_key(credential);
    if let Some(cached) = cached(&key, now_secs) {
        return Ok(cached);
    }
    let (token, expires_in) = refresh(credential)?;
    let record = Cached {
        access_token: token.clone(),
        good_until: now_secs + expires_in.saturating_sub(SAFETY_MARGIN_SECS),
    };
    if let Ok(bytes) = serde_json::to_vec(&record) {
        let _ = ::outlayer::storage::set(&key, &bytes);
    }
    Ok(token)
}

fn cached(key: &str, now_secs: u64) -> Option<String> {
    let bytes = ::outlayer::storage::get(key).ok()??;
    let record: Cached = serde_json::from_slice(&bytes).ok()?;
    (record.good_until > now_secs).then_some(record.access_token)
}

/// The token and the seconds Google says it is good for.
fn refresh(credential: &Credential) -> Result<(String, u64), String> {
    let body = format!(
        "client_id={}&client_secret={}&refresh_token={}&grant_type=refresh_token",
        form(&credential.client_id),
        form(&credential.client_secret),
        form(&credential.refresh_token)
    );
    let response = HttpClient::new()
        .post(TOKEN_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.as_bytes())
        .connect_timeout(TIMEOUT)
        .send()
        .map_err(|e| format!("Google's token endpoint could not be reached: {e}"))?;
    let status = response.status();
    let bytes = response.body().map_err(|e| format!("token answer: {e}"))?;
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    if status != 200 {
        let code = value.get("error").and_then(Value::as_str).unwrap_or("");
        let described = value
            .get("error_description")
            .and_then(Value::as_str)
            .unwrap_or_else(|| if bytes.is_empty() { "no detail" } else { "" });
        if code == "invalid_grant" {
            return Err(format!(
                "credential_expired: Google refused the refresh token ({described}). It is gone for \
                 good — revoked, unused for six months, or issued by an OAuth client still in \
                 testing mode, which expires tokens in days. Mint a new refresh token and store it \
                 again; retrying will not help."
            ));
        }
        return Err(format!(
            "Google refused the token request: HTTP {status} {code} {described}"
        ));
    }

    let token = value
        .get("access_token")
        .and_then(Value::as_str)
        .ok_or_else(|| "Google's token answer carries no access_token".to_string())?
        .to_string();
    // A life shorter than the margin would mean never caching anything; Google
    // answers an hour in practice.
    let expires_in = value
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(3600)
        .max(SAFETY_MARGIN_SECS + 60);
    Ok((token, expires_in))
}

/// Turn Google's authorisation code into a refresh token.
///
/// The one place this connector uses an OAuth client of OURS, and the only
/// place a code is ever seen. What comes back is long-lived: a refresh token is
/// the whole of "this account is connected", which is why it leaves this module
/// sealed and never as an answer.
pub fn exchange_code(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<String, String> {
    let body = format!(
        "code={}&client_id={}&client_secret={}&redirect_uri={}&grant_type=authorization_code",
        form(code),
        form(client_id),
        form(client_secret),
        form(redirect_uri)
    );
    let response = HttpClient::new()
        .post(TOKEN_URL)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.as_bytes())
        .connect_timeout(TIMEOUT)
        .send()
        .map_err(|e| format!("Google's token endpoint could not be reached: {e}"))?;
    let status = response.status();
    let bytes = response.body().map_err(|e| format!("token answer: {e}"))?;
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

    if status != 200 {
        let code_name = value.get("error").and_then(Value::as_str).unwrap_or("");
        let described = value.get("error_description").and_then(Value::as_str).unwrap_or("");
        // Every one of these means "start the consent again", and saying so
        // beats a caller retrying a code that can never work twice.
        if matches!(code_name, "invalid_grant" | "redirect_uri_mismatch") {
            return Err(format!(
                "consent_expired: Google refused this authorisation code ({code_name} {described}). \
                 A code is single-use and lives minutes, and it only works with the exact \
                 redirect_uri it was issued for. Start the connection again."
            ));
        }
        return Err(format!("Google refused the code exchange: HTTP {status} {code_name} {described}"));
    }

    match value.get("refresh_token").and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty()) {
        Some(token) => Ok(token.to_string()),
        // Google returns one only when the consent asked for offline access AND
        // the account has not already granted this client. Without it there is
        // nothing durable to store, and a run tomorrow would have no credential.
        None => Err(
            "Google returned no refresh token for this consent. Ask for it with \
             `access_type=offline` and `prompt=consent` — an account that granted this app before \
             is given one again only when the consent is forced."
                .to_string(),
        ),
    }
}

/// Percent-encode a form value. The credential is not ours to assume anything
/// about, and an unescaped `&` in a secret would silently send a different
/// request.
fn form(value: &str) -> String {
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

    /// A replaced credential must not inherit the previous one's cached token.
    #[test]
    fn each_credential_has_its_own_cache_entry() {
        let a = Credential { client_id: "id".into(), client_secret: "s".into(), refresh_token: "1//one".into() };
        let b = Credential { client_id: "id".into(), client_secret: "s".into(), refresh_token: "1//two".into() };
        let c = Credential { client_id: "other".into(), client_secret: "s".into(), refresh_token: "1//one".into() };
        assert_ne!(cache_key(&a), cache_key(&b), "a new refresh token is a new entry");
        assert_ne!(cache_key(&a), cache_key(&c), "a new client is a new entry");
        assert_eq!(cache_key(&a), cache_key(&a));
        assert!(!cache_key(&a).contains("one"), "the key carries a digest, never the token");
    }

    #[test]
    fn a_form_value_survives_every_byte_a_secret_may_hold() {
        assert_eq!(form("abcXYZ019-_.~"), "abcXYZ019-_.~");
        assert_eq!(form("a&b=c d"), "a%26b%3Dc%20d");
        assert_eq!(form("1//04xyz"), "1%2F%2F04xyz", "Google's refresh tokens start like this");
    }
}

