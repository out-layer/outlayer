//! The GitHub REST client: one host, one credential, and refusals an agent can
//! act on.
//!
//! Every request goes to `api.github.com`, the only host in the manifest, with
//! the owner's token as a bearer header. The token is whatever the owner stored
//! as `GITHUB_TOKEN`: the user token the OutLayer GitHub App issues at
//! <https://app.outlayer.ai/connect/github>, or a personal access token of the
//! owner's own. The connector does not care which — it never refreshes it, and
//! it never appears in an answer.
//!
//! GitHub's refusals are translated once, here. The status alone does not say
//! what to do: a 403 is a rate limit to wait out, or a repository the app was
//! never installed on, and an agent that cannot tell them apart retries the
//! second for ever.

use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use wasi_http_client::{Client as HttpClient, Method};

const BASE: &str = "https://api.github.com";
const TIMEOUT: Duration = Duration::from_secs(25);
pub const TOKEN_ENV: &str = "GITHUB_TOKEN";

/// Where the owner adds a repository to the app's installation.
pub const INSTALL_URL: &str = "https://github.com/apps/outlayer-auth/installations/new";

pub fn token() -> Result<String, String> {
    match std::env::var(TOKEN_ENV) {
        Ok(t) if !t.trim().is_empty() => Ok(t.trim().to_string()),
        _ => Err(format!(
            "credential_missing: no `{TOKEN_ENV}` reached this run. Name the owner's row in `secrets_ref` \
             (`{{\"account_id\": \"<owner>\", \"profile\": \"github\"}}`); the owner connects at {}",
            crate::policy::OWNER_PAGE
        )),
    }
}

pub struct Answer {
    pub status: u16,
    pub body: Value,
}

/// One request. `path` starts with `/` and is already escaped.
pub fn call(method: Method, path: &str, body: Option<&Value>) -> Result<Answer, String> {
    let token = token()?;
    let url = format!("{BASE}{path}");
    let mut request = HttpClient::new()
        .request(method, &url)
        .header("Authorization", format!("Bearer {token}").as_str())
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "outlayer-github-connector")
        .connect_timeout(TIMEOUT);
    let payload;
    if let Some(body) = body {
        payload = serde_json::to_vec(body).map_err(|e| format!("request encoding: {e}"))?;
        request = request.header("Content-Type", "application/json").body(&payload);
    }
    let response = request
        .send()
        .map_err(|e| format!("github_unreachable: GitHub could not be reached for {path}: {e}"))?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.body().map_err(|e| format!("github_unreachable: reading GitHub's answer for {path}: {e}"))?;
    if !(200..300).contains(&status) {
        return Err(describe(status, &bytes, &headers, path));
    }
    let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::Null) };
    Ok(Answer { status, body })
}

pub fn get(path: &str) -> Result<Value, String> {
    call(Method::Get, path, None).map(|a| a.body)
}

pub fn post(path: &str, body: &Value) -> Result<Value, String> {
    call(Method::Post, path, Some(body)).map(|a| a.body)
}

pub fn patch(path: &str, body: &Value) -> Result<Value, String> {
    call(Method::Patch, path, Some(body)).map(|a| a.body)
}

pub fn put(path: &str, body: Option<&Value>) -> Result<Answer, String> {
    call(Method::Put, path, body)
}

pub fn delete(path: &str) -> Result<Answer, String> {
    call(Method::Delete, path, None)
}

fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// GitHub's refusal, as a word an agent branches on and a sentence that says
/// what would change the answer. The words are the contract; the README and the
/// skill list them with which are terminal.
fn describe(status: u16, bytes: &[u8], headers: &HashMap<String, String>, path: &str) -> String {
    let value: Value = serde_json::from_slice(bytes).unwrap_or(Value::Null);
    let message: String = value
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or_else(|| std::str::from_utf8(bytes).unwrap_or("").trim())
        .chars()
        .take(300)
        .collect();
    // 422 carries the useful part in `errors`.
    let details: String = value
        .get("errors")
        .and_then(Value::as_array)
        .map(|errors| {
            errors
                .iter()
                .map(|e| match e {
                    Value::String(s) => s.clone(),
                    other => ["field", "code", "message"]
                        .iter()
                        .filter_map(|k| other.get(*k).and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join(" "),
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|d| !d.is_empty())
        .map(|d| format!(" [{}]", d.chars().take(300).collect::<String>()))
        .unwrap_or_default();
    let lower = message.to_ascii_lowercase();
    let out_of_requests = header(headers, "x-ratelimit-remaining") == Some("0");

    match status {
        401 => format!(
            "token_rejected: GitHub refused the owner's token ({message}). It was revoked or replaced; \
             the owner authorizes again at {}",
            crate::policy::OWNER_PAGE
        ),
        403 | 429 if out_of_requests || lower.contains("rate limit") || lower.contains("abuse") => {
            let wait = header(headers, "retry-after")
                .map(|s| format!("{s} seconds"))
                .or_else(|| header(headers, "x-ratelimit-reset").map(|at| format!("until unix time {at}")))
                .unwrap_or_else(|| "a few minutes".to_string());
            format!("rate_limited: GitHub is throttling this account ({message}). Wait {wait}, then repeat the call once")
        }
        // The app's own boundary, and the answer an agent must not retry.
        403 if lower.contains("not accessible by integration") => format!(
            "not_permitted: GitHub refused {path}. Either the OutLayer app is not installed on this \
             repository — the owner adds it at {INSTALL_URL} — or the action needs a permission the app \
             was not given (workflow files, settings and administration never are)"
        ),
        403 => format!("forbidden: GitHub refused {path} ({message}). The owner's own account may not do this here"),
        404 => format!(
            "not_found: GitHub has nothing at {path}. It does not exist, or it is a private repository \
             the OutLayer app was not installed on — the owner adds it at {INSTALL_URL}"
        ),
        409 => format!("conflict: {message}{details}. The branch or file moved since it was read; read it again and repeat"),
        422 => format!("invalid: GitHub did not accept the request for {path}: {message}{details}"),
        500..=599 => format!("github_unavailable: GitHub answered {status} for {path}. Repeat the call later"),
        other => format!("github_refused: GitHub answered {other} for {path}: {message}{details}"),
    }
}

/// One URL path segment. Everything but the unreserved characters is escaped, so
/// a name can never add a segment or a query of its own.
pub fn segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(byte as char),
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// A file path: every segment escaped, the slashes kept.
pub fn file_path(path: &str) -> String {
    path.split('/').map(segment).collect::<Vec<_>>().join("/")
}

/// `?a=1&b=2` from the pairs that have a value.
pub fn query(pairs: &[(&str, Option<String>)]) -> String {
    let parts: Vec<String> = pairs
        .iter()
        .filter_map(|(k, v)| v.as_ref().map(|v| format!("{k}={}", segment(v))))
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        format!("?{}", parts.join("&"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn said(status: u16, body: &str, headers: &[(&str, &str)]) -> String {
        let headers: HashMap<String, String> = headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        describe(status, body.as_bytes(), &headers, "/repos/a/b/issues")
    }

    /// The same status, three different things to do about it.
    #[test]
    fn a_403_says_which_403_it_is() {
        let boundary = said(403, r#"{"message":"Resource not accessible by integration"}"#, &[]);
        assert!(boundary.starts_with("not_permitted:") && boundary.contains(INSTALL_URL), "{boundary}");

        let spent = said(403, r#"{"message":"API rate limit exceeded for user ID 1."}"#, &[("X-RateLimit-Remaining", "0"), ("X-RateLimit-Reset", "1789900000")]);
        assert!(spent.starts_with("rate_limited:") && spent.contains("1789900000"), "{spent}");

        let secondary = said(403, r#"{"message":"You have exceeded a secondary rate limit."}"#, &[("Retry-After", "60")]);
        assert!(secondary.starts_with("rate_limited:") && secondary.contains("60 seconds"), "{secondary}");

        let plain = said(403, r#"{"message":"Must have admin rights to Repository."}"#, &[]);
        assert!(plain.starts_with("forbidden:"), "{plain}");
    }

    #[test]
    fn the_rest_are_named_for_what_to_do() {
        assert!(said(401, r#"{"message":"Bad credentials"}"#, &[]).starts_with("token_rejected:"));
        let gone = said(404, r#"{"message":"Not Found"}"#, &[]);
        assert!(gone.starts_with("not_found:") && gone.contains(INSTALL_URL), "{gone}");
        let invalid = said(422, r#"{"message":"Validation Failed","errors":[{"resource":"Issue","field":"title","code":"missing_field"}]}"#, &[]);
        assert!(invalid.starts_with("invalid:") && invalid.contains("title missing_field"), "{invalid}");
        assert!(said(409, r#"{"message":"is at abc but expected def"}"#, &[]).starts_with("conflict:"));
        assert!(said(502, "<html>", &[]).starts_with("github_unavailable:"));
    }

    /// A refusal never carries more of GitHub's text than fits in a sentence, and
    /// never the token: it is not in the body to begin with.
    #[test]
    fn a_long_answer_is_cut() {
        let long = format!(r#"{{"message":"{}"}}"#, "x".repeat(5000));
        assert!(said(400, &long, &[]).len() < 500);
    }

    #[test]
    fn a_name_cannot_add_a_segment_or_a_query() {
        assert_eq!(segment("a/b?c=d#e f"), "a%2Fb%3Fc%3Dd%23e%20f");
        assert_eq!(file_path("docs/my file.md"), "docs/my%20file.md");
        assert_eq!(query(&[("state", Some("open".into())), ("labels", None), ("page", Some("2".into()))]), "?state=open&page=2");
        assert_eq!(query(&[("x", None)]), "");
    }
}
