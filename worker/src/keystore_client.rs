//! Client for communicating with keystore worker
//!
//! Handles secret decryption requests and the TEE session handshake.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Response with decrypted secrets
#[derive(Debug, Deserialize)]
struct DecryptResponse {
    plaintext_secrets: String,
}

/// Secret accessor type - matches keystore's SecretAccessor enum
///
/// IMPORTANT: When adding new accessor types:
/// 1. Add variant here in worker
/// 2. Add variant in keystore-worker/src/api.rs (SecretAccessor enum)
/// 3. Add variant in coordinator/src/handlers/github.rs (SecretAccessor enum)
/// 4. Add variant in contract/src/lib.rs (SecretAccessor enum)
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum SecretAccessor {
    /// Secrets bound to a GitHub repository
    Repo {
        repo: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        branch: Option<String>,
    },
    /// Secrets bound to a specific WASM hash: the row a WasmUrl run reads
    /// under. A project or repository run reads its own row instead; locking
    /// that row to one build is the `WasmHash` access condition, not this
    /// accessor.
    WasmHash {
        hash: String,
    },
    /// Secrets bound to a project (available to all versions)
    Project {
        project_id: String,
    },
}

/// No secret exists for the accessor that was asked for.
///
/// Distinct from every other failure on purpose: it is the only one a caller
/// may respond to by asking a different question.
#[derive(Debug)]
pub struct SecretsNotFound;

impl std::fmt::Display for SecretsNotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "no secret for that accessor")
    }
}

impl std::error::Error for SecretsNotFound {}

impl SecretsNotFound {
    /// Does this failure mean "there is no such secret"?
    ///
    /// The one question a caller may answer by running anyway, with no secrets.
    /// Every other failure — a refusal, an unreadable blob, a keystore that is
    /// down — must stop the job, because running without a credential that was
    /// supposed to be there is worse than not running.
    ///
    /// Asked of the typed marker rather than of the message. The message is
    /// user-facing prose assembled from the keystore's own words, and a refusal
    /// whose text happened to contain "not found" would otherwise be read as
    /// "no secrets" — a job silently running with none, on an ACCESS-CONTROL
    /// refusal of all things.
    pub fn is_missing(error: &anyhow::Error) -> bool {
        error.downcast_ref::<SecretsNotFound>().is_some()
    }
}

/// The keystore ANSWERED about a run's signing keys with the
/// `signing_keys_refused` code: a declaration, a project or a vault it
/// judged and refused. A configuration the component's author or caller can
/// act on, as opposed to a keystore that could not be reached or could not
/// serve keys at all ([`SigningKeysUnserved`]).
#[derive(Debug)]
pub struct SigningKeysRefused;

impl std::fmt::Display for SigningKeysRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the keystore refused the declared signing keys")
    }
}

impl std::error::Error for SigningKeysRefused {}

impl SigningKeysRefused {
    pub fn is_refusal(error: &anyhow::Error) -> bool {
        error.downcast_ref::<SigningKeysRefused>().is_some()
    }
}

/// The keystore did not serve the declared signing keys, and it did not
/// refuse them either: it predates signing keys — it could not read a request
/// naming only keys, answered a keyed request with its plain "not found", or
/// answered without a `signing_keys` member — or the seeds it sent are not
/// the set the manifest declares. Nothing the component's author or caller
/// can fix: the run fails as it does when the keystore cannot be reached.
#[derive(Debug)]
pub struct SigningKeysUnserved;

impl std::fmt::Display for SigningKeysUnserved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the keystore did not serve the declared signing keys")
    }
}

impl std::error::Error for SigningKeysUnserved {}

impl SigningKeysUnserved {
    pub fn is_unserved(error: &anyhow::Error) -> bool {
        error.downcast_ref::<SigningKeysUnserved>().is_some()
    }
}

/// The `code` a keystore puts on a refusal of signing keys.
const SIGNING_KEYS_REFUSED: &str = "signing_keys_refused";

/// The signing keys a run asks for: the manifest's declarations and the job's
/// project, if it runs one — present for a run through a project, absent for
/// a direct run of a wasm URL — read off the job, never from the guest. The
/// keystore reads the kind of run off the project alone; the accounts the
/// keys belong to travel with the request as `user_account_id` and
/// `predecessor_id`, as does the build.
pub struct KeysRequest<'a> {
    pub project_id: Option<&'a str>,
    pub keys: &'a [crate::signing_keys::ManifestKey],
}

/// What one run's decrypt brought back.
pub struct RunSecrets {
    /// The secrets; `None` when the row does not exist — the case a run
    /// continues past without secrets.
    pub secrets: Option<std::collections::HashMap<String, String>>,
    /// The run's signing keys, when it asked for any.
    pub keys: Option<crate::signing_keys::SigningKeys>,
}

/// A run's secrets request, carrying its signing keys when it declares any —
/// see [`KeystoreClient::with_signing_keys`].
pub struct RunDecrypt<'a> {
    client: &'a KeystoreClient,
    keys: Option<&'a KeysRequest<'a>>,
}

impl RunSecrets {
    fn plain(secrets: std::collections::HashMap<String, String>) -> Self {
        Self { secrets: Some(secrets), keys: None }
    }
}

impl RunDecrypt<'_> {
    /// With keys: one request naming the row and the keys.
    async fn keyed(
        &self,
        keys: &KeysRequest<'_>,
        accessor: SecretAccessor,
        profile: &str,
        owner: &str,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
    ) -> Result<RunSecrets> {
        self.client
            .decrypt_keyed(Some((&accessor, profile, owner)), user_account_id, task_id, executed_wasm_sha256, predecessor_id, keys)
            .await
    }

    /// As [`KeystoreClient::decrypt_secrets_by_project`], with the run's keys.
    pub async fn decrypt_secrets_by_project(
        &self,
        project_id: &str,
        profile: &str,
        owner: &str,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
    ) -> Result<RunSecrets> {
        match self.keys {
            None => self
                .client
                .decrypt_secrets_by_project(project_id, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id)
                .await
                .map(RunSecrets::plain),
            Some(keys) => {
                let accessor = SecretAccessor::Project { project_id: project_id.to_string() };
                self.keyed(keys, accessor, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id).await
            }
        }
    }

    /// As [`KeystoreClient::decrypt_secrets_from_contract`], with the run's keys.
    pub async fn decrypt_secrets_from_contract(
        &self,
        repo: &str,
        branch: Option<&str>,
        profile: &str,
        owner: &str,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
    ) -> Result<RunSecrets> {
        match self.keys {
            None => self
                .client
                .decrypt_secrets_from_contract(repo, branch, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id)
                .await
                .map(RunSecrets::plain),
            Some(keys) => {
                let accessor = SecretAccessor::Repo { repo: repo.to_string(), branch: branch.map(|s| s.to_string()) };
                self.keyed(keys, accessor, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id).await
            }
        }
    }

    /// As [`KeystoreClient::decrypt_secrets_by_wasm_hash`], with the run's keys.
    pub async fn decrypt_secrets_by_wasm_hash(
        &self,
        wasm_hash: &str,
        profile: &str,
        owner: &str,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
    ) -> Result<RunSecrets> {
        match self.keys {
            None => self
                .client
                .decrypt_secrets_by_wasm_hash(wasm_hash, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id)
                .await
                .map(RunSecrets::plain),
            Some(keys) => {
                let accessor = SecretAccessor::WasmHash { hash: wasm_hash.to_string() };
                self.keyed(keys, accessor, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id).await
            }
        }
    }
}

/// How long an instance that refused a connection is skipped when the worker chooses where to
/// move next. There is no prober: the next request that would otherwise land on the instance is
/// the probe, and one connect timeout per window is the whole cost of a wrong guess.
const DOWN_WINDOW: Duration = Duration::from_secs(60);

/// Parse `KEYSTORE_BASE_URLS`: a comma-separated list of `http(s)://` origins, in preference
/// order. Blank entries and duplicates are dropped; an empty result is an error, because a
/// worker that silently ran without a keystore would fail every secrets job with a message
/// blaming the user's configuration.
pub fn parse_base_urls(raw: &str) -> Result<Vec<String>> {
    let mut urls: Vec<String> = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim().trim_end_matches('/');
        if entry.is_empty() {
            continue;
        }
        if !(entry.starts_with("https://") || entry.starts_with("http://")) {
            anyhow::bail!(
                "KEYSTORE_BASE_URLS entry '{}' is not an http(s):// URL",
                entry
            );
        }
        if !urls.iter().any(|u| u == entry) {
            urls.push(entry.to_string());
        }
    }
    if urls.is_empty() {
        anyhow::bail!("KEYSTORE_BASE_URLS is empty: at least one keystore URL is required");
    }
    Ok(urls)
}

/// One keystore instance and the TEE session the worker holds THERE.
///
/// Sessions live in a keystore's memory, so a session made on one instance means nothing to
/// another: every instance carries its own, established the first time the worker talks to it.
struct Instance {
    url: String,
    session_id: Mutex<Option<String>>,
    down_until: Mutex<Option<Instant>>,
}

impl Instance {
    fn new(url: String) -> Self {
        Self {
            url,
            session_id: Mutex::new(None),
            down_until: Mutex::new(None),
        }
    }

    fn session(&self) -> Option<String> {
        self.session_id.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn set_session(&self, id: Option<String>) {
        *self.session_id.lock().unwrap_or_else(|p| p.into_inner()) = id;
    }

    fn is_down(&self, now: Instant) -> bool {
        self.down_until
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .map_or(false, |until| until > now)
    }

    fn mark_down(&self) {
        *self.down_until.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now() + DOWN_WINDOW);
    }

    fn mark_up(&self) {
        *self.down_until.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

/// Why a call to one instance ended, as far as choosing the next instance is concerned.
enum CallError {
    /// The instance never answered: connection refused, DNS failure, connection dropped before a
    /// response. The request can be repeated on another instance.
    Unreachable(anyhow::Error),
    /// The instance took the request and did not answer in time. It may still be working on it,
    /// so THIS request is not repeated elsewhere — but the instance is marked down, so the next
    /// request goes to the next one. Without that an instance that accepts connections and never
    /// answers (a wedged process, a frozen CVM behind a live gateway) would hold every worker on
    /// it forever, while the other instance idles.
    Stalled(anyhow::Error),
    /// The instance answered, or the failure is not about reaching it, so moving elsewhere would
    /// not help.
    Final(anyhow::Error),
}

/// Whether a `send()` failure means "this instance is unreachable".
///
/// Every keystore endpoint the worker calls is pure computation on the request, so a request
/// that never produced a response is safe to repeat elsewhere. A request timeout is the one
/// exception: the instance may well be working on it, and moving the same work to a second
/// instance is how a slow dependency turns into a doubled load (see [`is_stall`]).
///
/// A connect failure is always a move, including a connect TIMEOUT: a host that is powered off
/// or frozen drops the SYN and reqwest reports that as both `is_connect()` and `is_timeout()`.
/// Nothing was sent, so nothing can be doubled — and this is the dead-server case failover
/// exists for.
fn should_failover(e: &reqwest::Error) -> bool {
    e.is_connect() || !e.is_timeout()
}

/// A timeout after the connection was made: the request was sent, the answer never came.
fn is_stall(e: &reqwest::Error) -> bool {
    e.is_timeout() && !e.is_connect()
}

/// Status and body of a keystore reply, read in full so the session-expiry check and the caller's
/// own status mapping can both look at it.
struct Reply {
    status: reqwest::StatusCode,
    body: Vec<u8>,
}

impl Reply {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Client for keystore worker API
///
/// Holds every keystore instance the worker may use, in preference order. Requests go to the
/// current instance until it becomes unreachable or stops answering; then the next reachable one
/// becomes current and stays current. Sticky on purpose: an instance that died is not tried again
/// unless the one serving now dies too, so a dead instance costs one connect timeout, not one per
/// request, and a wedged one costs one request timeout.
#[derive(Clone)]
pub struct KeystoreClient {
    instances: Arc<Vec<Instance>>,
    /// Index of the instance requests go to first.
    current: Arc<AtomicUsize>,
    auth_token: String,
    http_client: reqwest::Client,
    /// TEE signing key: with it the worker establishes a session on an instance it has not
    /// talked to yet, and re-establishes one the keystore has forgotten.
    tee_signing_info: Option<Arc<near_crypto::SecretKey>>,
}

/// What a caller is told when the keystore refuses a secret's access condition.
///
/// The keystore's OWN sentence is kept. It is the only party that knows why the
/// condition refused, and the one reason it can name — a time limit that has
/// passed — is also the one the owner fixes by re-granting rather than the
/// caller by asking to be let in. A fixed string here made a lapsed grant read
/// exactly like never having been granted at all.
fn access_denied_message(error_text: &str) -> String {
    let said = serde_json::from_str::<serde_json::Value>(error_text)
        .ok()
        .and_then(|json| {
            json.get("error")
                .and_then(|e| e.as_str())
                .map(|e| e.trim().trim_end_matches('.').to_string())
        })
        .filter(|e| !e.is_empty());
    match said {
        Some(said) => format!("{said}. Check the access conditions configured by the secret owner."),
        None => "Access to secrets denied. Check access conditions.".to_string(),
    }
}

impl KeystoreClient {
    /// Create new keystore client over one or more instances (see [`parse_base_urls`]).
    pub fn new(base_urls: Vec<String>, auth_token: String) -> Result<Self> {
        if base_urls.is_empty() {
            anyhow::bail!("KEYSTORE_BASE_URLS is empty: at least one keystore URL is required");
        }
        Ok(Self {
            instances: Arc::new(base_urls.into_iter().map(Instance::new).collect()),
            current: Arc::new(AtomicUsize::new(0)),
            auth_token,
            http_client: Self::http_client(Duration::from_secs(30)),
            tee_signing_info: None,
        })
    }

    fn http_client(timeout: Duration) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .build()
            .expect("Failed to build keystore HTTP client")
    }

    /// Set TEE signing info for auto-reconnect on session expiry
    pub fn set_tee_signing_info(&mut self, secret_key: near_crypto::SecretKey) {
        self.tee_signing_info = Some(Arc::new(secret_key));
    }

    /// The instance requests currently go to, with the TEE session held on it.
    ///
    /// For clients that are handed a fixed endpoint at job start (storage, VRF): they keep talking
    /// to this instance for the job's lifetime, so a failover mid-job fails that job — the same
    /// accepted behaviour as a keystore restart mid-job.
    pub fn current_endpoint(&self) -> (String, Option<String>) {
        let inst = &self.instances[self.current.load(Ordering::Relaxed)];
        (inst.url.clone(), inst.session())
    }

    /// Test hook: pretend a session already exists on instance `i`.
    #[cfg(test)]
    fn set_session_for_test(&self, i: usize, session_id: &str) {
        self.instances[i].set_session(Some(session_id.to_string()));
    }

    /// Test hook: a short request timeout, so a silent instance fails in test time.
    #[cfg(test)]
    fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.http_client = Self::http_client(timeout);
        self
    }

    /// Test hook: a short connect timeout, so a black-holed instance fails in test time.
    #[cfg(test)]
    fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(timeout)
            .build()
            .expect("Failed to build keystore HTTP client");
        self
    }

    /// Instances in the order a request should try them: the current one first, then the rest in
    /// list order, skipping instances marked down. When every instance is marked down the marks
    /// are ignored — a request must go somewhere, and the failure it gets is the honest answer.
    fn candidates(&self) -> Vec<usize> {
        let n = self.instances.len();
        let start = self.current.load(Ordering::Relaxed) % n;
        let order: Vec<usize> = (0..n).map(|k| (start + k) % n).collect();
        let now = Instant::now();
        let up: Vec<usize> = order
            .iter()
            .copied()
            .filter(|&i| !self.instances[i].is_down(now))
            .collect();
        if up.is_empty() {
            order
        } else {
            up
        }
    }

    /// Record that instance `i` answered: it becomes current and loses any down mark.
    fn settle_on(&self, i: usize) {
        self.instances[i].mark_up();
        self.current.store(i, Ordering::Relaxed);
    }

    /// Record that instance `i` did not answer, and say so once per event.
    fn leave(&self, i: usize, what: &str, error: &anyhow::Error) {
        self.instances[i].mark_down();
        tracing::warn!(
            keystore = %self.instances[i].url,
            error = %format!("{error:#}"),
            "keystore instance did not answer during {}; moving to the next one",
            what
        );
    }

    /// Record that instance `i` took a request and never answered it: this request fails, the
    /// next one goes elsewhere.
    fn stall(&self, i: usize, what: &str, error: &anyhow::Error) {
        self.instances[i].mark_down();
        tracing::warn!(
            keystore = %self.instances[i].url,
            error = %format!("{error:#}"),
            "keystore instance did not answer {} in time; this request fails, the next one goes to the next instance",
            what
        );
    }

    /// The error a caller gets when no instance answered. It carries the transport reasons but
    /// not the instance hostnames: job errors reach the user, the hostnames belong in the worker
    /// log, which `leave` writes per instance.
    fn all_unreachable(what: &str, errors: Vec<anyhow::Error>) -> anyhow::Error {
        let detail: Vec<String> = errors.iter().map(|e| format!("{e:#}")).collect();
        anyhow::anyhow!(
            "{} failed: every keystore instance is unreachable ({} tried: {})",
            what,
            errors.len(),
            detail.join("; ")
        )
    }

    /// Register a TEE session with the keystore via challenge-response.
    ///
    /// 1. POST {keystore}/tee-challenge → get challenge
    /// 2. Sign challenge with the worker's key
    /// 3. POST {keystore}/register-tee → get session_id
    ///
    /// Direct, not via the coordinator proxy, so the session lands on the instance that will
    /// handle the worker's requests. Tries the instances in preference order and settles on the
    /// first one that answers; an instance that rejects the handshake (an HTTP error) stops the
    /// attempt, since the next instance would reject the same key for the same reason. One that
    /// does not answer at all — unreachable or silent — is left for the next: a handshake has
    /// nothing to double, an unused challenge is harmless, and a worker must not fail to start
    /// because the first instance in its list is wedged.
    pub async fn register_tee_session(
        &self,
        secret_key: &near_crypto::SecretKey,
    ) -> Result<String> {
        let mut unreachable = Vec::new();
        for i in self.candidates() {
            match self.register_session_on(i, secret_key).await {
                Ok(session_id) => {
                    self.settle_on(i);
                    return Ok(session_id);
                }
                Err(CallError::Unreachable(e)) | Err(CallError::Stalled(e)) => {
                    self.leave(i, "TEE session registration", &e);
                    unreachable.push(e);
                }
                Err(CallError::Final(e)) => return Err(e),
            }
        }
        Err(Self::all_unreachable("TEE session registration", unreachable))
    }

    /// The challenge-response handshake against instance `i`; stores the session on it.
    async fn register_session_on(
        &self,
        i: usize,
        secret_key: &near_crypto::SecretKey,
    ) -> std::result::Result<String, CallError> {
        let inst = &self.instances[i];
        // NEAR canonical form carries the scheme (ed25519 / ml-dsa-65) in its prefix.
        let near_public_key = secret_key.public_key().to_string();

        // 1. Request challenge
        let url = format!("{}/tee-challenge", inst.url);
        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .send()
            .await
            .map_err(|e| Self::send_error(e, "Failed to request TEE challenge from keystore"))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(CallError::Final(anyhow::anyhow!(
                "Keystore TEE challenge failed ({}): {}",
                status,
                text
            )));
        }

        #[derive(serde::Deserialize)]
        struct ChallengeResponse {
            challenge: String,
        }
        let challenge_resp: ChallengeResponse = response
            .json()
            .await
            .context("Failed to parse keystore TEE challenge")
            .map_err(CallError::Final)?;

        // 2. Sign challenge (ed25519 or ml-dsa-65), send signature in NEAR form.
        let challenge_bytes = hex::decode(&challenge_resp.challenge)
            .context("Invalid challenge hex")
            .map_err(CallError::Final)?;
        let signature = secret_key.sign(&challenge_bytes).to_string();

        // 3. Register with signed challenge
        let url = format!("{}/register-tee", inst.url);
        let response = self
            .http_client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .json(&serde_json::json!({
                "public_key": near_public_key,
                "challenge": challenge_resp.challenge,
                "signature": signature,
            }))
            .send()
            .await
            .map_err(|e| Self::send_error(e, "Failed to submit keystore TEE registration"))?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(CallError::Final(anyhow::anyhow!(
                "Keystore TEE registration failed ({}): {}",
                status,
                text
            )));
        }

        #[derive(serde::Deserialize)]
        struct RegisterResponse {
            session_id: String,
        }
        let register_resp: RegisterResponse = response
            .json()
            .await
            .context("Failed to parse keystore TEE registration response")
            .map_err(CallError::Final)?;

        inst.set_session(Some(register_resp.session_id.clone()));
        tracing::info!(
            keystore = %inst.url,
            session_id = %register_resp.session_id,
            "TEE session registered directly with keystore"
        );

        Ok(register_resp.session_id)
    }

    /// Classify a `send()` failure for the failover loop. The URL is stripped from the reqwest
    /// error: the instance is named in the worker log by `leave`, and the error text may end up in
    /// a job's user-facing failure.
    fn send_error(e: reqwest::Error, what: &str) -> CallError {
        let stalled = is_stall(&e);
        let failover = should_failover(&e);
        let err = anyhow::Error::new(e.without_url()).context(what.to_string());
        if stalled {
            CallError::Stalled(err)
        } else if failover {
            CallError::Unreachable(err)
        } else {
            CallError::Final(err)
        }
    }

    /// Check if an HTTP error response indicates TEE session expiry.
    /// Parses JSON `{"error": "..."}` and checks for session-related keywords.
    fn is_tee_session_expired(status: reqwest::StatusCode, body: &str) -> bool {
        if status != reqwest::StatusCode::FORBIDDEN {
            return false;
        }
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(error) = json.get("error").and_then(|e| e.as_str()) {
                return error.contains("session not found") || error.contains("session expired");
            }
        }
        // Fallback: plain text match
        body.contains("session not found")
    }

    /// (Re-)establish the TEE session on instance `i`, if there is a key to do it with.
    ///
    /// The "no key" case is a `Final` error on purpose: a worker without signing info cannot
    /// make a session anywhere, so the next instance would fail identically.
    async fn establish_session_on(&self, i: usize) -> std::result::Result<(), CallError> {
        let secret_key = match self.tee_signing_info.as_ref() {
            Some(key) => key.clone(),
            None => {
                return Err(CallError::Final(anyhow::anyhow!(
                    "No TEE signing info for reconnect"
                )))
            }
        };
        self.register_session_on(i, &secret_key).await.map(|_| ())
    }

    /// POST a JSON body to the keystore and read the whole reply.
    ///
    /// Three recoveries live here, in this order, so every business endpoint gets all of them:
    ///
    /// 1. **No session yet on this instance** (first contact after a failover): establish one
    ///    before sending, when the worker has a signing key. Without one the request goes out
    ///    with the bearer token only, as it always did outside TEE mode.
    /// 2. **Instance unreachable** (connection refused, DNS, connect timeout, dropped before a
    ///    reply): mark it down and repeat the request on the next candidate. A request that was
    ///    sent and timed out is NOT repeated (the instance may be working on it) but marks the
    ///    instance down all the same, so the NEXT request goes to the next candidate; see
    ///    [`should_failover`] and [`is_stall`]. The handshake in step 1 is repeated on a timeout
    ///    too — it has nothing to double.
    /// 3. **Session expired** (the keystore's own 403): the keystore restarted and forgot every
    ///    session at once. Re-handshake on the same instance and repeat the request there once.
    ///
    /// Deliberately NOT covering `/storage/*` and `/vrf/generate`: those run inside a WASI
    /// execution on blocking clients that were handed an endpoint by value at job start, so a
    /// keystore restart or failover mid-job fails that job — accepted behaviour, not an oversight.
    ///
    /// `build_body` is a closure so every attempt re-serializes from scratch rather than reusing
    /// a half-consumed request. A non-success status other than session expiry is returned as a
    /// reply, not an error: `/decrypt` maps keystore statuses into user-facing messages itself.
    async fn post_json<T: Serialize>(
        &self,
        path: &str,
        build_body: impl Fn() -> Result<T>,
        what: &str,
        vault_id: Option<&str>,
    ) -> Result<Reply> {
        let mut unreachable = Vec::new();
        for i in self.candidates() {
            let inst = &self.instances[i];

            if self.tee_signing_info.is_some() && inst.session().is_none() {
                match self.establish_session_on(i).await {
                    Ok(()) => {}
                    Err(CallError::Unreachable(e)) | Err(CallError::Stalled(e)) => {
                        self.leave(i, what, &e);
                        unreachable.push(e);
                        continue;
                    }
                    Err(CallError::Final(e)) => {
                        tracing::error!(keystore = %inst.url, error = %format!("{e:#}"), "TEE session could not be made");
                        return Err(e.context(format!(
                            "{} needs a TEE session and none could be made",
                            what
                        )))
                    }
                }
            }

            let reply = match self.post_once(i, path, &build_body, what, vault_id).await {
                Ok(reply) => reply,
                Err(CallError::Unreachable(e)) => {
                    self.leave(i, what, &e);
                    unreachable.push(e);
                    continue;
                }
                Err(CallError::Stalled(e)) => {
                    self.stall(i, what, &e);
                    return Err(e);
                }
                Err(CallError::Final(e)) => return Err(e),
            };

            let expired = reply.status == reqwest::StatusCode::FORBIDDEN
                && Self::is_tee_session_expired(reply.status, &reply.text());
            if !expired {
                self.settle_on(i);
                return Ok(reply);
            }

            // The keystore answered, so it is up; it just no longer knows us. Unlike the first
            // handshake above, a reconnect that cannot happen is surfaced with the keystore's
            // status attached: "we got a 403 and could not re-handshake" names both halves.
            let status = reply.status;
            match self.establish_session_on(i).await {
                Ok(()) => {}
                Err(CallError::Unreachable(e)) | Err(CallError::Stalled(e)) => {
                    self.leave(i, what, &e);
                    unreachable.push(e);
                    continue;
                }
                Err(CallError::Final(e)) => {
                    return Err(e.context(format!(
                        "{} got {} and the TEE session reconnect failed",
                        what, status
                    )))
                }
            }

            // The retry carries the SAME scope. Dropping it here would silently reach for the
            // default master on the second attempt, which reads a vault customer's blob with the
            // wrong key and fails in a way that looks like corruption rather than a missing header.
            let retry = match self.post_once(i, path, &build_body, what, vault_id).await {
                Ok(reply) => reply,
                Err(CallError::Unreachable(e)) => {
                    self.leave(i, what, &e);
                    unreachable.push(e);
                    continue;
                }
                Err(CallError::Stalled(e)) => {
                    self.stall(i, what, &e);
                    return Err(e);
                }
                Err(CallError::Final(e)) => return Err(e),
            };
            if !retry.status.is_success() {
                anyhow::bail!(
                    "{} failed again after session reconnect ({}): {}",
                    what,
                    retry.status,
                    retry.text()
                );
            }
            self.settle_on(i);
            return Ok(retry);
        }
        Err(Self::all_unreachable(what, unreachable))
    }

    /// One POST to instance `i`, with the bearer token, the instance's session and the vault
    /// scope, read to the end.
    async fn post_once<T: Serialize>(
        &self,
        i: usize,
        path: &str,
        build_body: &impl Fn() -> Result<T>,
        what: &str,
        vault_id: Option<&str>,
    ) -> std::result::Result<Reply, CallError> {
        let inst = &self.instances[i];
        let url = format!("{}{}", inst.url, path);
        let body = build_body().map_err(CallError::Final)?;
        let response = Self::add_vault_header(self.add_auth_headers(i, self.http_client.post(&url)), vault_id)
            .json(&body)
            .send()
            .await
            .map_err(|e| Self::send_error(e, &format!("Failed to send {} request", what)))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| Self::send_error(e, &format!("Failed to read {} response", what)))?;
        Ok(Reply { status, body })
    }

    /// Parse a successful decrypt response into a HashMap of env vars.
    fn parse_decrypt_response(response_bytes: &[u8]) -> Result<std::collections::HashMap<String, String>> {
        let decrypt_response: DecryptResponse = serde_json::from_slice(response_bytes)
            .context("Failed to parse decrypt response")?;
        Self::parse_plaintext_secrets(&decrypt_response.plaintext_secrets)
    }

    /// Decrypted secrets, base64 of a JSON object of strings, as env vars.
    fn parse_plaintext_secrets(plaintext_secrets: &str) -> Result<std::collections::HashMap<String, String>> {
        let plaintext = base64::decode(plaintext_secrets)
            .context("Failed to decode plaintext secrets")?;
        let plaintext_str = String::from_utf8(plaintext)
            .context("Invalid secrets format: not valid UTF-8 text")?;
        serde_json::from_str(&plaintext_str)
            .context("Invalid secrets format: must be a JSON object with string key-value pairs")
    }

    /// Add the vault scope, when the material belongs to one.
    ///
    /// Absent header means the default master, which is where every key of a
    /// wallet without a vault lives. The header must match how the blob was
    /// written: a mismatch does not corrupt anything, it simply fails to
    /// decrypt — loud, but a lockout.
    fn add_vault_header(
        builder: reqwest::RequestBuilder,
        vault_id: Option<&str>,
    ) -> reqwest::RequestBuilder {
        match vault_id.map(str::trim).filter(|v| !v.is_empty()) {
            Some(vault) => builder.header("X-Customer-Vault", vault),
            None => builder,
        }
    }

    /// Add auth headers: Bearer token + the session held on instance `i`, if any
    fn add_auth_headers(&self, i: usize, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let builder = builder.header("Authorization", format!("Bearer {}", self.auth_token));
        match self.instances[i].session() {
            Some(session_id) => builder.header("X-TEE-Session", session_id),
            None => builder,
        }
    }

    /// Get keystore public key (for testing/verification)
    #[allow(dead_code)]
    pub async fn get_public_key(&self) -> Result<String> {
        let (base_url, _) = self.current_endpoint();
        let url = format!("{}/pubkey", base_url);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .context("Failed to get public key")?;

        let data: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse pubkey response")?;

        let pubkey_hex = data["public_key_hex"]
            .as_str()
            .context("Missing public_key_hex in response")?
            .to_string();

        Ok(pubkey_hex)
    }

    /// Decrypt secrets from contract using unified accessor format
    ///
    /// This method:
    /// 1. Calls keystore /decrypt with accessor (Repo or WasmHash)
    /// 2. Keystore reads secrets from NEAR contract
    /// 3. Keystore validates access conditions (user_account_id as caller;
    ///    executed_wasm_sha256 as the build a `WasmHash` leaf is judged
    ///    against; predecessor_id as the calling account a `Predecessor`
    ///    leaf is judged against)
    /// 4. Keystore decrypts using derived key for seed
    /// 5. Returns HashMap of environment variables
    ///
    /// Note: This requires keystore to have NEAR RPC access configured
    pub async fn decrypt_secrets(
        &self,
        accessor: SecretAccessor,
        profile: &str,
        owner: &str,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
    ) -> Result<std::collections::HashMap<String, String>> {
        let accessor_desc = match &accessor {
            SecretAccessor::Repo { repo, branch } => {
                format!("Repo(repo={}, branch={:?})", repo, branch)
            }
            SecretAccessor::WasmHash { hash } => {
                format!("WasmHash({})", hash)
            }
            SecretAccessor::Project { project_id } => {
                format!("Project({})", project_id)
            }
        };

        tracing::info!(
            "🔑 decrypt_secrets called: accessor={}, profile={}, owner={}, task_id={:?}",
            accessor_desc, profile, owner, task_id
        );

        // Prepare request with accessor
        #[derive(Debug, Clone, Serialize)]
        struct DecryptRequest {
            accessor: SecretAccessor,
            profile: String,
            owner: String,
            user_account_id: String,
            task_id: Option<String>,
            /// SHA-256 of the bytes this worker is about to run, measured on
            /// the loaded buffer — what a `WasmHash` access condition is
            /// judged against. Never a value the task or the guest supplied.
            executed_wasm_sha256: Option<String>,
            /// The account that called the contract — the receipt's
            /// predecessor on chain, the payer over HTTPS — what a
            /// `Predecessor` access condition is judged against. From the
            /// contract's event, never from the task body or the guest.
            predecessor_id: Option<String>,
        }

        let request = DecryptRequest {
            accessor: accessor.clone(),
            profile: profile.to_string(),
            owner: owner.to_string(),
            user_account_id: user_account_id.to_string(),
            task_id: task_id.map(|s| s.to_string()),
            executed_wasm_sha256: executed_wasm_sha256.map(|s| s.to_string()),
            predecessor_id: predecessor_id.map(|s| s.to_string()),
        };

        let (keystore, tee_session) = self.current_endpoint();
        tracing::info!(
            keystore = %keystore,
            tee_session_id = ?tee_session,
            accessor = %accessor_desc,
            profile = %profile,
            owner = %owner,
            task_id = ?task_id,
            "🔑 Sending decrypt request to keystore"
        );

        // Session establishment, failover and the expired-session re-handshake all happen inside.
        let reply = self
            .post_json("/decrypt", || Ok(request.clone()), "Decrypt", None)
            .await?;

        if !reply.status.is_success() {
            return Err(self.secrets_error(reply.status, &reply.text(), &accessor));
        }

        let env_vars = Self::parse_decrypt_response(&reply.body)?;

        tracing::info!(
            accessor = %accessor_desc,
            profile = %profile,
            env_count = env_vars.len(),
            "Successfully decrypted secrets"
        );

        Ok(env_vars)
    }

    /// A secret row's refusal as the run reports it: the keystore's status read
    /// into a user-facing sentence, with "there is no such secret" typed as
    /// [`SecretsNotFound`] — the one refusal a run may continue past.
    fn secrets_error(&self, status: reqwest::StatusCode, error_text: &str, accessor: &SecretAccessor) -> anyhow::Error {
        let truncated_body: String = error_text.chars().take(500).collect();
        tracing::error!(
            status = %status,
            error_body = %truncated_body,
            keystore = %self.current_endpoint().0,
            "🔒 Keystore /decrypt failed"
        );

        // Parse user-friendly error message based on accessor type
        let context = match accessor {
            SecretAccessor::Repo { .. } => "repository, branch, and profile",
            SecretAccessor::WasmHash { .. } => "WASM hash and profile",
            SecretAccessor::Project { .. } => "project ID and profile",
        };

        let user_message = if status == 400 {
            if error_text.contains("not found") {
                format!("Secrets not found. Please check that secrets exist for this {}.", context)
            } else {
                "Invalid secrets request. Please check your secrets configuration.".to_string()
            }
        } else if status == 401 {
            access_denied_message(error_text)
        } else if status == 404 {
            format!("Secrets not found for this {}.", context)
        } else {
            "Failed to decrypt secrets. Please check your secrets configuration.".to_string()
        };

        // A typed marker for "there is no such secret", so a caller can
        // tell it apart from "the keystore refused" or "the keystore is
        // down". String-matching the message from outside would break the
        // moment the wording changed, and the caller deciding to fall back
        // must never do so because a keystore was merely unreachable.
        let not_found = status == 404 || (status == 400 && error_text.contains("not found"));
        if not_found {
            return anyhow::Error::new(SecretsNotFound).context(user_message);
        }
        anyhow::anyhow!("{}", user_message)
    }

    /// Decrypt secrets from contract (convenience wrapper for Repo accessor)
    ///
    /// This is a convenience method that wraps decrypt_secrets with Repo accessor.
    pub async fn decrypt_secrets_from_contract(
        &self,
        repo: &str,
        branch: Option<&str>,
        profile: &str,
        owner: &str,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
    ) -> Result<std::collections::HashMap<String, String>> {
        let accessor = SecretAccessor::Repo {
            repo: repo.to_string(),
            branch: branch.map(|s| s.to_string()),
        };
        self.decrypt_secrets(accessor, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id).await
    }

    /// Decrypt secrets from contract by WASM hash (convenience wrapper for WasmHash accessor)
    ///
    /// This is a convenience method that wraps decrypt_secrets with WasmHash accessor.
    pub async fn decrypt_secrets_by_wasm_hash(
        &self,
        wasm_hash: &str,
        profile: &str,
        owner: &str,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
    ) -> Result<std::collections::HashMap<String, String>> {
        let accessor = SecretAccessor::WasmHash {
            hash: wasm_hash.to_string(),
        };
        self.decrypt_secrets(accessor, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id).await
    }

    /// Decrypt secrets from contract by project ID (convenience wrapper for Project accessor)
    ///
    /// This is a convenience method that wraps decrypt_secrets with Project accessor.
    /// All versions of the project can use the same secrets.
    pub async fn decrypt_secrets_by_project(
        &self,
        project_id: &str,
        profile: &str,
        owner: &str,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
    ) -> Result<std::collections::HashMap<String, String>> {
        let accessor = SecretAccessor::Project {
            project_id: project_id.to_string(),
        };
        self.decrypt_secrets(accessor, profile, owner, user_account_id, task_id, executed_wasm_sha256, predecessor_id).await
    }

    /// Scope the next decrypt to a run that declares signing keys.
    ///
    /// With `keys`, the secrets request of the run carries them too, and the
    /// one answer brings both; without, the calls are exactly the plain
    /// secrets requests.
    pub fn with_signing_keys<'a>(&'a self, keys: Option<&'a KeysRequest<'a>>) -> RunDecrypt<'a> {
        RunDecrypt { client: self, keys }
    }

    /// The signing keys of a run that names no secret row: one `/decrypt`
    /// request carrying the keys alone, with both accounts of the run —
    /// `user_account_id` (the signer) and `predecessor_id` (the calling
    /// account), exactly as a secrets request carries them.
    pub async fn derive_signing_keys(
        &self,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: &str,
        predecessor_id: Option<&str>,
        keys: &KeysRequest<'_>,
    ) -> Result<crate::signing_keys::SigningKeys> {
        let run = self
            .decrypt_keyed(None, user_account_id, task_id, Some(executed_wasm_sha256), predecessor_id, keys)
            .await?;
        run.keys.ok_or_else(|| anyhow::anyhow!("the keystore's answer carries no signing keys"))
    }

    /// One `/decrypt` request naming the run's signing keys and, when the run
    /// has one, its secret row.
    ///
    /// The keystore judges the two independently. A refusal of the keys is
    /// typed [`SigningKeysRefused`]; a keystore that predates signing keys, or
    /// serves other seeds than the declared ones, is [`SigningKeysUnserved`];
    /// a refusal of the row reads exactly as it does for a secrets-only
    /// request. A row that does not exist comes back as `secrets: None` beside
    /// the keys — the case a secrets-only request answers with
    /// [`SecretsNotFound`] and the run continues past.
    ///
    /// The response body holds the seeds in hex and the plaintext secrets; it
    /// is wiped once read, and the seeds live on only inside the returned
    /// [`crate::signing_keys::SigningKeys`].
    async fn decrypt_keyed(
        &self,
        row: Option<(&SecretAccessor, &str, &str)>,
        user_account_id: &str,
        task_id: Option<&str>,
        executed_wasm_sha256: Option<&str>,
        predecessor_id: Option<&str>,
        keys: &KeysRequest<'_>,
    ) -> Result<RunSecrets> {
        use zeroize::Zeroize;

        #[derive(Clone, Serialize)]
        struct KeyedRequest<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            accessor: Option<&'a SecretAccessor>,
            #[serde(skip_serializing_if = "Option::is_none")]
            profile: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            owner: Option<&'a str>,
            user_account_id: &'a str,
            task_id: Option<&'a str>,
            executed_wasm_sha256: Option<&'a str>,
            predecessor_id: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            project_id: Option<&'a str>,
            signing_keys: &'a [crate::signing_keys::ManifestKey],
        }
        #[derive(Deserialize)]
        struct KeyedResponse {
            #[serde(default)]
            secrets: Option<SecretsPart>,
            #[serde(default)]
            signing_keys: Option<std::collections::BTreeMap<String, crate::signing_keys::SeedHex>>,
        }
        #[derive(Deserialize)]
        #[serde(tag = "status", rename_all = "snake_case")]
        enum SecretsPart {
            Decrypted { plaintext_secrets: String },
            NotFound {},
        }

        let request = KeyedRequest {
            accessor: row.map(|r| r.0),
            profile: row.map(|r| r.1),
            owner: row.map(|r| r.2),
            user_account_id,
            task_id,
            executed_wasm_sha256,
            predecessor_id,
            project_id: keys.project_id,
            signing_keys: keys.keys,
        };
        tracing::info!(
            project_id = ?keys.project_id,
            predecessor = ?predecessor_id,
            caller = %user_account_id,
            signing_keys = ?keys.keys.iter().map(|k| k.path.as_str()).collect::<Vec<_>>(),
            secret_row = row.is_some(),
            task_id = ?task_id,
            "🔑 Sending decrypt request with signing keys to keystore"
        );

        let mut reply = self
            .post_json("/decrypt", || Ok(request.clone()), "Decrypt with signing keys", None)
            .await?;

        if !reply.status.is_success() {
            let status = reply.status;
            let text = reply.text();
            let body = serde_json::from_str::<serde_json::Value>(&text).ok();
            let code = body.as_ref().and_then(|v| v.get("code")).and_then(|c| c.as_str());
            if code == Some(SIGNING_KEYS_REFUSED) {
                let said: String = body
                    .as_ref()
                    .and_then(|v| v.get("error"))
                    .and_then(|e| e.as_str())
                    .unwrap_or_default()
                    .chars()
                    .take(500)
                    .collect();
                tracing::error!(status = %status, error_body = %said, "🔒 Keystore refused the signing keys");
                return Err(anyhow::Error::new(SigningKeysRefused)
                    .context(format!("The keystore refused the signing keys this component declares ({status}): {said}")));
            }
            let Some((accessor, _, _)) = row else {
                let said: String = text.chars().take(500).collect();
                if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
                    return Err(anyhow::Error::new(SigningKeysUnserved).context(format!(
                        "The keystore could not read a request naming only signing keys ({status}): it predates \
                         signing keys. {said}"
                    )));
                }
                anyhow::bail!("The keystore could not serve the signing keys this component declares ({status}): {said}");
            };
            let error = self.secrets_error(status, &text, accessor);
            if SecretsNotFound::is_missing(&error) {
                // A keystore that knows signing keys reports a missing row in
                // its answer, beside the keys; one that answers "not found" as
                // a refusal never read them.
                return Err(anyhow::Error::new(SigningKeysUnserved).context(
                    "The keystore answered a request carrying signing keys with a plain \"not found\": it \
                     predates signing keys. The run was refused rather than started without them.",
                ));
            }
            return Err(error);
        }

        let parsed = serde_json::from_slice::<KeyedResponse>(&reply.body);
        reply.body.zeroize();
        let parsed = parsed.context("Failed to parse the keystore's answer with signing keys")?;
        let seeds = parsed.signing_keys.ok_or_else(|| {
            anyhow::Error::new(SigningKeysUnserved).context(
                "The keystore answered without the signing keys this component declares: it predates \
                 signing keys. The run was refused rather than started without them.",
            )
        })?;
        let signing_keys = crate::signing_keys::SigningKeys::from_keystore(keys.keys, seeds)
            .map_err(|m| anyhow::Error::new(SigningKeysUnserved).context(m))?;
        tracing::debug!(keys = ?signing_keys, "Signing keys received");

        let secrets = match (row, parsed.secrets) {
            (None, None) => None,
            (None, Some(_)) => anyhow::bail!("The keystore answered with secrets to a request that named none"),
            (Some(_), None) => anyhow::bail!("The keystore's answer carries no outcome for the secret row it was asked for"),
            (Some(_), Some(SecretsPart::NotFound {})) => None,
            (Some(_), Some(SecretsPart::Decrypted { plaintext_secrets })) => {
                Some(Self::parse_plaintext_secrets(&plaintext_secrets)?)
            }
        };
        Ok(RunSecrets { secrets, keys: Some(signing_keys) })
    }

    /// Encrypt data using keystore's derived key
    ///
    /// Used for TopUp flow to re-encrypt Payment Key data with updated balance.
    ///
    /// # Arguments
    /// * `seed` - Seed for key derivation (format: "system:payment_key:{owner}:{nonce}")
    /// * `plaintext` - Raw bytes to encrypt
    ///
    /// # Returns
    /// * `Ok(encrypted_base64)` - Base64 encoded encrypted data
    pub async fn encrypt(
        &self,
        seed: &str,
        plaintext: &[u8],
        vault_id: Option<&str>,
    ) -> Result<String> {
        tracing::info!(
            seed = %seed,
            plaintext_len = plaintext.len(),
            "🔐 Encrypting data via keystore"
        );

        // Prepare request
        #[derive(Debug, Serialize)]
        struct EncryptRequest {
            seed: String,
            plaintext_base64: String,
        }

        #[derive(Debug, Deserialize)]
        struct EncryptResponse {
            encrypted_base64: String,
        }

        let plaintext_base64 = base64::encode(plaintext);

        let reply = self
            .post_json(
                "/encrypt",
                || {
                    Ok(EncryptRequest {
                        seed: seed.to_string(),
                        plaintext_base64: plaintext_base64.clone(),
                    })
                },
                "Encrypt",
                vault_id,
            )
            .await?;
        if !reply.status.is_success() {
            anyhow::bail!("Encrypt request failed ({}): {}", reply.status, reply.text());
        }

        let encrypt_response: EncryptResponse = serde_json::from_slice(&reply.body)
            .context("Failed to parse encrypt response")?;

        tracing::info!(
            seed = %seed,
            encrypted_len = encrypt_response.encrypted_base64.len(),
            "Successfully encrypted data"
        );

        Ok(encrypt_response.encrypted_base64)
    }

    /// Decrypt raw encrypted data using keystore's derived key
    ///
    /// Used for TopUp flow to decrypt Payment Key data.
    ///
    /// # Arguments
    /// * `seed` - Seed for key derivation (format: "system:payment_key:{owner}:{nonce}")
    /// * `encrypted_base64` - Base64 encoded encrypted data
    ///
    /// # Returns
    /// * `Ok(plaintext)` - Decrypted bytes
    pub async fn decrypt_raw(
        &self,
        seed: &str,
        encrypted_base64: &str,
        vault_id: Option<&str>,
    ) -> Result<Vec<u8>> {
        tracing::info!(
            seed = %seed,
            encrypted_len = encrypted_base64.len(),
            "🔓 Decrypting raw data via keystore"
        );

        // For raw decryption, we need a different approach
        // The keystore's /decrypt endpoint expects accessor/profile/owner
        // For Payment Keys, we need to use the System accessor

        // For TopUp, we pass encrypted data directly (from the event)
        // and keystore decrypts using the seed
        #[derive(Debug, Serialize)]
        struct DecryptRawRequest {
            seed: String,
            encrypted_base64: String,
        }

        #[derive(Debug, Deserialize)]
        struct DecryptRawResponse {
            plaintext_base64: String,
        }

        let reply = self
            .post_json(
                "/decrypt-raw",
                || {
                    Ok(DecryptRawRequest {
                        seed: seed.to_string(),
                        encrypted_base64: encrypted_base64.to_string(),
                    })
                },
                "Decrypt-raw",
                vault_id,
            )
            .await?;
        if !reply.status.is_success() {
            anyhow::bail!("Decrypt-raw request failed ({}): {}", reply.status, reply.text());
        }

        let decrypt_response: DecryptRawResponse = serde_json::from_slice(&reply.body)
            .context("Failed to parse decrypt-raw response")?;

        let plaintext = base64::decode(&decrypt_response.plaintext_base64)
            .context("Failed to decode plaintext from base64")?;

        tracing::info!(
            seed = %seed,
            plaintext_len = plaintext.len(),
            "Successfully decrypted raw data"
        );

        Ok(plaintext)
    }
}

// Base64 encoding/decoding helpers
mod base64 {
    use ::base64::Engine;
    use ::base64::engine::general_purpose::STANDARD;

    pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
        STANDARD.encode(input)
    }

    pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, ::base64::DecodeError> {
        STANDARD.decode(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== post_with_session_retry: recovery after the keystore forgets its sessions =====

    /// A throwaway keystore: answers the first business request with the keystore's own
    /// session-expired 403, serves the challenge-response handshake, then answers 200.
    ///
    /// Every response closes the connection so the client's pool cannot outlive a step.
    fn fake_keystore(reject_first: bool) -> (String, std::thread::JoinHandle<Vec<String>>) {
        fake_keystore_serving(reject_first, if reject_first { 4 } else { 1 })
    }

    /// Same, serving exactly `connections` requests before the listener goes away.
    fn fake_keystore_serving(
        reject_first: bool,
        connections: usize,
    ) -> (String, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut business_calls = 0;
            for stream in listener.incoming().take(connections) {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = req
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                seen.push(path.clone());

                let (code, body) = match path.as_str() {
                    "/tee-challenge" => (200, r#"{"challenge":"deadbeef"}"#.to_string()),
                    "/register-tee" => (
                        200,
                        r#"{"session_id":"6f1e9d3a-0000-4000-8000-000000000001"}"#.to_string(),
                    ),
                    _ => {
                        business_calls += 1;
                        if reject_first && business_calls == 1 {
                            (403, r#"{"error":"TEE session not found"}"#.to_string())
                        } else {
                            (200, r#"{"encrypted_base64":"Y2lwaGVy"}"#.to_string())
                        }
                    }
                };

                let response = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
            seen
        });
        (format!("http://{}", addr), handle)
    }

    fn client_with_signing_key(base_url: String) -> KeystoreClient {
        let mut client = KeystoreClient::new(vec![base_url], "test-token".to_string()).expect("one url");
        client.set_tee_signing_info(near_crypto::SecretKey::from_random(
            near_crypto::KeyType::ED25519,
        ));
        client.set_session_for_test(0, "stale-session");
        client
    }

    /// A client over several instances, in order, with a signing key and no session anywhere.
    fn client_over(urls: Vec<String>) -> KeystoreClient {
        let mut client = KeystoreClient::new(urls, "test-token".to_string()).expect("urls");
        client.set_tee_signing_info(near_crypto::SecretKey::from_random(
            near_crypto::KeyType::ED25519,
        ));
        client
    }

    /// A URL nothing listens on: bound, then released.
    fn dead_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        drop(listener);
        format!("http://{}", addr)
    }

    /// A URL that accepts the connection and never answers.
    fn silent_url() -> (String, std::net::TcpListener) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        (format!("http://{}", addr), listener)
    }

    /// The keystore restarted and forgot every session. The worker must re-handshake and finish
    /// the original call on its own — before this existed, only `/decrypt` recovered and every
    /// other endpoint stayed broken until someone restarted the worker.
    #[tokio::test]
    async fn encrypt_reestablishes_a_dropped_tee_session_and_succeeds() {
        let (url, server) = fake_keystore(true);
        let client = client_with_signing_key(url);

        let out = client.encrypt("seed", b"plaintext", None).await;

        let seen = server.join().expect("server thread");
        assert!(out.is_ok(), "expected recovery, got {out:?}");
        assert_eq!(
            seen,
            vec![
                "/encrypt".to_string(),
                "/tee-challenge".to_string(),
                "/register-tee".to_string(),
                "/encrypt".to_string(),
            ],
            "expected: rejected call, handshake, then the same call again"
        );
    }

    /// Without a signing key there is nothing to re-handshake with. The failure must name that
    /// cause — the old code discarded it and reported only the keystore's 403, which reads as
    /// "the keystore rejected us" when the problem is on our side.
    #[tokio::test]
    async fn encrypt_reports_why_a_reconnect_could_not_happen() {
        let (url, server) = fake_keystore(true);
        // No `set_tee_signing_info` — this is a worker that never got its key.
        let client = KeystoreClient::new(vec![url], "test-token".to_string()).expect("one url");
        client.set_session_for_test(0, "stale-session");

        let err = client
            .encrypt("seed", b"plaintext", None)
            .await
            .expect_err("must fail without a way to re-handshake");
        let chain = format!("{err:#}");

        assert!(
            chain.contains("No TEE signing info"),
            "the reconnect failure must be in the error chain, got: {chain}"
        );
        assert!(
            chain.contains("403"),
            "the original keystore status should still be visible, got: {chain}"
        );
        drop(server);
    }

    /// A keystore that answers one business call with a chosen status and body.
    fn fake_keystore_answering(code: u16, body: &'static str) -> String {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Some(Ok(mut stream)) = listener.incoming().next() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf);
                let response = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://{}", addr)
    }

    async fn decrypt_against(code: u16, body: &'static str) -> anyhow::Error {
        let client = KeystoreClient::new(vec![fake_keystore_answering(code, body)], "t".to_string())
            .expect("one url");
        client
            .decrypt_secrets_by_project("a.near/p", "prod", "a.near", "a.near", None, None, None)
            .await
            .expect_err("a non-2xx must be an error")
    }

    /// "There is no such secret" is the ONLY failure a job may shrug off and run
    /// without one. It is recognised by TYPE, and the type is what the worker
    /// asks about.
    ///
    /// The trap this guards is narrow and nasty: the user-facing message is
    /// assembled from the keystore's own words, so a REFUSAL whose text happens
    /// to contain "not found" would, under a string test, start the job with no
    /// credential — silently, on an access-control refusal. The 401 case below
    /// says exactly that phrase for exactly that reason.
    #[tokio::test]
    async fn only_a_missing_secret_lets_a_job_continue_without_one() {
        assert!(
            SecretsNotFound::is_missing(&decrypt_against(404, r#"{"error":"nope"}"#).await),
            "a 404 means there is no such secret"
        );
        assert!(
            SecretsNotFound::is_missing(
                &decrypt_against(400, r#"{"error":"secret not found"}"#).await
            ),
            "the keystore also reports it as a 400 saying so"
        );

        let refusal =
            decrypt_against(401, r#"{"error":"agent profile not found on this wallet"}"#).await;
        assert!(
            !SecretsNotFound::is_missing(&refusal),
            "a REFUSAL must stop the job even when its wording contains the words \
             the old string test looked for: {refusal:#}"
        );

        let broken = decrypt_against(500, r#"{"error":"boom"}"#).await;
        assert!(
            !SecretsNotFound::is_missing(&broken),
            "a keystore that is down is not a keystore saying the secret is absent"
        );
    }

    /// Test SecretAccessor::Repo serialization (with branch)
    // ===== failover across keystore instances =====

    /// The first instance refuses connections. The request must land on the second one, after
    /// a fresh handshake THERE (sessions do not travel between instances), and the second
    /// instance must stay current afterwards.
    #[tokio::test]
    async fn a_refusing_instance_is_skipped_and_the_session_is_made_on_the_next_one() {
        let dead = dead_url();
        let (live, server) = fake_keystore_serving(false, 3);
        let client = client_over(vec![dead.clone(), live.clone()]);

        let out = client.encrypt("seed", b"plaintext", None).await;

        let seen = server.join().expect("server thread");
        assert!(out.is_ok(), "expected the second instance to serve, got {out:?}");
        assert_eq!(
            seen,
            vec![
                "/tee-challenge".to_string(),
                "/register-tee".to_string(),
                "/encrypt".to_string(),
            ],
            "expected a handshake on the new instance, then the call"
        );
        assert_eq!(client.current_endpoint().0, live, "the live instance must become current");
        assert!(client.current_endpoint().1.is_some(), "and hold the session made there");
    }

    /// Startup registration walks the list the same way: the first reachable instance gets the
    /// session and becomes current.
    #[tokio::test]
    async fn startup_registration_settles_on_the_first_reachable_instance() {
        let dead = dead_url();
        let (live, server) = fake_keystore_serving(false, 2);
        let client = client_over(vec![dead, live.clone()]);
        let key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);

        let session = client.register_tee_session(&key).await.expect("registration");

        let seen = server.join().expect("server thread");
        assert_eq!(seen, vec!["/tee-challenge".to_string(), "/register-tee".to_string()]);
        assert_eq!(client.current_endpoint(), (live, Some(session)));
    }

    /// A host that swallows the SYN (powered off, frozen, firewalled) is a connect timeout.
    /// reqwest reports it as a timeout too, and it must still be a move: nothing was sent, and
    /// this is the dead-server case failover exists for. 192.0.2.0/24 (TEST-NET-1) never routes.
    #[tokio::test]
    async fn a_black_holed_instance_is_left_on_connect_timeout() {
        let (live, server) = fake_keystore_serving(false, 3);
        let client = client_over(vec!["http://192.0.2.1:8081".to_string(), live.clone()])
            .with_connect_timeout(Duration::from_millis(300));

        let out = client.encrypt("seed", b"plaintext", None).await;

        let seen = server.join().expect("server thread");
        assert!(out.is_ok(), "expected the live instance to serve, got {out:?}");
        assert_eq!(
            seen,
            vec![
                "/tee-challenge".to_string(),
                "/register-tee".to_string(),
                "/encrypt".to_string(),
            ]
        );
        assert_eq!(client.current_endpoint().0, live);
    }

    /// A request timeout is not a reason to repeat the request: the instance may be working on
    /// it, and the second instance must not receive a copy. But it IS a reason to leave: the
    /// next request goes to the next instance, or a wedged instance would hold the worker forever.
    #[tokio::test]
    async fn a_timeout_fails_the_request_and_moves_the_next_one() {
        let (silent, _hold) = silent_url();
        let (live, server) = fake_keystore_serving(false, 3);
        let client = client_over(vec![silent.clone(), live.clone()])
            .with_request_timeout(Duration::from_millis(300));
        client.set_session_for_test(0, "session-on-silent");

        let err = client
            .encrypt("seed", b"plaintext", None)
            .await
            .expect_err("a silent instance must fail the call");
        let chain = format!("{err:#}");
        assert!(
            !chain.contains("every keystore instance is unreachable"),
            "a timeout must not be reported as a failover exhaustion, got: {chain}"
        );
        assert_eq!(
            client.candidates()[0], 1,
            "the silent instance must be marked down so the next request goes elsewhere"
        );

        let out = client.encrypt("seed", b"plaintext", None).await;
        assert!(out.is_ok(), "the next request must be served by the live instance, got {out:?}");
        assert_eq!(client.current_endpoint().0, live);

        // The live instance saw exactly the second request (with its handshake): nothing from
        // the first one was moved to it.
        let seen = server.join().expect("server thread");
        assert_eq!(
            seen,
            vec![
                "/tee-challenge".to_string(),
                "/register-tee".to_string(),
                "/encrypt".to_string(),
            ]
        );
    }

    /// A worker must not fail to start because the first instance in its list accepts the
    /// connection and never answers the handshake.
    #[tokio::test]
    async fn startup_registration_moves_past_a_silent_instance() {
        let (silent, _hold) = silent_url();
        let (live, server) = fake_keystore_serving(false, 2);
        let client = client_over(vec![silent, live.clone()])
            .with_request_timeout(Duration::from_millis(300));
        let key = near_crypto::SecretKey::from_random(near_crypto::KeyType::ED25519);

        let session = client.register_tee_session(&key).await.expect("registration");

        let seen = server.join().expect("server thread");
        assert_eq!(seen, vec!["/tee-challenge".to_string(), "/register-tee".to_string()]);
        assert_eq!(client.current_endpoint(), (live, Some(session)));
    }

    /// With nobody reachable the error names the operation and how many instances were tried,
    /// without their hostnames.
    #[tokio::test]
    async fn all_instances_unreachable_is_one_error_naming_them_all() {
        let (a, b) = (dead_url(), dead_url());
        let client = client_over(vec![a.clone(), b.clone()]);

        let err = client
            .encrypt("seed", b"plaintext", None)
            .await
            .expect_err("nothing to talk to");
        let chain = format!("{err:#}");
        assert!(chain.contains("Encrypt failed: every keystore instance is unreachable (2 tried"), "{chain}");
        // Hostnames stay in the worker log; a job error that reaches the user must not carry them.
        assert!(!chain.contains(&a) && !chain.contains(&b), "instance URLs must not leak: {chain}");
    }

    /// An instance that answers "session expired" is up; the re-handshake happens on it, not on
    /// a neighbour, and the neighbour is never contacted.
    #[tokio::test]
    async fn an_expired_session_is_renewed_on_the_same_instance() {
        let (first, server) = fake_keystore(true);
        let dead = dead_url();
        let client = client_over(vec![first.clone(), dead]);
        client.set_session_for_test(0, "stale-session");

        let out = client.encrypt("seed", b"plaintext", None).await;

        let seen = server.join().expect("server thread");
        assert!(out.is_ok(), "{out:?}");
        assert_eq!(
            seen,
            vec![
                "/encrypt".to_string(),
                "/tee-challenge".to_string(),
                "/register-tee".to_string(),
                "/encrypt".to_string(),
            ]
        );
        assert_eq!(client.current_endpoint().0, first);
    }

    // ===== KEYSTORE_BASE_URLS parsing =====

    #[test]
    fn base_urls_are_trimmed_deduplicated_and_kept_in_order() {
        let urls = parse_base_urls(" https://a.example/ ,https://b.example,, https://a.example ")
            .expect("valid list");
        assert_eq!(urls, vec!["https://a.example".to_string(), "https://b.example".to_string()]);
    }

    #[test]
    fn base_urls_reject_empty_and_non_http_entries() {
        assert!(parse_base_urls("").is_err());
        assert!(parse_base_urls(" , ").is_err());
        let err = parse_base_urls("keystore.internal:8081").expect_err("scheme required");
        assert!(format!("{err:#}").contains("not an http(s):// URL"));
    }

    #[test]
    fn a_client_needs_at_least_one_instance() {
        assert!(KeystoreClient::new(vec![], "t".to_string()).is_err());
    }

    #[test]
    fn test_secret_accessor_repo_with_branch() {
        let accessor = SecretAccessor::Repo {
            repo: "github.com/user/repo".to_string(),
            branch: Some("main".to_string()),
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "Repo");
        assert_eq!(parsed["repo"], "github.com/user/repo");
        assert_eq!(parsed["branch"], "main");
    }

    /// Test SecretAccessor::Repo serialization (without branch - branch should be omitted)
    #[test]
    fn test_secret_accessor_repo_without_branch() {
        let accessor = SecretAccessor::Repo {
            repo: "github.com/user/repo".to_string(),
            branch: None,
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "Repo");
        assert_eq!(parsed["repo"], "github.com/user/repo");
        // branch should be omitted (not null) due to skip_serializing_if
        assert!(parsed.get("branch").is_none());
    }

    /// Test SecretAccessor::WasmHash serialization
    #[test]
    fn test_secret_accessor_wasm_hash() {
        let accessor = SecretAccessor::WasmHash {
            hash: "abc123def456".to_string(),
        };

        let json = serde_json::to_string(&accessor).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["type"], "WasmHash");
        assert_eq!(parsed["hash"], "abc123def456");
    }

    /// Test that serialized JSON is compatible with keystore's expected format
    #[test]
    fn test_secret_accessor_keystore_compatibility() {
        // Repo with branch
        let accessor = SecretAccessor::Repo {
            repo: "github.com/test/project".to_string(),
            branch: Some("develop".to_string()),
        };
        let json = serde_json::to_string(&accessor).unwrap();
        // Keystore expects: {"type": "Repo", "repo": "...", "branch": "..."}
        assert!(json.contains(r#""type":"Repo""#));
        assert!(json.contains(r#""repo":"github.com/test/project""#));
        assert!(json.contains(r#""branch":"develop""#));

        // WasmHash
        let accessor = SecretAccessor::WasmHash {
            hash: "deadbeef".to_string(),
        };
        let json = serde_json::to_string(&accessor).unwrap();
        // Keystore expects: {"type": "WasmHash", "hash": "..."}
        assert!(json.contains(r#""type":"WasmHash""#));
        assert!(json.contains(r#""hash":"deadbeef""#));
    }
}

#[cfg(test)]
mod access_denied_tests {
    use super::access_denied_message;

    /// The keystore names the instant a grant lapsed, and that instant must
    /// reach the caller: it is the whole difference between "ask to be granted"
    /// and "ask to be granted again".
    #[test]
    fn a_lapsed_time_limit_reaches_the_caller() {
        let m = access_denied_message(
            r#"{"error":"Access denied by access condition: its time limit passed at 2026-10-01T00:00:00Z"}"#,
        );
        assert!(m.contains("time limit passed at 2026-10-01T00:00:00Z"), "{m}");
        assert!(m.contains("access conditions"), "the advice is still offered: {m}");
    }

    #[test]
    fn a_plain_refusal_still_reads_as_one() {
        assert_eq!(
            access_denied_message(r#"{"error":"Access denied by access condition"}"#),
            "Access denied by access condition. Check the access conditions configured by the secret owner."
        );
    }

    /// An agent-shaped row refused for being somebody else's is not a condition
    /// refusal, and its own sentence reaches the caller too.
    #[test]
    fn any_reason_the_keystore_gives_is_passed_on() {
        let m = access_denied_message(r#"{"error":"This secret belongs to another agent"}"#);
        assert!(m.starts_with("This secret belongs to another agent."), "{m}");
    }

    /// A body that is not the keystore's shape must not produce an empty or
    /// misleading sentence.
    #[test]
    fn an_unreadable_body_falls_back() {
        for body in ["", "not json", "{}", r#"{"error":""}"#, r#"{"error":"   "}"#] {
            assert_eq!(
                access_denied_message(body),
                "Access to secrets denied. Check access conditions.",
                "{body}"
            );
        }
    }
}

/// The build a run executes reaches the keystore, and is the worker's own
/// measurement.
///
/// The whole lock rests on this one field: the keystore judges a `WasmHash`
/// condition against what arrives here, so a decrypt that forgot to carry it
/// turns every locked row into a 500, and one that carried a value from the
/// task or the guest would let a caller name the build it wants to be.
#[cfg(test)]
mod the_decrypt_request_carries_the_executing_build {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    const EXECUTED: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    /// A keystore that answers once and keeps what it was asked.
    fn capturing_keystore() -> (String, Arc<Mutex<String>>) {
        let seen = Arc::new(Mutex::new(String::new()));
        let recorder = Arc::clone(&seen);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Some(Ok(mut stream)) = listener.incoming().next() {
                let mut buf = [0u8; 16384];
                let read = stream.read(&mut buf).unwrap_or(0);
                *recorder.lock().unwrap() = String::from_utf8_lossy(&buf[..read]).to_string();
                // An empty secrets object: the call succeeds and the test judges
                // the REQUEST, not the answer.
                let body = r#"{"plaintext_secrets":"e30="}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        (format!("http://{}", addr), seen)
    }

    /// The body of the request the keystore received, as JSON.
    async fn request_body_of(executed: Option<&str>) -> serde_json::Value {
        request_body_with(executed, None).await
    }

    async fn request_body_with(executed: Option<&str>, predecessor: Option<&str>) -> serde_json::Value {
        let (url, seen) = capturing_keystore();
        let client = KeystoreClient::new(vec![url], "t".to_string()).expect("one url");
        let _ = client
            .decrypt_secrets_by_project("a.near/p", "prod", "a.near", "a.near", None, executed, predecessor)
            .await;
        let raw = seen.lock().unwrap().clone();
        let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        serde_json::from_str(&body).unwrap_or_else(|e| panic!("the keystore was sent no JSON body ({e}): {raw}"))
    }

    #[tokio::test]
    async fn the_hash_is_in_the_body_the_keystore_receives() {
        let body = request_body_of(Some(EXECUTED)).await;
        assert_eq!(
            body["executed_wasm_sha256"].as_str(),
            Some(EXECUTED),
            "the field the keystore judges a build lock against is missing: {body}"
        );
        // And the rest of the request is unchanged, so an older keystore reads
        // everything it always read.
        assert_eq!(body["profile"].as_str(), Some("prod"));
        assert_eq!(body["owner"].as_str(), Some("a.near"));
        assert_eq!(body["accessor"]["type"].as_str(), Some("Project"));
    }

    /// A run with no measurement sends the field as null rather than omitting
    /// the question: the keystore then refuses a locked row instead of judging
    /// it against nothing.
    #[tokio::test]
    async fn no_measurement_sends_an_explicit_null() {
        let body = request_body_of(None).await;
        assert!(body["executed_wasm_sha256"].is_null(), "{body}");
        assert!(body["predecessor_id"].is_null(), "{body}");
    }

    /// The calling account travels beside the build, under the name the
    /// keystore judges a `Predecessor` leaf by.
    #[tokio::test]
    async fn the_calling_account_is_in_the_body_the_keystore_receives() {
        let body = request_body_with(Some(EXECUTED), Some("dao.near")).await;
        assert_eq!(body["predecessor_id"].as_str(), Some("dao.near"), "{body}");
        assert_eq!(body["executed_wasm_sha256"].as_str(), Some(EXECUTED), "{body}");
    }
}

#[cfg(test)]
mod signing_key_requests {
    use super::*;
    use crate::signing_keys::{CallerKind, KeyBinding, ManifestKey, SigningKeyType};

    const H: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const SEED: &str = "b5ca092c9bb7c321f2d6f69c6eb147907d5df9fcc2309552786e7502706a7493";
    /// base64 of `{"API_KEY":"x"}`
    const PLAIN: &str = "eyJBUElfS0VZIjoieCJ9";

    /// One answer from a local socket; the request body it received comes back
    /// on the handle.
    fn keystore_answering(code: u16, body: String) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut buf = [0u8; 8192];
            // Headers, then as much body as Content-Length says.
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                request.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&request).to_string();
                if let Some(split) = text.find("\r\n\r\n") {
                    let len = text[..split]
                        .lines()
                        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap_or(0)))
                        .unwrap_or(0);
                    if request.len() >= split + 4 + len || n == 0 {
                        break;
                    }
                } else if n == 0 {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let text = String::from_utf8_lossy(&request).to_string();
            text[text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0)..].to_string()
        });
        (format!("http://{addr}"), handle)
    }

    fn declared() -> Vec<ManifestKey> {
        vec![ManifestKey {
            path: "records".into(),
            key_type: SigningKeyType::Ed25519,
            bind: KeyBinding::Project,
            caller: CallerKind::Signer,
            vault: None,
        }]
    }

    fn keys_ok() -> String {
        format!(r#""signing_keys":{{"records":"{SEED}"}}"#)
    }

    /// The run's one call: its project row, with or without the keys.
    async fn run_call(code: u16, body: String, with_keys: bool) -> (Result<RunSecrets>, serde_json::Value) {
        let (url, sent) = keystore_answering(code, body);
        let client = KeystoreClient::new(vec![url], "t".to_string()).unwrap();
        let declared = declared();
        let request = KeysRequest { project_id: Some("alice.near/app"), keys: &declared };
        let result = client
            .with_signing_keys(with_keys.then_some(&request))
            .decrypt_secrets_by_project("alice.near/app", "default", "alice.near", "bob.near", Some("data-1"), Some(H), Some("bob.near"))
            .await;
        let sent: serde_json::Value = serde_json::from_str(&sent.join().unwrap()).unwrap();
        (result, sent)
    }

    /// A keys-only call, with the calling account when the run has one.
    async fn keys_only_as(
        code: u16,
        body: String,
        predecessor: Option<&str>,
    ) -> (Result<crate::signing_keys::SigningKeys>, serde_json::Value) {
        let (url, sent) = keystore_answering(code, body);
        let client = KeystoreClient::new(vec![url], "t".to_string()).unwrap();
        let declared = declared();
        let request = KeysRequest { project_id: Some("alice.near/app"), keys: &declared };
        let result = client.derive_signing_keys("bob.near", Some("data-1"), H, predecessor, &request).await;
        let sent: serde_json::Value = serde_json::from_str(&sent.join().unwrap()).unwrap();
        (result, sent)
    }

    /// A keys-only call of a run with no calling account.
    async fn keys_only(code: u16, body: String) -> (Result<crate::signing_keys::SigningKeys>, serde_json::Value) {
        keys_only_as(code, body, None).await
    }

    #[tokio::test]
    async fn without_keys_the_request_is_the_plain_secrets_request() {
        let (result, sent) = run_call(200, format!(r#"{{"plaintext_secrets":"{PLAIN}"}}"#), false).await;
        let run = result.expect("served");
        assert_eq!(run.secrets.unwrap()["API_KEY"], "x");
        assert!(run.keys.is_none());
        assert_eq!(
            sent,
            serde_json::json!({
                "accessor": { "type": "Project", "project_id": "alice.near/app" },
                "profile": "default", "owner": "alice.near", "user_account_id": "bob.near",
                "task_id": "data-1", "executed_wasm_sha256": H, "predecessor_id": "bob.near",
            }),
            "no keys, no project_id: exactly the request a keystore has always been sent"
        );
        // And "not found" is the typed error a run continues past, as always.
        let (result, _) = run_call(400, r#"{"error":"Secrets not found in contract"}"#.into(), false).await;
        assert!(SecretsNotFound::is_missing(&result.err().expect("not found")));
    }

    #[tokio::test]
    async fn with_keys_one_request_carries_the_row_and_the_keys() {
        let body = format!(r#"{{"secrets":{{"status":"decrypted","plaintext_secrets":"{PLAIN}"}},{}}}"#, keys_ok());
        let (result, sent) = run_call(200, body, true).await;
        let run = result.expect("served");
        assert_eq!(run.secrets.unwrap()["API_KEY"], "x");
        assert_eq!(run.keys.unwrap().paths().collect::<Vec<_>>(), vec!["records"]);
        assert_eq!(
            sent,
            serde_json::json!({
                "accessor": { "type": "Project", "project_id": "alice.near/app" },
                "profile": "default", "owner": "alice.near", "user_account_id": "bob.near",
                "task_id": "data-1", "executed_wasm_sha256": H, "predecessor_id": "bob.near",
                "project_id": "alice.near/app",
                "signing_keys": [{ "path": "records", "type": "ed25519", "bind": "project", "caller": "signer" }],
            }),
            "the job's fields and the declared keys — no derivation string, no field saying how the run was started"
        );
    }

    /// A missing row beside the keys: the run continues without secrets, as it
    /// does on a plain "not found", and it has its keys.
    #[tokio::test]
    async fn a_missing_row_beside_the_keys_is_no_secrets_not_an_error() {
        let body = format!(r#"{{"secrets":{{"status":"not_found","error":"Secrets not found in contract"}},{}}}"#, keys_ok());
        let run = run_call(200, body, true).await.0.expect("served");
        assert!(run.secrets.is_none());
        assert!(run.keys.is_some());
    }

    #[tokio::test]
    async fn a_key_refusal_is_typed_and_carries_the_keystores_reason() {
        let refusal = r#"{"error":"Signing keys refused: vault x does not belong to alice.near","code":"signing_keys_refused"}"#;
        let e = run_call(403, refusal.into(), true).await.0.err().expect("refused");
        assert!(SigningKeysRefused::is_refusal(&e));
        assert!(!SecretsNotFound::is_missing(&e));
        assert!(format!("{e:#}").contains("does not belong to alice.near"), "{e:#}");
        let e = keys_only(403, refusal.into()).await.0.err().expect("refused");
        assert!(SigningKeysRefused::is_refusal(&e));
    }

    /// A secret's own refusal, beside keys, reads exactly as it does without
    /// them — and is not a key refusal.
    #[tokio::test]
    async fn a_denied_secret_beside_keys_reads_as_a_denied_secret() {
        let denied = r#"{"error":"Access denied by access condition: bob.near is not whitelisted"}"#;
        let with_keys = run_call(401, denied.into(), true).await.0.err().expect("denied");
        let without = run_call(401, denied.into(), false).await.0.err().expect("denied");
        assert!(!SigningKeysRefused::is_refusal(&with_keys));
        assert_eq!(format!("{with_keys:#}"), format!("{without:#}"));
    }

    /// A new worker against a keystore that predates signing keys: every way
    /// it can answer fails the run, saying so — and none of them is a
    /// refusal, since nothing the author or caller does changes the keystore.
    #[tokio::test]
    async fn an_old_keystore_fails_the_run_with_a_clear_reason() {
        let unserved = |e: &anyhow::Error| {
            SigningKeysUnserved::is_unserved(e) && !SigningKeysRefused::is_refusal(e) && format!("{e:#}").contains("predates signing keys")
        };
        // It ignores the keys and answers the row as always.
        let e = run_call(200, format!(r#"{{"plaintext_secrets":"{PLAIN}"}}"#), true).await.0.err().expect("unserved");
        assert!(unserved(&e), "{e:#}");
        // It answers a missing row with its plain "not found".
        let e = run_call(400, r#"{"error":"Secrets not found in contract"}"#.into(), true).await.0.err().expect("unserved");
        assert!(unserved(&e) && !SecretsNotFound::is_missing(&e), "{e:#}");
        // It cannot read a request that names only keys.
        let e = keys_only(422, "Failed to deserialize the JSON body into the target type: missing field `accessor`".into())
            .await
            .0
            .err()
            .expect("unserved");
        assert!(unserved(&e), "{e:#}");
    }

    #[tokio::test]
    async fn the_keys_only_request_names_no_row() {
        let (result, sent) = keys_only(200, format!("{{{}}}", keys_ok())).await;
        assert_eq!(result.expect("served").paths().collect::<Vec<_>>(), vec!["records"]);
        assert_eq!(
            sent,
            serde_json::json!({
                "user_account_id": "bob.near", "task_id": "data-1", "executed_wasm_sha256": H,
                "predecessor_id": null, "project_id": "alice.near/app",
                "signing_keys": [{ "path": "records", "type": "ed25519", "bind": "project", "caller": "signer" }],
            })
        );
    }

    #[tokio::test]
    async fn the_keys_only_request_carries_the_calling_account_when_the_run_has_one() {
        let (result, sent) = keys_only_as(200, format!("{{{}}}", keys_ok()), Some("dao.near")).await;
        assert_eq!(result.expect("served").paths().collect::<Vec<_>>(), vec!["records"]);
        assert_eq!(sent["user_account_id"].as_str(), Some("bob.near"), "{sent}");
        assert_eq!(sent["predecessor_id"].as_str(), Some("dao.near"), "both accounts of the run: {sent}");
    }

    /// Seeds that are not the declared set are not served keys, and not a
    /// refusal either: the keystore answered, and its answer cannot be used.
    #[tokio::test]
    async fn keys_other_than_the_declared_ones_are_unserved() {
        let unserved = |e: &anyhow::Error| SigningKeysUnserved::is_unserved(e) && !SigningKeysRefused::is_refusal(e);
        let (result, _) = keys_only(200, format!(r#"{{"signing_keys":{{"records":"{SEED}","extra":"{SEED}"}}}}"#)).await;
        assert!(unserved(&result.err().expect("unserved")));
        let (result, _) = keys_only(200, r#"{"signing_keys":{}}"#.into()).await;
        assert!(unserved(&result.err().expect("unserved")));
        // An answer under another member's name is an answer without keys.
        let (result, _) = keys_only(200, format!(r#"{{"keys":{{"records":"{SEED}"}}}}"#)).await;
        let e = result.err().expect("unserved");
        assert!(unserved(&e) && format!("{e:#}").contains("predates signing keys"), "{e:#}");
        // An answer with a row outcome the request did not ask for is not trusted.
        let (result, _) = keys_only(200, format!(r#"{{"secrets":{{"status":"decrypted","plaintext_secrets":"{PLAIN}"}},{}}}"#, keys_ok())).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_keystore_that_cannot_be_reached_is_not_a_refusal() {
        let client = KeystoreClient::new(vec!["http://127.0.0.1:1".into()], "t".to_string()).unwrap();
        let declared = declared();
        let request = KeysRequest { project_id: None, keys: &declared };
        let e = client.derive_signing_keys("bob.near", None, H, None, &request).await.err().expect("unreachable");
        assert!(!SigningKeysRefused::is_refusal(&e) && !SigningKeysUnserved::is_unserved(&e), "{e:#}");
    }
}
