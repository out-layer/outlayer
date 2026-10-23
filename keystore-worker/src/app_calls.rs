//! One-time tokens for a guest that runs on the Defuse worker beside ours.
//!
//! The same token the coordinator knows (its `app_calls`): minted by the worker
//! for one run, registered here by its hash over the worker's own TEE session
//! together with the run's scope, revoked when the run ends, dead by TTL
//! otherwise. A request carrying it may encrypt and decrypt storage records in
//! that scope — the same project and account the worker's host functions would
//! have named — and nothing else. The TEE identity it acts under is the
//! registering worker's.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    response::Json,
    routing::post,
    Extension, Router,
};
use serde::{Deserialize, Serialize};

use crate::api::{ApiError, AppState, WorkerIdentity};

pub const PREFIX: &str = "act_";

/// Longest a registration lives: a run's ceiling plus the worker's own margin.
const MAX_TTL_SECONDS: u64 = 3600;

/// What one run may touch, as the worker registered it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppCallScope {
    pub project_uuid: Option<String>,
    pub wasm_hash: String,
    /// The guest's `NEAR_SENDER_ID`: the account whose records it reads and writes.
    pub account_id: String,
    pub call_id: Option<String>,
}

impl AppCallScope {
    /// Whether a storage request naming `project_uuid`, `wasm_hash` and `account_id`
    /// stays inside this scope. The seed a record is sealed under is built from
    /// exactly these three, so all three are held.
    pub fn allows(&self, project_uuid: Option<&str>, wasm_hash: &str, account_id: &str) -> bool {
        project_uuid == self.project_uuid.as_deref() && wasm_hash == self.wasm_hash && account_id == self.account_id
    }
}

/// Refuses a request that a call token would take outside its scope. A request
/// without a token (the worker's own) passes untouched.
pub fn check(
    scope: &Option<Extension<AppCallScope>>,
    project_uuid: Option<&str>,
    wasm_hash: &str,
    account_id: &str,
) -> Result<(), ApiError> {
    match scope {
        Some(Extension(scope)) if !scope.allows(project_uuid, wasm_hash, account_id) => {
            tracing::warn!(
                "app call token used outside its scope: asked project={:?} wasm={} account={}, scope project={:?} wasm={} account={}",
                project_uuid, wasm_hash, account_id, scope.project_uuid, scope.wasm_hash, scope.account_id
            );
            Err(ApiError::Forbidden("the call token does not cover this project, build or account".to_string()))
        }
        _ => Ok(()),
    }
}

/// Routes a call token may reach.
pub fn path_allowed(path: &str) -> bool {
    matches!(path, "/storage/encrypt" | "/storage/decrypt")
}

struct Registration {
    scope: AppCallScope,
    /// The TEE identity of the worker that registered it.
    worker_public_key: Option<String>,
    expires_at: Instant,
}

/// The live registrations, by token hash. In memory: a registration outlives
/// nothing but its run, and a keystore restart forgets every worker session too.
#[derive(Clone, Default)]
pub struct Registry(Arc<Mutex<HashMap<String, Registration>>>);

impl Registry {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Registration>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `false` when the hash is already registered: a replay or a clash.
    pub fn register(&self, token_hash: String, scope: AppCallScope, worker_public_key: Option<String>, ttl: Duration) -> bool {
        let mut map = self.lock();
        let now = Instant::now();
        map.retain(|_, r| r.expires_at > now);
        if map.contains_key(&token_hash) {
            return false;
        }
        map.insert(token_hash, Registration { scope, worker_public_key, expires_at: now + ttl });
        true
    }

    pub fn revoke(&self, token_hash: &str) {
        self.lock().remove(token_hash);
    }

    /// The scope and worker identity a presented token stands for, if registered and alive.
    pub fn resolve(&self, token: &str) -> Option<(AppCallScope, Option<String>)> {
        let hash = token_hash(token);
        let map = self.lock();
        map.get(&hash)
            .filter(|r| r.expires_at > Instant::now())
            .map(|r| (r.scope.clone(), r.worker_public_key.clone()))
    }
}

pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// SHA-256 of the token, hex. The token itself never reaches the keystore.
    pub token_hash: String,
    pub ttl_seconds: u64,
    pub scope: AppCallScope,
}

/// Worker-only: merged under the worker auth and TEE session layers.
pub fn worker_routes() -> Router<AppState> {
    Router::new()
        .route("/app-calls/register", post(register_handler))
        .route("/app-calls/revoke", post(revoke_handler))
}

async fn register_handler(
    State(state): State<AppState>,
    worker: Option<Extension<WorkerIdentity>>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.token_hash.len() != 64 || !req.token_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("token_hash must be 32 bytes of hex".to_string()));
    }
    if req.ttl_seconds == 0 || req.ttl_seconds > MAX_TTL_SECONDS {
        return Err(ApiError::BadRequest(format!("ttl_seconds must be within 1..={MAX_TTL_SECONDS}")));
    }
    if req.scope.account_id.is_empty() || req.scope.wasm_hash.is_empty() {
        return Err(ApiError::BadRequest("scope.account_id and scope.wasm_hash are required".to_string()));
    }
    let worker_public_key = worker.map(|Extension(w)| w.0);
    if !state.app_calls.register(req.token_hash, req.scope, worker_public_key, Duration::from_secs(req.ttl_seconds)) {
        return Err(ApiError::BadRequest("this token hash is already registered".to_string()));
    }
    Ok(Json(serde_json::json!({ "registered": true })))
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token_hash: String,
}

async fn revoke_handler(
    State(state): State<AppState>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    state.app_calls.revoke(&req.token_hash);
    Ok(Json(serde_json::json!({ "revoked": true })))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> AppCallScope {
        AppCallScope { project_uuid: Some("p1".into()), wasm_hash: "h1".into(), account_id: "bob.testnet".into(), call_id: None }
    }

    #[test]
    fn a_token_covers_exactly_its_project_build_and_account() {
        let s = scope();
        assert!(s.allows(Some("p1"), "h1", "bob.testnet"));
        assert!(!s.allows(Some("p2"), "h1", "bob.testnet"));
        assert!(!s.allows(Some("p1"), "h2", "bob.testnet"));
        assert!(!s.allows(Some("p1"), "h1", "@worker"));
        assert!(!s.allows(None, "h1", "bob.testnet"), "a standalone-wasm seed is another seed");
    }

    #[test]
    fn a_registration_is_single_use_and_expires() {
        let r = Registry::default();
        assert!(r.register("a".repeat(64), scope(), Some("pk".into()), Duration::from_secs(60)));
        assert!(!r.register("a".repeat(64), scope(), None, Duration::from_secs(60)), "a hash registers once");
        let token = "act_x";
        assert!(r.resolve(token).is_none(), "a token whose hash is not registered resolves to nothing");
        let hash = token_hash(token);
        assert!(r.register(hash.clone(), scope(), Some("pk".into()), Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(r.resolve(token).is_none(), "expired");
        assert!(r.register(hash, scope(), Some("pk".into()), Duration::from_secs(60)), "an expired hash may register again");
        assert_eq!(r.resolve(token).map(|(s, w)| (s.account_id, w)), Some(("bob.testnet".to_string(), Some("pk".to_string()))));
        r.revoke(&token_hash(token));
        assert!(r.resolve(token).is_none());
    }

    #[test]
    fn only_storage_sealing_takes_a_token() {
        assert!(path_allowed("/storage/encrypt") && path_allowed("/storage/decrypt"));
        assert!(!path_allowed("/decrypt") && !path_allowed("/vrf/generate") && !path_allowed("/app-calls/register"));
    }
}
