//! GitHub connector for OutLayer — an agent works in the owner's GitHub account,
//! as the owner, under the owner's policy, without ever holding the credential.
//!
//! The owner connects an account once, at
//! <https://app.outlayer.ai/connect/github>: they install the OutLayer GitHub App
//! on the repositories they choose and authorize it, and one value is stored —
//! the user token GitHub issued. What that token can reach is decided by GitHub:
//! only the repositories the owner picked, and only what the app was permitted
//! (never workflow files, settings or administration). What the AGENT may do
//! inside that is decided by the owner's policy, enforced here before any call
//! leaves the enclave. An owner who would rather not use the app stores a
//! personal access token under the same name; nothing here can tell the two apart.
//!
//! There are no prompts in here and no judgement: this is an interface to
//! GitHub. What to read, what to write and whether a pull request is any good
//! is the agent's business; whether it is ALLOWED is this module's.
//!
//! Everything an agent reads from GitHub — issues, comments, files, patches —
//! was written by somebody, and may have been written for the agent. The policy
//! is what bounds the damage when an agent believes it.
//!
//! One host in the manifest: `api.github.com`.

mod github;
mod ops;
mod policy;
mod seal;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use outlayer::env;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The manifest, embedded so the on-chain hash covers it: the connector id, the
/// one host this module may reach, and the daily caps it declares about itself.
#[cfg(target_family = "wasm")]
#[used]
#[link_section = "outlayer.manifest"]
static OUTLAYER_MANIFEST: [u8; include_bytes!("../manifest.json").len()] =
    *include_bytes!("../manifest.json");

#[derive(Serialize)]
struct Envelope {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    output: Option<Value>,
    logs: Vec<Value>,
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// One file of a `commit`, a `gist_create` or a `gist_update`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct FileChange {
    pub path: String,
    pub content: Option<String>,
    /// `utf-8` (the default) or `base64`.
    pub encoding: Option<String>,
    #[serde(default)]
    pub delete: bool,
}

/// One comment of a `pr_review`, on a line of the diff.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ReviewComment {
    pub path: String,
    pub line: u64,
    /// `RIGHT` (the new side, the default) or `LEFT`.
    pub side: Option<String>,
    pub body: String,
}

/// Every field any operation reads. A field nobody reads is refused rather than
/// ignored: an agent that wrote `branch_name` should hear about it, not watch a
/// commit land on the wrong branch.
#[derive(Debug, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Input {
    pub operation: String,
    /// `owner/name`.
    pub repo: Option<String>,
    /// An issue or pull request number.
    pub number: Option<u64>,
    pub path: Option<String>,
    /// A branch, tag or sha to READ at.
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    /// The branch to WRITE to.
    pub branch: Option<String>,
    /// `branch_create`: the branch to start from. Absent: the default branch.
    pub from: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
    pub state: Option<String>,
    pub labels: Option<Vec<String>>,
    pub assignees: Option<Vec<String>>,
    pub content: Option<String>,
    pub encoding: Option<String>,
    /// A commit message.
    pub message: Option<String>,
    /// `file_put`: the sha of the file being replaced. `pr_merge`: the head to merge.
    pub sha: Option<String>,
    pub files: Vec<FileChange>,
    pub head: Option<String>,
    pub base: Option<String>,
    pub draft: Option<bool>,
    /// `pr_review`: `COMMENT`, `REQUEST_CHANGES` or `APPROVE`.
    pub event: Option<String>,
    pub comments: Vec<ReviewComment>,
    pub merge_method: Option<String>,
    pub gist_id: Option<String>,
    pub description: Option<String>,
    pub public: Option<bool>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    /// `status` only: a secp256k1 public key in hex (33 bytes compressed, as
    /// `eciesjs` gives it) to seal the policy to. Required for the policy to be
    /// shown at all when the run's output lands on chain.
    pub reply_pubkey: Option<String>,
}

/// Everything this connector sells. A name not here is refused with the list.
const OPERATIONS: &[&str] = &[
    "status", "repo_list", "repo_get", "dir_list", "file_get", "branch_list", "issue_list", "issue_get",
    "pr_list", "pr_get", "pr_files", "gist_list", "gist_get", "branch_create", "file_put", "commit",
    "issue_create", "issue_comment", "issue_update", "pr_create", "pr_review", "pr_merge", "gist_create",
    "gist_update", "repo_star", "repo_unstar",
];

fn main() {
    // Storage is imported by being called: the day's count needs a project context.
    let _ = ::outlayer::storage::has("_init");

    let raw = env::input();
    let envelope = match serde_json::from_slice::<Input>(&raw) {
        Err(e) => Envelope {
            success: false,
            operation: String::new(),
            error: Some(format!("invalid: the input is not what this connector reads: {e}")),
            output: None,
            logs: Vec::new(),
        },
        Ok(input) => {
            let op = input.operation.trim().to_string();
            match run(&op, &input) {
                Ok(output) => Envelope { success: true, operation: op, error: None, output: Some(output), logs: Vec::new() },
                Err(e) => Envelope { success: false, operation: op, error: Some(e), output: None, logs: Vec::new() },
            }
        }
    };
    let _ = env::output_json(&envelope);
}

fn run(op: &str, input: &Input) -> Result<Value, String> {
    match op {
        "status" => status(input),
        "repo_list" => ops::repo_list(input),
        "repo_get" => ops::repo_get(input),
        "dir_list" => ops::dir_list(input),
        "file_get" => ops::file_get(input),
        "branch_list" => ops::branch_list(input),
        "issue_list" => ops::issue_list(input),
        "issue_get" => ops::issue_get(input),
        "pr_list" => ops::pr_list(input),
        "pr_get" => ops::pr_get(input),
        "pr_files" => ops::pr_files(input),
        "gist_list" => ops::gist_list(input),
        "gist_get" => ops::gist_get(input),
        "branch_create" => ops::branch_create(input),
        "file_put" => ops::file_put(input),
        "commit" => ops::commit(input),
        "issue_create" => ops::issue_create(input),
        "issue_comment" => ops::issue_comment(input),
        "issue_update" => ops::issue_update(input),
        "pr_create" => ops::pr_create(input),
        "pr_review" => ops::pr_review(input),
        "pr_merge" => ops::pr_merge(input),
        "gist_create" => ops::gist_create(input),
        "gist_update" => ops::gist_update(input),
        "repo_star" => ops::repo_star(input),
        "repo_unstar" => ops::repo_unstar(input),
        "" => Err(format!("invalid: no `operation` in the input. This connector sells: {}", OPERATIONS.join(", "))),
        other => Err(format!("invalid: unknown operation `{other}`. This connector sells: {}", OPERATIONS.join(", "))),
    }
}

/// Is the credential alive, whose is it, what can it reach, and what may the
/// agent do with it? The one operation that runs without a policy.
fn status(input: &Input) -> Result<Value, String> {
    // A key that is not one is refused before GitHub is asked for anything: the
    // refusal is the caller's to fix, and it should not cost a request.
    if let Some(key) = input.reply_pubkey.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        seal::parse_pubkey(key)?;
    }
    let user = github::get("/user")?;
    let reachable = github::get("/user/repos?per_page=30&sort=pushed")?;
    let reachable: Vec<Value> = reachable
        .as_array()
        .map(|repos| repos.iter().filter_map(|r| r.get("full_name").cloned()).collect())
        .unwrap_or_default();
    let (policy, sealed) = policy_view(policy::load(), input.reply_pubkey.as_deref(), on_chain())?;
    let mut answer = json!({
        "credential": "ok",
        "acting_as": user.get("login"),
        // Names only, and only the first page: enough to see the connection is
        // the intended one. `repo_list` is the operation that lists.
        "reachable_repositories": reachable,
        "reachable_more": reachable.len() >= 30,
        "add_repositories": github::INSTALL_URL,
        "policy": policy,
        "writes_today": policy::writes_today().unwrap_or(0),
    });
    if reachable.is_empty() {
        answer["note"] = json!(
            "the token reaches no repository: the OutLayer app is installed on none, or on an account with none. \
             Gists still work. The owner adds repositories at `add_repositories`"
        );
    }
    if let Some(sealed) = sealed {
        answer["policy_sealed"] = Value::String(sealed);
    }
    Ok(answer)
}

/// Where this run's output goes. The worker names an HTTPS run in so many
/// words; anything else is treated as public — the direction that leaks nothing
/// when the variable is missing.
fn on_chain() -> bool {
    std::env::var("OUTLAYER_EXECUTION_TYPE").map(|v| v != "HTTPS").unwrap_or(true)
}

/// The policy as `status` reports it, and — when the caller gave a key — the
/// same thing sealed to that key as base64.
///
/// Three cases, decided by two facts. With a `reply_pubkey`, the full policy is
/// sealed and the open part says only whether one exists. Without one, over
/// HTTPS the full policy goes in the clear, as the transport already is. Without
/// one on chain the fields are withheld: the output of an on-chain run sits in
/// the transaction for ever, and the policy names the owner's repositories —
/// private ones among them.
fn policy_view(loaded: policy::Loaded, reply_pubkey: Option<&str>, on_chain: bool) -> Result<(Value, Option<String>), String> {
    let full = match loaded {
        policy::Loaded::Some(p) => json!({
            "present": true,
            "actions": p.actions,
            "repos": p.repos,
            "branches": p.branches,
            "paths": p.paths,
            "max_writes_per_day": p.max_writes_per_day,
            "max_files_per_commit": p.max_files_per_commit,
            "allow_merge": p.allow_merge,
            "allow_approve": p.allow_approve,
            "allow_public_gists": p.allow_public_gists,
            "marker": p.marker,
        }),
        policy::Loaded::None => json!({
            "present": false,
            "effect": "only `status` runs until the owner stores a policy",
        }),
        policy::Loaded::Unreadable(e) => json!({"present": true, "readable": false, "error": e}),
    };
    let present = full["present"].as_bool().unwrap_or(false);
    match reply_pubkey.map(str::trim).filter(|k| !k.is_empty()) {
        Some(key) => {
            let key = seal::parse_pubkey(key)?;
            let blob = seal::seal(&key, full.to_string().as_bytes())?;
            Ok((json!({"present": present, "sealed": true}), Some(BASE64.encode(blob))))
        }
        None if on_chain => Ok((
            json!({
                "present": present,
                "sealed": false,
                "note": "on chain the policy is returned only sealed: pass `reply_pubkey`, a secp256k1 \
                         public key in hex (33 bytes compressed), and read it back from `policy_sealed`",
            }),
            None,
        )),
        None => Ok((full, None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_operations_this_code_runs_are_the_ones_it_advertises() {
        for bad in ["", "delete_repo", "api", "workflow_dispatch"] {
            let err = run(bad, &Input::default()).unwrap_err();
            assert!(err.contains("This connector sells: status, repo_list"), "{bad} → {err}");
        }
        let manifest: Value = serde_json::from_str(include_str!("../manifest.json")).unwrap();
        let declared: Vec<&str> = manifest["operations"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(declared, OPERATIONS, "the manifest and the code sell the same things, in the same order");
    }

    /// There is no operation that forwards a request of the agent's choosing:
    /// the platform prices by operation and the policy allows by action, and a
    /// passthrough would be one price and one permission for everything.
    #[test]
    fn nothing_here_is_a_passthrough() {
        for op in OPERATIONS {
            assert!(!["api", "request", "raw", "graphql"].contains(op));
        }
    }

    #[test]
    fn a_field_nobody_reads_is_refused() {
        let err = serde_json::from_str::<Input>(r#"{"operation":"file_put","branch_name":"main"}"#).unwrap_err();
        assert!(err.to_string().contains("branch_name"), "{err}");
        assert!(serde_json::from_str::<Input>(r#"{"operation":"file_get","repo":"a/b","path":"x","ref":"main"}"#).is_ok());
    }

    /// Without a policy every operation but `status` is refused before GitHub is
    /// asked anything — reading a private repository is a disclosure too.
    #[test]
    fn without_a_policy_nothing_but_status_runs() {
        std::env::remove_var(policy::POLICY_ENV);
        for op in OPERATIONS.iter().filter(|op| **op != "status") {
            let err = run(op, &Input { repo: Some("a/b".into()), ..Input::default() }).unwrap_err();
            assert!(err.starts_with("policy_missing:"), "{op} → {err}");
        }
    }

    fn loaded(json: &str) -> policy::Loaded {
        match serde_json::from_str::<policy::Policy>(json) {
            Ok(p) => policy::Loaded::Some(p),
            Err(e) => policy::Loaded::Unreadable(e.to_string()),
        }
    }

    /// The policy names the owner's repositories. Over HTTPS it may travel in the
    /// clear; on chain it leaves only sealed, and without a key it does not leave.
    #[test]
    fn the_policy_reaches_the_chain_only_sealed() {
        let rules = r#"{"actions":["issue_create"],"repos":["alice/private-thing"],"max_writes_per_day":20}"#;

        let (open, sealed) = policy_view(loaded(rules), None, false).unwrap();
        assert!(sealed.is_none());
        assert_eq!(open["repos"], json!(["alice/private-thing"]), "HTTPS, no key: in the clear");

        let (open, sealed) = policy_view(loaded(rules), None, true).unwrap();
        assert!(sealed.is_none());
        assert!(!open.to_string().contains("private-thing"), "on chain without a key nothing is named: {open}");
        assert_eq!(open["present"], true);

        for on_chain in [true, false] {
            let secret = [7u8; 32];
            let public = libsecp256k1::PublicKey::from_secret_key(&libsecp256k1::SecretKey::parse(&secret).unwrap());
            let hex: String = public.serialize_compressed().iter().map(|b| format!("{b:02x}")).collect();
            let (open, sealed) = policy_view(loaded(rules), Some(&hex), on_chain).unwrap();
            assert!(!open.to_string().contains("private-thing"));
            let blob = BASE64.decode(sealed.expect("a key was given")).unwrap();
            let inside: Value = serde_json::from_slice(&seal::open(&secret, &blob).unwrap()).unwrap();
            assert_eq!(inside["repos"], json!(["alice/private-thing"]));
            assert_eq!(inside["max_writes_per_day"], json!(20));
        }
    }

    #[test]
    fn a_key_that_is_not_one_is_refused() {
        assert!(policy_view(loaded("{}"), Some("not-hex"), true).is_err());
    }
}
