//! The task key: the key a project's tasks for one owner are sealed under.
//!
//! A run of a project that declares tasks (`"tasks": true` in its manifest)
//! and names a secret row asks for it in the run's `/decrypt` request
//! (`KeyedDecryptRequest::task_key`, `api_support.rs`), beside the row and any
//! declared keys:
//!
//! ```text
//! HMAC-SHA256(master, "task-key:v1:{project_uuid}:{owner}")
//! ```
//!
//! `project_uuid` is the uuid the contract holds for the run's project, and
//! `owner` the account whose secret row the run named. The master is the
//! master of the vault the row is bound to, and the default master for a row
//! bound to none: what a vault seals, it seals with its own key, tasks
//! included. The grant names the vault, and the tasks the run makes are
//! recorded under it.
//!
//! **Who gets it.** A run of the project, for the owner whose row it opened:
//!
//! * a project run whose build is a WasmUrl version of the project on the
//!   contract — the check declared keys pass, made by the same reads. A direct
//!   run of a wasm URL and a build from a GitHub repository get none;
//! * that names a secret row OF THIS PROJECT — the row's accessor is the run's
//!   own project — and the row opened: its access condition admitted the
//!   caller and it decrypted. A row that does not exist yields no task key and
//!   the run goes on without one; a row that refuses the caller refuses the
//!   request, as it does without a task key.
//!
//! * whose caller and predecessor are accounts: neither a placeholder the
//!   worker writes for a run without one, nor a string that is no NEAR
//!   account id — what a declared key asks of them. A run that names declared
//!   keys too is refused on them; a run that asks for the task key alone is
//!   served its row as a request without `task_key` is, and no task key.
//!
//! So the key is bound to the two facts the keystore itself established — the
//! project the code is published under and the owner whose row admitted the
//! run — and to nothing a request spells. Every run of the project admitted
//! to the owner's row holds the same key: which tasks a run may touch is
//! decided by the worker's host, which holds the key and never gives it to
//! the guest.
//!
//! **Admitted by name.** The answer says whether the row's condition admitted
//! the caller by a whitelist that lists them
//! ([`crate::types::AccessCondition::admits_by_name`]). The host opens a task
//! for the owner only for a run admitted so, or the owner's own.
//!
//! **A root of its own.** No other string this keystore derives starts with
//! `task-key:`: a declared key's starts with `signing-key:v1:` or
//! `encryption-key:v1:`, and a seed a caller spells is refused when it starts
//! at any of the three (`api.rs`, `DECLARED_KEY_ROOTS`). `v1` names the
//! scheme and never changes; another scheme would be `task-key:v2:`.

use crate::signing_keys::{truncate_for_message, ProjectId, ProjectUuid, SeedHex, WasmSha256, PLACEHOLDER_CALLERS};
use near_primitives::types::AccountId;
use serde::Serialize;

/// The root of every task key's derivation string.
pub const TASK_KEY_LABEL: &str = "task-key:v1:";

/// What a request that asks for a task key says of its run, validated before
/// any chain read.
#[derive(Debug, Clone)]
pub struct TaskKeyRun {
    pub project: ProjectId,
    pub wasm_sha256: WasmSha256,
    /// The account whose secret row the run names.
    pub owner: AccountId,
}

/// Validate what the request says. `row_project` is the project the named
/// row's accessor spells — `None` for a request that names no row, or a row
/// of another kind. Refused:
/// * a direct run (no `project_id`), or a malformed project id;
/// * a build hash that is missing or not 64 lowercase hex;
/// * no secret row, or a row that is not the run's own project's;
/// * an owner that is a placeholder or not a NEAR account id.
pub fn validate_request(
    project_id: Option<&str>,
    executed_wasm_sha256: Option<&str>,
    row_project: Option<&str>,
    row_owner: Option<&str>,
) -> Result<TaskKeyRun, String> {
    let Some(project_id) = project_id else {
        return Err("a task key is issued only to a run through a project, and this is a direct run with none".to_string());
    };
    let project = ProjectId::parse(project_id)?;
    let Some(executed_wasm_sha256) = executed_wasm_sha256 else {
        return Err("a task key needs the running build's executed_wasm_sha256, and the request names none".to_string());
    };
    let wasm_sha256 = WasmSha256::parse(executed_wasm_sha256)?;
    let (Some(row_project), Some(row_owner)) = (row_project, row_owner) else {
        return Err(
            "a task key belongs to the owner of the secret row a run names, and the request names no row of a project"
                .to_string(),
        );
    };
    if row_project != project.as_str() {
        return Err(format!(
            "the secret row is project {:?}'s and the run is project {}'s; a task key is issued for the run's own \
             project's row",
            truncate_for_message(row_project),
            project.as_str()
        ));
    }
    if PLACEHOLDER_CALLERS.contains(&row_owner) {
        return Err(format!("the owner {row_owner:?} is the worker's placeholder for a missing account, not an account"));
    }
    let owner: AccountId = row_owner
        .parse()
        .map_err(|e| format!("the owner {:?} is not a valid NEAR account id ({e})", truncate_for_message(row_owner)))?;
    Ok(TaskKeyRun { project, wasm_sha256, owner })
}

/// Are the accounts a run names accounts a task is made or answered by?
/// `user_account_id` made the run and `predecessor_id`, when the run names
/// one, called OutLayer. Neither is a placeholder ([`PLACEHOLDER_CALLERS`]),
/// and each is a NEAR account id. The refusal names the one that is not.
pub fn real_callers(user_account_id: &str, predecessor_id: Option<&str>) -> Result<(), String> {
    for (role, raw) in [("caller", Some(user_account_id)), ("predecessor", predecessor_id)] {
        let Some(raw) = raw else { continue };
        if PLACEHOLDER_CALLERS.contains(&raw) {
            return Err(format!(
                "the {role} {raw:?} is the worker's placeholder for a run without one, not an account; a task is \
                 made and answered by an account, so a run without one gets no task key"
            ));
        }
        raw.parse::<AccountId>().map_err(|e| {
            format!(
                "the {role} {:?} is not a valid NEAR account id ({e}); a task is made and answered by one",
                truncate_for_message(raw)
            )
        })?;
    }
    Ok(())
}

/// The derivation string of one task key. Built only here, from a uuid the
/// contract gave and an account id — neither can hold a `:`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskKeyInput(String);

impl TaskKeyInput {
    pub fn new(project: &ProjectUuid, owner: &AccountId) -> Self {
        Self(format!("{TASK_KEY_LABEL}{}:{}", project.as_str(), owner.as_str()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    #[cfg(test)]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The task key as the `/decrypt` response carries it.
#[derive(Debug, Serialize)]
pub struct TaskKeyGrant {
    /// 32 bytes, hex.
    pub key: SeedHex,
    /// Whether the row's condition admitted the caller by a whitelist that
    /// lists them.
    pub admitted_by_name: bool,
    /// The vault the row is bound to, whose master the key is under; absent
    /// for a row bound to none. Recorded beside the tasks the run makes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const WASM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn refusal(project: Option<&str>, wasm: Option<&str>, row_project: Option<&str>, owner: Option<&str>) -> String {
        validate_request(project, wasm, row_project, owner).expect_err("refused")
    }

    #[test]
    fn a_project_run_that_names_its_own_projects_row_is_valid() {
        let run = validate_request(Some("alice.near/app"), Some(WASM), Some("alice.near/app"), Some("owner.near")).unwrap();
        assert_eq!(run.project.as_str(), "alice.near/app");
        assert_eq!(run.owner.as_str(), "owner.near");
        assert_eq!(run.wasm_sha256.as_str(), WASM);
    }

    #[test]
    fn a_direct_run_gets_none() {
        assert!(refusal(None, Some(WASM), Some("alice.near/app"), Some("owner.near")).contains("direct run"));
    }

    #[test]
    fn a_run_without_a_build_hash_gets_none() {
        assert!(refusal(Some("alice.near/app"), None, Some("alice.near/app"), Some("owner.near")).contains("executed_wasm_sha256"));
        assert!(refusal(Some("alice.near/app"), Some("AB"), Some("alice.near/app"), Some("owner.near")).contains("64 lowercase hex"));
    }

    #[test]
    fn a_run_that_names_no_row_gets_none() {
        assert!(refusal(Some("alice.near/app"), Some(WASM), None, None).contains("names no row"));
        assert!(refusal(Some("alice.near/app"), Some(WASM), None, Some("owner.near")).contains("names no row"));
    }

    #[test]
    fn a_row_of_another_project_gets_none() {
        let said = refusal(Some("alice.near/app"), Some(WASM), Some("bob.near/other"), Some("owner.near"));
        assert!(said.contains("bob.near/other") && said.contains("alice.near/app"), "{said}");
    }

    #[test]
    fn an_owner_that_is_no_account_gets_none() {
        assert!(refusal(Some("alice.near/app"), Some(WASM), Some("alice.near/app"), Some("anonymous")).contains("placeholder"));
        assert!(refusal(Some("alice.near/app"), Some(WASM), Some("alice.near/app"), Some("Not An Account")).contains("not a valid NEAR account id"));
    }

    #[test]
    fn a_caller_or_a_predecessor_that_is_no_account_is_told_from_one_that_is() {
        real_callers("agent.near", None).unwrap();
        real_callers("agent.near", Some("agent.near")).unwrap();
        real_callers("agent.near", Some("dao.near")).unwrap();
        for placeholder in PLACEHOLDER_CALLERS {
            let said = real_callers(placeholder, None).unwrap_err();
            assert!(said.contains("the caller") && said.contains("placeholder"), "{said}");
            let said = real_callers("agent.near", Some(placeholder)).unwrap_err();
            assert!(said.contains("the predecessor") && said.contains("placeholder"), "{said}");
        }
        let long = "a".repeat(5000);
        for no_account in ["", "Not An Account", "a", "agent.near/app", long.as_str()] {
            let said = real_callers(no_account, None).unwrap_err();
            assert!(said.contains("the caller") && said.contains("not a valid NEAR account id"), "{said}");
            assert!(said.len() < 600, "what is quoted is bounded: {}", said.len());
            let said = real_callers("agent.near", Some(no_account)).unwrap_err();
            assert!(said.contains("the predecessor") && said.contains("not a valid NEAR account id"), "{said}");
        }
    }

    /// A row bound to a vault seals its tasks under the vault's master: the
    /// same label under another master is another key, and a vault that is
    /// not loaded gives none.
    #[test]
    fn a_row_bound_to_a_vault_gets_its_key_under_the_vaults_master() {
        let keystore = crate::crypto::Keystore::generate();
        let uuid = ProjectUuid::parse("p0000000000000001").unwrap();
        let owner: AccountId = "owner.near".parse().unwrap();
        let input = TaskKeyInput::new(&uuid, &owner);
        let vault: AccountId = "v1.vault.near".parse().unwrap();
        let under_default = keystore.derive_task_key(&input, None).unwrap();
        assert!(keystore.derive_task_key(&input, Some(&vault)).is_err(), "a vault not loaded gives no key");
        keystore.add_customer(vault.clone(), [5u8; 32]);
        let under_vault = keystore.derive_task_key(&input, Some(&vault)).unwrap();
        assert_ne!(under_default.as_ref(), under_vault.as_ref());
        assert_eq!(under_vault.as_ref(), keystore.derive_task_key(&input, Some(&vault)).unwrap().as_ref());
        keystore.evict_customer(&vault);
        assert!(keystore.derive_task_key(&input, Some(&vault)).is_err(), "evicted, it gives none again");
    }

    #[test]
    fn the_string_is_the_root_the_uuid_and_the_owner() {
        let uuid = ProjectUuid::parse("p0000000000000001").unwrap();
        let owner: AccountId = "owner.near".parse().unwrap();
        assert_eq!(TaskKeyInput::new(&uuid, &owner).as_str(), "task-key:v1:p0000000000000001:owner.near");
    }

    #[test]
    fn the_grant_prints_nothing_of_the_key() {
        let grant = TaskKeyGrant { key: SeedHex::from_seed(&[7u8; 32]), admitted_by_name: true, vault: Some("vault.near".into()) };
        assert!(!format!("{grant:?}").contains("0707"));
        let sent = serde_json::to_value(&grant).unwrap();
        assert_eq!(sent["key"], "07".repeat(32));
        assert_eq!(sent["admitted_by_name"], true);
        assert_eq!(sent["vault"], "vault.near");
        let unbound = TaskKeyGrant { key: SeedHex::from_seed(&[7u8; 32]), admitted_by_name: false, vault: None };
        assert!(serde_json::to_value(&unbound).unwrap().get("vault").is_none(), "no vault, no member");
    }
}
