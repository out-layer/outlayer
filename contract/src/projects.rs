//! Project management module
//!
//! Implements the Project system for persistent storage across WASM versions.
//! Projects allow developers to update their code while preserving user data.
//!
//! ## Simplified Design (no yield/resume for projects)
//!
//! Projects are created and versions are added synchronously:
//! - create_project() and add_version() save data immediately
//! - For WasmUrl sources: wasm_hash is taken from the URL hash
//! - For GitHub sources: wasm_hash is empty, computed on first execution
//! - Worker verifies metadata (cleanup functions) at execution time, not at version addition
//!
//! This simplifies both contract and worker code - worker doesn't need
//! to distinguish between execution requests and version compilation requests.

use crate::*;
use near_sdk::collections::UnorderedMap;
use near_sdk::{env, log, near_bindgen, Promise};

/// Storage cost per byte in NEAR (same as secrets)
pub const STORAGE_PRICE_PER_BYTE: Balance = 10_000_000_000_000_000_000; // 0.00001 NEAR per byte

/// Base storage overhead for a project entry
const PROJECT_BASE_STORAGE: u64 = 200;

/// Base storage overhead for a version entry
const VERSION_BASE_STORAGE: u64 = 150;

#[near_bindgen]
impl Contract {
    // =========================================================================
    // Project Creation
    // =========================================================================

    /// Create a new project with first version
    ///
    /// Project ID format: "{predecessor_account_id}/{name}"
    /// Only the account matching the prefix can create such projects.
    ///
    /// ## Version Identification
    /// - For `WasmUrl`: uses the provided `hash` as version key
    /// - For `GitHub`: uses `{repo}@{commit}` as version key (wasm_hash determined on first run)
    ///
    /// ## Metadata Verification
    /// Worker will verify that WASM contains required metadata (cleanup functions)
    /// on first execution. If metadata is missing, execution will fail.
    ///
    /// # Arguments
    /// * `name` - Project name (e.g., "my-app")
    /// * `source` - Code source for first version
    #[payable]
    pub fn create_project(
        &mut self,
        name: String,
        source: CodeSource,
    ) {
        self.assert_not_paused();

        let caller = env::predecessor_account_id();
        let project_id = format!("{}/{}", caller, name);

        // Validate name
        assert!(!name.is_empty(), "Project name cannot be empty");
        assert!(name.len() <= 64, "Project name too long (max 64 chars)");
        assert!(
            name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'),
            "Project name must contain only alphanumeric, dash, or underscore"
        );

        // Check project doesn't exist
        assert!(
            self.projects.get(&project_id).is_none(),
            "Project '{}' already exists",
            project_id
        );

        // Generate UUID (p + 16 hex digits, starting from 1)
        self.next_project_id += 1;
        let uuid = format!("p{:016x}", self.next_project_id);

        assert_code_source(&source);

        // Get version key from source
        let version_key = Self::get_version_key(&source);

        // Calculate storage cost for project + first version
        let project_storage = self.calculate_project_storage_size(&project_id, &uuid);
        let version_storage = self.calculate_version_storage_size(&source);
        let total_storage = project_storage + version_storage;
        let required_deposit = total_storage as u128 * STORAGE_PRICE_PER_BYTE;
        let attached_deposit = env::attached_deposit().as_yoctonear();

        assert!(
            attached_deposit >= required_deposit,
            "Insufficient storage deposit. Required: {} yoctoNEAR, attached: {} yoctoNEAR",
            required_deposit,
            attached_deposit
        );

        // Create project with first version as active
        let project = Project {
            uuid: uuid.clone(),
            owner: caller.clone(),
            name: name.clone(),
            active_version: version_key.clone(),
            created_at: env::block_timestamp(),
            storage_deposit: project_storage as u128 * STORAGE_PRICE_PER_BYTE,
        };

        self.projects.insert(&project_id, &project);

        // Initialize versions map and add first version
        let mut versions: UnorderedMap<String, VersionInfo> = UnorderedMap::new(
            StorageKey::ProjectVersions { project_uuid: uuid.clone() }
        );

        let version_info = VersionInfo {
            source: source.clone(),
            added_at: env::block_timestamp(),
            storage_deposit: version_storage as u128 * STORAGE_PRICE_PER_BYTE,
        };
        versions.insert(&version_key, &version_info);
        self.project_versions.insert(&uuid, &versions);

        // Add to user index
        let mut user_projects = self
            .user_projects_index
            .get(&caller)
            .unwrap_or_else(|| UnorderedSet::new(StorageKey::UserProjectsList { account_id: caller.clone() }));
        user_projects.insert(&project_id);
        self.user_projects_index.insert(&caller, &user_projects);

        // Refund excess deposit
        let excess = attached_deposit - required_deposit;
        if excess > 0 {
            Promise::new(caller.clone())
                .transfer(NearToken::from_yoctonear(excess));
        }        

        log!(
            "Project created: id={}, uuid={}, owner={}, version={}",
            project_id, uuid, caller, version_key
        );
    }

    /// Add a new version to existing project
    ///
    /// Version is added synchronously - no worker confirmation needed.
    /// Worker will verify WASM metadata on first execution.
    ///
    /// # Arguments
    /// * `project_name` - Name of the project (not full ID)
    /// * `source` - Code source for new version
    /// * `set_active` - Whether to make this the active version
    #[payable]
    pub fn add_version(
        &mut self,
        project_name: String,
        source: CodeSource,
        set_active: bool,
    ) {
        self.assert_not_paused();

        let caller = env::predecessor_account_id();
        let project_id = format!("{}/{}", caller, project_name);

        let mut project = self.projects.get(&project_id)
            .expect("Project not found");

        assert_eq!(
            project.owner, caller,
            "Only project owner can add versions"
        );

        assert_code_source(&source);

        let version_key = Self::get_version_key(&source);

        // Calculate storage cost
        let version_storage = self.calculate_version_storage_size(&source);
        let required_deposit = version_storage as u128 * STORAGE_PRICE_PER_BYTE;
        let attached_deposit = env::attached_deposit().as_yoctonear();

        assert!(
            attached_deposit >= required_deposit,
            "Insufficient storage deposit. Required: {} yoctoNEAR, attached: {} yoctoNEAR",
            required_deposit,
            attached_deposit
        );

        // Get versions map
        let mut versions = self.project_versions.get(&project.uuid)
            .expect("Project versions not found");

        // Check version doesn't already exist
        assert!(
            versions.get(&version_key).is_none(),
            "Version '{}' already exists in project",
            version_key
        );

        // Add version
        let version_info = VersionInfo {
            source: source.clone(),
            added_at: env::block_timestamp(),
            storage_deposit: required_deposit,
        };
        versions.insert(&version_key, &version_info);
        self.project_versions.insert(&project.uuid, &versions);

        // Update active version if requested
        if set_active {
            project.active_version = version_key.clone();
            self.projects.insert(&project_id, &project);
        }

        // Refund excess deposit
        let excess = attached_deposit - required_deposit;
        if excess > 0 {
            Promise::new(caller.clone())
                .transfer(NearToken::from_yoctonear(excess));
        }

        log!(
            "Version added: project={}, version={}, active={}",
            project_id, version_key, set_active
        );
    }

    // =========================================================================
    // Helper Functions
    // =========================================================================

    // =========================================================================
    // Version Management
    // =========================================================================

    /// Set active version for a project
    ///
    /// # Arguments
    /// * `project_name` - Name of the project
    /// * `version_key` - Version key to set as active (hash or repo@commit)
    pub fn set_active_version(
        &mut self,
        project_name: String,
        version_key: String,
    ) {
        let caller = env::predecessor_account_id();
        let project_id = format!("{}/{}", caller, project_name);

        let mut project = self.projects.get(&project_id)
            .expect("Project not found");

        assert_eq!(
            project.owner, caller,
            "Only project owner can change active version"
        );

        // Verify version exists
        let versions = self.project_versions.get(&project.uuid)
            .expect("Project versions not found");

        assert!(
            versions.get(&version_key).is_some(),
            "Version '{}' not found in project",
            version_key
        );

        project.active_version = version_key.clone();
        self.projects.insert(&project_id, &project);

        log!(
            "Active version changed: project={}, version={:?}",
            project_id, version_key
        );
    }

    /// Remove a version from project
    ///
    /// Cannot remove the active version - must switch to another first.
    /// Triggers storage cleanup for data written by this version.
    ///
    /// # Arguments
    /// * `project_name` - Name of the project
    /// * `version_key` - Version key to remove
    pub fn remove_version(
        &mut self,
        project_name: String,
        version_key: String,
    ) {
        let caller = env::predecessor_account_id();
        let project_id = format!("{}/{}", caller, project_name);

        let project = self.projects.get(&project_id)
            .expect("Project not found");

        assert_eq!(
            project.owner, caller,
            "Only project owner can remove versions"
        );

        // Cannot remove active version
        assert_ne!(
            project.active_version, version_key,
            "Cannot remove active version. Switch to another version first."
        );

        // Get versions map
        let mut versions = self.project_versions.get(&project.uuid)
            .expect("Project versions not found");

        // Remove version and get deposit
        let version_info = versions.remove(&version_key)
            .expect("Version not found");

        self.project_versions.insert(&project.uuid, &versions);

        // Refund storage deposit
        if version_info.storage_deposit > 0 {
            Promise::new(caller.clone())
                .transfer(NearToken::from_yoctonear(version_info.storage_deposit));
        }

        log!(
            "Version removed: project={}, version={:?}, refund={}",
            project_id, version_key, version_info.storage_deposit
        );
    }

    /// Delete entire project
    ///
    /// Removes project and all versions. Triggers storage cleanup.
    ///
    /// # Arguments
    /// * `project_name` - Name of the project to delete
    pub fn delete_project(&mut self, project_name: String) {
        let caller = env::predecessor_account_id();
        let project_id = format!("{}/{}", caller, project_name);

        let project = self.projects.remove(&project_id)
            .expect("Project not found");

        assert_eq!(
            project.owner, caller,
            "Only project owner can delete project"
        );

        // Remove versions map
        self.project_versions.remove(&project.uuid);

        // Remove from user index
        if let Some(mut user_projects) = self.user_projects_index.get(&caller) {
            user_projects.remove(&project_id);
            if user_projects.is_empty() {
                self.user_projects_index.remove(&caller);
            } else {
                self.user_projects_index.insert(&caller, &user_projects);
            }
        }

        // Refund storage deposit
        if project.storage_deposit > 0 {
            Promise::new(caller.clone())
                .transfer(NearToken::from_yoctonear(project.storage_deposit));
        }

        // Emit event for storage cleanup (worker will delete all data for this project)
        events::emit_project_storage_cleanup(&self.event_standard, &self.event_version, &project_id, &project.uuid);

        log!(
            "Project deleted: project={}, uuid={}, refund={}",
            project_id, project.uuid, project.storage_deposit
        );
    }

    /// Transfer project ownership to another account
    ///
    /// The project will be renamed to `new_owner/name`.
    /// All data is preserved (UUID stays the same).
    ///
    /// # Arguments
    /// * `project_name` - Current name of the project
    /// * `new_owner` - Account to transfer ownership to
    pub fn transfer_project(
        &mut self,
        project_name: String,
        new_owner: AccountId,
    ) {
        let caller = env::predecessor_account_id();
        let old_project_id = format!("{}/{}", caller, project_name);

        let mut project = self.projects.remove(&old_project_id)
            .expect("Project not found");

        assert_eq!(
            project.owner, caller,
            "Only project owner can transfer project"
        );

        // New project ID
        let new_project_id = format!("{}/{}", new_owner, project_name);

        // Check new project_id doesn't exist
        assert!(
            self.projects.get(&new_project_id).is_none(),
            "Project '{}' already exists",
            new_project_id
        );

        // Update owner
        project.owner = new_owner.clone();

        // Insert with new key
        self.projects.insert(&new_project_id, &project);

        // Update user indices
        // Remove from old owner
        if let Some(mut old_user_projects) = self.user_projects_index.get(&caller) {
            old_user_projects.remove(&old_project_id);
            if old_user_projects.is_empty() {
                self.user_projects_index.remove(&caller);
            } else {
                self.user_projects_index.insert(&caller, &old_user_projects);
            }
        }

        // Add to new owner
        let mut new_user_projects = self
            .user_projects_index
            .get(&new_owner)
            .unwrap_or_else(|| UnorderedSet::new(StorageKey::UserProjectsList { account_id: new_owner.clone() }));
        new_user_projects.insert(&new_project_id);
        self.user_projects_index.insert(&new_owner, &new_user_projects);

        log!(
            "Project transferred: {} -> {}, uuid={}",
            old_project_id, new_project_id, project.uuid
        );

        self.emit_system_event(crate::payment::SystemEvent::ProjectTransferred {
            old_project_id,
            new_project_id,
            project_uuid: project.uuid,
            old_owner: caller,
            new_owner,
        });
    }

    // =========================================================================
    // Storage Calculation
    // =========================================================================

}

// View methods
#[near_bindgen]
impl Contract {
    /// Get project by full ID ("owner.near/name")
    pub fn get_project(&self, project_id: String) -> Option<ProjectView> {
        self.projects.get(&project_id).map(|project| {
            ProjectView {
                uuid: project.uuid,
                owner: project.owner,
                name: project.name,
                project_id,
                active_version: project.active_version,
                created_at: project.created_at,
                storage_deposit: U128(project.storage_deposit),
            }
        })
    }

    /// List all projects for a user
    pub fn list_user_projects(&self, account_id: AccountId) -> Vec<ProjectView> {
        self.user_projects_index
            .get(&account_id)
            .map(|project_ids| {
                project_ids
                    .iter()
                    .filter_map(|project_id| self.get_project(project_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get version info
    pub fn get_version(
        &self,
        project_id: String,
        version_key: String,
    ) -> Option<VersionView> {
        let project = self.projects.get(&project_id)?;
        let versions = self.project_versions.get(&project.uuid)?;
        let version = versions.get(&version_key)?;

        Some(VersionView {
            wasm_hash: version_key.clone(),
            source: version.source,
            added_at: version.added_at,
            is_active: project.active_version == version_key,
        })
    }

    /// List all versions for a project with pagination
    ///
    /// # Arguments
    /// * `project_id` - Full project ID ("owner.near/name")
    /// * `from_index` - Start index (0-based)
    /// * `limit` - Maximum number of versions to return
    pub fn list_versions(
        &self,
        project_id: String,
        from_index: Option<u64>,
        limit: Option<u64>,
    ) -> Vec<VersionView> {
        let project = match self.projects.get(&project_id) {
            Some(p) => p,
            None => return vec![],
        };

        let versions = match self.project_versions.get(&project.uuid) {
            Some(v) => v,
            None => return vec![],
        };

        let from = from_index.unwrap_or(0) as usize;
        let limit = limit.unwrap_or(50).min(100) as usize;

        versions
            .iter()
            .skip(from)
            .take(limit)
            .map(|(wasm_hash, version)| VersionView {
                wasm_hash: wasm_hash.clone(),
                source: version.source.clone(),
                added_at: version.added_at,
                is_active: project.active_version == wasm_hash,
            })
            .collect()
    }

    /// Whether a live project holds this uuid, under whatever name it has now.
    /// A deleted project's uuid is gone for good (uuids are never reused), so
    /// `false` is what allows the storage of that uuid to be erased.
    pub fn has_project_uuid(&self, project_uuid: String) -> bool {
        self.project_versions.contains_key(&project_uuid)
    }

    /// Get total number of versions for a project
    pub fn get_version_count(&self, project_id: String) -> u64 {
        let project = match self.projects.get(&project_id) {
            Some(p) => p,
            None => return 0,
        };

        self.project_versions
            .get(&project.uuid)
            .map(|v| v.len())
            .unwrap_or(0)
    }
}


// Internals. Deliberately OUTSIDE `#[near_bindgen]`: the macro exports a
// contract method for every `pub fn` in a block it annotates, so a helper that
// lives there is one visibility keyword away from becoming a public entry
// point. Out here that cannot happen by accident.
impl Contract {
    /// Get version key from code source
    /// - For WasmUrl: returns the hash
    /// - For GitHub: returns "{repo}@{commit}"
    fn get_version_key(source: &CodeSource) -> String {
        match source {
            CodeSource::WasmUrl { hash, .. } => hash.clone(),
            CodeSource::GitHub { repo, commit, .. } => format!("{}@{}", repo, commit),
        }
    }

    fn calculate_project_storage_size(&self, project_id: &str, uuid: &str) -> u64 {
        PROJECT_BASE_STORAGE
            + project_id.len() as u64  // Map key
            + uuid.len() as u64        // uuid field
            + 8                        // created_at
            + 16                       // storage_deposit
    }

    fn calculate_version_storage_size(&self, source: &CodeSource) -> u64 {
        let source_size = match source {
            CodeSource::GitHub { repo, commit, build_target } => {
                repo.len() + commit.len() + build_target.as_ref().map(|t| t.len()).unwrap_or(0)
            }
            CodeSource::WasmUrl { url, hash, build_target } => {
                url.len() + hash.len() + build_target.as_ref().map(|t| t.len()).unwrap_or(0)
            }
        };

        VERSION_BASE_STORAGE
            + source_size as u64
            + 64  // version_key
            + 8   // added_at
            + 16  // storage_deposit
    }
}

/// Longest `WasmUrl.url` accepted.
const MAX_WASM_URL_LEN: usize = 2048;
/// Longest `GitHub.repo` accepted.
const MAX_REPO_LEN: usize = 512;
/// Longest `GitHub.commit` accepted.
const MAX_COMMIT_LEN: usize = 256;
/// Longest `build_target` accepted.
const MAX_BUILD_TARGET_LEN: usize = 64;

/// Why a code source cannot be stored or run, or `None` when it is well formed.
///
/// Its fields become the version key (`hash`, or `repo@commit`), which the
/// contract writes into its logs, and they reach the worker's `git` and HTTP
/// client. Each is held to the shape the worker can actually use:
/// - `hash`: the SHA-256 of the WASM as 64 lowercase hex characters, the form
///   the worker compares the downloaded bytes against;
/// - `url`: `https://`, no whitespace or control characters;
/// - `repo`: letters, digits, `.`, `_`, `-`, `/`, `:`; no leading `-`, no `..`;
/// - `commit`: a git ref as the worker accepts it (`validate_git_ref`): letters,
///   digits, `.`, `_`, `/`, `-`, `+`; no leading `-`, no `..`;
/// - `build_target`: letters, digits, `.`, `_`, `-`.
///
/// No field admits whitespace or a line break, and `EVENT_JSON` is refused by
/// name. `url` may still hold `{` and `"`: every log prints it with `{:?}`, and
/// events carry it JSON-escaped.
pub(crate) fn code_source_error(source: &CodeSource) -> Option<String> {
    let (build_target, err) = match source {
        CodeSource::WasmUrl { url, hash, build_target } => {
            let err = if hash.len() != 64 || !hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
                Some("source.hash must be the SHA-256 of the WASM as 64 lowercase hex characters".to_string())
            } else if !url.starts_with("https://") || url.len() <= "https://".len() {
                Some("source.url must be an https:// URL".to_string())
            } else if url.len() > MAX_WASM_URL_LEN {
                Some(format!("source.url is longer than {MAX_WASM_URL_LEN} bytes"))
            } else if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
                Some("source.url must not contain whitespace or control characters".to_string())
            } else {
                None
            };
            (build_target, err.or_else(|| names_an_event("source.url", url)))
        }
        CodeSource::GitHub { repo, commit, build_target } => {
            let err = if repo.is_empty() || repo.len() > MAX_REPO_LEN {
                Some(format!("source.repo must be 1–{MAX_REPO_LEN} bytes"))
            } else if repo.starts_with('-')
                || repo.contains("..")
                || !repo.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
            {
                Some("source.repo must be a GitHub repository (letters, digits, '.', '_', '-', '/', ':'; no leading '-', no '..')".to_string())
            } else if commit.is_empty() || commit.len() > MAX_COMMIT_LEN {
                Some(format!("source.commit must be 1–{MAX_COMMIT_LEN} bytes"))
            } else if commit.starts_with('-')
                || commit.contains("..")
                || !commit.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-' | b'+'))
            {
                Some("source.commit must be a commit hash, branch or tag (letters, digits, '.', '_', '/', '-', '+'; no leading '-', no '..')".to_string())
            } else {
                None
            };
            let err = err
                .or_else(|| names_an_event("source.repo", repo))
                .or_else(|| names_an_event("source.commit", commit));
            (build_target, err)
        }
    };
    err.or_else(|| {
        let t = build_target.as_deref()?;
        if t.is_empty()
            || t.len() > MAX_BUILD_TARGET_LEN
            || !t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            Some(format!(
                "source.build_target must be 1–{MAX_BUILD_TARGET_LEN} bytes of letters, digits, '.', '_' or '-'"
            ))
        } else {
            None
        }
    })
}

/// `EVENT_JSON` opens every NEP-297 event log; no field of a code source has a
/// reason to spell it.
fn names_an_event(field: &str, value: &str) -> Option<String> {
    value
        .contains("EVENT_JSON")
        .then(|| format!("{field} must not contain 'EVENT_JSON'"))
}

/// Panics with the reason when `source` is not well formed (`code_source_error`).
pub(crate) fn assert_code_source(source: &CodeSource) {
    if let Some(why) = code_source_error(source) {
        env::panic_str(&why);
    }
}
