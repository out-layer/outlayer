//! OutLayer Persistent Storage for WASM host functions
//!
//! This module provides storage host functions that allow WASM code
//! to persist data across executions. Records are stored
//! in the coordinator's PostgreSQL database.
//!
//! ## Architecture
//!
//! ```text
//! WASM Code (outlayer crate)
//!     │ extern "C" calls via WIT
//!     ▼
//! Host Functions (this module)
//!     │ calls StorageClient
//!     ▼
//! StorageClient (HTTP to Coordinator)
//!     │ encrypted or raw records
//!     ▼
//! Coordinator API (/storage/*)
//!     │
//!     ▼
//! PostgreSQL (storage_data table)
//! ```
//!
//! ## Security
//!
//! - `set`/`get` and the conditional writes encrypt each record with
//!   `derive_key(master_key, project_uuid, account_id)` via the keystore
//! - The `-raw` functions store the caller's key name and bytes as given
//!   (`is_encrypted = false`) and never call the keystore; the caller encrypts
//!   first. A record is read and written only in the mode it was written in
//! - Keys are hashed (SHA256) for the unique constraint; both modes share one
//!   key namespace per project and account
//! - `@worker` account_id for WASM-private storage (not accessible by users)
//! - wasm_hash stored with each write for version migration support
//!
//! ## Whose cell
//!
//! Every function outside the `@worker` ones reads and writes ONE account's
//! cell of the project, fixed for the run before it executes by
//! [`cell_account`]: the manifest's `storage_account` picks which account of
//! the job it is — `signer` (the default: the transaction signer on chain,
//! the payment-key owner over HTTPS, `anonymous` when there is neither) or
//! `predecessor` (the account that called the contract on chain, the
//! payment-key owner over HTTPS; a run with none is refused). No host
//! function takes an account from the guest.

pub mod client;
pub mod host_functions;
#[cfg(test)]
mod fake_http;

pub use client::{StorageClient, StorageConfig};
pub use host_functions::{add_storage_to_linker, StorageHostState};

use crate::connector_manifest::StorageAccount;

/// The account whose cell of the project a run's storage reads and writes.
///
/// `declared` is the manifest's `storage_account` (the default when the
/// artefact carries no manifest); `user_account_id` and `predecessor_id` are
/// the job's — the second the same value the secrets and the
/// `caller: "predecessor"` keys are judged for (on chain the receipt's
/// predecessor from the job's context, over HTTPS the payment-key owner).
/// `Err` is the refusal: a `predecessor` cell on a run that carries no
/// predecessor has no owner, and neither the signer nor `anonymous` stands
/// in for one.
pub fn cell_account(
    declared: StorageAccount,
    user_account_id: Option<&str>,
    predecessor_id: Option<&str>,
) -> Result<String, String> {
    match declared {
        StorageAccount::Signer => Ok(user_account_id.unwrap_or("anonymous").to_string()),
        StorageAccount::Predecessor => match predecessor_id {
            Some(p) if !p.is_empty() => Ok(p.to_string()),
            _ => Err(
                "the manifest declares `storage_account: \"predecessor\"`, and this run carries no \
                 predecessor to own its storage; such a component runs only as a call some account made \
                 — on chain through the contract, or over HTTPS with a payment key"
                    .to_string(),
            ),
        },
    }
}

#[cfg(test)]
mod cell_account_tests {
    use super::*;
    use crate::connector_manifest::ProjectManifest;

    fn declared(manifest: &str) -> StorageAccount {
        ProjectManifest::read(manifest.as_bytes()).expect("manifest").storage_account
    }

    /// No field, or `signer`: the account is exactly what it was before the
    /// field existed — the signer, `anonymous` without one — whatever the
    /// predecessor is.
    #[test]
    fn signer_is_the_default_and_unchanged() {
        assert_eq!(declared("{}"), StorageAccount::Signer);
        assert_eq!(declared(r#"{"connector_id":"x"}"#), StorageAccount::Signer);
        assert_eq!(declared(r#"{"storage_account":"signer"}"#), StorageAccount::Signer);
        let before = |user: Option<&String>| user.cloned().unwrap_or_else(|| "anonymous".to_string());
        for (user, pred) in [
            (Some("alice.near"), Some("dao.near")),
            (Some("alice.near"), Some("alice.near")),
            (Some("alice.near"), None),
            (None, Some("dao.near")),
            (None, None),
            (Some(""), Some("dao.near")),
        ] {
            let owned = user.map(str::to_string);
            assert_eq!(
                cell_account(StorageAccount::Signer, user, pred).unwrap(),
                before(owned.as_ref()),
                "signer cell for user {user:?}, predecessor {pred:?}"
            );
        }
    }

    /// On chain the cell is the receipt's predecessor — a relaying contract,
    /// not the transaction's signer.
    #[test]
    fn predecessor_on_chain_is_the_receipt_predecessor() {
        assert_eq!(declared(r#"{"storage_account":"predecessor"}"#), StorageAccount::Predecessor);
        assert_eq!(
            cell_account(StorageAccount::Predecessor, Some("alice.near"), Some("relay.near")).unwrap(),
            "relay.near"
        );
        // A direct call: the predecessor is the signer, and so is the cell.
        assert_eq!(
            cell_account(StorageAccount::Predecessor, Some("alice.near"), Some("alice.near")).unwrap(),
            "alice.near"
        );
    }

    /// Over HTTPS the job path passes the payment-key owner as the
    /// predecessor, so the two declarations name one cell.
    #[test]
    fn predecessor_over_https_is_the_user_account() {
        let user = Some("owner.near");
        let predecessor = user; // the HTTPS arm of `predecessor_id` in main.rs
        assert_eq!(
            cell_account(StorageAccount::Predecessor, user, predecessor).unwrap(),
            cell_account(StorageAccount::Signer, user, predecessor).unwrap()
        );
    }

    /// No predecessor: refused, never the signer and never `anonymous`.
    #[test]
    fn a_missing_predecessor_is_refused() {
        for user in [Some("alice.near"), None] {
            for pred in [None, Some("")] {
                let err = cell_account(StorageAccount::Predecessor, user, pred).unwrap_err();
                assert!(err.contains("no predecessor"), "{err}");
            }
        }
    }

    /// Only the two spellings parse; anything else makes the manifest
    /// unreadable, which refuses the run.
    #[test]
    fn an_unknown_value_does_not_parse() {
        for bad in [
            r#"{"storage_account":"Predecessor"}"#,
            r#"{"storage_account":"contract"}"#,
            r#"{"storage_account":""}"#,
            r#"{"storage_account":null}"#,
            r#"{"storage_account":1}"#,
        ] {
            assert!(ProjectManifest::read(bad.as_bytes()).is_err(), "{bad} must not parse");
        }
    }
}
