use crate::*;
use near_sdk::borsh::BorshDeserialize;

/// The layout live on `worker.outlayer.{testnet,near}`: multi-slot collaterals, no governance.
/// Field order MUST match the serialized layout.
#[derive(BorshDeserialize)]
#[cfg_attr(test, derive(near_sdk::borsh::BorshSerialize))]
#[borsh(crate = "near_sdk::borsh")]
pub struct RegisterContractV3 {
    pub owner_id: AccountId,
    pub init_worker_account: AccountId,
    pub approved_measurements: Vec<ApprovedMeasurements>,
    pub collaterals: Vec<String>,
    pub outlayer_contract_id: AccountId,
}

#[near_bindgen]
impl RegisterContract {
    /// V3 → V4: adds `governance_id`. Run once, with the full-access key that deploys V4 —
    /// the last deploy that key makes. Every version deployed through governance after this
    /// one has a `migrate()` without arguments (see `upgrade`).
    #[private]
    #[init(ignore_state)]
    pub fn migrate(governance_id: AccountId) -> Self {
        let old: RegisterContractV3 = env::state_read().expect("Failed to read V3 state");
        Self {
            owner_id: old.owner_id,
            init_worker_account: old.init_worker_account,
            approved_measurements: old.approved_measurements,
            collaterals: old.collaterals,
            outlayer_contract_id: old.outlayer_contract_id,
            governance_id,
        }
    }
}
