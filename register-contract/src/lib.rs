use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::json_types::Base58CryptoHash;
use near_sdk::{env, near_bindgen, require, AccountId, Allowance, CurveType, Gas, NearToken, Promise, PublicKey, BorshStorageKey};
use schemars::JsonSchema;

// Collateral wrapper with Borsh support (same approach as MPC Node)
mod collateral;
use collateral::Collateral;

pub(crate) mod migration;

#[cfg(test)]
mod governance_tests;

// Custom getrandom implementation for WASM (same as MPC Node)
// We don't need actual randomness in this contract (only verification)
#[cfg(target_arch = "wasm32")]
use getrandom::{register_custom_getrandom, Error};
#[cfg(target_arch = "wasm32")]
fn randomness_unsupported(_: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
register_custom_getrandom!(randomness_unsupported);

#[derive(BorshSerialize, BorshStorageKey)]
#[borsh(crate = "near_sdk::borsh")]
#[allow(dead_code)] // ApprovedRtmr3 used only in migration deserialization
enum StorageKey {
    ApprovedRtmr3,
}

/// Full TEE measurements for verifying the entire dstack environment.
/// All fields are 96 hex characters (48 bytes).
///
/// Without verifying MRTD + RTMR0-2, an attacker can run a dev dstack image
/// (with SSH enabled), connect to the container, and modify the running code
/// while RTMR3 still passes because the docker-compose is the same.
#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, JsonSchema, Clone, PartialEq, Eq, Debug)]
#[serde(crate = "near_sdk::serde")]
pub struct ApprovedMeasurements {
    /// MRTD - Virtual firmware (TDX module) identity
    pub mrtd: String,
    /// RTMR0 - Bootloader, firmware config
    pub rtmr0: String,
    /// RTMR1 - OS kernel, boot params, initrd
    pub rtmr1: String,
    /// RTMR2 - OS applications layer
    pub rtmr2: String,
    /// RTMR3 - Runtime events (compose-hash, key-provider)
    pub rtmr3: String,
}

/// Register Contract - TEE Worker Key Registration
///
/// This contract verifies TDX attestations and registers worker public keys
/// by adding them as access keys to its own account (the worker account).
///
/// # Security Model
/// 1. Worker generates keypair INSIDE TEE (private key never leaves TEE)
/// 2. Worker generates TDX quote with public key embedded in report_data
/// 3. This contract verifies TDX quote signature (Intel cryptographic proof)
/// 4. This contract extracts MRTD + RTMR0-3 and checks them against approved measurements list
/// 5. This contract adds public key to itself (current_account_id) with permissions for offchainvm_contract_id
/// 6. Result: Public key is cryptographically proven to be generated in approved TEE
///
/// # Roles
/// - Governance (`governance_id`, the DAO): approves worker builds, replaces the owner (`set_owner`),
///   upgrades this contract.
/// - Owner (ops): revokes builds, removes worker keys, keeps the Intel collateral current.
/// - `init_worker_account`: submits `register_worker_key` with a TDX quote of an approved build.
/// Max number of cached quote collaterals (one per platform/FMSPC, e.g. Phala + self-hosted).
/// register_worker_key tries each until the worker's quote verifies; keep small (gas).
const MAX_COLLATERALS: usize = 2;

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct RegisterContract {
    /// Owner who can manage approved RTMR3 list
    pub owner_id: AccountId,

    /// Init worker account that can call register_worker_key
    pub init_worker_account: AccountId,

    /// Full TEE measurements approved for worker registration.
    /// Each entry contains MRTD + RTMR0-3 (all must match for registration).
    pub approved_measurements: Vec<ApprovedMeasurements>,

    /// Cached quote collateral(s) — Intel reference data for TDX quote verification, one slot
    /// per platform/FMSPC (e.g. [0]=Phala 20a06f000000, [1]=self-hosted B0C06F000000).
    /// register_worker_key tries each slot until the worker's quote verifies, so a mixed fleet
    /// (Phala + self-hosted) coexists without deleting the other's collateral. Bounded by
    /// MAX_COLLATERALS; owner manages slots via `update_collateral(collateral, index)`.
    pub collaterals: Vec<String>,

    pub outlayer_contract_id: AccountId,

    /// The DAO (`dao.outlayer.<net>`). Approves worker builds, replaces the owner and
    /// upgrades this contract — see `upgrade`. A worker build that registers here opens
    /// keystore sessions, so approving one is a governance decision, never an owner's.
    pub governance_id: AccountId,
}

/// Gas for `migrate` and `gov_health` in the upgrade batch.
const MIGRATE_GAS: Gas = Gas::from_tgas(60);
const HEALTH_GAS: Gas = Gas::from_tgas(20);

impl Default for RegisterContract {
    fn default() -> Self {
        env::panic_str("RegisterContract must be initialized");
    }
}

// near-sdk >= 5.29 requires contract structs to implement `ContractState`. All methods are
// defaulted and `state_key()` stays `b"STATE"`, so the on-chain state layout and storage key
// are byte-identical to what the deployed contract already uses (no migration needed).
impl near_sdk::state::ContractState for RegisterContract {}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(crate = "near_sdk::serde")]
pub struct WorkerKeyInfo {
    #[schemars(with = "String")]
    pub public_key: PublicKey,
    pub measurements: ApprovedMeasurements,
    pub registered_at: u64,
}

#[near_bindgen]
impl RegisterContract {
    /// Initialize contract
    #[init]
    pub fn new(
        owner_id: AccountId,
        init_worker_account: AccountId,
        outlayer_contract_id: AccountId,
        governance_id: AccountId,
    ) -> Self {
        Self {
            owner_id,
            init_worker_account,
            approved_measurements: Vec::new(),
            collaterals: Vec::new(),
            outlayer_contract_id,
            governance_id,
        }
    }

    /// Register worker public key with TEE attestation
    ///
    /// This method:
    /// 1. Verifies TDX quote signature (Intel cryptographic proof)
    /// 2. Extracts RTMR3 from quote
    /// 3. Checks RTMR3 is in approved list
    /// 4. Extracts public key from quote report_data
    /// 5. Verifies public_key parameter matches embedded key
    /// 6. Adds access key to this contract's account (self)
    ///
    /// # Arguments
    /// * `public_key` - Worker's ed25519 public key (generated in TEE)
    /// * `tdx_quote_hex` - Hex-encoded TDX quote from Phala dstack
    ///
    /// # Returns
    /// Promise to add access key to this account
    ///
    /// # Panics
    /// - If TDX quote verification fails
    /// - If RTMR3 not in approved list
    /// - If public key doesn't match quote
    /// - If collateral not cached (use update_collateral first)
    pub fn register_worker_key(
        &mut self,
        public_key: PublicKey,
        tdx_quote_hex: String,
    ) -> Promise {
        // Check that caller is init_worker_account
        assert_eq!(
            env::predecessor_account_id(),
            self.init_worker_account,
            "Only {} can call register_worker_key",
            self.init_worker_account
        );

        // Use ONLY cached collateral(s) (security: prevent custom collateral bypass).
        let collaterals = self.collaterals.clone();
        assert!(
            !collaterals.is_empty(),
            "No quote collateral cached (owner must call update_collateral)"
        );

        // 1. Select the collateral whose FMSPC matches the quote's, then verify ONCE.
        //    dcap-qvl verify is gas-heavy; verifying against every cached slot would exceed
        //    the caller's prepaid gas. So we pick by FMSPC first (cheap quote parse + a small
        //    JSON read of each collateral's tcb_info) and run the expensive verify only once.
        let quote_bytes = hex::decode(&tdx_quote_hex).expect("Invalid quote hex encoding");
        let quote_fmspc = hex::encode(
            dcap_qvl::quote::Quote::parse(&quote_bytes)
                .expect("Failed to parse TDX quote")
                .fmspc()
                .expect("No FMSPC in TDX quote"),
        );
        let collateral = collaterals
            .iter()
            .find(|c| {
                Self::collateral_fmspc(c)
                    .map(|f| f.eq_ignore_ascii_case(&quote_fmspc))
                    .unwrap_or(false)
            })
            .unwrap_or_else(|| {
                env::panic_str(&format!(
                    "No cached collateral for quote FMSPC {} (owner must update_collateral for this platform)",
                    quote_fmspc
                ))
            });
        let (measurements, report_data_prefix) = self
            .verify_worker_registration(&tdx_quote_hex, collateral)
            .unwrap_or_else(|e| env::panic_str(&format!("TDX quote verification failed: {e}")));

        // Log verification result for admin visibility
        env::log_str(&format!(
            "📋 Verified TDX quote. report_data binding (hex): {}",
            hex::encode(report_data_prefix)
        ));
        env::log_str(&format!(
            "📋 Measurements from TDX quote: mrtd={}, rtmr0={}, rtmr1={}, rtmr2={}, rtmr3={}",
            measurements.mrtd, measurements.rtmr0, measurements.rtmr1,
            measurements.rtmr2, measurements.rtmr3
        ));

        // 2. Check full measurements are approved
        assert!(
            self.approved_measurements.contains(&measurements),
            "Worker measurements not approved. MRTD={}, RTMR0={}, RTMR1={}, RTMR2={}, RTMR3={}.",
            measurements.mrtd, measurements.rtmr0, measurements.rtmr1,
            measurements.rtmr2, measurements.rtmr3
        );

        // 3. Verify the submitted public_key matches the binding embedded in the TDX quote.
        //    ed25519: the binding is the raw 32-byte public key.
        //    ml-dsa-65: the 1952-byte key does not fit in report_data, so the binding is its
        //    SHA-256. Recompute the same hash here (must match worker::report_data_binding).
        let key_bytes = public_key.as_bytes(); // [curve_tag, ..data]
        let expected_binding: [u8; 32] = match public_key.curve_type() {
            CurveType::ED25519 => {
                let mut b = [0u8; 32];
                b.copy_from_slice(&key_bytes[1..33]);
                b
            }
            CurveType::MLDSA65 => env::sha256_array(&key_bytes[1..]),
            other => env::panic_str(&format!(
                "Unsupported worker key curve {:?} (use ed25519 or ml-dsa-65)",
                other
            )),
        };
        assert_eq!(
            report_data_prefix, expected_binding,
            "Public key mismatch: provided key doesn't match TDX quote report_data"
        );

        // NOTE: do not log the full public_key with {:?} — an ml-dsa-65 key debug-prints to
        // ~19 KB and blows the 16 KB per-log limit. Log the (short) curve + report_data binding.
        env::log_str(&format!(
            "✅ TEE verification passed: all 5 measurements approved, curve={:?}, binding={}",
            public_key.curve_type(),
            hex::encode(report_data_prefix)
        ));

        // 4. Add access key to this contract's account (worker account)
        // Permission: Function call to offchainvm_contract_id::resolve_execution and submit_execution_output_and_resolve
        let allowance: Allowance = Allowance::limited(NearToken::from_near(10)).unwrap(); // 10 NEAR for gas
        let method_names = "resolve_execution,submit_execution_output_and_resolve,resume_topup,resume_delete_payment_key".to_string();
        let current_account = env::current_account_id();
        
        env::log_str(&format!(
            "Adding access key to {}: curve={:?}, binding={}, allowance=10 NEAR, methods={}, receiver={}",
            current_account.clone(), public_key.curve_type(), hex::encode(report_data_prefix), method_names, self.outlayer_contract_id
        ));

        // Add key to this account (self) with permissions for offchainvm_contract_id
        Promise::new(current_account.clone()).add_access_key_allowance(
            public_key,
            allowance,
            self.outlayer_contract_id.clone(),
            method_names,
        )
    }

    /// Extract the FMSPC (hex) from a cached collateral so we can match it against the quote's
    /// FMSPC and verify only the matching slot. Uses a cheap byte scan — NOT a full `serde_json`
    /// parse of the ~22 KB collateral — to stay well under the caller's prepaid gas: `"fmspc"` is
    /// a unique key inside the embedded tcb_info and its value is exactly 6 bytes (12 hex chars).
    fn collateral_fmspc(collateral_str: &str) -> Option<String> {
        let bytes = collateral_str.as_bytes();
        let mut i = collateral_str.find("fmspc")? + "fmspc".len();
        // skip the escaped `":"` separator (any non-hex bytes) up to the value
        while i < bytes.len() && !bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i].is_ascii_hexdigit() {
            i += 1;
        }
        let hex = collateral_str.get(start..i)?;
        (hex.len() >= 12).then(|| hex[..12].to_string())
    }

    /// Verify TDX quote and extract RTMR3 + embedded public key
    ///
    /// Uses dcap-qvl library to:
    /// - Parse TDX quote structure
    /// - Verify Intel's cryptographic signature
    /// - Extract RTMR3 (TEE measurement)
    /// - Extract public key from report_data (first 32 bytes)
    ///
    /// Returns Err (not panic) on any failure (e.g. mismatched-FMSPC collateral or bad signature).
    fn verify_worker_registration(
        &self,
        quote_hex: &str,
        collateral_str: &str,
    ) -> Result<(ApprovedMeasurements, [u8; 32]), String> {
        use dcap_qvl::verify;
        use hex::decode;

        // Decode hex quote
        let quote_bytes = decode(quote_hex).map_err(|e| format!("Invalid quote hex encoding: {e}"))?;

        // Parse collateral JSON using MPC Node's Collateral wrapper (audited code)
        // Full structure with 9 fields including CRL
        let collateral_json: serde_json::Value =
            serde_json::from_str(collateral_str).map_err(|e| format!("Invalid collateral JSON format: {e}"))?;
        let collateral: Collateral = Collateral::try_from_json(collateral_json)
            .map_err(|e| format!("Failed to parse collateral: {e}"))?;

        // Verify quote with Intel's cryptographic signature
        // Uses dcap_qvl 0.3.11 with "contract" feature (NEAR-compatible, same as MPC Node)
        let now = env::block_timestamp() / 1_000_000_000; // Convert to seconds
        let result = verify::verify(&quote_bytes, collateral.inner(), now)
            .map_err(|e| format!("TDX quote verification failed (signature/TCB/collateral mismatch): {e:?}"))?;

        // Reject anything but an up-to-date platform: dcap-qvl's verify() returns Ok
        // for OutOfDate / ConfigurationNeeded / SWHardeningNeeded — only Revoked errors.
        if result.status.as_str() != "UpToDate" {
            return Err(format!(
                "TDX TCB status not acceptable: {} (platform needs a firmware/microcode update)",
                result.status
            ));
        }
        if !result.advisory_ids.is_empty() {
            return Err(format!(
                "TDX platform has outstanding security advisories: {}",
                result.advisory_ids.join(", ")
            ));
        }

        // Extract all measurements from TDX report (MRTD + RTMR0-3)
        let td10 = result
            .report
            .as_td10()
            .ok_or_else(|| "Quote is not TDX format (expected TD10)".to_string())?;

        let measurements = ApprovedMeasurements {
            mrtd: hex::encode(td10.mr_td.to_vec()),
            rtmr0: hex::encode(td10.rt_mr0.to_vec()),
            rtmr1: hex::encode(td10.rt_mr1.to_vec()),
            rtmr2: hex::encode(td10.rt_mr2.to_vec()),
            rtmr3: hex::encode(td10.rt_mr3.to_vec()),
        };

        // Extract the 32-byte report_data binding. This is the raw ed25519 public key, or
        // SHA-256 of an ml-dsa-65 public key (which is 1952 bytes and does not fit in
        // report_data's 32 bytes). register_worker_key re-derives this from the submitted key.
        let mut report_data_prefix = [0u8; 32];
        report_data_prefix.copy_from_slice(&td10.report_data[..32]);

        Ok((measurements, report_data_prefix))
    }

    /// Update cached quote collateral
    ///
    /// Collateral contains Intel's reference data (certificates, TCB info, CRL)
    /// Should be updated when Intel releases new TCB versions (~ monthly)
    ///
    /// Get collateral from: https://api.trustedservices.intel.com/sgx/certification/v4/
    /// or via Phala's dcap-qvl CLI tool
    /// `index` selects the collateral slot (0..MAX_COLLATERALS), one per platform/FMSPC — e.g.
    /// index 0 = Phala (20a06f000000), index 1 = self-hosted (B0C06F000000). Slots must be filled
    /// contiguously (set index N only when N <= current count). Updating a slot does NOT delete
    /// the others, so a mixed fleet coexists.
    pub fn update_collateral(&mut self, collateral: String, index: u32) {
        self.assert_owner();
        let i = index as usize;
        assert!(i < MAX_COLLATERALS, "index must be < {} (MAX_COLLATERALS)", MAX_COLLATERALS);
        if i < self.collaterals.len() {
            self.collaterals[i] = collateral;
        } else if i == self.collaterals.len() {
            self.collaterals.push(collateral);
        } else {
            env::panic_str("Fill lower collateral indices first (no gaps allowed)");
        }
        env::log_str(&format!(
            "Quote collateral updated at index {} (total slots: {})",
            i,
            self.collaterals.len()
        ));
    }

    /// Governance: approve a worker build (MRTD + RTMR0-3; all 5 must match for a worker to
    /// register). The DAO calls it through a `Call` proposal, so it runs after the vote and the
    /// delay. If `clear_others` is true, removes all existing entries before adding.
    pub fn add_approved_measurements(&mut self, measurements: ApprovedMeasurements, clear_others: Option<bool>) {
        self.assert_governance();
        Self::validate_measurements(&measurements);

        if clear_others.unwrap_or(false) {
            let count = self.approved_measurements.len();
            self.approved_measurements.clear();
            env::log_str(&format!("Cleared {} existing measurement entries", count));
        }

        if !self.approved_measurements.contains(&measurements) {
            self.approved_measurements.push(measurements.clone());
        }

        env::log_str(&format!(
            "Approved measurements added: mrtd={}, rtmr0={}, rtmr1={}, rtmr2={}, rtmr3={}",
            measurements.mrtd, measurements.rtmr0, measurements.rtmr1,
            measurements.rtmr2, measurements.rtmr3
        ));
        env::log_str(&format!("Total approved measurements: {}", self.approved_measurements.len()));
    }

    /// Owner or governance: remove one approved build. The fast path for a bad build — revoking
    /// takes a right away, so it needs no vote.
    pub fn remove_approved_measurements(&mut self, measurements: ApprovedMeasurements) {
        self.assert_owner_or_governance();
        self.approved_measurements.retain(|m| m != &measurements);
        env::log_str(&format!("Approved measurements removed. Remaining: {}", self.approved_measurements.len()));
    }

    /// Owner or governance: remove every approved build (see `remove_approved_measurements`).
    pub fn clear_all_approved_measurements(&mut self) {
        self.assert_owner_or_governance();
        let count = self.approved_measurements.len();
        self.approved_measurements.clear();
        env::log_str(&format!("Cleared all {} measurement entries", count));
    }

    /// Remove old worker access keys (cleanup + security revocation)
    ///
    /// Call after worker restart when old keys are no longer needed.
    /// Also used to immediately revoke compromised keys.
    ///
    /// Each key is removed via an independent promise so that one
    /// missing key does not cause the entire batch to fail.
    ///
    /// # Security
    /// - Owner or governance. The keys on this account are the workers' function-call keys
    ///   (`register_worker_key`), so the worst a removal does is stop a worker: no key it can
    ///   delete moves funds or decrypts anything.
    /// - Frees ~0.042 NEAR storage per key
    pub fn remove_worker_keys(&mut self, public_keys: Vec<PublicKey>) {
        self.assert_owner_or_governance();
        let account = env::current_account_id();
        for key in &public_keys {
            // Short fingerprint only: an ml-dsa-65 key debug-prints to ~19 KB (over the log limit).
            env::log_str(&format!(
                "Removing worker key: curve={:?}, sha256={}",
                key.curve_type(),
                hex::encode(env::sha256_array(key.as_bytes()))
            ));
            // Each delete_key is an independent promise — if one key
            // doesn't exist, the others still get removed. Detached on purpose: we schedule
            // them all and return nothing (near-sdk >= 5.29 marks Promise #[must_use]).
            Promise::new(account.clone()).delete_key(key.clone()).detach();
        }
        env::log_str(&format!("Scheduled removal of {} worker key(s)", public_keys.len()));
    }

    /// Governance: replace the owner (the ops role). Same name and argument as on the main
    /// contract, so one `Call` shape replaces the owner on both.
    pub fn set_owner(&mut self, new_owner_id: AccountId) {
        self.assert_governance();
        env::log_str(&format!("Owner changed from {} to {}", self.owner_id, new_owner_id));
        self.owner_id = new_owner_id;
    }

    /// Governance: hand governance to another account.
    pub fn set_governance(&mut self, governance_id: AccountId) {
        self.assert_governance();
        env::log_str(&format!("governance_set {} -> {}", self.governance_id, governance_id));
        self.governance_id = governance_id;
    }

    /// Governance: deploy the wasm given as the raw input of the call (not JSON) on this
    /// account. `upgrade_and_migrate` also calls the new code's `migrate()`. One atomic batch:
    /// a failing `migrate`, or a state the new code cannot read (`gov_health`), leaves the old
    /// code in place. Every version keeps `upgrade`, `upgrade_and_migrate`, `migrate()` (no
    /// arguments once deployed through governance) and `gov_health`: an earlier version calls
    /// them on a later one.
    pub fn upgrade(&mut self) -> Promise {
        self.governed_upgrade(false)
    }

    pub fn upgrade_and_migrate(&mut self) -> Promise {
        self.governed_upgrade(true)
    }

    /// Reads the state; the last step of the upgrade batch.
    pub fn gov_health(&self) -> usize {
        self.approved_measurements.len()
    }

    pub fn get_governance(&self) -> AccountId {
        self.governance_id.clone()
    }

    pub fn get_owner(&self) -> AccountId {
        self.owner_id.clone()
    }

    // ========== View methods ==========

    /// Get list of approved measurements
    pub fn get_approved_measurements(&self) -> Vec<ApprovedMeasurements> {
        self.approved_measurements.clone()
    }

    /// Check if measurements are approved
    pub fn is_measurements_approved(&self, measurements: ApprovedMeasurements) -> bool {
        self.approved_measurements.contains(&measurements)
    }

    /// Get cached collateral at slot 0 (backward-compatible; None if no slots set)
    pub fn get_collateral(&self) -> Option<String> {
        self.collaterals.first().cloned()
    }

    /// Get all cached collaterals (one per platform/FMSPC slot)
    pub fn get_collaterals(&self) -> Vec<String> {
        self.collaterals.clone()
    }

    /// Get init worker account
    pub fn get_init_worker_account(&self) -> AccountId {
        self.init_worker_account.clone()
    }

    // ========== Internal ==========

    fn assert_owner(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.owner_id,
            "Only owner can call this method"
        );
    }

    fn governed_upgrade(&self, migrate: bool) -> Promise {
        self.assert_governance();
        let code = env::input().unwrap_or_default();
        require!(!code.is_empty(), "upgrade takes the wasm as the raw input of the call");
        env::log_str(&format!(
            "upgrade code_hash={} size={} migrate={}",
            String::from(&Base58CryptoHash::from(env::sha256_array(&code))),
            code.len(),
            migrate
        ));
        let mut p = Promise::new(env::current_account_id()).deploy_contract(code);
        if migrate {
            p = p.function_call("migrate".to_string(), b"{}".to_vec(), NearToken::from_yoctonear(0), MIGRATE_GAS);
        }
        p.function_call("gov_health".to_string(), b"{}".to_vec(), NearToken::from_yoctonear(0), HEALTH_GAS)
    }

    fn assert_governance(&self) {
        require!(
            env::predecessor_account_id() == self.governance_id,
            format!("Only governance ({}) can call this method", self.governance_id)
        );
    }

    fn assert_owner_or_governance(&self) {
        let p = env::predecessor_account_id();
        require!(
            p == self.owner_id || p == self.governance_id,
            "Only the owner or governance can call this method"
        );
    }

    fn validate_measurement_field(name: &str, value: &str) {
        assert_eq!(
            value.len(),
            96,
            "Invalid {} format: expected 96 hex characters, got {}",
            name,
            value.len()
        );
        assert!(
            value.chars().all(|c| c.is_ascii_hexdigit()),
            "Invalid {} format: must be hex string",
            name
        );
    }

    fn validate_measurements(m: &ApprovedMeasurements) {
        Self::validate_measurement_field("mrtd", &m.mrtd);
        Self::validate_measurement_field("rtmr0", &m.rtmr0);
        Self::validate_measurement_field("rtmr1", &m.rtmr1);
        Self::validate_measurement_field("rtmr2", &m.rtmr2);
        Self::validate_measurement_field("rtmr3", &m.rtmr3);
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    fn get_context() -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .current_account_id(accounts(0))
            .predecessor_account_id(accounts(1))
            .signer_account_id(accounts(1));
        builder
    }

    fn dummy_measurements() -> ApprovedMeasurements {
        ApprovedMeasurements {
            mrtd: "a".repeat(96),
            rtmr0: "b".repeat(96),
            rtmr1: "c".repeat(96),
            rtmr2: "d".repeat(96),
            rtmr3: "e".repeat(96),
        }
    }

    #[test]
    fn test_init() {
        let context = get_context();
        testing_env!(context.build());

        let contract = RegisterContract::new(accounts(4), accounts(2), accounts(3), accounts(1));
        assert_eq!(contract.owner_id, accounts(4));
        assert_eq!(contract.governance_id, accounts(1));
        assert_eq!(contract.init_worker_account, accounts(2));
        assert_eq!(contract.get_approved_measurements().len(), 0);
    }

    #[test]
    fn test_add_approved_measurements() {
        let context = get_context();
        testing_env!(context.build());

        let mut contract = RegisterContract::new(accounts(4), accounts(2), accounts(3), accounts(1));
        let m = dummy_measurements();
        contract.add_approved_measurements(m.clone(), None);

        assert!(contract.is_measurements_approved(m));
        assert_eq!(contract.get_approved_measurements().len(), 1);
    }

    #[test]
    fn test_add_duplicate_measurements() {
        let context = get_context();
        testing_env!(context.build());

        let mut contract = RegisterContract::new(accounts(4), accounts(2), accounts(3), accounts(1));
        let m = dummy_measurements();
        contract.add_approved_measurements(m.clone(), None);
        contract.add_approved_measurements(m.clone(), None);

        assert_eq!(contract.get_approved_measurements().len(), 1);
    }

    #[test]
    fn test_clear_others() {
        let context = get_context();
        testing_env!(context.build());

        let mut contract = RegisterContract::new(accounts(4), accounts(2), accounts(3), accounts(1));
        let m1 = dummy_measurements();
        contract.add_approved_measurements(m1.clone(), None);

        let m2 = ApprovedMeasurements { rtmr3: "f".repeat(96), ..m1 };
        contract.add_approved_measurements(m2.clone(), Some(true));

        assert_eq!(contract.get_approved_measurements().len(), 1);
        assert!(contract.is_measurements_approved(m2));
    }

    #[test]
    #[should_panic(expected = "Invalid mrtd format")]
    fn test_invalid_measurement_length() {
        let context = get_context();
        testing_env!(context.build());

        let mut contract = RegisterContract::new(accounts(4), accounts(2), accounts(3), accounts(1));
        let m = ApprovedMeasurements {
            mrtd: "abc".to_string(),
            rtmr0: "b".repeat(96),
            rtmr1: "c".repeat(96),
            rtmr2: "d".repeat(96),
            rtmr3: "e".repeat(96),
        };
        contract.add_approved_measurements(m, None);
    }

    #[test]
    #[should_panic(expected = "Only governance")]
    fn test_non_governance_cannot_add_measurements() {
        let mut context = get_context();
        testing_env!(context.build());

        let mut contract = RegisterContract::new(accounts(4), accounts(2), accounts(3), accounts(1));

        // The owner is not governance.
        testing_env!(context.predecessor_account_id(accounts(4)).build());

        contract.add_approved_measurements(dummy_measurements(), None);
    }

    #[test]
    fn test_remove_measurements() {
        let context = get_context();
        testing_env!(context.build());

        let mut contract = RegisterContract::new(accounts(4), accounts(2), accounts(3), accounts(1));
        let m = dummy_measurements();
        contract.add_approved_measurements(m.clone(), None);
        assert_eq!(contract.get_approved_measurements().len(), 1);

        contract.remove_approved_measurements(m);
        assert_eq!(contract.get_approved_measurements().len(), 0);
    }
}
