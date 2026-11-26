//! The builds of the wallet contract that keystores sign for.
//!
//! An agent in on-chain custody keeps its balance on an account that runs a
//! wallet contract, and a keystore gives its half of a signature only to an
//! account whose code is on this list. The list is governance's
//! (`ApproveWalletContract`, `RevokeWalletContract`), so which code the
//! enclave trusts is decided where its own build is decided. It is a list and
//! not one value: an account stays on the build it was installed with, so a
//! later build is approved beside the earlier one, not instead of it.
//!
//! An entry is the code hash as NEAR reports it for the account, in base58.

use crate::*;

#[near_bindgen]
impl KeystoreDao {
    pub(crate) fn wallet_contracts() -> Vec<String> {
        LookupMap::<u8, Vec<String>>::new(StorageKey::ApprovedWalletContracts).get(&0).unwrap_or_default()
    }

    pub(crate) fn set_wallet_contracts(v: &Vec<String>) {
        LookupMap::<u8, Vec<String>>::new(StorageKey::ApprovedWalletContracts).insert(&0, v);
    }

    pub(crate) fn approve_wallet_contract(code_hash: Base58CryptoHash) {
        let code_hash = String::from(&code_hash);
        let mut v = Self::wallet_contracts();
        if !v.contains(&code_hash) {
            v.push(code_hash.clone());
            Self::set_wallet_contracts(&v);
        }
        env::log_str(&format!("wallet_contract_approved {} total={}", code_hash, v.len()));
    }

    pub(crate) fn drop_wallet_contract(code_hash: Base58CryptoHash, event: &str) {
        let code_hash = String::from(&code_hash);
        let mut v = Self::wallet_contracts();
        v.retain(|c| *c != code_hash);
        Self::set_wallet_contracts(&v);
        env::log_str(&format!("{} {} total={}", event, code_hash, v.len()));
    }

    /// The code hashes of the wallet contract builds keystores sign for.
    pub fn get_approved_wallet_contracts(&self) -> Vec<String> {
        Self::wallet_contracts()
    }

    /// Owner: take a wallet contract build off the list at once (the fast brake; approving
    /// one is governance's, `ApproveWalletContract`). From here on no keystore signs for an
    /// account that runs it; what lies on such an account moves by its own keys or through
    /// the owner's exit.
    pub fn remove_approved_wallet_contract(&mut self, code_hash: Base58CryptoHash) {
        self.assert_owner();
        Self::drop_wallet_contract(code_hash, "wallet_contract_removed");
    }
}
