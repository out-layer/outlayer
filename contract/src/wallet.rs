use crate::*;
use near_sdk::env;
use sha2::{Digest, Sha256};

/// Storage cost per byte in NEAR
const STORAGE_PRICE_PER_BYTE: Balance = 10_000_000_000_000_000_000; // 0.00001 NEAR per byte

/// Wallet policy entry stored on-chain
/// Encrypted by keystore (TEE), only keystore can decrypt
#[derive(Clone, Debug)]
#[near(serializers = [borsh])]
pub struct WalletPolicyEntry {
    /// Controller NEAR account (who created/manages this policy)
    pub owner: AccountId,
    /// Encrypted policy data (encrypted by keystore)
    pub encrypted_data: String,
    /// Emergency freeze flag (set by controller without wallet sig)
    pub frozen: bool,
    /// Block timestamp of last update
    pub updated_at: u64,
    /// Storage deposit staked for this entry
    pub storage_deposit: Balance,
}

/// What a refundable storage deposit is held for. Grows by variant: a new
/// kind of sponsored storage is a new variant and an argument on its creating
/// call, never a new map.
#[near(serializers = [borsh, json])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StorageItem {
    /// A wallet policy, by its wallet key (canonical — see
    /// [`canonical_wallet_pubkey`]).
    WalletPolicy { wallet_pubkey: String },
}

impl StorageItem {
    /// The same item under the one key it may be stored under.
    fn canonical(self) -> StorageItem {
        match self {
            StorageItem::WalletPolicy { wallet_pubkey } => StorageItem::WalletPolicy {
                wallet_pubkey: canonical_wallet_pubkey(&wallet_pubkey),
            },
        }
    }
}

/// Wallet policy view for JSON responses
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct WalletPolicyView {
    pub owner: AccountId,
    pub encrypted_data: String,
    pub frozen: bool,
    pub updated_at: u64,
    /// Who the storage deposit goes back to on a shrink or a delete; `None`:
    /// the owner, who calls them.
    pub storage_refund_to: Option<AccountId>,
    /// The storage deposit held for this policy now.
    pub storage_deposit: near_sdk::json_types::U128,
}

/// Lightweight view for listing wallets by owner
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct WalletPolicyListItem {
    pub wallet_pubkey: String,
    pub owner: AccountId,
    pub frozen: bool,
    pub updated_at: u64,
    pub storage_refund_to: Option<AccountId>,
}

/// Parse wallet pubkey string into (key_type, raw_bytes)
/// Formats: "ed25519:<hex32>" or "secp256k1:<hex33>"
pub(crate) fn parse_wallet_pubkey(wallet_pubkey: &str) -> (String, Vec<u8>) {
    let parts: Vec<&str> = wallet_pubkey.splitn(2, ':').collect();
    assert!(
        parts.len() == 2,
        "Invalid public key format. Expected 'ed25519:<hex>' or 'secp256k1:<hex>'"
    );

    let key_type = parts[0];
    let hex_str = parts[1];

    assert!(
        key_type == "ed25519" || key_type == "secp256k1",
        "Unsupported key type '{}'. Must be 'ed25519' or 'secp256k1'",
        key_type
    );

    let raw_bytes = hex::decode(hex_str).unwrap_or_else(|_| {
        env::panic_str("Invalid hex encoding in the public key");
    });

    match key_type {
        "ed25519" => {
            assert!(
                raw_bytes.len() == 32,
                "Ed25519 public key must be 32 bytes, got {}",
                raw_bytes.len()
            );
        }
        "secp256k1" => {
            assert!(
                raw_bytes.len() == 33,
                "Secp256k1 compressed public key must be 33 bytes, got {}",
                raw_bytes.len()
            );
            assert!(
                raw_bytes[0] == 0x02 || raw_bytes[0] == 0x03,
                "Secp256k1 compressed key must start with 0x02 or 0x03"
            );
        }
        _ => unreachable!(),
    }

    (key_type.to_string(), raw_bytes)
}

/// The one spelling of a wallet key that anything may be stored under.
///
/// `hex::decode` accepts either case, so `ed25519:ABCD…` and `ed25519:abcd…`
/// are the same cryptographic key written two ways. Stored raw, they became two
/// entries for one wallet — a wallet with two policies, and a view returning
/// whichever one the caller happened to spell. `implicit_account_of` already
/// answered in lower case, so the account a key names and the key it is stored
/// under disagreed.
///
/// Not a way in for a stranger: registering a policy needs a signature by the
/// key itself, so only the wallet's own owner could ever have made the
/// duplicate. This removes the possibility of doing it by accident, which is
/// the way it would actually have happened.
///
/// Rebuilt from the parsed bytes rather than lower-cased, so the key type is
/// validated on the same pass and a malformed value cannot reach storage at
/// all.
pub(crate) fn canonical_wallet_pubkey(wallet_pubkey: &str) -> String {
    let (key_type, raw_bytes) = parse_wallet_pubkey(wallet_pubkey);
    format!("{}:{}", key_type, hex::encode(raw_bytes))
}

/// The same canonical form, for READS.
///
/// A view answers a question; it does not accept a value. `has_wallet_policy`
/// has always answered `false` for a string that is not a wallet key at all,
/// and callers rely on that — the coordinator uses it as a negative cache. Made
/// strict, it would start returning an RPC error where it used to return an
/// answer, which is a breaking change dressed up as a fix.
///
/// So: canonicalise what parses, pass through what does not. An unparseable key
/// matches nothing either way, and the caller gets the same `false` as before.
fn lookup_wallet_pubkey(wallet_pubkey: &str) -> String {
    let parts: Vec<&str> = wallet_pubkey.splitn(2, ':').collect();
    match parts.as_slice() {
        [key_type, hex_str] if *key_type == "ed25519" || *key_type == "secp256k1" => {
            match hex::decode(hex_str) {
                Ok(raw) => format!("{}:{}", key_type, hex::encode(raw)),
                Err(_) => wallet_pubkey.to_string(),
            }
        }
        _ => wallet_pubkey.to_string(),
    }
}

/// The NEAR implicit account a wallet's public key corresponds to.
///
/// An implicit account IS the hex of an ed25519 public key, which is why a
/// custody wallet can own things on chain without anyone creating an account for
/// it. Only ed25519 has this form: a secp256k1 wallet key addresses EVM or
/// Bitcoin and has no NEAR account of its own, so asking for one is a caller
/// error rather than something to invent an answer for.
pub(crate) fn implicit_account_of(wallet_pubkey: &str) -> AccountId {
    let (key_type, raw_bytes) = parse_wallet_pubkey(wallet_pubkey);
    assert!(
        key_type == "ed25519",
        "Only an ed25519 wallet key has a NEAR account. Got '{}'.",
        key_type
    );
    hex::encode(raw_bytes)
        .parse()
        .unwrap_or_else(|_| env::panic_str("Wallet key does not form a valid implicit account"))
}

/// Verify wallet signature on-chain using native host functions
/// message_hash: SHA256 hash of the data being signed (32 bytes)
pub(crate) fn verify_wallet_signature(
    wallet_pubkey: &str,
    message_hash: &[u8; 32],
    wallet_signature: &str,
) {
    let (key_type, pubkey_bytes) = parse_wallet_pubkey(wallet_pubkey);
    let sig_bytes = hex::decode(wallet_signature).unwrap_or_else(|_| {
        env::panic_str("Invalid hex encoding in wallet_signature");
    });

    match key_type.as_str() {
        "ed25519" => {
            assert!(
                sig_bytes.len() == 64,
                "Ed25519 signature must be 64 bytes, got {}",
                sig_bytes.len()
            );
            let sig: [u8; 64] = sig_bytes.try_into().unwrap();
            let pk: [u8; 32] = pubkey_bytes.try_into().unwrap();
            // ed25519_verify(signature, message, public_key) -> bool
            let valid = env::ed25519_verify(&sig, message_hash, &pk);
            assert!(valid, "Invalid Ed25519 wallet signature");
        }
        "secp256k1" => {
            // Signature: 64 bytes (r || s) + 1 byte recovery id (v)
            assert!(
                sig_bytes.len() == 65,
                "Secp256k1 signature must be 65 bytes (64 sig + 1 recovery id), got {}",
                sig_bytes.len()
            );
            let sig: [u8; 64] = sig_bytes[..64].try_into().unwrap();
            let v = sig_bytes[64];
            assert!(v <= 1, "Recovery id (v) must be 0 or 1, got {}", v);

            // ecrecover returns uncompressed public key (64 bytes: x || y)
            let recovered = env::ecrecover(message_hash, &sig, v, true)
                .unwrap_or_else(|| env::panic_str("Secp256k1 signature recovery failed"));

            // Compress recovered key and compare with stored compressed key
            let x = &recovered[0..32];
            let y_last_byte = recovered[63];
            let prefix = if y_last_byte % 2 == 0 { 0x02 } else { 0x03 };

            let mut compressed = Vec::with_capacity(33);
            compressed.push(prefix);
            compressed.extend_from_slice(x);

            assert!(
                compressed == pubkey_bytes,
                "Recovered secp256k1 public key does not match wallet_pubkey"
            );
        }
        _ => unreachable!(),
    }
}

/// The exact string `store_wallet_policy` requires a signature over.
///
/// **The signature used to cover the bare `sha256(encrypted_data)`, and that
/// was a hole.** Every wallet signature in this system is `sign(sha256(<some
/// string>))` with the same key, and the strings are public: a
/// `store_agent_secret` transaction carries its message's parts and its
/// signature in the clear. So anyone reading the chain could lift that pair and
/// present it here with `encrypted_data` set to the rebuilt message — becoming
/// the policy's controller for somebody else's wallet, and locking its owner
/// out of the slot for good.
///
/// Two things close it, and both are needed:
///
/// * the leading DOMAIN, which makes a signature from another verb useless
///   here — and, as everywhere else, makes the preimage unusable as a
///   transaction: read as borsh it claims a `signer_id` of about 1.9 billion
///   against a 64-byte maximum;
/// * the CALLER, last, so a signature authorises one account to store this
///   policy and nobody else. Lifting it from the chain now buys nothing,
///   because the account that sends it is part of what was signed.
///
/// `encrypted_data` is length-prefixed, so it may hold anything at all without
/// moving a boundary.
pub(crate) fn policy_store_message(
    wallet_pubkey: &str,
    encrypted_data: &str,
    caller: &AccountId,
) -> String {
    format!(
        "store_wallet_policy:v1:{}:{}:{}:{}",
        wallet_pubkey,
        encrypted_data.len(),
        encrypted_data,
        caller
    )
}

#[near_bindgen]
impl Contract {
    /// Store or update wallet policy
    ///
    /// Requires `wallet_signature` over [`policy_store_message`] from the
    /// wallet's key — the keystore signs it, which proves the requester holds
    /// the wallet's `wk_`, and the message names the account sending this call.
    /// If entry already exists, caller must be the same controller (owner).
    /// Requires attached storage deposit.
    ///
    /// # Arguments
    /// * `wallet_pubkey` - "ed25519:<hex32>" or "secp256k1:<hex33>"
    /// * `encrypted_data` - Policy encrypted by keystore
    /// * `wallet_signature` - Hex-encoded signature proving API key ownership
    /// * `storage_refund_to` - Who the storage deposit goes back to on a shrink
    ///   or a delete, for a sponsor that pays it. Set only when the policy is
    ///   CREATED; on an update it must be absent (the beneficiary changes it
    ///   with `set_storage_refund_to`). Absent: the owner, as always. Covered by
    ///   the owner's transaction signature — a NEP-366 relayer cannot change it.
    #[payable]
    pub fn store_wallet_policy(
        &mut self,
        wallet_pubkey: String,
        encrypted_data: String,
        wallet_signature: String,
        storage_refund_to: Option<AccountId>,
    ) {
        self.assert_not_paused();

        let caller = env::predecessor_account_id();
        let attached_deposit = env::attached_deposit().as_yoctonear();

        // Validate inputs
        assert!(!wallet_pubkey.is_empty(), "wallet_pubkey cannot be empty");
        assert!(!encrypted_data.is_empty(), "encrypted_data cannot be empty");
        // DO NOT RAISE THIS. It is already above the ceiling that actually
        // binds: this method emits `WalletPolicyUpdated` carrying the whole
        // blob, and NEAR caps a call's total log output at
        // `max_total_log_length: 16_384` — 16 KB, the same figure in the
        // mainnet and testnet parameter files. So a policy somewhere between
        // 16 KB and this number is accepted here and then fails at the log,
        // after the signature check, the storage accounting and the refund have
        // all been done.
        //
        // Nobody has hit it: a real policy is small, and it takes a long
        // allowlist or a large approver set to get near. Left as it is
        // deliberately — the note is here so the next person raising the limit
        // knows the log is what will stop them, not this assert.
        assert!(
            encrypted_data.len() <= 100_000,
            "encrypted_data too large (max 100KB)"
        );
        assert!(!wallet_signature.is_empty(), "wallet_signature is required");

        // Parse, validate, and shadow the parameter with the ONE spelling
        // anything may be stored under. Shadowed rather than assigned to a new
        // name so the caller's raw string is unreachable from here on — the
        // storage key, the owner index and the signature check all see the same
        // value by construction.
        let wallet_pubkey = canonical_wallet_pubkey(&wallet_pubkey);

        // Verify wallet signature on-chain, over a message that names this
        // caller — see `policy_store_message` for why the bare hash was unsafe.
        let mut hasher = Sha256::new();
        hasher.update(policy_store_message(&wallet_pubkey, &encrypted_data, &caller).as_bytes());
        let message_hash: [u8; 32] = hasher.finalize().into();

        verify_wallet_signature(&wallet_pubkey, &message_hash, &wallet_signature);

        let item = StorageItem::WalletPolicy { wallet_pubkey: wallet_pubkey.clone() };
        let existing = self.wallet_policies.get(&wallet_pubkey);

        // The beneficiary is named when the policy is created and changed only
        // by itself. An update that names one is refused rather than ignored:
        // ignored, the owner would believe they had changed it.
        let beneficiary = if existing.is_some() {
            assert!(
                storage_refund_to.is_none(),
                "storage_refund_to is set when the policy is created; the beneficiary changes it with set_storage_refund_to"
            );
            self.storage_refund_to.get(&item)
        } else {
            if let Some(b) = &storage_refund_to {
                self.storage_refund_to.insert(&item, b);
            }
            storage_refund_to
        };

        // Calculate storage cost — the beneficiary's own record included.
        let storage_size = self.calculate_wallet_policy_storage_size(
            &wallet_pubkey,
            &encrypted_data,
            beneficiary.is_some(),
        );
        let required_deposit = storage_size as u128 * STORAGE_PRICE_PER_BYTE;
        // Every refund of this deposit — the excess now, a shrink or a delete
        // later — goes to the beneficiary when there is one.
        let refund_to = beneficiary.unwrap_or_else(|| caller.clone());

        // Check ownership and handle deposit. `was_frozen` travels with the
        // entry: a freeze must survive a policy edit — see below.
        let mut was_frozen = false;
        let is_new = if let Some(existing) = existing {
            // Update: caller must be the same controller
            assert!(
                existing.owner == caller,
                "Only the original controller ({}) can update this wallet policy",
                existing.owner
            );
            was_frozen = existing.frozen;

            let total_available = attached_deposit + existing.storage_deposit;
            assert!(
                total_available >= required_deposit,
                "Insufficient deposit for update. Required: {}, available (attached {} + old {}): {}",
                required_deposit,
                attached_deposit,
                existing.storage_deposit,
                total_available
            );

            // Refund excess
            let refund = total_available - required_deposit;
            if refund > 0 {
                near_sdk::Promise::new(refund_to.clone())
                    .transfer(NearToken::from_yoctonear(refund));
            }
            false
        } else {
            // New entry
            assert!(
                attached_deposit >= required_deposit,
                "Insufficient storage deposit. Required: {} yoctoNEAR, attached: {}",
                required_deposit,
                attached_deposit
            );

            // Refund excess
            if attached_deposit > required_deposit {
                let refund = attached_deposit - required_deposit;
                near_sdk::Promise::new(refund_to.clone())
                    .transfer(NearToken::from_yoctonear(refund));
            }
            true
        };

        // Store wallet policy entry
        let entry = WalletPolicyEntry {
            owner: caller.clone(),
            encrypted_data,
            // A FREEZE SURVIVES AN EDIT. A new entry starts unfrozen because
            // there is nothing to carry; an update keeps whatever the entry
            // held.
            //
            // This used to reset to `false`, and the direction was wrong.
            // Freezing exists for the case where the agent's key is
            // COMPROMISED — it takes no wallet signature precisely so the
            // controller can act while the key is in someone else's hands. The
            // controller's next move is usually to tighten the policy, and that
            // edit silently reopened the wallet at the moment the attacker was
            // still holding the key, with nothing in the answer to say so.
            //
            // Nothing is lost: `unfreeze_wallet` is the way out, it is
            // controller-only exactly as this call is, and it says what it does.
            frozen: was_frozen,
            updated_at: env::block_timestamp(),
            storage_deposit: required_deposit,
        };

        self.wallet_policies.insert(&wallet_pubkey, &entry);

        // Add to owner index (new entries only — updates keep the same owner)
        if is_new {
            let mut owner_set = self
                .wallet_owner_index
                .get(&caller)
                .unwrap_or_else(|| {
                    UnorderedSet::new(StorageKey::WalletOwnerList {
                        account_id: caller.clone(),
                    })
                });
            owner_set.insert(&wallet_pubkey);
            self.wallet_owner_index.insert(&caller, &owner_set);
        }

        self.emit_system_event(crate::payment::SystemEvent::WalletPolicyUpdated {
            wallet_pubkey,
            owner: caller,
            encrypted_data: entry.encrypted_data.clone(),
            frozen: entry.frozen,
        });
    }

    /// Freeze wallet (controller-only, NO wallet signature required)
    ///
    /// Only the controller (caller == entry.owner) can freeze.
    /// Does not require wallet key signature — enables emergency freeze
    /// even if agent's key is compromised.
    pub fn freeze_wallet(&mut self, wallet_pubkey: String) {
        self.assert_not_paused();

        let caller = env::predecessor_account_id();
        // The SAME spelling anything is stored under. `store_wallet_policy`
        // canonicalises before inserting, so a key written in upper case names
        // an entry that is not there — and this method would have answered
        // "Wallet policy not found" for a wallet its controller was looking
        // straight at. On an emergency freeze that is the worst possible
        // moment to lose to a spelling.
        let wallet_pubkey = canonical_wallet_pubkey(&wallet_pubkey);
        let mut entry = self
            .wallet_policies
            .get(&wallet_pubkey)
            .unwrap_or_else(|| env::panic_str("Wallet policy not found"));

        assert!(
            entry.owner == caller,
            "Only the controller ({}) can freeze this wallet",
            entry.owner
        );

        assert!(!entry.frozen, "Wallet is already frozen");

        entry.frozen = true;
        entry.updated_at = env::block_timestamp();
        self.wallet_policies.insert(&wallet_pubkey, &entry);

        self.emit_system_event(crate::payment::SystemEvent::WalletFrozenChanged {
            wallet_pubkey,
            owner: caller,
            frozen: true,
        });
    }

    /// Unfreeze wallet (controller-only, NO wallet signature required)
    ///
    /// Only the controller (caller == entry.owner) can unfreeze.
    /// If admin_quorum is set in policy, keystore will additionally verify
    /// quorum approval during check-policy.
    pub fn unfreeze_wallet(&mut self, wallet_pubkey: String) {
        self.assert_not_paused();

        let caller = env::predecessor_account_id();
        // Canonical, for the same reason as `freeze_wallet` — and this is the
        // half that matters most: the way OUT of a freeze must not depend on
        // how the caller happened to spell the key.
        let wallet_pubkey = canonical_wallet_pubkey(&wallet_pubkey);
        let mut entry = self
            .wallet_policies
            .get(&wallet_pubkey)
            .unwrap_or_else(|| env::panic_str("Wallet policy not found"));

        assert!(
            entry.owner == caller,
            "Only the controller ({}) can unfreeze this wallet",
            entry.owner
        );

        assert!(entry.frozen, "Wallet is not frozen");

        entry.frozen = false;
        entry.updated_at = env::block_timestamp();
        self.wallet_policies.insert(&wallet_pubkey, &entry);

        self.emit_system_event(crate::payment::SystemEvent::WalletFrozenChanged {
            wallet_pubkey,
            owner: caller,
            frozen: false,
        });
    }

    /// Delete wallet policy and refund storage deposit
    ///
    /// Only the controller can delete.
    pub fn delete_wallet_policy(&mut self, wallet_pubkey: String) {
        let wallet_pubkey = canonical_wallet_pubkey(&wallet_pubkey);
        let caller = env::predecessor_account_id();
        let entry = self
            .wallet_policies
            .get(&wallet_pubkey)
            .unwrap_or_else(|| env::panic_str("Wallet policy not found"));

        assert!(
            entry.owner == caller,
            "Only the controller ({}) can delete this wallet policy",
            entry.owner
        );

        self.wallet_policies.remove(&wallet_pubkey);

        // Remove from owner index
        if let Some(mut owner_set) = self.wallet_owner_index.get(&caller) {
            owner_set.remove(&wallet_pubkey);
            if owner_set.is_empty() {
                self.wallet_owner_index.remove(&caller);
            } else {
                self.wallet_owner_index.insert(&caller, &owner_set);
            }
        }

        // Refund storage deposit — to the beneficiary when there is one — and
        // drop the beneficiary with the policy: a policy created again under
        // this key starts without one.
        let refunded_to = self
            .storage_refund_to
            .remove(&StorageItem::WalletPolicy { wallet_pubkey: wallet_pubkey.clone() })
            .unwrap_or_else(|| caller.clone());
        if entry.storage_deposit > 0 {
            near_sdk::Promise::new(refunded_to.clone())
                .transfer(NearToken::from_yoctonear(entry.storage_deposit));
        }

        self.emit_system_event(crate::payment::SystemEvent::WalletPolicyDeleted {
            wallet_pubkey,
            owner: caller,
            refunded_to,
        });
    }

    /// Hand the storage refunds of `item` to another account.
    ///
    /// A beneficiary is named only when the item is created. From then on only
    /// the beneficiary itself can hand it on — to another sponsor, or to the
    /// owner to give the deposit back. The owner cannot take it, and an item
    /// created without one never gets one. The record's size does not change,
    /// so nothing is attached and nothing is refunded. Emits
    /// `StorageRefundToChanged`.
    pub fn set_storage_refund_to(&mut self, item: StorageItem, storage_refund_to: AccountId) {
        self.assert_not_paused();
        let caller = env::predecessor_account_id();
        let item = item.canonical();

        // A beneficiary record lives exactly as long as its item: written when
        // the item is created, removed when it is deleted. So no record means
        // either no such item or one created without a beneficiary.
        let current = self.storage_refund_to.get(&item).unwrap_or_else(|| {
            env::panic_str(
                "No storage beneficiary is set for this item; one is named only when the item is created",
            )
        });
        assert!(
            caller == current,
            "Only the storage beneficiary ({}) can change where this deposit is refunded",
            current
        );

        self.storage_refund_to.insert(&item, &storage_refund_to);
        self.emit_system_event(crate::payment::SystemEvent::StorageRefundToChanged {
            item,
            storage_refund_to,
        });
    }
}

// View methods
#[near_bindgen]
impl Contract {
    /// Check if a wallet policy exists (view, no decryption needed)
    /// Used by coordinator for negative cache check (free RPC call)
    pub fn has_wallet_policy(&self, wallet_pubkey: String) -> bool {
        self.wallet_policies
            .get(&lookup_wallet_pubkey(&wallet_pubkey))
            .is_some()
    }

    /// Get wallet policy entry (view)
    /// Returns owner, encrypted_data, frozen flag, updated_at
    /// Keystore decrypts encrypted_data for policy rules
    pub fn get_wallet_policy(&self, wallet_pubkey: String) -> Option<WalletPolicyView> {
        let wallet_pubkey = lookup_wallet_pubkey(&wallet_pubkey);
        self.wallet_policies.get(&wallet_pubkey).map(|entry| WalletPolicyView {
            owner: entry.owner,
            encrypted_data: entry.encrypted_data,
            frozen: entry.frozen,
            updated_at: entry.updated_at,
            storage_refund_to: self
                .storage_refund_to
                .get(&StorageItem::WalletPolicy { wallet_pubkey: wallet_pubkey.clone() }),
            storage_deposit: near_sdk::json_types::U128(entry.storage_deposit),
        })
    }

    /// List all wallet policies owned by an account
    pub fn get_wallet_policies_by_owner(&self, owner: AccountId) -> Vec<WalletPolicyListItem> {
        let Some(owner_set) = self.wallet_owner_index.get(&owner) else {
            return vec![];
        };
        owner_set
            .iter()
            .filter_map(|wallet_pubkey| {
                self.wallet_policies.get(&wallet_pubkey).map(|entry| {
                    let storage_refund_to = self
                        .storage_refund_to
                        .get(&StorageItem::WalletPolicy { wallet_pubkey: wallet_pubkey.clone() });
                    WalletPolicyListItem {
                        wallet_pubkey,
                        owner: entry.owner,
                        frozen: entry.frozen,
                        updated_at: entry.updated_at,
                        storage_refund_to,
                    }
                })
            })
            .collect()
    }

    /// Estimate storage cost for wallet policy (before storing). With
    /// `storage_refund_to`, the beneficiary's record is included, as
    /// `store_wallet_policy` will charge it.
    pub fn estimate_wallet_policy_cost(
        &self,
        wallet_pubkey: String,
        encrypted_data: String,
        storage_refund_to: Option<AccountId>,
    ) -> near_sdk::json_types::U128 {
        let storage_bytes = self.calculate_wallet_policy_storage_size(
            &wallet_pubkey,
            &encrypted_data,
            storage_refund_to.is_some(),
        );
        near_sdk::json_types::U128((storage_bytes as u128) * STORAGE_PRICE_PER_BYTE)
    }
}

impl Contract {
    /// Calculate storage size for wallet policy entry, and the beneficiary's
    /// record when there is one.
    fn calculate_wallet_policy_storage_size(
        &self,
        wallet_pubkey: &str,
        encrypted_data: &str,
        with_beneficiary: bool,
    ) -> u64 {
        const BASE_OVERHEAD: u64 = 40; // LookupMap entry overhead

        let key_size = (4 + wallet_pubkey.len()) as u64; // String with length prefix

        // WalletPolicyEntry fields:
        // owner (AccountId = String): 4 + len
        // encrypted_data (String): 4 + len
        // frozen (bool): 1
        // updated_at (u64): 8
        // storage_deposit (u128): 16
        let owner_estimate = 4 + 64; // AccountId max ~64 chars
        let value_size = (owner_estimate
            + 4
            + encrypted_data.len()
            + 1  // frozen
            + 8  // updated_at
            + 16 // storage_deposit
        ) as u64;

        // The beneficiary's record: its map entry, its key (the borsh variant
        // tag and the wallet key) and an account id at its maximum.
        let beneficiary = if with_beneficiary {
            BASE_OVERHEAD + (1 + 4 + wallet_pubkey.len() as u64) + (4 + 64)
        } else {
            0
        };

        BASE_OVERHEAD + key_size + value_size + beneficiary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    /// One key, one spelling — whatever case it arrives in.
    ///
    /// `hex::decode` takes either case, so the same wallet key can be written
    /// two ways. Stored raw, that was two entries for one wallet: two policies,
    /// and a view answering with whichever spelling it was handed. The account
    /// the key names was already lower case, so the two disagreed about which
    /// wallet they described.
    #[test]
    fn a_wallet_key_has_exactly_one_storage_form() {
        // 64 hex characters = 32 bytes, the only length an ed25519 key has.
        let hex_lower = "abcdef01".repeat(8);
        let lower = format!("ed25519:{}", hex_lower);
        let upper = format!("ed25519:{}", hex_lower.to_uppercase());
        let mixed = format!("ed25519:AbCdEf01{}", "abcdef01".repeat(7));

        assert_eq!(canonical_wallet_pubkey(&lower), lower);
        assert_eq!(canonical_wallet_pubkey(&upper), lower);
        assert_eq!(
            canonical_wallet_pubkey(&mixed),
            lower,
            "mixed case is the same key and must land on the same entry"
        );

        // And it agrees with the account the key names, which was lower case
        // all along — that disagreement was the actual defect.
        assert_eq!(implicit_account_of(&upper).to_string(), hex_lower);

        // secp256k1 keys canonicalise too, and keep their own type: 33 bytes,
        // leading 0x02 or 0x03.
        let k_upper = format!("secp256k1:02{}", "ABCDEF01".repeat(8));
        assert_eq!(
            canonical_wallet_pubkey(&k_upper),
            format!("secp256k1:02{}", "abcdef01".repeat(8))
        );
    }

    /// A view must keep answering rather than start failing.
    ///
    /// `has_wallet_policy` answers `false` for anything that is not a wallet
    /// key, and the coordinator uses it as a negative cache. Canonicalising
    /// strictly there would have turned that answer into an RPC error — a
    /// breaking change dressed up as a fix.
    #[test]
    fn a_lookup_canonicalises_what_it_can_and_passes_through_what_it_cannot() {
        let upper = "ed25519:AAAA111111111111111111111111111111111111111111111111111111111111";
        assert_eq!(lookup_wallet_pubkey(upper), upper.to_lowercase());

        for junk in ["", "garbage", "ed25519:", "ed25519:zz", "rsa:abcd", "no-colon"] {
            assert_eq!(
                lookup_wallet_pubkey(junk),
                junk,
                "an unparseable key must pass through, not panic: {junk:?}"
            );
        }
    }

    fn get_context(predecessor: AccountId, attached_deposit: NearToken) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .predecessor_account_id(predecessor)
            .attached_deposit(attached_deposit);
        builder
    }

    #[test]
    fn test_parse_wallet_pubkey_ed25519() {
        let hex_key = "a".repeat(64); // 32 bytes
        let wallet_pubkey = format!("ed25519:{}", hex_key);
        let (key_type, raw_bytes) = parse_wallet_pubkey(&wallet_pubkey);
        assert_eq!(key_type, "ed25519");
        assert_eq!(raw_bytes.len(), 32);
    }

    #[test]
    fn test_parse_wallet_pubkey_secp256k1() {
        // Valid compressed secp256k1 key (prefix 02 + 32 bytes)
        let hex_key = format!("02{}", "b".repeat(64));
        let wallet_pubkey = format!("secp256k1:{}", hex_key);
        let (key_type, raw_bytes) = parse_wallet_pubkey(&wallet_pubkey);
        assert_eq!(key_type, "secp256k1");
        assert_eq!(raw_bytes.len(), 33);
    }

    #[test]
    #[should_panic(expected = "Unsupported key type")]
    fn test_parse_invalid_key_type() {
        parse_wallet_pubkey("rsa:abcdef");
    }

    #[test]
    #[should_panic(expected = "Unsupported key type")]
    fn test_parse_account_type_rejected() {
        parse_wallet_pubkey("account:some-uuid");
    }

    #[test]
    #[should_panic(expected = "Ed25519 public key must be 32 bytes")]
    fn test_parse_ed25519_wrong_length() {
        let hex_key = "ab".repeat(16); // 16 bytes, not 32
        parse_wallet_pubkey(&format!("ed25519:{}", hex_key));
    }

    #[test]
    fn test_has_wallet_policy_empty() {
        let owner = accounts(0);
        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let contract = Contract::new(owner, None, None, None);
        assert!(!contract.has_wallet_policy("ed25519:aaaa".to_string()));
    }

    #[test]
    fn test_freeze_unfreeze() {
        let owner = accounts(0);
        let controller = accounts(1);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner, None, None, None);

        // Manually insert a policy entry for testing (bypassing signature verification)
        let wallet_pubkey = format!("ed25519:{}", "a".repeat(64));
        let entry = WalletPolicyEntry {
            owner: controller.clone(),
            encrypted_data: "test_encrypted".to_string(),
            frozen: false,
            updated_at: 0,
            storage_deposit: 0,
        };
        contract.wallet_policies.insert(&wallet_pubkey, &entry);

        // Freeze
        let context = get_context(controller.clone(), NearToken::from_near(0));
        testing_env!(context.build());
        contract.freeze_wallet(wallet_pubkey.clone());

        let view = contract.get_wallet_policy(wallet_pubkey.clone()).unwrap();
        assert!(view.frozen);

        // Unfreeze
        contract.unfreeze_wallet(wallet_pubkey.clone());
        let view = contract.get_wallet_policy(wallet_pubkey).unwrap();
        assert!(!view.frozen);
    }

    #[test]
    #[should_panic(expected = "Only the controller")]
    fn test_freeze_wrong_controller() {
        let owner = accounts(0);
        let controller = accounts(1);
        let attacker = accounts(2);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner, None, None, None);

        let wallet_pubkey = format!("ed25519:{}", "a".repeat(64));
        let entry = WalletPolicyEntry {
            owner: controller,
            encrypted_data: "test".to_string(),
            frozen: false,
            updated_at: 0,
            storage_deposit: 0,
        };
        contract.wallet_policies.insert(&wallet_pubkey, &entry);

        // Attacker tries to freeze
        let context = get_context(attacker, NearToken::from_near(0));
        testing_env!(context.build());
        contract.freeze_wallet(wallet_pubkey);
    }
}
