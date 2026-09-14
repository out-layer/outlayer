use crate::*;
use crate::payment::SystemEvent;
use near_sdk::{env, require};
use near_sdk::json_types::U128;
use sha2::{Digest, Sha256};

/// How an accessor appears inside a signed message.
///
/// One line per kind, each carrying the whole of what identifies it. The
/// signing side only ever produces the `Project` form — that is what an agent's
/// secret is — and the others exist so that binding the accessor does not
/// narrow what `store_agent_secret` accepts.
fn accessor_binding(accessor: &SecretAccessor) -> String {
    match accessor {
        SecretAccessor::Project { project_id } => project_id.clone(),
        SecretAccessor::Repo { repo, branch } => {
            format!("repo:{}:{}", repo, branch.as_deref().unwrap_or(""))
        }
        SecretAccessor::WasmHash { hash } => format!("wasm:{}", hash),
        SecretAccessor::System(kind) => format!("system:{}", system_binding(kind)),
    }
}

/// The one spelling of an accessor that anything is stored under.
///
/// A WASM hash is hex, and hex has two spellings for every byte. The contract
/// checked only that the characters WERE hex, so `AB…` and `ab…` were two
/// different storage keys for one binary — and the worker computes the hash
/// with `hex::encode`, which is lower case. A secret filed under the upper-case
/// spelling was therefore a secret nothing would ever ask for: it stored
/// cleanly, read back under its own spelling, and was invisible to the code it
/// was left for. Confirmed against the deployed contract by
/// `tests/contract_probe_e2e.sh`, probe P1.
///
/// The other accessors have one spelling each as far as this contract is
/// concerned. A repository is stored as given — normalising a URL is the
/// caller's job and this method has no opinion about `https://` — and a project
/// id must already exist in `projects`, which settles it.
pub(crate) fn canonical_accessor(accessor: SecretAccessor) -> SecretAccessor {
    match accessor {
        SecretAccessor::WasmHash { hash } => SecretAccessor::WasmHash {
            hash: hash.to_lowercase(),
        },
        other => other,
    }
}

/// Does this name have the shape of a NEAR implicit account — 64 lowercase hex?
///
/// The same test `shared_tee_helpers::is_implicit_account` applies in the
/// keystore, written out here because the contract does not depend on that
/// crate. Both sides must agree: the keystore treats a profile of this shape as
/// an agent's, and this contract refuses to let anyone else take such a name.
pub(crate) fn is_implicit_account_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The one spelling of a profile, for the accessors where the profile is not
/// free text.
///
/// A payment key's profile IS its nonce, and `"01"` is the same nonce as `"1"`
/// written differently. Both passed validation and landed in DIFFERENT slots —
/// so a key at `"01"` was a second on-chain key for nonce 1 that
/// `delete_payment_key`, which looks up `nonce.to_string()`, could not see or
/// remove, and that the coordinator's one row per `(owner, nonce)` could not
/// represent. Confirmed live as probe P2.
///
/// Rendered from the parsed number, so the canonical form is exactly what
/// `delete_payment_key` builds. A profile that is not a number is left alone:
/// the write path rejects it with a message about nonces, and a READ asking for
/// nonsense should answer "nothing", not panic.
pub(crate) fn canonical_profile(accessor: &SecretAccessor, profile: String) -> String {
    match accessor {
        SecretAccessor::System(SystemSecretType::PaymentKey) => match profile.parse::<u32>() {
            Ok(nonce) => nonce.to_string(),
            Err(_) => profile,
        },
        _ => profile,
    }
}

/// The exact string `store_agent_secret` requires a signature over.
///
/// A function rather than a `format!` at the call site, so a test can exercise
/// the REAL construction. Pinned against an inline `format!` it would only
/// compare two strings this file wrote, and would keep passing while the
/// production message drifted — the shape of tautology that hides a signature
/// covering less than it claims.
///
/// ORDER MATTERS. The fields are colon-joined with no escaping, so all but the
/// last must be colon-free for the string to name exactly one tuple. `access`
/// is JSON and may contain anything, so it goes LAST, with nothing after it to
/// confuse its boundary.
///
/// That requirement was once stated here and enforced by nothing, and it was
/// not true: `accessor_binding` renders a `Repo` as `repo:{repo}:{branch}` with
/// nothing stopping either half from carrying a colon, so one signature covered
/// two different tuples — `(branch "main", profile "x:y")` and
/// `(branch "main:x", profile "y")` produced the same bytes.
///
/// **The accessor is now LENGTH-PREFIXED**, which is what lets it hold colons
/// again. `git@github.com:owner/repo` is an ordinary way to write a repository
/// and refusing it was a real cost; with the length in front, the field's end is
/// pinned by arithmetic instead of by a delimiter, so its content stops
/// mattering. Refusing colons everywhere was the cheap answer and this is the
/// one that scales — the next field to need a colon needs no new rule.
///
/// Still `v1`, deliberately. A version exists to tell two formats apart IN THE
/// WILD, and there is no v1 in the wild: the mechanism has never been on
/// mainnet and the only testnet secrets under the earlier format are ours. A
/// bump would have marked a boundary nobody is on either side of. The keystore
/// pins the same string.
///
/// What is left holding colons is deliberate and safe: `agent_pubkey` is
/// `ed25519:` plus exactly 64 hex characters, a fixed shape that consumes a
/// known number of segments; the accessor is pinned by its length; and `access`
/// is last, with nothing after it to confuse. `profile` is the one field still
/// required to be colon-free — see [`assert_unambiguous_fields`].
///
/// An absent vault leaves an EMPTY field rather than dropping one: dropping
/// would shift every field after it, and two different tuples would share a
/// message.
/// Refuse any signed field that could move a boundary in the message above.
///
/// A colon in a variable field is not a formatting nuisance, it is a second
/// meaning for one signature: the verifier compares STRINGS, so a tuple that
/// renders to the same bytes is authorised by the same signature. The payer —
/// who submits the signed call and did not sign it — is the party who would
/// choose the second meaning, and what it buys them is landing the store under
/// a different accessor or profile of the same owner, overwriting whatever was
/// there.
///
/// Only the caller-supplied halves are checked. The prefixes `accessor_binding`
/// writes (`repo:`, `wasm:`, `system:`) are fixed per variant, so once the
/// halves are colon-free the number of segments each variant occupies is known
/// and the string reads back to exactly one tuple.
///
/// A ban rather than escaping or length prefixes, which is the cheaper half of
/// a real answer: it has to be re-applied by hand to every field and every
/// accessor variant added later. Signing a concatenation of per-field hashes
/// would end the question instead of answering it once — worth doing when this
/// format next changes for another reason.
///
/// Nothing legitimate is lost. A profile is an agent's account (hex) or a name
/// somebody types; git forbids a colon in a refname; a normalised repo path is
/// `github.com/owner/repo` with no scheme; a project id is `owner/name` and NEAR
/// account ids cannot hold a colon; a wasm hash is hex.
pub(crate) fn assert_profile_is_unambiguous(profile: &str) {
    // Only `profile`. The accessor is length-prefixed in the message, so its
    // content cannot move a boundary however it is spelled — which is what lets
    // a repository be written `git@github.com:owner/repo`.
    //
    // `profile` is a plain argument here, not something derived — that happens
    // in the keystore — so it is worth being exact about what already guards
    // it. On the STORE path a colon could never have reached the message:
    // `profile_shape_error` admits only letters, digits, dashes and
    // underscores. The DELETE path never reaches that rule, and this is what
    // makes it hold the same line.
    assert!(
        !profile.contains(':'),
        "profile must not contain ':' — it is a field separator in the signed \
         `store_agent_secret` message, and a colon there would let one signature \
         authorise a different secret. Got '{}'. A profile is an agent's \
         64-character account or a plain name like 'production'.",
        profile
    );
}

/// The exact string `delete_agent_secret` requires a signature over.
///
/// A DIFFERENT domain from the store, and that is the point: a signature made
/// to store a secret must never also destroy one.
///
/// Same shape otherwise, for the same reasons — a leading ASCII domain, so read
/// as borsh it claims a `signer_id` of about 1.9 billion against a 64-byte
/// maximum and no transaction can wear it; the accessor length-prefixed, so it
/// may hold anything; the payer last, binding the submitter.
///
/// The payer is in here for the same reason as in the store, and a sharper one:
/// without it the pair `(args, signature)` sits on chain forever and anyone
/// could replay it — and a replayed DELETE is not a rollback, it is a deletion
/// that happens whenever an attacker chooses.
pub(crate) fn secret_delete_message(
    agent_pubkey: &str,
    accessor: &SecretAccessor,
    profile: &str,
    payer: &AccountId,
) -> String {
    let binding = accessor_binding(accessor);
    format!(
        "delete_agent_secret:v1:{}:{}:{}:{}:{}",
        agent_pubkey,
        binding.len(),
        binding,
        profile,
        payer
    )
}

pub(crate) fn secret_store_message(
    agent_pubkey: &str,
    accessor: &SecretAccessor,
    profile: &str,
    encrypted_secrets_base64: &str,
    payer: &AccountId,
    vault_id: Option<&AccountId>,
    access: &types::AccessCondition,
) -> String {
    let binding = accessor_binding(accessor);
    format!(
        "store_secrets_for:v1:{}:{}:{}:{}:{}:{}:{}:{}",
        agent_pubkey,
        binding.len(),
        binding,
        profile,
        encrypted_secrets_base64,
        payer,
        vault_id.map(|v| v.as_str()).unwrap_or(""),
        serde_json::to_string(access)
            .unwrap_or_else(|_| env::panic_str("access condition could not be serialised"))
    )
}

/// The name a system accessor goes by INSIDE A SIGNATURE.
///
/// Written out per variant rather than derived from the type. It was
/// `format!("{:?}", kind)`, and `Debug` is not a stability contract — it is
/// generated from the variant's Rust name, so renaming `PaymentKey` would have
/// changed what a signature covers with nothing failing to compile and nothing
/// failing at run time. What is signed must not depend on how something happens
/// to print for a human.
///
/// The strings are the same ones `Debug` produced, so no signature that was
/// valid before is invalid now: this fixes how the value is arrived at, not the
/// value. Adding a variant means adding a line here, and the compiler says so
/// because the match is exhaustive.
fn system_binding(kind: &SystemSecretType) -> &'static str {
    match kind {
        SystemSecretType::PaymentKey => "PaymentKey",
    }
}

/// Storage cost per byte in NEAR
pub const STORAGE_PRICE_PER_BYTE: Balance = 10_000_000_000_000_000_000; // 0.00001 NEAR per byte

#[near_bindgen]
impl Contract {
    /// Store secrets with access control.
    ///
    /// User must attach storage deposit to cover the cost of storing
    /// secrets. The deposit is refunded when secrets are deleted.
    ///
    /// # Arguments
    /// * `accessor` - What code can access these secrets (Repo /
    ///   WasmHash / Project / System)
    /// * `profile` - Profile name (e.g., "default", "premium", "staging")
    /// * `encrypted_secrets_base64` - Base64-encoded encrypted secrets
    /// * `access` - Access control rules
    /// * `vault_id` - Optional per-customer vault binding.
    ///   * `null` — secret was encrypted with the default OutLayer
    ///     master. **Existing vault bindings on the same `(accessor,
    ///     profile, owner)` key are LEFT UNTOUCHED** so a re-store
    ///     that just rotates the ciphertext does not silently break
    ///     decryption. To opt out of an existing binding call
    ///     [`Contract::unbind_secret_vault`] explicitly (typically
    ///     paired with re-encrypting under the default master).
    ///   * `"vault.alice.near"` — secret was encrypted with that
    ///     vault's master. The worker resolves the master through MPC
    ///     CKD using the vault account id as the signer.
    ///
    /// Storage deposit cost includes the binding entry when
    /// `vault_id = Some(_)`.
    ///
    /// **Off-chain callers MUST pass `vault_id` explicitly** (set to
    /// `null` for the default-master path). near-sdk's argument
    /// deserialiser rejects JSON that omits a required `Option` field.
    #[payable]
    pub fn store_secrets(
        &mut self,
        accessor: SecretAccessor,
        profile: String,
        encrypted_secrets_base64: String,
        access: types::AccessCondition,
        vault_id: Option<AccountId>,
    ) {
        let caller = env::predecessor_account_id();
        self.store_secrets_internal(
            caller.clone(),
            caller,
            accessor,
            profile,
            encrypted_secrets_base64,
            access,
            vault_id,
        );
    }

    /// Store a secret for YOUR AGENT — not for yourself — paid for by whoever
    /// calls.
    ///
    /// The name says all three things it needs to, because each one is a
    /// question somebody would otherwise ask of the code:
    ///
    ///   * **agent secret** — the owner is the AGENT, derived from the key that
    ///     signed. It is not the caller's own secret, and there is no argument
    ///     through which another NEAR account could be named as the owner. Use
    ///     `store_secrets` for your own.
    ///   * **a project or a wasm hash, nothing else.** Not a limit of the
    ///     signature — the accessor is length-prefixed and would carry anything
    ///     — but of what an agent secret IS. A repository names a source that
    ///     can be rewritten under it; a payment key is not a secret of this kind
    ///     at all and has its own door. `delete_agent_secret` accepts exactly
    ///     the same two, because a door that takes more than its counterpart is
    ///     a door somebody finds.
    ///
    /// Exists so an agent needs no NEAR of its own. On the ordinary path the
    /// owner is the caller, which means a custody wallet has to hold a NEAR
    /// balance before it can be given anything — an onboarding step with no
    /// purpose, since the human funding the agent is right there and can pay.
    ///
    /// **Who owns it is proven, not asserted.** The signature is by the WALLET's
    /// own key, which only the keystore can produce and only for a holder of that
    /// wallet's `wk_`. So the caller cannot make a secret owned by a wallet they
    /// do not control, and — the case this is really for — a stranger cannot
    /// plant a credential under an agent's public account.
    ///
    /// The signed message binds the PREDECESSOR. Without it the pair
    /// `(data, signature)` sits on chain forever and anyone could replay it: not
    /// to steal, but to roll a secret back to an earlier ciphertext, which for a
    /// rotated credential is exactly an attack. `store_wallet_policy` signs
    /// without the payer and has that hole; this does not repeat it.
    ///
    /// The accessor is deliberately NOT in the message. Rendering it identically
    /// on both sides is a source of drift, and it buys nothing: replay by anyone
    /// else is already impossible, and the ciphertext is sealed to a seed that
    /// names the project, so the same bytes filed under another accessor decrypt
    /// to nothing.
    ///
    /// Everything else — accessor validation, the payment-key write-once rule,
    /// deposit arithmetic, refunds to the payer, the vault side-table — is the
    /// same code the ordinary path runs.
    #[payable]
    pub fn store_agent_secret(
        &mut self,
        agent_pubkey: String,
        accessor: SecretAccessor,
        profile: String,
        encrypted_secrets_base64: String,
        access: types::AccessCondition,
        vault_id: Option<AccountId>,
        wallet_signature: String,
    ) {
        let payer = env::predecessor_account_id();
        let owner = crate::wallet::implicit_account_of(&agent_pubkey);

        // Canonical BEFORE the message is built, so the string the signature
        // covers is the one that names the slot this writes to. Canonicalising
        // afterwards would sign one accessor and store under another.
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);

        // The profile rule first, worded as every store door words it; the
        // colon check after it is about the signed message's shape and cannot
        // fire on a profile the rule admits.
        if let Some(why) = profile_shape_error(&profile) {
            env::panic_str(&format!("profile must be {PROFILE_RULE} ({why})"));
        }
        // Before anything is hashed: a field that can move a boundary makes the
        // signature cover more than one tuple. Checked here rather than inside
        // `secret_store_message`, which is a pure function used for verification
        // too — the refusal belongs on the way IN.
        assert_profile_is_unambiguous(&profile);

        // This door is for PROJECTS, and says so rather than leaving it to be
        // discovered.
        //
        // Not a limit of the signature — the accessor is length-prefixed and
        // would carry a repo or a hash perfectly well. It is the ENCRYPTION
        // that is project-shaped: the ciphertext is sealed to
        // `project:{project_id}:{agent}`, derived by the keystore from the
        // project alone, and there is no agreed seed for a repository or a wasm
        // hash. Accepting one would store a secret under a key nothing can
        // derive a decryption for — working on the way in, silent on the way
        // out, which is the worst of the three possible behaviours.
        //
        // If a repo or hash accessor is ever wanted here, the seed is what has
        // to be designed first, and with the same care: `repo:{repo}:{branch}:
        // {agent}` colon-joined would let two different repositories derive ONE
        // key, and that costs confidentiality rather than the integrity the
        // message ambiguity cost.
        //
        // GitHub is simply not supported here. A wasm hash is, and nothing
        // checks it was ever deployed: there is nothing to check a commitment
        // against, and a secret sealed to bytes that have not run yet is a
        // secret waiting for them.
        assert!(
            !matches!(accessor, SecretAccessor::Repo { .. }),
            "GitHub repositories are not supported for agent secrets. Use a wasm hash \
             or a project."
        );

        // A payment key is not an agent secret, and the write-once rule further
        // in does NOT cover this — it refuses a REWRITE, so a first store would
        // have gone through. Payment keys are created by their owner through
        // `store_secrets`, never here, so refusing costs nothing and the two
        // doors now accept exactly the same set.
        assert!(
            !matches!(accessor, SecretAccessor::System(_)),
            "A payment key is not an agent secret. Create it with store_secrets from \
             the account that owns it."
        );


        // EVERY argument that decides what is stored, who may read it, and who
        // pays is inside the signature. Not most of them.
        //
        // `access` is the one that makes this worth spelling out: it is what
        // the keystore evaluates to decide who gets a decryption, and it was
        // outside the signature at first. The wallet's owner then consented to
        // a ciphertext while the payer chose, afterwards and unsigned, who
        // could read it — with the signature still verifying. Consent to
        // content is not consent to an audience.
        //
        // `vault_id` decides which master decrypts, and `accessor` what the
        // secret is for; leaving either out would let the payer resend the same
        // signed bytes under a different one.
        //
        // ORDER MATTERS. The fields are colon-joined with no escaping, so all
        // but the last must be colon-free for the string to name exactly one
        // tuple. `access` is JSON and can contain anything, so it goes LAST,
        // where nothing follows it to be confused with. Everything before it —
        // the key, the accessor, the ciphertext (base64), the payer and the
        // vault (account ids) — is colon-free, so the boundaries are readable
        // from both ends.
        let message = secret_store_message(
            &agent_pubkey,
            &accessor,
            &profile,
            &encrypted_secrets_base64,
            &payer,
            vault_id.as_ref(),
            &access,
        );
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash: [u8; 32] = hasher.finalize().into();

        crate::wallet::verify_wallet_signature(&agent_pubkey, &message_hash, &wallet_signature);

        self.store_secrets_internal(
            owner,
            payer,
            accessor,
            profile,
            encrypted_secrets_base64,
            access,
            vault_id,
        );
    }

    /// Remove an agent secret, on the authority of the key that owns it.
    ///
    /// The mirror of [`Contract::store_agent_secret`], and it exists because
    /// without it a secret written there could never be removed by anybody: the
    /// owner is an implicit account whose key lives only inside the keystore, so
    /// the ordinary `delete_secrets` — which deletes under `owner = caller` —
    /// has no caller that could ever match. The secret and its storage deposit
    /// were permanent.
    ///
    /// **The agent's key authorises it, and that is the whole rule.** The
    /// signature is produced by the keystore for a holder of the wallet's
    /// `wk_`, so the human who set the secret up can remove it — and so can the
    /// agent itself, deliberately. An agent that has finished with a credential
    /// should be able to take it out of the world rather than leaving it on
    /// chain because only somebody else could.
    ///
    /// **The submitter is bound but not restricted.** They are in the signed
    /// message, so a signature cannot be lifted and replayed by a third party;
    /// they are not required to be any particular account, because an agent has
    /// no NEAR and needs whoever is paying gas to be able to send this.
    ///
    /// The storage deposit comes BACK to the submitter — the same refund the
    /// ordinary delete makes, to the party the signature names and, on the path
    /// this is built for, the one who paid it in.
    ///
    /// NOT `#[payable]`, matching `delete_secrets`. A delete needs no deposit,
    /// and accepting one would mean NEAR attached by mistake settles into the
    /// contract with nothing to return it; refusing the attachment is the
    /// runtime's job and it does it for free.
    pub fn delete_agent_secret(
        &mut self,
        agent_pubkey: String,
        accessor: SecretAccessor,
        profile: String,
        wallet_signature: String,
    ) {
        let payer = env::predecessor_account_id();
        let owner = crate::wallet::implicit_account_of(&agent_pubkey);

        // Canonical first, for the same reason as the store: the signature must
        // cover the slot this actually removes.
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);

        // The same rule the store applies, from the same place. Two copies
        // would be two messages for one constraint, and the second is the one
        // nobody updates.
        assert_profile_is_unambiguous(&profile);

        // A payment key is NOT an agent secret and must not leave by this door.
        //
        // An agent's payment key lives at exactly this shape — accessor
        // `System(PaymentKey)`, owner the agent's own implicit account — so
        // without this line a valid agent signature could erase it from the
        // chain. That bypasses `delete_payment_key`, which the write-once rule
        // names as the honest way out precisely because the coordinator SEES
        // it, and it bypasses the coordinator's own refusal to delete an agent
        // key at all, which exists because the balance behind it would be
        // stranded.
        //
        // Accepts exactly what the store accepts, and for the same reason: a
        // door that takes more than its counterpart is a door somebody finds.
        assert!(
            matches!(
                accessor,
                SecretAccessor::Project { .. } | SecretAccessor::WasmHash { .. }
            ),
            "delete_agent_secret removes an agent SECRET, stored against a project or \
             a wasm hash. A payment key is not one: delete it with delete_payment_key, \
             which the coordinator is told about."
        );

        let message = secret_delete_message(&agent_pubkey, &accessor, &profile, &payer);
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let message_hash: [u8; 32] = hasher.finalize().into();

        crate::wallet::verify_wallet_signature(&agent_pubkey, &message_hash, &wallet_signature);

        let key = SecretKey {
            accessor: accessor.clone(),
            profile: profile.clone(),
            owner: owner.clone(),
        };

        // The index belongs to the owner; the deposit goes back to whoever is
        // standing here paying gas, which on this path is who put it in.
        self.delete_secrets_internal(key, &owner, &payer);

        log!(
            "Agent secret deleted: accessor={:?}, profile={}, owner={}, submitted by {}",
            accessor,
            profile,
            owner,
            payer
        );
    }

    /// Delete secrets and refund storage deposit
    ///
    /// # Arguments
    /// * `accessor` - What code can access these secrets (Repo or WasmHash)
    /// * `profile` - Profile name
    pub fn delete_secrets(
        &mut self,
        accessor: SecretAccessor,
        profile: String,
    ) {
        let caller = env::predecessor_account_id();
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);

        let key = SecretKey {
            accessor: accessor.clone(),
            profile: profile.clone(),
            owner: caller.clone(),
        };

        // The ordinary door: the caller IS the owner, so both roles are theirs.
        self.delete_secrets_internal(key, &caller, &caller);

        log!(
            "Secrets deleted: accessor={:?}, profile={}, owner={}",
            accessor,
            profile,
            caller
        );
    }

    /// Drop the vault binding for an existing secret without touching
    /// the ciphertext.
    ///
    /// Use this when re-encrypting a secret under the default OutLayer
    /// master after it had previously been bound to a vault. Calling
    /// `store_secrets(..., vault_id: None)` does NOT clear an existing
    /// binding (that's the back-compat invariant for legacy callers);
    /// this method is the explicit opt-out.
    ///
    /// Idempotent: succeeds silently if no binding exists.
    pub fn unbind_secret_vault(&mut self, accessor: SecretAccessor, profile: String) {
        let caller = env::predecessor_account_id();
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);
        let key = SecretKey {
            accessor,
            profile,
            owner: caller,
        };
        require!(
            self.secrets_storage.get(&key).is_some(),
            "secret not found or not owned by caller"
        );
        self.secret_vault_bindings.remove(&key);
    }

    /// Update access control rules for existing secrets
    ///
    /// # Arguments
    /// * `accessor` - What code can access these secrets (Repo or WasmHash)
    /// * `profile` - Profile name
    /// * `new_access` - New access control rules
    ///
    /// Payable, for the reason `store_secrets` is payable: a condition is
    /// stored bytes, and a `Whitelist` of two thousand accounts occupies some
    /// fifty kilobytes whichever door it arrives through. Storage that nobody
    /// funds is storage every other account funds.
    ///
    /// The deposit already held against the row counts towards the new
    /// requirement, so the common edits cost nothing: narrowing a condition
    /// refunds the difference, and one that does not change the size needs no
    /// deposit at all. Only growth asks for more, and only for the growth.
    #[payable]
    pub fn update_access(
        &mut self,
        accessor: SecretAccessor,
        profile: String,
        new_access: types::AccessCondition,
    ) {
        let caller = env::predecessor_account_id();
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);

        let key = SecretKey {
            accessor: accessor.clone(),
            profile: profile.clone(),
            owner: caller.clone(),
        };

        let mut profile_data = self.secrets_storage.get(&key)
            .expect("Secrets not found");

        assert_account_pattern_bounds(&new_access);

        // Priced exactly as a store prices it, against the row's real
        // ciphertext and the NEW condition. The binding state is read rather
        // than assumed: an edit never changes it, but the size depends on it.
        let vault_bound = self.secret_vault_bindings.get(&key).is_some();
        let required_deposit = self.calculate_secret_storage_size(
            &key,
            &profile_data.encrypted_secrets,
            &new_access,
            vault_bound,
        ) as u128
            * STORAGE_PRICE_PER_BYTE;

        let attached_deposit = env::attached_deposit().as_yoctonear();
        let total_available = attached_deposit + profile_data.storage_deposit;
        assert!(
            total_available >= required_deposit,
            "Insufficient deposit for this condition. Required: {} yoctoNEAR, \
             available (attached {} + already held {}): {} yoctoNEAR",
            required_deposit,
            attached_deposit,
            profile_data.storage_deposit,
            total_available
        );

        let refund = total_available - required_deposit;
        if refund > 0 {
            near_sdk::Promise::new(caller.clone()).transfer(NearToken::from_yoctonear(refund));
        }

        // Update access rules, timestamp and what the row is funded for.
        profile_data.access = new_access;
        profile_data.updated_at = env::block_timestamp();
        profile_data.storage_deposit = required_deposit;

        self.secrets_storage.insert(&key, &profile_data);

        log!(
            "Access control updated: accessor={:?}, profile={}, deposit={}",
            accessor,
            profile,
            required_deposit
        );
    }

}

// View methods
#[near_bindgen]
impl Contract {
    /// Estimate storage cost for secrets (before storing).
    ///
    /// Returns cost in yoctoNEAR. Call this before `store_secrets` to
    /// know the exact deposit amount required.
    ///
    /// # Arguments
    /// * `accessor` - What code can access these secrets
    /// * `profile` - Profile name
    /// * `owner` - Account that will own the secrets
    /// * `encrypted_secrets_base64` - Base64-encoded encrypted secrets
    /// * `access` - Access control rules
    /// * `vault_id` - Match the value the caller will pass to
    ///   `store_secrets`. `Some(_)` includes the side-table binding
    ///   entry in the cost; `None` excludes it. Off-chain callers MUST
    ///   pass this explicitly (no missing-field-as-default).
    pub fn estimate_storage_cost(
        &self,
        accessor: SecretAccessor,
        profile: String,
        owner: AccountId,
        encrypted_secrets_base64: String,
        access: types::AccessCondition,
        vault_id: Option<AccountId>,
    ) -> U128 {
        // The estimate must price the slot the store will actually use.
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);
        let key = SecretKey {
            accessor,
            profile,
            owner,
        };
        // Match the post-call state of the side-table, not the delta.
        // See `internal_store_secrets` for the rationale — the same
        // bug would surface here as inaccurate quotes for updates
        // that keep an existing binding implicitly.
        let vault_bound_after_call =
            vault_id.is_some() || self.secret_vault_bindings.get(&key).is_some();
        let storage_bytes = self.calculate_secret_storage_size(
            &key,
            &encrypted_secrets_base64,
            &access,
            vault_bound_after_call,
        );
        U128((storage_bytes as u128) * STORAGE_PRICE_PER_BYTE)
    }

    /// Get secrets (for keystore worker to read)
    ///
    /// For Repo accessor: if querying with a specific branch returns None,
    /// automatically tries with branch=null to find wildcard secrets.
    ///
    /// # Arguments
    /// * `accessor` - What code can access these secrets (Repo or WasmHash)
    /// * `profile` - Profile name
    /// * `owner` - Account that owns the secrets
    pub fn get_secrets(
        &self,
        accessor: SecretAccessor,
        profile: String,
        owner: AccountId,
    ) -> Option<SecretProfileView> {
        // A READ must ask for the same slot a write produced, whatever case the
        // caller typed the hash in.
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);
        let key = SecretKey {
            accessor: accessor.clone(),
            profile: profile.clone(),
            owner: owner.clone(),
        };

        // Try with exact accessor first
        if let Some(profile_data) = self.secrets_storage.get(&key) {
            return Some(SecretProfileView {
                encrypted_secrets: profile_data.encrypted_secrets,
                access: profile_data.access,
                created_at: profile_data.created_at,
                updated_at: profile_data.updated_at,
                storage_deposit: U128(profile_data.storage_deposit),
                accessor: key.accessor,
            });
        }

        // For Repo with branch, try wildcard (branch=null)
        if let SecretAccessor::Repo { repo, branch: Some(_) } = accessor {
            let wildcard_key = SecretKey {
                accessor: SecretAccessor::Repo {
                    repo,
                    branch: None,
                },
                profile,
                owner,
            };
            if let Some(profile_data) = self.secrets_storage.get(&wildcard_key) {
                return Some(SecretProfileView {
                    encrypted_secrets: profile_data.encrypted_secrets,
                    access: profile_data.access,
                    created_at: profile_data.created_at,
                    updated_at: profile_data.updated_at,
                    storage_deposit: U128(profile_data.storage_deposit),
                    accessor: wildcard_key.accessor,
                });
            }
        }

        None
    }

    /// List all profile names for a repository owned by caller
    pub fn list_profiles(
        &self,
        _repo: String,
        _branch: Option<String>,
    ) -> Vec<String> {
        // Note: This is inefficient and should be optimized with indexing in production
        // For MVP, we accept O(n) iteration
        let profiles = Vec::new();

        // We can't iterate LookupMap directly, so this would require maintaining
        // a separate index. For now, return empty vector with a note.
        log!("WARNING: list_profiles requires indexing implementation");

        profiles
    }

    /// View — return the vault binding for a given secret, if any.
    ///
    /// A `Some(v)` result means the secret was
    /// encrypted with vault `v`'s master and the keystore-worker MUST
    /// resolve `v`'s per-vault master to decrypt it. `None` means the
    /// secret was encrypted with the default OutLayer master (legacy
    /// path).
    ///
    /// Off-chain consumers (keystore-worker, dashboards) typically want
    /// both `SecretProfile` and the binding in one shot; use
    /// [`Contract::get_secret_with_vault`] to save a round-trip.
    pub fn get_secret_vault(
        &self,
        accessor: SecretAccessor,
        profile: String,
        owner: AccountId,
    ) -> Option<AccountId> {
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);
        let key = SecretKey {
            accessor,
            profile,
            owner,
        };
        self.secret_vault_bindings.get(&key)
    }

    /// View — combined secret profile + vault binding lookup. Saves an
    /// RPC round-trip for the keystore-worker, which always needs both
    /// fields together to decide which master to use for decryption.
    ///
    /// `profile.is_none()` and `vault_id.is_none()` are independent —
    /// a missing secret returns `profile = None`, while
    /// `vault_id = None` simply means "default master".
    pub fn get_secret_with_vault(
        &self,
        accessor: SecretAccessor,
        profile: String,
        owner: AccountId,
    ) -> SecretWithVault {
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);
        let key = SecretKey {
            accessor: accessor.clone(),
            profile: profile.clone(),
            owner: owner.clone(),
        };

        // Reuse get_secrets' wildcard-fallback behaviour for Repo entries
        // by calling it directly. The vault binding is keyed against the
        // exact-match SecretKey first, falling back to the wildcard if
        // that's where the actual secret lives.
        let secret = self.get_secrets(accessor, profile, owner);

        let vault_id = if let Some(ref view) = secret {
            // get_secrets may have returned a wildcard match. Re-key the
            // binding lookup using whatever accessor it actually
            // resolved to.
            let resolved_key = SecretKey {
                accessor: view.accessor.clone(),
                profile: key.profile.clone(),
                owner: key.owner.clone(),
            };
            self.secret_vault_bindings.get(&resolved_key)
        } else {
            None
        };

        SecretWithVault {
            profile: secret,
            vault_id,
        }
    }

    /// Check if secrets exist for a given key
    ///
    /// # Arguments
    /// * `accessor` - What code can access these secrets (Repo or WasmHash)
    /// * `profile` - Profile name
    /// * `owner` - Account that owns the secrets
    pub fn secrets_exist(
        &self,
        accessor: SecretAccessor,
        profile: String,
        owner: AccountId,
    ) -> bool {
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);
        let key = SecretKey {
            accessor,
            profile,
            owner,
        };

        self.secrets_storage.get(&key).is_some()
    }

    /// One PAGE of a user's secrets, as metadata.
    ///
    /// Paged for the same reason `get_priced_projects` is: this walks an
    /// `UnorderedSet` and does a storage READ per entry, so the work grows with
    /// the account and a big enough account cannot be read at all — the view
    /// exceeds its gas and every caller sees a failure rather than a long
    /// answer. An account gets that many secrets by using the product, and this
    /// project already has the incident to prove it: a worker enumerating a
    /// key set of that size stalled for hours.
    ///
    /// A caller that names no limit gets a PAGE, not everything, so the
    /// unbounded read is not reachable by omission. Callers that want the whole
    /// list ask for the next page until one comes back short — the CLI's
    /// `secrets list` and `keys list` do exactly that, because a silently
    /// truncated list of your own secrets is worse than a slow one.
    ///
    /// `from_index` and `limit` may be omitted entirely; near-sdk reads an
    /// absent `Option` argument as `None`, which is what makes this a
    /// compatible change for callers that only pass `account_id`.
    pub fn list_user_secrets(
        &self,
        account_id: AccountId,
        from_index: Option<u64>,
        limit: Option<u64>,
    ) -> Vec<UserSecretInfo> {
        let from_index = from_index.unwrap_or(0) as usize;
        let limit = limit.unwrap_or(100).min(500) as usize;

        match self.user_secrets_index.get(&account_id) {
            Some(secrets_set) => secrets_set
                .iter()
                .skip(from_index)
                .take(limit)
                .filter_map(|key| {
                    self.secrets_storage.get(&key).map(|profile| UserSecretInfo {
                        accessor: key.accessor.clone(),
                        profile: key.profile.clone(),
                        created_at: profile.created_at,
                        updated_at: profile.updated_at,
                        storage_deposit: U128(profile.storage_deposit),
                        access: profile.access,
                    })
                })
                .collect(),
            None => vec![],
        }
    }
}

/// Combined response for [`Contract::get_secret_with_vault`]. Returning
/// both fields in one structure lets the keystore-worker make a single
/// RPC call to learn (a) whether a secret exists and what its profile
/// looks like, and (b) which master should be used to decrypt it.
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct SecretWithVault {
    pub profile: Option<SecretProfileView>,
    pub vault_id: Option<AccountId>,
}

/// Project secrets storage info
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct ProjectSecretsStorage {
    pub project_id: String,
    pub owner: AccountId,
    pub total_bytes: u64,
    pub profiles_count: u32,
}

/// User secret metadata for list view
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct UserSecretInfo {
    pub accessor: SecretAccessor,
    pub profile: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub storage_deposit: U128,
    pub access: types::AccessCondition,
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{accounts, VMContextBuilder};
    use near_sdk::testing_env;

    /// The `store_agent_secret` message, byte for byte.
    ///
    /// The keystore builds the SAME string from its own types
    /// (`the_secret_store_message_format_is_pinned` in
    /// `keystore-worker/src/api.rs`), and the two never compare notes at run
    /// time: a drifted format shows up as signatures this contract silently
    /// rejects, on a path nobody exercises until launch. The agreement is held
    /// by these two tests reading alike, so change one and change the other.
    #[test]
    fn the_signed_message_is_pinned() {
        let message = |vault: Option<AccountId>, access: &types::AccessCondition| {
            secret_store_message(
                "ed25519:ab",
                &SecretAccessor::Project { project_id: "a.near/p".into() },
                "agent",
                "cipher",
                &"payer.near".parse().unwrap(),
                vault.as_ref(),
                access,
            )
        };

        assert_eq!(
            message(None, &types::AccessCondition::AllowAll),
            "store_secrets_for:v1:ed25519:ab:8:a.near/p:agent:cipher:payer.near::\"AllowAll\""
        );
        assert_eq!(
            message(Some("vault.alice.near".parse().unwrap()), &types::AccessCondition::AllowAll),
            "store_secrets_for:v1:ed25519:ab:8:a.near/p:agent:cipher:payer.near:vault.alice.near:\"AllowAll\""
        );

        // `access` is LAST because it is JSON and may contain colons; anything
        // after it would have ambiguous boundaries. The accessor is the one
        // exception, and the `8:` before it is why: its end is arithmetic, not
        // a delimiter, so it may hold colons of its own.
        let whitelist = types::AccessCondition::Whitelist {
            accounts: vec!["a.near".parse().unwrap()],
        };
        assert!(message(None, &whitelist)
            .ends_with(&serde_json::to_string(&whitelist).unwrap()));

        // The two fields that were added. Both were OUTSIDE the signature at
        // first: the payer chose who could read the secret, and under which
        // master, after the owner had signed — and the signature still
        // verified.
        assert_ne!(
            message(None, &types::AccessCondition::AllowAll),
            message(None, &whitelist),
            "who may READ the secret must change the message"
        );
        assert_ne!(
            message(None, &types::AccessCondition::AllowAll),
            message(Some("vault.x.near".parse().unwrap()), &types::AccessCondition::AllowAll),
            "which master decrypts must change the message"
        );
    }

    /// What an accessor looks like inside a SIGNATURE, pinned.
    ///
    /// These strings are covered by `store_agent_secret`'s signature, so
    /// changing one silently invalidates every signature a client is about to
    /// send and, worse, makes a signature for one accessor verify against
    /// another. Nothing else fails when that happens: the code compiles, the
    /// tests pass, and a request either stops working or starts working when it
    /// should not.
    ///
    /// The system arm is the reason this test exists. It used to be
    /// `format!("{:?}", kind)`, and `Debug` is generated from the Rust variant
    /// name — so renaming `PaymentKey` would have rewritten a signed message
    /// with no diff anywhere near this file.
    #[test]
    fn the_signed_form_of_an_accessor_is_frozen() {
        assert_eq!(
            accessor_binding(&SecretAccessor::Project {
                project_id: "connectors.outlayer.near/near-email".to_string()
            }),
            "connectors.outlayer.near/near-email",
            "the only form that is ever signed today"
        );
        assert_eq!(
            accessor_binding(&SecretAccessor::Repo {
                repo: "github.com/a/b".to_string(),
                branch: Some("main".to_string())
            }),
            "repo:github.com/a/b:main"
        );
        assert_eq!(
            accessor_binding(&SecretAccessor::Repo {
                repo: "github.com/a/b".to_string(),
                branch: None
            }),
            "repo:github.com/a/b:",
            "a branchless repo keeps the separator, so it cannot collide with a branch named after the next field"
        );
        assert_eq!(
            accessor_binding(&SecretAccessor::WasmHash {
                hash: "abcd".to_string()
            }),
            "wasm:abcd"
        );
        assert_eq!(
            accessor_binding(&SecretAccessor::System(SystemSecretType::PaymentKey)),
            "system:PaymentKey",
            "same bytes Debug produced, so no signature valid before is invalid now"
        );

        // Distinct accessors must produce distinct strings. A collision would
        // let a signature for one verify against another.
        let forms = [
            accessor_binding(&SecretAccessor::Project { project_id: "a/b".into() }),
            accessor_binding(&SecretAccessor::Repo { repo: "a/b".into(), branch: None }),
            accessor_binding(&SecretAccessor::WasmHash { hash: "a/b".into() }),
            accessor_binding(&SecretAccessor::System(SystemSecretType::PaymentKey)),
        ];
        let mut seen = forms.to_vec();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), forms.len(), "two accessors share a signed form");
    }

    fn get_context(predecessor: AccountId, attached_deposit: NearToken) -> VMContextBuilder {
        let mut builder = VMContextBuilder::new();
        builder
            .predecessor_account_id(predecessor)
            .attached_deposit(attached_deposit);
        builder
    }

    #[test]
    fn test_store_secrets_repo() {
        let owner = accounts(0);
        let operator = accounts(1);
        let user = accounts(2);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner.clone(), Some(operator), None, None);

        // Store secrets with sufficient deposit
        let context = get_context(user.clone(), NearToken::from_near(1));
        testing_env!(context.build());

        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/project".to_string(),
                branch: None,
            },
            "default".to_string(),
            "base64encodeddata".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        // Verify secrets exist
        assert!(contract.secrets_exist(
            SecretAccessor::Repo {
                repo: "github.com/alice/project".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        ));
    }

    /// A condition is stored bytes, so growing one is buying storage.
    ///
    /// Fifty kilobytes of whitelist funded by nobody is fifty kilobytes every
    /// other account funds. The row is re-priced on every edit; these three
    /// pin the whole of that arithmetic. They use a `Repo` accessor because
    /// the arithmetic does not depend on which accessor names the row, and a
    /// `Project` one would drag project registration into a storage test.
    fn a_row_with(access: types::AccessCondition, deposit: NearToken) -> (Contract, AccountId) {
        let owner = accounts(0);
        let user = accounts(2);
        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner, None, None, None);

        testing_env!(get_context(user.clone(), deposit).build());
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/project".to_string(),
                branch: None,
            },
            "default".to_string(),
            "base64encodeddata".to_string(),
            access,
            None,
        );
        (contract, user)
    }

    fn repo_accessor() -> SecretAccessor {
        SecretAccessor::Repo {
            repo: "github.com/alice/project".to_string(),
            branch: None,
        }
    }

    fn many_accounts(n: usize) -> Vec<AccountId> {
        (0..n)
            .map(|i| format!("account{i}.near").parse().unwrap())
            .collect()
    }

    #[test]
    #[should_panic(expected = "Insufficient deposit for this condition")]
    fn growing_a_condition_without_a_deposit_is_refused() {
        let user = accounts(2);
        let (mut contract, _) = a_row_with(
            types::AccessCondition::Whitelist { accounts: vec![user.clone()] },
            NearToken::from_near(1),
        );

        // A thousand accounts is tens of kilobytes the row was never funded
        // for. Nothing attached, so there is nothing to fund it with.
        testing_env!(get_context(user, NearToken::from_near(0)).build());
        contract.update_access(
            repo_accessor(),
            "default".to_string(),
            types::AccessCondition::Whitelist { accounts: many_accounts(1000) },
        );
    }

    #[test]
    fn narrowing_a_condition_gives_the_difference_back() {
        let user = accounts(2);
        let (mut contract, _) = a_row_with(
            types::AccessCondition::Whitelist { accounts: many_accounts(500) },
            NearToken::from_near(5),
        );
        let wide = contract
            .get_secrets(repo_accessor(), "default".to_string(), user.clone())
            .expect("row stored")
            .storage_deposit
            .0;

        testing_env!(get_context(user.clone(), NearToken::from_near(0)).build());
        contract.update_access(
            repo_accessor(),
            "default".to_string(),
            types::AccessCondition::Whitelist { accounts: vec![user.clone()] },
        );
        let narrow = contract
            .get_secrets(repo_accessor(), "default".to_string(), user)
            .expect("row still there")
            .storage_deposit
            .0;

        assert!(
            narrow < wide,
            "narrowing left the row funded for the wider condition: {narrow} vs {wide}"
        );
    }

    #[test]
    fn an_edit_that_does_not_change_the_size_needs_no_deposit() {
        let user = accounts(2);
        // Two names of EQUAL length. `accounts(2)` and `accounts(3)` are
        // `charlie` and `danny`, and swapping those is a narrowing, which is a
        // different claim and is covered by its own test.
        let named: AccountId = "aaa.near".parse().unwrap();
        let other: AccountId = "bbb.near".parse().unwrap();
        let (mut contract, _) = a_row_with(
            types::AccessCondition::Whitelist { accounts: vec![named] },
            NearToken::from_near(1),
        );
        let before = contract
            .get_secrets(repo_accessor(), "default".to_string(), user.clone())
            .expect("row stored")
            .storage_deposit
            .0;

        // Swapping one name for another of the same length moves no bytes, so
        // an owner revoking and re-granting is never asked for money.
        testing_env!(get_context(user.clone(), NearToken::from_near(0)).build());
        contract.update_access(
            repo_accessor(),
            "default".to_string(),
            types::AccessCondition::Whitelist { accounts: vec![other.clone()] },
        );

        let row = contract
            .get_secrets(repo_accessor(), "default".to_string(), user)
            .expect("row still there");
        assert_eq!(
            row.access,
            types::AccessCondition::Whitelist { accounts: vec![other] },
            "the condition did not move"
        );
        assert_eq!(
            row.storage_deposit.0, before,
            "a same-size edit changed what the row is funded for"
        );
    }

    #[test]
    fn test_store_secrets_wasm_hash() {
        let owner = accounts(0);
        let user = accounts(2);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner.clone(), None, None, None);

        // Store secrets by wasm hash
        let context = get_context(user.clone(), NearToken::from_near(1));
        testing_env!(context.build());

        let wasm_hash = "a".repeat(64); // Valid SHA256 hex hash
        contract.store_secrets(
            SecretAccessor::WasmHash {
                hash: wasm_hash.clone(),
            },
            "default".to_string(),
            "base64encodeddata".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        // Verify secrets exist
        assert!(contract.secrets_exist(
            SecretAccessor::WasmHash {
                hash: wasm_hash.clone(),
            },
            "default".to_string(),
            user.clone(),
        ));

        // Verify can retrieve
        let secrets = contract.get_secrets(
            SecretAccessor::WasmHash {
                hash: wasm_hash,
            },
            "default".to_string(),
            user.clone(),
        );
        assert!(secrets.is_some());
    }

    #[test]
    #[should_panic(expected = "WASM hash must be 64 hex characters")]
    fn test_invalid_wasm_hash_length() {
        let owner = accounts(0);
        let user = accounts(2);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner.clone(), None, None, None);

        let context = get_context(user.clone(), NearToken::from_near(1));
        testing_env!(context.build());

        contract.store_secrets(
            SecretAccessor::WasmHash {
                hash: "tooshort".to_string(), // Invalid length
            },
            "default".to_string(),
            "base64encodeddata".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );
    }

    #[test]
    #[should_panic(expected = "profile must be 1–64 bytes of letters, digits, '-' or '_' (it contains ' ')")]
    fn test_invalid_profile_name() {
        let owner = accounts(0);
        let user = accounts(2);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner.clone(), None, None, None);

        let context = get_context(user.clone(), NearToken::from_near(1));
        testing_env!(context.build());

        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/project".to_string(),
                branch: None,
            },
            "invalid profile!".to_string(), // Invalid characters
            "base64encodeddata".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );
    }

    #[test]
    fn test_delete_secrets_repo() {
        let owner = accounts(0);
        let user = accounts(2);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner.clone(), None, None, None);

        // Store secrets
        let context = get_context(user.clone(), NearToken::from_near(1));
        testing_env!(context.build());

        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/project".to_string(),
                branch: None,
            },
            "default".to_string(),
            "base64encodeddata".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        // Delete secrets
        contract.delete_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/project".to_string(),
                branch: None,
            },
            "default".to_string(),
        );

        // Verify secrets don't exist
        assert!(!contract.secrets_exist(
            SecretAccessor::Repo {
                repo: "github.com/alice/project".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        ));
    }

    #[test]
    fn test_delete_secrets_wasm_hash() {
        let owner = accounts(0);
        let user = accounts(2);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner.clone(), None, None, None);

        // Store secrets by wasm hash
        let context = get_context(user.clone(), NearToken::from_near(1));
        testing_env!(context.build());

        let wasm_hash = "b".repeat(64);
        contract.store_secrets(
            SecretAccessor::WasmHash {
                hash: wasm_hash.clone(),
            },
            "default".to_string(),
            "base64encodeddata".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        // Delete secrets
        contract.delete_secrets(
            SecretAccessor::WasmHash {
                hash: wasm_hash.clone(),
            },
            "default".to_string(),
        );

        // Verify secrets don't exist
        assert!(!contract.secrets_exist(
            SecretAccessor::WasmHash {
                hash: wasm_hash,
            },
            "default".to_string(),
            user.clone(),
        ));
    }

    // ===== Per-customer vault binding =====

    #[test]
    fn store_secrets_with_vault_id_records_binding() {
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        let vault: AccountId = "vault.alice.near".parse().unwrap();
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            "ciphertext".to_string(),
            types::AccessCondition::AllowAll,
            Some(vault.clone()),
        );

        let bound = contract.get_secret_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        );
        assert_eq!(bound, Some(vault));
    }

    #[test]
    fn store_secrets_without_vault_id_records_no_binding() {
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            "ciphertext".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        let bound = contract.get_secret_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        );
        assert!(bound.is_none(), "no binding expected for default-master secret");
    }

    #[test]
    fn update_with_vault_id_none_keeps_binding_overhead_funded() {
        // Round-2 audit B-NEW-1 regression. Customer initially binds
        // to a vault, then updates the ciphertext with `vault_id: None`
        // (B-3 says the binding survives). The contract MUST quote
        // storage cost for the *post-call* state — i.e. with the
        // binding still on chain — otherwise the binding side-table
        // entry stays funded by nothing.
        //
        // The invariant we check: after the update, the deposit
        // recorded on the secret matches what `estimate_storage_cost`
        // says the cost is RIGHT NOW (binding present). If the bug
        // were back, the actual deposit (post-update) would be
        // smaller than the estimate — i.e. the contract under-funded
        // itself by the binding overhead.
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        let vault: AccountId = "vault.alice.near".parse().unwrap();
        let accessor = SecretAccessor::Repo {
            repo: "github.com/alice/p".to_string(),
            branch: None,
        };
        let ciphertext = "ciphertext".to_string();

        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        contract.store_secrets(
            accessor.clone(),
            "default".to_string(),
            ciphertext.clone(),
            types::AccessCondition::AllowAll,
            Some(vault.clone()),
        );
        // Sanity: binding really is in the side-table after the first
        // store. Pre-condition for the post-call check at
        // `internal_store_secrets` to see `vault_bound_after_call =
        // true` on the update.
        assert_eq!(
            contract.get_secret_vault(accessor.clone(), "default".to_string(), user.clone()),
            Some(vault.clone())
        );

        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        contract.store_secrets(
            accessor.clone(),
            "default".to_string(),
            ciphertext.clone(),
            types::AccessCondition::AllowAll,
            None,
        );

        // The deposit AFTER the no-op-on-binding update must match
        // what an estimate-with-vault-still-present would quote. If
        // the bug regressed, the actual post-update deposit would be
        // smaller than this estimate by the binding overhead.
        let post_update_deposit = contract
            .get_secrets(accessor.clone(), "default".to_string(), user.clone())
            .unwrap()
            .storage_deposit
            .0;
        let estimate_with_binding = contract
            .estimate_storage_cost(
                accessor,
                "default".to_string(),
                user,
                ciphertext,
                types::AccessCondition::AllowAll,
                None, // vault_id arg = None — binding-existence comes from side-table check
            )
            .0;
        assert_eq!(
            post_update_deposit, estimate_with_binding,
            "storage_deposit must match the post-call estimate (which sees the existing binding); \
             stored={post_update_deposit}, estimated={estimate_with_binding}"
        );
    }

    #[test]
    fn restore_with_vault_id_none_preserves_existing_binding() {
        // Plan back-compat invariant: an update that re-stores the
        // ciphertext but passes `vault_id: None` must NOT silently
        // clear an existing binding. Otherwise a forgetful caller
        // (legacy dashboard, half-migrated CLI) would brick decryption
        // by walking the binding back to default-master while the
        // ciphertext still requires the vault master.
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        let vault: AccountId = "vault.alice.near".parse().unwrap();
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            "ciphertext".to_string(),
            types::AccessCondition::AllowAll,
            Some(vault.clone()),
        );

        // Update with vault_id = None — binding must persist.
        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            "ciphertext_v2".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        let bound = contract.get_secret_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        );
        assert_eq!(
            bound,
            Some(vault),
            "existing vault binding must survive a vault_id=None update"
        );
    }

    #[test]
    fn unbind_secret_vault_clears_existing_binding() {
        // Explicit opt-out path: customer wants to re-encrypt under
        // the default master and drop the vault binding.
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        let vault: AccountId = "vault.alice.near".parse().unwrap();
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            "ciphertext".to_string(),
            types::AccessCondition::AllowAll,
            Some(vault.clone()),
        );

        testing_env!(get_context(user.clone(), NearToken::from_near(0)).build());
        contract.unbind_secret_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
        );

        let bound = contract.get_secret_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        );
        assert!(bound.is_none(), "unbind_secret_vault must clear the binding");
    }

    #[test]
    #[should_panic(expected = "secret not found or not owned by caller")]
    fn unbind_secret_vault_panics_on_missing_secret() {
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        testing_env!(get_context(user.clone(), NearToken::from_near(0)).build());
        contract.unbind_secret_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
        );
    }

    #[test]
    fn delete_secrets_cleans_up_binding() {
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        let vault: AccountId = "vault.alice.near".parse().unwrap();
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            "ciphertext".to_string(),
            types::AccessCondition::AllowAll,
            Some(vault),
        );

        contract.delete_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
        );

        let bound = contract.get_secret_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        );
        assert!(bound.is_none(), "delete must remove the binding");
    }

    #[test]
    fn get_secret_with_vault_combined_returns_both_fields() {
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        let vault: AccountId = "vault.alice.near".parse().unwrap();
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            "ciphertext".to_string(),
            types::AccessCondition::AllowAll,
            Some(vault.clone()),
        );

        let combined = contract.get_secret_with_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        );
        assert!(combined.profile.is_some());
        assert_eq!(combined.vault_id, Some(vault));
    }

    #[test]
    fn pre_migration_secret_returns_no_vault_via_combined_view() {
        // Back-compat invariant. Secrets stored without a vault
        // binding have no entry in `secret_vault_bindings`. The
        // combined view must report `vault_id = None` for them so
        // the keystore-worker falls through to the default OutLayer
        // master.
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let mut contract = Contract::new(owner.clone(), None, None, None);

        // Simulate "stored before migration" by calling store_secrets
        // with vault_id = None (post-migration the side-table entry is
        // simply absent for this key, which is exactly the
        // pre-migration state).
        testing_env!(get_context(user.clone(), NearToken::from_near(1)).build());
        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/legacy/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            "ciphertext".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        let combined = contract.get_secret_with_vault(
            SecretAccessor::Repo {
                repo: "github.com/legacy/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        );
        assert!(combined.profile.is_some(), "secret must exist");
        assert!(
            combined.vault_id.is_none(),
            "pre-migration / unbound secret must report vault_id = None"
        );
    }

    #[test]
    fn get_secret_with_vault_returns_no_profile_for_missing_secret() {
        let owner = accounts(0);
        let user = accounts(2);

        testing_env!(get_context(owner.clone(), NearToken::from_near(0)).build());
        let contract = Contract::new(owner.clone(), None, None, None);

        let combined = contract.get_secret_with_vault(
            SecretAccessor::Repo {
                repo: "github.com/alice/p".to_string(),
                branch: None,
            },
            "default".to_string(),
            user.clone(),
        );
        assert!(combined.profile.is_none());
        assert!(combined.vault_id.is_none());
    }

    #[test]
    fn test_list_user_secrets() {
        let owner = accounts(0);
        let user = accounts(2);

        let context = get_context(owner.clone(), NearToken::from_near(0));
        testing_env!(context.build());

        let mut contract = Contract::new(owner.clone(), None, None, None);

        // Store both repo and wasm_hash secrets
        let context = get_context(user.clone(), NearToken::from_near(1));
        testing_env!(context.build());

        contract.store_secrets(
            SecretAccessor::Repo {
                repo: "github.com/alice/project".to_string(),
                branch: Some("main".to_string()),
            },
            "default".to_string(),
            "base64encodeddata".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        let wasm_hash = "c".repeat(64);
        contract.store_secrets(
            SecretAccessor::WasmHash {
                hash: wasm_hash.clone(),
            },
            "production".to_string(),
            "base64encodeddata2".to_string(),
            types::AccessCondition::AllowAll,
            None,
        );

        // List user secrets — no page named, so the default page.
        let secrets = contract.list_user_secrets(user.clone(), None, None);
        assert_eq!(secrets.len(), 2);

        // Verify we have both types
        let has_repo = secrets.iter().any(|s| matches!(&s.accessor, SecretAccessor::Repo { .. }));
        let has_wasm = secrets.iter().any(|s| matches!(&s.accessor, SecretAccessor::WasmHash { .. }));
        assert!(has_repo);
        assert!(has_wasm);
    }
}


// Internals. Deliberately OUTSIDE `#[near_bindgen]`: the macro exports a
// contract method for every `pub fn` in a block it annotates, so a helper that
// lives there is one visibility keyword away from becoming a public entry
// point. `store_secrets_internal` takes the OWNER as an argument — exposed, it
// would let anyone store a secret owned by anyone.
impl Contract {
    /// The body of `store_secrets`, with the OWNER and the PAYER separated.
    ///
    /// They are the same account on the ordinary path and different on
    /// [`Contract::store_agent_secret`], where a wallet's signature says who owns
    /// the secret while somebody else stakes the storage. Everything else — the
    /// accessor validation, the payment-key write-once rule, the deposit
    /// arithmetic, the vault side-table, the owner's index — is identical, and
    /// duplicating it is how two entry points drift apart on the rule that
    /// matters.
    pub(crate) fn store_secrets_internal(
        &mut self,
        owner: AccountId,
        payer: AccountId,
        accessor: SecretAccessor,
        profile: String,
        encrypted_secrets_base64: String,
        access: types::AccessCondition,
        vault_id: Option<AccountId>,
    ) {
        // ONE spelling, decided before anything is validated or stored. Both
        // entry points reach this function, so a secret cannot be written under
        // a spelling the readers will not ask for.
        let accessor = canonical_accessor(accessor);
        let profile = canonical_profile(&accessor, profile);

        assert_account_pattern_bounds(&access);

        // Validate accessor
        match &accessor {
            SecretAccessor::Repo { repo, branch } => {
                assert!(!repo.is_empty(), "Repository cannot be empty");
                if let Some(ref b) = branch {
                    assert!(!b.is_empty(), "Branch name cannot be empty if provided");
                    assert!(b.len() <= 255, "Branch name too long (max 255 chars)");
                }
            }
            SecretAccessor::WasmHash { hash } => {
                assert!(!hash.is_empty(), "WASM hash cannot be empty");
                assert!(hash.len() == 64, "WASM hash must be 64 hex characters (SHA256)");
                assert!(
                    hash.chars().all(|c| c.is_ascii_hexdigit()),
                    "WASM hash must be hex encoded"
                );
            }
            SecretAccessor::Project { project_id } => {
                assert!(!project_id.is_empty(), "Project ID cannot be empty");
                assert!(project_id.contains('/'), "Project ID must be in format 'owner.near/name'");
                // Verify project exists
                assert!(
                    self.projects.get(project_id).is_some(),
                    "Project '{}' does not exist",
                    project_id
                );
            }
            SecretAccessor::System(secret_type) => {
                match secret_type {
                    SystemSecretType::PaymentKey => {
                        // The profile IS the nonce, so it has to be a number the
                        // rest of the system can hold.
                        //
                        // `get_next_payment_key_nonce` has always answered 1 for
                        // a fresh account, but it only SUGGESTS: nothing stopped
                        // a hand-built call from claiming any other value. Two
                        // are now refused outright, and both because something
                        // downstream reserves them.
                        let nonce: u32 = profile.parse().unwrap_or_else(|_| {
                            env::panic_str(
                                "A payment key's profile is its nonce and must be a number",
                            )
                        });
                        // Zero is reserved for keys the coordinator issues in its
                        // own database — the free trial — which have no on-chain
                        // record and cost no gas. They live at `(owner, 0)`, and
                        // `payment_keys` is keyed by exactly that pair, so an
                        // on-chain key here would land in the same row: one order
                        // silently drops the real key's hash, the other marks a
                        // funded key as a grant and stops its owner withdrawing
                        // their own money.
                        assert!(
                            nonce >= 1,
                            "Payment key nonce 0 is reserved. The first nonce is 1 — \
                             ask the contract with get_next_payment_key_nonce."
                        );
                        // The coordinator stores a nonce as a 32-bit SIGNED
                        // integer, so anything from 2^31 up arrives there as a
                        // negative number. Nothing collides today, but a nonce
                        // that means one thing on chain and another in the
                        // database is a bug waiting for whoever reads both.
                        assert!(
                            nonce <= i32::MAX as u32,
                            "Payment key nonce is too large (maximum 2147483647)"
                        );
                    }
                }
            }
        }

        // Validate common inputs
        if let Some(why) = profile_shape_error(&profile) {
            env::panic_str(&format!("profile must be {PROFILE_RULE} ({why})"));
        }
        assert!(
            !encrypted_secrets_base64.is_empty(),
            "Encrypted secrets cannot be empty"
        );

        // A profile shaped like an implicit account belongs to the AGENT of
        // that name, and to nobody else.
        //
        // The keystore decides whether a secret is an agent's by the SHAPE of
        // its profile — 64 lowercase hex — and then serves it only when the
        // reader, the owner and the name are all the same account. That rule is
        // what stops a stranger planting a credential under an agent's name.
        //
        // The cost of it, until now, was on the honest side: an ordinary secret
        // whose profile happened to look like that — a content hash, a session
        // id — stored cleanly and could then never be read, with an error about
        // agents that had nothing to do with what its owner did. Refusing the
        // name on the way IN turns a secret that silently never works into a
        // message at the moment the name is chosen.
        //
        // An agent's own secret passes: its owner IS that implicit account, so
        // the name and the owner agree.
        assert!(
            !is_implicit_account_name(&profile) || profile == owner.as_str(),
            "A profile of 64 hex characters names an AGENT, and only that agent's own \
             secrets may use it. This secret is owned by '{}' — give it a different \
             profile name.",
            owner
        );

        // Create secret key
        let key = SecretKey {
            accessor: accessor.clone(),
            profile: profile.clone(),
            owner: owner.clone(),
        };

        // Calculate storage cost. The size MUST reflect the
        // post-call state of the side-table, not the delta — otherwise
        // an update from `Some(v) → None` (binding survives per the
        // B-3 invariant) would re-quote the size as if the binding
        // were gone, refund the binding overhead to the caller, and
        // leave the entry sitting on chain unfunded. Same trap on
        // `Some(v1) → Some(v2)` rebinds.
        let vault_bound_after_call =
            vault_id.is_some() || self.secret_vault_bindings.get(&key).is_some();
        let storage_usage = self.calculate_secret_storage_size(
            &key,
            &encrypted_secrets_base64,
            &access,
            vault_bound_after_call,
        );
        let required_deposit = storage_usage as u128 * STORAGE_PRICE_PER_BYTE;
        let attached_deposit = env::attached_deposit().as_yoctonear();

        // Check if updating existing secrets
        let is_new = self.secrets_storage.get(&key).is_none();

        // A payment key is written ONCE. Ordinary secrets keep overwrite
        // semantics — rotating a credential in place is what they are for —
        // but a payment key's blob is a money record, and rewriting it is
        // never a legitimate act by its owner:
        //
        //   * the balance inside it is maintained by the worker through
        //     yield/resume on a real transfer. An owner-supplied rewrite can
        //     only disagree with it, and the disagreement is silent because
        //     nothing on chain can read the ciphertext to notice;
        //   * `store_secrets` cannot check what is inside — it takes opaque
        //     bytes — so "the owner may rewrite it" means "the owner may put
        //     anything in it", which is exactly how a blob field turned into a
        //     way of granting oneself credits.
        //
        // Deleting the key and creating it again remains available and is the
        // honest way to start over: it goes through `delete_payment_key`,
        // which the coordinator sees.
        if !is_new {
            if let SecretAccessor::System(SystemSecretType::PaymentKey) = &accessor {
                env::panic_str(
                    "Payment key already exists for this nonce. \
                     A payment key cannot be rewritten — delete it first, or use a new nonce.",
                );
            }
        }

        if let Some(existing) = self.secrets_storage.get(&key) {
            // Updating existing: combine attached + old deposit, require only new cost
            let total_available = attached_deposit + existing.storage_deposit;

            assert!(
                total_available >= required_deposit,
                "Insufficient deposit for update. Required: {} yoctoNEAR, available (attached {} + old {}): {} yoctoNEAR",
                required_deposit,
                attached_deposit,
                existing.storage_deposit,
                total_available
            );

            // Refund excess
            let refund = total_available - required_deposit;
            if refund > 0 {
                near_sdk::Promise::new(payer.clone()).transfer(NearToken::from_yoctonear(refund));
                log!(
                    "Updating secrets: accessor={:?}, profile={}, old_deposit={}, attached={}, new_required={}, refund={}",
                    accessor, profile,
                    existing.storage_deposit,
                    attached_deposit,
                    required_deposit,
                    refund
                );
            }
        } else {
            // Check attached deposit
            assert!(
                attached_deposit >= required_deposit,
                "Insufficient storage deposit. Required: {} yoctoNEAR, attached: {} yoctoNEAR",
                required_deposit,
                attached_deposit
            );

            // Refund excess if any
            if attached_deposit > required_deposit {
                let refund = attached_deposit - required_deposit;
                near_sdk::Promise::new(payer.clone()).transfer(NearToken::from_yoctonear(refund));
            }
        }

        // Store secret profile
        let profile_data = SecretProfile {
            encrypted_secrets: encrypted_secrets_base64,
            access,
            created_at: env::block_timestamp(),
            updated_at: env::block_timestamp(),
            storage_deposit: required_deposit,
        };

        self.secrets_storage.insert(&key, &profile_data);

        // Side-table for the optional vault binding.
        //
        // Semantics:
        //   * `Some(v)` → set/overwrite the binding to vault `v`.
        //   * `None`    → DO NOT TOUCH the side-table. An existing
        //     binding survives the update; that is the back-compat
        //     contract for legacy callers that never pass `vault_id`.
        //     If a customer wants to opt out of an existing binding
        //     they must call `unbind_secret_vault(...)` explicitly,
        //     usually paired with re-encrypting the ciphertext under
        //     the default master.
        if let Some(v) = vault_id {
            self.secret_vault_bindings.insert(&key, &v);
        }

        // Add to user index if new
        if is_new {
            let mut user_secrets = self
                .user_secrets_index
                .get(&owner)
                .unwrap_or_else(|| UnorderedSet::new(StorageKey::UserSecretsList { account_id: owner.clone() }));

            user_secrets.insert(&key);
            self.user_secrets_index.insert(&owner, &user_secrets);
        }

        log!(
            "Secrets stored: accessor={:?}, profile={}, owner={}, deposit={} yoctoNEAR",
            accessor,
            profile,
            owner,
            required_deposit
        );

        // Emit TopUp event with amount=0 for PaymentKey creation
        // Worker will create payment_keys record with initial_balance=0
        // Key cannot be used until real TopUp or admin grant
        if let SecretAccessor::System(SystemSecretType::PaymentKey) = &accessor {
            let nonce: u32 = profile.parse()
                .expect("PaymentKey profile must be a valid u32 nonce");
            self.emit_system_event(SystemEvent::TopUpPaymentKey {
                data_id: [0u8; 32], // No yield promise - dummy data_id
                owner: owner.clone(),
                nonce,
                amount: U128(0),
                encrypted_data: profile_data.encrypted_secrets.clone(),
            });
            log!(
                "PaymentKey created event emitted: owner={}, nonce={}",
                owner,
                nonce
            );
        }
    }

    /// Internal method to delete secrets by key
    /// pub(crate) to allow access from payment.rs for delete_payment_key
    /// Remove a secret, clean the OWNER's index, and refund the deposit to
    /// whoever is owed it.
    ///
    /// Two accounts, because they are two questions and only coincide on the
    /// ordinary path. The index is keyed by owner, so cleaning it under anyone
    /// else leaves a dangling entry pointing at a secret that is gone. The
    /// refund follows the money instead: on an agent secret the deposit was
    /// paid by a human who is not the owner, and returning it to the agent —
    /// an account with no keys outside the TEE — would strand it forever.
    pub(crate) fn delete_secrets_internal(
        &mut self,
        key: SecretKey,
        owner: &AccountId,
        refund_to: &AccountId,
    ) {
        let profile_data = self.secrets_storage.get(&key)
            .expect("Secrets not found");

        // Remove from storage
        self.secrets_storage.remove(&key);

        // Drop the vault binding alongside the secret. Idempotent
        // — `remove()` on a missing key is a no-op.
        self.secret_vault_bindings.remove(&key);

        // Remove from user index
        if let Some(mut user_secrets) = self.user_secrets_index.get(owner) {
            user_secrets.remove(&key);
            if user_secrets.is_empty() {
                // Remove empty set
                self.user_secrets_index.remove(owner);
            } else {
                self.user_secrets_index.insert(owner, &user_secrets);
            }
        }

        // Refund storage deposit
        if profile_data.storage_deposit > 0 {
            near_sdk::Promise::new(refund_to.clone())
                .transfer(NearToken::from_yoctonear(profile_data.storage_deposit));
            log!("Refunded {} yoctoNEAR", profile_data.storage_deposit);
        }
    }

    /// Calculate storage size for secrets (in bytes).
    ///
    /// `vault_bound` toggles the side-table contribution: when true,
    /// the cost of a `secret_vault_bindings` entry (a duplicate of the
    /// SecretKey plus an AccountId value) is added to the result.
    pub(crate) fn calculate_secret_storage_size(
        &self,
        key: &SecretKey,
        encrypted_secrets: &str,
        access: &types::AccessCondition,
        vault_bound: bool,
    ) -> u64 {
        // Storage calculation:
        // - SecretKey: key_type (enum) + profile + owner (Borsh serialized)
        // - SecretProfile: encrypted_secrets + access + timestamps + deposit (Borsh serialized)
        // - User index entry: UnorderedSet overhead (for new entries)
        // - Base overhead: LookupMap entry overhead

        const BASE_STORAGE_OVERHEAD: u64 = 40; // LookupMap entry overhead (key hash + pointer)
        const INDEX_ENTRY_OVERHEAD: u64 = 64; // UnorderedSet entry overhead

        // Accessor size (Borsh serialization adds enum discriminant + data)
        let accessor_size = match &key.accessor {
            SecretAccessor::Repo { repo, branch } => {
                1 + // enum discriminant
                4 + repo.len() + // String with u32 length prefix
                1 + branch.as_ref().map(|b| 4 + b.len()).unwrap_or(0) // Option<String>
            }
            SecretAccessor::WasmHash { hash } => {
                1 + // enum discriminant
                4 + hash.len() // String with u32 length prefix
            }
            SecretAccessor::Project { project_id } => {
                1 + // enum discriminant
                4 + project_id.len() // String with u32 length prefix
            }
            SecretAccessor::System(_secret_type) => {
                1 + // enum discriminant for System
                1   // enum discriminant for SystemSecretType (PaymentKey = 0)
            }
        };

        // Key size
        let key_size = (accessor_size
            + 4 + key.profile.len() // String with u32 length prefix
            + 4 + key.owner.as_str().len()) as u64; // AccountId (String with u32 length prefix)

        // Value size
        let encrypted_size = (4 + encrypted_secrets.len()) as u64; // String with u32 length prefix

        // AccessCondition size (serialize to estimate actual size)
        let access_json = serde_json::to_string(access).unwrap_or_default();
        let access_size = (access_json.len() + 10) as u64; // JSON + Borsh overhead

        let timestamps_and_deposit_size = 8 + 8 + 16; // created_at + updated_at + storage_deposit

        let value_size = encrypted_size + access_size + timestamps_and_deposit_size;

        // The owner's index entry, counted always.
        //
        // This function quotes the TOTAL a row occupies, not the delta from
        // whatever is there now: `store_secrets` and `update_access` both
        // compare the answer against the deposit already held and settle the
        // difference. An index entry that exists before the call still exists
        // after it, so leaving it out on the update paths would refund its 64
        // bytes to the owner while the entry stays on chain — storage funded
        // by nobody, which is the very thing the deposit exists to prevent.
        let index_overhead = INDEX_ENTRY_OVERHEAD;

        // Side-table entry for the optional vault binding. The
        // `secret_vault_bindings: LookupMap<SecretKey, AccountId>` map
        // re-stores the full SecretKey as its key plus an AccountId
        // value, so the contribution mirrors `key_size` plus a small
        // AccountId payload. Plus its own LookupMap entry overhead.
        let binding_overhead = if vault_bound {
            BASE_STORAGE_OVERHEAD + key_size + 4 + 64 // AccountId max ~64 bytes (String length-prefixed)
        } else {
            0
        };

        BASE_STORAGE_OVERHEAD + key_size + value_size + index_overhead + binding_overhead
    }
}

/// Bounds on a condition's `AccountPattern` leaves: how many, and how many
/// bytes of pattern text in all. The keystore compiles every pattern of a
/// condition before judging a decrypt and refuses a condition past these
/// same numbers (`shared_tee_helpers::access_limits`), so a row it would
/// refuse to judge is not stored. Nothing else bounds them: a condition is
/// priced by the byte, and a pattern's compiled size is not its text size.
pub(crate) const MAX_ACCOUNT_PATTERNS: usize = 16;
pub(crate) const MAX_ACCOUNT_PATTERN_BYTES: usize = 4096;

fn account_pattern_count(access: &types::AccessCondition) -> (usize, usize) {
    match access {
        types::AccessCondition::AccountPattern { pattern } => (1, pattern.len()),
        types::AccessCondition::Logic { conditions, .. } => conditions
            .iter()
            .map(account_pattern_count)
            .fold((0, 0), |(l, b), (l2, b2)| (l + l2, b + b2)),
        types::AccessCondition::Not { condition } => account_pattern_count(condition),
        _ => (0, 0),
    }
}

fn assert_account_pattern_bounds(access: &types::AccessCondition) {
    let (leaves, bytes) = account_pattern_count(access);
    if leaves > MAX_ACCOUNT_PATTERNS {
        env::panic_str(&format!(
            "the condition holds {leaves} AccountPattern leaves; at most {MAX_ACCOUNT_PATTERNS} are judged"
        ));
    }
    if bytes > MAX_ACCOUNT_PATTERN_BYTES {
        env::panic_str(&format!(
            "the condition's AccountPattern text is {bytes} bytes in all; at most {MAX_ACCOUNT_PATTERN_BYTES} are judged"
        ));
    }
}

/// The shape of a profile name, as every refusal words it.
pub(crate) const PROFILE_RULE: &str = "1–64 bytes of letters, digits, '-' or '_'";
pub(crate) const PROFILE_MAX_BYTES: usize = 64;

/// Why a profile name cannot be stored — and therefore why a `secrets_ref`
/// carrying it can name nothing: `None` when it is well formed, otherwise the
/// half of the rule it fails, worded for the refusal. One rule for both doors:
/// `store_secrets` refuses the row and `request_execution` refuses a reference
/// the contract could never match, with the same words. Bytes, not characters:
/// storage is priced by the byte and the row is keyed by the bytes. The
/// worker and the coordinator mirror the byte-length and ASCII halves of this
/// rule (`shared_tee_helpers::secrets_ref`), with the same sentence; a
/// non-ASCII character is judged only here, by this crate's own Unicode table.
pub(crate) fn profile_shape_error(profile: &str) -> Option<String> {
    let n = profile.len();
    if !(1..=PROFILE_MAX_BYTES).contains(&n) {
        return Some(format!("got {n} bytes"));
    }
    profile
        .chars()
        .find(|c| !(c.is_alphanumeric() || *c == '-' || *c == '_'))
        .map(|c| format!("it contains {c:?}"))
}

