//! Keystore Worker - TEE-based secret management for NEAR OutLayer
//!
//! This worker runs in a Trusted Execution Environment (TEE) and provides
//! secure decryption of user secrets for executor workers.
//!
//! Architecture:
//! 1. Keystore worker has a master_secret that NEVER leaves TEE
//! 2. Per-repo keypairs are derived using HMAC-SHA256(master_secret, seed)
//! 3. Seed format: "github.com/owner/repo:account_id[:branch]"
//! 4. Users encrypt secrets with repo-specific public key from coordinator
//! 5. Executor workers request decryption with TEE attestation proof
//! 6. Keystore verifies attestation and decrypts secrets
//! 7. Secrets are returned only to verified TEE workers
//!
//! Security guarantees:
//! - Master secret NEVER leaves TEE memory
//! - Each repo/branch/owner gets a unique keypair
//! - Only verified workers (via attestation) can decrypt
//! - All operations are async and non-blocking
//! - Token-based authentication for API access

mod api;
mod config;
mod crypto;
mod eip712;
mod ephemeral_keys;
mod near;
mod solana;
mod secret_generation;
mod types;
mod utils;
mod mpc_ckd;
mod tee_registration;
mod tdx_attestation;
mod vault_verifier;
mod signing_keys;
mod encryption_keys;

use anyhow::{Context, Result};
use config::{Config, TeeMode};
use crypto::Keystore;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,keystore_worker=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting NEAR OutLayer Keystore Worker");

    // Load configuration
    let config = Config::from_env().context("Failed to load configuration")?;
    config.validate().context("Invalid configuration")?;

    tracing::info!(
        server_addr = %config.server_addr,
        tee_mode = ?config.tee_mode,
        contract = %config.offchainvm_contract_id,
        "Configuration loaded"
    );

    // Try to get Phala app info (for TEE verification URL)
    if config.tee_mode == TeeMode::OutlayerTee {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tdx_attestation::get_phala_app_info()
        ).await {
            Ok(Some(info)) => {
                tracing::info!("🔐 Phala TEE verification: https://trust.phala.com/app/{}", info.app_id);
            }
            Ok(None) => {
                tracing::warn!("⚠️ Could not get Phala app info");
            }
            Err(_) => {
                tracing::warn!("⚠️ Timeout getting Phala app info");
            }
        }
    }

    // Initialize NEAR RPC client for reading secrets from contract
    // Only NEAR_RPC_URL and NEAR_CONTRACT_ID are required (read-only)
    let near_client = if let (Ok(rpc_url), Ok(contract_id)) = (
        std::env::var("NEAR_RPC_URL"),
        std::env::var("NEAR_CONTRACT_ID"),
    ) {
        tracing::info!("Initializing NEAR RPC client (read-only)");

        match near::NearClient::new(&rpc_url, &contract_id) {
            Ok(client) => {
                tracing::info!("✅ NEAR RPC client initialized");
                Some(client)
            }
            Err(e) => {
                tracing::warn!("❌ Failed to initialize NEAR client: {}", e);
                tracing::warn!("   Secrets reading from contract will not work");
                None
            }
        }
    } else {
        tracing::warn!("NEAR_RPC_URL or NEAR_CONTRACT_ID not set");
        tracing::warn!("Secrets reading from contract will be disabled");
        tracing::warn!("Required env vars: NEAR_RPC_URL, NEAR_CONTRACT_ID");
        None
    };

    // Check if we're in TEE registration mode
    let use_tee_registration = std::env::var("USE_TEE_REGISTRATION")
        .unwrap_or_else(|_| "false".to_string())
        .parse::<bool>()
        .unwrap_or(false);

    // Inside a TEE the master can only come from MPC CKD after the DAO vote; every env knob of the
    // non-TEE path (a provided master, the master dump file) is refused before anything else runs.
    validate_master_source(&MasterSourceEnv {
        tee_mode_is_outlayer: config.tee_mode == TeeMode::OutlayerTee,
        use_tee_registration,
        has_master_secret: std::env::var_os("KEYSTORE_MASTER_SECRET").is_some(),
        has_dump_path: std::env::var_os(MASTER_DUMP_PATH_VAR).is_some(),
    })
    .map_err(|e| {
        tracing::error!("❌ Configuration error: {e}");
        e
    })?;

    // Initialize keystore (temporary if TEE mode)
    let initial_keystore = if use_tee_registration {
        tracing::info!("🔐 TEE registration mode - starting with temporary keystore");
        tracing::info!("   API will be blocked until DAO approval and MPC key obtained");
        crypto::Keystore::generate() // Temporary keystore
    } else {
        // Initialize normal keystore for non-TEE mode
        let keystore = initialize_keystore(&config).await?;
        tracing::info!("Keystore initialized with master secret derivation");
        tracing::info!("Each repo will have a unique keypair derived from master_secret + seed");
        keystore
    };

    // Create API server
    let app_state = api::AppState::new(initial_keystore, config.clone(), near_client);

    // The public listener is bound only once the instance can serve. The dstack gateway balances a
    // version's hostname across every instance of that app-id by first successful TCP connect, so
    // an instance that accepted connections while waiting for its DAO vote would draw traffic it
    // can only answer with 503. Registration therefore runs to completion here, in the foreground;
    // an instance that fails it stays alive without a listener (readable logs, no traffic, no
    // restart loop — a restart would mint a new registration key and a new proposal).
    if use_tee_registration {
        tracing::info!("🔐 Starting TEE registration process (public port stays closed until ready)");
        match perform_tee_registration(&config).await {
            Ok(result) => {
                // Order matters: install the real keystore FIRST, then publish the MPC context,
                // then flip is_ready. Anyone observing `mpc_ckd_config.get().is_some()` is thereby
                // guaranteed to also see the real default master — a per-vault master derived
                // against the temporary boot keystore would be unique to this boot and unrecoverable.
                app_state.replace_keystore(result.keystore).await;
                app_state.set_mpc_context(result.mpc_ckd_config, result.keystore_dao_signer);
                app_state.mark_ready();
                tracing::info!("✅ TEE registration complete! Keystore is now ready to serve requests");
            }
            Err(e) => {
                tracing::error!("❌ TEE registration failed: {}", e);
                if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
                    tracing::error!("🔍 DEBUG: Full error chain:");
                    let mut source = e.source();
                    let mut level = 1;
                    while let Some(err) = source {
                        tracing::error!("   Level {}: {}", level, err);
                        source = err.source();
                        level += 1;
                    }
                    tracing::error!("🔍 DEBUG: Error Debug format: {:?}", e);
                }
                tracing::error!(
                    addr = %config.server_addr,
                    "   Keystore stays not-ready and the public port is NOT opened; fix the issue and restart the service"
                );
                std::future::pending::<()>().await;
            }
        }
    }

    let router = api::create_router(app_state);

    // Start server
    let listener = tokio::net::TcpListener::bind(&config.server_addr)
        .await
        .context("Failed to bind server")?;

    tracing::info!(
        addr = %config.server_addr,
        "Keystore worker API server started"
    );
    tracing::info!("Ready to serve decryption requests from executor workers");

    // Run server (this blocks until shutdown)
    axum::serve(listener, router)
        .await
        .context("Server error")?;

    Ok(())
}

/// Outcome of a successful TEE registration: the freshly-derived
/// default-master keystore plus the MPC CKD context that the lazy
/// per-vault-master path needs at request time, plus the worker's
/// signer for the keystore-dao contract (used by `/sign-vault-verification`
/// to land `mark_vault_verified` tx).
struct TeeRegistrationResult {
    keystore: Keystore,
    /// MPC CKD config — carries `keystore_dao_id` and `mpc_contract_id`
    /// as parsed `AccountId`s. Phase 4 holistic audit I8: previously
    /// this struct also had a separate `keystore_dao_id` field,
    /// duplicating `mpc_ckd_config.keystore_dao_id`. Collapsed.
    mpc_ckd_config: mpc_ckd::MpcCkdConfig,
    keystore_dao_signer: near_crypto::InMemorySigner,
}

/// Perform TEE registration and get MPC-derived keystore
async fn perform_tee_registration(config: &Config) -> Result<TeeRegistrationResult> {
    tracing::info!("🔐 Starting TEE registration flow with retry logic");

    // Check required environment variables - NO FALLBACKS!
    let dao_contract = std::env::var("KEYSTORE_DAO_CONTRACT")
        .context("KEYSTORE_DAO_CONTRACT not set")?;
    let init_account_id = std::env::var("INIT_ACCOUNT_ID")
        .context("INIT_ACCOUNT_ID not set")?;
    let init_private_key = std::env::var("INIT_ACCOUNT_PRIVATE_KEY")
        .context("INIT_ACCOUNT_PRIVATE_KEY not set")?;
    let near_rpc_url = std::env::var("NEAR_RPC_URL")
        .context("NEAR_RPC_URL is required for TEE registration")?;

    // Create registration client
    let registration = tee_registration::RegistrationClient::new(
        near_rpc_url.clone(),
        dao_contract.parse()?,
        init_account_id.parse()?,
        init_private_key.parse()?,
        config.keystore_key_type,
    )?;

    // Load or generate keypair
    // In TEE mode, generate ephemeral keypair in memory only
    let is_tee_mode = config.tee_mode == TeeMode::OutlayerTee;
    let (public_key, secret_key) = registration.load_or_generate_keypair(is_tee_mode)?;
    tracing::info!("📂 Using keystore public key: {}", public_key);

    // Check if already approved
    let approved = match mpc_ckd::check_keystore_approval(
        &near_rpc_url,
        &dao_contract,
        &public_key.to_string(),
    ).await {
        Ok(approved) => approved,
        Err(e) => {
            let error_str = format!("{:?}", e);
            if error_str.contains("MethodNotFound") {
                tracing::warn!("⚠️ Method 'is_keystore_approved' not found on DAO contract");
                tracing::warn!("   This might be an older version of the contract");
                tracing::warn!("   Assuming keystore is NOT approved and proceeding with registration");
                false // Assume not approved if method doesn't exist
            } else {
                return Err(e);
            }
        }
    };

    if !approved {
        tracing::info!("📝 Keystore not yet approved, submitting registration to DAO");

        // Debug log the registration parameters if LOG_MASTER_KEY_HASH is set
        if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
            tracing::info!("🔍 DEBUG: Registration parameters:");
            tracing::info!("   DAO contract: {}", dao_contract);
            tracing::info!("   Init account: {}", init_account_id);
            tracing::info!("   Public key: {}", public_key);
            tracing::info!("   TEE mode: {:?}", config.tee_mode);
        }

        // Generate attestation using new TdxClient
        use crate::tdx_attestation::TdxClient;
        let tdx_client = TdxClient::new(config.tee_mode.to_string());

        // Compute the 32-byte report_data binding (raw pubkey for ed25519, SHA-256 of the
        // pubkey for ml-dsa-65). The DAO contract re-derives and checks this.
        let pubkey_bytes = tee_registration::report_data_binding(&public_key)?;

        let tdx_quote = tdx_client.generate_registration_quote(&pubkey_bytes).await?;
        tracing::info!("📡 Generated TEE attestation (mode: {:?})", config.tee_mode);
        tracing::info!("   Quote will be verified by DAO contract against approved RTMR3 list");

        // Do not pay to be told something a free view call answers.
        //
        // `submit_keystore_registration` verifies the DCAP quote and extracts the measurements
        // BEFORE it checks them against the approved list, so an unapproved set burns virtually
        // the whole verification — measured at 183.6 TGas / 0.0183 NEAR on a real rejection, and
        // repeated on every container restart until an operator approves. The measurements are
        // already in hand here (the quote was just generated and the line above logged them), so
        // ask the DAO first and submit only when the answer is yes.
        //
        // Nothing is lost by deciding locally: the keystore parses the same measurements the
        // contract does — verified against a live rejection where both values matched exactly —
        // and `scripts/deploy_tdx.sh` already reads them from this log rather than from the
        // contract's receipt.
        if let Some(measurements) =
            crate::tdx_attestation::extract_all_measurements_from_quote_hex(&tdx_quote)
        {
            let approved = mpc_ckd::check_measurements_approved(
                &near_rpc_url,
                &dao_contract,
                &measurements,
            )
            .await
            .unwrap_or_else(|e| {
                // An RPC failure must not become a silent refusal to register: fall through to
                // the submit and let the chain be the authority, exactly as before this check.
                tracing::warn!(error = %e, "Could not check measurements against the DAO; submitting anyway");
                true
            });

            if !approved {
                tracing::error!("⏸️  Registration NOT submitted — these measurements are not approved yet");
                tracing::error!("   No transaction was sent, so no gas was spent.");
                tracing::error!("");
                tracing::error!("📝 Approve them (owner key), then restart the keystore:");
                tracing::error!(
                    "   near contract call-function as-transaction {} add_approved_measurements \\",
                    dao_contract
                );
                tracing::error!(
                    "     json-args '{}' \\",
                    crate::tdx_attestation::measurements_approval_args(&measurements)
                );
                tracing::error!("     prepaid-gas '100.0 Tgas' attached-deposit '0 NEAR' sign-as <owner> ...");
                tracing::error!("");
                tracing::error!("   (scripts/deploy_tdx.sh does this automatically at step [4/6].)");
                anyhow::bail!(
                    "TEE measurements not approved on {} — approve them and restart",
                    dao_contract
                );
            }
            tracing::info!("✅ Measurements already approved by the DAO — submitting registration");
        } else {
            // Malformed/short quote: leave the decision to the contract rather than blocking a
            // registration on our own parsing.
            tracing::warn!("Could not extract measurements from the quote; submitting without the pre-check");
        }

        // Get Phala app_id for TEE verification (will be logged in blockchain tx)
        let app_id = crate::tdx_attestation::get_phala_app_info()
            .await
            .map(|info| info.app_id);

        // Submit to DAO (contract will verify the quote)
        let proposal_id = match registration.submit_registration(public_key.clone(), tdx_quote, app_id).await {
            Ok(id) => id,
            Err(e) => {
                let error_str = e.to_string();

                // Check if error is due to RTMR3 not being approved
                if error_str.contains("not approved") || error_str.contains("RTMR3") {
                    tracing::error!("❌ Registration rejected by DAO contract");
                    tracing::error!("   RTMR3 not in approved list");
                    tracing::error!("");
                    tracing::error!("📝 Solution:");
                    tracing::error!("   1. Check DAO contract logs for the extracted RTMR3");
                    tracing::error!("   2. Admin needs to add RTMR3 to approved list");
                    tracing::error!("   3. Restart keystore worker after RTMR3 is approved");
                    tracing::error!("");
                    tracing::error!("⏹️  Keystore stopped - fix the issue and restart");
                } else if std::env::var("LOG_MASTER_KEY_HASH").unwrap_or_default() == "true" {
                    tracing::error!("🔍 DEBUG: Failed to submit registration");
                    tracing::error!("   Error: {:?}", e);
                    tracing::error!("   Check that dao.outlayer.testnet has 'submit_keystore_registration' method");
                    tracing::error!("   You can verify with: near view dao.outlayer.testnet get_config");
                }
                return Err(e);
            }
        };
        tracing::info!("📤 Registration submitted! Proposal ID: {}", proposal_id);

        // Wait for approval
        tracing::info!("⏳ Waiting for DAO approval (this may take a while)...");
        tracing::info!("   DAO members need to vote on proposal #{}", proposal_id);
        registration.wait_for_approval(proposal_id, &public_key).await?;
    } else {
        tracing::info!("✅ Keystore already approved by DAO");
        // Defense against silent upgrade-path bugs: just because the
        // pubkey is in `approved_keystores` doesn't mean its access
        // key on the DAO contract has the method-list this build
        // expects. A widened DAO grant + an existing approved
        // keystore = stale access key that silently fails calls to
        // the new methods. Catch it loudly here so operators
        // regenerate the keypair (TEE mode: restart) or manually
        // upgrade the access key.
        mpc_ckd::check_access_key_methods(&near_rpc_url, &dao_contract, &public_key)
            .await?;
        tracing::info!("✅ Access key method-list covers all required methods");
    }

    // Now we're approved, get MPC-derived secret
    tracing::info!("🔑 Requesting master secret from MPC network via CKD");
    let (keystore, mpc_ckd_config, keystore_dao_signer) =
        mpc_ckd::initialize_mpc_keystore(dao_contract.clone(), secret_key).await?;

    tracing::info!("✅ Successfully obtained MPC-derived master secret");
    Ok(TeeRegistrationResult {
        keystore,
        mpc_ckd_config,
        keystore_dao_signer,
    })
}

/// Non-TEE development only: where `initialize_keystore` writes a freshly generated master so the
/// developer can carry it into `.env`. The name says so because the value is the raw master; inside
/// a TEE (`TEE_MODE=outlayer_tee` or `USE_TEE_REGISTRATION=true`) its presence aborts startup.
const MASTER_DUMP_PATH_VAR: &str = "KEYSTORE_MASTER_SECRET_OUT_PATH_NON_TEE";

/// The env facts that decide where the master may come from.
struct MasterSourceEnv {
    tee_mode_is_outlayer: bool,
    use_tee_registration: bool,
    has_master_secret: bool,
    has_dump_path: bool,
}

/// Refuse every configuration in which a TEE keystore could end up with a master that did not come
/// from MPC CKD, or could write one to disk. Pure so it can be tested without an environment.
fn validate_master_source(e: &MasterSourceEnv) -> Result<()> {
    let in_tee = e.tee_mode_is_outlayer || e.use_tee_registration;
    if e.tee_mode_is_outlayer && !e.use_tee_registration {
        anyhow::bail!(
            "TEE_MODE=outlayer_tee requires USE_TEE_REGISTRATION=true: inside a TEE the master is \
             derived from MPC CKD after the DAO vote; a locally generated or env-provided master is \
             never valid there"
        );
    }
    if in_tee && e.has_master_secret {
        anyhow::bail!(
            "KEYSTORE_MASTER_SECRET cannot be set in TEE mode (USE_TEE_REGISTRATION=true / \
             TEE_MODE=outlayer_tee): the master comes from MPC CKD after DAO approval; remove it \
             from the env"
        );
    }
    if in_tee && e.has_dump_path {
        anyhow::bail!(
            "{MASTER_DUMP_PATH_VAR} cannot be set in TEE mode: it exists only for non-TEE \
             development and writes the raw master secret to a file; remove it from the env"
        );
    }
    Ok(())
}

#[cfg(test)]
mod master_source_tests {
    use super::*;

    fn env(tee: bool, reg: bool, secret: bool, dump: bool) -> MasterSourceEnv {
        MasterSourceEnv {
            tee_mode_is_outlayer: tee,
            use_tee_registration: reg,
            has_master_secret: secret,
            has_dump_path: dump,
        }
    }

    #[test]
    fn production_tee_config_is_accepted() {
        assert!(validate_master_source(&env(true, true, false, false)).is_ok());
    }

    #[test]
    fn non_tee_dev_may_provide_or_dump_the_master() {
        assert!(validate_master_source(&env(false, false, true, false)).is_ok());
        assert!(validate_master_source(&env(false, false, false, true)).is_ok());
        assert!(validate_master_source(&env(false, false, false, false)).is_ok());
    }

    #[test]
    fn tee_mode_without_tee_registration_is_refused() {
        let err = validate_master_source(&env(true, false, false, false)).unwrap_err();
        assert!(err.to_string().contains("USE_TEE_REGISTRATION=true"));
    }

    #[test]
    fn master_secret_is_refused_in_either_tee_flag() {
        assert!(validate_master_source(&env(true, true, true, false)).is_err());
        assert!(validate_master_source(&env(false, true, true, false)).is_err());
    }

    #[test]
    fn dump_path_is_refused_in_either_tee_flag() {
        let err = validate_master_source(&env(true, true, false, true)).unwrap_err();
        assert!(err.to_string().contains(MASTER_DUMP_PATH_VAR));
        assert!(validate_master_source(&env(false, true, false, true)).is_err());
    }
}

/// Initialize keystore from environment or generate new one
///
/// For non-TEE mode only:
/// - Use KEYSTORE_MASTER_SECRET from environment (if set)
/// - Otherwise: Generate new master_secret and warn user to save it
async fn initialize_keystore(_config: &Config) -> Result<Keystore> {
    // Non-TEE mode: use environment variable or generate
    if let Ok(master_secret_hex) = std::env::var("KEYSTORE_MASTER_SECRET") {
        tracing::info!("Loading keystore from KEYSTORE_MASTER_SECRET");

        // Log master key hash if configured to do so
        if std::env::var("LOG_MASTER_KEY_HASH")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false)
        {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(master_secret_hex.as_bytes());
            let hash = hasher.finalize();
            tracing::info!("Master key hash (SHA256): {}", hex::encode(hash));
        }

        Keystore::from_master_secret_hex(&master_secret_hex)
            .context("Failed to load keystore from master secret")
    } else {
        // Generate new master secret
        tracing::warn!("KEYSTORE_MASTER_SECRET not found - generating new master secret");
        let keystore = Keystore::generate();

        // Get hex representation for the operator to capture.
        let master_hex = keystore.default_master_hex();

        // Log only a sha256 fingerprint via the structured logger —
        // anything written via `tracing::*` is liable to end up in
        // log shippers, SIEMs, Phala dashboards, and operator
        // terminals' scrollback. Raw master never goes there.
        let fp = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(master_hex.as_bytes());
            let d = h.finalize();
            hex::encode(&d[..4])
        };
        tracing::warn!(
            "Generated new keystore master (fingerprint sha256[..8]: {fp}). \
             Capture the secret out-of-band as instructed below — restarting \
             without saving it invalidates every encrypted secret already \
             stored against this keystore."
        );

        // Raw master goes either to a 0o600 file (preferred,
        // pickup-able by the operator's deploy automation) or, as a
        // last resort, to stderr — bypassing `tracing` entirely so
        // it doesn't reach structured-log destinations.
        if let Ok(out_path) = std::env::var(MASTER_DUMP_PATH_VAR) {
            use std::io::Write as _;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                opts.mode(0o600);
            }
            match opts.open(&out_path) {
                Ok(mut f) => {
                    let _ = writeln!(f, "KEYSTORE_MASTER_SECRET={master_hex}");
                    tracing::warn!(
                        "Wrote new master to {out_path} (mode 0600). Move it into your .env \
                         and `unset {MASTER_DUMP_PATH_VAR}` before next start."
                    );
                }
                Err(e) => {
                    // Fall back to stderr if the file can't be created
                    // — better than losing the secret silently.
                    eprintln!(
                        "WARN: {MASTER_DUMP_PATH_VAR}={out_path} could not be written ({e}); \
                         emitting master to stderr instead."
                    );
                    eprintln!("KEYSTORE_MASTER_SECRET={master_hex}");
                }
            }
        } else {
            // Stderr (not tracing!) — the operator running the binary
            // interactively sees this once; log shippers usually only
            // capture stdout (and tracing-subscriber writes to stdout
            // by default). Not perfect, but a meaningful step up from
            // burying the secret in a `warn!` event.
            eprintln!();
            eprintln!("=================================================================");
            eprintln!("IMPORTANT: capture this master secret now (printed once on stderr):");
            eprintln!("KEYSTORE_MASTER_SECRET={master_hex}");
            eprintln!();
            eprintln!("Add it to your .env to persist the keystore. Restarting without it");
            eprintln!("regenerates a new master and invalidates every encrypted secret.");
            eprintln!("Set {MASTER_DUMP_PATH_VAR}=<file> on next start to receive");
            eprintln!("the secret in a 0o600 file instead of stderr.");
            eprintln!("=================================================================");
            eprintln!();
        }

        Ok(keystore)
    }
}
