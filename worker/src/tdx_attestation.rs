//! TDX Attestation Generation
//!
//! This module handles Intel TDX quote generation for worker registration
//! and task attestations. It communicates with the dstack socket or
//! directly with TDX hardware.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Refuses a report_data binding that is an ed25519 key of small order: such a key has no secret,
/// and near-crypto's verifier accepts signatures for it made without one, so a quote binding it
/// would let anyone who obtains the quote register a key that anyone can sign for.
pub fn refuse_small_order_binding(binding: &[u8; 32]) -> Result<()> {
    let small = ed25519_dalek::VerifyingKey::from_bytes(binding)
        .map(|k| k.is_weak())
        .unwrap_or(false);
    anyhow::ensure!(
        !small,
        "Refusing to quote a report_data binding that is an ed25519 key of small order"
    );
    Ok(())
}

// TDX Quote v4 = Header (48 bytes) + TD10 Report Body (584 bytes) + Auth Data
// Absolute offsets for measurements within the raw quote bytes:
const MEASUREMENT_SIZE: usize = 48; // Each measurement is 48 bytes (96 hex chars)
const MRTD_OFFSET: usize = 184;     // 48 (header) + 136 (body offset for mr_td)
const RTMR0_OFFSET: usize = 376;    // 48 (header) + 328 (body offset for rt_mr0)
const RTMR1_OFFSET: usize = 424;    // 48 (header) + 376 (body offset for rt_mr1)
const RTMR2_OFFSET: usize = 472;    // 48 (header) + 424 (body offset for rt_mr2)
const RTMR3_OFFSET: usize = 520;    // 48 (header) + 472 (body offset for rt_mr3)

/// All TEE measurements extracted from a TDX quote
#[derive(Debug, Clone)]
pub struct TdxMeasurements {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
}

/// Information from dstack about the running app
#[derive(Debug, Clone)]
pub struct DstackAppInfo {
    pub app_id: String,
}

/// Get app info (app_id) from the dstack socket
///
/// Returns None if not running in a dstack TEE or if dstack is unavailable
pub async fn get_dstack_app_info() -> Option<DstackAppInfo> {
    use dstack_sdk::dstack_client::DstackClient;

    let client = DstackClient::new(None);
    match client.info().await {
        Ok(info) => {
            tracing::info!("📱 dstack app_id: {}", info.app_id);
            Some(DstackAppInfo {
                app_id: info.app_id,
            })
        }
        Err(e) => {
            tracing::debug!("Could not get dstack app info (not in TEE?): {}", e);
            None
        }
    }
}

/// TDX attestation client
pub struct TdxClient {
    tee_mode: String,
}

impl TdxClient {
    /// Create new TDX client
    pub fn new(tee_mode: String) -> Self {
        Self { tee_mode }
    }

    /// Generate TDX quote for worker registration with public key embedded
    ///
    /// This method embeds the worker's 32-byte report_data binding into the first
    /// 32 bytes of the TDX quote's report_data field. This allows the register
    /// contract to cryptographically verify that the public key was generated
    /// inside the TEE. The binding is the raw public key for ed25519, or SHA-256
    /// of the public key for ml-dsa-65 (which does not fit in 32 bytes).
    ///
    /// # Arguments
    /// * `public_key_bytes` - 32-byte report_data binding (see registration::report_data_binding)
    ///
    /// # Returns
    /// * Hex-encoded TDX quote (ready to pass to register_worker_key)
    pub async fn generate_registration_quote(&self, public_key_bytes: &[u8; 32]) -> Result<String> {
        refuse_small_order_binding(public_key_bytes)?;
        tracing::info!("🔐 Generating registration TDX quote with embedded public key");
        tracing::info!("   Public key (hex): {}", hex::encode(public_key_bytes));

        match self.tee_mode.as_str() {
            "outlayer_tee" => {
                // OutLayer TEE mode: Generate real TDX quote with custom report_data
                tracing::info!("Using TDX attestation (dstack socket)");

                // Create report_data: first 32 bytes = public key, rest = zeros
                let mut report_data = [0u8; 64];
                report_data[..32].copy_from_slice(public_key_bytes);

                // Call the dstack socket to generate TDX quote
                let tdx_quote = self.call_dstack_socket(&report_data)
                    .await
                    .context("Failed to generate TDX quote via dstack socket")?;

                tracing::info!("✅ Generated real TDX quote (size: {} bytes)", tdx_quote.len());

                // Return hex-encoded quote (register contract expects hex string)
                Ok(hex::encode(&tdx_quote))
            }
            "none" => {
                // No attestation mode: Create minimal fake quote
                tracing::warn!("⚠️  Using NO-ATTESTATION mode (dev only!)");

                let fake_quote = format!(
                    "NO_ATTESTATION:pubkey={}",
                    hex::encode(public_key_bytes)
                );

                tracing::info!("✅ Generated NO-ATTESTATION stub (hex-encoded, size: {} bytes)", hex::encode(fake_quote.as_bytes()).len());

                Ok(hex::encode(fake_quote.as_bytes()))
            }
            other => {
                anyhow::bail!(
                    "Unsupported TEE mode for registration: {}. Use 'outlayer_tee' or 'none'",
                    other
                );
            }
        }
    }

    /// Generate TDX quote for task attestation (V1 format)
    ///
    /// This is used to create attestations for compilation and execution tasks.
    /// The report_data contains a hash of all task parameters including caller identity.
    ///
    /// # Arguments
    /// * `task_type` - Type of task (compile, execute, startup)
    /// * `task_id` - Unique task identifier
    /// * `repo` - GitHub repository URL
    /// * `commit` - Git commit hash
    /// * `build_target` - WASM build target
    /// * `wasm_hash` - SHA256 hash of compiled WASM
    /// * `input_hash` - SHA256 hash of execution input
    /// * `output_hash` - SHA256 hash of execution output
    /// * `block_height` - NEAR block height
    /// * `caller_account_id` - Caller's account ID (NEAR account or payment key owner)
    /// * `project_id` - Project ID (e.g., "alice.near/my-app")
    /// * `secrets_ref` - Secrets reference in format "{account_id}/{profile}"
    /// * `timestamp` - Job creation timestamp (unix seconds)
    /// * `attached_usd` - Payment amount in minimal token units
    ///
    /// # Returns
    /// * Base64-encoded TDX quote
    ///
    /// # Report Data Layout (V1)
    /// - Bytes 0-31: SHA256(task_type || task_id || repo || commit || build_target ||
    ///                      wasm_hash || input_hash || output_hash || block_height ||
    ///                      caller_account_id || project_id || secrets_ref || timestamp || attached_usd)
    /// - Bytes 32-63: zeros (reserved)
    #[allow(clippy::too_many_arguments)]
    pub async fn generate_task_attestation(
        &self,
        task_type: &str,
        task_id: i64,
        repo: Option<&str>,
        commit: Option<&str>,
        build_target: Option<&str>,
        wasm_hash: Option<&str>,
        input_hash: Option<&str>,
        output_hash: &str,
        block_height: Option<u64>,
        caller_account_id: Option<&str>,
        project_id: Option<&str>,
        secrets_ref: Option<&str>,
        timestamp: i64,
        attached_usd: Option<&str>,
    ) -> Result<String> {
        // Build report_data from all task parameters (V1 format)
        let mut hasher = Sha256::new();

        // Original fields
        hasher.update(task_type.as_bytes());
        hasher.update(&task_id.to_le_bytes());
        if let Some(r) = repo {
            hasher.update(r.as_bytes());
        }
        if let Some(c) = commit {
            hasher.update(c.as_bytes());
        }
        if let Some(bt) = build_target {
            hasher.update(bt.as_bytes());
        }
        if let Some(wh) = wasm_hash {
            hasher.update(wh.as_bytes());
        }
        if let Some(ih) = input_hash {
            hasher.update(ih.as_bytes());
        }
        hasher.update(output_hash.as_bytes());
        if let Some(bh) = block_height {
            hasher.update(&bh.to_le_bytes());
        }

        // V1 fields: caller, project, secrets, timestamp, payment
        if let Some(caller) = caller_account_id {
            hasher.update(caller.as_bytes());
        }
        if let Some(pid) = project_id {
            hasher.update(pid.as_bytes());
        }
        if let Some(sref) = secrets_ref {
            hasher.update(sref.as_bytes());
        }
        hasher.update(&timestamp.to_le_bytes());
        if let Some(usd) = attached_usd {
            hasher.update(usd.as_bytes());
        }

        let task_hash = hasher.finalize();

        // Create report_data: [task_hash (32 bytes)][zeros (32 bytes)]
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&task_hash);

        match self.tee_mode.as_str() {
            "outlayer_tee" => {
                // Real TDX attestation
                let tdx_quote = self.call_dstack_socket(&report_data)
                    .await
                    .context("Failed to generate TDX quote for task")?;
                Ok(base64::encode(&tdx_quote))
            }
            "none" => {
                // Dev mode: Minimal fake quote
                tracing::warn!("Using no-attestation mode (dev only!)");
                Ok(base64::encode(b"no-attestation-dev-mode"))
            }
            other => {
                anyhow::bail!("Unsupported TEE mode for task attestation: {}", other);
            }
        }
    }

    /// Call the dstack SDK to generate a TDX quote
    ///
    /// This is the real TDX attestation generation for a dstack CVM.
    ///
    /// Uses dstack-sdk library (same as MPC Node) which communicates with:
    /// - Unix socket: /var/run/dstack.sock (default on Linux)
    /// - HTTP API: http://localhost:8090 (if DSTACK_SIMULATOR_ENDPOINT is set)
    ///
    /// Returns HEX-encoded TDX quote (not base64!)
    async fn call_dstack_socket(&self, report_data: &[u8; 64]) -> Result<Vec<u8>> {
        use dstack_sdk::dstack_client::DstackClient;

        tracing::info!("🔌 Calling dstack SDK for TDX quote generation");
        tracing::debug!("   report_data (hex): {}", hex::encode(report_data));

        // Create dstack client (auto-detects Unix socket or HTTP endpoint)
        let client = DstackClient::new(None); // None = use default /var/run/dstack.sock

        // Request TDX quote with report_data
        let response = client.get_quote(report_data.to_vec())
            .await
            .context("Failed to call dstack-sdk get_quote")?;

        tracing::info!("✅ Received TDX quote from dstack-sdk");
        tracing::debug!("   quote (hex, first 100 chars): {}", crate::near_client::head(&response.quote, 100));

        // Decode HEX quote to bytes (dstack-sdk returns HEX string, not base64)
        let tdx_quote = hex::decode(&response.quote)
            .context("Failed to decode TDX quote from HEX")?;

        tracing::info!(
            quote_size = tdx_quote.len(),
            "Successfully generated TDX quote via dstack-sdk"
        );

        // Extract and log measurements (debug level — logged at info during registration)
        if let Some(m) = extract_all_measurements_from_bytes(&tdx_quote) {
            tracing::debug!("TDX Measurements: MRTD={}, RTMR0={}, RTMR1={}, RTMR2={}, RTMR3={}",
                m.mrtd, m.rtmr0, m.rtmr1, m.rtmr2, m.rtmr3);
        } else {
            tracing::warn!("⚠️  Quote too short to extract measurements: {} bytes (need {})", tdx_quote.len(), RTMR3_OFFSET + MEASUREMENT_SIZE);
        }

        Ok(tdx_quote)
    }
}

/// Extract all TEE measurements (MRTD + RTMR0-3) from raw TDX quote bytes.
fn extract_all_measurements_from_bytes(tdx_quote: &[u8]) -> Option<TdxMeasurements> {
    if tdx_quote.len() < RTMR3_OFFSET + MEASUREMENT_SIZE {
        return None;
    }
    Some(TdxMeasurements {
        mrtd: hex::encode(&tdx_quote[MRTD_OFFSET..MRTD_OFFSET + MEASUREMENT_SIZE]),
        rtmr0: hex::encode(&tdx_quote[RTMR0_OFFSET..RTMR0_OFFSET + MEASUREMENT_SIZE]),
        rtmr1: hex::encode(&tdx_quote[RTMR1_OFFSET..RTMR1_OFFSET + MEASUREMENT_SIZE]),
        rtmr2: hex::encode(&tdx_quote[RTMR2_OFFSET..RTMR2_OFFSET + MEASUREMENT_SIZE]),
        rtmr3: hex::encode(&tdx_quote[RTMR3_OFFSET..RTMR3_OFFSET + MEASUREMENT_SIZE]),
    })
}

/// Extract all TEE measurements from a hex-encoded TDX quote.
///
/// Returns None if the quote is too short or not a real TDX quote.
pub fn extract_all_measurements_from_quote_hex(tdx_quote_hex: &str) -> Option<TdxMeasurements> {
    let tdx_quote = hex::decode(tdx_quote_hex).ok()?;
    extract_all_measurements_from_bytes(&tdx_quote)
}

// Base64 encoding/decoding helpers
mod base64 {
    use ::base64::Engine;
    use ::base64::engine::general_purpose::STANDARD;

    pub fn encode<T: AsRef<[u8]>>(input: T) -> String {
        STANDARD.encode(input)
    }

    #[allow(dead_code)]
    pub fn decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, ::base64::DecodeError> {
        STANDARD.decode(input)
    }
}

#[cfg(test)]
mod small_order_tests {
    use super::refuse_small_order_binding;

    #[test]
    fn a_binding_of_small_order_is_refused() {
        let mut one = [0u8; 32];
        one[0] = 1;
        let mut order8 = [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
            0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
            0xfc, 0x05,
        ];
        order8[31] |= 0x80;
        for b in [[0u8; 32], one, order8] {
            assert!(refuse_small_order_binding(&b).is_err(), "{:02x?}", b);
        }
        let real = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes();
        assert!(refuse_small_order_binding(&real).is_ok());
    }
}
