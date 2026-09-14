use anyhow::{Context, Result};
use reqwest::multipart::Form;
use serde::Deserialize;

/// Response from Phala Cloud API when uploading TDX quote for collateral
#[derive(Debug, Deserialize)]
struct UploadResponse {
    quote_collateral: serde_json::Value,
}

/// Fetch TDX quote collateral from Phala Cloud API
///
/// This function uploads a TDX quote to Phala's verification endpoint
/// and receives back the collateral JSON needed to verify the quote on NEAR.
///
/// The collateral includes Intel certificate chains, CRLs, and TCB info.
///
/// # Arguments
/// * `tdx_quote_hex` - Hex-encoded TDX quote (e.g., "04000200000000000a00...")
///
/// # Returns
/// JSON string with collateral data that can be used with update_collateral contract method
pub async fn fetch_collateral_from_phala(tdx_quote_hex: &str) -> Result<String> {
    const PHALA_COLLATERAL_API: &str =
        "https://cloud-api.phala.network/api/v1/attestations/verify";

    tracing::info!("📡 Fetching collateral from Phala Cloud API...");
    tracing::info!("   API endpoint: {}", PHALA_COLLATERAL_API);
    tracing::info!("   Quote size: {} bytes (hex: {} chars)",
        tdx_quote_hex.len() / 2, tdx_quote_hex.len());
    tracing::info!("   Quote hex preview (first 100 chars): {}", crate::near_client::head(tdx_quote_hex, 100));

    // Create HTTP client with 10s timeout
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("Failed to create HTTP client")?;

    // IMPORTANT: Phala API expects lowercase hex string WITHOUT 0x prefix
    // The field name is "hex" (not "quote" or "data")
    let form = Form::new()
        .text("hex", tdx_quote_hex.to_string());

    // Send POST request
    let response = client
        .post(PHALA_COLLATERAL_API)
        .multipart(form)
        .send()
        .await
        .context("Failed to send request to Phala API")?;

    // Check status
    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "Phala API returned error status {}: {}",
            status, error_text
        );
    }

    // Parse JSON response
    let upload_response: UploadResponse = response
        .json()
        .await
        .context("Failed to parse JSON response from Phala API")?;

    // Convert collateral to pretty JSON string
    let collateral_json = serde_json::to_string_pretty(&upload_response.quote_collateral)
        .context("Failed to serialize collateral JSON")?;

    tracing::info!("✅ Successfully fetched collateral from Phala Cloud");
    tracing::info!("   Collateral size: {} bytes", collateral_json.len());

    Ok(collateral_json)
}
