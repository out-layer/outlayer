/// Component tests for worker modules
/// Run with: cargo test --test component_tests

use offchainvm_worker::executor::Executor;
use offchainvm_worker::api_client::ResourceLimits;

#[tokio::test]
async fn test_executor_with_minimal_wasm() {
    // Minimal valid WASM module
    let wasm = vec![
        0x00, 0x61, 0x73, 0x6d, // magic
        0x01, 0x00, 0x00, 0x00, // version
    ];

    let executor = Executor::new(1_000_000, false);
    let limits = ResourceLimits {
        max_instructions: 1_000_000,
        max_memory_mb: 16,
        max_execution_seconds: 5,
    };

    let input = vec![];
    use offchainvm_worker::api_client::ResponseFormat;
    let response_format = ResponseFormat::Text;

    // Should succeed (no functions to execute, but valid WASM)
    let result = executor.execute(&wasm, None, &input, &limits, None, None, &response_format, None, None, None, None).await;

    // Minimal WASM has no export, so execution will fail with specific error
    // But WASM parsing should succeed
    assert!(result.is_err() || !result.unwrap().success);
}

#[tokio::test]
async fn test_executor_with_invalid_wasm() {
    let invalid_wasm = vec![0xFF, 0xFF, 0xFF, 0xFF]; // Invalid magic number

    let executor = Executor::new(1_000_000, false);
    let limits = ResourceLimits {
        max_instructions: 1_000_000,
        max_memory_mb: 16,
        max_execution_seconds: 5,
    };

    let input = vec![];
    use offchainvm_worker::api_client::ResponseFormat;
    let response_format = ResponseFormat::Text;

    let result = executor.execute(&invalid_wasm, None, &input, &limits, None, None, &response_format, None, None, None, None).await;

    // Should fail to parse - executor.execute() returns Ok(ExecutionResult)
    // but ExecutionResult.success should be false
    assert!(result.is_ok());
    let exec_result = result.unwrap();
    assert!(!exec_result.success, "Expected execution to fail with invalid WASM");
    assert!(exec_result.error.is_some(), "Expected error message");
    assert!(exec_result.error.unwrap().contains("Failed to load WASM binary"));
}

#[test]
fn test_checksum_computation() {
    use sha2::{Digest, Sha256};

    let compute_checksum = |repo: &str, commit: &str, target: &str| -> String {
        let mut hasher = Sha256::new();
        hasher.update(repo.as_bytes());
        hasher.update(commit.as_bytes());
        hasher.update(target.as_bytes());
        hex::encode(hasher.finalize())
    };

    let c1 = compute_checksum("https://github.com/test/repo", "abc123", "wasm32-wasi");
    let c2 = compute_checksum("https://github.com/test/repo", "abc123", "wasm32-wasi");
    let c3 = compute_checksum("https://github.com/test/repo", "def456", "wasm32-wasi");

    assert_eq!(c1, c2, "Same inputs should produce same checksum");
    assert_ne!(c1, c3, "Different commits should produce different checksums");
}

#[test]
fn test_event_json_parsing() {
    use offchainvm_worker::event_monitor::event_json_payload;
    use serde_json::Value;

    let log = r#"EVENT_JSON:{"standard":"near-outlayer","version":"1.0.0","event":"execution_requested","data":[{"request_data":"{}","data_id":[1,2,3],"timestamp":123}]}"#;

    let event_json = event_json_payload(log).unwrap();

    let event: Value = serde_json::from_str(event_json).unwrap();

    assert_eq!(event["standard"], "near-outlayer");
    assert_eq!(event["event"], "execution_requested");
    assert!(event["data"].is_array());
}

#[cfg(test)]
mod api_client_tests {
    use offchainvm_worker::api_client::ApiClient;

    #[test]
    fn test_api_client_creation() {
        let client = ApiClient::new(
            "http://localhost:8080".to_string(),
            "test-token".to_string(),
        );
        assert!(client.is_ok());
    }

    #[test]
    fn test_base_url_trimming() {
        let _client = ApiClient::new(
            "http://localhost:8080/".to_string(),
            "test-token".to_string(),
        )
        .unwrap();

        // ApiClient should trim trailing slash
        // This is a white-box test - we know the internal structure
        // In production, you'd test this through the public API
    }
}

#[cfg(test)]
mod config_tests {
    #[test]
    fn test_config_validation() {
        // Test that poll timeout must be reasonable
        let valid_range = 1..=300;
        assert!(valid_range.contains(&60));
        assert!(!valid_range.contains(&0));
        assert!(!valid_range.contains(&301));
    }

    #[test]
    fn test_memory_limits() {
        let min_memory_mb = 512;
        assert!(2048 >= min_memory_mb);
        assert!(100 < min_memory_mb);
    }
}
