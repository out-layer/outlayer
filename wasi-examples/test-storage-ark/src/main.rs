//! Storage Test Ark - Test suite for OutLayer persistent storage
//!
//! Uses the `outlayer` SDK for storage operations.
//!
//! Env variables (set by OutLayer runtime):
//! - OUTLAYER_PROJECT_UUID = "p0000000000000001" (used for cross-project public storage reads)
//! - OUTLAYER_PROJECT_ID = "owner/name"
//! - OUTLAYER_PROJECT_OWNER = "owner"
//! - OUTLAYER_PROJECT_NAME = "name"

use outlayer::{storage, env};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use wasi_http_client::Client;
use base64::{Engine, engine::general_purpose::STANDARD};

#[derive(Debug, Deserialize)]
struct Input {
    command: String,
    #[serde(default)]
    key: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    expected: String,        // For set_if_equals
    #[serde(default)]
    delta: i64,              // For increment/decrement
    #[serde(default)]
    project: String,         // For cross-project public storage reads (e.g., "owner.near/project-id")
    #[serde(default)]
    coordinator_url: String, // For HTTP verification of public storage (e.g., "https://coordinator.outlayer.network")
}

#[derive(Debug, Serialize)]
struct Output {
    success: bool,
    command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exists: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deleted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    inserted: Option<bool>,      // For set_if_absent
    #[serde(skip_serializing_if = "Option::is_none")]
    updated: Option<bool>,       // For set_if_equals
    #[serde(skip_serializing_if = "Option::is_none")]
    current: Option<String>,     // For set_if_equals (current value on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    numeric_value: Option<i64>,  // For increment/decrement
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tests: Option<TestResults>,
}

#[derive(Debug, Serialize)]
struct TestResults {
    total: usize,
    passed: usize,
    failed: usize,
    results: Vec<TestResult>,
}

#[derive(Debug, Serialize)]
struct TestResult {
    name: String,
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn main() {
    let output = match env::input_json::<Input>() {
        Ok(Some(input)) => process_command(&input),
        Ok(None) => error_output("parse", "No input provided"),
        Err(e) => error_output("parse", &format!("Failed to parse input: {}", e)),
    };

    let _ = env::output_json(&output);
}

/// Helper to create an error Output
fn error_output(command: &str, error: &str) -> Output {
    Output {
        success: false,
        command: command.to_string(),
        value: None,
        exists: None,
        deleted: None,
        keys: None,
        inserted: None,
        updated: None,
        current: None,
        numeric_value: None,
        error: Some(error.to_string()),
        tests: None,
    }
}

fn process_command(input: &Input) -> Output {
    match input.command.as_str() {
        "set" => cmd_set(&input.key, &input.value),
        "get" => cmd_get(&input.key),
        "delete" => cmd_delete(&input.key),
        "has" => cmd_has(&input.key),
        "list" => cmd_list(&input.prefix),
        "set_worker" => cmd_set_worker(&input.key, &input.value),
        "get_worker" => cmd_get_worker(&input.key),
        "clear_all" => cmd_clear_all(),
        // Conditional write commands
        "set_if_absent" => cmd_set_if_absent(&input.key, &input.value),
        "set_if_equals" => cmd_set_if_equals(&input.key, &input.expected, &input.value),
        "increment" => cmd_increment(&input.key, input.delta),
        "decrement" => cmd_decrement(&input.key, input.delta),
        // Public storage commands (unencrypted, readable by other projects)
        "set_public" => cmd_set_public(&input.key, &input.value),
        "get_public_cross" => cmd_get_public_cross(&input.key, &input.project),
        "verify_public_http" => cmd_verify_public_http(&input.key, &input.coordinator_url),
        // Tests
        "test_all" => cmd_test_all(),
        "test_public_storage" => cmd_test_public_storage(&input.coordinator_url),
        _ => error_output(&input.command, &format!("Unknown command: {}", input.command)),
    }
}

fn cmd_set(key: &str, value: &str) -> Output {
    match storage::set(key, value.as_bytes()) {
        Ok(()) => Output {
            success: true,
            command: "set".to_string(),
            value: Some(format!("Stored {} bytes at key '{}'", value.len(), key)),
            exists: None,
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("set", &e.to_string()),
    }
}

fn cmd_get(key: &str) -> Output {
    match storage::get(key) {
        Ok(Some(data)) => {
            let value = String::from_utf8(data)
                .unwrap_or_else(|e| format!("<binary data, {} bytes>", e.as_bytes().len()));
            Output {
                success: true,
                command: "get".to_string(),
                value: Some(value),
                exists: Some(true),
                deleted: None,
                keys: None,
                inserted: None,
                updated: None,
                current: None,
                numeric_value: None,
                error: None,
                tests: None,
            }
        }
        Ok(None) => Output {
            success: true,
            command: "get".to_string(),
            value: None,
            exists: Some(false),
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("get", &e.to_string()),
    }
}

fn cmd_delete(key: &str) -> Output {
    let deleted = storage::delete(key);
    Output {
        success: true,
        command: "delete".to_string(),
        value: None,
        exists: None,
        deleted: Some(deleted),
        keys: None,
        inserted: None,
        updated: None,
        current: None,
        numeric_value: None,
        error: None,
        tests: None,
    }
}

fn cmd_has(key: &str) -> Output {
    let exists = storage::has(key);
    Output {
        success: true,
        command: "has".to_string(),
        value: None,
        exists: Some(exists),
        deleted: None,
        keys: None,
        inserted: None,
        updated: None,
        current: None,
        numeric_value: None,
        error: None,
        tests: None,
    }
}

fn cmd_list(prefix: &str) -> Output {
    match storage::list_keys(prefix) {
        Ok(keys) => Output {
            success: true,
            command: "list".to_string(),
            value: None,
            exists: None,
            deleted: None,
            keys: Some(keys),
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("list", &e.to_string()),
    }
}

fn cmd_set_worker(key: &str, value: &str) -> Output {
    match storage::set_worker(key, value.as_bytes()) {
        Ok(()) => Output {
            success: true,
            command: "set_worker".to_string(),
            value: Some(format!("Stored {} bytes at worker key '{}'", value.len(), key)),
            exists: None,
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("set_worker", &e.to_string()),
    }
}

fn cmd_get_worker(key: &str) -> Output {
    match storage::get_worker(key) {
        Ok(Some(data)) => {
            let value = String::from_utf8(data)
                .unwrap_or_else(|e| format!("<binary data, {} bytes>", e.as_bytes().len()));
            Output {
                success: true,
                command: "get_worker".to_string(),
                value: Some(value),
                exists: Some(true),
                deleted: None,
                keys: None,
                inserted: None,
                updated: None,
                current: None,
                numeric_value: None,
                error: None,
                tests: None,
            }
        }
        Ok(None) => Output {
            success: true,
            command: "get_worker".to_string(),
            value: None,
            exists: Some(false),
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("get_worker", &e.to_string()),
    }
}

fn cmd_clear_all() -> Output {
    match storage::clear_all() {
        Ok(()) => Output {
            success: true,
            command: "clear_all".to_string(),
            value: Some("All storage cleared".to_string()),
            exists: None,
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("clear_all", &e.to_string()),
    }
}

// ==================== Public Storage Commands ====================

/// Set public storage (unencrypted, readable by other projects via coordinator API)
fn cmd_set_public(key: &str, value: &str) -> Output {
    match storage::set_worker_with_options(key, value.as_bytes(), Some(false)) {
        Ok(()) => Output {
            success: true,
            command: "set_public".to_string(),
            value: Some(format!("Stored {} bytes as PUBLIC at key '{}'", value.len(), key)),
            exists: None,
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("set_public", &e.to_string()),
    }
}

/// Get public storage from another project (cross-project read)
fn cmd_get_public_cross(key: &str, project: &str) -> Output {
    if project.is_empty() {
        return error_output("get_public_cross", "project parameter is required: the project's name (e.g., 'owner.near/name') or its uuid (e.g., 'p0000000000000001')");
    }

    match storage::get_worker_from_project(key, Some(project)) {
        Ok(Some(data)) => {
            let value = String::from_utf8(data)
                .unwrap_or_else(|e| format!("<binary data, {} bytes>", e.as_bytes().len()));
            Output {
                success: true,
                command: "get_public_cross".to_string(),
                value: Some(value),
                exists: Some(true),
                deleted: None,
                keys: None,
                inserted: None,
                updated: None,
                current: None,
                numeric_value: None,
                error: None,
                tests: None,
            }
        }
        Ok(None) => Output {
            success: true,
            command: "get_public_cross".to_string(),
            value: None,
            exists: Some(false),
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("get_public_cross", &e.to_string()),
    }
}

/// Verify public storage via coordinator HTTP API
fn cmd_verify_public_http(key: &str, coordinator_url: &str) -> Output {
    if coordinator_url.is_empty() {
        return error_output("verify_public_http", "coordinator_url parameter is required");
    }

    let project_uuid = std::env::var("OUTLAYER_PROJECT_UUID").unwrap_or_default();

    if project_uuid.is_empty() {
        return error_output("verify_public_http", "OUTLAYER_PROJECT_UUID env not set");
    }

    match verify_public_storage_http(key, coordinator_url, &project_uuid) {
        Ok(Some(value)) => Output {
            success: true,
            command: "verify_public_http".to_string(),
            value: Some(value),
            exists: Some(true),
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Ok(None) => Output {
            success: true,
            command: "verify_public_http".to_string(),
            value: None,
            exists: Some(false),
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("verify_public_http", &e),
    }
}

/// HTTP request to coordinator's public storage endpoint
fn verify_public_storage_http(key: &str, coordinator_url: &str, project_uuid: &str) -> Result<Option<String>, String> {
    let url = format!(
        "{}/public/storage/get?project_uuid={}&key={}",
        coordinator_url.trim_end_matches('/'),
        project_uuid,
        key
    );

    let response = Client::new()
        .get(&url)
        .connect_timeout(Duration::from_secs(10))
        .send()
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    let status = response.status();
    if status == 403 {
        return Err("Storage key exists but is encrypted (not public)".to_string());
    }
    if status < 200 || status >= 300 {
        return Err(format!("HTTP {}", status));
    }

    let body = response.body().map_err(|e| format!("Failed to read response: {}", e))?;
    let json: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|e| format!("Failed to parse JSON: {}", e))?;

    let exists = json.get("exists").and_then(|v| v.as_bool()).unwrap_or(false);
    if !exists {
        return Ok(None);
    }

    let value_b64 = json.get("value").and_then(|v| v.as_str()).unwrap_or("");
    let value_bytes = STANDARD.decode(value_b64)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;
    let value = String::from_utf8(value_bytes)
        .map_err(|e| format!("Invalid UTF-8: {}", e))?;

    Ok(Some(value))
}

// ==================== Conditional Write Commands ====================

fn cmd_set_if_absent(key: &str, value: &str) -> Output {
    match storage::set_if_absent(key, value.as_bytes()) {
        Ok(inserted) => Output {
            success: true,
            command: "set_if_absent".to_string(),
            value: if inserted {
                Some(format!("Inserted {} bytes at key '{}'", value.len(), key))
            } else {
                Some(format!("Key '{}' already exists, not modified", key))
            },
            exists: None,
            deleted: None,
            keys: None,
            inserted: Some(inserted),
            updated: None,
            current: None,
            numeric_value: None,
            error: None,
            tests: None,
        },
        Err(e) => error_output("set_if_absent", &e.to_string()),
    }
}

fn cmd_set_if_equals(key: &str, expected: &str, new_value: &str) -> Output {
    match storage::set_if_equals(key, expected.as_bytes(), new_value.as_bytes()) {
        Ok((updated, current)) => {
            let current_str = current.map(|bytes| {
                String::from_utf8(bytes).unwrap_or_else(|e| format!("<binary, {} bytes>", e.as_bytes().len()))
            });
            Output {
                success: true,
                command: "set_if_equals".to_string(),
                value: if updated {
                    Some(format!("Updated key '{}' to new value", key))
                } else if current_str.is_some() {
                    Some(format!("Key '{}' has different value, not modified", key))
                } else {
                    Some(format!("Key '{}' does not exist", key))
                },
                exists: None,
                deleted: None,
                keys: None,
                inserted: None,
                updated: Some(updated),
                current: current_str,
                numeric_value: None,
                error: None,
                tests: None,
            }
        },
        Err(e) => error_output("set_if_equals", &e.to_string()),
    }
}

fn cmd_increment(key: &str, delta: i64) -> Output {
    match storage::increment(key, delta) {
        Ok(new_value) => Output {
            success: true,
            command: "increment".to_string(),
            value: Some(format!("Key '{}' incremented by {}, new value: {}", key, delta, new_value)),
            exists: None,
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: Some(new_value),
            error: None,
            tests: None,
        },
        Err(e) => error_output("increment", &e.to_string()),
    }
}

fn cmd_decrement(key: &str, delta: i64) -> Output {
    match storage::decrement(key, delta) {
        Ok(new_value) => Output {
            success: true,
            command: "decrement".to_string(),
            value: Some(format!("Key '{}' decremented by {}, new value: {}", key, delta, new_value)),
            exists: None,
            deleted: None,
            keys: None,
            inserted: None,
            updated: None,
            current: None,
            numeric_value: Some(new_value),
            error: None,
            tests: None,
        },
        Err(e) => error_output("decrement", &e.to_string()),
    }
}

fn cmd_test_all() -> Output {
    let mut results = Vec::new();
    let mut passed = 0;
    let mut failed = 0;

    // Clear all storage first to ensure clean state
    let _ = storage::clear_all();

    // Test 1: Set a value
    let test = test_set("test-key-1", "Hello, Storage!");
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 2: Get the value back
    let test = test_get("test-key-1", Some("Hello, Storage!"));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 3: Check key exists
    let test = test_has("test-key-1", true);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 4: Check non-existent key
    let test = test_has("non-existent-key", false);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 5: Get non-existent key
    let test = test_get("non-existent-key", None);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 6: Set multiple keys
    let _ = storage::set("prefix:key1", b"value1");
    let _ = storage::set("prefix:key2", b"value2");
    let _ = storage::set("other:key3", b"value3");
    let test = test_list_with_prefix("prefix:", 2);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 7: List all keys
    let test = test_list_all_exists();
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 8: Delete a key
    let test = test_delete("test-key-1", true);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 9: Verify key is deleted
    let test = test_has("test-key-1", false);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 10: Delete non-existent key
    let test = test_delete("non-existent-key", false);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 11: Worker-private storage set
    let test = test_set_worker("worker-secret", "secret-data");
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 12: Worker-private storage get
    let test = test_get_worker("worker-secret", Some("secret-data"));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // ==================== Conditional Write Tests ====================

    // Test 13: set_if_absent on new key (should insert)
    let test = test_set_if_absent("new-key-absent", "first-value", true);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 14: set_if_absent on existing key (should NOT insert)
    let test = test_set_if_absent("new-key-absent", "second-value", false);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 15: Verify set_if_absent didn't overwrite
    let test = test_get("new-key-absent", Some("first-value"));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 16: set_if_equals with correct expected value
    let _ = storage::set("cas-key", b"value-a");
    let test = test_set_if_equals("cas-key", "value-a", "value-b", true, None);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 17: Verify set_if_equals updated
    let test = test_get("cas-key", Some("value-b"));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 18: set_if_equals with wrong expected value (should NOT update)
    let test = test_set_if_equals("cas-key", "wrong-expected", "value-c", false, Some("value-b"));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 19: set_if_equals on non-existent key
    let test = test_set_if_equals("non-existent-cas", "any", "new-value", false, None);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 20: increment on new key (starts from delta)
    let test = test_increment("counter-new", 10, 10);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 21: increment existing counter
    let test = test_increment("counter-new", 5, 15);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 22: decrement
    let test = test_decrement("counter-new", 3, 12);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 23: increment with negative delta (same as decrement)
    let test = test_increment("counter-new", -2, 10);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 24: decrement new key (starts from -delta)
    let test = test_decrement("counter-dec", 5, -5);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // ==================== Public Storage Tests ====================

    // Test 25: Set public data (unencrypted)
    let test = test_set_public("public-test-key", "public-test-value");
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 26: Read public data back via worker storage
    let test = test_get_worker("public-test-key", Some("public-test-value"));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 27: Cross-project read of public data (from self, using project_uuid)
    let project_uuid = std::env::var("OUTLAYER_PROJECT_UUID").unwrap_or_default();
    if !project_uuid.is_empty() {
        let test = test_get_public_cross("public-test-key", &project_uuid, Some("public-test-value"));
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);
    }

    // Final: Clear all and verify
    let test = test_clear_all_and_verify();
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    Output {
        success: failed == 0,
        command: "test_all".to_string(),
        value: Some(format!("{}/{} tests passed", passed, passed + failed)),
        exists: None,
        deleted: None,
        keys: None,
        inserted: None,
        updated: None,
        current: None,
        numeric_value: None,
        error: if failed > 0 { Some(format!("{} tests failed", failed)) } else { None },
        tests: Some(TestResults {
            total: passed + failed,
            passed,
            failed,
            results,
        }),
    }
}

// ==================== Test Functions ====================

fn test_set(key: &str, value: &str) -> TestResult {
    match storage::set(key, value.as_bytes()) {
        Ok(()) => TestResult {
            name: format!("set({})", key),
            success: true,
            error: None,
        },
        Err(e) => TestResult {
            name: format!("set({})", key),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_get(key: &str, expected: Option<&str>) -> TestResult {
    match storage::get(key) {
        Ok(data) => {
            match (data, expected) {
                (Some(bytes), Some(exp)) => {
                    let actual = String::from_utf8(bytes).unwrap_or_default();
                    if actual == exp {
                        TestResult { name: format!("get({})", key), success: true, error: None }
                    } else {
                        TestResult { name: format!("get({})", key), success: false, error: Some(format!("Expected '{}' but got '{}'", exp, actual)) }
                    }
                }
                (None, None) => TestResult { name: format!("get({}) -> None", key), success: true, error: None },
                (Some(_), None) => TestResult { name: format!("get({}) -> None", key), success: false, error: Some("Expected None but got data".to_string()) },
                (None, Some(exp)) => TestResult { name: format!("get({})", key), success: false, error: Some(format!("Expected '{}' but got None", exp)) },
            }
        }
        Err(e) => TestResult {
            name: format!("get({})", key),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_has(key: &str, expected: bool) -> TestResult {
    let exists = storage::has(key);
    if exists == expected {
        TestResult { name: format!("has({}) == {}", key, expected), success: true, error: None }
    } else {
        TestResult { name: format!("has({}) == {}", key, expected), success: false, error: Some(format!("Expected {} but got {}", expected, exists)) }
    }
}

fn test_delete(key: &str, expected_existed: bool) -> TestResult {
    let deleted = storage::delete(key);
    if deleted == expected_existed {
        TestResult { name: format!("delete({}) == {}", key, expected_existed), success: true, error: None }
    } else {
        TestResult { name: format!("delete({}) == {}", key, expected_existed), success: false, error: Some(format!("Expected {} but got {}", expected_existed, deleted)) }
    }
}

fn test_list_with_prefix(prefix: &str, expected_count: usize) -> TestResult {
    match storage::list_keys(prefix) {
        Ok(keys) => {
            if keys.len() == expected_count {
                TestResult { name: format!("list_keys({}) -> {} keys", prefix, expected_count), success: true, error: None }
            } else {
                // Include actual keys in error for debugging
                TestResult {
                    name: format!("list_keys({}) -> {} keys", prefix, expected_count),
                    success: false,
                    error: Some(format!("Expected {} keys but got {}: {:?}", expected_count, keys.len(), keys))
                }
            }
        }
        Err(e) => TestResult {
            name: format!("list_keys({})", prefix),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_list_all_exists() -> TestResult {
    match storage::list_keys("") {
        Ok(keys) => {
            if !keys.is_empty() {
                TestResult { name: format!("list_keys() -> {} keys", keys.len()), success: true, error: None }
            } else {
                TestResult { name: "list_keys() not empty".to_string(), success: false, error: Some("Expected keys but got empty list".to_string()) }
            }
        }
        Err(e) => TestResult {
            name: "list_keys() not empty".to_string(),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_set_worker(key: &str, value: &str) -> TestResult {
    match storage::set_worker(key, value.as_bytes()) {
        Ok(()) => TestResult { name: format!("set_worker({})", key), success: true, error: None },
        Err(e) => TestResult { name: format!("set_worker({})", key), success: false, error: Some(e.to_string()) },
    }
}

fn test_get_worker(key: &str, expected: Option<&str>) -> TestResult {
    match storage::get_worker(key) {
        Ok(data) => {
            match (data, expected) {
                (Some(bytes), Some(exp)) => {
                    let actual = String::from_utf8(bytes).unwrap_or_default();
                    if actual == exp {
                        TestResult { name: format!("get_worker({})", key), success: true, error: None }
                    } else {
                        TestResult { name: format!("get_worker({})", key), success: false, error: Some(format!("Expected '{}' but got '{}'", exp, actual)) }
                    }
                }
                (None, None) => TestResult { name: format!("get_worker({}) -> None", key), success: true, error: None },
                (Some(_), None) => TestResult { name: format!("get_worker({}) -> None", key), success: false, error: Some("Expected None but got data".to_string()) },
                (None, Some(exp)) => TestResult { name: format!("get_worker({})", key), success: false, error: Some(format!("Expected '{}' but got None", exp)) },
            }
        }
        Err(e) => TestResult {
            name: format!("get_worker({})", key),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_clear_all_and_verify() -> TestResult {
    if let Err(e) = storage::clear_all() {
        return TestResult { name: "clear_all()".to_string(), success: false, error: Some(e.to_string()) };
    }

    // Verify keys are cleared
    match storage::list_keys("") {
        Ok(keys) => {
            if keys.is_empty() {
                TestResult { name: "clear_all() + verify empty".to_string(), success: true, error: None }
            } else {
                TestResult { name: "clear_all() + verify empty".to_string(), success: false, error: Some(format!("Expected empty storage but found {} keys", keys.len())) }
            }
        }
        Err(e) => TestResult { name: "clear_all() + verify empty".to_string(), success: false, error: Some(e.to_string()) },
    }
}

// ==================== Conditional Write Test Functions ====================

fn test_set_if_absent(key: &str, value: &str, expected_inserted: bool) -> TestResult {
    match storage::set_if_absent(key, value.as_bytes()) {
        Ok(inserted) => {
            if inserted == expected_inserted {
                TestResult {
                    name: format!("set_if_absent({}) -> {}", key, expected_inserted),
                    success: true,
                    error: None,
                }
            } else {
                TestResult {
                    name: format!("set_if_absent({}) -> {}", key, expected_inserted),
                    success: false,
                    error: Some(format!("Expected inserted={} but got {}", expected_inserted, inserted)),
                }
            }
        }
        Err(e) => TestResult {
            name: format!("set_if_absent({})", key),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_set_if_equals(
    key: &str,
    expected_value: &str,
    new_value: &str,
    expect_updated: bool,
    expect_current: Option<&str>,
) -> TestResult {
    match storage::set_if_equals(key, expected_value.as_bytes(), new_value.as_bytes()) {
        Ok((updated, current)) => {
            if updated != expect_updated {
                return TestResult {
                    name: format!("set_if_equals({}) updated", key),
                    success: false,
                    error: Some(format!("Expected updated={} but got {}", expect_updated, updated)),
                };
            }

            // Check current value if expected
            let current_str = current.map(|bytes| {
                String::from_utf8(bytes).unwrap_or_else(|_| "<binary>".to_string())
            });

            match (current_str.as_deref(), expect_current) {
                (None, None) => TestResult {
                    name: format!("set_if_equals({}) -> updated={}", key, updated),
                    success: true,
                    error: None,
                },
                (Some(got), Some(exp)) if got == exp => TestResult {
                    name: format!("set_if_equals({}) -> updated={}, current={}", key, updated, got),
                    success: true,
                    error: None,
                },
                (got, exp) => TestResult {
                    name: format!("set_if_equals({}) current", key),
                    success: false,
                    error: Some(format!("Expected current={:?} but got {:?}", exp, got)),
                },
            }
        }
        Err(e) => TestResult {
            name: format!("set_if_equals({})", key),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_increment(key: &str, delta: i64, expected_value: i64) -> TestResult {
    match storage::increment(key, delta) {
        Ok(new_value) => {
            if new_value == expected_value {
                TestResult {
                    name: format!("increment({}, {}) -> {}", key, delta, expected_value),
                    success: true,
                    error: None,
                }
            } else {
                TestResult {
                    name: format!("increment({}, {}) -> {}", key, delta, expected_value),
                    success: false,
                    error: Some(format!("Expected {} but got {}", expected_value, new_value)),
                }
            }
        }
        Err(e) => TestResult {
            name: format!("increment({}, {})", key, delta),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_decrement(key: &str, delta: i64, expected_value: i64) -> TestResult {
    match storage::decrement(key, delta) {
        Ok(new_value) => {
            if new_value == expected_value {
                TestResult {
                    name: format!("decrement({}, {}) -> {}", key, delta, expected_value),
                    success: true,
                    error: None,
                }
            } else {
                TestResult {
                    name: format!("decrement({}, {}) -> {}", key, delta, expected_value),
                    success: false,
                    error: Some(format!("Expected {} but got {}", expected_value, new_value)),
                }
            }
        }
        Err(e) => TestResult {
            name: format!("decrement({}, {})", key, delta),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

// ==================== Public Storage Test Functions ====================

/// Test public storage functionality
/// Tests writing unencrypted data and reading it back (simulating cross-project reads)
/// If coordinator_url is provided, also verifies via HTTP API
fn cmd_test_public_storage(coordinator_url: &str) -> Output {
    let mut results = Vec::new();
    let mut passed = 0;
    let mut failed = 0;

    // Get project info from env (use project_uuid for cross-project reads)
    let project_uuid = std::env::var("OUTLAYER_PROJECT_UUID").unwrap_or_default();

    // Test 1: Set public data
    let test = test_set_public("public-key-1", "public-value-1");
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 2: Read public data back via worker storage
    let test = test_get_worker("public-key-1", Some("public-value-1"));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 3: Set another public value (JSON data like oracle price)
    let json_value = r#"{"price":"1234.56","timestamp":1704067200}"#;
    let test = test_set_public("oracle:ETH", json_value);
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 4: Read JSON public data back
    let test = test_get_worker("oracle:ETH", Some(json_value));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 5: Cross-project read from self (simulates reading from another project using project_uuid)
    if !project_uuid.is_empty() {
        let test = test_get_public_cross("public-key-1", &project_uuid, Some("public-value-1"));
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);

        // Test 6: Cross-project read of oracle data
        let test = test_get_public_cross("oracle:ETH", &project_uuid, Some(json_value));
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);
    }

    // Test 7: Overwrite public data
    let test = test_set_public("public-key-1", "updated-public-value");
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 8: Verify overwrite worked
    let test = test_get_worker("public-key-1", Some("updated-public-value"));
    if test.success { passed += 1; } else { failed += 1; }
    results.push(test);

    // Test 9: Cross-project read of non-existent key
    if !project_uuid.is_empty() {
        let test = test_get_public_cross("non-existent-public-key", &project_uuid, None);
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);
    }

    // Test 10: Mix of public and private storage
    let _ = storage::set_worker("private-key", b"private-value");
    if !project_uuid.is_empty() {
        let test = test_private_not_accessible_cross("private-key", &project_uuid);
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);
    }

    // HTTP verification tests (if coordinator_url provided)
    if !coordinator_url.is_empty() && !project_uuid.is_empty() {
        // Test HTTP: Verify public data via coordinator API
        let test = test_verify_http("public-key-1", "updated-public-value", coordinator_url, &project_uuid);
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);

        // Test HTTP: Verify oracle data
        let test = test_verify_http("oracle:ETH", json_value, coordinator_url, &project_uuid);
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);

        // Test HTTP: Non-existent key returns exists=false
        let test = test_verify_http_not_exists("non-existent-http-key", coordinator_url, &project_uuid);
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);

        // Test HTTP: Private key should return 403 or not exist
        let test = test_verify_http_private_forbidden("private-key", coordinator_url, &project_uuid);
        if test.success { passed += 1; } else { failed += 1; }
        results.push(test);
    }

    Output {
        success: failed == 0,
        command: "test_public_storage".to_string(),
        value: Some(format!("{}/{} public storage tests passed", passed, passed + failed)),
        exists: None,
        deleted: None,
        keys: None,
        inserted: None,
        updated: None,
        current: None,
        numeric_value: None,
        error: if failed > 0 { Some(format!("{} tests failed", failed)) } else { None },
        tests: Some(TestResults {
            total: passed + failed,
            passed,
            failed,
            results,
        }),
    }
}

fn test_set_public(key: &str, value: &str) -> TestResult {
    match storage::set_worker_with_options(key, value.as_bytes(), Some(false)) {
        Ok(()) => TestResult {
            name: format!("set_public({})", key),
            success: true,
            error: None,
        },
        Err(e) => TestResult {
            name: format!("set_public({})", key),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

fn test_get_public_cross(key: &str, project: &str, expected: Option<&str>) -> TestResult {
    match storage::get_worker_from_project(key, Some(project)) {
        Ok(data) => {
            match (data, expected) {
                (Some(bytes), Some(exp)) => {
                    let actual = String::from_utf8(bytes).unwrap_or_default();
                    if actual == exp {
                        TestResult {
                            name: format!("get_public_cross({}, {})", key, project),
                            success: true,
                            error: None,
                        }
                    } else {
                        TestResult {
                            name: format!("get_public_cross({}, {})", key, project),
                            success: false,
                            error: Some(format!("Expected '{}' but got '{}'", exp, actual)),
                        }
                    }
                }
                (None, None) => TestResult {
                    name: format!("get_public_cross({}, {}) -> None", key, project),
                    success: true,
                    error: None,
                },
                (Some(bytes), None) => {
                    let actual = String::from_utf8(bytes).unwrap_or_else(|_| "<binary>".to_string());
                    TestResult {
                        name: format!("get_public_cross({}, {}) -> None", key, project),
                        success: false,
                        error: Some(format!("Expected None but got '{}'", actual)),
                    }
                }
                (None, Some(exp)) => TestResult {
                    name: format!("get_public_cross({}, {})", key, project),
                    success: false,
                    error: Some(format!("Expected '{}' but got None", exp)),
                },
            }
        }
        Err(e) => TestResult {
            name: format!("get_public_cross({}, {})", key, project),
            success: false,
            error: Some(e.to_string()),
        },
    }
}

/// Test that private (encrypted) data is NOT accessible via cross-project read
fn test_private_not_accessible_cross(key: &str, project: &str) -> TestResult {
    match storage::get_worker_from_project(key, Some(project)) {
        Ok(None) => TestResult {
            name: format!("private_not_accessible_cross({}, {})", key, project),
            success: true,
            error: None,
        },
        Ok(Some(_)) => TestResult {
            name: format!("private_not_accessible_cross({}, {})", key, project),
            success: false,
            error: Some("Private data should NOT be accessible cross-project".to_string()),
        },
        Err(e) => {
            // An error (like FORBIDDEN) is also acceptable - means access denied
            if e.to_string().contains("FORBIDDEN") || e.to_string().contains("403") || e.to_string().contains("encrypted") {
                TestResult {
                    name: format!("private_not_accessible_cross({}, {}) -> access denied", key, project),
                    success: true,
                    error: None,
                }
            } else {
                TestResult {
                    name: format!("private_not_accessible_cross({}, {})", key, project),
                    success: false,
                    error: Some(format!("Unexpected error: {}", e)),
                }
            }
        }
    }
}

// ==================== HTTP Verification Test Functions ====================

fn test_verify_http(key: &str, expected: &str, coordinator_url: &str, project_uuid: &str) -> TestResult {
    match verify_public_storage_http(key, coordinator_url, project_uuid) {
        Ok(Some(actual)) => {
            if actual == expected {
                TestResult {
                    name: format!("verify_http({})", key),
                    success: true,
                    error: None,
                }
            } else {
                TestResult {
                    name: format!("verify_http({})", key),
                    success: false,
                    error: Some(format!("Expected '{}' but got '{}'", expected, actual)),
                }
            }
        }
        Ok(None) => TestResult {
            name: format!("verify_http({})", key),
            success: false,
            error: Some(format!("Expected '{}' but got None", expected)),
        },
        Err(e) => TestResult {
            name: format!("verify_http({})", key),
            success: false,
            error: Some(e),
        },
    }
}

fn test_verify_http_not_exists(key: &str, coordinator_url: &str, project_uuid: &str) -> TestResult {
    match verify_public_storage_http(key, coordinator_url, project_uuid) {
        Ok(None) => TestResult {
            name: format!("verify_http_not_exists({})", key),
            success: true,
            error: None,
        },
        Ok(Some(value)) => TestResult {
            name: format!("verify_http_not_exists({})", key),
            success: false,
            error: Some(format!("Expected None but got '{}'", value)),
        },
        Err(e) => TestResult {
            name: format!("verify_http_not_exists({})", key),
            success: false,
            error: Some(e),
        },
    }
}

fn test_verify_http_private_forbidden(key: &str, coordinator_url: &str, project_uuid: &str) -> TestResult {
    match verify_public_storage_http(key, coordinator_url, project_uuid) {
        Ok(None) => TestResult {
            name: format!("verify_http_private_forbidden({}) -> not found", key),
            success: true,
            error: None,
        },
        Ok(Some(_)) => TestResult {
            name: format!("verify_http_private_forbidden({})", key),
            success: false,
            error: Some("Private data should NOT be accessible via HTTP".to_string()),
        },
        Err(e) if e.contains("403") || e.contains("FORBIDDEN") || e.contains("encrypted") => TestResult {
            name: format!("verify_http_private_forbidden({}) -> 403", key),
            success: true,
            error: None,
        },
        Err(e) => TestResult {
            name: format!("verify_http_private_forbidden({})", key),
            success: false,
            error: Some(format!("Unexpected error: {}", e)),
        },
    }
}
