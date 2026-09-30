//! Environment API for OutLayer WASM components
//!
//! Provides access to execution context like signer account ID, input data, and output.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use outlayer::env;
//!
//! fn main() {
//!     // Get the NEAR account that requested this execution
//!     let signer = env::signer_account_id();
//!     println!("Execution requested by: {}", signer);
//!
//!     // Get input data from execution request
//!     let input = env::input();
//!     let request: MyRequest = serde_json::from_slice(&input).unwrap();
//!
//!     // Process request...
//!     let result = process(request);
//!
//!     // Output result
//!     let output = serde_json::to_vec(&result).unwrap();
//!     env::output(&output);
//! }
//! ```
//!
//! ## Environment Variables
//!
//! OutLayer automatically injects several environment variables:
//!
//! - `NEAR_SENDER_ID` - Account that signed the transaction (original user, e.g. alice.near);
//!   for a NEP-366 meta-transaction, the account that signed the delegate action
//! - `NEAR_PREDECESSOR_ID` - Account that called OutLayer directly (e.g. token.near)
//! - `NEAR_RELAYER_ID` - Account that relayed a meta-transaction and paid its gas;
//!   empty for every other call
//! - `NEAR_TRANSACTION_HASH` - Transaction hash (if applicable)
//!
//! Example call chain: User (alice.near) → Token (token.near) → OutLayer → Worker → WASM
//! - NEAR_SENDER_ID = alice.near (user who signed)
//! - NEAR_PREDECESSOR_ID = token.near (contract that called OutLayer)
//!
//! Example meta-transaction: alice.near signs a delegate action calling OutLayer,
//! relayer.near sends it and pays the gas
//! - NEAR_SENDER_ID = NEAR_PREDECESSOR_ID = alice.near
//! - NEAR_RELAYER_ID = relayer.near
//!
//! To admit only some ways of calling the project — only through named
//! contracts, no HTTPS, no meta-transactions — declare `callers` in the
//! manifest rather than checking these values in code: the worker refuses a
//! run the manifest does not admit before any secret is decrypted or any code
//! runs (`wasi-examples/CONNECTOR_MANIFEST.md`, `callers`).
//!
//! You can also access secrets stored via the contract as environment variables:
//!
//! ```rust,ignore
//! // Secrets stored via dashboard or contract are accessible as env vars
//! let api_key = std::env::var("OPENAI_API_KEY").ok();
//! ```

use std::io::{self, Read, Write};

/// Get the NEAR account ID that requested this execution
///
/// This is the account that signed the transaction calling `request_execution`
/// on the OutLayer contract — for a NEP-366 meta-transaction, the account that
/// signed the delegate action, not the relayer that sent it (see
/// [`relayer_account_id`]).
///
/// # Returns
/// * `Some(account_id)` - The signer's account ID
/// * `None` - Not available (e.g., in test environment)
///
/// # Example
/// ```rust,ignore
/// if let Some(signer) = env::signer_account_id() {
///     println!("Request from: {}", signer);
///
///     // Authorization check
///     if signer == "admin.near" {
///         // Allow admin operations
///     }
/// }
/// ```
pub fn signer_account_id() -> Option<String> {
    std::env::var("NEAR_SENDER_ID").ok()
}

/// Get the transaction hash for this execution
///
/// # Returns
/// * `Some(hash)` - The transaction hash
/// * `None` - Not available
///
/// # Example
/// ```rust,ignore
/// if let Some(tx_hash) = env::transaction_hash() {
///     println!("Transaction: {}", tx_hash);
/// }
/// ```
pub fn transaction_hash() -> Option<String> {
    std::env::var("NEAR_TRANSACTION_HASH").ok()
}

/// Get the execution request ID
///
/// # Returns
/// * `Some(request_id)` - The request ID assigned by the contract
/// * `None` - Not available
pub fn request_id() -> Option<String> {
    std::env::var("OUTLAYER_REQUEST_ID").ok()
}

/// Get input data from the execution request
///
/// Reads all data from stdin, which contains the `input_data` from `request_execution`.
///
/// # Returns
/// The input data as bytes. Empty if no input was provided.
///
/// # Example
/// ```rust,ignore
/// use serde::Deserialize;
///
/// #[derive(Deserialize)]
/// struct Request {
///     action: String,
///     params: Vec<String>,
/// }
///
/// fn main() {
///     let input = env::input();
///
///     if input.is_empty() {
///         eprintln!("No input provided");
///         return;
///     }
///
///     let request: Request = serde_json::from_slice(&input).unwrap();
///     println!("Action: {}", request.action);
/// }
/// ```
pub fn input() -> Vec<u8> {
    let mut buffer = Vec::new();
    io::stdin().read_to_end(&mut buffer).unwrap_or(0);
    buffer
}

/// Get input data as a string
///
/// Convenience function that reads input and converts to UTF-8 string.
///
/// # Returns
/// * `Some(string)` - Input as valid UTF-8 string
/// * `None` - No input or invalid UTF-8
///
/// # Example
/// ```rust,ignore
/// if let Some(json_str) = env::input_string() {
///     println!("Got input: {}", json_str);
/// }
/// ```
pub fn input_string() -> Option<String> {
    let data = input();
    if data.is_empty() {
        None
    } else {
        String::from_utf8(data).ok()
    }
}

/// Get input data as JSON
///
/// Convenience function that reads input and deserializes from JSON.
///
/// # Returns
/// * `Ok(Some(T))` - Deserialized value
/// * `Ok(None)` - No input provided
/// * `Err(e)` - JSON parse error
///
/// # Example
/// ```rust,ignore
/// #[derive(Deserialize)]
/// struct Config {
///     name: String,
///     count: u32,
/// }
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///     if let Some(config) = env::input_json::<Config>()? {
///         println!("Name: {}, Count: {}", config.name, config.count);
///     }
///     Ok(())
/// }
/// ```
pub fn input_json<T: serde::de::DeserializeOwned>() -> Result<Option<T>, serde_json::Error> {
    let data = input();
    if data.is_empty() {
        Ok(None)
    } else {
        serde_json::from_slice(&data).map(Some)
    }
}

/// Write output data
///
/// Writes data to stdout which becomes the execution result.
///
/// # Arguments
/// * `data` - The output data as bytes
///
/// # Example
/// ```rust,ignore
/// let result = b"Success!";
/// env::output(result);
/// ```
pub fn output(data: &[u8]) {
    let _ = io::stdout().write_all(data);
    let _ = io::stdout().flush();
}

/// Write output as string
///
/// Convenience function to write a string as output.
///
/// # Example
/// ```rust,ignore
/// env::output_string("Hello, World!");
/// ```
pub fn output_string(s: &str) {
    output(s.as_bytes());
}

/// Write output as JSON
///
/// Serializes the value to JSON and writes to output.
///
/// # Returns
/// * `Ok(())` - Success
/// * `Err(e)` - JSON serialization error
///
/// # Example
/// ```rust,ignore
/// #[derive(Serialize)]
/// struct Result {
///     status: String,
///     data: Vec<u8>,
/// }
///
/// let result = Result {
///     status: "ok".to_string(),
///     data: vec![1, 2, 3],
/// };
///
/// env::output_json(&result)?;
/// ```
pub fn output_json<T: serde::Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_vec(value)?;
    output(&json);
    Ok(())
}

/// Get an environment variable
///
/// This includes both system variables and secrets stored via the contract.
///
/// # Arguments
/// * `key` - The environment variable name
///
/// # Returns
/// * `Some(value)` - Variable exists
/// * `None` - Variable not set
///
/// # Example
/// ```rust,ignore
/// // Access secrets stored via dashboard
/// if let Some(api_key) = env::var("OPENAI_API_KEY") {
///     // Use API key...
/// }
/// ```
pub fn var(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Check if an environment variable is set
///
/// # Arguments
/// * `key` - The environment variable name
///
/// # Returns
/// * `true` - Variable is set
/// * `false` - Variable is not set
///
/// # Example
/// ```rust,ignore
/// if env::has_var("DEBUG") {
///     // Enable debug mode
/// }
/// ```
pub fn has_var(key: &str) -> bool {
    std::env::var(key).is_ok()
}

/// Get the predecessor account ID (the account that called OutLayer)
///
/// The account that called `request_execution` on OutLayer: a contract
/// relaying the call, or the signer itself on a direct call or a
/// meta-transaction.
///
/// To admit only calls from your contract, declare
/// `"callers": {"contract": {"only": ["token.near"]}}` in the manifest: the
/// worker then refuses any other caller before the secrets are decrypted and
/// before this code runs. A check in code, as below, runs after both.
///
/// # Returns
/// * `Some(account_id)` - The predecessor contract's account ID
/// * `None` - Not available (e.g., in test environment)
///
/// # Example
/// ```rust,ignore
/// const TOKEN_CONTRACT: &str = "token.near";
///
/// fn init() {
///     // Verify this was called from our token contract
///     let predecessor = env::predecessor_account_id()
///         .expect("Predecessor not available");
///
///     if predecessor != TOKEN_CONTRACT {
///         panic!("Unauthorized: only {} can initialize", TOKEN_CONTRACT);
///     }
/// }
/// ```
pub fn predecessor_account_id() -> Option<String> {
    std::env::var("NEAR_PREDECESSOR_ID").ok()
}

/// Get the account that relayed this call as a NEP-366 meta-transaction
///
/// A meta-transaction is signed by the user as a delegate action and sent by a
/// relayer, which pays the gas. The run belongs to the user
/// ([`signer_account_id`]); this names the relayer.
///
/// # Returns
/// * `Some(account_id)` - The relayer's account ID
/// * `None` - The call was not a meta-transaction, or not on chain
///
/// # Example
/// ```rust,ignore
/// if let Some(relayer) = env::relayer_account_id() {
///     println!("Gas paid by {}", relayer);
/// }
/// ```
pub fn relayer_account_id() -> Option<String> {
    std::env::var("NEAR_RELAYER_ID").ok().filter(|id| !id.is_empty())
}
