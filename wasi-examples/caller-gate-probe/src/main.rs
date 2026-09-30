//! A WASI module whose only job is exercising the manifest's `callers` block.
//!
//! It answers one operation, `whoami`, with what the worker told it about the
//! run: the sender, the paying account, the account that called OutLayer, the
//! relayer of a meta-transaction and the signer's key. A run the manifest does
//! not admit never reaches it: the worker refuses before anything executes, so
//! a refused row sees no output at all.
//!
//! Eight builds, one per manifest (`manifests/`), chosen by feature:
//!
//! | feature | `callers` |
//! |---|---|
//! | `open` (default) | none: every door |
//! | `direct-only` | `contract: deny`, `https: deny` |
//! | `contract-any` | `direct: deny`, `https: deny` |
//! | `contract-relay` | `contract: {only: [relay.outlayer-alice.testnet]}` |
//! | `contract-deputy` | `contract: {only: [deputy.outlayer-alice.testnet]}` |
//! | `https-only` | `direct: deny`, `contract: deny` |
//! | `meta-tx` | `contract: deny`, `meta_tx: allow` |
//! | `tasks-direct-deny` | `tasks: true` with `direct: deny`: the manifest does not parse |
//!
//! `v2` builds the same manifest with one constant changed: another sha256.

use std::io::Read;

/// Embeds `$file` as the `outlayer.manifest` custom section, covered by the
/// wasm's sha256. The section only on wasm: the host build rejects the name.
macro_rules! manifest {
    ($file:literal) => {
        #[cfg(target_arch = "wasm32")]
        #[used]
        #[link_section = "outlayer.manifest"]
        static OUTLAYER_MANIFEST: [u8; include_bytes!($file).len()] = *include_bytes!($file);
    };
}

#[cfg(feature = "open")]
manifest!("../manifests/open.json");
#[cfg(feature = "direct-only")]
manifest!("../manifests/direct-only.json");
#[cfg(feature = "contract-any")]
manifest!("../manifests/contract-any.json");
#[cfg(feature = "contract-relay")]
manifest!("../manifests/contract-relay.json");
#[cfg(feature = "contract-deputy")]
manifest!("../manifests/contract-deputy.json");
#[cfg(feature = "https-only")]
manifest!("../manifests/https-only.json");
#[cfg(feature = "meta-tx")]
manifest!("../manifests/meta-tx.json");
#[cfg(feature = "tasks-direct-deny")]
manifest!("../manifests/tasks-direct-deny.json");

#[cfg(not(feature = "v2"))]
const BUILD: &str = "v1";
#[cfg(feature = "v2")]
const BUILD: &str = "v2";

fn env(name: &str) -> serde_json::Value {
    std::env::var(name).map(serde_json::Value::String).unwrap_or(serde_json::Value::Null)
}

fn main() {
    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);
    let operation = serde_json::from_str::<serde_json::Value>(&input)
        .ok()
        .and_then(|v| v.get("operation").and_then(|o| o.as_str()).map(str::to_string));
    let answer = match operation.as_deref() {
        Some("whoami") => serde_json::json!({
            "build": BUILD,
            "execution_type": env("OUTLAYER_EXECUTION_TYPE"),
            "sender_id": env("NEAR_SENDER_ID"),
            "user_account_id": env("NEAR_USER_ACCOUNT_ID"),
            "predecessor_id": env("NEAR_PREDECESSOR_ID"),
            "relayer_id": env("NEAR_RELAYER_ID"),
            "signer_public_key": env("NEAR_SIGNER_PUBLIC_KEY"),
        }),
        other => serde_json::json!({ "error": format!("unknown operation {other:?}: the only one is whoami") }),
    };
    println!("{answer}");
}
