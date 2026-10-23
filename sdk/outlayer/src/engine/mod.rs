//! The Defuse worker as the engine (feature `defuse-engine`).
//!
//! On that engine a component has no OutLayer host functions and an empty
//! environment. What the environment carried arrives in `meta` on stdin, inside
//! `{"meta": {...}, "input": ...}`, and storage is reached over HTTPS with the
//! run's one-time call token (`OUTLAYER_CALL_TOKEN`), which opens exactly the
//! storage cell the host functions would have used. The public API of `env` and
//! `storage` is the same as on the OutLayer engine; this module is what sits
//! behind it.

pub mod storage;
mod http;

use std::{
    collections::HashMap,
    io::Read,
    sync::OnceLock,
};

struct Context {
    meta: HashMap<String, String>,
    input: Vec<u8>,
}

static CONTEXT: OnceLock<Context> = OnceLock::new();

/// Read once, from stdin, on first use.
fn context() -> &'static Context {
    CONTEXT.get_or_init(|| {
        let mut raw = Vec::new();
        std::io::stdin().read_to_end(&mut raw).unwrap_or(0);
        parse(&raw)
    })
}

/// Tests never read the process's stdin: they set the run's context themselves.
#[cfg(test)]
pub(crate) fn preset(meta: HashMap<String, String>, input: Vec<u8>) {
    let _ = CONTEXT.set(Context { meta, input });
}

/// The envelope, or — for a run that was not wrapped — the bytes as the input
/// and no meta.
fn parse(raw: &[u8]) -> Context {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return Context { meta: HashMap::new(), input: raw.to_vec() };
    };
    let Some(obj) = value.as_object() else {
        return Context { meta: HashMap::new(), input: raw.to_vec() };
    };
    let Some(meta_obj) = obj.get("meta").and_then(|m| m.as_object()) else {
        return Context { meta: HashMap::new(), input: raw.to_vec() };
    };
    let meta = meta_obj
        .iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
        .collect();
    let input = match (obj.get("input"), obj.get("input_base64")) {
        (Some(serde_json::Value::String(s)), _) => s.as_bytes().to_vec(),
        (_, Some(serde_json::Value::String(b64))) => {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(b64).unwrap_or_default()
        }
        _ => Vec::new(),
    };
    Context { meta, input }
}

/// The caller's input, as the OutLayer engine would have put it on stdin.
pub fn input() -> Vec<u8> {
    context().input.clone()
}

/// A variable of `meta`: the same names as the environment variables on the
/// OutLayer engine.
pub fn var(key: &str) -> Option<String> {
    context().meta.get(key).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_envelope_yields_meta_and_input() {
        let c = parse(br#"{"meta":{"NEAR_SENDER_ID":"bob.testnet","N":"1"},"input":"{\"op\":1}"}"#);
        assert_eq!(c.meta.get("NEAR_SENDER_ID").map(String::as_str), Some("bob.testnet"));
        assert_eq!(c.input, br#"{"op":1}"#);
    }

    #[test]
    fn binary_input_comes_back_from_base64() {
        let c = parse(br#"{"meta":{},"input_base64":"//4="}"#);
        assert_eq!(c.input, vec![0xff, 0xfe]);
    }

    #[test]
    fn bytes_that_are_not_an_envelope_are_the_input() {
        let c = parse(b"plain text");
        assert!(c.meta.is_empty());
        assert_eq!(c.input, b"plain text");
        let c = parse(br#"{"op":"echo"}"#);
        assert!(c.meta.is_empty(), "an object without meta is the caller's own JSON");
        assert_eq!(c.input, br#"{"op":"echo"}"#);
    }
}
