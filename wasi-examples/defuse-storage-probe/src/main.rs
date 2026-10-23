//! Runs on the Defuse worker engine through the OutLayer SDK's `defuse-engine`
//! feature. The first word of the input picks the operation:
//! `echo <rest>`, `var <NAME>` (a `meta` variable), `sender`,
//! `set <key> <value>`, `get <key>`, `set-raw <key> <value>`, `get-raw <key>`,
//! `incr <key> <delta>`, `list <prefix>`. Storage answers are the value, `<none>`,
//! or `error: <why>`.

use outlayer::{env, storage};

fn main() {
    let input = env::input_string().unwrap_or_default();
    let mut words = input.splitn(3, ' ');
    let op = words.next().unwrap_or_default();
    let a = words.next().unwrap_or_default();
    let b = words.next().unwrap_or_default();
    let out = match op {
        "echo" => format!("{a}{}{b}", if b.is_empty() { "" } else { " " }),
        "var" => env::var(a).unwrap_or_else(|| "<unset>".to_string()),
        "sender" => env::signer_account_id().unwrap_or_else(|| "<unset>".to_string()),
        "set" => storage::set(a, b.as_bytes()).map(|_| "ok".to_string()).unwrap_or_else(|e| format!("error: {e}")),
        "get" => show(storage::get(a)),
        "set-raw" => storage::set_raw(a, b.as_bytes()).map(|_| "ok".to_string()).unwrap_or_else(|e| format!("error: {e}")),
        "get-raw" => show(storage::get_raw(a)),
        "incr" => storage::increment(a, b.parse().unwrap_or(1)).map(|v| v.to_string()).unwrap_or_else(|e| format!("error: {e}")),
        "list" => storage::list_keys(a).map(|k| k.join(",")).unwrap_or_else(|e| format!("error: {e}")),
        _ => {
            eprintln!("unknown op");
            std::process::exit(2);
        }
    };
    env::output_string(&out);
}

fn show(r: storage::Result<Option<Vec<u8>>>) -> String {
    match r {
        Ok(Some(v)) => String::from_utf8_lossy(&v).into_owned(),
        Ok(None) => "<none>".to_string(),
        Err(e) => format!("error: {e}"),
    }
}
