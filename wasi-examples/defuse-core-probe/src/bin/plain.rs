//! The probe without `outlayer:crypto`: `echo <rest>`, `env`, `clock`, `spin`.
//! Built from the same crate; a binary that references no signing imports none.

use std::io::{Read, Write};

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let (op, rest) = input.split_once(' ').unwrap_or((input.as_str(), ""));
    let out = match op {
        "echo" => rest.to_string(),
        "env" => std::env::vars().count().to_string(),
        "clock" => format!("{:?}", std::time::Instant::now().elapsed()),
        "spin" => {
            let mut n: u64 = 0;
            loop {
                n = std::hint::black_box(n.wrapping_add(1));
            }
        }
        _ => {
            eprintln!("unknown op");
            std::process::exit(2);
        }
    };
    std::io::stdout().write_all(out.as_bytes()).expect("stdout");
}
