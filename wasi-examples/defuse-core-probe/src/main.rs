//! The first word of stdin picks the operation:
//! `echo <rest>` writes `<rest>` back, `env` writes the number of
//! environment variables, `clock` reads the monotonic clock.

use std::io::{Read, Write};

fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).expect("stdin");
    let (op, rest) = match input.iter().position(|b| *b == b' ') {
        Some(i) => (&input[..i], &input[i + 1..]),
        None => (&input[..], &[][..]),
    };
    let mut out = std::io::stdout();
    match op {
        b"echo" => out.write_all(rest).expect("stdout"),
        b"env" => write!(out, "{}", std::env::vars().count()).expect("stdout"),
        b"clock" => {
            let t = std::time::Instant::now();
            write!(out, "{:?}", t.elapsed()).expect("stdout");
        }
        _ => {
            eprintln!("unknown op");
            std::process::exit(2);
        }
    }
}
