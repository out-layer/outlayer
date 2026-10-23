//! The first word of stdin picks the operation, the rest are its arguments:
//! `echo <rest>`, `env` (number of environment variables), `clock` (reads the
//! monotonic clock), `spin` (never returns), `ed25519-pk <path>`, `ed25519-sign <path> <msg-hex>`,
//! `secp256k1-pk <path>`, `secp256k1-sign <path> <prehash-hex>`. Keys and
//! signatures are written as hex; a secp256k1 key is SEC1 compressed, a
//! secp256k1 signature is `r || s || v`.

use std::io::{Read, Write};

use defuse_outlayer_sdk::{
    host::signer::{DeriveSignerExt, HostSigner, RecoverableDeriveSignerExt},
    kdf::{
        crypto::{ed25519::Ed25519, secp256k1::Secp256k1},
        DeriveSigner,
    },
};

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let (op, rest) = input.split_once(' ').unwrap_or((input.as_str(), ""));
    let args: Vec<&str> = rest.split(' ').collect();
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
        "ed25519-pk" => hex::encode(DeriveSigner::<Ed25519, _>::derive_public_key(&HostSigner, args[0]).as_bytes()),
        "ed25519-sign" => {
            let msg = hex::decode(args[1]).expect("msg hex");
            hex::encode(DeriveSignerExt::<Ed25519, _>::derive_sign_sync(&HostSigner, args[0], &msg).to_bytes())
        }
        "secp256k1-pk" => hex::encode(DeriveSigner::<Secp256k1, _>::derive_public_key(&HostSigner, args[0]).to_sec1_bytes()),
        "secp256k1-sign" => {
            let prehash = hex::decode(args[1]).expect("prehash hex");
            let (sig, v) = HostSigner.derive_sign_recoverable_sync(args[0], &prehash);
            let mut bytes = sig.to_bytes().to_vec();
            bytes.push(v.to_byte());
            hex::encode(bytes)
        }
        _ => {
            eprintln!("unknown op");
            std::process::exit(2);
        }
    };
    std::io::stdout().write_all(out.as_bytes()).expect("stdout");
}
