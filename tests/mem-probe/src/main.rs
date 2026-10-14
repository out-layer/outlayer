//! A guest for `tests/worker_memory_e2e.sh`: grows its linear memory towards a
//! target and reports what it was given.
//!
//! Input (stdin): `<target MiB> [fail]`. The probe does a fixed amount of
//! arithmetic (so the run burns instructions the worker must report), then
//! grows memory a MiB at a time, then a page at a time once a MiB is refused,
//! until it holds the target or the worker refuses growth. It prints
//! `reached=<MiB>` (whole MiB of linear memory held at the end). With `fail`
//! it then exits with status 1: a run that failed after real work.

use core::arch::wasm32::{memory_grow, memory_size};
use std::io::Read;

const PAGES_PER_MIB: usize = 16;

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let mut words = input.split_whitespace();
    let target_mib: usize = words.next().and_then(|w| w.parse().ok()).expect("input: <target MiB> [fail]");
    let fail = words.next() == Some("fail");

    let mut acc: u64 = 0;
    for i in 0..10_000_000u64 {
        acc = std::hint::black_box(acc.wrapping_mul(6364136223846793005).wrapping_add(i));
    }

    let target_pages = target_mib * PAGES_PER_MIB;
    while memory_size(0) < target_pages {
        if memory_grow(0, PAGES_PER_MIB) == usize::MAX {
            while memory_size(0) < target_pages && memory_grow(0, 1) != usize::MAX {}
            break;
        }
    }

    println!("reached={} acc={}", memory_size(0) / PAGES_PER_MIB, acc % 10);
    if fail {
        std::process::exit(1);
    }
}
