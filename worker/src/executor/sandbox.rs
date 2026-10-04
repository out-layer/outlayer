//! What a guest run is given of the host, and what it leaves behind: a
//! private scratch directory, and the epoch ticker that times it.
//!
//! A WASI guest has no file access but the directories the host preopens.
//! While [`GUEST_FILES_ALLOWED`] is false it gets none: every file call
//! answers an error, as on WASI P1. When files are allowed it gets exactly
//! one: a fresh directory under [`SCRATCH_ROOT`], made for the run (mode
//! 0700, random name) and deleted with everything in it when the run is
//! over — success, trap, timeout or an early return. Nothing a guest writes
//! reaches the next job, and no guest sees the worker's own files: the wasm
//! cache and anything else under `/tmp` stay outside it.
//!
//! The epoch ticker advances the engine's epoch once a second for the run's
//! deadline. The engine is shared by every run, so a ticker left behind
//! would advance the epoch for the next run too and end it early: the
//! [`Ticker`] guard stops it on drop, whichever way the run returns.

use std::path::{Path, PathBuf};

/// Whether a WASI P2 guest gets a scratch directory at all.
///
/// Off: no directory is preopened and every file call answers an error, as
/// on WASI P1. A run keeps its data in memory, where `max_memory_mb` bounds
/// it; a file would be the one way round that limit. None of our connectors
/// or examples writes files, and a file never outlived its run.
///
/// The per-run directory below stays for the day this is turned on. Before
/// that, two things:
///
/// * **A size cap.** WASI has no quota, so a guest could fill memory or disk
///   for as long as its time limit lasts. The cap is a tmpfs mount for
///   [`SCRATCH_ROOT`] with `size=` and `nr_inodes=` in the worker's compose
///   file.
/// * **The docs.** `wasi-examples/WASI_TUTORIAL.md`, `executor/README.md` and
///   the dashboard's WASI section say a guest has no files.
///
/// `tests/signing_key_probe.rs` checks that the guest's `/` and `.` cannot be
/// listed while this is off.
pub const GUEST_FILES_ALLOWED: bool = false;

/// Where the runs' scratch directories live. Never the wasm cache's
/// directory, and never preopened itself.
pub const SCRATCH_ROOT: &str = "/tmp/outlayer-jobs";

/// One run's scratch directory: preopened to the guest as `.`, removed with
/// its contents when this is dropped.
pub struct Scratch(tempfile::TempDir);

impl Scratch {
    pub fn new() -> anyhow::Result<Self> {
        Self::under(Path::new(SCRATCH_ROOT))
    }

    pub fn under(root: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(root)?;
        restrict(root);
        let dir = tempfile::Builder::new().prefix("job-").tempdir_in(root)?;
        Ok(Self(dir))
    }

    pub fn path(&self) -> &Path {
        self.0.path()
    }
}

/// Owner-only on the root, where the platform has modes at all.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// What runs left behind when the worker stopped mid-run, before the
/// directory's drop ran: removed at start-up, before the first job. Answers
/// how many directories were removed.
pub fn clear_leftovers() -> usize {
    clear_under(Path::new(SCRATCH_ROOT))
}

pub fn clear_under(root: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else { return 0 };
    entries
        .flatten()
        .map(|e| e.path())
        .filter(|p: &PathBuf| std::fs::remove_dir_all(p).or_else(|_| std::fs::remove_file(p)).is_ok())
        .count()
}

/// The epoch ticker of one run, stopped when dropped.
pub struct Ticker(tokio::task::JoinHandle<()>);

impl Ticker {
    /// Advance `engine`'s epoch once a second, `ticks` times.
    pub fn start(engine: wasmtime::Engine, ticks: u64) -> Self {
        Self(tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            for _ in 0..ticks {
                interval.tick().await;
                engine.increment_epoch();
            }
        }))
    }
}

impl Drop for Ticker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A run that executed and did not succeed, with what it consumed — typed,
/// never read back from the message: the message begins with the guest's
/// own stderr, and a number parsed out of it would be the guest's to choose.
#[derive(Debug)]
pub struct RunFailed {
    pub message: String,
    /// The instructions the run consumed before it ended.
    pub instructions: u64,
    /// A timeout or an abuse of the run's limits: the whole compute limit is
    /// charged, with no refund.
    pub penalty: bool,
}

impl std::fmt::Display for RunFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RunFailed {}

/// The error of a guest call: a timeout (the epoch trap, or the wall-clock
/// bound that stands in for it while the guest waits in a host call), an
/// explicit exit with its status, or anything else.
pub enum Ended {
    TimedOut,
    Exited(i32),
    Other,
}

pub fn ended(error: &anyhow::Error, wall_clock_hit: bool) -> Ended {
    if wall_clock_hit || error.downcast_ref::<wasmtime::Trap>() == Some(&wasmtime::Trap::Interrupt) {
        return Ended::TimedOut;
    }
    match error.downcast_ref::<wasmtime_wasi::I32Exit>() {
        Some(exit) => Ended::Exited(exit.0),
        None => Ended::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runs_files_go_with_its_directory_and_the_next_run_starts_empty() {
        let root = tempfile::tempdir().unwrap();
        let first = Scratch::under(root.path()).unwrap();
        std::fs::write(first.path().join("secret.txt"), b"guest A").unwrap();
        let first_path = first.path().to_path_buf();
        drop(first);
        assert!(!first_path.exists(), "the directory and its files are gone with the run");
        let second = Scratch::under(root.path()).unwrap();
        assert_eq!(std::fs::read_dir(second.path()).unwrap().count(), 0, "the next run sees nothing");
        assert_ne!(second.path(), first_path);
    }

    #[test]
    fn leftovers_of_a_stopped_worker_are_cleared() {
        let root = tempfile::tempdir().unwrap();
        let left = root.path().join("job-left");
        std::fs::create_dir_all(left.join("deep")).unwrap();
        std::fs::write(left.join("deep/f"), b"x").unwrap();
        assert_eq!(clear_under(root.path()), 1);
        assert!(!left.exists());
        assert_eq!(clear_under(&root.path().join("absent")), 0);
    }

    #[tokio::test]
    async fn a_ticker_dropped_early_stops_advancing_the_epoch() {
        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true);
        let engine = wasmtime::Engine::new(&config).unwrap();
        let ticker = Ticker::start(engine.clone(), 1_000);
        drop(ticker);
        // A store whose deadline is one tick away would trap if anything
        // still advanced the epoch.
        let mut store = wasmtime::Store::new(&engine, ());
        store.set_epoch_deadline(1);
        tokio::time::sleep(std::time::Duration::from_millis(2_300)).await;
        let module = wasmtime::Module::new(&engine, r#"(module (func (export "f")))"#).unwrap();
        let instance = wasmtime::Instance::new(&mut store, &module, &[]).unwrap();
        let f = instance.get_typed_func::<(), ()>(&mut store, "f").unwrap();
        assert!(f.call(&mut store, ()).is_ok(), "no tick arrived after the ticker was dropped");
    }
}

#[cfg(test)]
mod ended_tests {
    use super::*;

    #[test]
    fn a_run_ends_by_its_type_and_never_by_the_words_of_its_message() {
        assert!(matches!(ended(&anyhow::Error::new(wasmtime::Trap::Interrupt), false), Ended::TimedOut));
        assert!(matches!(ended(&anyhow::anyhow!("anything"), true), Ended::TimedOut));
        assert!(matches!(ended(&anyhow::Error::new(wasmtime_wasi::I32Exit(0)), false), Ended::Exited(0)));
        assert!(matches!(ended(&anyhow::Error::new(wasmtime_wasi::I32Exit(3)), false), Ended::Exited(3)));
        // A guest that prints the words of a timeout or of a count is still an
        // ordinary failure.
        assert!(matches!(ended(&anyhow::anyhow!("interrupt (penalty) consumed 1 instructions"), false), Ended::Other));
        assert!(matches!(ended(&anyhow::Error::new(wasmtime::Trap::UnreachableCodeReached), false), Ended::Other));
    }
}
