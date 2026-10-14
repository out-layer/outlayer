//! A soft stop: SIGTERM or SIGINT means "finish the task in hand, take no new
//! one, exit".
//!
//! The worker runs as PID 1 in its container, and PID 1 ignores a signal it
//! has no handler for, so without this a stop waits out the container's grace
//! period and then SIGKILLs whatever is running — a job cut between its money
//! moving and its completion being reported.
//!
//! A poll already in flight is never cancelled: the coordinator may have taken
//! a task off its queue for it, and dropping the request would lose that task.
//! The loops look at the flag only BEFORE they poll, so a task a poll returns
//! is always run to the end.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;

/// Shared by every loop that polls for work.
#[derive(Clone, Default)]
pub struct Shutdown {
    requested: Arc<AtomicBool>,
}

impl Shutdown {
    /// True once a stop was asked for: poll for nothing more.
    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Ask for a stop; false when one was already asked for.
    fn request(&self, signal_name: &str) -> bool {
        let first = !self.requested.swap(true, Ordering::SeqCst);
        if first {
            info!("{}: finishing the current task, taking no new work", signal_name);
        }
        first
    }
}

/// Listen for SIGTERM and SIGINT for the life of the process. The first one is
/// a soft stop; a second one ends the process at once — the way out of a task
/// that hangs, for a worker run by hand (a second Ctrl-C).
pub fn install() -> Result<Shutdown> {
    let shutdown = Shutdown::default();
    let mut term = signal(SignalKind::terminate()).context("Failed to install the SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt()).context("Failed to install the SIGINT handler")?;
    let listener = shutdown.clone();
    tokio::spawn(async move {
        loop {
            let (name, code) = tokio::select! {
                _ = term.recv() => ("SIGTERM", 143),
                _ = int.recv() => ("SIGINT", 130),
            };
            if !listener.request(name) {
                tracing::warn!("{} again: exiting without finishing the current task", name);
                std::process::exit(code);
            }
        }
    });
    Ok(shutdown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_shutdown_is_not_requested() {
        assert!(!Shutdown::default().requested());
    }

    #[test]
    fn a_request_is_seen_by_every_clone() {
        let shutdown = Shutdown::default();
        let loop_view = shutdown.clone();
        assert!(shutdown.request("SIGTERM"));
        assert!(loop_view.requested());
        // The second request is what the listener turns into an immediate exit.
        assert!(!loop_view.request("SIGINT"));
    }

    #[tokio::test]
    async fn sigterm_sets_the_flag() {
        let shutdown = install().expect("handlers install");
        // The handler is installed above, so the signal cannot end the test run.
        let status = std::process::Command::new("kill")
            .args(["-TERM", &std::process::id().to_string()])
            .status()
            .expect("kill runs");
        assert!(status.success());
        for _ in 0..100 {
            if shutdown.requested() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("SIGTERM did not set the shutdown flag");
    }
}
