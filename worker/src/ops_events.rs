//! Errors and attack signals this worker counted, reported to the coordinator.
//!
//! An event is a [`Code`] — a name chosen where the failure is decided — and the
//! worker operation it happened in. Never a message: a log line carries whatever
//! was interpolated into it (a keyed RPC URL, a guest's text), and these counts
//! leave the worker for the coordinator's `ops_events` table and monitoring.
//!
//! [`record`] is a short lock and a map insert, safe from any thread. The
//! heartbeat task [`take`]s the tally every 30 s and sends it
//! (`ApiClient::report_ops_events`); a report that fails is [`restore`]d and goes
//! with the next one.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use serde::Serialize;

/// The coordinator's `MAX_COUNT` per event.
const MAX_COUNT: u64 = 1_000_000;

/// Where in the worker it happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Route {
    Poll,
    Heartbeat,
    Compile,
    Download,
    Execute,
    EventMonitor,
    Keystore,
    GuestHttp,
}

impl Route {
    pub const ALL: [Route; 8] = [
        Route::Poll, Route::Heartbeat, Route::Compile, Route::Download,
        Route::Execute, Route::EventMonitor, Route::Keystore, Route::GuestHttp,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Route::Poll => "poll",
            Route::Heartbeat => "heartbeat",
            Route::Compile => "compile",
            Route::Download => "download",
            Route::Execute => "execute",
            Route::EventMonitor => "event_monitor",
            Route::Keystore => "keystore",
            Route::GuestHttp => "guest_http",
        }
    }
}

/// Declares [`Code`], its wire names and [`Code::ALL`] from one list, so the three cannot drift.
macro_rules! codes {
    ($($(#[$doc:meta])* $variant:ident => $name:literal,)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Code {
            $($(#[$doc])* $variant,)*
        }

        impl Code {
            pub const ALL: &'static [Code] = &[$(Code::$variant,)*];

            /// The name the coordinator knows this code by. Its severity and kind are the
            /// coordinator's to assign (`WORKER_CODES` in its `handlers/ops_events.rs`): a worker
            /// report carries no claim about how bad it is.
            pub fn name(self) -> &'static str {
                match self {
                    $(Code::$variant => $name,)*
                }
            }
        }
    };
}

codes! {
    /// A guest repository did not build.
    CompileFailed => "compile_failed",
    /// A guest ran and failed (trap, limits, output that is not the declared format).
    WasmExecFailed => "wasm_exec_failed",
    /// A job did not run: its binary did not load, or the host failed around the run.
    ExecutionError => "execution_error",
    /// The coordinator's WASM cache did not hand over a binary.
    DownloadFailed => "download_failed",
    /// A caller's `wasm_url` did not answer with the file.
    WasmUrlUnavailable => "wasm_url_unavailable",
    /// A caller's `wasm_url` served bytes whose hash is not the declared one.
    WasmUrlHashMismatch => "wasm_url_hash_mismatch",
    /// A cached binary no longer hashes to what was recorded when it was stored: corrupted on disk
    /// or rewritten (a P2 guest can see the cache when it lives under `/tmp`). Never served.
    WasmCacheTampered => "wasm_cache_tampered",
    /// A block the event monitor needs could not be read.
    RpcUnreadableBlock => "rpc_unreadable_block",
    /// Contract events the event monitor gave up on: never delivered.
    EventsAbandoned => "events_abandoned",
    /// The coordinator could not be polled for work.
    MainLoopFailed => "main_loop_failed",
    /// An iteration of the main loop ran past its timeout and was abandoned.
    MainLoopStalled => "main_loop_stalled",
    /// The coordinator refused this worker's credentials (401/403).
    CoordinatorAuthRefused => "coordinator_auth_refused",
    /// No keystore instance answered, or the one asked never replied.
    KeystoreUnreachable => "keystore_unreachable",
    /// A keystore refused this worker a TEE session.
    KeystoreSessionFailed => "keystore_session_failed",
    /// A keystore answered 5xx.
    KeystoreServerError => "keystore_server_error",
    /// A guest tried to reach an internal / private / link-local address (once per run).
    GuestPrivateDestination => "guest_private_destination",
    /// A guest tried a host its manifest does not allow (once per run).
    GuestEgressNotAllowed => "guest_egress_not_allowed",
    /// A guest's HTTP requests kept timing out and the run was ended for it (the run itself is
    /// also counted, as `wasm_exec_failed`).
    GuestHttpTimeouts => "guest_http_timeouts",
}

/// A report carries one event per (code, route), and the coordinator refuses one with more than
/// 500 (`MAX_EVENTS_PER_REPORT`): the enums keep the map under that with no cap of its own.
const _: () = assert!(Code::ALL.len() * Route::ALL.len() <= 500);

/// The counts since the last report that went through. No times: the coordinator stamps a
/// report with the time it arrives, so a report that waited (a failed send put back) lands where
/// readers look for new rows, and the worker's clock is never trusted.
#[derive(Debug, Default)]
pub struct Tally {
    counters: HashMap<(Code, Route), u64>,
}

impl Tally {
    fn add(&mut self, key: (Code, Route), count: u64) {
        let c = self.counters.entry(key).or_default();
        *c = (*c + count).min(MAX_COUNT);
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    /// The events as the coordinator's `POST /workers/ops-events` reads them.
    pub fn events(&self) -> Vec<WireEvent> {
        let mut out: Vec<WireEvent> = self
            .counters
            .iter()
            .map(|(&(code, route), &count)| WireEvent { code: code.name(), route: route.as_str(), count })
            .collect();
        out.sort_by(|a, b| a.code.cmp(b.code).then(a.route.cmp(b.route)));
        out
    }
}

/// One event of a report (the coordinator's `WorkerEvent`).
#[derive(Debug, Serialize)]
pub struct WireEvent {
    pub code: &'static str,
    pub route: &'static str,
    pub count: u64,
}

/// A whole report (the coordinator's `WorkerReport`).
#[derive(Debug, Serialize)]
pub struct WireReport<'a> {
    pub worker_name: &'a str,
    pub worker_type: &'a str,
    pub events: Vec<WireEvent>,
}

static TALLY: LazyLock<Mutex<Tally>> = LazyLock::new(|| Mutex::new(Tally::default()));

fn lock() -> std::sync::MutexGuard<'static, Tally> {
    TALLY.lock().unwrap_or_else(|p| p.into_inner())
}

/// Count one occurrence of `code` in `route`.
pub fn record(code: Code, route: Route) {
    lock().add((code, route), 1);
}

/// Everything counted since the last report; the tally starts empty again.
pub fn take() -> Tally {
    std::mem::take(&mut *lock())
}

/// Put back a report that did not go through: it rides with the next one.
pub fn restore(unsent: Tally) {
    let mut tally = lock();
    for (key, count) in unsent.counters {
        tally.add(key, count);
    }
}

/// Whether the coordinator accepts this worker name in a report
/// (`[a-z0-9_.-]{1,64}`, its `is_token`).
pub fn reportable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_and_route_is_a_token_the_coordinator_accepts() {
        for code in Code::ALL {
            let name = code.name();
            assert!(!name.is_empty() && name.len() <= 64, "{name}");
            assert!(name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'), "{name}");
        }
        for route in Route::ALL {
            assert!(route.as_str().chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
        let names: std::collections::HashSet<_> = Code::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(names.len(), Code::ALL.len(), "two codes share a name");
    }

    /// The same file is in outlayer-coordinator `src/handlers/fixtures/`, where the coordinator's
    /// `WORKER_CODES` must classify exactly these: a code added on one side only breaks a test.
    #[test]
    fn every_code_is_one_the_coordinator_classifies() {
        let theirs: Vec<String> =
            serde_json::from_str(include_str!("testdata/ops_events_worker_codes.json")).unwrap();
        let mut ours: Vec<&str> = Code::ALL.iter().map(|c| c.name()).collect();
        ours.sort_unstable();
        let mut theirs_sorted: Vec<&str> = theirs.iter().map(String::as_str).collect();
        theirs_sorted.sort_unstable();
        assert_eq!(ours, theirs_sorted);
    }

    #[test]
    fn same_key_adds() {
        let mut t = Tally::default();
        for _ in 0..3 {
            t.add((Code::DownloadFailed, Route::Download), 1);
        }
        t.add((Code::DownloadFailed, Route::Execute), 1);
        let e = t.events();
        assert_eq!(e.len(), 2);
        assert_eq!((e[0].route, e[0].count), ("download", 3));
        assert_eq!((e[1].route, e[1].count), ("execute", 1));
    }

    #[test]
    fn a_failed_report_comes_back_merged() {
        let mut unsent = Tally::default();
        unsent.add((Code::DownloadFailed, Route::Download), 2);
        let mut now = Tally::default();
        now.add((Code::DownloadFailed, Route::Download), 1);
        for (k, c) in unsent.counters {
            now.add(k, c);
        }
        let e = now.events();
        assert_eq!((e.len(), e[0].count), (1, 3));
    }

    #[test]
    fn counts_stop_at_the_coordinators_cap() {
        let mut t = Tally::default();
        t.add((Code::MainLoopFailed, Route::Poll), MAX_COUNT - 1);
        t.add((Code::MainLoopFailed, Route::Poll), MAX_COUNT - 1);
        assert_eq!(t.events()[0].count, MAX_COUNT);
    }

    /// The same file is in outlayer-coordinator `src/handlers/fixtures/`, where
    /// the coordinator's `WorkerReport` must accept it: a shape change on either
    /// side breaks one of the two tests.
    #[test]
    fn report_matches_the_coordinators_fixture() {
        let mut t = Tally::default();
        t.add((Code::DownloadFailed, Route::Download), 3);
        t.add((Code::GuestPrivateDestination, Route::GuestHttp), 1);
        let report = WireReport {
            worker_name: "testnet-downloader-node1",
            worker_type: "downloader",
            events: t.events(),
        };
        let ours = serde_json::to_value(&report).unwrap();
        let theirs: serde_json::Value =
            serde_json::from_str(include_str!("testdata/ops_events_worker_report.json")).unwrap();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn names_the_coordinator_refuses_are_not_reported() {
        assert!(reportable_name("mainnet-executor-88d7a47d95ab002c7aacc65b20a42629ffef814c"));
        assert!(reportable_name("testnet-downloader-node1"));
        assert!(!reportable_name(""));
        assert!(!reportable_name("Mainnet-executor"));
        assert!(!reportable_name(&"a".repeat(65)));
    }
}
