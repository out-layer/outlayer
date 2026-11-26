//! Refusals of bearer tokens, counted for the whole keystore.
//!
//! Every client of a keystore is ours (the coordinator, the workers) and holds a valid token, so
//! a refused token is never an honest mistake for long: it is a forgotten deployment with a
//! retired token, or someone guessing. A keystore cannot tell its clients apart (behind the dstack
//! gateway, which passes TLS through, every connection comes from the gateway), so the count is
//! global. A valid token is checked first and always passes; only refusals are counted, so no
//! number of them can lock our own clients out.
//!
//! Past `THRESHOLD` refusals within `WINDOW`, the keystore is in lockout for `FIRST_LOCKOUT`.
//! From then on every refusal — during that lockout or after it — puts it in lockout for
//! `REPEAT_LOCKOUT`, counted from that refusal. In lockout a refusal is answered at once, the same
//! for every cause, and not logged one by one: the log gets one summary per `WINDOW`. The answer
//! names no number and no window. The count lives in memory and starts over with the keystore.

use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const WINDOW: Duration = Duration::from_secs(10 * 60);
pub const THRESHOLD: u32 = 3;
pub const FIRST_LOCKOUT: Duration = Duration::from_secs(60 * 60);
pub const REPEAT_LOCKOUT: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Default)]
struct State {
    window_start: Option<Instant>,
    in_window: u32,
    locked_until: Option<Instant>,
    /// A lockout has happened since the keystore started: every refusal from now on is a repeat.
    struck: bool,
    /// Refusals not logged one by one since the last summary.
    unlogged: u64,
    last_summary: Option<Instant>,
}

/// What to do with one refusal.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Log it and answer 401, as for any refused token.
    Logged,
    /// In lockout: answer 429 and do not log it. `summary` carries the count of refusals since
    /// the last summary when one is due now.
    Quiet { summary: Option<u64> },
}

#[derive(Debug, Default)]
pub struct AuthGuard {
    state: Mutex<State>,
    total: std::sync::atomic::AtomicU64,
}

impl AuthGuard {
    /// Whether the keystore is in lockout: a request without a valid token is refused at once.
    #[cfg(test)]
    pub fn locked(&self, now: Instant) -> bool {
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        s.locked_until.map_or(false, |t| now < t)
    }

    /// Count one refusal at `now` and say how to answer it.
    pub fn refused(&self, now: Instant) -> Refusal {
        self.total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut s = self.state.lock().unwrap_or_else(|p| p.into_inner());

        if s.struck {
            s.locked_until = Some(now + REPEAT_LOCKOUT);
            s.unlogged += 1;
            let due = s.last_summary.map_or(true, |t| now.duration_since(t) >= WINDOW);
            let summary = if due {
                s.last_summary = Some(now);
                Some(std::mem::take(&mut s.unlogged))
            } else {
                None
            };
            return Refusal::Quiet { summary };
        }

        match s.window_start {
            Some(start) if now.duration_since(start) < WINDOW => s.in_window += 1,
            _ => {
                s.window_start = Some(now);
                s.in_window = 1;
            }
        }
        if s.in_window > THRESHOLD {
            s.struck = true;
            s.locked_until = Some(now + FIRST_LOCKOUT);
            s.unlogged = 0;
            s.last_summary = Some(now);
            return Refusal::Quiet { summary: Some(1) };
        }
        Refusal::Logged
    }

    /// Refusals since the keystore started.
    pub fn total(&self) -> u64 {
        self.total.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t: Instant, secs: u64) -> Instant {
        t + Duration::from_secs(secs)
    }

    #[test]
    fn up_to_the_threshold_every_refusal_is_logged() {
        let g = AuthGuard::default();
        let t = Instant::now();
        for i in 0..THRESHOLD {
            assert_eq!(g.refused(at(t, i as u64)), Refusal::Logged);
        }
        assert!(!g.locked(at(t, 10)));
    }

    #[test]
    fn one_more_within_the_window_locks_for_an_hour() {
        let g = AuthGuard::default();
        let t = Instant::now();
        for _ in 0..THRESHOLD {
            g.refused(t);
        }
        assert_eq!(g.refused(t), Refusal::Quiet { summary: Some(1) });
        assert!(g.locked(t + FIRST_LOCKOUT - Duration::from_secs(1)));
        assert!(!g.locked(t + FIRST_LOCKOUT));
    }

    #[test]
    fn after_the_first_lockout_one_refusal_locks_for_a_day() {
        let g = AuthGuard::default();
        let t = Instant::now();
        for _ in 0..=THRESHOLD {
            g.refused(t);
        }
        // Long after the hour: one refusal is enough.
        let later = t + FIRST_LOCKOUT + Duration::from_secs(3 * 3600);
        assert!(!g.locked(later));
        assert!(matches!(g.refused(later), Refusal::Quiet { .. }));
        assert!(g.locked(later + REPEAT_LOCKOUT - Duration::from_secs(1)));
        assert!(!g.locked(later + REPEAT_LOCKOUT));
    }

    #[test]
    fn a_refusal_during_the_first_lockout_turns_it_into_a_day() {
        let g = AuthGuard::default();
        let t = Instant::now();
        for _ in 0..=THRESHOLD {
            g.refused(t);
        }
        g.refused(at(t, 60));
        assert!(g.locked(t + FIRST_LOCKOUT + Duration::from_secs(3600)));
        assert!(g.locked(at(t, 60) + REPEAT_LOCKOUT - Duration::from_secs(1)));
    }

    #[test]
    fn refusals_in_lockout_are_summarised_once_per_window() {
        let g = AuthGuard::default();
        let t = Instant::now();
        for _ in 0..=THRESHOLD {
            g.refused(t);
        }
        assert_eq!(g.refused(at(t, 5)), Refusal::Quiet { summary: None });
        assert_eq!(g.refused(at(t, 6)), Refusal::Quiet { summary: None });
        assert_eq!(g.refused(t + WINDOW + Duration::from_secs(7)), Refusal::Quiet { summary: Some(3) });
        assert_eq!(g.total(), THRESHOLD as u64 + 4);
    }

    #[test]
    fn refusals_spread_over_windows_do_not_lock() {
        let g = AuthGuard::default();
        let t = Instant::now();
        for w in 0..4u32 {
            for _ in 0..THRESHOLD {
                assert_eq!(g.refused(t + WINDOW * w), Refusal::Logged);
            }
        }
        assert!(!g.locked(t + WINDOW * 4));
    }
}
