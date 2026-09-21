//! The owner's rules for what the agent may do with their GitHub account.
//!
//! This is the whole reason the connector exists rather than handing an agent a
//! token. The agent acts AS the owner — its issues, comments, commits and
//! reviews carry the owner's name — and it reads text strangers wrote, which is
//! how an agent gets talked into things. So the owner says which actions, in
//! which repositories, on which branches and paths, and how many writes a day;
//! the connector enforces it inside the enclave, before anything reaches GitHub.
//!
//! Fail-closed, and more so than a mail policy: with no policy only `status`
//! runs, because READING a private repository is already a disclosure. A policy
//! this build cannot read refuses everything too — an unknown field is a parse
//! error, not something to ignore, because the field somebody added is probably
//! the restriction they cared about.
//!
//! What GitHub enforces by itself, through the app's permissions, is not
//! repeated here: repositories outside the installation, workflow files,
//! repository settings. What GitHub would ALLOW and the owner did not is this
//! module's job, and four refusals have no other guard at all: a public gist, a
//! write under `.github/`, a merge, and an approval.

use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

pub const POLICY_ENV: &str = "GITHUB_POLICY";

/// Appended to every text the agent posts under the owner's name, unless the
/// owner chose their own or blanked it. Those texts are otherwise
/// indistinguishable from the owner's own words.
pub const DEFAULT_MARKER: &str = "\n\n— posted by an AI agent via OutLayer";

/// Files in one commit. Not a policy field — the owner has nothing to decide
/// here, since a commit is atomic and one of fifty files is no more dangerous
/// than one of five. It is a run's budget: text rides in the tree itself, but a
/// binary file is a request of its own, and a run has a fixed time to live.
pub const MAX_FILES_PER_COMMIT: usize = 50;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Operations the agent may run, by name, or `["any"]`. Absent: none.
    pub actions: Option<Vec<String>>,
    /// Repositories, as `owner/name` or `owner/*`, or `["any"]`. Absent: none.
    /// Narrows what the app's installation already allows; it cannot widen it.
    pub repos: Option<Vec<String>>,
    /// Branches the agent may write files to and open pull requests from, e.g.
    /// `["agent/*"]`. Absent: no file writes. A repository's default branch is
    /// writable only when named literally — a pattern never reaches it.
    pub branches: Option<Vec<String>>,
    /// Paths the agent may write, e.g. `["docs/*"]`. Absent: any path that is
    /// not always refused.
    pub paths: Option<Vec<String>>,
    /// Writes a day, all write operations together, counted per calling wallet
    /// in UTC days. Required for any write: a policy that allows writing without
    /// saying how much allows a loop to open a thousand issues in the owner's name.
    pub max_writes_per_day: Option<u32>,
    /// Whether `pr_merge` is allowed at all. Absent: no.
    pub allow_merge: Option<bool>,
    /// Whether `pr_review` may APPROVE. Absent: no — an approval in the owner's
    /// name can satisfy a branch protection rule.
    pub allow_approve: Option<bool>,
    /// Whether a gist may be public. Absent: secret gists only.
    pub allow_public_gists: Option<bool>,
    /// Replaces [`DEFAULT_MARKER`]; an empty string posts without one.
    pub marker: Option<String>,
}

pub enum Loaded {
    None,
    Unreadable(String),
    Some(Policy),
}

pub fn load() -> Loaded {
    match std::env::var(POLICY_ENV) {
        Err(_) => Loaded::None,
        Ok(raw) if raw.trim().is_empty() || raw.trim() == "{}" => Loaded::None,
        Ok(raw) => match serde_json::from_str::<Policy>(&raw) {
            Ok(p) => Loaded::Some(p),
            Err(e) => Loaded::Unreadable(e.to_string()),
        },
    }
}

/// Where the owner sets or changes the policy. Named in every refusal that only
/// the owner can lift, so an agent can tell its owner what to do.
pub const OWNER_PAGE: &str = "https://app.outlayer.ai/connect/github";

pub fn require() -> Result<Policy, String> {
    match load() {
        Loaded::Some(p) => Ok(p),
        Loaded::None => Err(format!(
            "policy_missing: the owner has stored no policy, and without one only `status` runs. \
             The owner sets it at {OWNER_PAGE}"
        )),
        Loaded::Unreadable(e) => Err(format!(
            "policy_unreadable: the stored policy is not one this connector understands ({e}), so \
             nothing is allowed. The owner fixes it at {OWNER_PAGE}"
        )),
    }
}

/// `*` matches any run of characters, `/` included; there is no other wildcard.
/// One rule for repositories, branches and paths, so an owner learns it once.
pub fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) = (pattern.chars().collect(), text.chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

fn is_any(list: &[String]) -> bool {
    list.iter().any(|e| e.trim().eq_ignore_ascii_case("any"))
}

impl Policy {
    pub fn check_action(&self, operation: &str) -> Result<(), String> {
        let allowed = self.actions.as_deref().unwrap_or(&[]);
        if is_any(allowed) || allowed.iter().any(|a| a.trim() == operation) {
            return Ok(());
        }
        Err(format!(
            "policy_denied: the owner's policy does not allow `{operation}`. Allowed: {}",
            if allowed.is_empty() { "nothing".to_string() } else { allowed.join(", ") }
        ))
    }

    /// GitHub compares names without regard to case, so this does too.
    pub fn check_repo(&self, repo: &str) -> Result<(), String> {
        let allowed = self.repos.as_deref().unwrap_or(&[]);
        let wanted = repo.to_ascii_lowercase();
        if is_any(allowed) || allowed.iter().any(|r| glob(&r.trim().to_ascii_lowercase(), &wanted)) {
            return Ok(());
        }
        Err(format!("policy_denied: the owner's policy does not cover the repository `{repo}`"))
    }

    pub fn allows_repo(&self, repo: &str) -> bool {
        self.check_repo(repo).is_ok()
    }

    /// Whether `branch` may be written, and whether that rests on a PATTERN. A
    /// branch allowed only by a pattern must still be shown not to be the
    /// repository's default branch — see [`Policy::check_not_default`].
    pub fn check_branch(&self, branch: &str) -> Result<BranchMatch, String> {
        let allowed = self.branches.as_deref().unwrap_or(&[]);
        if allowed.iter().any(|b| b.trim() == branch) {
            return Ok(BranchMatch::Literal);
        }
        if allowed.iter().any(|b| b.contains('*') && glob(b.trim(), branch)) {
            return Ok(BranchMatch::Pattern);
        }
        Err(format!(
            "policy_denied: the owner's policy does not allow writing to the branch `{branch}`. Writable: {}",
            if allowed.is_empty() { "none".to_string() } else { allowed.join(", ") }
        ))
    }

    pub fn check_not_default(matched: BranchMatch, branch: &str, default_branch: &str) -> Result<(), String> {
        if matched == BranchMatch::Pattern && branch == default_branch {
            return Err(format!(
                "policy_denied: `{branch}` is this repository's default branch, and a pattern never \
                 reaches it — the owner has to name it literally in `branches`"
            ));
        }
        Ok(())
    }

    pub fn check_path(&self, path: &str) -> Result<(), String> {
        clean_path(path)?;
        if let Some(allowed) = self.paths.as_deref() {
            if !is_any(allowed) && !allowed.iter().any(|p| glob(p.trim(), path)) {
                return Err(format!(
                    "policy_denied: the owner's policy does not allow writing `{path}`. Writable: {}",
                    allowed.join(", ")
                ));
            }
        }
        Ok(())
    }

    pub fn check_merge(&self) -> Result<(), String> {
        if self.allow_merge == Some(true) {
            return Ok(());
        }
        Err("policy_denied: the owner's policy does not allow merging (`allow_merge`)".to_string())
    }

    pub fn check_approve(&self) -> Result<(), String> {
        if self.allow_approve == Some(true) {
            return Ok(());
        }
        Err("policy_denied: the owner's policy does not allow approving in their name \
             (`allow_approve`); a review may COMMENT or REQUEST_CHANGES"
            .to_string())
    }

    pub fn check_public_gist(&self, public: bool) -> Result<(), String> {
        if !public || self.allow_public_gists == Some(true) {
            return Ok(());
        }
        Err("policy_denied: the owner's policy allows secret gists only (`allow_public_gists`)".to_string())
    }

    /// `text` with the marker on the end, once.
    pub fn mark(&self, text: &str) -> String {
        let marker = self.marker.as_deref().unwrap_or(DEFAULT_MARKER);
        if marker.trim().is_empty() || text.trim_end().ends_with(marker.trim()) {
            return text.to_string();
        }
        format!("{}{}", text.trim_end(), marker)
    }

    /// A place in today's write budget, or the refusal.
    pub fn reserve_write(&self) -> Result<(Reservation, u32), String> {
        let cap = self.max_writes_per_day.ok_or_else(|| {
            format!(
                "policy_denied: the owner's policy sets no `max_writes_per_day`, and without it \
                 nothing is written. The owner sets it at {OWNER_PAGE}"
            )
        })?;
        reserve(&day_key(now_ms()), cap)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchMatch {
    Literal,
    Pattern,
}

/// A path the Contents and Git Data APIs will read the way it is written, and
/// not one under `.github/`.
///
/// `.github/` is refused whatever the policy says. GitHub itself refuses
/// workflow files to this app, but not the rest of the directory, and
/// `CODEOWNERS`, issue templates and Dependabot's configuration all change who
/// reviews and what runs. An owner who wants them changed changes them.
pub fn clean_path(path: &str) -> Result<(), String> {
    let bad = |why: &str| Err(format!("invalid: the path `{path}` {why}"));
    if path.is_empty() || path.len() > 1024 {
        return bad("is empty or too long");
    }
    if path.starts_with('/') || path.ends_with('/') || path.contains('\\') || path.contains("//") {
        return bad("must be relative, with `/` between segments and nothing else");
    }
    if path.chars().any(|c| c.is_control()) {
        return bad("holds a control character");
    }
    for segment in path.split('/') {
        if segment == "." || segment == ".." || segment.eq_ignore_ascii_case(".git") {
            return bad("holds a `.`, `..` or `.git` segment");
        }
    }
    if path.split('/').next().map(|s| s.eq_ignore_ascii_case(".github")).unwrap_or(false) {
        return Err(format!(
            "policy_denied: `{path}` is under `.github/`, which this connector never writes — it decides \
             who reviews and what runs. The owner changes it themselves"
        ));
    }
    Ok(())
}

/// `owner/name`, in the characters GitHub allows.
pub fn clean_repo(repo: &str) -> Result<(), String> {
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 100
            && s != "."
            && s != ".."
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    };
    match repo.split_once('/') {
        Some((owner, name)) if ok(owner) && ok(name) && !name.contains('/') => Ok(()),
        _ => Err(format!("invalid: `repo` must be `owner/name`, got `{repo}`")),
    }
}

/// A branch name that can sit in a URL unescaped and cannot climb out of `refs/heads/`.
pub fn clean_branch(branch: &str) -> Result<(), String> {
    let ok = !branch.is_empty()
        && branch.len() <= 200
        && !branch.starts_with('/')
        && !branch.ends_with('/')
        && !branch.starts_with('-')
        && !branch.contains("..")
        && !branch.contains("//")
        && !branch.ends_with(".lock")
        && branch.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid: the branch `{branch}` must be letters, digits, `-`, `_`, `.` and `/`, with no `..`"
        ))
    }
}

// ==================== the day's count ====================

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// `YYYY-MM-DD` in UTC for a millisecond timestamp.
pub fn day_key(ms: u64) -> String {
    let days = (ms / 86_400_000) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// The day's count, touched only through `storage::increment` — which the SDK
/// documents as atomic (compare-and-swap with retries). Never read and then
/// written back: two calls of one agent can run at once, and a read-then-write
/// lets both see room for one more write.
fn key(day: &str) -> String {
    format!("gh:writes:{day}")
}

/// How the day's count is changed: the storage primitive in a run, a stand-in in
/// the tests. A plain function pointer, so a reservation can carry it into `Drop`.
type Bump = fn(&str, i64) -> Result<i64, String>;

fn storage_bump(key: &str, delta: i64) -> Result<i64, String> {
    ::outlayer::storage::increment(key, delta).map_err(|e| e.to_string())
}

/// Writes counted today, including any a call in flight has reserved.
pub fn writes_today() -> Result<u32, String> {
    let count = storage_bump(&key(&day_key(now_ms())), 0)
        .map_err(|e| format!("the day's write count could not be read: {e}"))?;
    Ok(count.max(0) as u32)
}

/// One write's place in today's budget, taken BEFORE GitHub is asked.
///
/// Reserve first, settle after — how the platform treats money too. The
/// reservation is released when it is dropped without being kept, so every early
/// return between here and a write GitHub accepted gives the place back, and the
/// owner's budget is spent only by writes that happened.
pub struct Reservation {
    key: String,
    kept: bool,
    bump: Bump,
}

impl Reservation {
    /// GitHub accepted the write: the place stays taken.
    pub fn keep(mut self) {
        self.kept = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.kept {
            // A release that fails leaves the count one too high, which refuses
            // a write rather than allowing one: the safe direction.
            let _ = (self.bump)(&self.key, -1);
        }
    }
}

pub fn reserve(day: &str, max_per_day: u32) -> Result<(Reservation, u32), String> {
    reserve_with(storage_bump, day, max_per_day)
}

fn reserve_with(bump: Bump, day: &str, max_per_day: u32) -> Result<(Reservation, u32), String> {
    let key = key(day);
    let after = bump(&key, 1).map_err(|e| format!("the day's write count could not be updated: {e}"))?;
    let reservation = Reservation { key, kept: false, bump };
    if after > max_per_day as i64 {
        drop(reservation);
        return Err(format!(
            "policy_denied: {} of the owner's {max_per_day} writes a day are used; this one would pass it",
            after - 1
        ));
    }
    Ok((reservation, after as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn policy(json: &str) -> Policy {
        serde_json::from_str(json).expect("the test policy must parse")
    }

    #[test]
    fn a_star_matches_any_run_and_nothing_else_is_special() {
        assert!(glob("agent/*", "agent/fix-1"));
        assert!(glob("agent/*", "agent/a/b"), "`/` is just a character");
        assert!(glob("docs/*.md", "docs/guide/intro.md"));
        assert!(glob("*", "main"));
        assert!(!glob("agent/*", "agents/x"));
        assert!(!glob("agent/*", "agent"));
        assert!(!glob("docs/?", "docs/a"), "`?` is a literal question mark");
        assert!(glob("a*b*c", "a-x-b-y-c") && !glob("a*b*c", "a-x-c"));
    }

    #[test]
    fn a_field_nobody_knows_is_a_refusal_not_a_shrug() {
        let err = serde_json::from_str::<Policy>(r#"{"actions":["any"],"repositories":["a/b"]}"#).unwrap_err();
        assert!(err.to_string().contains("repositories"), "{err}");
    }

    #[test]
    fn nothing_is_allowed_that_was_not_named() {
        let p = policy("{}");
        assert!(p.check_action("issue_list").is_err(), "reading is a disclosure too");
        assert!(p.check_repo("a/b").is_err());
        assert!(p.check_branch("agent/x").is_err());
        assert!(p.check_merge().is_err() && p.check_approve().is_err());
        assert!(p.check_public_gist(true).is_err() && p.check_public_gist(false).is_ok());
    }

    #[test]
    fn actions_are_exact_names_or_any() {
        let p = policy(r#"{"actions":["issue_create","file_get"]}"#);
        assert!(p.check_action("issue_create").is_ok());
        assert!(p.check_action("issue_comment").is_err(), "a prefix is not a grant");
        assert!(policy(r#"{"actions":["any"]}"#).check_action("pr_merge").is_ok());
    }

    #[test]
    fn repositories_compare_the_way_github_does() {
        let p = policy(r#"{"repos":["Out-Layer/*","alice/site"]}"#);
        assert!(p.check_repo("out-layer/cli").is_ok());
        assert!(p.check_repo("ALICE/Site").is_ok());
        assert!(p.check_repo("alice/site-backup").is_err());
        assert!(p.check_repo("out-layerx/cli").is_err());
    }

    /// The four refusals nothing but this module makes: GitHub accepts every one
    /// of these writes from the app's token.
    #[test]
    fn what_github_would_allow_and_the_owner_did_not() {
        let open = policy(r#"{"actions":["any"],"repos":["any"],"branches":["*"],"paths":["any"],"max_writes_per_day":100}"#);
        for path in [".github/CODEOWNERS", ".GitHub/dependabot.yml", ".github/workflows/ci.yml", ".github/ISSUE_TEMPLATE/x.md"] {
            let err = open.check_path(path).unwrap_err();
            assert!(err.starts_with("policy_denied") && err.contains(".github/"), "{path} → {err}");
        }
        assert!(open.check_public_gist(true).is_err());
        assert!(open.check_merge().is_err());
        assert!(open.check_approve().is_err());
    }

    #[test]
    fn a_pattern_never_reaches_the_default_branch() {
        let p = policy(r#"{"branches":["*","release"]}"#);
        let by_pattern = p.check_branch("main").unwrap();
        assert_eq!(by_pattern, BranchMatch::Pattern);
        assert!(Policy::check_not_default(by_pattern, "main", "main").is_err());
        assert!(Policy::check_not_default(by_pattern, "agent/x", "main").is_ok());
        // Named literally, the owner meant it — even when it is the default.
        let literal = p.check_branch("release").unwrap();
        assert_eq!(literal, BranchMatch::Literal);
        assert!(Policy::check_not_default(literal, "release", "release").is_ok());
    }

    #[test]
    fn paths_stay_inside_the_repository() {
        let p = policy(r#"{"paths":["docs/*"]}"#);
        assert!(p.check_path("docs/a.md").is_ok());
        assert!(p.check_path("src/a.rs").is_err());
        for bad in ["", "/etc/passwd", "docs/../.github/x", "docs//a", "docs\\a", "a/.git/config", "docs/", "./a"] {
            assert!(p.check_path(bad).is_err(), "`{bad}` must be refused");
        }
        assert!(policy("{}").check_path("anything/at/all.txt").is_ok(), "no `paths` narrows nothing");
    }

    #[test]
    fn names_that_go_into_a_url_are_plain() {
        assert!(clean_repo("out-layer/outlayer").is_ok());
        for bad in ["outlayer", "a/b/c", "a/", "/b", "a/b?x=1", "a/..", "a b/c"] {
            assert!(clean_repo(bad).is_err(), "`{bad}`");
        }
        assert!(clean_branch("agent/fix-1.2").is_ok());
        for bad in ["", "/a", "a/", "a..b", "a//b", "-a", "a b", "a?b", "a.lock", "refs/../x"] {
            assert!(clean_branch(bad).is_err(), "`{bad}`");
        }
    }

    #[test]
    fn the_marker_goes_on_once() {
        let p = policy("{}");
        let once = p.mark("hello");
        assert!(once.ends_with(DEFAULT_MARKER.trim_start_matches('\n')) && once.starts_with("hello"));
        assert_eq!(p.mark(&once), once, "a text that already carries it is left alone");
        assert_eq!(policy(r#"{"marker":""}"#).mark("hello"), "hello");
        assert_eq!(policy(r#"{"marker":"\n\n~bot"}"#).mark("hi"), "hi\n\n~bot");
    }

    #[test]
    fn writing_needs_a_number() {
        let err = policy(r#"{"actions":["any"]}"#).reserve_write().err().unwrap();
        assert!(err.contains("max_writes_per_day"), "{err}");
    }

    thread_local! { static COUNT: Cell<i64> = const { Cell::new(0) }; }
    fn fake_bump(_key: &str, delta: i64) -> Result<i64, String> {
        COUNT.with(|c| {
            c.set(c.get() + delta);
            Ok(c.get())
        })
    }

    /// A write GitHub refused gives its place back; one it accepted keeps it.
    #[test]
    fn only_writes_that_happened_are_counted() {
        COUNT.with(|c| c.set(0));
        let (first, used) = reserve_with(fake_bump, "2026-09-20", 2).unwrap();
        assert_eq!(used, 1);
        drop(first); // GitHub said no
        assert_eq!(COUNT.with(Cell::get), 0);

        let (a, _) = reserve_with(fake_bump, "2026-09-20", 2).unwrap();
        a.keep();
        let (b, used) = reserve_with(fake_bump, "2026-09-20", 2).unwrap();
        b.keep();
        assert_eq!(used, 2);
        let err = reserve_with(fake_bump, "2026-09-20", 2).err().unwrap();
        assert!(err.contains("2 of the owner's 2"), "{err}");
        assert_eq!(COUNT.with(Cell::get), 2, "the refused third gave its place back");
    }

    #[test]
    fn days_are_utc_calendar_days() {
        assert_eq!(day_key(0), "1970-01-01");
        assert_eq!(day_key(1_789_862_400_000), "2026-09-20");
    }

    /// The field is gone, and a policy carrying it is refused like any other
    /// key this build does not know — silently ignoring it would leave an owner
    /// believing a limit is in force.
    #[test]
    fn the_old_per_commit_field_is_not_quietly_accepted() {
        let err = serde_json::from_str::<Policy>(r#"{"actions":["any"],"max_files_per_commit":5}"#).unwrap_err();
        assert!(err.to_string().contains("max_files_per_commit"), "{err}");
    }
}
