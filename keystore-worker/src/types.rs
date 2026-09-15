//! Access control types for validating secrets access
//!
//! Adapted from contract types for use in keystore validation

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogicOperator {
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComparisonOperator {
    #[serde(rename = "Gte")]
    Gte, // >=
    #[serde(rename = "Lte")]
    Lte, // <=
    #[serde(rename = "Gt")]
    Gt, // >
    #[serde(rename = "Lt")]
    Lt, // <
    #[serde(rename = "Eq")]
    Eq, // ==
    #[serde(rename = "Ne")]
    Ne, // !=
}

/// Access control conditions for secrets
/// Note: Matches NEAR SDK adjacently tagged enum format
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AccessCondition {
    /// Logical combination of conditions
    Logic {
        operator: LogicOperator,
        conditions: Vec<AccessCondition>,
    },
    /// Logical NOT
    Not {
        condition: Box<AccessCondition>,
    },
    /// Allow all accounts (no restrictions)
    AllowAll,
    /// Whitelist specific accounts
    Whitelist {
        accounts: Vec<String>,
    },
    /// Match the caller's account id against a regular expression.
    ///
    /// The pattern is matched against the WHOLE id (anchored `\A(?:…)\z` in
    /// [`compile_anchored_account_pattern`]), never a substring. Two regex
    /// facts still bite the unwary, so prefer [`AccessCondition::Whitelist`]
    /// for an exact set of accounts:
    ///   * `.` is a metacharacter — write `\.` for a literal dot, otherwise
    ///     `team.near` also admits `teamXnear`;
    ///   * a pattern is only as tight as it is written — `.*\.gov\.near`
    ///     admits every `*.gov.near`, which may be broader than intended.
    ///
    /// Example: `.*\.gov\.near` matches any `*.gov.near` account and only those.
    AccountPattern {
        pattern: String,
    },
    /// Require minimum NEAR balance (in yoctoNEAR)
    NearBalance {
        operator: ComparisonOperator,
        value: String, // u128 as string
    },
    /// Require minimum fungible token balance
    FtBalance {
        contract: String,
        operator: ComparisonOperator,
        value: String, // u128 as string
    },
    /// Require NFT ownership
    /// token_id: None = any token from this contract
    /// token_id: Some("123") = specific token ID
    NftOwned {
        contract: String,
        token_id: Option<String>,
    },
    /// Require DAO membership (Sputnik v2 compatible)
    /// Checks if caller is member of specified role in DAO
    /// role: "council", "members", etc.
    DaoMember {
        dao_contract: String,
        role: String,
    },
    /// Admit only until a moment in time: nanoseconds since the epoch, carried
    /// as a decimal string the way the contract writes its `U64`. Composed with
    /// the others — `And[Whitelist[agent], ValidUntil(t)]` is a grant that
    /// lapses on its own, `Not { ValidUntil }` reads as "valid after". Judged
    /// against this host's clock, the same machine trust the rest of custody
    /// rests on.
    ValidUntil {
        until_ns: String,
    },
}

/// Nanoseconds since the epoch, by this host's clock. A clock that reads
/// before the epoch cannot judge a time limit, and says so as an error —
/// which refuses at every combinator. A verdict either way would admit
/// somebody: "lapsed" admits everyone under `Not`, "live" admits every
/// dated grant.
fn now_ns() -> anyhow::Result<u64> {
    let since_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("the host clock reads before the epoch; no time limit can be judged"))?;
    Ok(since_epoch.as_nanos().min(u64::MAX as u128) as u64)
}

/// `ns` since the epoch as `YYYY-MM-DDTHH:MM:SSZ`, for a refusal a person reads.
/// Civil-from-days after Howard Hinnant; no calendar crate for one line of output.
pub fn iso8601_utc(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Compile an [`AccessCondition::AccountPattern`] into a FULL-MATCH regex.
///
/// The pattern is wrapped in `\A(?:…)\z`, so it must match the ENTIRE caller
/// id. Without this, `regex::Regex::is_match` succeeds on any partial match:
/// a pattern `team\.near`, written as an exact check, would also admit
/// `xteam.near`, `team.near.attacker.near`, or — because `.` is a
/// metacharacter — `teamXnear`. That is a silent whitelist bypass that hands
/// one account's secrets to another, so the anchoring is a security boundary,
/// not a nicety.
///
/// `\A` / `\z` (absolute start / end of text) are deliberate over `^` / `$`,
/// as belt and braces rather than because `^` / `$` are known to fail here.
/// Measured against this crate's `regex`, the two constructions agree on every
/// input tried, including the ones usually cited:
///
/// ```text
/// pattern            caller                    \A(?:..)\z   ^(?:..)$
/// team\.near         "team.near"               true         true
/// team\.near         "team.near\n"             false        false
/// (?m)^team\.near$   "evil.near\nteam.near"    false        false
/// ```
///
/// An owner's inline `(?m)` does NOT re-point our anchors: in Rust's `regex` a
/// flag applies from where it appears to the end of the ENCLOSING GROUP, and
/// ours sit outside `(?:…)`. Reaching them would mean closing that group, which
/// leaves an unbalanced pattern — invalid, and the caller treats a compile error
/// as denial.
///
/// So the absolute anchors buy insurance, not the guarantee itself: they cannot
/// be re-pointed by any future reading of inline flags, and they cost nothing.
/// Simplifying them to `^` / `$` would not open the hole today — but the
/// property this function exists for would then rest on where a flag happens to
/// take effect, which is not where a security boundary should rest.
/// See `test_a_second_line_never_satisfies_a_full_match`.
///
/// The wrapping group `(?:…)` is required so a top-level alternation binds
/// correctly: `a|b` becomes `\A(?:a|b)\z`, not `\Aa|b\z` ("starts with a" OR
/// "ends with b"). An owner's own anchors, if present, are preserved —
/// `\A(?:^team\.near$)\z` is a harmless double anchor. A pattern that is
/// invalid on its own is invalid wrapped too, and the caller treats a compile
/// error as denial (fail-closed); wrapping a VALID pattern can never make it
/// invalid.
fn compile_anchored_account_pattern(pattern: &str) -> Result<regex::Regex, regex::Error> {
    // Bounded: an account id is at most 64 bytes, and a pattern that needs
    // megabytes of program to match one is not a pattern for account ids. The
    // default limit (10 MiB per pattern) is what lets a row of a few
    // patterns like `\pL{200}` cost a gigabyte per decrypt.
    regex::RegexBuilder::new(&format!(r"\A(?:{})\z", pattern))
        .size_limit(shared_tee_helpers::access_limits::REGEX_SIZE_LIMIT)
        .dfa_size_limit(shared_tee_helpers::access_limits::REGEX_SIZE_LIMIT)
        .build()
}

/// An `AccountPattern` the engine will not compile, found while compiling a
/// condition's patterns before anything is evaluated. One anywhere in the
/// tree refuses the whole condition for everyone — the owner hears which
/// pattern, in so many bytes, and nobody is judged by a tree that cannot be
/// read. Carried as the ERROR of [`AccessCondition::validate`], so a caller
/// that evaluates without compiling first still cannot admit through it.
/// The pattern and the compiler's reason are clipped: the pattern is
/// owner-written, the reason quotes it, and the row bounds neither.
#[derive(Debug)]
pub struct UnreadablePattern {
    pub pattern: String,
    pub why: String,
}

impl UnreadablePattern {
    const CLIP: usize = 256;

    fn new(pattern: &str, error: &regex::Error) -> Self {
        // The compiler's message quotes the whole wrapped pattern with a caret
        // line under it; its last line is the reason ("error: unclosed group").
        let reason = error
            .to_string()
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .unwrap_or_default()
            .trim()
            .trim_start_matches("error: ")
            .to_string();
        Self { pattern: clip(pattern, Self::CLIP), why: clip(&reason, Self::CLIP) }
    }
}

impl std::fmt::Display for UnreadablePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Access denied by access condition: its AccountPattern `{}` cannot be compiled as a regular expression ({})",
            self.pattern, self.why
        )
    }
}

impl std::error::Error for UnreadablePattern {}

/// The first `max` bytes of `s` on a character boundary, with an ellipsis
/// when anything was cut.
fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Every `AccountPattern` of one condition, compiled once, keyed by its text.
/// Built before evaluation and handed to it, so a pattern is compiled exactly
/// once per decrypt however many branches name it and whichever the caller
/// reaches.
pub struct CompiledPatterns(std::collections::HashMap<String, regex::Regex>);

impl CompiledPatterns {
    fn get(&self, pattern: &str) -> Option<&regex::Regex> {
        self.0.get(pattern)
    }
}

impl AccessCondition {
    /// Every pattern in this tree, compiled. The first the engine will not
    /// compile is the error, wherever it sits: an unreadable leaf makes the
    /// whole condition unreadable, and a condition that cannot be read
    /// admits nobody — its owner fixes the row, and hears which pattern.
    pub fn compile_patterns(&self) -> Result<CompiledPatterns, UnreadablePattern> {
        let mut compiled = std::collections::HashMap::new();
        self.collect_patterns(&mut compiled)?;
        Ok(CompiledPatterns(compiled))
    }

    fn collect_patterns(&self, into: &mut std::collections::HashMap<String, regex::Regex>) -> Result<(), UnreadablePattern> {
        match self {
            AccessCondition::AccountPattern { pattern } => {
                if !into.contains_key(pattern) {
                    let re = compile_anchored_account_pattern(pattern).map_err(|e| UnreadablePattern::new(pattern, &e))?;
                    into.insert(pattern.clone(), re);
                }
                Ok(())
            }
            AccessCondition::Logic { conditions, .. } => conditions.iter().try_for_each(|c| c.collect_patterns(into)),
            AccessCondition::Not { condition } => condition.collect_patterns(into),
            _ => Ok(()),
        }
    }

    /// Validate access condition against caller account: compile every
    /// pattern, then evaluate.
    ///
    /// `Ok(true)` admits, `Ok(false)` denies. `Err` means the condition could
    /// not be evaluated — an `AccountPattern` the engine will not compile
    /// ([`UnreadablePattern`], refused before anything is evaluated, wherever
    /// it sits), a chain read that failed or has no client, a time limit that
    /// is not a number — and an error refuses at every combinator: `Not`
    /// propagates it rather than negating a guess, `And`/`Or` stop at it.
    /// Test-only, and deliberately so: it compiles and evaluates WITHOUT the
    /// bounds `judge_access` applies first, so a production caller reaching
    /// for it would be a door with no limit on how many patterns are compiled
    /// or how many times the chain is asked. The door is `judge_access`.
    #[cfg(test)]
    pub async fn validate(&self, caller: &str, near_client: Option<&crate::near::NearClient>) -> anyhow::Result<bool> {
        let patterns = self.compile_patterns().map_err(anyhow::Error::new)?;
        self.evaluate(caller, near_client, &patterns).await
    }

    /// Evaluate against patterns already compiled by [`Self::compile_patterns`]
    /// — the door compiles once and uses the same set for the verdict and for
    /// the refusal's wording.
    pub async fn evaluate(
        &self,
        caller: &str,
        near_client: Option<&crate::near::NearClient>,
        patterns: &CompiledPatterns,
    ) -> anyhow::Result<bool> {
        match self {
            AccessCondition::AllowAll => {
                tracing::debug!("AllowAll condition - access granted");
                Ok(true)
            }

            AccessCondition::Whitelist { accounts } => {
                let granted = accounts.iter().any(|acc| acc == caller);
                tracing::debug!(
                    condition = "Whitelist",
                    caller = %caller,
                    granted = %granted,
                    "Validated whitelist"
                );
                Ok(granted)
            }

            AccessCondition::AccountPattern { pattern } => {
                // Anchored full match — NOT `Regex::new(pattern).is_match`,
                // which matches a substring and silently turns an exact-looking
                // pattern into a whitelist bypass. See
                // [`compile_anchored_account_pattern`].
                let re = patterns
                    .get(pattern)
                    .ok_or_else(|| anyhow::anyhow!("AccountPattern was not compiled before evaluation"))?;
                let granted = re.is_match(caller);
                tracing::debug!(
                    condition = "AccountPattern",
                    pattern = %pattern,
                    caller = %caller,
                    granted = %granted,
                    "Validated account pattern"
                );
                Ok(granted)
            }

            AccessCondition::Logic { operator, conditions } => {
                match operator {
                    LogicOperator::And => {
                        // All conditions must pass
                        for condition in conditions {
                            let fut = Box::pin(condition.evaluate(caller, near_client, patterns));
                            if !fut.await? {
                                tracing::debug!("Logic::And - condition failed");
                                return Ok(false);
                            }
                        }
                        tracing::debug!("Logic::And - all conditions passed");
                        Ok(true)
                    }
                    LogicOperator::Or => {
                        // At least one condition must pass
                        for condition in conditions {
                            let fut = Box::pin(condition.evaluate(caller, near_client, patterns));
                            if fut.await? {
                                tracing::debug!("Logic::Or - condition passed");
                                return Ok(true);
                            }
                        }
                        tracing::debug!("Logic::Or - no conditions passed");
                        Ok(false)
                    }
                }
            }

            AccessCondition::Not { condition } => {
                let fut = Box::pin(condition.evaluate(caller, near_client, patterns));
                let result = fut.await?;
                tracing::debug!(
                    inner_result = %result,
                    negated = %(!result),
                    "Logic::Not"
                );
                Ok(!result)
            }

            AccessCondition::NearBalance { operator, value } => {
                let near_client = match near_client {
                    Some(client) => client,
                    // Not a verdict: under `Not` a false here would ADMIT. An error
                    // refuses at every combinator.
                    None => anyhow::bail!("NearBalance cannot be evaluated: this keystore has no NEAR client configured"),
                };

                // Parse required balance
                let required_balance: u128 = value.parse()
                    .map_err(|e| anyhow::anyhow!("Invalid balance value: {}", e))?;

                // Get actual balance
                let actual_balance = near_client.get_account_balance(caller).await?;

                // Compare
                let granted = Self::compare_values(actual_balance, *operator, required_balance);

                tracing::debug!(
                    condition = "NearBalance",
                    caller = %caller,
                    actual = %actual_balance,
                    required = %required_balance,
                    operator = ?operator,
                    granted = %granted,
                    "Validated NEAR balance"
                );

                Ok(granted)
            }

            AccessCondition::FtBalance { contract, operator, value } => {
                let near_client = match near_client {
                    Some(client) => client,
                    // Not a verdict: under `Not` a false here would ADMIT. An error
                    // refuses at every combinator.
                    None => anyhow::bail!("FtBalance cannot be evaluated: this keystore has no NEAR client configured"),
                };

                // Parse required balance
                let required_balance: u128 = value.parse()
                    .map_err(|e| anyhow::anyhow!("Invalid balance value: {}", e))?;

                // Get actual FT balance
                let actual_balance = near_client.get_ft_balance(contract, caller).await?;

                // Compare
                let granted = Self::compare_values(actual_balance, *operator, required_balance);

                tracing::debug!(
                    condition = "FtBalance",
                    contract = %contract,
                    caller = %caller,
                    actual = %actual_balance,
                    required = %required_balance,
                    operator = ?operator,
                    granted = %granted,
                    "Validated FT balance"
                );

                Ok(granted)
            }

            AccessCondition::NftOwned { contract, token_id } => {
                let near_client = match near_client {
                    Some(client) => client,
                    // Not a verdict: under `Not` a false here would ADMIT. An error
                    // refuses at every combinator.
                    None => anyhow::bail!("NftOwned cannot be evaluated: this keystore has no NEAR client configured"),
                };

                // Check NFT ownership (specific token or any token)
                let granted = near_client.check_nft_ownership(contract, caller, token_id.as_deref()).await?;

                tracing::debug!(
                    condition = "NftOwned",
                    contract = %contract,
                    caller = %caller,
                    token_id = ?token_id,
                    granted = %granted,
                    "Validated NFT ownership"
                );

                Ok(granted)
            }

            AccessCondition::DaoMember { dao_contract, role } => {
                let near_client = match near_client {
                    Some(client) => client,
                    // Not a verdict: under `Not` a false here would ADMIT. An error
                    // refuses at every combinator.
                    None => anyhow::bail!("DaoMember cannot be evaluated: this keystore has no NEAR client configured"),
                };

                // Check DAO membership for specified role
                let granted = near_client.check_dao_membership(dao_contract, caller, role).await?;

                tracing::debug!(
                    condition = "DaoMember",
                    dao_contract = %dao_contract,
                    role = %role,
                    caller = %caller,
                    granted = %granted,
                    "Validated DAO membership"
                );

                Ok(granted)
            }

            AccessCondition::ValidUntil { until_ns } => Self::valid_until_at(until_ns, now_ns()?),
        }
    }

    /// `ValidUntil` at a given instant. A limit that is not a number cannot
    /// be evaluated and is an error — under `Not` a plain "denied" would
    /// admit. The contract stores the field as a `U64`, so the chain never
    /// hands one over; the error is for any other caller of this type.
    fn valid_until_at(until_ns: &str, now: u64) -> anyhow::Result<bool> {
        let until: u64 = until_ns
            .parse()
            .map_err(|_| anyhow::anyhow!("ValidUntil.until_ns {until_ns:?} is not a number"))?;
        let granted = now < until;
        tracing::debug!(condition = "ValidUntil", until_ns = %until, now_ns = %now, granted = %granted, "Validated time limit");
        Ok(granted)
    }

    /// The time limit that stands between THIS caller and admission, if that
    /// is what refused them: a lapsed `ValidUntil` in a branch that names the
    /// caller — `And[…, Whitelist[caller], …, ValidUntil]` — searched through
    /// `Or`s, or a lapsed limit that binds everyone (top level, or beside
    /// `AllowAll`). A hint for a person; the verdict is [`Self::validate`]'s.
    /// A lapsed limit beside a whitelist that does not name the caller is not
    /// their reason: re-granting the date would not admit them. Never under
    /// `Not`, where a passed limit is what ADMITS.
    #[cfg(test)]
    pub(crate) fn lapsed_grant_for(&self, caller: &str, now: u64) -> Option<u64> {
        let patterns = self.compile_patterns().ok()?;
        self.lapsed_grant_in(caller, now, &patterns)
    }

    /// [`Self::lapsed_grant_for`] with the patterns already compiled.
    pub fn lapsed_grant_in(&self, caller: &str, now: u64, patterns: &CompiledPatterns) -> Option<u64> {
        match self {
            AccessCondition::ValidUntil { .. } => self.lapsed_limit(now),
            AccessCondition::Logic { operator: LogicOperator::Or, conditions } => {
                // A branch that names the caller and has not lapsed means
                // time is not what refused them, whatever another branch says.
                if conditions.iter().any(|c| c.names_without_lapse(caller, now, patterns)) {
                    return None;
                }
                conditions.iter().find_map(|c| c.lapsed_grant_in(caller, now, patterns))
            }
            AccessCondition::Logic { operator: LogicOperator::And, conditions } => {
                // A leaf that names people and not this caller refused them by
                // name; a date beside it is somebody else's.
                if conditions.iter().any(|c| c.is_naming_leaf() && !c.names(caller, patterns)) {
                    return None;
                }
                let names_caller = conditions.iter().any(|c| c.names(caller, patterns));
                let lapsed_here = conditions.iter().find_map(|c| c.lapsed_limit(now));
                match (names_caller, lapsed_here) {
                    (true, Some(until)) => Some(until),
                    // The caller's own dated branch may sit deeper.
                    _ => conditions
                        .iter()
                        .filter(|c| matches!(c, AccessCondition::Logic { .. }))
                        .find_map(|c| c.lapsed_grant_in(caller, now, patterns)),
                }
            }
            _ => None,
        }
    }

    /// A branch that names the caller and carries no lapsed limit: a leaf
    /// that names them, or an `And` that names them beside limits still live.
    fn names_without_lapse(&self, caller: &str, now: u64, patterns: &CompiledPatterns) -> bool {
        match self {
            AccessCondition::Logic { operator: LogicOperator::And, conditions } => {
                conditions.iter().any(|c| c.names(caller, patterns))
                    && !conditions.iter().any(|c| c.is_naming_leaf() && !c.names(caller, patterns))
                    && conditions.iter().all(|c| c.lapsed_limit(now).is_none())
            }
            _ => self.names(caller, patterns),
        }
    }

    /// A leaf whose whole job is to say WHO — or the negation of one.
    fn is_naming_leaf(&self) -> bool {
        match self {
            AccessCondition::AllowAll | AccessCondition::Whitelist { .. } | AccessCondition::AccountPattern { .. } => true,
            AccessCondition::Not { condition } => condition.is_naming_leaf(),
            _ => false,
        }
    }

    /// This leaf, lapsed at `now`.
    fn lapsed_limit(&self, now: u64) -> Option<u64> {
        match self {
            AccessCondition::ValidUntil { until_ns } => until_ns.parse::<u64>().ok().filter(|until| *until <= now),
            _ => None,
        }
    }

    /// Whether this leaf admits the caller BY NAME — the half of a dated grant
    /// that says whose grant it is.
    fn names(&self, caller: &str, patterns: &CompiledPatterns) -> bool {
        match self {
            AccessCondition::AllowAll => true,
            AccessCondition::Whitelist { accounts } => accounts.iter().any(|a| a == caller),
            AccessCondition::AccountPattern { pattern } => patterns.get(pattern).map(|re| re.is_match(caller)).unwrap_or(false),
            // "Everyone but bob" names alice.
            AccessCondition::Not { condition } if condition.is_naming_leaf() => !condition.names(caller, patterns),
            _ => false,
        }
    }

    /// What a refused caller is told. Names the caller's own lapsed time
    /// limit when that is what refused them, because that is the one refusal
    /// the owner fixes by re-granting rather than the caller by asking.
    #[cfg(test)]
    pub(crate) fn denial_message_for(&self, caller: &str) -> String {
        match self.compile_patterns() {
            Ok(patterns) => self.denial_message_in(caller, &patterns),
            Err(_) => "Access denied by access condition".to_string(),
        }
    }

    /// [`Self::denial_message_for`] with the patterns already compiled.
    pub fn denial_message_in(&self, caller: &str, patterns: &CompiledPatterns) -> String {
        match now_ns().ok().and_then(|now| self.lapsed_grant_in(caller, now, patterns)) {
            Some(until) => format!(
                "Access denied by access condition: its time limit passed at {}",
                iso8601_utc(until)
            ),
            None => "Access denied by access condition".to_string(),
        }
    }

    /// Compare two u128 values using the given operator
    fn compare_values(actual: u128, operator: ComparisonOperator, required: u128) -> bool {
        match operator {
            ComparisonOperator::Gte => actual >= required,
            ComparisonOperator::Lte => actual <= required,
            ComparisonOperator::Gt => actual > required,
            ComparisonOperator::Lt => actual < required,
            ComparisonOperator::Eq => actual == required,
            ComparisonOperator::Ne => actual != required,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_760_000_000_000_000_000; // 2025-10-09T08:53:20Z

    /// A time limit admits strictly before its instant and denies from it on;
    /// one that is not a number cannot be evaluated and is an error — a plain
    /// denial would admit under `Not`.
    #[test]
    fn a_time_limit_admits_before_and_denies_from_its_instant() {
        let until = T.to_string();
        assert!(AccessCondition::valid_until_at(&until, T - 1).unwrap());
        assert!(!AccessCondition::valid_until_at(&until, T).unwrap());
        assert!(!AccessCondition::valid_until_at(&until, T + 1).unwrap());
        assert!(AccessCondition::valid_until_at("soon", T - 1).is_err(), "not a number: an error, not a verdict");
        assert!(AccessCondition::valid_until_at("", T - 1).is_err());
        assert!(!AccessCondition::valid_until_at(&until, u64::MAX).unwrap(), "at the end of time every limit has lapsed");
    }

    /// The contract writes `U64` as a decimal string; that is the shape read here.
    #[test]
    fn valid_until_parses_the_contracts_json() {
        let parsed: AccessCondition =
            serde_json::from_str(r#"{"ValidUntil":{"until_ns":"1760000000000000000"}}"#).unwrap();
        assert_eq!(parsed, AccessCondition::ValidUntil { until_ns: T.to_string() });
    }

    /// Composed the way a grant is written: one agent, until a date. `Not`
    /// turns it into "valid after".
    #[tokio::test]
    async fn a_grant_with_a_time_limit_composes_with_a_whitelist() {
        let far = (now_ns().unwrap() + 3_600_000_000_000).to_string();
        let past = "1".to_string();
        let grant = |until: &str| AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::Whitelist { accounts: vec!["agent.near".into()] },
                AccessCondition::ValidUntil { until_ns: until.to_string() },
            ],
        };
        assert!(grant(&far).validate("agent.near", None).await.unwrap());
        assert!(!grant(&far).validate("other.near", None).await.unwrap(), "the whitelist still decides who");
        assert!(!grant(&past).validate("agent.near", None).await.unwrap(), "and the limit decides when");
        let after = AccessCondition::Not {
            condition: Box::new(AccessCondition::ValidUntil { until_ns: past.clone() }),
        };
        assert!(after.validate("anyone.near", None).await.unwrap(), "Not over ValidUntil is valid-after");
    }

    /// The refusal names a lapsed limit when it is THE CALLER's — the dated
    /// branch that names them — and says nothing about time otherwise: not
    /// for a caller another branch refused, not for a lapse in somebody
    /// else's grant, never under Not.
    #[test]
    fn a_lapsed_limit_is_named_to_the_caller_it_bound() {
        let wl = |a: &str| AccessCondition::Whitelist { accounts: vec![a.to_string()] };
        let dated = |a: &str, until: u64| AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![wl(a), AccessCondition::ValidUntil { until_ns: until.to_string() }],
        };
        // The shape every interface writes: the owner for ever, agents until a date.
        let grants = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![wl("owner.near"), dated("agent.near", T), dated("other.near", T + 100)],
        };
        assert_eq!(grants.lapsed_grant_for("agent.near", T + 5), Some(T), "the agent's own grant lapsed");
        assert_eq!(grants.lapsed_grant_for("agent.near", T - 5), None, "a live limit is not lapsed");
        assert_eq!(grants.lapsed_grant_for("other.near", T + 5), None, "the other agent's grant is live");
        assert_eq!(grants.lapsed_grant_for("stranger.near", T + 5), None, "a stranger was refused for not being named, not for time");
        // A lapsed date beside somebody ELSE's name is not this caller's reason.
        assert_eq!(dated("bob.near", T).lapsed_grant_for("alice.near", T + 5), None);
        assert_eq!(dated("bob.near", T).lapsed_grant_for("bob.near", T + 5), Some(T));
        // A limit that binds everyone binds the caller.
        assert_eq!(AccessCondition::ValidUntil { until_ns: T.to_string() }.lapsed_grant_for("anyone.near", T), Some(T));
        let everyone_until = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![AccessCondition::AllowAll, AccessCondition::ValidUntil { until_ns: T.to_string() }],
        };
        assert_eq!(everyone_until.lapsed_grant_for("anyone.near", T + 1), Some(T));
        // A pattern names whoever it matches.
        let by_pattern = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::AccountPattern { pattern: r".*\.agents\.near".to_string() },
                AccessCondition::ValidUntil { until_ns: T.to_string() },
            ],
        };
        assert_eq!(by_pattern.lapsed_grant_for("x.agents.near", T + 1), Some(T));
        assert_eq!(by_pattern.lapsed_grant_for("x.near", T + 1), None);
        // The caller's dated branch may sit under an outer And.
        let deeper = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![AccessCondition::AllowAll, grants.clone()],
        };
        assert_eq!(deeper.lapsed_grant_for("agent.near", T + 5), Some(T));
        // A live branch that names the caller means time did not refuse them,
        // whatever a lapsed sibling says: the agent re-granted until T2 is
        // refused by the outer gate, not by the lapsed T1 grant.
        let regranted = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::NearBalance { operator: ComparisonOperator::Gte, value: "1".into() },
                AccessCondition::Logic {
                    operator: LogicOperator::Or,
                    conditions: vec![wl("owner.near"), dated("agent.near", T), dated("agent.near", T + 100)],
                },
            ],
        };
        assert_eq!(regranted.lapsed_grant_for("agent.near", T + 5), None, "the T2 grant is live");
        let lapsed_beside_a_name = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::NearBalance { operator: ComparisonOperator::Gte, value: "1".into() },
                AccessCondition::Logic {
                    operator: LogicOperator::Or,
                    conditions: vec![AccessCondition::ValidUntil { until_ns: T.to_string() }, wl("alice.near")],
                },
            ],
        };
        assert_eq!(lapsed_beside_a_name.lapsed_grant_for("alice.near", T + 5), None, "the Or admits alice by name");
        // A name that is not the caller's, beside a nested lapsed limit, is a
        // refusal by name.
        let bobs = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                wl("bob.near"),
                AccessCondition::Logic { operator: LogicOperator::Or, conditions: vec![AccessCondition::ValidUntil { until_ns: T.to_string() }] },
            ],
        };
        assert_eq!(bobs.lapsed_grant_for("alice.near", T + 5), None);
        assert_eq!(bobs.lapsed_grant_for("bob.near", T + 5), Some(T), "bob's own grant, lapsed");
        // The negation of a name is a name: "everyone but bob, until T" binds
        // alice, and a branch that excludes alice by name is not her live grant.
        let not_wl = |a: &str| AccessCondition::Not { condition: Box::new(wl(a)) };
        let everyone_but_bob = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![AccessCondition::ValidUntil { until_ns: T.to_string() }, not_wl("bob.near")],
        };
        assert_eq!(everyone_but_bob.lapsed_grant_for("alice.near", T + 5), Some(T));
        assert_eq!(everyone_but_bob.lapsed_grant_for("bob.near", T + 5), None, "bob is refused by name");
        let excluded_then_dated = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![
                AccessCondition::Logic { operator: LogicOperator::And, conditions: vec![AccessCondition::AllowAll, not_wl("alice.near")] },
                dated("alice.near", T),
            ],
        };
        assert_eq!(excluded_then_dated.lapsed_grant_for("alice.near", T + 5), Some(T), "her own dated grant lapsed");
        let self_contradictory = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![wl("alice.near"), AccessCondition::ValidUntil { until_ns: T.to_string() }, not_wl("alice.near")],
        };
        assert_eq!(self_contradictory.lapsed_grant_for("alice.near", T + 5), None, "re-granting the date would not admit her");
        let valid_after = AccessCondition::Not {
            condition: Box::new(AccessCondition::ValidUntil { until_ns: "1".to_string() }),
        };
        assert_eq!(valid_after.lapsed_grant_for("anyone.near", T), None, "under Not a passed limit admits");
        assert_eq!(AccessCondition::AllowAll.lapsed_grant_for("anyone.near", T), None);
        assert_eq!(
            AccessCondition::ValidUntil { until_ns: "1".to_string() }.denial_message_for("anyone.near"),
            "Access denied by access condition: its time limit passed at 1970-01-01T00:00:00Z"
        );
        assert_eq!(
            dated("bob.near", 1).denial_message_for("alice.near"),
            "Access denied by access condition",
            "alice is told nothing about bob's date"
        );
    }

    #[test]
    fn iso8601_renders_known_instants() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601_utc(1_700_000_000 * 1_000_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(iso8601_utc(T), "2025-10-09T08:53:20Z");
        assert_eq!(iso8601_utc(951_782_400 * 1_000_000_000), "2000-02-29T00:00:00Z", "a leap day");
    }

    #[tokio::test]
    async fn test_allow_all() {
        let condition = AccessCondition::AllowAll;
        assert!(condition.validate("anyone.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_whitelist_allowed() {
        let condition = AccessCondition::Whitelist {
            accounts: vec!["alice.near".to_string(), "bob.near".to_string()],
        };
        assert!(condition.validate("alice.near", None).await.unwrap());
        assert!(condition.validate("bob.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_whitelist_denied() {
        let condition = AccessCondition::Whitelist {
            accounts: vec!["alice.near".to_string()],
        };
        assert!(!condition.validate("bob.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_pattern_match() {
        let condition = AccessCondition::AccountPattern {
            pattern: r".*\.gov\.near".to_string(),
        };
        assert!(condition.validate("treasury.gov.near", None).await.unwrap());
        assert!(!condition.validate("alice.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_pattern_is_anchored_full_match() {
        // `team.near`, escaped, meant as an exact check. Unanchored `is_match`
        // used to admit every near-miss an attacker can register; anchoring
        // must reject all of them while still matching the real account.
        let condition = AccessCondition::AccountPattern {
            pattern: r"team\.near".to_string(),
        };
        assert!(condition.validate("team.near", None).await.unwrap());
        // Substring bypasses — all of these `is_match(caller)` accepted before.
        assert!(!condition.validate("xteam.near", None).await.unwrap());
        assert!(!condition.validate("team.near.attacker.near", None).await.unwrap());
        assert!(!condition.validate("team.nearx", None).await.unwrap());
        // A trailing newline must not satisfy the anchor. (Rust's `$` would
        // also reject this one — see the note on `\A`/`\z` above for what the
        // absolute anchors actually buy.)
        assert!(!condition.validate("team.near\n", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_unescaped_dot_matches_one_char_but_never_a_substring() {
        // Anchoring does NOT fix the `.`-is-a-metachar footgun (that needs the
        // owner to escape it); it only removes the SUBSTRING bypass. This pins
        // the anchored behaviour so a refactor cannot silently un-anchor.
        let condition = AccessCondition::AccountPattern {
            pattern: r"team.near".to_string(), // unescaped dot — owner mistake
        };
        assert!(condition.validate("team.near", None).await.unwrap());
        // `.` still matches one arbitrary char (the documented footgun)...
        assert!(condition.validate("teamXnear", None).await.unwrap());
        // ...but only as a whole-id match, never as a substring of a longer id.
        assert!(!condition.validate("teamXnear.attacker.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_pattern_top_level_alternation_is_grouped() {
        // `a|b` must anchor as a whole: `\A(?:a|b)\z`, not `\Aa|b\z`, which
        // would mean "starts with a" OR "ends with b" — a bypass on both sides.
        let condition = AccessCondition::AccountPattern {
            pattern: r"alice\.near|bob\.near".to_string(),
        };
        assert!(condition.validate("alice.near", None).await.unwrap());
        assert!(condition.validate("bob.near", None).await.unwrap());
        assert!(!condition.validate("alice.near.evil.near", None).await.unwrap());
        assert!(!condition.validate("evil.bob.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_empty_pattern_denies_instead_of_granting_everyone() {
        // Latent bug the anchoring incidentally closes: `Regex::new("")` matches
        // ANY input, so an empty pattern used to grant every caller. Anchored,
        // `\A(?:)\z` matches only the empty string, so a real account is denied.
        let condition = AccessCondition::AccountPattern { pattern: String::new() };
        assert!(!condition.validate("anyone.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_metachar_injection_cannot_escape_the_anchors() {
        // A pattern that injects its own parens can restructure the groups but
        // never remove `\A`/`\z`: `a)(b` compiles to `\A(?:a)(b)\z`, still a
        // full match of exactly "ab" — no substring bypass survives.
        let condition = AccessCondition::AccountPattern { pattern: "a)(b".to_string() };
        assert!(condition.validate("ab", None).await.unwrap());
        assert!(!condition.validate("xabx", None).await.unwrap());
        // A pattern that unbalances the wrapper cannot be compiled: an error,
        // which refuses at every combinator, never a verdict.
        let broken = AccessCondition::AccountPattern { pattern: ")".to_string() };
        assert!(broken.validate("anything.near", None).await.is_err());
    }

    #[tokio::test]
    async fn test_a_second_line_never_satisfies_a_full_match() {
        // Named for what it proves. It used to be called "…cannot defeat
        // absolute anchors", which claims more than it shows: the same input is
        // rejected with `^`/`$` too, because an owner's inline `(?m)` applies
        // only inside the group it appears in and our anchors are outside it.
        // What IS pinned here is the property that matters — a caller id with an
        // embedded newline cannot be admitted by one of its lines.
        let condition = AccessCondition::AccountPattern {
            pattern: r"(?m)^team\.near$".to_string(),
        };
        assert!(!condition.validate("evil.near\nteam.near", None).await.unwrap());
        assert!(condition.validate("team.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_pattern_invalid_regex() {
        let condition = AccessCondition::AccountPattern {
            pattern: "[invalid".to_string(), // unclosed bracket
        };
        // An unreadable pattern is an error naming itself, not a denial.
        let err = condition.validate("alice.near", None).await.expect_err("cannot be evaluated");
        let unreadable = err.downcast_ref::<UnreadablePattern>().expect("typed, so the door can name it");
        assert_eq!(unreadable.pattern, "[invalid");
    }

    #[tokio::test]
    async fn test_logic_and_pass() {
        let condition = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::AccountPattern {
                    pattern: r".*\.near".to_string(),
                },
                AccessCondition::Whitelist {
                    accounts: vec!["alice.near".to_string()],
                },
            ],
        };
        assert!(condition.validate("alice.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_logic_and_fail() {
        let condition = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::AccountPattern {
                    pattern: r".*\.near".to_string(),
                },
                AccessCondition::Whitelist {
                    accounts: vec!["bob.near".to_string()],
                },
            ],
        };
        assert!(!condition.validate("alice.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_logic_or_pass() {
        let condition = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![
                AccessCondition::Whitelist {
                    accounts: vec!["bob.near".to_string()],
                },
                AccessCondition::AccountPattern {
                    pattern: r"alice\..*".to_string(),
                },
            ],
        };
        assert!(condition.validate("alice.near", None).await.unwrap());
    }

    #[tokio::test]
    async fn test_logic_not() {
        let condition = AccessCondition::Not {
            condition: Box::new(AccessCondition::Whitelist {
                accounts: vec!["blocked.near".to_string()],
            }),
        };
        assert!(condition.validate("alice.near", None).await.unwrap());
        assert!(!condition.validate("blocked.near", None).await.unwrap());
    }
}

#[cfg(test)]
mod near_sdk_format_tests {
    use super::*;

    #[test]
    fn test_parse_allow_all_from_contract() {
        // NEAR SDK returns unit variants as simple strings
        let json = r#""AllowAll""#;
        let parsed: AccessCondition = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, AccessCondition::AllowAll);
    }

    #[test]
    fn test_parse_whitelist_from_contract() {
        // NEAR SDK returns struct variants as adjacently tagged
        let json = r#"{"Whitelist":{"accounts":["alice.near","bob.near"]}}"#;
        let parsed: AccessCondition = serde_json::from_str(json).unwrap();
        match parsed {
            AccessCondition::Whitelist { accounts } => {
                assert_eq!(accounts, vec!["alice.near", "bob.near"]);
            }
            _ => panic!("Expected Whitelist variant"),
        }
    }
}


#[cfg(test)]
mod a_condition_that_cannot_be_read_refuses_wherever_the_unreadable_leaf_sits {
    //! A pattern the engine will not compile is an ERROR of `validate`, raised
    //! while the tree's patterns are compiled — before any combinator runs, so
    //! `Not` never sees a refused leaf to negate — and the door names the
    //! pattern to the owner.
    use super::*;

    fn bad() -> AccessCondition {
        AccessCondition::AccountPattern { pattern: "(".to_string() }
    }
    fn whitelist(a: &str) -> AccessCondition {
        AccessCondition::Whitelist { accounts: vec![a.to_string()] }
    }

    #[tokio::test]
    async fn a_bad_leaf_is_an_error_that_names_the_pattern() {
        let err = bad().validate("anyone.near", None).await.expect_err("cannot be evaluated");
        let u = err.downcast_ref::<UnreadablePattern>().expect("typed");
        assert_eq!(u.pattern, "(");
        assert!(!u.why.is_empty(), "the compiler's reason travels with it");
        assert!(!u.why.contains('\n') && !u.why.contains("\\A"), "one line, the owner's pattern only: {}", u.why);
        let shown = u.to_string();
        assert!(shown.contains("AccountPattern `(`") && shown.contains("cannot be compiled"), "{shown}");
    }

    #[tokio::test]
    async fn under_not_and_or_the_tree_is_refused_before_evaluation() {
        let shapes = [
            AccessCondition::Not { condition: Box::new(bad()) },
            AccessCondition::Logic { operator: LogicOperator::And, conditions: vec![AccessCondition::AllowAll, bad()] },
            AccessCondition::Logic { operator: LogicOperator::Or, conditions: vec![whitelist("bob.near"), bad()] },
            AccessCondition::Not { condition: Box::new(AccessCondition::Logic { operator: LogicOperator::Or, conditions: vec![bad()] }) },
        ];
        for c in shapes {
            let err = c.validate("anyone.near", None).await.expect_err("an unreadable leaf refuses the tree");
            assert!(err.downcast_ref::<UnreadablePattern>().is_some(), "still the typed error after propagation: {err}");
        }
    }

    #[tokio::test]
    async fn an_unreadable_leaf_anywhere_refuses_everyone_before_anything_is_evaluated() {
        // Even a branch that would decide the verdict on its own does not
        // save the condition: nobody is judged by a tree that cannot be read,
        // and the owner hears which pattern, whoever knocked.
        let or = AccessCondition::Logic { operator: LogicOperator::Or, conditions: vec![AccessCondition::AllowAll, bad()] };
        let err = or.validate("anyone.near", None).await.expect_err("AllowAll beside an unreadable leaf still refuses");
        assert!(err.downcast_ref::<UnreadablePattern>().is_some(), "{err}");
        let and = AccessCondition::Logic { operator: LogicOperator::And, conditions: vec![whitelist("bob.near"), bad()] };
        assert!(and.validate("alice.near", None).await.is_err(), "alice is not told 'denied' — the row is unreadable");
        assert!(and.validate("bob.near", None).await.is_err());
        assert!(or.compile_patterns().is_err() && and.compile_patterns().is_err());
    }

    #[tokio::test]
    async fn a_pattern_is_compiled_once_however_many_branches_name_it() {
        let p = || AccessCondition::AccountPattern { pattern: r".*\.near".to_string() };
        let tree = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![p(), AccessCondition::Not { condition: Box::new(p()) }, AccessCondition::Logic { operator: LogicOperator::And, conditions: vec![p(), p()] }],
        };
        let compiled = tree.compile_patterns().unwrap();
        assert_eq!(compiled.0.len(), 1, "one text, one regex");
        assert!(tree.evaluate("alice.near", None, &compiled).await.unwrap());
    }

    #[tokio::test]
    async fn a_valid_pattern_is_evaluated_not_reported() {
        let ok = AccessCondition::AccountPattern { pattern: ".*\\.near".to_string() };
        assert!(ok.validate("alice.near", None).await.unwrap());
        assert!(!ok.validate("alice.testnet", None).await.unwrap());
    }

    #[tokio::test]
    async fn the_message_is_bounded_whatever_the_owner_wrote() {
        let huge = AccessCondition::AccountPattern { pattern: "(".repeat(100_000) };
        let err = huge.validate("anyone.near", None).await.expect_err("unclosed groups");
        let shown = err.downcast_ref::<UnreadablePattern>().unwrap().to_string();
        assert!(shown.len() < 2 * UnreadablePattern::CLIP + 200, "{} bytes", shown.len());
        assert!(shown.contains('…'), "clipped, and says so");
    }

    #[tokio::test]
    async fn a_pattern_too_large_to_compile_is_reported_as_such() {
        let big = AccessCondition::AccountPattern { pattern: r"\pL{2000}".to_string() };
        let err = big.validate("anyone.near", None).await.expect_err("exceeds the size limit");
        let u = err.downcast_ref::<UnreadablePattern>().unwrap();
        assert!(u.why.to_lowercase().contains("size limit"), "{}", u.why);
    }

    #[tokio::test]
    async fn a_pattern_that_needs_megabytes_to_match_an_account_id_is_refused_and_a_real_one_is_not() {
        // `\pL{200}` compiles to ~10 MB under the regex crate's default limit
        // — one such leaf per row was a gigabyte of keystore memory across a
        // few decrypts. Under the account-id-sized limit it does not compile
        // at all; the shapes an owner actually writes do.
        let heavy = AccessCondition::AccountPattern { pattern: r"\pL{200}".to_string() };
        assert!(heavy.compile_patterns().is_err(), "a 10 MB program for a 64-byte id is refused");
        for real in [r".*\.near", r"[a-z0-9-]{2,64}\.agents\.near", r"(alice|bob)\.near", &"a".repeat(64)] {
            let ok = AccessCondition::AccountPattern { pattern: real.to_string() };
            assert!(ok.compile_patterns().is_ok(), "{real}");
        }
    }

    #[tokio::test]
    async fn a_chain_read_with_no_client_is_an_error_not_a_verdict() {
        let balance = AccessCondition::NearBalance { operator: ComparisonOperator::Gte, value: "1".to_string() };
        assert!(balance.validate("anyone.near", None).await.is_err());
        let negated = AccessCondition::Not { condition: Box::new(balance) };
        assert!(negated.validate("anyone.near", None).await.is_err(), "Not over an unevaluable leaf admits nobody");
    }

    #[test]
    fn clip_cuts_on_a_character_boundary() {
        assert_eq!(clip("abc", 3), "abc");
        assert_eq!(clip("abcd", 3), "abc…");
        assert_eq!(clip("жжж", 3), "ж…");
    }
}
