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
    /// Admit only a run of one exact build: the SHA-256 of the WebAssembly
    /// bytes executing, as the attested worker measured them on the buffer it
    /// loaded and reports in `DecryptRequest.executed_wasm_sha256`. Compared
    /// case-insensitively; a request that reports no hash leaves this leaf
    /// UNKNOWN, and a tree carrying one is then unknown — and so refused —
    /// unless another branch settles the answer on its own, in which case the
    /// admission owes this leaf nothing. Composed with the others:
    /// `And[Whitelist[owner], WasmHash(h)]` is a secret a rebuild cannot open.
    WasmHash {
        hash: String,
    },
}

/// Why a build refused a run, as the denial is worded.
#[derive(Clone, Copy)]
enum BuildRefusal<'a> {
    /// A `WasmHash` leaf names a build that is not the one running.
    LockedTo(&'a str),
    /// A negated leaf names the build that IS running.
    Refuses,
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
        self.evaluate(caller, near_client, &patterns, None).await
    }

    /// Evaluate against patterns already compiled by [`Self::compile_patterns`]
    /// — the door compiles once and uses the same set for the verdict and for
    /// the refusal's wording.
    pub async fn evaluate(
        &self,
        caller: &str,
        near_client: Option<&crate::near::NearClient>,
        patterns: &CompiledPatterns,
        executed_wasm_sha256: Option<&str>,
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
                        // All conditions must pass.
                        //
                        // A branch that cannot be evaluated is UNKNOWN, not a
                        // refusal, and is carried rather than returned at once:
                        // `false AND unknown` is false whichever order the two
                        // were written in. Returning the error immediately made
                        // the verdict depend on branch order for an operator
                        // that is commutative — the same row admitting when
                        // spelt one way and erroring when spelt the other.
                        // Nothing is admitted on an unknown: an admission can
                        // only come from branches that all genuinely passed.
                        let mut unknown = None;
                        for condition in conditions {
                            let fut = Box::pin(condition.evaluate(caller, near_client, patterns, executed_wasm_sha256));
                            match fut.await {
                                Ok(true) => {}
                                Ok(false) => {
                                    tracing::debug!("Logic::And - condition failed");
                                    return Ok(false);
                                }
                                Err(e) => {
                                    if unknown.is_none() {
                                        unknown = Some(e);
                                    }
                                }
                            }
                        }
                        if let Some(e) = unknown {
                            return Err(e);
                        }
                        tracing::debug!("Logic::And - all conditions passed");
                        Ok(true)
                    }
                    LogicOperator::Or => {
                        // At least one condition must pass. An unevaluable
                        // branch is carried, not returned: `true OR unknown` is
                        // true, and a branch that genuinely admits settles the
                        // answer whatever the others could not decide. See the
                        // `And` arm for why the order must not matter.
                        let mut unknown = None;
                        for condition in conditions {
                            let fut = Box::pin(condition.evaluate(caller, near_client, patterns, executed_wasm_sha256));
                            match fut.await {
                                Ok(true) => {
                                    tracing::debug!("Logic::Or - condition passed");
                                    return Ok(true);
                                }
                                Ok(false) => {}
                                Err(e) => {
                                    if unknown.is_none() {
                                        unknown = Some(e);
                                    }
                                }
                            }
                        }
                        if let Some(e) = unknown {
                            return Err(e);
                        }
                        tracing::debug!("Logic::Or - no conditions passed");
                        Ok(false)
                    }
                }
            }

            AccessCondition::Not { condition } => {
                let fut = Box::pin(condition.evaluate(caller, near_client, patterns, executed_wasm_sha256));
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
            AccessCondition::WasmHash { hash } => match executed_wasm_sha256 {
                Some(executed) => {
                    let granted = executed.eq_ignore_ascii_case(hash);
                    tracing::debug!(condition = "WasmHash", expected = %hash, executed = %executed, granted = %granted, "Validated build");
                    Ok(granted)
                }
                // A request that names no build cannot be judged against one:
                // an error, refused at every combinator — never a guess.
                None => Err(anyhow::anyhow!(
                    "the condition admits one build, but this request reports no executing wasm hash"
                )),
            },
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
            Ok(patterns) => self.denial_message_in(caller, &patterns, None),
            Err(_) => "Access denied by access condition".to_string(),
        }
    }

    /// [`Self::denial_message_for`] with the patterns already compiled and the
    /// executing build known. A build the condition is locked to is named
    /// first: like a lapsed grant, it is the refusal the OWNER fixes — by
    /// moving the row to the new build — rather than the caller by asking.
    pub fn denial_message_in(&self, caller: &str, patterns: &CompiledPatterns, executed_wasm_sha256: Option<&str>) -> String {
        if let Some(refusal) = self.build_refusal(executed_wasm_sha256) {
            let running = executed_wasm_sha256.unwrap_or("not reported");
            return match refusal {
                BuildRefusal::LockedTo(locked_to) => format!(
                    "Access denied by access condition: this secret is locked to build {locked_to} and the running build is {running}"
                ),
                BuildRefusal::Refuses => format!(
                    "Access denied by access condition: this secret refuses the running build {running}"
                ),
            };
        }
        match now_ns().ok().and_then(|now| self.lapsed_grant_in(caller, now, patterns)) {
            Some(until) => format!(
                "Access denied by access condition: its time limit passed at {}",
                iso8601_utc(until)
            ),
            None => "Access denied by access condition".to_string(),
        }
    }

    /// Why a build refused this run, when a build is what refused it.
    ///
    /// Structural rather than a search for any `WasmHash` leaf, because a leaf
    /// sitting somewhere in the tree is not the same as the tree refusing over
    /// it: under `Or` another branch may have refused for its own reason, and
    /// under `Not` a leaf that MATCHES is what refuses. Claiming a lock that is
    /// not there sends the owner to re-point a row that was never locked.
    fn build_refusal(&self, executed_wasm_sha256: Option<&str>) -> Option<BuildRefusal<'_>> {
        // Nothing to say about a build when the request named none. The verdict
        // on such a request is an ERROR, not a denial, so this is only reached
        // when something ELSE refused — an old worker's call against a row whose
        // whitelist excluded the caller, say — and blaming the build there sends
        // the owner to re-point a lock that was never the reason.
        let executed = executed_wasm_sha256?;
        let names_running = |hash: &str| executed.eq_ignore_ascii_case(hash);
        match self {
            AccessCondition::WasmHash { hash } => (!names_running(hash)).then_some(BuildRefusal::LockedTo(hash)),
            // "Any build but this one", refused by the one it names.
            AccessCondition::Not { condition } => match condition.as_ref() {
                AccessCondition::WasmHash { hash } => names_running(hash).then_some(BuildRefusal::Refuses),
                _ => None,
            },
            // Every branch of an AND must pass, so the first a build refused is
            // the reason the whole tree refused.
            AccessCondition::Logic { operator: LogicOperator::And, conditions } => {
                conditions.iter().find_map(|c| c.build_refusal(executed_wasm_sha256))
            }
            // An OR refuses over a build only when EVERY branch does. One
            // branch that says nothing about builds refused for its own reason,
            // and the tree is then not locked to anything.
            AccessCondition::Logic { operator: LogicOperator::Or, conditions } => {
                let mut first = None;
                for condition in conditions {
                    let refusal = condition.build_refusal(executed_wasm_sha256)?;
                    first.get_or_insert(refusal);
                }
                first
            }
            _ => None,
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
        assert!(tree.evaluate("alice.near", None, &compiled, None).await.unwrap());
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

/// A `WasmHash` leaf admits one build, and the refusal says which.
///
/// Two things are pinned apart here, because they fail apart. The VERDICT is
/// what admits or refuses a run; the MESSAGE is what the owner reads to fix a
/// row. A message that claims a lock the tree does not carry sends them to
/// re-point a row that was never locked, and one that stays silent where the
/// build IS the reason leaves them with nothing to act on.
#[cfg(test)]
mod a_build_leaf_admits_one_build_and_says_so_when_it_refuses {
    use super::*;

    const RUNNING: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn build(hash: &str) -> AccessCondition {
        AccessCondition::WasmHash { hash: hash.to_string() }
    }
    fn wl(account: &str) -> AccessCondition {
        AccessCondition::Whitelist { accounts: vec![account.to_string()] }
    }
    fn and(conditions: Vec<AccessCondition>) -> AccessCondition {
        AccessCondition::Logic { operator: LogicOperator::And, conditions }
    }
    fn or(conditions: Vec<AccessCondition>) -> AccessCondition {
        AccessCondition::Logic { operator: LogicOperator::Or, conditions }
    }
    fn not(condition: AccessCondition) -> AccessCondition {
        AccessCondition::Not { condition: Box::new(condition) }
    }

    async fn verdict(condition: &AccessCondition, executed: Option<&str>) -> anyhow::Result<bool> {
        let patterns = condition.compile_patterns().expect("no patterns here");
        condition.evaluate("alice.near", None, &patterns, executed).await
    }

    fn message(condition: &AccessCondition, executed: Option<&str>) -> String {
        let patterns = condition.compile_patterns().expect("no patterns here");
        condition.denial_message_in("alice.near", &patterns, executed)
    }

    #[tokio::test]
    async fn the_running_build_is_admitted_and_any_other_is_not() {
        assert!(verdict(&build(RUNNING), Some(RUNNING)).await.unwrap());
        assert!(!verdict(&build(RUNNING), Some(OTHER)).await.unwrap());
    }

    /// The contract stores lowercase; the worker reports lowercase. Comparing
    /// case-insensitively means a row that reached the chain by some other door
    /// still decides the same way, rather than admitting nobody for a reason
    /// nothing in the answer would name.
    #[tokio::test]
    async fn the_comparison_ignores_case() {
        assert!(verdict(&build(&RUNNING.to_uppercase()), Some(RUNNING)).await.unwrap());
    }

    /// A request that names no build cannot be judged against one: the leaf is
    /// an ERROR, not a denial, and an error stops `And`, `Or` and `Not` alike.
    ///
    /// Stated carefully, because the obvious phrasing overstates it. An
    /// unevaluable leaf is UNKNOWN, and unknown combines the way it should:
    /// `true OR unknown` is true, `false AND unknown` is false, and everything
    /// else stays unknown. So a tree carrying a lock is unknown unless some
    /// OTHER branch settles it on its own — which is the property that matters,
    /// since an admission then owes nothing to the lock. Order-independence is
    /// pinned separately by
    /// [`a_skipped_lock_never_turns_a_denial_into_an_admission`].
    #[tokio::test]
    async fn a_request_that_reports_no_build_never_reaches_a_verdict_through_a_lock() {
        // Nothing else to go on: unknown.
        assert!(verdict(&build(RUNNING), None).await.is_err());
        assert!(verdict(&not(build(RUNNING)), None).await.is_err());
        // The lock is the only thing standing between the caller and the row.
        assert!(verdict(&and(vec![AccessCondition::AllowAll, build(RUNNING)]), None).await.is_err());
        assert!(verdict(&and(vec![wl("alice.near"), build(RUNNING)]), None).await.is_err());
        // Settled without the lock: admitted by a branch that admits anyway,
        // refused by one that refuses anyway. Neither owes anything to the lock.
        assert_eq!(
            verdict(&or(vec![build(RUNNING), AccessCondition::AllowAll]), None).await.unwrap(),
            true
        );
        assert_eq!(
            verdict(&and(vec![wl("bob.near"), build(RUNNING)]), None).await.unwrap(),
            false
        );
    }

    /// Short-circuiting must not make the verdict depend on the order branches
    /// were written in — the operators are commutative and so is the answer.
    /// The leaf is skipped only where the result is already decided, so the
    /// same tree judges the same way whichever way round it is spelt.
    #[tokio::test]
    async fn a_skipped_lock_never_turns_a_denial_into_an_admission() {
        let lock = build(RUNNING);
        for (a, b) in [
            (AccessCondition::AllowAll, lock.clone()),
            (wl("bob.near"), lock.clone()),
            (wl("alice.near"), lock.clone()),
        ] {
            let forwards = verdict(&or(vec![a.clone(), b.clone()]), None).await;
            let backwards = verdict(&or(vec![b.clone(), a.clone()]), None).await;
            assert_eq!(
                forwards.as_ref().ok().copied(),
                backwards.as_ref().ok().copied(),
                "an Or judged differently depending on branch order"
            );
            // Whatever the order, a missing build never ADMITS through the lock:
            // an admission here can only come from a branch that admits on its own.
            if matches!(forwards, Ok(true)) {
                assert!(
                    verdict(&a, None).await.unwrap_or(false),
                    "the Or admitted, but not because a build-free branch did"
                );
            }
            let and_fwd = verdict(&and(vec![a.clone(), b.clone()]), None).await;
            let and_bwd = verdict(&and(vec![b.clone(), a.clone()]), None).await;
            assert_eq!(and_fwd.as_ref().ok().copied(), and_bwd.as_ref().ok().copied());
            assert!(!matches!(and_fwd, Ok(true)), "an And with a lock admitted with no build reported");
        }
    }

    #[tokio::test]
    async fn a_lock_beside_a_whitelist_needs_both() {
        let locked = and(vec![wl("alice.near"), build(RUNNING)]);
        assert!(verdict(&locked, Some(RUNNING)).await.unwrap());
        assert!(!verdict(&locked, Some(OTHER)).await.unwrap());

        let stranger = and(vec![wl("bob.near"), build(RUNNING)]);
        assert!(!verdict(&stranger, Some(RUNNING)).await.unwrap());
    }

    #[tokio::test]
    async fn a_negated_leaf_admits_every_build_but_the_one_it_names() {
        assert!(!verdict(&not(build(RUNNING)), Some(RUNNING)).await.unwrap());
        assert!(verdict(&not(build(RUNNING)), Some(OTHER)).await.unwrap());
    }

    #[test]
    fn a_bare_leaf_names_the_build_it_is_locked_to() {
        let m = message(&build(OTHER), Some(RUNNING));
        assert!(m.contains(OTHER) && m.contains(RUNNING), "{m}");
        assert!(m.contains("locked to build"), "{m}");
    }

    /// The build matched, so something else refused — and the message must not
    /// send the owner after the build.
    #[test]
    fn a_matching_leaf_makes_no_claim_about_builds() {
        let m = message(&and(vec![wl("bob.near"), build(RUNNING)]), Some(RUNNING));
        assert_eq!(m, "Access denied by access condition", "{m}");
    }

    /// Under `Not`, the leaf that MATCHES is the one that refused. Reading the
    /// tree as "a leaf matched, so the build is fine" is exactly backwards.
    #[test]
    fn a_negated_leaf_names_the_running_build_it_refuses() {
        let m = message(&not(build(RUNNING)), Some(RUNNING));
        assert!(m.contains("refuses the running build") && m.contains(RUNNING), "{m}");
        assert!(!m.contains("locked to build"), "a negated leaf is not a lock: {m}");
        // And the other way: a build it does not name was refused by something
        // else, so no build claim at all.
        assert_eq!(message(&not(build(OTHER)), Some(RUNNING)), "Access denied by access condition");
    }

    /// An `Or` with one branch that says nothing about builds is not locked to
    /// anything: that branch refused for its own reason, whatever the build.
    #[test]
    fn an_or_with_a_build_free_branch_claims_no_lock() {
        let m = message(&or(vec![wl("bob.near"), build(OTHER)]), Some(RUNNING));
        assert_eq!(m, "Access denied by access condition", "{m}");
    }

    /// Every branch refused over a build, so the tree did.
    #[test]
    fn an_or_of_builds_alone_names_the_first() {
        let third = "3333333333333333333333333333333333333333333333333333333333333333";
        let m = message(&or(vec![build(OTHER), build(third)]), Some(RUNNING));
        assert!(m.contains(OTHER), "the first branch is named: {m}");
    }

    /// A tree with no build leaf keeps the sentence it always had — the lapsed
    /// grant here, which the build check must not shadow.
    #[test]
    fn a_time_limit_still_speaks_for_itself() {
        let dated = and(vec![wl("alice.near"), AccessCondition::ValidUntil { until_ns: "1".into() }]);
        assert!(message(&dated, Some(RUNNING)).contains("time limit passed"), "{}", message(&dated, Some(RUNNING)));
    }

    /// Both wrong: the build is named first, because it is the half the OWNER
    /// fixes by re-pointing the row.
    #[test]
    fn a_wrong_build_beside_a_lapsed_grant_names_the_build() {
        let both = and(vec![
            wl("alice.near"),
            build(OTHER),
            AccessCondition::ValidUntil { until_ns: "1".into() },
        ]);
        assert!(message(&both, Some(RUNNING)).contains("locked to build"), "{}", message(&both, Some(RUNNING)));
    }

    /// The shape the contract writes, as the keystore must read it.
    /// A request that named no build says nothing about builds. Reached in the
    /// deploy window — an old worker, a row whose whitelist excluded the
    /// caller — where blaming the build would send the owner to re-point a
    /// lock that was never the reason.
    #[test]
    fn a_request_with_no_build_blames_no_build() {
        assert_eq!(message(&and(vec![wl("bob.near"), build(RUNNING)]), None), "Access denied by access condition");
        assert_eq!(message(&build(RUNNING), None), "Access denied by access condition");
        assert_eq!(message(&not(build(RUNNING)), None), "Access denied by access condition");
    }
    /// An empty `Logic` is not a rule. The contract refuses to store one
    /// (`assert_logic_is_not_empty`), and this pins WHY: an `And` of nothing
    /// admits everybody, so a row opened that way would read as a condition
    /// rather than as the absence of one — and it is why an edit that lifts a
    /// lock out of a node must collapse the node rather than leave it empty.
    #[tokio::test]
    async fn an_empty_logic_node_is_not_a_rule() {
        let empty_and = AccessCondition::Logic { operator: LogicOperator::And, conditions: vec![] };
        let empty_or = AccessCondition::Logic { operator: LogicOperator::Or, conditions: vec![] };
        assert!(verdict(&empty_and, Some(RUNNING)).await.unwrap(), "an And of nothing admits everyone");
        assert!(!verdict(&empty_or, Some(RUNNING)).await.unwrap(), "an Or of nothing admits nobody");
    }


    #[test]
    fn the_contracts_json_round_trips() {
        let json = format!(r#"{{"WasmHash":{{"hash":"{RUNNING}"}}}}"#);
        let parsed: AccessCondition = serde_json::from_str(&json).expect("the contract's shape");
        assert_eq!(parsed, build(RUNNING));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
    }
}
