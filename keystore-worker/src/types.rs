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
/// before the epoch answers `u64::MAX`, so every time limit has lapsed: a
/// host whose time cannot be trusted admits nobody on the strength of it.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(u64::MAX)
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
    regex::Regex::new(&format!(r"\A(?:{})\z", pattern))
}

impl AccessCondition {
    /// Validate access condition against caller account
    ///
    /// Returns Ok(true) if access granted, Ok(false) if denied
    /// Returns Err if validation failed (e.g. invalid regex, RPC error)
    pub async fn validate(&self, caller: &str, near_client: Option<&crate::near::NearClient>) -> anyhow::Result<bool> {
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
                match compile_anchored_account_pattern(pattern) {
                    Ok(re) => {
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
                    Err(e) => {
                        tracing::warn!(
                            pattern = %pattern,
                            error = %e,
                            "Invalid regex pattern in AccessCondition"
                        );
                        // Invalid regex = deny access (fail-safe)
                        Ok(false)
                    }
                }
            }

            AccessCondition::Logic { operator, conditions } => {
                match operator {
                    LogicOperator::And => {
                        // All conditions must pass
                        for condition in conditions {
                            let fut = Box::pin(condition.validate(caller, near_client));
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
                            let fut = Box::pin(condition.validate(caller, near_client));
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
                let fut = Box::pin(condition.validate(caller, near_client));
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
                    None => {
                        tracing::warn!("NearBalance check requires NEAR client, but none provided");
                        return Ok(false);
                    }
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
                    None => {
                        tracing::warn!("FtBalance check requires NEAR client, but none provided");
                        return Ok(false);
                    }
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
                    None => {
                        tracing::warn!("NftOwned check requires NEAR client, but none provided");
                        return Ok(false);
                    }
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
                    None => {
                        tracing::warn!("DaoMember check requires NEAR client, but none provided");
                        return Ok(false);
                    }
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

            AccessCondition::ValidUntil { until_ns } => Ok(Self::valid_until_at(until_ns, now_ns())),
        }
    }

    /// `ValidUntil` at a given instant. A limit that does not parse denies —
    /// the owner wrote something the chain stored and nobody can read, and the
    /// safe reading of that is "not yet".
    fn valid_until_at(until_ns: &str, now: u64) -> bool {
        match until_ns.parse::<u64>() {
            Ok(until) => {
                let granted = now < until;
                tracing::debug!(condition = "ValidUntil", until_ns = %until, now_ns = %now, granted = %granted, "Validated time limit");
                granted
            }
            Err(_) => {
                tracing::warn!(condition = "ValidUntil", until_ns = %until_ns, "time limit is not a number; denying");
                false
            }
        }
    }

    /// A time limit that has passed AND necessarily stands in the way, if any —
    /// so a refusal can say "your grant lapsed at …" rather than only "denied".
    /// A hint for a person; the verdict is [`Self::validate`]'s. Named only
    /// where the lapse must be part of the reason: under `And` any lapsed leaf
    /// denies the whole; under `Or` only when every branch carries one (a live
    /// sibling branch means the caller was refused for something else); never
    /// under `Not`, where a passed limit is what ADMITS.
    pub fn lapsed_time_limit(&self, now: u64) -> Option<u64> {
        match self {
            AccessCondition::ValidUntil { until_ns } => until_ns.parse::<u64>().ok().filter(|until| *until <= now),
            AccessCondition::Logic { operator: LogicOperator::And, conditions } => {
                conditions.iter().find_map(|c| c.lapsed_time_limit(now))
            }
            AccessCondition::Logic { operator: LogicOperator::Or, conditions } => {
                let lapsed: Vec<u64> = conditions.iter().filter_map(|c| c.lapsed_time_limit(now)).collect();
                (!conditions.is_empty() && lapsed.len() == conditions.len()).then(|| lapsed[0])
            }
            _ => None,
        }
    }

    /// What a refused caller is told. Names a lapsed time limit when there is
    /// one, because that is the one refusal the owner fixes by re-granting
    /// rather than the caller by asking.
    /// The first `AccountPattern` in this tree that is not a valid regular
    /// expression, with the compiler's reason — `None` when every pattern
    /// compiles. Any position counts: a leaf that cannot be evaluated makes
    /// the whole condition unreadable, and an unreadable condition refuses the
    /// owner's own runs rather than being guessed at. Under `Not` the guess
    /// would ADMIT — a denying leaf negated — which is the wrong side to err on.
    pub fn unparseable_pattern(&self) -> Option<(String, String)> {
        match self {
            AccessCondition::AccountPattern { pattern } => compile_anchored_account_pattern(pattern)
                .err()
                .map(|e| (pattern.clone(), e.to_string())),
            AccessCondition::Logic { conditions, .. } => conditions.iter().find_map(|c| c.unparseable_pattern()),
            AccessCondition::Not { condition } => condition.unparseable_pattern(),
            _ => None,
        }
    }

    pub fn denial_message(&self) -> String {
        match self.lapsed_time_limit(now_ns()) {
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
    /// one that does not parse denies rather than erroring.
    #[test]
    fn a_time_limit_admits_before_and_denies_from_its_instant() {
        let until = T.to_string();
        assert!(AccessCondition::valid_until_at(&until, T - 1));
        assert!(!AccessCondition::valid_until_at(&until, T));
        assert!(!AccessCondition::valid_until_at(&until, T + 1));
        assert!(!AccessCondition::valid_until_at("soon", T - 1), "unparseable denies");
        assert!(!AccessCondition::valid_until_at("", T - 1));
        assert!(!AccessCondition::valid_until_at(&until, u64::MAX), "an untrusted clock (now_ns's fallback) denies");
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
        let far = (now_ns() + 3_600_000_000_000).to_string();
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

    /// The refusal names a lapsed limit wherever it sits in the tree, and says
    /// nothing about time when none has lapsed.
    #[test]
    fn a_lapsed_limit_is_found_in_the_tree_and_named() {
        let nested = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![
                AccessCondition::Whitelist { accounts: vec![] },
                AccessCondition::Logic {
                    operator: LogicOperator::And,
                    conditions: vec![
                        AccessCondition::Whitelist { accounts: vec!["a.near".into()] },
                        AccessCondition::ValidUntil { until_ns: T.to_string() },
                    ],
                },
            ],
        };
        // The other Or branch (an empty whitelist) carries no limit, so a caller
        // refused here was refused for not being on it — the lapse is not named.
        assert_eq!(nested.lapsed_time_limit(T + 5), None, "a live sibling branch means time was not the reason");
        assert_eq!(nested.lapsed_time_limit(T - 5), None, "a live limit is not lapsed");
        let and_only = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![
                AccessCondition::Whitelist { accounts: vec!["a.near".into()] },
                AccessCondition::ValidUntil { until_ns: T.to_string() },
            ],
        };
        assert_eq!(and_only.lapsed_time_limit(T + 5), Some(T), "under And a lapsed leaf is the reason");
        let all_lapsed = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![and_only.clone(), AccessCondition::ValidUntil { until_ns: (T - 1).to_string() }],
        };
        assert_eq!(all_lapsed.lapsed_time_limit(T + 5), Some(T), "every Or branch lapsed: time is the reason");
        let valid_after = AccessCondition::Not {
            condition: Box::new(AccessCondition::ValidUntil { until_ns: "1".to_string() }),
        };
        assert_eq!(valid_after.lapsed_time_limit(T), None, "under Not a passed limit admits");
        assert_eq!(AccessCondition::AllowAll.lapsed_time_limit(T), None);
        let lapsed = AccessCondition::ValidUntil { until_ns: "1".to_string() };
        assert_eq!(
            lapsed.denial_message(),
            "Access denied by access condition: its time limit passed at 1970-01-01T00:00:00Z"
        );
        assert_eq!(
            AccessCondition::Whitelist { accounts: vec![] }.denial_message(),
            "Access denied by access condition"
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
        // A pattern that unbalances the wrapper is invalid → fail-closed deny.
        let broken = AccessCondition::AccountPattern { pattern: ")".to_string() };
        assert!(!broken.validate("anything.near", None).await.unwrap());
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
        // Invalid regex should deny access
        assert!(!condition.validate("alice.near", None).await.unwrap());
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
mod an_unreadable_condition_refuses_wherever_it_sits {
    //! Plan U12b: a malformed condition (a bad regex) refuses that owner's own
    //! runs with a parse message. The parse check runs before evaluation
    //! because evaluation alone gets one placement wrong: a bad pattern denies
    //! as a leaf, and `Not` over a denying leaf ADMITS.
    use super::*;

    fn bad() -> AccessCondition {
        AccessCondition::AccountPattern { pattern: "(".to_string() }
    }
    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(f)
    }

    #[test]
    fn a_bad_pattern_is_found_and_named() {
        let (pattern, why) = bad().unparseable_pattern().expect("found");
        assert_eq!(pattern, "(");
        assert!(!why.is_empty(), "the compiler's reason travels with it");
    }

    #[test]
    fn a_valid_pattern_is_not_reported() {
        let ok = AccessCondition::AccountPattern { pattern: ".*\\.near".to_string() };
        assert!(ok.unparseable_pattern().is_none());
        assert!(AccessCondition::AllowAll.unparseable_pattern().is_none());
    }

    #[test]
    fn found_under_and_or_and_not() {
        let under_and = AccessCondition::Logic {
            operator: LogicOperator::And,
            conditions: vec![AccessCondition::AllowAll, bad()],
        };
        let under_or = AccessCondition::Logic {
            operator: LogicOperator::Or,
            conditions: vec![AccessCondition::AllowAll, bad()],
        };
        let under_not = AccessCondition::Not { condition: Box::new(bad()) };
        for c in [under_and, under_or, under_not] {
            assert_eq!(c.unparseable_pattern().map(|(p, _)| p).as_deref(), Some("("));
        }
    }

    #[test]
    fn evaluated_alone_a_bad_pattern_under_not_would_admit_everyone() {
        // The reason the parse check exists: this is what `validate` says.
        let under_not = AccessCondition::Not { condition: Box::new(bad()) };
        let admitted = run(under_not.validate("anyone.near", None)).expect("validate answers");
        assert!(admitted, "a denying leaf negated admits — so the door must refuse before evaluating");
    }
}
