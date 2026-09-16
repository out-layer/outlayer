use near_sdk::json_types::U64;
use near_sdk::{near, AccountId, NearToken};

// V1 enums for backward compatibility
#[derive(PartialEq, Debug, Clone, Copy)]
#[near(serializers=[borsh, json])]
pub enum LogicOperatorV1 {
    And,
    Or,
}

#[derive(PartialEq, Debug, Clone, Copy)]
#[near(serializers=[borsh, json])]
pub enum ComparisonOperatorV1 {
    Gte, // >=
    Lte, // <=
    Gt,  // >
    Lt,  // <
    Eq,  // ==
    Ne,  // !=
}

/// Access control conditions for secrets (V1)
/// Supports complex logic combinations with regex patterns
#[derive(Clone, Debug, PartialEq)]
#[near(serializers=[borsh, json])]
pub enum AccessConditionV1 {
    /// Logical combination of conditions
    Logic {
        operator: LogicOperatorV1,
        conditions: Vec<AccessConditionV1>,
    },
    /// Logical NOT
    Not {
        condition: Box<AccessConditionV1>,
    },
    /// Allow all accounts
    AllowAll,
    /// Whitelist specific accounts
    Whitelist {
        accounts: Vec<AccountId>,
    },
    /// Match the caller's account id against a regular expression.
    ///
    /// The contract STORES this pattern and signs it into the message that
    /// authorises the write; it never evaluates it. Evaluation happens in the
    /// keystore, which compiles it anchored — `\A(?:…)\z` — so the pattern must
    /// match the WHOLE id and never a substring. A pattern meant as an exact
    /// check does not silently admit `victim.near.attacker.near`.
    ///
    /// Two regex facts still bite the unwary, so prefer [`AccessCondition::Whitelist`]
    /// when the intent is an exact set of accounts:
    ///   * `.` is a metacharacter — write `\.` for a literal dot, or
    ///     `team.near` also admits `teamXnear`;
    ///   * a pattern is only as tight as it is written — `.*\.gov\.near` admits
    ///     every `*.gov.near`, which may be wider than intended.
    ///
    /// Nothing here validates the pattern: one that does not compile is stored
    /// happily and then denies every caller, because the keystore refuses a
    /// condition it cannot read. What the contract does bound is how many
    /// patterns a condition holds and their total length
    /// (`MAX_ACCOUNT_PATTERNS`, `MAX_ACCOUNT_PATTERN_BYTES` in `secrets.rs`) —
    /// the same numbers the keystore judges by.
    ///
    /// Example: `.*\.gov\.near` matches any `*.gov.near` account and only those.
    AccountPattern {
        pattern: String,
    },
    /// Require minimum NEAR balance
    NearBalance {
        operator: ComparisonOperatorV1,
        value: NearToken,
    },
    /// Require minimum fungible token balance
    FtBalance {
        contract: AccountId,
        operator: ComparisonOperatorV1,
        value: NearToken,
    },
    /// Require NFT ownership
    /// token_id: None = any token from this contract
    /// token_id: Some("123") = specific token ID
    NftOwned {
        contract: AccountId,
        token_id: Option<String>,
    },
    /// Require DAO membership (Sputnik v2 compatible)
    /// Checks if caller is member of specified role in DAO
    /// role: "council", "members", etc.
    DaoMember {
        dao_contract: AccountId,
        role: String,
    },
    /// Admit only until a moment in time (nanoseconds since the epoch, the
    /// chain's own unit). Composed with the others: `And[Whitelist[agent],
    /// ValidUntil(t)]` is a grant to one agent that lapses on its own, and
    /// `Not { ValidUntil }` reads as "valid after". Evaluated by the keystore
    /// against its clock, like every other condition; stored here.
    ///
    /// Every variant from here on is APPENDED, never inserted or reordered:
    /// `SecretProfile.access` is stored as Borsh of this enum directly, so a
    /// variant's index is its position here, and every row already on chain
    /// decodes by that position.
    ValidUntil {
        until_ns: U64,
    },
    /// Admit only a run of one exact build: the SHA-256 of the WebAssembly
    /// bytes that execute, 64 lowercase hex characters. Composed with the
    /// others — `And[Whitelist[owner], WasmHash(h)]` is the owner's secret
    /// that a rebuild cannot open; `update_access` moves it to the next build
    /// without touching the ciphertext. The contract stores the hash; the
    /// keystore judges it against the hash the attested worker measured on
    /// the bytes it loaded, never one the call or the guest supplied.
    WasmHash {
        hash: String,
    },
    /// Judge the inner condition against the account that CALLED the
    /// contract — `predecessor_account_id` — instead of the account that
    /// signed the transaction. Every other leaf is judged against the
    /// signer, so a contract the owner signs any transaction to can relay a
    /// `request_execution` that names the owner's row: the signer is still
    /// the owner, and the whitelist admits. This wrapper is the owner's way
    /// to say who may stand in between. `And[Whitelist[me],
    /// Predecessor{Whitelist[me]}]` admits only a call the owner makes
    /// directly, with no contract in the way; `Predecessor{Whitelist[dao]}`
    /// admits on-chain calls through that DAO and through no other contract.
    /// Any leaf composes inside it — `DaoMember`, a balance, a pattern —
    /// judged on the calling account. Over HTTPS there is no transaction and
    /// nothing in between: the payer is judged as the calling account too,
    /// so there `Predecessor{X}` is `X`. Evaluated by the keystore; stored here. The
    /// calling account has no predecessor of its own, so a `Predecessor`
    /// nested in a `Predecessor` judges the same account again.
    Predecessor {
        condition: Box<AccessConditionV1>,
    },
}

// Versioned enums for future upgrades
#[derive(Clone)]
#[near(serializers=[borsh])]
pub enum VersionedLogicOperator {
    V1(LogicOperatorV1),
}

#[derive(Clone)]
#[near(serializers=[borsh])]
pub enum VersionedComparisonOperator {
    V1(ComparisonOperatorV1),
}

#[derive(Clone)]
#[near(serializers=[borsh])]
pub enum VersionedAccessCondition {
    V1(AccessConditionV1),
}

// Migration traits and implementations
impl From<VersionedLogicOperator> for LogicOperatorV1 {
    fn from(versioned: VersionedLogicOperator) -> Self {
        match versioned {
            VersionedLogicOperator::V1(operator) => operator,
        }
    }
}

impl From<VersionedComparisonOperator> for ComparisonOperatorV1 {
    fn from(versioned: VersionedComparisonOperator) -> Self {
        match versioned {
            VersionedComparisonOperator::V1(operator) => operator,
        }
    }
}

impl From<VersionedAccessCondition> for AccessConditionV1 {
    fn from(versioned: VersionedAccessCondition) -> Self {
        match versioned {
            VersionedAccessCondition::V1(condition) => condition,
        }
    }
}

// Conversion from current types to versioned
impl From<LogicOperatorV1> for VersionedLogicOperator {
    fn from(operator: LogicOperatorV1) -> Self {
        VersionedLogicOperator::V1(operator)
    }
}

impl From<ComparisonOperatorV1> for VersionedComparisonOperator {
    fn from(operator: ComparisonOperatorV1) -> Self {
        VersionedComparisonOperator::V1(operator)
    }
}

impl From<AccessConditionV1> for VersionedAccessCondition {
    fn from(condition: AccessConditionV1) -> Self {
        VersionedAccessCondition::V1(condition)
    }
}

// Current type alias (points to latest version)
pub type AccessCondition = AccessConditionV1;

#[cfg(test)]
mod tests {
    use super::*;

    /// Variant positions are storage layout. `DaoMember` was the last variant
    /// when rows were first written; `ValidUntil` sits after it and nothing may
    /// be inserted before either.
    #[test]
    fn borsh_positions_are_the_layout_rows_were_written_in() {
        use near_sdk::borsh;
        let dao = AccessCondition::DaoMember {
            dao_contract: "dao.near".parse().unwrap(),
            role: "council".to_string(),
        };
        let until = AccessCondition::ValidUntil { until_ns: U64(1_760_000_000_000_000_000) };
        let build = AccessCondition::WasmHash { hash: "0".repeat(64) };
        let via = AccessCondition::Predecessor { condition: Box::new(AccessCondition::AllowAll) };
        assert_eq!(borsh::to_vec(&dao).unwrap()[0], 8, "DaoMember is the ninth variant");
        assert_eq!(borsh::to_vec(&until).unwrap()[0], 9, "ValidUntil is appended after it");
        assert_eq!(borsh::to_vec(&build).unwrap()[0], 10, "WasmHash after that");
        assert_eq!(borsh::to_vec(&via).unwrap()[0], 11, "Predecessor after that");
        assert_eq!(borsh::to_vec(&AccessCondition::AllowAll).unwrap()[0], 2);
    }

    /// The JSON a client sends for a predecessor rule: the same shape as `Not`,
    /// one nested condition under `condition`.
    #[test]
    fn a_predecessor_rule_wraps_one_condition_like_not_does() {
        let json = r#"{"Predecessor":{"condition":{"Whitelist":{"accounts":["dao.near"]}}}}"#;
        let parsed: AccessCondition = near_sdk::serde_json::from_str(json).unwrap();
        assert_eq!(
            parsed,
            AccessCondition::Predecessor {
                condition: Box::new(AccessCondition::Whitelist { accounts: vec!["dao.near".parse().unwrap()] })
            }
        );
        assert_eq!(near_sdk::serde_json::to_string(&parsed).unwrap(), json);
    }

    /// The JSON a client sends, round-tripped: a string for the time, since
    /// nanoseconds overflow JSON numbers.
    #[test]
    fn valid_until_is_written_as_a_string_of_nanoseconds() {
        let json = r#"{"ValidUntil":{"until_ns":"1760000000000000000"}}"#;
        let parsed: AccessCondition = near_sdk::serde_json::from_str(json).unwrap();
        assert_eq!(parsed, AccessCondition::ValidUntil { until_ns: U64(1_760_000_000_000_000_000) });
        assert_eq!(near_sdk::serde_json::to_string(&parsed).unwrap(), json);
    }

    /// The contract's JSON shape for a whitelist is the struct variant,
    /// `{"Whitelist":{"accounts":[...]}}`. A bare array under the variant name is
    /// not a whitelist and must not be read as one.
    #[test]
    fn a_whitelist_is_an_object_with_accounts_not_a_bare_array() {
        let shaped = r#"{"Whitelist":{"accounts":["alice.near"]}}"#;
        assert!(near_sdk::serde_json::from_str::<AccessCondition>(shaped).is_ok());
        let bare = r#"{"Whitelist":["alice.near"]}"#;
        assert!(near_sdk::serde_json::from_str::<AccessCondition>(bare).is_err());
    }

    #[test]
    fn test_access_condition_serialization() {
        let condition = AccessCondition::AllowAll;
        let json = near_sdk::serde_json::to_string(&condition).unwrap();
        assert!(json.contains("AllowAll"));
    }

    #[test]
    fn test_whitelist_condition() {
        let condition = AccessCondition::Whitelist {
            accounts: vec!["alice.near".parse().unwrap(), "bob.near".parse().unwrap()],
        };
        assert_eq!(condition, condition.clone());
    }

    #[test]
    fn test_pattern_condition() {
        let condition = AccessCondition::AccountPattern {
            pattern: String::from(".*\\.gov\\.near"),
        };
        let json = near_sdk::serde_json::to_string(&condition).unwrap();
        assert!(json.contains("AccountPattern"));
        assert!(json.contains("\\\\.gov\\\\.near")); // escaped in JSON
    }

    #[test]
    fn test_logic_and_condition() {
        let condition = AccessCondition::Logic {
            operator: LogicOperatorV1::And,
            conditions: vec![
                AccessCondition::AccountPattern {
                    pattern: String::from(".*\\.near"),
                },
                AccessCondition::NearBalance {
                    operator: ComparisonOperatorV1::Gte,
                    value: NearToken::from_near(10),
                },
            ],
        };
        assert_eq!(condition, condition.clone());
    }

    #[test]
    fn test_not_condition() {
        let condition = AccessCondition::Not {
            condition: Box::new(AccessCondition::AccountPattern {
                pattern: String::from(".*\\.blocked\\.near"),
            }),
        };
        assert_eq!(condition, condition.clone());
    }

    #[test]
    fn test_versioned_conversion() {
        let original = AccessCondition::AllowAll;
        let versioned: VersionedAccessCondition = original.clone().into();
        let back: AccessCondition = versioned.into();
        assert_eq!(original, back);
    }
}
