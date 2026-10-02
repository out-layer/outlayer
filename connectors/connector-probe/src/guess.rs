//! A guessing game played through tasks: a conversation of several turns
//! between an agent and its owner, played by the agent's runs, with a secret
//! neither of them reads.
//!
//! `guess_start` (the agent) picks a number from 1 to `max` and opens an
//! `input` task for the owner of the row the run names. The owner answers it
//! in the inbox with one signature; the platform starts `guess` as a run of
//! the agent, which judges the guess, reports the turn, and opens the next
//! task of the same thread: a turn that says `higher` or `lower` and counts
//! the attempts, or — when the guess was right — a notice that says so and
//! asks nothing. Every turn is the agent's.
//!
//! The secret lives in the task's sealed `state`, handed from turn to turn,
//! and nowhere else: nothing but the sealed task is kept between runs, so a
//! game leaves no record behind it. The envelope the owner reads carries
//! `state_hash`, the SHA-256 of the state bytes, so the state carries a random
//! salt beside the secret: without it, hashing every state for 1 to `max` would
//! name the secret.

use outlayer::tasks::{self, Display, FieldKind, Supplies, WrittenBy};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::ops::RangeInclusive;

/// The operation that answers every task of the game.
pub const ANSWER_BY: &str = "guess";

/// `max` when the call names none.
pub const DEFAULT_MAX: u64 = 100;

/// The `max` a call may name.
pub const MAX_BOUNDS: RangeInclusive<u64> = 2..=1000;

/// Random bytes sealed beside the secret: over the 16 that put a table of
/// every state out of reach.
pub const SALT_BYTES: usize = 32;

const TITLE: &str = "Guess my number";

/// The policy every task of the game is made and answered under. The game has
/// no policy of the owner's to read, so it is a constant, and a turn is never
/// void by it.
const POLICY: &[u8] = b"";

/// The `max` of a `guess_start` call: [`DEFAULT_MAX`] when it names none.
pub fn parse_max(input: &Value) -> Result<u64, String> {
    match input.get("max") {
        None | Some(Value::Null) => Ok(DEFAULT_MAX),
        Some(named) => named.as_u64().filter(|max| MAX_BOUNDS.contains(max)).ok_or_else(|| {
            format!(
                "invalid_request: `max` is a whole number from {} to {}, not {named}",
                MAX_BOUNDS.start(),
                MAX_BOUNDS.end()
            )
        }),
    }
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("no randomness for the game ({e}); no task was opened"))?;
    Ok(bytes)
}

/// A number from 1 to `max`, each equally likely: a draw past the last whole
/// multiple of `max` is drawn again.
fn random_secret(max: u64) -> Result<u64, String> {
    let whole = u64::MAX - u64::MAX % max;
    loop {
        let drawn = u64::from_le_bytes(random::<8>()?);
        if drawn < whole {
            return Ok(drawn % max + 1);
        }
    }
}

/// The game as it is sealed in a task's state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Game {
    /// [`SALT_BYTES`] random bytes, in hex.
    salt: String,
    secret: u64,
    max: u64,
    /// The guesses taken so far, a guess that was not a number among them.
    attempts: u64,
}

impl Game {
    /// A new game with a random secret.
    pub fn new(max: u64) -> Result<Self, String> {
        Self::salted(random_secret(max)?, max)
    }

    /// A new game with `secret` and a fresh salt.
    pub fn salted(secret: u64, max: u64) -> Result<Self, String> {
        Ok(Self { salt: hex::encode(random::<SALT_BYTES>()?), secret, max, attempts: 0 })
    }

    pub fn state(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a game is plain JSON")
    }

    /// The game a task's state holds. The state is the game's own, sealed by
    /// the enclave, so a state that does not read is a fault, never a move.
    pub fn from_state(state: &[u8]) -> Result<Self, String> {
        let game: Self = serde_json::from_slice(state).map_err(|e| format!("the game's state does not read: {e}"))?;
        let salted = hex::decode(&game.salt).map(|salt| salt.len() == SALT_BYTES).unwrap_or(false);
        if !salted || !MAX_BOUNDS.contains(&game.max) || !(1..=game.max).contains(&game.secret) {
            return Err("the game's state is not a game this build makes".to_string());
        }
        Ok(game)
    }

    /// The turn a guess makes: every guess is an attempt, a guess that is not a
    /// number from 1 to `max` among them.
    pub fn play(&self, supplied: Option<&[u8]>) -> Turn {
        let guess = read_guess(supplied, self.max);
        Turn { guess, verdict: judge(self.secret, guess), game: Self { attempts: self.attempts + 1, ..self.clone() } }
    }

    fn question(&self) -> String {
        format!("I picked a number from 1 to {}. Your guess?", self.max)
    }
}

/// What a guess is to the secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Higher,
    Lower,
    Right,
    /// Not a number from 1 to `max`: a wrong turn, and the game goes on.
    NotANumber,
}

impl Verdict {
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Higher => "higher",
            Verdict::Lower => "lower",
            Verdict::Right => "right",
            Verdict::NotANumber => "not_a_number",
        }
    }
}

/// The owner's text as a guess: a whole number from 1 to `max`, spaces around
/// it allowed.
pub fn read_guess(supplied: Option<&[u8]>, max: u64) -> Option<u64> {
    let text = std::str::from_utf8(supplied?).ok()?.trim();
    text.parse::<u64>().ok().filter(|guess| (1..=max).contains(guess))
}

pub fn judge(secret: u64, guess: Option<u64>) -> Verdict {
    match guess {
        None => Verdict::NotANumber,
        Some(guess) if guess < secret => Verdict::Higher,
        Some(guess) if guess > secret => Verdict::Lower,
        Some(_) => Verdict::Right,
    }
}

/// One turn: the guess read, what it is to the secret, and the game after it.
#[derive(Debug, Clone, PartialEq)]
pub struct Turn {
    pub guess: Option<u64>,
    pub verdict: Verdict,
    pub game: Game,
}

impl Turn {
    pub fn goes_on(&self) -> bool {
        self.verdict != Verdict::Right
    }

    /// What the next task tells the owner about this guess.
    pub fn hint(&self) -> String {
        match self.verdict {
            Verdict::Higher => "higher".to_string(),
            Verdict::Lower => "lower".to_string(),
            Verdict::Right => "right".to_string(),
            Verdict::NotANumber => format!("not a number from 1 to {}", self.game.max),
        }
    }

    /// The turn in a sentence, for the preparer's report and the run's answer.
    pub fn sentence(&self) -> String {
        let n = self.game.attempts;
        match (self.verdict, self.guess) {
            (Verdict::Right, _) => format!("guessed in {n} {}", if n == 1 { "attempt" } else { "attempts" }),
            (_, Some(guess)) => format!("attempt {n}: {guess} is wrong, the number is {}", self.hint()),
            (_, None) => format!("attempt {n}: {}", self.hint()),
        }
    }

    /// The title of the notice a right guess leaves the owner.
    pub fn told(&self) -> String {
        let n = self.game.attempts;
        format!("You guessed it: {}, in {n} {}", self.game.secret, if n == 1 { "attempt" } else { "attempts" })
    }

    /// The fields of the next task: what this turn said, and the question.
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = Vec::new();
        if let Some(guess) = self.guess {
            fields.push(("Your guess", guess.to_string()));
        }
        fields.push(("Answer", self.hint()));
        fields.push(("Attempts", self.game.attempts.to_string()));
        fields.push(("Question", self.game.question()));
        fields
    }

    /// What `guess` reports to the preparer of the task it answered.
    pub fn result(&self) -> Value {
        json!({
            "attempt": self.game.attempts,
            "guess": self.guess,
            "verdict": self.verdict.name(),
            "max": self.game.max,
            "detail": self.sentence(),
        })
    }
}

fn task(game: &Game, fields: Vec<(&'static str, String)>) -> tasks::Task {
    let display = fields
        .into_iter()
        .fold(Display::new(TITLE), |display, (label, value)| display.field(label, FieldKind::Text, &value, WrittenBy::Project));
    tasks::input(display, ANSWER_BY, Supplies::Text, &game.state(), POLICY)
}

/// `guess_start`: a new game, and its first task. Answers `max` and the task
/// as `tasks::awaiting_owner` spells it.
pub fn start(input: &Value) -> Result<(u64, Value), String> {
    let max = parse_max(input)?;
    let game = Game::new(max)?;
    let opened = task(&game, vec![("Question", game.question())]).open().map_err(|e| e.refusal())?;
    Ok((max, tasks::awaiting_owner(&opened)))
}

/// The notice of a right guess: the number and the count, and nothing asked.
fn notice(turn: &Turn) -> tasks::Task {
    let display = Display::new(&turn.told())
        .field("Number", FieldKind::Text, &turn.game.secret.to_string(), WrittenBy::Project)
        .field("Attempts", FieldKind::Text, &turn.game.attempts.to_string(), WrittenBy::Project);
    tasks::notice(display, POLICY)
}

/// What a `guess` call did.
pub struct Answered {
    pub turn: Turn,
    /// What was reported to the preparer of the task answered.
    pub result: Value,
    /// What was opened next in the thread: the next turn, as
    /// `tasks::awaiting_owner` spells it, while the game goes on; the notice
    /// of the right guess, as `tasks::notified` spells it, when it is won. Or
    /// why it was not opened.
    pub next: Result<Value, String>,
}

/// `guess`: the agent's run on the owner's answer to a turn. Judges it, opens
/// the next turn when the game goes on, and reports.
pub fn answer(input: &Value) -> Result<Answered, String> {
    let answer = tasks::answered_for(ANSWER_BY, input, POLICY).map_err(|e| e.refusal())?;
    // A state that does not read is not reported on: the task ends `failed`.
    let game = Game::from_state(&answer.state)?;
    let turn = game.play(answer.supplied.as_deref());
    let next = match turn.goes_on() {
        true => task(&turn.game, turn.fields()).open().map(|opened| tasks::awaiting_owner(&opened)),
        false => notice(&turn).open().map(|opened| tasks::notified(&opened)),
    }
    .map_err(|e| e.refusal());
    let mut result = turn.result();
    let (named, failed) = match turn.goes_on() {
        true => ("next_task_id", "next_error"),
        false => ("notice_task_id", "notice_error"),
    };
    match &next {
        Ok(opened) => result[named] = opened["task_id"].clone(),
        Err(refusal) => result[failed] = json!(refusal),
    }
    tasks::report(&answer.id, result.to_string().as_bytes()).map_err(|e| e.refusal())?;
    Ok(Answered { turn, result, next })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn game(secret: u64, max: u64) -> Game {
        Game::salted(secret, max).unwrap()
    }

    #[test]
    fn max_is_100_unless_named_and_named_within_2_to_1000() {
        assert_eq!(parse_max(&json!({})), Ok(100));
        assert_eq!(parse_max(&json!({ "max": null })), Ok(100));
        assert_eq!(parse_max(&json!({ "max": 2 })), Ok(2));
        assert_eq!(parse_max(&json!({ "max": 1000 })), Ok(1000));
        for bad in [json!(1), json!(0), json!(1001), json!(-5), json!(50.5), json!("50"), json!(true)] {
            let refusal = parse_max(&json!({ "max": bad })).unwrap_err();
            assert!(refusal.starts_with("invalid_request: `max` is a whole number from 2 to 1000"), "{refusal}");
        }
    }

    #[test]
    fn a_secret_is_within_the_range() {
        for max in [2, 3, 100, 1000] {
            for _ in 0..200 {
                assert!((1..=max).contains(&random_secret(max).unwrap()));
            }
        }
        let g = Game::new(2).unwrap();
        assert!((1..=2).contains(&g.secret) && g.attempts == 0);
    }

    #[test]
    fn a_guess_below_is_higher_above_is_lower_and_equal_is_right() {
        assert_eq!(judge(42, Some(41)), Verdict::Higher);
        assert_eq!(judge(42, Some(1)), Verdict::Higher);
        assert_eq!(judge(42, Some(43)), Verdict::Lower);
        assert_eq!(judge(42, Some(100)), Verdict::Lower);
        assert_eq!(judge(42, Some(42)), Verdict::Right);
        assert_eq!(judge(42, None), Verdict::NotANumber);
    }

    #[test]
    fn a_guess_is_a_whole_number_from_1_to_max() {
        assert_eq!(read_guess(Some(b"42"), 100), Some(42));
        assert_eq!(read_guess(Some(b"  42\n"), 100), Some(42));
        assert_eq!(read_guess(Some(b"1"), 100), Some(1));
        assert_eq!(read_guess(Some(b"100"), 100), Some(100));
        for bad in [&b"0"[..], b"101", b"-5", b"4.2", b"forty-two", b"", b"  ", b"42 43", &[0xff, 0xfe]] {
            assert_eq!(read_guess(Some(bad), 100), None, "{:?}", String::from_utf8_lossy(bad));
        }
        assert_eq!(read_guess(None, 100), None);
    }

    #[test]
    fn two_games_with_one_secret_seal_different_states_that_carry_the_salt() {
        let (a, b) = (game(42, 100), game(42, 100));
        assert_eq!((a.secret, b.secret), (42, 42));
        let (sa, sb) = (a.state(), b.state());
        assert_ne!(sa, sb, "the same secret seals different states");
        assert_ne!(Sha256::digest(&sa), Sha256::digest(&sb), "so the owner reads different state hashes");
        for (g, state) in [(&a, &sa), (&b, &sb)] {
            let salt = hex::decode(&g.salt).unwrap();
            assert!(salt.len() >= 16);
            let text = String::from_utf8(state.clone()).unwrap();
            assert!(text.contains(&g.salt), "the state bytes carry the salt");
        }
        // Nobody hashes their way to the secret: no unsalted state matches.
        let unsalted = |secret: u64| serde_json::to_vec(&json!({ "secret": secret, "max": 100, "attempts": 0 })).unwrap();
        assert!((1..=100).all(|secret| Sha256::digest(unsalted(secret)) != Sha256::digest(&sa)));
    }

    #[test]
    fn a_state_reads_back_as_its_game_and_nothing_else_reads() {
        let g = game(7, 10);
        assert_eq!(Game::from_state(&g.state()), Ok(g.clone()));
        let turned = g.play(Some(b"3")).game;
        assert_eq!(Game::from_state(&turned.state()).unwrap().attempts, 1);

        let with = |salt: &str, secret: u64, max: u64| {
            serde_json::to_vec(&json!({ "salt": salt, "secret": secret, "max": max, "attempts": 0 })).unwrap()
        };
        let salt = "ab".repeat(SALT_BYTES);
        assert!(Game::from_state(&with(&salt, 7, 10)).is_ok());
        assert!(Game::from_state(&with("abcd", 7, 10)).is_err(), "a short salt");
        assert!(Game::from_state(&with(&salt, 0, 10)).is_err());
        assert!(Game::from_state(&with(&salt, 11, 10)).is_err());
        assert!(Game::from_state(&with(&salt, 1, 1)).is_err());
        assert!(Game::from_state(b"not json").is_err());
    }

    #[test]
    fn a_wrong_guess_opens_the_next_turn_with_higher_or_lower_and_the_count() {
        let g = game(42, 100);
        let low = g.play(Some(b"10"));
        assert_eq!((low.verdict, low.goes_on(), low.game.attempts), (Verdict::Higher, true, 1));
        assert_eq!(
            low.fields(),
            vec![
                ("Your guess", "10".to_string()),
                ("Answer", "higher".to_string()),
                ("Attempts", "1".to_string()),
                ("Question", "I picked a number from 1 to 100. Your guess?".to_string()),
            ]
        );
        let high = low.game.play(Some(b"60"));
        assert_eq!((high.verdict, high.game.attempts, high.hint().as_str()), (Verdict::Lower, 2, "lower"));
        assert_eq!(high.sentence(), "attempt 2: 60 is wrong, the number is lower");
        assert_eq!(high.result()["verdict"], "lower");
        assert_eq!(high.game.secret, 42, "the secret goes on");
    }

    #[test]
    fn a_right_guess_ends_the_game_with_the_count() {
        let g = game(42, 100);
        let first = g.play(Some(b"42"));
        assert_eq!((first.verdict, first.goes_on()), (Verdict::Right, false));
        assert_eq!(first.sentence(), "guessed in 1 attempt");

        let third = g.play(Some(b"10")).game.play(Some(b"90")).game.play(Some(b" 42 "));
        assert!(!third.goes_on());
        assert_eq!(third.sentence(), "guessed in 3 attempts");
        let result = third.result();
        assert_eq!((result["verdict"].as_str(), result["attempt"].as_u64()), (Some("right"), Some(3)));
        assert_eq!(result["detail"], "guessed in 3 attempts");
    }

    #[test]
    fn a_guess_that_is_not_a_number_is_a_wrong_turn_and_the_next_task_says_so() {
        let g = game(42, 100);
        for bad in [&b"banana"[..], b"0", b"101", b"-1", b""] {
            let turn = g.play(Some(bad));
            assert_eq!(turn.verdict, Verdict::NotANumber);
            assert!(turn.goes_on(), "the game does not end on a bad guess");
            assert_eq!((turn.game.secret, turn.game.attempts), (42, 1));
            assert_eq!(turn.hint(), "not a number from 1 to 100");
            assert_eq!(
                turn.fields(),
                vec![
                    ("Answer", "not a number from 1 to 100".to_string()),
                    ("Attempts", "1".to_string()),
                    ("Question", "I picked a number from 1 to 100. Your guess?".to_string()),
                ],
                "the owner's text is not shown back: it is not a number and may not be drawable"
            );
            assert_eq!(turn.sentence(), "attempt 1: not a number from 1 to 100");
            assert_eq!(turn.result()["guess"], Value::Null);
        }
        let none = g.play(None);
        assert_eq!((none.verdict, none.goes_on()), (Verdict::NotANumber, true));
        // And the game goes on to be won.
        let won = g.play(Some(b"banana")).game.play(Some(b"42"));
        assert_eq!(won.sentence(), "guessed in 2 attempts");
    }

    #[test]
    fn the_right_guess_tells_the_number_and_the_count_and_a_wrong_one_opens_the_next_turn() {
        let won = game(57, 100).play(Some(b"10")).game.play(Some(b"57"));
        assert_eq!(won.told(), "You guessed it: 57, in 2 attempts");
        assert_eq!(game(5, 10).play(Some(b"5")).told(), "You guessed it: 5, in 1 attempt");
        let told = notice(&won);
        let shown = format!("{told:?}");
        assert!(shown.contains("TaskKind::Notice") && shown.contains("answer-by: None"), "{shown}");
        assert!(shown.contains("\"Number\"") && shown.contains("\"57\"") && shown.contains("\"Attempts\""), "{shown}");
        assert!(!shown.contains(&won.game.salt), "the notice carries nothing of the state");
        let longest = game(1000, 1000).play(Some(b"1000"));
        assert!(longest.told().chars().count() <= 80, "{}", longest.told());
    }

    #[test]
    fn every_label_and_value_is_within_the_display_bounds() {
        let g = game(1000, 1000);
        for turn in [g.play(Some(b"1")), g.play(Some(b"x")), g.play(Some(b"1000"))] {
            for (label, value) in turn.fields() {
                assert!(label.chars().count() <= 40 && value.chars().count() <= 500, "{label}: {value}");
            }
        }
        assert!(TITLE.chars().count() <= 80);
    }
}
