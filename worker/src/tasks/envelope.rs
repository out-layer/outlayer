//! A task's envelope: everything of a task but the component's own `state`,
//! as one canonical JSON document, and the check of what a task shows.
//!
//! The envelope's bytes are what the owner's page decrypts and draws, and
//! `task_hash` is the SHA-256 of exactly those bytes: the page hashes what it
//! opened, the owner's answer names that hash, and the host compares it with
//! the hash of the envelope it holds sealed. So what was shown is what is
//! acted on. The document is written with its members in one fixed order
//! (alphabetical, at every level), without insignificant whitespace; nothing
//! re-serialises it on the way.
//!
//! **What a task shows** is data for one card the dashboard draws. The check
//! here bounds it and refuses what could mislead the eye even as plain text:
//! control characters, the characters that reorder or hide text or are drawn
//! as nothing, and combining marks stacked over the lines around them.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The envelope's format.
pub const VERSION: u32 = 1;

pub const MAX_TITLE_CHARS: usize = 80;
pub const MAX_FIELDS: usize = 12;
pub const MAX_LABEL_CHARS: usize = 40;
pub const MAX_LONG_TEXT_CHARS: usize = 50_000;
pub const MAX_FILE_NAME_CHARS: usize = 200;
pub const MAX_CONTENT_TYPE_CHARS: usize = 100;
pub const MAX_TEXT_CHARS: usize = 500;
pub const MAX_SHORT_CHARS: usize = 200;
pub const MAX_LIST_ITEMS: usize = 20;
pub const MAX_OPERATION_CHARS: usize = 64;
/// Most combining marks in a row: more stack over the neighbouring lines.
pub const MAX_COMBINING_RUN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Confirm,
    Input,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Money,
    Account,
    Address,
    Text,
    LongText,
    List,
}

impl FieldKind {
    fn name(self) -> &'static str {
        match self {
            Self::Money => "money",
            Self::Account => "account",
            Self::Address => "address",
            Self::Text => "text",
            Self::LongText => "long_text",
            Self::List => "list",
        }
    }

    fn most_chars(self) -> usize {
        match self {
            Self::LongText => MAX_LONG_TEXT_CHARS,
            Self::Text => MAX_TEXT_CHARS,
            Self::Money | Self::Account | Self::Address | Self::List => MAX_SHORT_CHARS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WrittenBy {
    Project,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Supplies {
    Nothing,
    Text,
    File,
}

/// One field. Members in alphabetical order: the order they are written in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub kind: FieldKind,
    pub label: String,
    pub values: Vec<String>,
    pub written_by: WrittenBy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Display {
    pub fields: Vec<Field>,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnswerBy {
    pub operation: String,
    pub supplies: Supplies,
}

/// What the envelope says of a file: enough for the owner's page to list it,
/// and to tell that the bytes it opened are the ones the task was made with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileNote {
    pub content_type: String,
    pub name: String,
    /// SHA-256 of the file's bytes, hex.
    pub sha256: String,
    pub size: u64,
}

/// Is what a file is called and said to be within what the owner's page
/// lists? The name is drawn as text and saved under by the owner: it holds no
/// path separator, and neither begins nor ends in a space or a dot. The type
/// is a media type, `type/subtype`, with parameters or without.
pub fn check_file(at: usize, name: &str, content_type: &str) -> Result<(), String> {
    let named = format!("the name of file {}", at + 1);
    check_text(&named, name, MAX_FILE_NAME_CHARS, false)?;
    if name.contains(['/', '\\']) {
        return Err(format!("{named} holds a path separator"));
    }
    let at_an_edge = |c: Option<char>| c.is_some_and(|c| c == '.' || c.is_whitespace());
    if at_an_edge(name.chars().next()) {
        return Err(format!("{named} begins with a space or a dot"));
    }
    if at_an_edge(name.chars().next_back()) {
        return Err(format!("{named} ends in a space or a dot"));
    }
    match is_media_type(content_type) {
        true => Ok(()),
        false => Err(format!(
            "the type of file {} is not a media type, `type/subtype`, of at most {MAX_CONTENT_TYPE_CHARS} characters",
            at + 1
        )),
    }
}

/// Is `content_type` a media type: `type/subtype` with one `/` and a part on
/// each side of it, and whatever parameters follow a `;`?
fn is_media_type(content_type: &str) -> bool {
    let of_a_part = |b: u8| b.is_ascii_alphanumeric() || b".+-_".contains(&b);
    let of_a_parameter = |b: u8| of_a_part(b) || b";= ".contains(&b);
    if content_type.len() > MAX_CONTENT_TYPE_CHARS {
        return false;
    }
    let (essence, parameters) = match content_type.split_once(';') {
        Some((essence, parameters)) => (essence.trim_end_matches(' '), parameters),
        None => (content_type, ""),
    };
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    [kind, subtype].iter().all(|part| !part.is_empty() && part.bytes().all(of_a_part))
        && parameters.bytes().all(of_a_parameter)
}

/// Are the files of one task within what the owner's page lists: each by
/// [`check_file`], and no two under one name? Names are compared without
/// their case, as the file systems they are saved to compare them.
pub fn check_files<'a>(files: impl IntoIterator<Item = (&'a str, &'a str)>) -> Result<(), String> {
    let mut names: Vec<String> = Vec::new();
    for (at, (name, content_type)) in files.into_iter().enumerate() {
        check_file(at, name, content_type)?;
        let folded = name.to_lowercase();
        if let Some(first) = names.iter().position(|taken| *taken == folded) {
            return Err(format!("file {} has the name of file {}", at + 1, first + 1));
        }
        names.push(folded);
    }
    Ok(())
}

/// The envelope. Members in alphabetical order: the order they are written in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub answer_by: AnswerBy,
    /// SHA-256 of the build that made the task, hex: the code the owner's
    /// proof names. The answer is taken by that build and no other.
    pub build: String,
    /// Unix seconds.
    pub created_at: u64,
    pub display: Display,
    pub expires_at: u64,
    /// The files the owner is given to open, in order.
    pub files: Vec<FileNote>,
    pub id: String,
    pub kind: Kind,
    pub owner: String,
    /// SHA-256 of the policy the task was made under, hex.
    pub policy_hash: String,
    pub preparer: String,
    pub profile: String,
    pub project: String,
    pub project_uuid: String,
    /// What the owner's answer is encrypted to.
    pub reply_pubkey: String,
    /// SHA-256 of the component's `state`, hex.
    pub state_hash: String,
    pub thread: String,
    pub v: u32,
}

impl Envelope {
    /// The document: the bytes that are stored, shown and hashed.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        serde_json::to_vec(self).map_err(|e| format!("the envelope could not be written: {e}"))
    }

    /// Read a document this host wrote. One with a member missing, unknown or
    /// of another type is not an envelope.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|_| "the envelope cannot be read".to_string())
    }
}

/// SHA-256, lowercase hex.
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A character that is not drawn, or that changes how the characters around
/// it are drawn: the C0 and C1 controls, the marks and overrides that reorder
/// text, the characters of zero width and the invisible operators, the
/// fillers and the blank that are drawn as nothing, the line and paragraph
/// separators, the variation selectors, the byte-order mark, the controls of
/// annotations, shorthand and musical notation, and the language tags. Two
/// of them are part of how an emoji is written, and do not mislead there:
/// see [`misleads_here`].
fn misleads(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}' | '\u{1160}'
            | '\u{17B4}' | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF9}'..='\u{FFFC}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}')
}

/// A picture: an emoji, a symbol or a dingbat, with the modifiers of its
/// colour. What the selectors and the joiner of pictures stand beside.
fn pictures(c: char) -> bool {
    matches!(c,
        '\u{203C}' | '\u{2049}' | '\u{2122}' | '\u{2139}' | '\u{00A9}' | '\u{00AE}'
        | '\u{2190}'..='\u{21FF}'
        | '\u{2300}'..='\u{23FF}'
        | '\u{2460}'..='\u{24FF}'
        | '\u{25A0}'..='\u{27BF}'
        | '\u{2900}'..='\u{297F}'
        | '\u{2B00}'..='\u{2BFF}'
        | '\u{3030}' | '\u{303D}' | '\u{3297}' | '\u{3299}'
        | '\u{1F000}'..='\u{1FAFF}')
}

/// The selector that says how the picture before it is drawn, as text or as
/// an emoji.
fn selects_a_picture(c: char) -> bool {
    matches!(c, '\u{FE0E}' | '\u{FE0F}')
}

/// The character at `at` is one that misleads where it stands. A selector
/// after a picture, and the joiner between two pictures, are how an emoji is
/// written — a red heart, a family — and are drawn as that emoji; anywhere
/// else they are characters of no width, and mislead as those do.
fn misleads_here(text: &[char], at: usize) -> bool {
    let c = text[at];
    if !misleads(c) {
        return false;
    }
    let before = at.checked_sub(1).map(|i| text[i]);
    let after = text.get(at + 1).copied();
    if selects_a_picture(c) {
        return !before.is_some_and(|b| pictures(b) || b.is_ascii_digit() || matches!(b, '#' | '*'));
    }
    if c == '\u{200D}' {
        let joined = before.is_some_and(|b| pictures(b) || selects_a_picture(b));
        return !(joined && after.is_some_and(pictures));
    }
    true
}

/// A mark drawn over, under or through the character before it.
fn combines(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036F}'
        | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20FF}'
        | '\u{FE20}'..='\u{FE2F}')
}

/// The longest run of combining marks in `text`.
fn longest_combining_run(text: &str) -> usize {
    let (mut longest, mut run) = (0, 0);
    for c in text.chars() {
        run = match combines(c) {
            true => run + 1,
            false => 0,
        };
        longest = longest.max(run);
    }
    longest
}

fn check_text(what: &str, text: &str, most: usize, line_breaks: bool) -> Result<(), String> {
    let chars = text.chars().count();
    if chars == 0 {
        return Err(format!("{what} is empty"));
    }
    if chars > most {
        return Err(format!("{what} is {chars} characters; at most {most} are shown"));
    }
    // Every character of the Unicode property White_Space is a space here.
    if text.chars().all(char::is_whitespace) {
        return Err(format!("{what} is blank"));
    }
    let drawn: Vec<char> = text.chars().collect();
    let misled = (0..drawn.len())
        .find(|at| misleads_here(&drawn, *at) && !(line_breaks && matches!(drawn[*at], '\n' | '\t')))
        .map(|at| drawn[at]);
    if let Some(c) = misled {
        return Err(format!(
            "{what} holds the character U+{:04X}, which is not drawn or changes how text is drawn",
            c as u32
        ));
    }
    match longest_combining_run(text) {
        run if run > MAX_COMBINING_RUN => Err(format!(
            "{what} holds {run} combining marks in a row; at most {MAX_COMBINING_RUN} are drawn over one character"
        )),
        _ => Ok(()),
    }
}

/// Is `text` what a `long_text` of a display may hold, by its characters and
/// its length: the check of words the owner wrote that are handed to a
/// component.
pub fn check_long_text(what: &str, text: &str) -> Result<(), String> {
    check_text(what, text, MAX_LONG_TEXT_CHARS, true)
}

/// Is `display` within what the owner's card draws? The refusal names the
/// first thing that is not.
pub fn check_display(display: &Display) -> Result<(), String> {
    check_text("the title", &display.title, MAX_TITLE_CHARS, false)?;
    if display.fields.len() > MAX_FIELDS {
        return Err(format!("{} fields; at most {MAX_FIELDS} are shown", display.fields.len()));
    }
    for (at, field) in display.fields.iter().enumerate() {
        let named = format!("field {}", at + 1);
        check_text(&format!("the label of {named}"), &field.label, MAX_LABEL_CHARS, false)?;
        match (field.kind, field.values.len()) {
            (FieldKind::List, 1..=MAX_LIST_ITEMS) => {}
            (FieldKind::List, n) => {
                return Err(format!("{named} is a list of {n} values; a list holds 1 to {MAX_LIST_ITEMS}"));
            }
            (_, 1) => {}
            (kind, n) => {
                return Err(format!("{named} is a {} with {n} values; it holds exactly one", kind.name()));
            }
        }
        for value in &field.values {
            check_text(
                &format!("a value of {named}"),
                value,
                field.kind.most_chars(),
                field.kind == FieldKind::LongText,
            )?;
        }
    }
    Ok(())
}

/// Is `operation` the name of an operation: 1 to 64 of `a-z`, `0-9` and `_`?
pub fn check_operation(operation: &str) -> Result<(), String> {
    let ok = !operation.is_empty()
        && operation.len() <= MAX_OPERATION_CHARS
        && operation.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    match ok {
        true => Ok(()),
        false => Err(format!(
            "the operation to answer by is not a name: 1 to {MAX_OPERATION_CHARS} of a-z, 0-9 and _"
        )),
    }
}

/// What the sealed copy of a task holds.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedTask {
    /// The content key, hex.
    pub content_key: String,
    /// The envelope's document, as text.
    pub envelope: String,
    /// The component's `state`, base64.
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(kind: FieldKind, values: &[&str]) -> Field {
        Field { kind, label: "To".into(), values: values.iter().map(|v| v.to_string()).collect(), written_by: WrittenBy::Agent }
    }

    fn display(fields: Vec<Field>) -> Display {
        Display { title: "Send an email".into(), fields }
    }

    pub(crate) fn envelope() -> Envelope {
        Envelope {
            answer_by: AnswerBy { operation: "confirm".into(), supplies: Supplies::Nothing },
            build: "ab".repeat(32),
            created_at: 1_790_000_000,
            display: display(vec![field(FieldKind::Address, &["bob@example.com"])]),
            expires_at: 1_790_003_600,
            files: vec![],
            id: "run-0".into(),
            kind: Kind::Confirm,
            owner: "owner.near".into(),
            policy_hash: hash(b"policy"),
            preparer: "agent.near".into(),
            profile: "gmail".into(),
            project: "connectors.outlayer.near/gmail".into(),
            project_uuid: "p0000000000000001".into(),
            reply_pubkey: "p256:abc".into(),
            state_hash: hash(b"state"),
            thread: "run-0".into(),
            v: VERSION,
        }
    }

    #[test]
    fn the_document_is_written_in_one_order_and_read_back_whole() {
        let bytes = envelope().to_bytes().unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        let members: Vec<&str> = [
            "answer_by", "\"build\"", "created_at", "display", "expires_at", "\"files\"", "\"id\"", "\"kind\":\"confirm\"", "owner",
            "policy_hash", "preparer", "profile", "\"project\"", "project_uuid", "reply_pubkey", "state_hash",
            "thread", "\"v\"",
        ]
        .to_vec();
        let mut last = 0;
        for member in members {
            let at = text[last..].find(member).unwrap_or_else(|| panic!("{member} after {last} in {text}")) + last;
            last = at;
        }
        assert!(!text.contains(' ') || text.contains("Send an email"), "{text}");
        assert_eq!(Envelope::from_bytes(&bytes).unwrap(), envelope());
        assert_eq!(bytes, envelope().to_bytes().unwrap());
        assert_eq!(hash(&bytes).len(), 64);
    }

    #[test]
    fn one_byte_of_what_is_shown_is_another_hash() {
        let mut changed = envelope();
        changed.display.fields[0].values[0] = "bob@example.con".into();
        assert_ne!(hash(&envelope().to_bytes().unwrap()), hash(&changed.to_bytes().unwrap()));
    }

    #[test]
    fn a_document_with_a_member_missing_unknown_or_of_another_type_is_not_an_envelope() {
        let mut value: serde_json::Value = serde_json::from_slice(&envelope().to_bytes().unwrap()).unwrap();
        value["then"] = serde_json::json!({"operation": "send", "args": {}});
        assert!(Envelope::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&envelope().to_bytes().unwrap()).unwrap();
        value.as_object_mut().unwrap().remove("state_hash");
        assert!(Envelope::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&envelope().to_bytes().unwrap()).unwrap();
        value["kind"] = serde_json::json!("approve");
        assert!(Envelope::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(Envelope::from_bytes(b"").is_err());
    }

    #[test]
    fn what_a_card_draws_is_accepted() {
        check_display(&display(vec![])).unwrap();
        check_display(&display(vec![
            field(FieldKind::Money, &["$12.50"]),
            field(FieldKind::LongText, &["Hello,\n\n\tsee attached.\nBob"]),
            field(FieldKind::List, &["a.pdf (12 KB)", "b.png (1 MB)"]),
            field(FieldKind::Text, &["Привет — 你好 — مرحبا"]),
        ]))
        .unwrap();
        check_display(&display(vec![field(FieldKind::Text, &["<script>alert(1)</script> [x](http://e.com)"])])).unwrap();
        check_display(&display((0..MAX_FIELDS).map(|_| field(FieldKind::Text, &["x"])).collect())).unwrap();
    }

    fn refusal(display: Display) -> String {
        check_display(&display).expect_err("refused")
    }

    #[test]
    fn a_display_outside_the_bounds_is_refused_and_the_refusal_names_what() {
        let mut long_title = display(vec![]);
        long_title.title = "x".repeat(MAX_TITLE_CHARS + 1);
        assert!(refusal(long_title).contains("the title is 81 characters"));
        let mut empty_title = display(vec![]);
        empty_title.title = String::new();
        assert!(refusal(empty_title).contains("the title is empty"));
        let mut blank = display(vec![]);
        blank.title = "   ".into();
        assert!(refusal(blank).contains("blank"));

        let many = display((0..=MAX_FIELDS).map(|_| field(FieldKind::Text, &["x"])).collect());
        assert!(refusal(many).contains("13 fields"));

        assert!(refusal(display(vec![field(FieldKind::Text, &["a", "b"])])).contains("field 1 is a text with 2 values"));
        assert!(refusal(display(vec![field(FieldKind::Money, &[])])).contains("with 0 values"));
        assert!(refusal(display(vec![field(FieldKind::List, &[])])).contains("a list of 0 values"));
        let items: Vec<String> = (0..=MAX_LIST_ITEMS).map(|n| n.to_string()).collect();
        let items: Vec<&str> = items.iter().map(String::as_str).collect();
        assert!(refusal(display(vec![field(FieldKind::List, &items)])).contains("a list of 21 values"));

        let over = "x".repeat(MAX_LONG_TEXT_CHARS + 1);
        assert!(refusal(display(vec![field(FieldKind::LongText, &[&over])])).contains("50001 characters"));
        let over = "x".repeat(MAX_TEXT_CHARS + 1);
        assert!(refusal(display(vec![field(FieldKind::Text, &[&over])])).contains("501 characters"));
        let over = "x".repeat(MAX_SHORT_CHARS + 1);
        assert!(refusal(display(vec![field(FieldKind::Address, &[&over])])).contains("201 characters"));

        let mut long_label = field(FieldKind::Text, &["x"]);
        long_label.label = "x".repeat(MAX_LABEL_CHARS + 1);
        assert!(refusal(display(vec![long_label])).contains("the label of field 1"));
    }

    #[test]
    fn the_bounds_count_characters_not_bytes() {
        let exactly = "й".repeat(MAX_SHORT_CHARS);
        check_display(&display(vec![field(FieldKind::Address, &[&exactly])])).unwrap();
    }

    #[test]
    fn characters_that_are_not_drawn_or_reorder_text_are_refused() {
        for (name, hostile) in [
            ("a right-to-left override", "evil\u{202E}txt.exe"),
            ("an isolate", "a\u{2066}b"),
            ("a zero-width space", "pay\u{200B}pal.com"),
            ("a null", "a\0b"),
            ("an escape", "a\u{1B}[31mb"),
            ("a carriage return", "a\rb"),
            ("a line separator", "a\u{2028}b"),
            ("a byte-order mark", "\u{FEFF}a"),
            ("a language tag", "a\u{E0041}"),
        ] {
            let said = refusal(display(vec![field(FieldKind::Text, &[hostile])]));
            assert!(said.contains("holds the character U+"), "{name}: {said}");
        }
        // A line break is a text's own only in a long text.
        assert!(refusal(display(vec![field(FieldKind::Text, &["a\nb"])])).contains("U+000A"));
        let mut title = display(vec![]);
        title.title = "Send\nnow".into();
        assert!(refusal(title).contains("the title holds the character U+000A"));
    }

    #[test]
    fn a_file_is_listed_by_a_name_that_is_text_and_a_type_that_is_one() {
        check_file(0, "report.pdf", "application/pdf").unwrap();
        check_file(0, "отчёт за март.pdf", "text/plain; charset=utf-8").unwrap();
        for (name, kind, said) in [
            ("", "application/pdf", "the name of file 1 is empty"),
            ("../etc/passwd", "text/plain", "path separator"),
            ("a\\b.txt", "text/plain", "path separator"),
            ("invoice\u{202E}fdp.exe", "application/pdf", "U+202E"),
            ("a\nb.pdf", "application/pdf", "U+000A"),
            ("a.pdf", "", "is not a media type"),
            ("a.pdf", "text/html\r\nX-Injected: 1", "is not a media type"),
            ("a.pdf", "<script>", "is not a media type"),
        ] {
            let refused = check_file(0, name, kind).expect_err(name);
            assert!(refused.contains(said), "{name:?} {kind:?}: {refused}");
        }
        assert!(check_file(0, &"x".repeat(MAX_FILE_NAME_CHARS + 1), "a/b").is_err());
        assert!(check_file(2, "", "a/b").unwrap_err().contains("file 3"));
    }

    #[test]
    fn every_character_drawn_as_nothing_or_hiding_text_is_refused_by_its_code_point() {
        let singles = [
            0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2028, 0x2029, 0x2800, 0x3164, 0xFEFF, 0xFFA0,
        ];
        let ranges = [
            (0x180B, 0x180F),
            (0x2060, 0x206F),
            (0xFE00, 0xFE0F),
            (0xFFF9, 0xFFFC),
            (0x1BCA0, 0x1BCA3),
            (0x1D173, 0x1D17A),
            (0xE0000, 0xE0FFF),
        ];
        let points = singles.into_iter().chain(ranges.into_iter().flat_map(|(from, to)| from..=to));
        for point in points {
            let hostile = format!("pay{}pal", char::from_u32(point).expect("a character"));
            let named = format!("U+{point:04X},");
            for kind in [FieldKind::Text, FieldKind::LongText] {
                let said = refusal(display(vec![field(kind, &[&hostile])]));
                assert!(said.contains(&named), "{named} {said}");
            }
            let mut title = display(vec![]);
            title.title = hostile.clone();
            assert!(refusal(title).contains(&named), "{named} in a title");
            let mut label = field(FieldKind::Text, &["x"]);
            label.label = hostile.clone();
            assert!(refusal(display(vec![label])).contains(&named), "{named} in a label");
            assert!(check_file(0, &format!("{hostile}.pdf"), "application/pdf").unwrap_err().contains(&named), "{named} in a name");
        }
    }

    #[test]
    fn a_long_text_keeps_its_line_breaks_and_tabs_and_nothing_else_does() {
        check_display(&display(vec![field(FieldKind::LongText, &["one\n\ttwo\n"])])).unwrap();
        check_long_text("the reason", "one\n\ttwo").unwrap();
        assert!(check_long_text("the reason", "one\u{2028}two").unwrap_err().contains("U+2028"));
        assert!(check_long_text("the reason", "one\rtwo").unwrap_err().contains("U+000D"));
        assert!(refusal(display(vec![field(FieldKind::Text, &["one\ttwo"])])).contains("U+0009"));
    }

    #[test]
    fn a_title_a_label_or_a_value_made_only_of_spaces_of_any_kind_is_refused_as_blank() {
        let spaces = [
            "\u{0020}", "\u{00A0}", "\u{1680}", "\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}",
            "\u{2006}\u{2007}\u{2008}\u{2009}\u{200A}", "\u{202F}", "\u{205F}", "\u{3000}", " \u{00A0}\u{3000} ",
        ];
        for space in spaces {
            let mut title = display(vec![]);
            title.title = space.to_string();
            assert_eq!(refusal(title), "the title is blank", "{space:?}");
            let mut label = field(FieldKind::Text, &["x"]);
            label.label = space.to_string();
            assert_eq!(refusal(display(vec![label])), "the label of field 1 is blank", "{space:?}");
            assert_eq!(refusal(display(vec![field(FieldKind::Text, &[space])])), "a value of field 1 is blank", "{space:?}");
        }
        assert_eq!(refusal(display(vec![field(FieldKind::LongText, &["\n\t \n"])])), "a value of field 1 is blank");
        // Drawn as nothing and no space: refused all the same.
        for nothing in ["\u{2800}", "\u{3164}\u{3164}", "\u{115F}", " \u{FFA0} "] {
            let mut title = display(vec![]);
            title.title = nothing.to_string();
            assert!(refusal(title).contains("holds the character U+"), "{nothing:?}");
        }
    }

    #[test]
    fn an_emoji_is_written_with_its_selector_and_its_joiner_and_they_mislead_anywhere_else() {
        let body = |text: &str| check_text("the body", text, 1000, true);
        for written in [
            "With love \u{2764}\u{FE0F}",
            "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} are coming",
            "Done \u{2705} and \u{1F44D}\u{1F3FD}",
            "\u{1F3F3}\u{FE0F}\u{200D}\u{1F308}",
            "Press 1\u{FE0F}\u{20E3}",
            "\u{00A9}\u{FE0F} 2026",
        ] {
            assert_eq!(body(written), Ok(()), "{written:?}");
        }
        for (hidden, named) in [
            ("pay\u{FE0F}pal", "U+FE0F"),
            ("\u{FE0F}at the start", "U+FE0F"),
            ("a space \u{FE0F}", "U+FE0F"),
            ("pay\u{200D}pal", "U+200D"),
            ("\u{1F468}\u{200D}", "U+200D"),
            ("\u{1F468}\u{200D}x", "U+200D"),
            ("\u{200D}\u{1F468}", "U+200D"),
            ("x\u{FE00}", "U+FE00"),
        ] {
            let said = body(hidden).unwrap_err();
            assert!(said.contains(named), "{hidden:?}: {said}");
        }
    }

    #[test]
    fn more_than_four_combining_marks_in_a_row_are_refused() {
        for mark in ['\u{0301}', '\u{1AB0}', '\u{1DC0}', '\u{20D0}', '\u{FE20}'] {
            let four = format!("Z{}lgo", mark.to_string().repeat(MAX_COMBINING_RUN));
            check_display(&display(vec![field(FieldKind::Text, &[&four])])).unwrap();
            let five = format!("Z{}lgo", mark.to_string().repeat(MAX_COMBINING_RUN + 1));
            let said = refusal(display(vec![field(FieldKind::LongText, &[&five])]));
            assert!(said.contains("5 combining marks in a row"), "{said}");
            let mut title = display(vec![]);
            title.title = five;
            assert!(refusal(title).contains("the title holds 5 combining marks"));
        }
        // Marks of several blocks are one run; marks apart are not.
        let mixed = "a\u{0301}\u{1AB0}\u{1DC0}\u{20D0}\u{FE20}";
        assert!(refusal(display(vec![field(FieldKind::Text, &[mixed])])).contains("5 combining marks"));
        let apart = "a\u{0301}\u{0302}\u{0303}e\u{0301}\u{0302}\u{0303}";
        check_display(&display(vec![field(FieldKind::Text, &[apart])])).unwrap();
        check_display(&display(vec![field(FieldKind::Text, &["Việt Nam, й, é"])])).unwrap();
    }

    #[test]
    fn a_files_name_neither_begins_nor_ends_in_a_space_or_a_dot() {
        for (name, said) in [
            ("report.pdf ", "ends in a space or a dot"),
            ("report.pdf.", "ends in a space or a dot"),
            ("report.pdf\u{00A0}", "ends in a space or a dot"),
            ("report.pdf\u{3000}", "ends in a space or a dot"),
            ("report.exe. . .", "ends in a space or a dot"),
            (".bashrc", "begins with a space or a dot"),
            (" report.pdf", "begins with a space or a dot"),
            ("\u{2003}report.pdf", "begins with a space or a dot"),
            (".", "begins with a space or a dot"),
            ("a/b.pdf", "path separator"),
            ("a\\b.pdf", "path separator"),
            ("a\tb.pdf", "U+0009"),
            ("a\u{7F}b.pdf", "U+007F"),
            ("a\u{85}b.pdf", "U+0085"),
        ] {
            let refused = check_file(0, name, "application/pdf").expect_err(name);
            assert!(refused.contains(said), "{name:?}: {refused}");
        }
        for good in ["report.pdf", "a report of march.final.pdf", "отчёт.pdf", "a"] {
            check_file(0, good, "application/pdf").unwrap();
        }
    }

    #[test]
    fn a_files_type_is_a_type_and_a_subtype_about_one_slash() {
        for good in ["application/pdf", "image/svg+xml", "text/plain; charset=utf-8", "text/plain;charset=utf-8", "application/vnd.ms-excel", "a/b"] {
            check_file(0, "a.pdf", good).unwrap_or_else(|why| panic!("{good}: {why}"));
        }
        let long = format!("a/{}", "b".repeat(MAX_CONTENT_TYPE_CHARS));
        for bad in [
            "pdf", "/", "/pdf", "application/", "application//pdf", "a/b/c", "application/pdf; a=b/c", "text/; charset=utf-8",
            "text /plain", "text/ plain", " text/plain", "; charset=utf-8", "text/plain\n", "текст/plain", long.as_str(),
        ] {
            let refused = check_file(0, "a.pdf", bad).expect_err(bad);
            assert!(refused.contains("is not a media type"), "{bad:?}: {refused}");
        }
    }

    #[test]
    fn two_files_of_one_task_have_two_names_whatever_their_case() {
        let pdf = "application/pdf";
        check_files([("a.pdf", pdf), ("b.pdf", pdf), ("a.png", "image/png")]).unwrap();
        check_files(std::iter::empty()).unwrap();
        assert_eq!(check_files([("a.pdf", pdf), ("b.pdf", pdf), ("a.pdf", pdf)]).unwrap_err(), "file 3 has the name of file 1");
        assert_eq!(check_files([("Report.PDF", pdf), ("report.pdf", pdf)]).unwrap_err(), "file 2 has the name of file 1");
        assert_eq!(check_files([("ОТЧЁТ.pdf", pdf), ("отчёт.pdf", pdf)]).unwrap_err(), "file 2 has the name of file 1");
        // Each file is checked as one file is.
        assert!(check_files([("a.pdf", pdf), ("b.pdf.", pdf)]).unwrap_err().contains("the name of file 2 ends in"));
        assert!(check_files([("a.pdf", "pdf")]).unwrap_err().contains("the type of file 1"));
    }

    #[test]
    fn an_operation_is_a_name() {
        for good in ["confirm", "upload_photo", "a1"] {
            check_operation(good).unwrap();
        }
        let long = "a".repeat(MAX_OPERATION_CHARS + 1);
        for bad in ["", "Confirm", "send mail", "a-b", "a/b", "{\"op\":1}", long.as_str()] {
            assert!(check_operation(bad).is_err(), "{bad}");
        }
    }
}
