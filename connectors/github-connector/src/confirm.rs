//! A write the owner asked to confirm.
//!
//! When the owner's policy lists a write under `confirm`, the agent's call
//! checks it against the policy as it would before writing, and instead of
//! writing it leaves it as a task: the owner is shown every value the write
//! will use — the repository, the branch, the path, the commit message, the
//! title, the body with its marker, each file's content — and the write
//! waits sealed. The owner approves with one signature of their wallet, and
//! the platform starts `confirm` as a run of the agent that prepared the
//! task — on the agent's own payment key — with the approval in its input.
//! That run takes the write back, checks it against the policy — the one the
//! task was made under: a task made under another is void — and makes
//! exactly that write. Nothing in the task says what to do on a yes: this
//! code does.
//!
//! What the owner is shown is what is written, so a write to be confirmed has
//! to fit what a task shows whole. A text is shown in a field; a file's
//! content is shown in a field when it is text a field draws and there is
//! room, and is otherwise given to the owner as a file of the task, to open —
//! at most 10 of them, 6 MiB together. What fits neither is refused, never
//! shown in part.
//!
//! A pull request the owner is asked to merge or review is read when the task
//! is made, and the owner's yes is bound to the head they were shown: a merge
//! must match it, and an approval of any other head is refused.
//!
//! The owner's daily cap counts a confirmed write in the agent's own cell,
//! beside the writes the agent makes itself: both runs are the agent's. The
//! cap bounds each count.

use crate::action::{Action, Change, Content, GistFile, LineComment};
use crate::github as gh;
use crate::policy::{self, Counted};
use crate::Input;
use outlayer::tasks::{self, Display, FieldKind, WrittenBy};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The operation the platform starts, as the agent, on the owner's approval.
const ANSWERED_BY: &str = "confirm";

// What a task shows, as the host bounds it (`outlayer:tasks`, `display`).
const MOST_TITLE_CHARS: usize = 80;
const MOST_FIELDS: usize = 12;
const MOST_LABEL_CHARS: usize = 40;
const MOST_LONG_TEXT_CHARS: usize = 50_000;
const MOST_TEXT_CHARS: usize = 500;
const MOST_SHORT_CHARS: usize = 200;
const MOST_LIST_VALUES: usize = 20;
const MOST_FILES: usize = 10;
const MOST_FILE_BYTES: usize = 6 * 1024 * 1024;

/// What the contents shown in fields hold together, at most: the rest of the
/// task and its state must still fit the 256 KiB each is allowed.
const MOST_SHOWN_CONTENT_BYTES: usize = 128 * 1024;

/// The file that holds a review's line comments when they do not fit a field
/// each.
const REVIEW_COMMENTS_FILE: &str = "review-comments.json";

/// One field of what the owner is shown.
#[derive(Debug, Clone)]
pub(crate) struct Field {
    pub label: String,
    pub kind: FieldKind,
    pub values: Vec<String>,
    pub by: WrittenBy,
}

/// A write as it goes into a task: what the owner is shown, the files they
/// are given, and the write sealed as the task's state — its contents that
/// are files named there by name, size and hash.
#[derive(Debug)]
pub(crate) struct Shown {
    pub title: &'static str,
    pub fields: Vec<Field>,
    pub files: Vec<tasks::File>,
    pub sealed: Action,
}

#[derive(Default)]
struct Fields(Vec<Field>);

impl Fields {
    fn push(&mut self, label: &str, kind: FieldKind, values: Vec<String>, by: WrittenBy) {
        self.0.push(Field { label: label.to_string(), kind, values, by });
    }

    fn text(&mut self, label: &str, value: &str, by: WrittenBy) {
        self.push(label, FieldKind::Text, vec![value.to_string()], by);
    }

    /// A text the agent wrote, or, when it is blank, `blank` in the project's
    /// words: a field holds something, and an empty body is a value too.
    fn long_or(&mut self, label: &str, value: &str, blank: &str) {
        match value.trim().is_empty() {
            true => self.text(label, blank, WrittenBy::Project),
            false => self.push(label, FieldKind::LongText, vec![value.to_string()], WrittenBy::Agent),
        }
    }

    /// A list the agent gave, or, when it is empty, `empty` in the project's
    /// words: an empty list replaces what was there.
    fn list_or(&mut self, label: &str, values: &Option<Vec<String>>, empty: &str) {
        match values {
            None => {}
            Some(values) if values.is_empty() => self.text(label, empty, WrittenBy::Project),
            Some(values) => self.push(label, FieldKind::List, values.clone(), WrittenBy::Agent),
        }
    }
}

// ==================== what a field draws ====================

/// Drawn as nothing, or changing how text around it is drawn: the characters
/// the host refuses in a display. Line breaks and tabs a `long_text` holds.
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

/// A mark drawn over, under or through the character before it.
fn combines(c: char) -> bool {
    matches!(c,
        '\u{0300}'..='\u{036F}'
        | '\u{1AB0}'..='\u{1AFF}'
        | '\u{1DC0}'..='\u{1DFF}'
        | '\u{20D0}'..='\u{20FF}'
        | '\u{FE20}'..='\u{FE2F}')
}

/// Is `text` a file's content a `long_text` field shows exactly as it is
/// written? Stricter than the host, never looser: a text this refuses is
/// given to the owner as a file instead, which shows every byte.
fn shown_whole(text: &str) -> bool {
    !text.chars().all(char::is_whitespace)
        && text.chars().count() <= MOST_LONG_TEXT_CHARS
        && text.chars().all(|c| matches!(c, '\n' | '\t') || !(misleads(c) || combines(c)))
}

// ==================== files of the task ====================

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// The name a file of the task goes by: its place in the write, and the last
/// part of its path in characters any file system keeps. The path itself is
/// shown in a field.
fn file_name(number: usize, path: &str) -> String {
    let last = path.rsplit('/').next().unwrap_or_default();
    let kept: String = last
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') { c } else { '_' })
        .take(120)
        .collect();
    match kept.trim_end_matches('.') {
        "" => number.to_string(),
        kept => format!("{number}-{kept}"),
    }
}

/// Where a content went.
enum Placed {
    /// In a field of its own, under this label.
    Shown(String),
    /// Into a file of the task, under this name.
    InFile(String),
    /// Nowhere: it is empty, and the entry says so.
    Empty,
}

/// Contents are shown in fields while there is room and they are text a field
/// draws, and go into files of the task otherwise.
struct Placing {
    slots: usize,
    shown_bytes: usize,
    fields: Vec<Field>,
    files: Vec<tasks::File>,
}

impl Placing {
    fn new(slots: usize) -> Self {
        Self { slots, shown_bytes: 0, fields: Vec::new(), files: Vec::new() }
    }

    fn place(&mut self, number: usize, path: &str, label: String, content: &mut Content) -> Result<Placed, String> {
        if content.len() == 0 {
            return Ok(Placed::Empty);
        }
        if let Content::Text(text) = content {
            if self.slots > 0 && self.shown_bytes + text.len() <= MOST_SHOWN_CONTENT_BYTES && shown_whole(text) {
                self.slots -= 1;
                self.shown_bytes += text.len();
                self.fields.push(Field { label: label.clone(), kind: FieldKind::LongText, values: vec![text.clone()], by: WrittenBy::Agent });
                return Ok(Placed::Shown(label));
            }
        }
        let data = content.bytes()?.to_vec();
        let name = file_name(number, path);
        let content_type = match std::str::from_utf8(&data) {
            Ok(_) => "text/plain",
            Err(_) => "application/octet-stream",
        };
        *content = Content::File { name: name.clone(), bytes: data.len(), sha256: sha256_hex(&data) };
        self.files.push(tasks::File { name: name.clone(), content_type: content_type.to_string(), data });
        Ok(Placed::InFile(name))
    }

    /// One entry of a list of files: the number, the path, and where its
    /// content is.
    fn entry(&mut self, number: usize, path: &str, content: &mut Content, shown_as: &str) -> Result<String, String> {
        let size = content.len();
        Ok(match self.place(number, path, format!("{shown_as} {number}"), content)? {
            Placed::Shown(label) => format!("{number}. {path}: {size} bytes, shown as {label}"),
            Placed::InFile(name) => format!("{number}. {path}: {size} bytes, in the file {name}"),
            Placed::Empty => format!("{number}. {path}: empty, 0 bytes"),
        })
    }
}

/// Line ends as the owner reads them and as the text is posted: `\n`.
fn as_read(text: &mut String) {
    if text.contains("\r\n") {
        *text = text.replace("\r\n", "\n");
    }
}

fn as_read_all(action: &mut Action) {
    match action {
        Action::FilePut(a) => as_read(&mut a.message),
        Action::Commit(a) => as_read(&mut a.message),
        Action::IssueCreate(a) => as_read(&mut a.body),
        Action::IssueComment(a) => as_read(&mut a.body),
        Action::IssueUpdate(a) => {
            if let Some(body) = &mut a.body {
                as_read(body);
            }
        }
        Action::PrCreate(a) => as_read(&mut a.body),
        Action::PrReview(a) => {
            as_read(&mut a.body);
            a.comments.iter_mut().for_each(|c| as_read(&mut c.body));
        }
        Action::GistCreate(a) => as_read(&mut a.description),
        Action::GistUpdate(a) => {
            if let Some(description) = &mut a.description {
                as_read(description);
            }
        }
        Action::BranchCreate(_) | Action::PrMerge(_) | Action::RepoStar(_) | Action::RepoUnstar(_) => {}
    }
}

fn too_many(what: &str, n: usize) -> String {
    format!(
        "display_invalid: the owner confirms this write, and a write to be confirmed shows each of its \
         {what} on the task: at most {MOST_LIST_VALUES}, and this one has {n}. Split it"
    )
}

fn line_comment(c: &LineComment) -> String {
    format!("{}, line {}, {} side:\n\n{}", c.path, c.line, c.side, c.body)
}

/// `action`, which passed the owner's rules, as it goes into a task.
pub(crate) fn shown(action: &Action) -> Result<Shown, String> {
    use WrittenBy::{Agent, Project};
    let mut sealed = action.clone();
    as_read_all(&mut sealed);
    let mut f = Fields::default();
    let mut placing = Placing::new(0);
    let title = match &mut sealed {
        Action::BranchCreate(a) => {
            let start = a.start.as_ref().ok_or("task_unreadable: the branch has no commit to start from")?;
            f.text("Repository", &a.repo, Agent);
            f.text("Branch", &a.branch, Agent);
            f.text("From", &start.branch, if a.from.is_some() { Agent } else { Project });
            f.text("Starts at commit", &start.sha, Project);
            "Create a branch"
        }
        Action::FilePut(a) => {
            f.text("Repository", &a.repo, Agent);
            f.text("Branch", &a.branch, Agent);
            f.text("Path", &a.path, Agent);
            f.long_or("Commit message", &a.message, "empty");
            if let Some(sha) = &a.sha {
                f.text("Replaces the file at blob", sha, Agent);
            }
            placing.slots = 1;
            let size = a.content.len();
            match placing.place(1, &a.path, "Content".into(), &mut a.content)? {
                Placed::Shown(_) => {}
                Placed::InFile(name) => f.text("Content", &format!("{size} bytes, in the file {name}"), Project),
                Placed::Empty => f.text("Content", "empty, 0 bytes", Project),
            }
            "Write a file"
        }
        Action::Commit(a) => {
            if a.changes.len() > MOST_LIST_VALUES {
                return Err(too_many("changed files", a.changes.len()));
            }
            f.text("Repository", &a.repo, Agent);
            f.text("Branch", &a.branch, Agent);
            f.long_or("Commit message", &a.message, "empty");
            placing.slots = MOST_FIELDS.saturating_sub(f.0.len() + 1);
            let mut entries = Vec::with_capacity(a.changes.len());
            for (at, change) in a.changes.iter_mut().enumerate() {
                entries.push(match change {
                    Change::Delete { path } => format!("{}. {path}: deleted", at + 1),
                    Change::Write { path, content } => placing.entry(at + 1, path, content, "Change")?,
                });
            }
            f.push("Changes", FieldKind::List, entries, Agent);
            "Commit files"
        }
        Action::IssueCreate(a) => {
            f.text("Repository", &a.repo, Agent);
            f.text("Title", &a.title, Agent);
            f.long_or("Body", &a.body, "empty");
            f.list_or("Labels", &a.labels, "none");
            f.list_or("Assignees", &a.assignees, "none");
            "Open an issue"
        }
        Action::IssueComment(a) => {
            f.text("Repository", &a.repo, Agent);
            f.text("Issue or pull request", &format!("#{}", a.number), Agent);
            f.long_or("Comment", &a.body, "empty");
            "Comment on an issue or pull request"
        }
        Action::IssueUpdate(a) => {
            f.text("Repository", &a.repo, Agent);
            f.text("Issue", &format!("#{}", a.number), Agent);
            if let Some(state) = &a.state {
                f.text("State", state, Agent);
            }
            if let Some(title) = &a.title {
                f.text("Title", title, Agent);
            }
            if let Some(body) = &a.body {
                f.long_or("Body", body, "empty");
            }
            f.list_or("Labels", &a.labels, "none: every label is removed");
            f.list_or("Assignees", &a.assignees, "none: every assignee is removed");
            "Change an issue"
        }
        Action::PrCreate(a) => {
            f.text("Repository", &a.repo, Agent);
            f.text("From branch", &a.head, Agent);
            f.text("Into branch", &a.base, Agent);
            f.text("Title", &a.title, Agent);
            f.long_or("Body", &a.body, "empty");
            f.text("Draft", if a.draft { "yes" } else { "no" }, Agent);
            "Open a pull request"
        }
        Action::PrReview(a) => {
            f.text("Repository", &a.repo, Agent);
            f.text("Pull request", &format!("#{}", a.number), Agent);
            if let Some(pull) = &a.pull {
                if !pull.title.trim().is_empty() {
                    f.text("Its title", &pull.title, Project);
                }
                f.text("Reviewed commit", &pull.sha, Project);
            }
            f.text("Verdict", &a.event, Agent);
            f.long_or("Summary", &a.body, "empty");
            let rendered: Vec<String> = a.comments.iter().map(line_comment).collect();
            let room = MOST_FIELDS.saturating_sub(f.0.len());
            if rendered.len() <= room && rendered.iter().all(|c| shown_whole(c)) {
                for (at, comment) in rendered.iter().enumerate() {
                    f.push(&format!("Line comment {}", at + 1), FieldKind::LongText, vec![comment.clone()], Agent);
                }
            } else {
                let data = serde_json::to_vec_pretty(&a.comments).map_err(|e| format!("the comments could not be shown: {e}"))?;
                f.text("Line comments", &format!("{}, in the file {REVIEW_COMMENTS_FILE}", a.comments.len()), Project);
                placing.files.push(tasks::File {
                    name: REVIEW_COMMENTS_FILE.into(),
                    content_type: "application/json".into(),
                    data,
                });
            }
            "Review a pull request"
        }
        Action::PrMerge(a) => {
            f.text("Repository", &a.repo, Agent);
            f.text("Pull request", &format!("#{}", a.number), Agent);
            if let Some(pull) = &a.pull {
                if !pull.title.trim().is_empty() {
                    f.text("Its title", &pull.title, Project);
                }
                f.text("Branches", &format!("{} into {}", pull.head, pull.base), Project);
            }
            match (&a.sha, &a.pull) {
                (Some(sha), _) => f.text("Head commit", sha, Agent),
                (None, Some(pull)) => f.text("Head commit", &pull.sha, Project),
                (None, None) => {}
            }
            f.text("Method", &a.merge_method, Agent);
            "Merge a pull request"
        }
        Action::GistCreate(a) => {
            if a.files.len() > MOST_LIST_VALUES {
                return Err(too_many("files", a.files.len()));
            }
            f.text("Visibility", if a.public { "public" } else { "secret" }, Agent);
            if !a.description.trim().is_empty() {
                f.long_or("Description", &a.description, "empty");
            }
            placing.slots = MOST_FIELDS.saturating_sub(f.0.len() + 1);
            let entries = gist_entries(&mut placing, &mut a.files)?;
            f.push("Files", FieldKind::List, entries, Agent);
            "Create a gist"
        }
        Action::GistUpdate(a) => {
            if a.files.len() > MOST_LIST_VALUES {
                return Err(too_many("files", a.files.len()));
            }
            f.text("Gist", &a.gist_id, Agent);
            if let Some(description) = &a.description {
                f.long_or("Description", description, "empty: the description is removed");
            }
            if !a.files.is_empty() {
                placing.slots = MOST_FIELDS.saturating_sub(f.0.len() + 1);
                let entries = gist_entries(&mut placing, &mut a.files)?;
                f.push("Files", FieldKind::List, entries, Agent);
            }
            "Change a gist"
        }
        Action::RepoStar(a) => {
            f.text("Repository", &a.repo, Agent);
            "Star a repository"
        }
        Action::RepoUnstar(a) => {
            f.text("Repository", &a.repo, Agent);
            "Unstar a repository"
        }
    };
    let mut fields = f.0;
    fields.extend(placing.fields);
    Ok(Shown { title, fields, files: placing.files, sealed })
}

fn gist_entries(placing: &mut Placing, files: &mut [GistFile]) -> Result<Vec<String>, String> {
    let mut entries = Vec::with_capacity(files.len());
    for (at, file) in files.iter_mut().enumerate() {
        entries.push(match file {
            GistFile::Delete { name } => format!("{}. {name}: deleted", at + 1),
            GistFile::Write { name, content } => placing.entry(at + 1, name, content, "File")?,
        });
    }
    Ok(entries)
}

/// What a task must be to be shown whole, or the refusal. The refusal names
/// the field by its label and nothing the agent wrote.
pub(crate) fn check_shown(shown: &Shown) -> Result<(), String> {
    let refuse = |what: String| {
        Err(format!("display_invalid: the owner confirms this write, and what is confirmed is shown whole: {what}"))
    };
    if shown.title.chars().count() > MOST_TITLE_CHARS {
        return refuse(format!("its title is longer than {MOST_TITLE_CHARS} characters"));
    }
    if shown.fields.len() > MOST_FIELDS {
        return refuse(format!("it needs {} fields, and a task shows {MOST_FIELDS}", shown.fields.len()));
    }
    for field in &shown.fields {
        let label = &field.label;
        if label.chars().count() > MOST_LABEL_CHARS {
            return refuse(format!("the label `{label}` is longer than {MOST_LABEL_CHARS} characters"));
        }
        let most = match field.kind {
            FieldKind::LongText => MOST_LONG_TEXT_CHARS,
            FieldKind::Text => MOST_TEXT_CHARS,
            _ => MOST_SHORT_CHARS,
        };
        if field.kind == FieldKind::List && !(1..=MOST_LIST_VALUES).contains(&field.values.len()) {
            return refuse(format!("`{label}` lists {} values, and a list shows 1 to {MOST_LIST_VALUES}", field.values.len()));
        }
        for value in &field.values {
            let chars = value.chars().count();
            if chars > most {
                return refuse(format!("`{label}` holds {chars} characters, and a field shows at most {most}"));
            }
        }
    }
    if shown.files.len() > MOST_FILES {
        return Err(format!(
            "task_too_large: the owner confirms this write, and it gives the owner {} files to open; a task holds \
             at most {MOST_FILES}. Split it",
            shown.files.len()
        ));
    }
    let bytes: usize = shown.files.iter().map(|f| f.data.len()).sum();
    if bytes > MOST_FILE_BYTES {
        return Err(format!(
            "task_too_large: the owner confirms this write, and the files it gives the owner to open are {bytes} \
             bytes; a task holds at most {MOST_FILE_BYTES}. Split it"
        ));
    }
    Ok(())
}

fn display(shown: &Shown) -> Display {
    shown.fields.iter().fold(Display::new(shown.title), |display, field| match field.kind {
        FieldKind::List => display.list(&field.label, &field.values, field.by),
        kind => display.field(&field.label, kind, &field.values[0], field.by),
    })
}

/// Leave `action`, which passed the owner's rules, as a task for the owner.
pub(crate) fn ask(action: &Action) -> Result<Value, String> {
    let shown = shown(action)?;
    check_shown(&shown)?;
    let state = serde_json::to_vec(&shown.sealed).map_err(|e| format!("the write could not be kept: {e}"))?;
    let mut task = tasks::confirm(display(&shown), ANSWERED_BY, &state, &policy::stored());
    for file in &shown.files {
        task = task.file(&file.name, &file.content_type, &file.data);
    }
    let opened = task.open().map_err(|e| e.refusal())?;
    Ok(tasks::awaiting_owner(&opened))
}

// ==================== the owner's answer ====================

fn named<'a>(value: &'a Option<String>, member: &str) -> Result<&'a str, String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("task_answer_invalid: the call names no `{member}`"))
}

/// What every refusal after the answer was taken ends with.
const CLOSED: &str = "The task is closed: to make this write, prepare it again";

/// A refusal after the answer was taken: the same code, and a sentence that
/// says the task is over.
fn closed(refusal: String) -> String {
    format!("{}. {CLOSED}", refusal.trim_end().trim_end_matches('.'))
}

/// The members of a write's result that name what was made and nothing
/// else: numbers, ids, shas, counts, yes or no.
const ON_CHAIN: [&str; 10] =
    ["number", "comment_id", "review_id", "commit", "sha", "created", "merged", "starred", "state", "writes_today"];

/// What was made, as a refusal names it: the members of [`ON_CHAIN`] that
/// name a thing, and over HTTPS its URL and a gist's id.
fn made(done: &Value, on_chain: bool) -> String {
    let mut names = vec!["number", "comment_id", "review_id", "commit", "sha"];
    if !on_chain {
        names.extend(["gist_id", "url"]);
    }
    let parts: Vec<String> = names
        .iter()
        .filter_map(|name| match done.get(*name) {
            None | Some(Value::Null) => None,
            Some(Value::String(v)) => Some(format!("{name} {v}")),
            Some(v) => Some(format!("{name} {v}")),
        })
        .collect();
    match parts.is_empty() {
        true => "it has no id to name".to_string(),
        false => parts.join(", "),
    }
}

/// The refusal when the write was made and its result could not be left for
/// the agent: the task ends as failed although GitHub has the write, so the
/// sentence says which of the two is true.
fn made_unreported(refusal: String, done: &Value, on_chain: bool) -> String {
    format!(
        "{}. The write WAS made on GitHub ({}) and the task is closed without its result: do not prepare it again",
        refusal.trim_end().trim_end_matches('.'),
        made(done, on_chain)
    )
}

/// The codes the host's task interface answers with. Their sentences are the
/// host's and name no repository, path or person.
const HOST_CODES: [&str; 23] = [
    "tasks_not_declared", "no_owner", "relayed", "not_granted_by_name", "muted", "inbox_full", "task_run_limit",
    "display_invalid", "task_too_large", "task_life_too_long", "task_not_found", "not_the_owner", "not_the_preparer",
    "task_approval_invalid", "task_no_payment_key", "task_hash_mismatch", "task_answer_invalid", "task_closed",
    "task_expired", "task_void", "task_unreadable", "task_store_unavailable", "task_internal_error",
];

fn code_of(refusal: &str) -> &str {
    match refusal.split_once(':') {
        Some((code, _)) if !code.is_empty() && code.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') => code,
        _ => "refused",
    }
}

/// A refusal as `confirm` answers it where it runs. On chain the
/// answer stays in the owner's transaction for ever, and this connector's
/// sentences name repositories, branches and paths: the code is kept and the
/// sentence is one that names nothing. The host's own refusals are as they
/// are. Over HTTPS the refusal is whole.
fn as_answered(refusal: String, on_chain: bool) -> String {
    let code = code_of(&refusal);
    if !on_chain || HOST_CODES.contains(&code) {
        return refusal;
    }
    let sentence = match code {
        "policy_missing" => "the owner has stored no policy",
        "policy_unreadable" => "the stored policy is not one this connector understands",
        "policy_denied" => "the owner's policy does not allow this write as it stands now",
        "invalid" => "the write was not accepted as it was made",
        "not_permitted" => "the OutLayer app may not make this write there",
        "not_found" => "GitHub has nothing where this write goes, or the app does not reach it",
        "forbidden" => "GitHub refused the owner's own account",
        "conflict" => "what this write names moved since the task was made",
        "rate_limited" => "GitHub is throttling this account",
        "token_rejected" => "GitHub refused the owner's token; the owner connects the account again",
        "credential_missing" => "no GitHub token reached this run",
        "github_unavailable" | "github_unreachable" => "GitHub did not answer",
        "github_refused" => "GitHub refused the write",
        "too_large" => "the write is larger than this connector makes",
        _ => "the write was refused",
    };
    format!("{code}: {sentence}")
}

/// What is checked before the owner's answer is taken: that the call names
/// the task, its hash and the owner's approval, and that the owner's policy
/// is there and readable. Answers the call as `tasks::answered_for` reads it.
fn before_answer(input: &Input, loaded: policy::Loaded) -> Result<(Value, policy::Policy), String> {
    let id = named(&input.task_id, "task_id")?;
    let hash = named(&input.task_hash, "task_hash")?;
    let approval = input.approval.clone().ok_or("task_answer_invalid: the call carries no `approval`")?;
    let call = json!({ "task_id": id, "task_hash": hash, "approval": approval, "note": input.note });
    Ok((call, policy::required(loaded)?))
}

/// The write a task held: its state, with each content that waited as a file
/// of the task taken back from that file.
fn held(state: &[u8], files: &[tasks::File]) -> Result<Action, String> {
    let mut action: Action = serde_json::from_slice(state)
        .map_err(|_| "task_unreadable: the task does not hold a write of this connector".to_string())?;
    for (_, content) in action.contents_mut() {
        let Content::File { name, bytes, sha256 } = content else {
            continue;
        };
        let file = files
            .iter()
            .find(|f| f.name == *name)
            .ok_or_else(|| "task_unreadable: a file the task's write names is not among the task's files".to_string())?;
        if file.data.len() != *bytes || sha256_hex(&file.data) != *sha256 {
            return Err("task_unreadable: a file of the task is not the one the write was made with".to_string());
        }
        *content = Content::from_bytes(file.data.clone());
    }
    Ok(action)
}

/// The run the platform starts on the owner's approval: make the write the
/// task holds.
///
/// The write is inside the task and the host hands it over only with the
/// answer, so the answer is taken first and the write is judged and made
/// after. Taking the answer moves the task to `answering`, and a task never
/// returns to `open`.
///
/// **Refused before the answer is taken — the task fails when the run ends,
/// `run_refused:unreported` for a refusal of this connector's own (the host
/// never saw the task) and `run_refused:<reason>` for one of the host's, and
/// the agent prepares again:**
/// a call that names no `task_id`, `task_hash` or `approval`; a policy that
/// is absent or cannot be read; and everything the host refuses the answer
/// for — a run that is not the preparer's on the key, wallet and identity
/// the task was prepared with, an approval that does not hold, a hash that
/// is not the task's, a task that names another operation, a store that did
/// not answer, a task already closed or past its life. A task made under
/// another policy is refused `task_void`: the policy's bytes are part of the
/// task, so the rules a write is judged by here are the rules it was
/// prepared under.
///
/// **Refused after the answer is taken — the task ends as failed, and the
/// refusal's sentence says so:** a state that is not a write; a write its own
/// rules refuse; a branch a pattern allows that is now the default one; the
/// day's count of the agent that prepared it, full or unreadable; the token;
/// GitHub's refusal of the write — a branch that moved, a pull request whose
/// head is not the one shown. Last, a result the host would not keep: the
/// write was made, and the refusal says that instead.
///
/// A refusal after the answer that is certain nothing was written comes with
/// the notice that told the owner why, which the run's answer names.
pub(crate) fn confirm(input: &Input) -> Result<Value, tasks::Refused> {
    let on_chain = crate::on_chain();
    let (call, rules) = before_answer(input, policy::load()).map_err(|e| as_answered(e, on_chain))?;
    let answer = tasks::answered_for(ANSWERED_BY, &call, &policy::stored()).map_err(|e| e.refusal())?;
    let notice = std::cell::RefCell::new(None);
    after_answer(
        &rules,
        &answer,
        on_chain,
        |rules, action, counted| {
            action.check_on_github(rules).map_err(Unmade::Refused)?;
            gh::begin_writes();
            action.execute(rules, counted).map_err(|e| if gh::may_have_written() { Unmade::Unknown(e) } else { Unmade::Refused(e) })
        },
        |id, result| tasks::report(id, result).map_err(|e| e.refusal()),
        |id, refusal| {
            let told = tasks::failed_and_told(id, refusal, &policy::stored());
            *notice.borrow_mut() = told.notice;
            told.reported.map_err(|e| e.refusal())
        },
    )
    .map_err(|refusal| tasks::Refused { refusal, notice: notice.take() })
}

/// Why a write the task held was not answered with a result.
#[derive(Debug, PartialEq, Eq)]
enum Unmade {
    /// Nothing was changed on GitHub: refused before a write, or GitHub
    /// refused it (4xx).
    Refused(String),
    /// A write may have changed something and its outcome is not known: a
    /// lost answer, GitHub's own failure, or a later step of the write that
    /// failed after an earlier one was made.
    Unknown(String),
}

/// The refusal when a write may have been made and its outcome is not known:
/// the task is not reported as not carried out, and the sentence tells the
/// agent to look at GitHub before it prepares the write again.
fn outcome_unknown(refusal: String) -> String {
    format!(
        "{}. A write reached GitHub and its outcome is not known — an earlier step was made, or GitHub's \
         answer was lost — so it MAY have been made: check the repository before preparing it again",
        refusal.trim_end().trim_end_matches('.')
    )
}

/// Everything that follows the answer: the task is `answering`, and any
/// refusal from here ends it. `act` makes the write and `report` leaves the
/// result for the agent — the host's doing in a run. A refusal that says
/// nothing was written goes to the agent through `fail` (`report-failure`):
/// the task ends `failed` as `run_failed` with `{"error": <the refusal>}` as
/// the result it reads, and the owner is shown the same refusal in a notice
/// under the task. A write whose outcome is not known is NOT reported
/// as not carried out: the run ends with the refusal, and the task as
/// `run_unreported` — "it may have acted".
fn after_answer(
    rules: &policy::Policy,
    answer: &tasks::Answer,
    on_chain: bool,
    act: impl FnOnce(&policy::Policy, &Action, Counted) -> Result<Value, Unmade>,
    report: impl FnOnce(&str, &[u8]) -> Result<(), String>,
    fail: impl FnOnce(&str, &str) -> Result<(), String>,
) -> Result<Value, String> {
    // Nothing was written: the agent reads why as the failed task's result. A
    // report that does not land leaves the task failed without it, which the
    // refusal still answers.
    let refused = |e: String| {
        let refusal = closed(as_answered(e, on_chain));
        let _ = fail(&answer.id, &refusal);
        Err(refusal)
    };
    let action = match held(&answer.state, &answer.files).and_then(|action| action.check(rules).map(|_| action)) {
        Ok(action) => action,
        Err(e) => return refused(e),
    };
    // Counted in this run's own cell, beside the agent's direct writes: the
    // cap is the owner's bound on this agent, confirmed or not.
    let mut done = match act(rules, &action, Counted::Confirmed) {
        Ok(done) => done,
        Err(Unmade::Refused(e)) => return refused(e),
        Err(Unmade::Unknown(e)) => return Err(outcome_unknown(as_answered(e, on_chain))),
    };
    // What the owner wrote beside their yes goes to the agent with the result.
    if let Some(note) = answer.note.as_deref().and_then(|n| std::str::from_utf8(n).ok()) {
        with_note(&mut done, note);
    }
    // The agent reads the whole of it, repository and URL with the rest: the
    // host seals a report for the preparer.
    report(&answer.id, done.to_string().as_bytes())
        .map_err(|e| made_unreported(as_answered(e, on_chain), &done, on_chain))?;
    Ok(answered_with(&action, &done, &answer.id, on_chain))
}

/// The most a report holds, as the host bounds it (`MAX_RESULT_BYTES`).
const MAX_REPORT_BYTES: usize = 16 * 1024;

/// Put the owner's note on the result, whole when the report stays within
/// its bound and cut at a character otherwise, said so by `note_truncated`:
/// a report over the bound is refused, and the write it describes would then
/// read as unreported. The write's own members are never cut.
fn with_note(result: &mut Value, note: &str) {
    result["note"] = json!(note);
    if result.to_string().len() <= MAX_REPORT_BYTES {
        return;
    }
    result["note_truncated"] = json!(true);
    let mut keep = note.len();
    while keep > 0 {
        while keep > 0 && !note.is_char_boundary(keep) {
            keep -= 1;
        }
        result["note"] = json!(&note[..keep]);
        if result.to_string().len() <= MAX_REPORT_BYTES {
            return;
        }
        keep = keep.saturating_sub(256);
    }
    result["note"] = json!("");
}

/// What `confirm` answers the owner, given what the write answered: on chain
/// the members of [`ON_CHAIN`] it has — picked by name, so a member added to
/// what a write answers stays off the chain until it is listed there — and
/// over HTTPS the whole of it; with `status`, `task_id` and the `action`.
fn answered_with(action: &Action, done: &Value, task_id: &str, on_chain: bool) -> Value {
    let mut out = match on_chain {
        true => Value::Object(
            ON_CHAIN
                .iter()
                .filter_map(|name| done.get(*name).map(|v| (name.to_string(), v.clone())))
                .collect(),
        ),
        false => done.clone(),
    };
    out["status"] = json!("done");
    out["task_id"] = json!(task_id);
    out["action"] = json!(action.confirmable().name());
    out
}

/// The operations every project that uses tasks answers alike.
pub(crate) fn task(operation: &str, input: &Input) -> Result<Value, String> {
    let call = json!({ "task_id": input.task_id });
    tasks::dispatch(operation, &call).unwrap_or_else(|| Err(format!("unknown operation `{operation}`")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::*;
    use crate::policy::Confirmable;
    use std::cell::RefCell;

    fn rules(json: &str) -> policy::Policy {
        serde_json::from_str(json).unwrap()
    }

    /// Everything the owner reads: the title, the labels, the values, the
    /// names of the files.
    fn read(shown: &Shown) -> String {
        let mut out = vec![shown.title.to_string()];
        for field in &shown.fields {
            out.push(field.label.clone());
            out.extend(field.values.iter().cloned());
        }
        out.extend(shown.files.iter().map(|f| f.name.clone()));
        out.join("\n")
    }

    fn pull() -> Pull {
        Pull { title: "Fix the parser".into(), head: "agent/fix".into(), base: "main".into(), sha: "c0ffee1".into() }
    }

    /// One write of every kind, each value distinct, so that a value missing
    /// from the display is found.
    fn every_write() -> Vec<(Action, Vec<&'static str>)> {
        vec![
            (
                Action::BranchCreate(BranchCreate {
                    repo: "alice/site".into(),
                    branch: "agent/new".into(),
                    from: Some("develop".into()),
                    start: Some(Start { branch: "develop".into(), sha: "5eed5eed".into() }),
                }),
                vec!["alice/site", "agent/new", "develop", "5eed5eed"],
            ),
            (
                Action::FilePut(FilePut {
                    repo: "alice/site".into(),
                    branch: "agent/docs".into(),
                    path: "docs/intro.md".into(),
                    message: "Explain the intro".into(),
                    content: Content::Text("# Intro\n\nHello.\n".into()),
                    sha: Some("b10bb10b".into()),
                }),
                vec!["alice/site", "agent/docs", "docs/intro.md", "Explain the intro", "# Intro\n\nHello.\n", "b10bb10b"],
            ),
            (
                Action::Commit(Commit {
                    repo: "alice/site".into(),
                    branch: "agent/many".into(),
                    message: "Two files and a removal".into(),
                    changes: vec![
                        Change::Write { path: "a/one.txt".into(), content: Content::Text("first file".into()) },
                        Change::Write { path: "b/logo.png".into(), content: Content::Bytes(vec![0x89, 0x50, 0xff]) },
                        Change::Delete { path: "c/old.txt".into() },
                    ],
                }),
                vec!["alice/site", "agent/many", "Two files and a removal", "a/one.txt", "first file", "b/logo.png", "2-logo.png", "c/old.txt", "deleted"],
            ),
            (
                Action::IssueCreate(IssueCreate {
                    repo: "alice/site".into(),
                    title: "Broken link".into(),
                    body: "The link is broken.\n\n— posted by an AI agent via OutLayer".into(),
                    labels: Some(vec!["bug".into()]),
                    assignees: Some(vec!["bob".into()]),
                }),
                vec!["alice/site", "Broken link", "The link is broken.\n\n— posted by an AI agent via OutLayer", "bug", "bob"],
            ),
            (
                Action::IssueComment(IssueComment { repo: "alice/site".into(), number: 42, body: "Agreed.".into() }),
                vec!["alice/site", "#42", "Agreed."],
            ),
            (
                Action::IssueUpdate(IssueUpdate {
                    repo: "alice/site".into(),
                    number: 43,
                    state: Some("closed".into()),
                    title: Some("Renamed".into()),
                    body: Some("New body".into()),
                    labels: Some(vec![]),
                    assignees: Some(vec!["carol".into()]),
                }),
                vec!["alice/site", "#43", "closed", "Renamed", "New body", "every label is removed", "carol"],
            ),
            (
                Action::PrCreate(PrCreate {
                    repo: "alice/site".into(),
                    title: "Add docs".into(),
                    head: "agent/docs".into(),
                    base: "main".into(),
                    body: "Adds the docs.".into(),
                    draft: true,
                }),
                vec!["alice/site", "Add docs", "agent/docs", "main", "Adds the docs.", "yes"],
            ),
            (
                Action::PrReview(PrReview {
                    repo: "alice/site".into(),
                    number: 7,
                    event: "APPROVE".into(),
                    body: "Looks right.".into(),
                    comments: vec![LineComment { path: "src/lib.rs".into(), line: 12, side: "RIGHT".into(), body: "Nice.".into() }],
                    pull: Some(pull()),
                }),
                vec!["alice/site", "#7", "APPROVE", "Looks right.", "src/lib.rs", "line 12", "RIGHT", "Nice.", "Fix the parser", "c0ffee1"],
            ),
            (
                Action::PrMerge(PrMerge { repo: "alice/site".into(), number: 8, merge_method: "rebase".into(), sha: None, pull: Some(pull()) }),
                vec!["alice/site", "#8", "rebase", "c0ffee1", "agent/fix into main", "Fix the parser"],
            ),
            (
                Action::GistCreate(GistCreate {
                    description: "Notes".into(),
                    public: false,
                    files: vec![GistFile::Write { name: "notes.md".into(), content: Content::Text("note one".into()) }],
                }),
                vec!["secret", "Notes", "notes.md", "note one"],
            ),
            (
                Action::GistUpdate(GistUpdate {
                    gist_id: "aa11bb22".into(),
                    description: Some("Renamed notes".into()),
                    files: vec![
                        GistFile::Write { name: "more.md".into(), content: Content::Text("note two".into()) },
                        GistFile::Delete { name: "old.md".into() },
                    ],
                }),
                vec!["aa11bb22", "Renamed notes", "more.md", "note two", "old.md", "deleted"],
            ),
            (Action::RepoStar(Repo { repo: "bob/lib".into() }), vec!["bob/lib", "Star"]),
            (Action::RepoUnstar(Repo { repo: "bob/lib".into() }), vec!["bob/lib", "Unstar"]),
        ]
    }

    #[test]
    fn a_policy_asks_for_the_owner_by_naming_the_operation() {
        for op in Confirmable::ALL {
            let asks: policy::Policy = serde_json::from_str(&format!(r#"{{"confirm":["{}"]}}"#, op.name())).unwrap();
            assert!(asks.confirms(op), "{}", op.name());
            assert!(Confirmable::ALL.iter().filter(|o| **o != op).all(|o| !asks.confirms(*o)), "{}", op.name());
            assert_eq!(serde_json::to_value(op).unwrap(), json!(op.name()));
        }
        for quiet in [r#"{}"#, r#"{"confirm":[]}"#, r#"{"confirm":null}"#] {
            let policy: policy::Policy = serde_json::from_str(quiet).unwrap();
            assert!(Confirmable::ALL.iter().all(|op| !policy.confirms(*op)), "{quiet}");
        }
        // An operation that cannot be confirmed is a policy that cannot be read.
        for unread in [
            r#"{"confirm":["file_get"]}"#,
            r#"{"confirm":["status"]}"#,
            r#"{"confirm":["confirm"]}"#,
            r#"{"confirm":["task_cancel"]}"#,
            r#"{"confirm":["any"]}"#,
            r#"{"confirm":["Commit"]}"#,
            r#"{"confirm":["PR_MERGE"]}"#,
            r#"{"confirm":["merge"]}"#,
            r#"{"confirm":"commit"}"#,
        ] {
            assert!(serde_json::from_str::<policy::Policy>(unread).is_err(), "{unread}");
        }
    }

    #[test]
    fn every_write_can_be_confirmed_and_is_shown_with_every_value_it_uses() {
        let writes = every_write();
        let kinds: Vec<Confirmable> = writes.iter().map(|(a, _)| a.confirmable()).collect();
        assert_eq!(kinds, Confirmable::ALL, "one write of each kind, in order");
        for (action, values) in writes {
            let name = action.confirmable().name();
            let shown = shown(&action).unwrap_or_else(|e| panic!("{name}: {e}"));
            check_shown(&shown).unwrap_or_else(|e| panic!("{name}: {e}"));
            let text = read(&shown);
            for value in values {
                let in_a_file = shown.files.iter().any(|f| f.name.contains(value));
                assert!(text.contains(value) || in_a_file, "{name}: `{value}` is not shown in\n{text}");
            }
            // Every field is within what the owner's card draws.
            for field in &shown.fields {
                assert!(!field.values.is_empty() && field.values.iter().all(|v| !v.trim().is_empty()), "{name}: {field:?}");
            }
            // What is sealed is the write, and it reads back, with its files,
            // as the write that was shown.
            let state = serde_json::to_vec(&shown.sealed).unwrap();
            let back = held(&state, &shown.files).unwrap();
            let mut expected = action.clone();
            as_read_all(&mut expected);
            assert_eq!(back, expected, "{name}");
        }
    }

    #[test]
    fn a_binary_file_waits_as_a_file_of_the_task_and_comes_back_byte_for_byte() {
        let (commit, _) = every_write().remove(2);
        let shown = shown(&commit).unwrap();
        assert_eq!(shown.files.len(), 1);
        let file = &shown.files[0];
        assert_eq!((file.name.as_str(), file.content_type.as_str(), file.data.as_slice()), ("2-logo.png", "application/octet-stream", &[0x89, 0x50, 0xff][..]));
        let state = String::from_utf8(serde_json::to_vec(&shown.sealed).unwrap()).unwrap();
        assert!(state.contains(&sha256_hex(&[0x89, 0x50, 0xff])) && state.contains("first file"), "{state}");
        let changes = &shown.fields.iter().find(|f| f.label == "Changes").unwrap().values;
        assert_eq!(changes[0], "1. a/one.txt: 10 bytes, shown as Change 1");
        assert_eq!(changes[1], "2. b/logo.png: 3 bytes, in the file 2-logo.png");
        assert_eq!(changes[2], "3. c/old.txt: deleted");
    }

    #[test]
    fn a_text_a_field_would_not_draw_as_written_is_given_as_a_file() {
        let put = |content: Content| {
            Action::FilePut(FilePut {
                repo: "a/b".into(),
                branch: "agent/x".into(),
                path: "dir/.env.example".into(),
                message: "m".into(),
                content,
                sha: None,
            })
        };
        for text in ["line\r\nends", "zero\u{200B}width", "right\u{202E}left", "   \n", &"x".repeat(MOST_LONG_TEXT_CHARS + 1)] {
            let shown = shown(&put(Content::Text(text.to_string()))).unwrap();
            assert_eq!(shown.files.len(), 1, "{text:?}");
            assert_eq!(shown.files[0].data, text.as_bytes(), "the file holds the bytes as written");
            assert_eq!(shown.files[0].name, "1-.env.example");
            assert!(shown.fields.iter().all(|f| f.kind != FieldKind::LongText || f.label != "Content"));
            let content = shown.fields.iter().find(|f| f.label == "Content").unwrap();
            assert!(content.values[0].ends_with("in the file 1-.env.example"), "{content:?}");
        }
        let shown = shown(&put(Content::Text("plain\ttext\n".into()))).unwrap();
        assert!(shown.files.is_empty());
        let empty = super::shown(&put(Content::Text(String::new()))).unwrap();
        assert!(empty.files.is_empty() && read(&empty).contains("empty, 0 bytes"));
    }

    #[test]
    fn contents_fill_the_fields_there_are_and_the_rest_go_into_files() {
        let changes: Vec<Change> = (1..=12)
            .map(|n| Change::Write { path: format!("f/{n}.txt"), content: Content::Text(format!("content {n}")) })
            .collect();
        let commit = Action::Commit(Commit { repo: "a/b".into(), branch: "agent/x".into(), message: "m".into(), changes });
        let shown = shown(&commit).unwrap();
        check_shown(&shown).unwrap();
        assert_eq!(shown.fields.len(), MOST_FIELDS);
        assert_eq!(shown.files.len(), 4);
        assert_eq!(shown.files[0].name, "9-9.txt");
        let back = held(&serde_json::to_vec(&shown.sealed).unwrap(), &shown.files).unwrap();
        assert_eq!(back, commit);

        // More than a task holds: refused, never shown in part.
        let many: Vec<Change> = (1..=21).map(|n| Change::Delete { path: format!("f/{n}") }).collect();
        let said = super::shown(&Action::Commit(Commit { repo: "a/b".into(), branch: "agent/x".into(), message: "m".into(), changes: many })).unwrap_err();
        assert!(said.starts_with("display_invalid: ") && said.contains("21"), "{said}");
        let binaries: Vec<Change> = (1..=11).map(|n| Change::Write { path: format!("f/{n}.bin"), content: Content::Bytes(vec![0xff]) }).collect();
        let shown = super::shown(&Action::Commit(Commit { repo: "a/b".into(), branch: "agent/x".into(), message: "m".into(), changes: binaries })).unwrap();
        let said = check_shown(&shown).unwrap_err();
        assert!(said.starts_with("task_too_large: ") && said.contains("11 files"), "{said}");
    }

    #[test]
    fn a_body_is_shown_whole_or_the_write_is_refused() {
        let comment = |body: String| Action::IssueComment(IssueComment { repo: "a/b".into(), number: 1, body });
        check_shown(&shown(&comment("й".repeat(MOST_LONG_TEXT_CHARS))).unwrap()).unwrap();
        let said = check_shown(&shown(&comment("x".repeat(MOST_LONG_TEXT_CHARS + 1))).unwrap()).unwrap_err();
        assert!(said.starts_with("display_invalid: ") && said.contains("50001") && said.contains("`Comment`"), "{said}");
        // Line ends as the owner reads them are the ones posted.
        let shown = shown(&comment("a\r\nb".into())).unwrap();
        let Action::IssueComment(sealed) = &shown.sealed else { panic!() };
        assert_eq!(sealed.body, "a\nb");
    }

    #[test]
    fn line_comments_that_do_not_fit_a_field_each_are_given_as_one_file() {
        let comments: Vec<LineComment> = (1..=9)
            .map(|n| LineComment { path: "src/a.rs".into(), line: n, side: "RIGHT".into(), body: format!("remark {n}") })
            .collect();
        let review = Action::PrReview(PrReview { repo: "a/b".into(), number: 7, event: "COMMENT".into(), body: "s".into(), comments: comments.clone(), pull: Some(pull()) });
        let shown = shown(&review).unwrap();
        check_shown(&shown).unwrap();
        assert_eq!(shown.files.len(), 1);
        assert_eq!(shown.files[0].name, REVIEW_COMMENTS_FILE);
        let listed: Vec<LineComment> = serde_json::from_slice(&shown.files[0].data).unwrap();
        assert_eq!(listed, comments, "the file holds every comment as it is posted");
        assert!(read(&shown).contains("9, in the file review-comments.json"));
        // The file is shown; the comments are acted on from the state.
        assert_eq!(held(&serde_json::to_vec(&shown.sealed).unwrap(), &[]).unwrap(), review);
    }

    #[test]
    fn what_is_kept_is_the_write_and_nothing_else_reads_as_one() {
        let (issue, _) = every_write().remove(3);
        let kept = serde_json::to_vec(&issue).unwrap();
        assert_eq!(serde_json::from_slice::<Action>(&kept).unwrap(), issue);
        // A member this build does not know, inside the write or beside it: not a write.
        let mut inside: Value = serde_json::from_slice(&kept).unwrap();
        inside["issue_create"]["milestone"] = json!(3);
        assert!(serde_json::from_value::<Action>(inside).is_err());
        let mut beside: Value = serde_json::from_slice(&kept).unwrap();
        beside["pr_merge"] = json!({"repo": "a/b", "number": 1, "merge_method": "merge", "sha": null, "pull": null});
        assert!(serde_json::from_value::<Action>(beside).is_err());
        assert!(held(b"not a write", &[]).unwrap_err().starts_with("task_unreadable: "));
    }

    #[test]
    fn a_file_that_is_not_the_one_the_task_was_made_with_is_not_written() {
        let (commit, _) = every_write().remove(2);
        let shown = shown(&commit).unwrap();
        let state = serde_json::to_vec(&shown.sealed).unwrap();
        let mut other = shown.files.clone();
        other[0].data = vec![0x89, 0x50, 0xfe];
        for files in [other, vec![]] {
            let said = held(&state, &files).unwrap_err();
            assert!(said.starts_with("task_unreadable: ") && !said.contains("logo"), "{said}");
        }
    }

    // ===== the owner's answer: before it is taken, and after =====

    fn call() -> Input {
        Input {
            task_id: Some(" run-0 ".into()),
            task_hash: Some("ab".repeat(32)),
            approval: Some(json!({ "at": 1_790_000_000u64, "public_key": "ed25519:k", "signature": "s", "nonce": "n" })),
            ..Input::default()
        }
    }

    fn answer_holding(action: &Action) -> tasks::Answer {
        let shown = shown(action).unwrap();
        tasks::Answer {
            id: "run-0".into(),
            thread: "run-0".into(),
            preparer: "agent.testnet".into(),
            kind: tasks::TaskKind::Confirm,
            operation: ANSWERED_BY.into(),
            state: serde_json::to_vec(&shown.sealed).unwrap(),
            files: shown.files,
            supplied: None,
            note: None,
        }
    }

    fn never_acts(_: &policy::Policy, _: &Action, _: Counted) -> Result<Value, Unmade> {
        panic!("nothing is written")
    }

    fn never_reports(_: &str, _: &[u8]) -> Result<(), String> {
        panic!("a refusal is never reported as carried out")
    }

    fn never_fails(_: &str, _: &str) -> Result<(), String> {
        panic!("nothing is reported as not carried out")
    }

    const ALLOWS: &str = r#"{"actions":["any"],"repos":["alice/*"],"branches":["agent/*"],"max_writes_per_day":5,"allow_merge":true,"allow_approve":true,"confirm":["pr_merge","commit"]}"#;

    fn merge() -> Action {
        Action::PrMerge(PrMerge { repo: "alice/private-thing".into(), number: 8, merge_method: "squash".into(), sha: None, pull: Some(pull()) })
    }

    /// What a merge answers, as `execute` builds it.
    fn merged() -> Value {
        json!({"repo": "alice/private-thing", "number": 8, "merged": true, "commit": "d00d", "writes_today": 2})
    }

    #[test]
    fn a_call_that_names_no_task_is_refused_before_anything_is_asked() {
        let said = confirm(&Input::default()).unwrap_err();
        assert!(said.notice.is_none(), "nothing was answered, so no owner is told");
        let said = said.refusal;
        assert!(said.starts_with("task_answer_invalid: ") && said.contains("task_id"), "{said}");
        let no_hash = Input { task_id: Some("run-0".into()), ..Input::default() };
        assert!(confirm(&no_hash).unwrap_err().refusal.contains("task_hash"));
    }

    /// A refusal from before the answer says nothing of a closed task: the
    /// task is as it was.
    #[test]
    fn before_the_answer_a_refusal_leaves_the_task_as_it_was() {
        let no_policy = before_answer(&call(), policy::Loaded::None).unwrap_err();
        assert!(no_policy.starts_with("policy_missing: "), "{no_policy}");
        let unread = before_answer(&call(), policy::Loaded::Unreadable("unknown field `repositories`".into())).unwrap_err();
        assert!(unread.starts_with("policy_unreadable: "), "{unread}");
        let unnamed = before_answer(&Input::default(), policy::Loaded::Some(rules("{}"))).unwrap_err();
        assert!(unnamed.starts_with("task_answer_invalid: "), "{unnamed}");
        let unsigned = before_answer(&Input { approval: None, ..call() }, policy::Loaded::Some(rules("{}"))).unwrap_err();
        assert!(unsigned.starts_with("task_answer_invalid: ") && unsigned.contains("approval"), "{unsigned}");
        for said in [&no_policy, &unread, &unnamed, &unsigned] {
            assert!(!said.contains("closed") && !said.contains("prepare"), "{said}");
        }
        // On chain the policy's own words stay off: a parse error quotes what it choked on.
        let public = as_answered(unread, true);
        assert_eq!(public, "policy_unreadable: the stored policy is not one this connector understands");
        let call = call();
        let (read, _) = before_answer(&call, policy::Loaded::Some(rules("{}"))).unwrap();
        assert_eq!((read["task_id"].as_str(), read["task_hash"].as_str().map(str::len)), (Some("run-0"), Some(64)));
        assert_eq!(read["approval"]["nonce"], "n");
    }

    #[test]
    fn what_is_written_is_what_the_task_held_counted_in_the_agents_own_cell() {
        let (commit, _) = every_write().remove(2);
        let Action::Commit(c) = &commit else { panic!() };
        let commit = Action::Commit(Commit { repo: "alice/site".into(), branch: "agent/many".into(), ..c.clone() });
        let (seen, reported) = (RefCell::new(None), RefCell::new(None));
        let act = |_: &policy::Policy, action: &Action, counted: Counted| {
            assert_eq!(counted, Counted::Confirmed);
            *seen.borrow_mut() = Some(action.clone());
            Ok(json!({"repo": "alice/site", "branch": "agent/many", "commit": "d00d", "parent": "beef", "files": 3, "url": "https://github.com/alice/site/commit/d00d", "writes_today": 1}))
        };
        let report = |id: &str, result: &[u8]| {
            assert!(seen.borrow().is_some(), "nothing is reported before the write is made");
            *reported.borrow_mut() = Some((id.to_string(), serde_json::from_slice::<Value>(result).unwrap()));
            Ok(())
        };
        let out = after_answer(&rules(ALLOWS), &answer_holding(&commit), true, act, report, never_fails).unwrap();
        let written = seen.into_inner().expect("a write was made");
        assert_eq!(written, commit, "the binary came back from its file, byte for byte");
        let (id, result) = reported.into_inner().expect("a result was left");
        assert_eq!(id, "run-0");
        assert_eq!(result["url"], "https://github.com/alice/site/commit/d00d", "the agent's sealed result is whole");
        assert_eq!(out, json!({"commit": "d00d", "writes_today": 1, "status": "done", "task_id": "run-0", "action": "commit"}));
    }

    /// The owner's note reaches the agent with the result, changes nothing of
    /// the write, and stays off a chain answer.
    #[test]
    fn the_note_reaches_the_connector_and_changes_nothing_of_the_action() {
        let (commit, _) = every_write().remove(2);
        let (seen, reported) = (RefCell::new(None), RefCell::new(None));
        let act = |_: &policy::Policy, action: &Action, _: Counted| {
            *seen.borrow_mut() = Some(action.clone());
            Ok(json!({"repo": "alice/site", "branch": "agent/many", "commit": "d00d", "files": 3, "url": "https://github.com/alice/site/commit/d00d", "writes_today": 1}))
        };
        let report = |_: &str, result: &[u8]| {
            *reported.borrow_mut() = Some(serde_json::from_slice::<Value>(result).unwrap());
            Ok(())
        };
        let mut answer = answer_holding(&commit);
        answer.note = Some("squash it later".as_bytes().to_vec());
        let out = after_answer(&rules(ALLOWS), &answer, true, act, report, never_fails).unwrap();
        assert_eq!(seen.into_inner().unwrap(), commit, "the note changes nothing of the write");
        let result = reported.into_inner().unwrap();
        assert_eq!(result["note"], "squash it later");
        assert_eq!(result["url"], "https://github.com/alice/site/commit/d00d");
        assert!(out.get("note").is_none(), "a chain answer carries no note");
    }

    #[test]
    fn on_chain_the_answer_names_no_repository_and_carries_no_content() {
        let out = answered_with(&merge(), &merged(), "run-0", true);
        assert_eq!(out, json!({"number": 8, "merged": true, "commit": "d00d", "writes_today": 2, "status": "done", "task_id": "run-0", "action": "pr_merge"}));
        // Whatever a write answers, only the listed members leave.
        let everything = json!({
            "repo": "alice/private-thing", "branch": "agent/secret-plan", "path": "docs/salary.md", "from": "main",
            "url": "https://github.com/alice/private-thing/pull/8", "gist_id": "aa11bb22", "public": false,
            "title": "Fire Bob", "body": "text", "files": 3, "parent": "beef",
            "number": 8, "comment_id": 5, "review_id": 6, "commit": "d00d", "sha": "5eed", "created": true,
            "merged": true, "starred": true, "state": "APPROVED", "writes_today": 2,
        });
        let text = answered_with(&merge(), &everything, "run-0", true).to_string();
        for private in ["alice", "private-thing", "secret-plan", "salary", "github.com", "aa11bb22", "Fire Bob", "\"body\"", "\"from\"", "\"parent\""] {
            assert!(!text.contains(private), "`{private}` in {text}");
        }
        // Over HTTPS the answer is whole.
        let whole = answered_with(&merge(), &merged(), "run-0", false);
        assert_eq!(whole["repo"], "alice/private-thing");
        assert_eq!((whole["status"].as_str(), whole["action"].as_str()), (Some("done"), Some("pr_merge")));
    }

    #[test]
    fn after_the_answer_every_refusal_keeps_its_code_and_says_the_task_is_closed() {
        // Every refusal after the answer is also left for the agent, as the
        // failed task's result: `{"error": <the same sentence>}`.
        let failed = RefCell::new(None);
        let fails = |id: &str, why: &str| {
            *failed.borrow_mut() = Some((id.to_string(), why.to_string()));
            Ok(())
        };
        let ends = |said: &str, code: &str| {
            assert!(said.starts_with(code), "{said}");
            assert!(said.ends_with(CLOSED), "{said}");
            assert!(!said.contains(".."), "{said}");
            let (id, why) = failed.borrow_mut().take().expect("the refusal is reported as not carried out");
            assert_eq!((id.as_str(), why.as_str()), ("run-0", said));
        };
        // A state that is not a write: refused before anything is written.
        let broken = tasks::Answer { state: b"not a write".to_vec(), ..answer_holding(&merge()) };
        ends(&after_answer(&rules(ALLOWS), &broken, false, never_acts, never_reports, fails).unwrap_err(), "task_unreadable: ");

        // A write its rules refuse: a merge, under rules that allow none.
        let no_merge = rules(r#"{"actions":["any"],"repos":["alice/*"],"max_writes_per_day":5}"#);
        let said = after_answer(&no_merge, &answer_holding(&merge()), false, never_acts, never_reports, fails).unwrap_err();
        ends(&said, "policy_denied: ");
        assert!(said.contains("allow_merge"), "{said}");

        // The day's count, the token, GitHub: whatever the write refuses.
        for refusal in [
            "policy_denied: 5 of the owner's 5 writes a day are used; this one would pass it",
            "token_rejected: GitHub refused the owner's token (Bad credentials).",
            "conflict: Head branch was modified. The branch or file moved since it was read; read it again and repeat",
            "not_found: GitHub has nothing at /repos/alice/private-thing/pulls/8/merge.",
            "the day's write count could not be updated: storage unavailable",
        ] {
            let act = |_: &policy::Policy, _: &Action, _: Counted| Err(Unmade::Refused(refusal.to_string()));
            let said = after_answer(&rules(ALLOWS), &answer_holding(&merge()), false, act, never_reports, fails).unwrap_err();
            ends(&said, refusal.split(' ').next().unwrap());
            assert!(said.starts_with(refusal.trim_end_matches('.')), "over HTTPS the refusal is whole: {said}");

            // On chain the code stays and nothing is named.
            let act = |_: &policy::Policy, _: &Action, _: Counted| Err(Unmade::Refused(refusal.to_string()));
            let said = after_answer(&rules(ALLOWS), &answer_holding(&merge()), true, act, never_reports, fails).unwrap_err();
            ends(&said, code_of(refusal));
            assert!(!said.contains("alice") && !said.contains("/repos/"), "{said}");
        }
    }

    /// A write whose outcome GitHub did not give is reported neither way:
    /// the task ends `run_unreported`, and the agent is told to look first.
    #[test]
    fn a_write_whose_outcome_is_lost_is_never_reported_as_not_made() {
        for on_chain in [false, true] {
            let act = |_: &policy::Policy, _: &Action, _: Counted| {
                Err(Unmade::Unknown("github_unreachable: GitHub could not be reached for /repos/alice/site/pulls/8/merge: reset".into()))
            };
            let said = after_answer(&rules(ALLOWS), &answer_holding(&merge()), on_chain, act, never_reports, never_fails).unwrap_err();
            assert!(said.starts_with("github_unreachable") && said.contains("MAY have been made"), "{said}");
            assert!(!said.contains(CLOSED), "{said}");
        }
    }

    #[test]
    fn a_write_that_was_made_and_not_reported_is_said_to_have_been_made() {
        let act = |_: &policy::Policy, _: &Action, _: Counted| Ok(merged());
        let report = |_: &str, _: &[u8]| Err("task_store_unavailable: the task store did not answer".to_string());
        let said = after_answer(&rules(ALLOWS), &answer_holding(&merge()), true, act, report, never_fails).unwrap_err();
        assert!(said.starts_with("task_store_unavailable: the task store did not answer. "), "{said}");
        assert!(said.contains("WAS made") && said.contains("number 8") && said.contains("commit d00d") && said.contains("do not prepare it again"), "{said}");
        assert!(!said.contains(CLOSED) && !said.contains("alice"), "{said}");
    }
}
