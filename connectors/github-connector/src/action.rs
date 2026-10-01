//! A write, as one value: what the agent asked for, checked against the
//! owner's policy, and carried out — at once, or, when the owner's policy lists
//! the operation under `confirm`, sealed in a task and carried out when the
//! owner says yes.
//!
//! The four steps are apart so that `confirm` can repeat the ones that judge
//! and skip the ones that build:
//!
//! | step | what it does | GitHub |
//! |---|---|---|
//! | [`Action::prepare`] | reads the call into an action: every value it will use, the marker already on the texts | only to resolve what the action names (the commit a branch starts at; the head of a pull request the owner is asked to merge or review) |
//! | [`Action::check`] | the policy's rules, as the action holds its values | no |
//! | [`Action::check_on_github`] | that a branch a pattern allows is not the default one | yes |
//! | [`Action::execute`] | a place in the day's budget, then the calls | yes |
//!
//! `prepare` runs all of them but the last. `confirm` takes the action a task
//! held and runs `check`, `check_on_github` and `execute`: the action it
//! carries out is the one the owner was shown, judged by the rules as they
//! are at that moment.

use crate::github::{self as gh, file_path, segment};
use crate::ops::{self, need, number, one_of, repo, s};
use crate::policy::{self, BranchMatch, Confirmable, Counted, Policy};
use crate::{FileChange, Input};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// The longest text taken from an agent for a body, a comment or a description.
pub const MAX_TEXT_BYTES: usize = 60 * 1024;
/// The largest file `file_put` writes.
pub const MAX_PUT_BYTES: usize = ops::MAX_FILE_BYTES * 4;
/// Line comments in one review.
pub const MAX_REVIEW_COMMENTS: usize = 50;

/// What a file will hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Content {
    /// Text, held in the action itself.
    Text(String),
    /// Bytes that are not text. Never in a task's state: a task holds them
    /// as one of its files.
    Bytes(Vec<u8>),
    /// Held as a file of the task, under `name`. `confirm` writes the file's
    /// bytes only when they are `bytes` long and hash to `sha256`.
    File { name: String, bytes: usize, sha256: String },
}

impl Content {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        match String::from_utf8(bytes) {
            Ok(text) => Self::Text(text),
            Err(not_text) => Self::Bytes(not_text.into_bytes()),
        }
    }

    /// The bytes to write. A file of a task that was not taken back is not
    /// content.
    pub fn bytes(&self) -> Result<&[u8], String> {
        match self {
            Self::Text(text) => Ok(text.as_bytes()),
            Self::Bytes(bytes) => Ok(bytes),
            Self::File { .. } => Err("task_unreadable: a file of the task was not taken back".to_string()),
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Bytes(bytes) => bytes.len(),
            Self::File { bytes, .. } => *bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repo {
    pub repo: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BranchCreate {
    pub repo: String,
    pub branch: String,
    /// The branch the agent named to start from; absent: the default branch.
    pub from: Option<String>,
    /// Where the branch starts, as GitHub named it when the action was
    /// prepared.
    pub start: Option<Start>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub branch: String,
    pub sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePut {
    pub repo: String,
    pub branch: String,
    pub path: String,
    pub message: String,
    pub content: Content,
    /// The sha of the file being replaced; absent for a new file.
    pub sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Change {
    Write { path: String, content: Content },
    Delete { path: String },
}

impl Change {
    pub fn path(&self) -> &str {
        match self {
            Self::Write { path, .. } | Self::Delete { path } => path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub repo: String,
    pub branch: String,
    pub message: String,
    pub changes: Vec<Change>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueCreate {
    pub repo: String,
    pub title: String,
    /// With the marker.
    pub body: String,
    pub labels: Option<Vec<String>>,
    pub assignees: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueComment {
    pub repo: String,
    pub number: u64,
    /// With the marker.
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueUpdate {
    pub repo: String,
    pub number: u64,
    pub state: Option<String>,
    pub title: Option<String>,
    /// With the marker.
    pub body: Option<String>,
    pub labels: Option<Vec<String>>,
    pub assignees: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrCreate {
    pub repo: String,
    pub title: String,
    pub head: String,
    pub base: String,
    /// With the marker.
    pub body: String,
    pub draft: bool,
}

/// A pull request as GitHub described it when the owner was to be asked about
/// it: what the owner is shown, and the head the owner's yes is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pull {
    pub title: String,
    pub head: String,
    pub base: String,
    pub sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineComment {
    pub path: String,
    pub line: u64,
    pub side: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrReview {
    pub repo: String,
    pub number: u64,
    pub event: String,
    /// The summary, with the marker.
    pub body: String,
    pub comments: Vec<LineComment>,
    /// Present when the owner is asked: the review is of this head, and an
    /// approval of any other is refused.
    pub pull: Option<Pull>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrMerge {
    pub repo: String,
    pub number: u64,
    pub merge_method: String,
    /// The head the agent said the merge must match.
    pub sha: Option<String>,
    /// Present when the owner is asked: without a `sha` of the agent's, the
    /// merge must match the head the owner was shown.
    pub pull: Option<Pull>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum GistFile {
    Write { name: String, content: Content },
    Delete { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GistCreate {
    pub description: String,
    pub public: bool,
    pub files: Vec<GistFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GistUpdate {
    pub gist_id: String,
    pub description: Option<String>,
    pub files: Vec<GistFile>,
}

/// One write, by operation. What a task holds sealed, and all `confirm` acts
/// on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    BranchCreate(BranchCreate),
    FilePut(FilePut),
    Commit(Commit),
    IssueCreate(IssueCreate),
    IssueComment(IssueComment),
    IssueUpdate(IssueUpdate),
    PrCreate(PrCreate),
    PrReview(PrReview),
    PrMerge(PrMerge),
    GistCreate(GistCreate),
    GistUpdate(GistUpdate),
    RepoStar(Repo),
    RepoUnstar(Repo),
}

// ==================== reading the call ====================

fn text(value: &Option<String>, name: &str) -> Result<String, String> {
    let text = value.clone().unwrap_or_default();
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!("invalid: `{name}` is {} bytes; the most taken is {MAX_TEXT_BYTES}", text.len()));
    }
    Ok(text)
}

/// Text as it is, or bytes as base64 — the two ways an agent hands over a file.
fn content_bytes(content: &Option<String>, encoding: &Option<String>, what: &str) -> Result<Vec<u8>, String> {
    let content = content.as_deref().ok_or_else(|| format!("invalid: {what} needs `content`"))?;
    match encoding.as_deref().map(str::trim).unwrap_or("utf-8") {
        "utf-8" | "" => Ok(content.as_bytes().to_vec()),
        "base64" => BASE64
            .decode(content.chars().filter(|c| !c.is_whitespace()).collect::<String>().as_bytes())
            .map_err(|e| format!("invalid: {what} says base64 and is not: {e}")),
        other => Err(format!("invalid: `encoding` is `utf-8` or `base64`, got `{other}`")),
    }
}

/// `files` as a gist's: a plain name to text, or to nothing to remove it.
fn gist_files(files: &[FileChange], removing_allowed: bool) -> Result<Vec<GistFile>, String> {
    if files.is_empty() {
        return Err("invalid: `files` is required: [{\"path\": \"notes.md\", \"content\": \"…\"}]".to_string());
    }
    let mut out = Vec::with_capacity(files.len());
    for file in files {
        let name = file.path.trim();
        if name.is_empty() || name.contains('/') || name.len() > 255 {
            return Err(format!("invalid: a gist file's `path` is a plain file name, got `{}`", file.path));
        }
        if file.delete {
            if !removing_allowed {
                return Err("invalid: a new gist has no file to delete".to_string());
            }
            out.push(GistFile::Delete { name: name.to_string() });
            continue;
        }
        let bytes = content_bytes(&file.content, &file.encoding, &format!("`{name}`"))?;
        let content = String::from_utf8(bytes).map_err(|_| format!("invalid: `{name}` is not text; a gist holds text"))?;
        if content.trim().is_empty() {
            return Err(format!("invalid: `{name}` is empty; GitHub does not keep an empty gist file"));
        }
        out.push(GistFile::Write { name: name.to_string(), content: Content::Text(content) });
    }
    Ok(out)
}

fn list(value: &Option<Vec<String>>) -> Option<Vec<String>> {
    value.clone()
}

impl Action {
    /// The operation this action is.
    pub fn confirmable(&self) -> Confirmable {
        match self {
            Self::BranchCreate(_) => Confirmable::BranchCreate,
            Self::FilePut(_) => Confirmable::FilePut,
            Self::Commit(_) => Confirmable::Commit,
            Self::IssueCreate(_) => Confirmable::IssueCreate,
            Self::IssueComment(_) => Confirmable::IssueComment,
            Self::IssueUpdate(_) => Confirmable::IssueUpdate,
            Self::PrCreate(_) => Confirmable::PrCreate,
            Self::PrReview(_) => Confirmable::PrReview,
            Self::PrMerge(_) => Confirmable::PrMerge,
            Self::GistCreate(_) => Confirmable::GistCreate,
            Self::GistUpdate(_) => Confirmable::GistUpdate,
            Self::RepoStar(_) => Confirmable::RepoStar,
            Self::RepoUnstar(_) => Confirmable::RepoUnstar,
        }
    }

    /// The repository it writes to; a gist is in none.
    pub fn repo(&self) -> Option<&str> {
        match self {
            Self::BranchCreate(a) => Some(&a.repo),
            Self::FilePut(a) => Some(&a.repo),
            Self::Commit(a) => Some(&a.repo),
            Self::IssueCreate(a) => Some(&a.repo),
            Self::IssueComment(a) => Some(&a.repo),
            Self::IssueUpdate(a) => Some(&a.repo),
            Self::PrCreate(a) => Some(&a.repo),
            Self::PrReview(a) => Some(&a.repo),
            Self::PrMerge(a) => Some(&a.repo),
            Self::RepoStar(a) | Self::RepoUnstar(a) => Some(&a.repo),
            Self::GistCreate(_) | Self::GistUpdate(_) => None,
        }
    }

    /// The branch it writes to, and so must be one the policy lets it write.
    fn written_branch(&self) -> Option<&str> {
        match self {
            Self::BranchCreate(a) => Some(&a.branch),
            Self::FilePut(a) => Some(&a.branch),
            Self::Commit(a) => Some(&a.branch),
            Self::PrCreate(a) => Some(&a.head),
            _ => None,
        }
    }

    /// Every file's content, by the path or name it is written to.
    pub fn contents_mut(&mut self) -> Vec<(String, &mut Content)> {
        match self {
            Self::FilePut(a) => vec![(a.path.clone(), &mut a.content)],
            Self::Commit(a) => a
                .changes
                .iter_mut()
                .filter_map(|c| match c {
                    Change::Write { path, content } => Some((path.clone(), content)),
                    Change::Delete { .. } => None,
                })
                .collect(),
            Self::GistCreate(GistCreate { files, .. }) | Self::GistUpdate(GistUpdate { files, .. }) => files
                .iter_mut()
                .filter_map(|f| match f {
                    GistFile::Write { name, content } => Some((name.clone(), content)),
                    GistFile::Delete { .. } => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Read the call as `operation`, check it against `rules`, and resolve
    /// what it names on GitHub. `for_owner`: the action will be shown to the
    /// owner, so a pull request it merges or reviews is read now and its head
    /// becomes part of the action.
    pub fn prepare(operation: Confirmable, input: &Input, rules: &Policy, for_owner: bool) -> Result<Self, String> {
        rules.check_action(operation.name())?;
        let mut action = Self::read(operation, input, rules)?;
        action.check(rules)?;
        action.check_on_github(rules)?;
        action.resolve(for_owner)?;
        Ok(action)
    }

    /// The call as an action: every value it will use, the marker on the texts
    /// the agent posts under the owner's name.
    fn read(operation: Confirmable, input: &Input, rules: &Policy) -> Result<Self, String> {
        let owned = |v: &str| v.to_string();
        Ok(match operation {
            Confirmable::BranchCreate => Self::BranchCreate(BranchCreate {
                repo: owned(repo(input)?),
                branch: owned(need(&input.branch, "branch")?),
                from: input.from.as_deref().map(str::trim).filter(|f| !f.is_empty()).map(owned),
                start: None,
            }),
            Confirmable::FilePut => {
                let repo = owned(repo(input)?);
                let branch = owned(need(&input.branch, "branch")?);
                let path = owned(need(&input.path, "path")?);
                let message = owned(need(&input.message, "message")?);
                let content = Content::from_bytes(content_bytes(&input.content, &input.encoding, "`file_put`")?);
                let sha = input.sha.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(owned);
                Self::FilePut(FilePut { repo, branch, path, message, content, sha })
            }
            Confirmable::Commit => {
                let repo = owned(repo(input)?);
                let branch = owned(need(&input.branch, "branch")?);
                let message = owned(need(&input.message, "message")?);
                if input.files.is_empty() {
                    return Err("invalid: `files` is required: [{\"path\", \"content\"}] or [{\"path\", \"delete\": true}]".to_string());
                }
                if input.files.len() > policy::MAX_FILES_PER_COMMIT {
                    return Err(too_many_files(input.files.len()));
                }
                let mut changes = Vec::with_capacity(input.files.len());
                for file in &input.files {
                    changes.push(match file.delete {
                        true => Change::Delete { path: file.path.clone() },
                        false => Change::Write {
                            path: file.path.clone(),
                            content: Content::from_bytes(content_bytes(&file.content, &file.encoding, &format!("`{}`", file.path))?),
                        },
                    });
                }
                Self::Commit(Commit { repo, branch, message, changes })
            }
            Confirmable::IssueCreate => Self::IssueCreate(IssueCreate {
                repo: owned(repo(input)?),
                title: owned(need(&input.title, "title")?),
                body: rules.mark(&text(&input.body, "body")?),
                labels: list(&input.labels),
                assignees: list(&input.assignees),
            }),
            Confirmable::IssueComment => {
                let repo = owned(repo(input)?);
                let number = number(input)?;
                let said = text(&input.body, "body")?;
                if said.trim().is_empty() {
                    return Err("invalid: `body` is required".to_string());
                }
                Self::IssueComment(IssueComment { repo, number, body: rules.mark(&said) })
            }
            Confirmable::IssueUpdate => {
                let repo = owned(repo(input)?);
                let number = number(input)?;
                let state = one_of(&input.state, "state", &["open", "closed"])?;
                let title = input.title.as_deref().map(str::trim).filter(|t| !t.is_empty()).map(owned);
                let body = match input.body.is_some() {
                    true => Some(rules.mark(&text(&input.body, "body")?)),
                    false => None,
                };
                let update = IssueUpdate { repo, number, state, title, body, labels: list(&input.labels), assignees: list(&input.assignees) };
                if update.state.is_none() && update.title.is_none() && update.body.is_none() && update.labels.is_none() && update.assignees.is_none() {
                    return Err("invalid: nothing to change — give `state`, `title`, `body`, `labels` or `assignees`".to_string());
                }
                Self::IssueUpdate(update)
            }
            Confirmable::PrCreate => {
                let repo = owned(repo(input)?);
                let title = owned(need(&input.title, "title")?);
                let head = owned(need(&input.head, "head")?);
                let base = owned(need(&input.base, "base")?);
                let body = rules.mark(&text(&input.body, "body")?);
                Self::PrCreate(PrCreate { repo, title, head, base, body, draft: input.draft.unwrap_or(false) })
            }
            Confirmable::PrReview => {
                let repo = owned(repo(input)?);
                let number = number(input)?;
                let event = one_of(&input.event, "event", &["COMMENT", "REQUEST_CHANGES", "APPROVE"])?
                    .unwrap_or_else(|| "COMMENT".to_string());
                // Refused before anything else is read, as it always was.
                if event == "APPROVE" {
                    rules.check_approve()?;
                }
                let summary = text(&input.body, "body")?;
                if summary.trim().is_empty() && input.comments.is_empty() {
                    return Err("invalid: a review needs a `body`, `comments`, or both".to_string());
                }
                if input.comments.len() > MAX_REVIEW_COMMENTS {
                    return Err(format!(
                        "invalid: {} comments in one review; the most taken is {MAX_REVIEW_COMMENTS}",
                        input.comments.len()
                    ));
                }
                let mut comments = Vec::with_capacity(input.comments.len());
                for c in &input.comments {
                    if c.path.trim().is_empty() || c.line == 0 || c.body.trim().is_empty() {
                        return Err("invalid: each review comment needs `path`, `line` and `body`".to_string());
                    }
                    let side = one_of(&c.side, "side", &["LEFT", "RIGHT"])?.unwrap_or_else(|| "RIGHT".to_string());
                    comments.push(LineComment { path: c.path.clone(), line: c.line, side, body: c.body.clone() });
                }
                // The marker goes on the summary, once per review, not on every line comment.
                Self::PrReview(PrReview { repo, number, event, body: rules.mark(&summary), comments, pull: None })
            }
            Confirmable::PrMerge => {
                // Refused before anything else is read, as it always was.
                rules.check_merge()?;
                let repo = owned(repo(input)?);
                let number = number(input)?;
                let merge_method = one_of(&input.merge_method, "merge_method", &["merge", "squash", "rebase"])?
                    .unwrap_or_else(|| "squash".to_string());
                let sha = input.sha.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(owned);
                Self::PrMerge(PrMerge { repo, number, merge_method, sha, pull: None })
            }
            Confirmable::GistCreate => {
                let public = input.public.unwrap_or(false);
                rules.check_public_gist(public)?;
                Self::GistCreate(GistCreate {
                    description: text(&input.description, "description")?,
                    public,
                    files: gist_files(&input.files, false)?,
                })
            }
            Confirmable::GistUpdate => {
                let gist_id = owned(ops::gist_id(input)?);
                let files = match input.files.is_empty() {
                    true => Vec::new(),
                    false => gist_files(&input.files, true)?,
                };
                let description = match input.description.is_some() {
                    true => Some(text(&input.description, "description")?),
                    false => None,
                };
                if files.is_empty() && description.is_none() {
                    return Err("invalid: nothing to change — give `files`, `description` or both".to_string());
                }
                Self::GistUpdate(GistUpdate { gist_id, description, files })
            }
            Confirmable::RepoStar => Self::RepoStar(Repo { repo: owned(repo(input)?) }),
            Confirmable::RepoUnstar => Self::RepoUnstar(Repo { repo: owned(repo(input)?) }),
        })
    }

    /// The owner's rules, as the action holds its values. Needs nothing but
    /// the policy: `confirm` runs it on the action a task held, under the
    /// policy the task was made under.
    pub fn check(&self, rules: &Policy) -> Result<(), String> {
        rules.check_action(self.confirmable().name())?;
        if let Some(repo) = self.repo() {
            policy::clean_repo(repo)?;
            rules.check_repo(repo)?;
        }
        match self {
            Self::BranchCreate(a) => {
                writable(rules, &a.branch)?;
                if let Some(from) = &a.from {
                    policy::clean_branch(from)?;
                }
            }
            Self::FilePut(a) => {
                rules.check_path(&a.path)?;
                writable(rules, &a.branch)?;
                if a.content.len() > MAX_PUT_BYTES {
                    return Err(format!("too_large: the file is {} bytes; the most written is {MAX_PUT_BYTES}", a.content.len()));
                }
            }
            Self::Commit(a) => {
                if a.changes.is_empty() {
                    return Err("invalid: a commit changes at least one file".to_string());
                }
                if a.changes.len() > policy::MAX_FILES_PER_COMMIT {
                    return Err(too_many_files(a.changes.len()));
                }
                for change in &a.changes {
                    rules.check_path(change.path())?;
                }
                writable(rules, &a.branch)?;
            }
            Self::PrCreate(a) => {
                // The agent opens pull requests FROM branches it may write; where
                // they point is the owner's review to make.
                writable(rules, &a.head)?;
                policy::clean_branch(&a.base)?;
            }
            Self::PrReview(a) => {
                if a.event == "APPROVE" {
                    rules.check_approve()?;
                }
                if a.comments.len() > MAX_REVIEW_COMMENTS {
                    return Err(format!("invalid: {} comments in one review; the most taken is {MAX_REVIEW_COMMENTS}", a.comments.len()));
                }
            }
            Self::PrMerge(_) => rules.check_merge()?,
            Self::GistCreate(a) => rules.check_public_gist(a.public)?,
            Self::IssueCreate(_)
            | Self::IssueComment(_)
            | Self::IssueUpdate(_)
            | Self::GistUpdate(_)
            | Self::RepoStar(_)
            | Self::RepoUnstar(_) => {}
        }
        rules.write_cap().map(|_| ())
    }

    /// The rule GitHub has to be asked about: a branch the policy allows only
    /// through a pattern must not be the repository's default branch. One
    /// request, and only then.
    pub fn check_on_github(&self, rules: &Policy) -> Result<(), String> {
        let (Some(repo), Some(branch)) = (self.repo(), self.written_branch()) else {
            return Ok(());
        };
        let matched = rules.check_branch(branch)?;
        if matched == BranchMatch::Pattern {
            Policy::check_not_default(matched, branch, &default_branch(repo)?)?;
        }
        Ok(())
    }

    /// What the action names on GitHub, read once, when it is prepared.
    fn resolve(&mut self, for_owner: bool) -> Result<(), String> {
        match self {
            Self::BranchCreate(a) => {
                let branch = match &a.from {
                    Some(from) => from.clone(),
                    None => default_branch(&a.repo)?,
                };
                let sha = gh::get(&format!("/repos/{}/git/ref/heads/{branch}", a.repo))?
                    .get("object")
                    .and_then(|o| o.get("sha"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .ok_or_else(|| format!("not_found: the branch `{branch}` has no commit to start from"))?;
                a.start = Some(Start { branch, sha });
            }
            Self::PrReview(a) if for_owner => a.pull = Some(pull(&a.repo, a.number)?),
            Self::PrMerge(a) if for_owner => a.pull = Some(pull(&a.repo, a.number)?),
            _ => {}
        }
        Ok(())
    }

    /// Take a place in `counted`'s budget for the day, make the calls, and keep
    /// the place only when GitHub accepted. The answer is the whole result:
    /// the agent's, or the report a confirmed task leaves for its preparer.
    pub fn execute(&self, rules: &Policy, counted: Counted) -> Result<Value, String> {
        match self {
            Self::BranchCreate(a) => {
                let start = a.start.as_ref().ok_or("task_unreadable: the branch has no commit to start from")?;
                let (place, used) = rules.reserve_write(counted)?;
                gh::post(&format!("/repos/{}/git/refs", a.repo), &json!({"ref": format!("refs/heads/{}", a.branch), "sha": start.sha}))?;
                place.keep();
                Ok(json!({"repo": a.repo, "branch": a.branch, "from": start.branch, "sha": start.sha, "writes_today": used}))
            }
            Self::FilePut(a) => {
                let mut body = json!({"message": a.message, "content": BASE64.encode(a.content.bytes()?), "branch": a.branch});
                // Present for an update, absent for a new file: GitHub refuses an update
                // without it, which is what stops one write landing on top of another.
                if let Some(sha) = &a.sha {
                    body["sha"] = json!(sha);
                }
                let (place, used) = rules.reserve_write(counted)?;
                let answer = gh::put(&format!("/repos/{}/contents/{}", a.repo, file_path(&a.path)), Some(&body)).map_err(|e| {
                    if e.starts_with("invalid:") && e.contains("sha") {
                        format!("{e}. The file exists: read it with `file_get` and pass its `sha` to replace it")
                    } else {
                        e
                    }
                })?;
                place.keep();
                Ok(json!({
                    "repo": a.repo, "branch": a.branch, "path": a.path, "created": answer.status == 201,
                    "sha": answer.body.get("content").map(|c| s(c, "sha")).unwrap_or(Value::Null),
                    "commit": answer.body.get("commit").map(|c| s(c, "sha")).unwrap_or(Value::Null),
                    "url": answer.body.get("content").map(|c| s(c, "html_url")).unwrap_or(Value::Null),
                    "writes_today": used,
                }))
            }
            Self::Commit(a) => commit(rules, a, counted),
            Self::IssueCreate(a) => {
                let mut body = json!({"title": a.title, "body": a.body});
                if let Some(labels) = &a.labels { body["labels"] = json!(labels); }
                if let Some(assignees) = &a.assignees { body["assignees"] = json!(assignees); }
                let (place, used) = rules.reserve_write(counted)?;
                let issue = gh::post(&format!("/repos/{}/issues", a.repo), &body)?;
                place.keep();
                Ok(json!({"repo": a.repo, "number": s(&issue, "number"), "url": s(&issue, "html_url"), "writes_today": used}))
            }
            Self::IssueComment(a) => {
                let (place, used) = rules.reserve_write(counted)?;
                let comment = gh::post(&format!("/repos/{}/issues/{}/comments", a.repo, a.number), &json!({"body": a.body}))?;
                place.keep();
                Ok(json!({"repo": a.repo, "number": a.number, "comment_id": s(&comment, "id"), "url": s(&comment, "html_url"), "writes_today": used}))
            }
            Self::IssueUpdate(a) => {
                let mut body = json!({});
                if let Some(state) = &a.state { body["state"] = json!(state); }
                if let Some(title) = &a.title { body["title"] = json!(title); }
                if let Some(text) = &a.body { body["body"] = json!(text); }
                if let Some(labels) = &a.labels { body["labels"] = json!(labels); }
                if let Some(assignees) = &a.assignees { body["assignees"] = json!(assignees); }
                let (place, used) = rules.reserve_write(counted)?;
                let issue = gh::patch(&format!("/repos/{}/issues/{}", a.repo, a.number), &body)?;
                place.keep();
                Ok(json!({"repo": a.repo, "number": a.number, "state": s(&issue, "state"), "url": s(&issue, "html_url"), "writes_today": used}))
            }
            Self::PrCreate(a) => {
                let body = json!({"title": a.title, "head": a.head, "base": a.base, "body": a.body, "draft": a.draft});
                let (place, used) = rules.reserve_write(counted)?;
                let pr = gh::post(&format!("/repos/{}/pulls", a.repo), &body)?;
                place.keep();
                Ok(json!({"repo": a.repo, "number": s(&pr, "number"), "url": s(&pr, "html_url"), "writes_today": used}))
            }
            Self::PrReview(a) => {
                let comments: Vec<Value> = a
                    .comments
                    .iter()
                    .map(|c| json!({"path": c.path, "line": c.line, "side": c.side, "body": c.body}))
                    .collect();
                let mut body = json!({"event": a.event, "body": a.body, "comments": comments});
                if let Some(pull) = &a.pull {
                    body["commit_id"] = json!(pull.sha);
                }
                let (place, used) = rules.reserve_write(counted)?;
                // An approval the owner confirmed is of the head they were
                // shown: one that moved since is code nobody approved.
                if let (Some(pull), "APPROVE") = (&a.pull, a.event.as_str()) {
                    let now = head_of(&a.repo, a.number)?;
                    if now != pull.sha {
                        return Err(format!(
                            "conflict: the pull request's head moved from {} to {now} since the owner was shown it, \
                             and an approval is of the head the owner saw; nothing was approved",
                            pull.sha
                        ));
                    }
                }
                let review = gh::post(&format!("/repos/{}/pulls/{}/reviews", a.repo, a.number), &body)?;
                place.keep();
                Ok(json!({"repo": a.repo, "number": a.number, "review_id": s(&review, "id"), "state": s(&review, "state"), "url": s(&review, "html_url"), "writes_today": used}))
            }
            Self::PrMerge(a) => {
                let mut body = json!({"merge_method": a.merge_method});
                // Merges only the head the agent looked at, when it says which,
                // and the head the owner was shown, when the owner is asked.
                if let Some(sha) = a.sha.as_ref().or(a.pull.as_ref().map(|p| &p.sha)) {
                    body["sha"] = json!(sha);
                }
                let (place, used) = rules.reserve_write(counted)?;
                let answer = gh::put(&format!("/repos/{}/pulls/{}/merge", a.repo, a.number), Some(&body))?;
                place.keep();
                Ok(json!({"repo": a.repo, "number": a.number, "merged": s(&answer.body, "merged"), "commit": s(&answer.body, "sha"), "writes_today": used}))
            }
            Self::GistCreate(a) => {
                let body = json!({"description": a.description, "public": a.public, "files": gist_body(&a.files)?});
                let (place, used) = rules.reserve_write(counted)?;
                let gist = gh::post("/gists", &body)?;
                place.keep();
                Ok(json!({"gist_id": s(&gist, "id"), "public": s(&gist, "public"), "url": s(&gist, "html_url"), "writes_today": used}))
            }
            // Changes a gist's files or description. It cannot make a secret gist
            // public: GitHub's API has no such switch, and this does not pretend
            // to have one.
            Self::GistUpdate(a) => {
                let mut body = json!({});
                if !a.files.is_empty() { body["files"] = gist_body(&a.files)?; }
                if let Some(description) = &a.description { body["description"] = json!(description); }
                let (place, used) = rules.reserve_write(counted)?;
                let gist = gh::patch(&format!("/gists/{}", segment(&a.gist_id)), &body)?;
                place.keep();
                Ok(json!({"gist_id": s(&gist, "id"), "public": s(&gist, "public"), "url": s(&gist, "html_url"), "writes_today": used}))
            }
            Self::RepoStar(a) => star(rules, &a.repo, true, counted),
            Self::RepoUnstar(a) => star(rules, &a.repo, false, counted),
        }
    }
}

fn too_many_files(n: usize) -> String {
    format!(
        "too_large: {n} files in one commit; a run has time for {}. Split it into several commits",
        policy::MAX_FILES_PER_COMMIT
    )
}

/// A branch the policy lets the agent write, by name or by pattern.
fn writable(rules: &Policy, branch: &str) -> Result<BranchMatch, String> {
    policy::clean_branch(branch)?;
    rules.check_branch(branch)
}

fn default_branch(repo: &str) -> Result<String, String> {
    gh::get(&format!("/repos/{repo}"))?
        .get("default_branch")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "github_refused: the repository did not name its default branch".to_string())
}

fn pull(repo: &str, number: u64) -> Result<Pull, String> {
    let pr = gh::get(&format!("/repos/{repo}/pulls/{number}"))?;
    let named = |side: &str, key: &str| pr.get(side).and_then(|s| s.get(key)).and_then(Value::as_str).map(str::to_string);
    let unnamed = || "github_refused: the pull request did not name its head and base".to_string();
    Ok(Pull {
        title: pr.get("title").and_then(Value::as_str).unwrap_or_default().to_string(),
        head: named("head", "ref").ok_or_else(unnamed)?,
        base: named("base", "ref").ok_or_else(unnamed)?,
        sha: named("head", "sha").ok_or_else(unnamed)?,
    })
}

fn head_of(repo: &str, number: u64) -> Result<String, String> {
    Ok(pull(repo, number)?.sha)
}

/// A gist's `files` as GitHub takes them: a name to its content, or to `null`
/// to remove it.
fn gist_body(files: &[GistFile]) -> Result<Value, String> {
    let mut out = serde_json::Map::new();
    for file in files {
        match file {
            GistFile::Delete { name } => {
                out.insert(name.clone(), Value::Null);
            }
            GistFile::Write { name, content } => {
                let text = std::str::from_utf8(content.bytes()?)
                    .map_err(|_| format!("invalid: `{name}` is not text; a gist holds text"))?;
                out.insert(name.clone(), json!({"content": text}));
            }
        }
    }
    Ok(Value::Object(out))
}

fn star(rules: &Policy, repo: &str, on: bool, counted: Counted) -> Result<Value, String> {
    let (place, used) = rules.reserve_write(counted)?;
    let path = format!("/user/starred/{repo}");
    if on { gh::put(&path, None)? } else { gh::delete(&path)? };
    place.keep();
    Ok(json!({"repo": repo, "starred": on, "writes_today": used}))
}

/// Several files in one commit, through the Git Data API: the tree is built on
/// the branch's own tree, the commit on its head, and the branch is moved
/// without force — a branch that moved meanwhile answers `conflict`.
fn commit(rules: &Policy, a: &Commit, counted: Counted) -> Result<Value, String> {
    let (repo, branch) = (&a.repo, &a.branch);
    let (place, used) = rules.reserve_write(counted)?;
    let head = gh::get(&format!("/repos/{repo}/git/ref/heads/{branch}"))?
        .get("object").and_then(|o| o.get("sha")).and_then(Value::as_str).map(str::to_string)
        .ok_or_else(|| format!("not_found: the branch `{branch}` does not exist; create it with `branch_create`"))?;
    let base_tree = gh::get(&format!("/repos/{repo}/git/commits/{head}"))?
        .get("tree").and_then(|t| t.get("sha")).and_then(Value::as_str).map(str::to_string)
        .ok_or_else(|| "github_refused: the branch's head has no tree".to_string())?;

    let mut tree = Vec::with_capacity(a.changes.len());
    for change in &a.changes {
        match change {
            Change::Delete { path } => tree.push(json!({"path": path, "mode": "100644", "type": "blob", "sha": Value::Null})),
            Change::Write { path, content } => match std::str::from_utf8(content.bytes()?) {
                // Text rides in the tree itself: no request of its own.
                Ok(text) => tree.push(json!({"path": path, "mode": "100644", "type": "blob", "content": text})),
                Err(_) => {
                    let blob = gh::post(&format!("/repos/{repo}/git/blobs"), &json!({"content": BASE64.encode(content.bytes()?), "encoding": "base64"}))?;
                    tree.push(json!({"path": path, "mode": "100644", "type": "blob", "sha": s(&blob, "sha")}));
                }
            },
        }
    }
    let new_tree = gh::post(&format!("/repos/{repo}/git/trees"), &json!({"base_tree": base_tree, "tree": tree}))?;
    let new_commit = gh::post(&format!("/repos/{repo}/git/commits"), &json!({"message": a.message, "tree": s(&new_tree, "sha"), "parents": [head]}))?;
    let sha = s(&new_commit, "sha");
    // Never forced. A branch that moved since `head` was read refuses this, and
    // the agent reads again rather than overwriting somebody's push.
    gh::patch(&format!("/repos/{repo}/git/refs/heads/{branch}"), &json!({"sha": sha, "force": false}))?;
    place.keep();
    Ok(json!({"repo": repo, "branch": branch, "commit": sha, "parent": head, "files": a.changes.len(), "url": s(&new_commit, "html_url"), "writes_today": used}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(json: &str) -> Input {
        serde_json::from_str(json).unwrap()
    }

    fn rules(json: &str) -> Policy {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn a_gist_file_is_a_name_and_text() {
        let files = |json: &str| input(json).files;
        assert!(gist_files(&files(r#"{"files":[{"path":"a.md","content":"x"}]}"#), false).is_ok());
        assert!(gist_files(&files(r#"{"files":[{"path":"dir/a.md","content":"x"}]}"#), false).is_err());
        assert!(gist_files(&files(r#"{"files":[{"path":"a.md","content":"  "}]}"#), false).is_err());
        assert!(gist_files(&files(r#"{"files":[{"path":"a.md","delete":true}]}"#), false).is_err());
        let removed = gist_files(&files(r#"{"files":[{"path":"a.md","delete":true}]}"#), true).unwrap();
        assert_eq!(gist_body(&removed).unwrap()["a.md"], Value::Null);
    }

    /// What reads the call and needs no GitHub: every write, from a call, to
    /// the value that is carried out or sealed.
    #[test]
    fn a_call_reads_into_the_action_it_asks_for() {
        let open = rules(r#"{"actions":["any"],"repos":["any"],"branches":["agent/*"],"max_writes_per_day":9,"marker":" [bot]"}"#);
        let read = |op, json: &str| Action::read(op, &input(json), &open);

        let Action::Commit(c) = read(Confirmable::Commit, r#"{"repo":"a/b","branch":"agent/x","message":"m","files":[{"path":"a.txt","content":"hi"},{"path":"b.bin","content":"/w==","encoding":"base64"},{"path":"c","delete":true}]}"#).unwrap() else { panic!() };
        assert_eq!(c.changes, vec![
            Change::Write { path: "a.txt".into(), content: Content::Text("hi".into()) },
            Change::Write { path: "b.bin".into(), content: Content::Bytes(vec![0xff]) },
            Change::Delete { path: "c".into() },
        ]);
        // A file that does not decode is refused before anything is reserved.
        let said = read(Confirmable::Commit, r#"{"repo":"a/b","branch":"agent/x","message":"m","files":[{"path":"a","content":"*","encoding":"base64"}]}"#).unwrap_err();
        assert!(said.starts_with("invalid: `a` says base64"), "{said}");

        let Action::IssueComment(c) = read(Confirmable::IssueComment, r#"{"repo":"a/b","number":3,"body":"hello"}"#).unwrap() else { panic!() };
        assert_eq!(c.body, "hello [bot]", "the marker is part of what is posted");

        let said = read(Confirmable::IssueUpdate, r#"{"repo":"a/b","number":3}"#).unwrap_err();
        assert!(said.contains("nothing to change"), "{said}");

        let said = read(Confirmable::PrMerge, r#"{"repo":"a/b","number":3}"#).unwrap_err();
        assert!(said.contains("allow_merge"), "{said}");
    }

    #[test]
    fn the_policy_is_judged_on_the_values_the_action_holds() {
        let p = rules(r#"{"actions":["file_put","commit","pr_merge","gist_create"],"repos":["a/*"],"branches":["agent/*"],"paths":["docs/*"],"max_writes_per_day":5}"#);
        let put = |repo: &str, branch: &str, path: &str| {
            Action::FilePut(FilePut { repo: repo.into(), branch: branch.into(), path: path.into(), message: "m".into(), content: Content::Text("x".into()), sha: None })
        };
        assert!(put("a/b", "agent/x", "docs/a.md").check(&p).is_ok());
        assert!(put("c/d", "agent/x", "docs/a.md").check(&p).unwrap_err().contains("repository"));
        assert!(put("a/b", "main", "docs/a.md").check(&p).unwrap_err().contains("branch"));
        assert!(put("a/b", "agent/x", "src/a.rs").check(&p).unwrap_err().contains("src/a.rs"));
        assert!(put("a/b", "agent/x", ".github/CODEOWNERS").check(&p).unwrap_err().contains(".github/"));
        let merge = Action::PrMerge(PrMerge { repo: "a/b".into(), number: 1, merge_method: "squash".into(), sha: None, pull: None });
        assert!(merge.check(&p).unwrap_err().contains("allow_merge"));
        let gist = Action::GistCreate(GistCreate { description: String::new(), public: true, files: vec![] });
        assert!(gist.check(&p).unwrap_err().contains("allow_public_gists"));
        let star = Action::RepoStar(Repo { repo: "a/b".into() });
        assert!(star.check(&p).unwrap_err().contains("repo_star"), "an action the policy does not list");
        let uncapped = rules(r#"{"actions":["any"],"repos":["any"],"branches":["agent/*"]}"#);
        assert!(put("a/b", "agent/x", "docs/a.md").check(&uncapped).unwrap_err().contains("max_writes_per_day"));
    }
}
