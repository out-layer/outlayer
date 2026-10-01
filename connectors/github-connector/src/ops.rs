//! The operations: what an agent asks for, what the policy is asked first, the
//! call to GitHub, and the part of GitHub's answer an agent can use.
//!
//! Every operation on a repository checks the action and the repository before
//! anything else. Every write is an [`Action`]: read from the call and checked,
//! then carried out — or, when the owner's policy lists it under `confirm`,
//! left as a task for the owner (`crate::confirm`). Carrying it out takes a
//! place in the owner's daily budget BEFORE GitHub is called and keeps it only
//! when GitHub accepted — a refused write costs the owner nothing.
//!
//! Answers are cut down on purpose. GitHub describes one pull request in fifteen
//! kilobytes, most of it URLs of other endpoints; what is returned here is what
//! an agent reads or passes to the next call.

use crate::action::Action;
use crate::github::{self as gh, file_path, query};
use crate::policy::{self, Confirmable, Counted, Policy};
use crate::{confirm, Input};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{json, Value};

/// The largest file `file_get` returns, decoded.
pub(crate) const MAX_FILE_BYTES: usize = 256 * 1024;
/// The most of one file's patch `pr_files` returns, and of all of them together.
const MAX_PATCH_BYTES: usize = 8 * 1024;
const MAX_PATCHES_TOTAL: usize = 120 * 1024;

// ==================== input helpers ====================

pub(crate) fn need<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str, String> {
    match value.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("invalid: `{name}` is required")),
    }
}

pub(crate) fn repo(input: &Input) -> Result<&str, String> {
    let repo = need(&input.repo, "repo")?;
    policy::clean_repo(repo)?;
    Ok(repo)
}

pub(crate) fn number(input: &Input) -> Result<u64, String> {
    input.number.filter(|n| *n > 0).ok_or_else(|| "invalid: `number` is required".to_string())
}

fn paging(input: &Input) -> [(&'static str, Option<String>); 2] {
    [
        ("per_page", Some(input.per_page.unwrap_or(30).clamp(1, 50).to_string())),
        ("page", Some(input.page.unwrap_or(1).max(1).to_string())),
    ]
}

pub(crate) fn one_of(value: &Option<String>, name: &str, allowed: &[&str]) -> Result<Option<String>, String> {
    match value.as_deref().map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(None),
        Some(v) if allowed.contains(&v) => Ok(Some(v.to_string())),
        Some(v) => Err(format!("invalid: `{name}` must be one of {}, got `{v}`", allowed.join(", "))),
    }
}

/// A read of one repository: the action and the repository, nothing else.
fn reading<'a>(input: &'a Input, operation: &str) -> Result<(Policy, &'a str), String> {
    let rules = policy::require()?;
    rules.check_action(operation)?;
    let repo = repo(input)?;
    rules.check_repo(repo)?;
    Ok((rules, repo))
}

// ==================== what an agent gets back ====================

pub(crate) fn s(value: &Value, key: &str) -> Value {
    value.get(key).cloned().unwrap_or(Value::Null)
}

fn login(value: &Value, key: &str) -> Value {
    value.get(key).and_then(|u| u.get("login")).cloned().unwrap_or(Value::Null)
}

fn names(value: &Value, key: &str, field: &str) -> Value {
    Value::Array(
        value
            .get(key)
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(|i| i.get(field).cloned()).collect())
            .unwrap_or_default(),
    )
}

fn repo_view(r: &Value) -> Value {
    json!({
        "repo": s(r, "full_name"), "private": s(r, "private"), "description": s(r, "description"),
        "default_branch": s(r, "default_branch"), "archived": s(r, "archived"), "fork": s(r, "fork"),
        "language": s(r, "language"), "stars": s(r, "stargazers_count"), "open_issues": s(r, "open_issues_count"),
        "can_push": r.get("permissions").and_then(|p| p.get("push")).cloned().unwrap_or(Value::Null),
        "url": s(r, "html_url"), "pushed_at": s(r, "pushed_at"),
    })
}

fn issue_view(i: &Value) -> Value {
    json!({
        "number": s(i, "number"), "title": s(i, "title"), "state": s(i, "state"), "author": login(i, "user"),
        "labels": names(i, "labels", "name"), "assignees": names(i, "assignees", "login"),
        "comments": s(i, "comments"), "is_pull_request": i.get("pull_request").is_some(),
        "created_at": s(i, "created_at"), "updated_at": s(i, "updated_at"), "url": s(i, "html_url"),
        "body": s(i, "body"),
    })
}

fn comment_view(c: &Value) -> Value {
    json!({"id": s(c, "id"), "author": login(c, "user"), "created_at": s(c, "created_at"), "url": s(c, "html_url"), "body": s(c, "body")})
}

fn side(pr: &Value, key: &str) -> Value {
    let side = pr.get(key).cloned().unwrap_or(Value::Null);
    json!({"branch": s(&side, "ref"), "sha": s(&side, "sha"), "repo": side.get("repo").map(|r| s(r, "full_name")).unwrap_or(Value::Null)})
}

fn pr_view(pr: &Value) -> Value {
    json!({
        "number": s(pr, "number"), "title": s(pr, "title"), "state": s(pr, "state"), "draft": s(pr, "draft"),
        "merged": s(pr, "merged"), "mergeable": s(pr, "mergeable"), "mergeable_state": s(pr, "mergeable_state"),
        "author": login(pr, "user"), "head": side(pr, "head"), "base": side(pr, "base"),
        "commits": s(pr, "commits"), "changed_files": s(pr, "changed_files"),
        "additions": s(pr, "additions"), "deletions": s(pr, "deletions"),
        "created_at": s(pr, "created_at"), "updated_at": s(pr, "updated_at"), "url": s(pr, "html_url"),
        "body": s(pr, "body"),
    })
}

fn gist_view(g: &Value, with_content: bool) -> Value {
    let files: Vec<Value> = g
        .get("files")
        .and_then(Value::as_object)
        .map(|files| {
            files
                .values()
                .map(|f| {
                    let mut view = json!({"name": s(f, "filename"), "size": s(f, "size"), "language": s(f, "language")});
                    if with_content {
                        view["truncated"] = s(f, "truncated");
                        view["content"] = s(f, "content");
                    }
                    view
                })
                .collect()
        })
        .unwrap_or_default();
    json!({
        "gist_id": s(g, "id"), "description": s(g, "description"), "public": s(g, "public"),
        "owner": login(g, "owner"), "url": s(g, "html_url"), "updated_at": s(g, "updated_at"), "files": files,
    })
}

// ==================== repositories ====================

pub fn repo_list(input: &Input) -> Result<Value, String> {
    let rules = policy::require()?;
    rules.check_action("repo_list")?;
    let all = gh::get(&format!("/user/repos{}", query(&[&paging(input)[..], &[("sort", Some("pushed".into()))]].concat())))?;
    let all = all.as_array().cloned().unwrap_or_default();
    // What the policy does not cover is not listed: a name is information too.
    let shown: Vec<Value> = all
        .iter()
        .filter(|r| r.get("full_name").and_then(Value::as_str).map(|n| rules.allows_repo(n)).unwrap_or(false))
        .map(repo_view)
        .collect();
    Ok(json!({"repositories": shown, "page": input.page.unwrap_or(1).max(1), "on_this_page_before_policy": all.len()}))
}

pub fn repo_get(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "repo_get")?;
    Ok(repo_view(&gh::get(&format!("/repos/{repo}"))?))
}

pub fn repo_star(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::RepoStar)
}

pub fn repo_unstar(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::RepoUnstar)
}

// ==================== files and branches ====================

fn at_ref(input: &Input) -> Result<Option<String>, String> {
    match input.git_ref.as_deref().map(str::trim).filter(|r| !r.is_empty()) {
        None => Ok(None),
        Some(r) if r.len() <= 200 && !r.chars().any(|c| c.is_control() || c == ' ') => Ok(Some(r.to_string())),
        Some(r) => Err(format!("invalid: `ref` is a branch, a tag or a commit sha, got `{r}`")),
    }
}

pub fn dir_list(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "dir_list")?;
    let path = input.path.as_deref().map(str::trim).unwrap_or("").trim_matches('/');
    if !path.is_empty() {
        read_path(path)?;
    }
    let listing = gh::get(&format!("/repos/{repo}/contents/{}{}", file_path(path), query(&[("ref", at_ref(input)?)])))?;
    let Some(entries) = listing.as_array() else {
        return Err(format!("invalid: `{path}` is a file; read it with `file_get`"));
    };
    let entries: Vec<Value> = entries
        .iter()
        .map(|e| json!({"name": s(e, "name"), "path": s(e, "path"), "type": s(e, "type"), "size": s(e, "size"), "sha": s(e, "sha")}))
        .collect();
    Ok(json!({"repo": repo, "path": path, "entries": entries}))
}

/// A path to READ. Reading `.github/` is fine; climbing out of the repository is not.
fn read_path(path: &str) -> Result<(), String> {
    if path.contains("..") || path.contains('\\') || path.chars().any(|c| c.is_control()) {
        return Err(format!("invalid: the path `{path}` must be a plain relative path"));
    }
    Ok(())
}

pub fn file_get(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "file_get")?;
    let path = need(&input.path, "path")?.trim_matches('/');
    read_path(path)?;
    let file = gh::get(&format!("/repos/{repo}/contents/{}{}", file_path(path), query(&[("ref", at_ref(input)?)])))?;
    if file.is_array() {
        return Err(format!("invalid: `{path}` is a directory; list it with `dir_list`"));
    }
    let size = file.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
    if size > MAX_FILE_BYTES {
        return Err(format!("too_large: `{path}` is {size} bytes; `file_get` returns files up to {MAX_FILE_BYTES}"));
    }
    let encoded: String = file.get("content").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = BASE64.decode(encoded.as_bytes()).map_err(|e| format!("github_refused: the file's content is not base64: {e}"))?;
    let mut answer = json!({"repo": repo, "path": s(&file, "path"), "sha": s(&file, "sha"), "size": size, "url": s(&file, "html_url")});
    match String::from_utf8(bytes) {
        Ok(text) => {
            answer["encoding"] = json!("utf-8");
            answer["content"] = json!(text);
        }
        Err(not_text) => {
            answer["encoding"] = json!("base64");
            answer["content"] = json!(BASE64.encode(not_text.into_bytes()));
        }
    }
    Ok(answer)
}

pub fn branch_list(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "branch_list")?;
    let branches = gh::get(&format!("/repos/{repo}/branches{}", query(&paging(input))))?;
    let branches: Vec<Value> = branches
        .as_array()
        .map(|b| b.iter().map(|b| json!({"branch": s(b, "name"), "sha": b.get("commit").map(|c| s(c, "sha")).unwrap_or(Value::Null), "protected": s(b, "protected")})).collect())
        .unwrap_or_default();
    Ok(json!({"repo": repo, "branches": branches}))
}

pub fn branch_create(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::BranchCreate)
}

pub fn file_put(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::FilePut)
}

/// Several files in one commit, through the Git Data API.
pub fn commit(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::Commit)
}

// ==================== issues ====================

pub fn issue_list(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "issue_list")?;
    let state = one_of(&input.state, "state", &["open", "closed", "all"])?;
    let labels = input.labels.as_ref().filter(|l| !l.is_empty()).map(|l| l.join(","));
    let issues = gh::get(&format!("/repos/{repo}/issues{}", query(&[&paging(input)[..], &[("state", state), ("labels", labels)]].concat())))?;
    // Bodies are left out of a list: thirty of them is most of the answer, and
    // the one the agent wants is one `issue_get` away.
    let issues: Vec<Value> = issues
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|i| {
                    let mut view = issue_view(i);
                    if let Some(fields) = view.as_object_mut() {
                        fields.remove("body");
                    }
                    view
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({"repo": repo, "issues": issues, "page": input.page.unwrap_or(1).max(1)}))
}

/// One issue or pull request conversation, with a page of its comments.
pub fn issue_get(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "issue_get")?;
    let n = number(input)?;
    let issue = gh::get(&format!("/repos/{repo}/issues/{n}"))?;
    let comments = gh::get(&format!("/repos/{repo}/issues/{n}/comments{}", query(&paging(input))))?;
    let comments: Vec<Value> = comments.as_array().map(|c| c.iter().map(comment_view).collect()).unwrap_or_default();
    Ok(json!({"repo": repo, "issue": issue_view(&issue), "comments": comments, "comments_page": input.page.unwrap_or(1).max(1)}))
}

pub fn issue_create(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::IssueCreate)
}

/// A comment on an issue — or on a pull request's conversation, which GitHub
/// keeps in the same place under the same number.
pub fn issue_comment(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::IssueComment)
}

pub fn issue_update(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::IssueUpdate)
}

// ==================== pull requests ====================

pub fn pr_list(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "pr_list")?;
    let state = one_of(&input.state, "state", &["open", "closed", "all"])?;
    let prs = gh::get(&format!("/repos/{repo}/pulls{}", query(&[&paging(input)[..], &[("state", state)]].concat())))?;
    let prs: Vec<Value> = prs
        .as_array()
        .map(|items| items.iter().map(|p| json!({
            "number": s(p, "number"), "title": s(p, "title"), "state": s(p, "state"), "draft": s(p, "draft"),
            "author": login(p, "user"), "head": side(p, "head"), "base": side(p, "base"),
            "updated_at": s(p, "updated_at"), "url": s(p, "html_url"),
        })).collect())
        .unwrap_or_default();
    Ok(json!({"repo": repo, "pull_requests": prs, "page": input.page.unwrap_or(1).max(1)}))
}

pub fn pr_get(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "pr_get")?;
    Ok(json!({"repo": repo, "pull_request": pr_view(&gh::get(&format!("/repos/{repo}/pulls/{}", number(input)?))?)}))
}

fn cut(text: &str, at: usize) -> (&str, bool) {
    if text.len() <= at {
        return (text, false);
    }
    let mut end = at;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// What a review reads: each changed file with its patch. A patch is cut at a
/// size, and said to be — the whole file is one `file_get` at the head's sha.
pub fn pr_files(input: &Input) -> Result<Value, String> {
    let (_, repo) = reading(input, "pr_files")?;
    let n = number(input)?;
    let files = gh::get(&format!("/repos/{repo}/pulls/{n}/files{}", query(&paging(input))))?;
    let mut budget = MAX_PATCHES_TOTAL;
    let files: Vec<Value> = files
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|f| {
                    let patch = f.get("patch").and_then(Value::as_str).unwrap_or("");
                    let (shown, was_cut) = cut(patch, MAX_PATCH_BYTES.min(budget));
                    budget -= shown.len();
                    json!({
                        "path": s(f, "filename"), "status": s(f, "status"), "previous_path": s(f, "previous_filename"),
                        "additions": s(f, "additions"), "deletions": s(f, "deletions"),
                        "patch": shown, "patch_cut": was_cut, "binary_or_too_large": f.get("patch").is_none(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({"repo": repo, "number": n, "files": files, "page": input.page.unwrap_or(1).max(1)}))
}

pub fn pr_create(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::PrCreate)
}

/// A review: a verdict, a summary, and comments on lines of the diff.
pub fn pr_review(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::PrReview)
}

pub fn pr_merge(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::PrMerge)
}

// ==================== gists ====================

pub fn gist_list(input: &Input) -> Result<Value, String> {
    let rules = policy::require()?;
    rules.check_action("gist_list")?;
    let gists = gh::get(&format!("/gists{}", query(&paging(input))))?;
    let gists: Vec<Value> = gists.as_array().map(|g| g.iter().map(|g| gist_view(g, false)).collect()).unwrap_or_default();
    Ok(json!({"gists": gists, "page": input.page.unwrap_or(1).max(1)}))
}

pub(crate) fn gist_id(input: &Input) -> Result<&str, String> {
    let id = need(&input.gist_id, "gist_id")?;
    if id.len() > 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("invalid: `gist_id` is the hexadecimal id from a gist's URL, got `{id}`"));
    }
    Ok(id)
}

pub fn gist_get(input: &Input) -> Result<Value, String> {
    let rules = policy::require()?;
    rules.check_action("gist_get")?;
    Ok(gist_view(&gh::get(&format!("/gists/{}", gist_id(input)?))?, true))
}

pub fn gist_create(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::GistCreate)
}

/// Changes a gist's files or description.
pub fn gist_update(input: &Input) -> Result<Value, String> {
    write(input, Confirmable::GistUpdate)
}

// ==================== every write ====================

/// A write: read and checked, then carried out for the caller — or, when the
/// owner's policy lists the operation under `confirm`, left as a task for the
/// owner, and answered `awaiting_owner`.
fn write(input: &Input, operation: Confirmable) -> Result<Value, String> {
    let rules = policy::require()?;
    let for_owner = rules.confirms(operation);
    // Everything is checked before anything is written or shown to the owner.
    let action = Action::prepare(operation, input, &rules, for_owner)?;
    if for_owner {
        return confirm::ask(&action);
    }
    action.execute(&rules, Counted::Own)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_patch_is_cut_on_a_character_and_says_so() {
        let (shown, was_cut) = cut("héllo wörld", 2);
        assert_eq!((shown, was_cut), ("h", true), "never in the middle of a character");
        assert_eq!(cut("short", 100), ("short", false));
    }

    /// What goes back is what an agent uses — not GitHub's fifteen kilobytes.
    #[test]
    fn an_answer_is_cut_down_to_what_is_read() {
        let pr: Value = serde_json::from_str(r#"{"number":7,"title":"t","state":"open","user":{"login":"alice","avatar_url":"x"},
            "head":{"ref":"agent/x","sha":"abc","repo":{"full_name":"a/b","owner":{"login":"a"}}},
            "base":{"ref":"main","sha":"def","repo":{"full_name":"a/b"}},"_links":{"self":{"href":"x"}},"statuses_url":"x"}"#).unwrap();
        let view = pr_view(&pr);
        assert_eq!(view["head"], json!({"branch":"agent/x","sha":"abc","repo":"a/b"}));
        assert_eq!(view["author"], "alice");
        assert!(view.get("_links").is_none() && view.get("statuses_url").is_none());
    }
}
