//! The operations: what an agent asks for, what the policy is asked first, the
//! call to GitHub, and the part of GitHub's answer an agent can use.
//!
//! Every operation on a repository checks the action and the repository before
//! anything else. Every write then takes a place in the owner's daily budget
//! BEFORE GitHub is called and keeps it only when GitHub accepted — a refused
//! write costs the owner nothing.
//!
//! Answers are cut down on purpose. GitHub describes one pull request in fifteen
//! kilobytes, most of it URLs of other endpoints; what is returned here is what
//! an agent reads or passes to the next call.

use crate::github::{self as gh, file_path, query, segment};
use crate::policy::{self, Policy};
use crate::Input;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{json, Value};

/// The largest file `file_get` returns, decoded.
const MAX_FILE_BYTES: usize = 256 * 1024;
/// The most of one file's patch `pr_files` returns, and of all of them together.
const MAX_PATCH_BYTES: usize = 8 * 1024;
const MAX_PATCHES_TOTAL: usize = 120 * 1024;
/// The longest text taken from an agent for a body, a comment or a description.
const MAX_TEXT_BYTES: usize = 60 * 1024;

// ==================== input helpers ====================

fn need<'a>(value: &'a Option<String>, name: &str) -> Result<&'a str, String> {
    match value.as_deref().map(str::trim) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("invalid: `{name}` is required")),
    }
}

fn repo(input: &Input) -> Result<&str, String> {
    let repo = need(&input.repo, "repo")?;
    policy::clean_repo(repo)?;
    Ok(repo)
}

fn number(input: &Input) -> Result<u64, String> {
    input.number.filter(|n| *n > 0).ok_or_else(|| "invalid: `number` is required".to_string())
}

fn text(value: &Option<String>, name: &str) -> Result<String, String> {
    let text = value.clone().unwrap_or_default();
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!("invalid: `{name}` is {} bytes; the most taken is {MAX_TEXT_BYTES}", text.len()));
    }
    Ok(text)
}

fn paging(input: &Input) -> [(&'static str, Option<String>); 2] {
    [
        ("per_page", Some(input.per_page.unwrap_or(30).clamp(1, 50).to_string())),
        ("page", Some(input.page.unwrap_or(1).max(1).to_string())),
    ]
}

fn one_of(value: &Option<String>, name: &str, allowed: &[&str]) -> Result<Option<String>, String> {
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

fn s(value: &Value, key: &str) -> Value {
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

fn star(input: &Input, operation: &str, on: bool) -> Result<Value, String> {
    let (rules, repo) = reading(input, operation)?;
    let (place, used) = rules.reserve_write()?;
    let path = format!("/user/starred/{repo}");
    if on { gh::put(&path, None)? } else { gh::delete(&path)? };
    place.keep();
    Ok(json!({"repo": repo, "starred": on, "writes_today": used}))
}

pub fn repo_star(input: &Input) -> Result<Value, String> {
    star(input, "repo_star", true)
}

pub fn repo_unstar(input: &Input) -> Result<Value, String> {
    star(input, "repo_unstar", false)
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

fn default_branch(repo: &str) -> Result<String, String> {
    gh::get(&format!("/repos/{repo}"))?
        .get("default_branch")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "github_refused: the repository did not name its default branch".to_string())
}

/// A branch the agent may write to. One more request only when the policy
/// reached it through a pattern — then the default branch has to be ruled out.
fn writable_branch(rules: &Policy, repo: &str, branch: &str) -> Result<(), String> {
    policy::clean_branch(branch)?;
    let matched = rules.check_branch(branch)?;
    if matched == policy::BranchMatch::Pattern {
        Policy::check_not_default(matched, branch, &default_branch(repo)?)?;
    }
    Ok(())
}

pub fn branch_create(input: &Input) -> Result<Value, String> {
    let (rules, repo) = reading(input, "branch_create")?;
    let branch = need(&input.branch, "branch")?;
    writable_branch(&rules, repo, branch)?;
    let from = match input.from.as_deref().map(str::trim).filter(|f| !f.is_empty()) {
        Some(from) => {
            policy::clean_branch(from)?;
            from.to_string()
        }
        None => default_branch(repo)?,
    };
    let (place, used) = rules.reserve_write()?;
    let sha = gh::get(&format!("/repos/{repo}/git/ref/heads/{from}"))?
        .get("object")
        .and_then(|o| o.get("sha"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("not_found: the branch `{from}` has no commit to start from"))?;
    gh::post(&format!("/repos/{repo}/git/refs"), &json!({"ref": format!("refs/heads/{branch}"), "sha": sha}))?;
    place.keep();
    Ok(json!({"repo": repo, "branch": branch, "from": from, "sha": sha, "writes_today": used}))
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

pub fn file_put(input: &Input) -> Result<Value, String> {
    let (rules, repo) = reading(input, "file_put")?;
    let branch = need(&input.branch, "branch")?;
    let path = need(&input.path, "path")?;
    let message = need(&input.message, "message")?;
    rules.check_path(path)?;
    writable_branch(&rules, repo, branch)?;
    let bytes = content_bytes(&input.content, &input.encoding, "`file_put`")?;
    if bytes.len() > MAX_FILE_BYTES * 4 {
        return Err(format!("too_large: the file is {} bytes; the most written is {}", bytes.len(), MAX_FILE_BYTES * 4));
    }
    let mut body = json!({"message": message, "content": BASE64.encode(&bytes), "branch": branch});
    // Present for an update, absent for a new file: GitHub refuses an update
    // without it, which is what stops one write landing on top of another.
    if let Some(sha) = input.sha.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        body["sha"] = json!(sha);
    }
    let (place, used) = rules.reserve_write()?;
    let answer = gh::put(&format!("/repos/{repo}/contents/{}", file_path(path)), Some(&body)).map_err(|e| {
        if e.starts_with("invalid:") && e.contains("sha") {
            format!("{e}. The file exists: read it with `file_get` and pass its `sha` to replace it")
        } else {
            e
        }
    })?;
    place.keep();
    Ok(json!({
        "repo": repo, "branch": branch, "path": path, "created": answer.status == 201,
        "sha": answer.body.get("content").map(|c| s(c, "sha")).unwrap_or(Value::Null),
        "commit": answer.body.get("commit").map(|c| s(c, "sha")).unwrap_or(Value::Null),
        "url": answer.body.get("content").map(|c| s(c, "html_url")).unwrap_or(Value::Null),
        "writes_today": used,
    }))
}

/// Several files in one commit, through the Git Data API: the tree is built on
/// the branch's own tree, the commit on its head, and the branch is moved
/// without force — a branch that moved meanwhile answers `conflict`.
pub fn commit(input: &Input) -> Result<Value, String> {
    let (rules, repo) = reading(input, "commit")?;
    let branch = need(&input.branch, "branch")?;
    let message = need(&input.message, "message")?;
    if input.files.is_empty() {
        return Err("invalid: `files` is required: [{\"path\", \"content\"}] or [{\"path\", \"delete\": true}]".to_string());
    }
    if input.files.len() > policy::MAX_FILES_PER_COMMIT {
        return Err(format!(
            "too_large: {} files in one commit; a run has time for {}. Split it into several commits",
            input.files.len(),
            policy::MAX_FILES_PER_COMMIT
        ));
    }
    for file in &input.files {
        rules.check_path(&file.path)?;
    }
    writable_branch(&rules, repo, branch)?;

    let (place, used) = rules.reserve_write()?;
    let head = gh::get(&format!("/repos/{repo}/git/ref/heads/{branch}"))?
        .get("object").and_then(|o| o.get("sha")).and_then(Value::as_str).map(str::to_string)
        .ok_or_else(|| format!("not_found: the branch `{branch}` does not exist; create it with `branch_create`"))?;
    let base_tree = gh::get(&format!("/repos/{repo}/git/commits/{head}"))?
        .get("tree").and_then(|t| t.get("sha")).and_then(Value::as_str).map(str::to_string)
        .ok_or_else(|| "github_refused: the branch's head has no tree".to_string())?;

    let mut tree = Vec::with_capacity(input.files.len());
    for file in &input.files {
        if file.delete {
            tree.push(json!({"path": file.path, "mode": "100644", "type": "blob", "sha": Value::Null}));
            continue;
        }
        let bytes = content_bytes(&file.content, &file.encoding, &format!("`{}`", file.path))?;
        match String::from_utf8(bytes) {
            // Text rides in the tree itself: no request of its own.
            Ok(text) => tree.push(json!({"path": file.path, "mode": "100644", "type": "blob", "content": text})),
            Err(binary) => {
                let blob = gh::post(&format!("/repos/{repo}/git/blobs"), &json!({"content": BASE64.encode(binary.into_bytes()), "encoding": "base64"}))?;
                tree.push(json!({"path": file.path, "mode": "100644", "type": "blob", "sha": s(&blob, "sha")}));
            }
        }
    }
    let new_tree = gh::post(&format!("/repos/{repo}/git/trees"), &json!({"base_tree": base_tree, "tree": tree}))?;
    let new_commit = gh::post(&format!("/repos/{repo}/git/commits"), &json!({"message": message, "tree": s(&new_tree, "sha"), "parents": [head]}))?;
    let sha = s(&new_commit, "sha");
    // Never forced. A branch that moved since `head` was read refuses this, and
    // the agent reads again rather than overwriting somebody's push.
    gh::patch(&format!("/repos/{repo}/git/refs/heads/{branch}"), &json!({"sha": sha, "force": false}))?;
    place.keep();
    Ok(json!({"repo": repo, "branch": branch, "commit": sha, "parent": head, "files": input.files.len(), "url": s(&new_commit, "html_url"), "writes_today": used}))
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
    let (rules, repo) = reading(input, "issue_create")?;
    let title = need(&input.title, "title")?;
    let mut body = json!({"title": title, "body": rules.mark(&text(&input.body, "body")?)});
    if let Some(labels) = &input.labels { body["labels"] = json!(labels); }
    if let Some(assignees) = &input.assignees { body["assignees"] = json!(assignees); }
    let (place, used) = rules.reserve_write()?;
    let issue = gh::post(&format!("/repos/{repo}/issues"), &body)?;
    place.keep();
    Ok(json!({"repo": repo, "number": s(&issue, "number"), "url": s(&issue, "html_url"), "writes_today": used}))
}

/// A comment on an issue — or on a pull request's conversation, which GitHub
/// keeps in the same place under the same number.
pub fn issue_comment(input: &Input) -> Result<Value, String> {
    let (rules, repo) = reading(input, "issue_comment")?;
    let n = number(input)?;
    let said = text(&input.body, "body")?;
    if said.trim().is_empty() {
        return Err("invalid: `body` is required".to_string());
    }
    let (place, used) = rules.reserve_write()?;
    let comment = gh::post(&format!("/repos/{repo}/issues/{n}/comments"), &json!({"body": rules.mark(&said)}))?;
    place.keep();
    Ok(json!({"repo": repo, "number": n, "comment_id": s(&comment, "id"), "url": s(&comment, "html_url"), "writes_today": used}))
}

pub fn issue_update(input: &Input) -> Result<Value, String> {
    let (rules, repo) = reading(input, "issue_update")?;
    let n = number(input)?;
    let mut body = json!({});
    if let Some(state) = one_of(&input.state, "state", &["open", "closed"])? { body["state"] = json!(state); }
    if let Some(title) = input.title.as_deref().map(str::trim).filter(|t| !t.is_empty()) { body["title"] = json!(title); }
    if input.body.is_some() { body["body"] = json!(rules.mark(&text(&input.body, "body")?)); }
    if let Some(labels) = &input.labels { body["labels"] = json!(labels); }
    if let Some(assignees) = &input.assignees { body["assignees"] = json!(assignees); }
    if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return Err("invalid: nothing to change — give `state`, `title`, `body`, `labels` or `assignees`".to_string());
    }
    let (place, used) = rules.reserve_write()?;
    let issue = gh::patch(&format!("/repos/{repo}/issues/{n}"), &body)?;
    place.keep();
    Ok(json!({"repo": repo, "number": n, "state": s(&issue, "state"), "url": s(&issue, "html_url"), "writes_today": used}))
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
    let (rules, repo) = reading(input, "pr_create")?;
    let title = need(&input.title, "title")?;
    let head = need(&input.head, "head")?;
    let base = need(&input.base, "base")?;
    // The agent opens pull requests FROM branches it may write; where they point
    // is the owner's review to make.
    writable_branch(&rules, repo, head)?;
    policy::clean_branch(base)?;
    let body = json!({"title": title, "head": head, "base": base, "body": rules.mark(&text(&input.body, "body")?), "draft": input.draft.unwrap_or(false)});
    let (place, used) = rules.reserve_write()?;
    let pr = gh::post(&format!("/repos/{repo}/pulls"), &body)?;
    place.keep();
    Ok(json!({"repo": repo, "number": s(&pr, "number"), "url": s(&pr, "html_url"), "writes_today": used}))
}

/// A review: a verdict, a summary, and comments on lines of the diff.
pub fn pr_review(input: &Input) -> Result<Value, String> {
    let (rules, repo) = reading(input, "pr_review")?;
    let n = number(input)?;
    let event = one_of(&input.event, "event", &["COMMENT", "REQUEST_CHANGES", "APPROVE"])?.unwrap_or_else(|| "COMMENT".to_string());
    if event == "APPROVE" {
        rules.check_approve()?;
    }
    let summary = text(&input.body, "body")?;
    if summary.trim().is_empty() && input.comments.is_empty() {
        return Err("invalid: a review needs a `body`, `comments`, or both".to_string());
    }
    if input.comments.len() > 50 {
        return Err(format!("invalid: {} comments in one review; the most taken is 50", input.comments.len()));
    }
    let mut comments = Vec::with_capacity(input.comments.len());
    for c in &input.comments {
        if c.path.trim().is_empty() || c.line == 0 || c.body.trim().is_empty() {
            return Err("invalid: each review comment needs `path`, `line` and `body`".to_string());
        }
        let side = one_of(&c.side, "side", &["LEFT", "RIGHT"])?.unwrap_or_else(|| "RIGHT".to_string());
        comments.push(json!({"path": c.path, "line": c.line, "side": side, "body": c.body}));
    }
    // The marker goes on the summary, once per review, not on every line comment.
    let body = json!({"event": event, "body": rules.mark(&summary), "comments": comments});
    let (place, used) = rules.reserve_write()?;
    let review = gh::post(&format!("/repos/{repo}/pulls/{n}/reviews"), &body)?;
    place.keep();
    Ok(json!({"repo": repo, "number": n, "review_id": s(&review, "id"), "state": s(&review, "state"), "url": s(&review, "html_url"), "writes_today": used}))
}

pub fn pr_merge(input: &Input) -> Result<Value, String> {
    let (rules, repo) = reading(input, "pr_merge")?;
    rules.check_merge()?;
    let n = number(input)?;
    let method = one_of(&input.merge_method, "merge_method", &["merge", "squash", "rebase"])?.unwrap_or_else(|| "squash".to_string());
    let mut body = json!({"merge_method": method});
    // Merges only the head the agent looked at, when it says which.
    if let Some(sha) = input.sha.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        body["sha"] = json!(sha);
    }
    let (place, used) = rules.reserve_write()?;
    let answer = gh::put(&format!("/repos/{repo}/pulls/{n}/merge"), Some(&body))?;
    place.keep();
    Ok(json!({"repo": repo, "number": n, "merged": s(&answer.body, "merged"), "commit": s(&answer.body, "sha"), "writes_today": used}))
}

// ==================== gists ====================

pub fn gist_list(input: &Input) -> Result<Value, String> {
    let rules = policy::require()?;
    rules.check_action("gist_list")?;
    let gists = gh::get(&format!("/gists{}", query(&paging(input))))?;
    let gists: Vec<Value> = gists.as_array().map(|g| g.iter().map(|g| gist_view(g, false)).collect()).unwrap_or_default();
    Ok(json!({"gists": gists, "page": input.page.unwrap_or(1).max(1)}))
}

fn gist_id(input: &Input) -> Result<&str, String> {
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

/// `files` as GitHub's gist API takes them: a name to its content, or to `null`
/// to remove it.
fn gist_files(input: &Input, removing_allowed: bool) -> Result<Value, String> {
    if input.files.is_empty() {
        return Err("invalid: `files` is required: [{\"path\": \"notes.md\", \"content\": \"…\"}]".to_string());
    }
    let mut files = serde_json::Map::new();
    for file in &input.files {
        let name = file.path.trim();
        if name.is_empty() || name.contains('/') || name.len() > 255 {
            return Err(format!("invalid: a gist file's `path` is a plain file name, got `{}`", file.path));
        }
        if file.delete {
            if !removing_allowed {
                return Err("invalid: a new gist has no file to delete".to_string());
            }
            files.insert(name.to_string(), Value::Null);
            continue;
        }
        let bytes = content_bytes(&file.content, &file.encoding, &format!("`{name}`"))?;
        let content = String::from_utf8(bytes).map_err(|_| format!("invalid: `{name}` is not text; a gist holds text"))?;
        if content.trim().is_empty() {
            return Err(format!("invalid: `{name}` is empty; GitHub does not keep an empty gist file"));
        }
        files.insert(name.to_string(), json!({"content": content}));
    }
    Ok(Value::Object(files))
}

pub fn gist_create(input: &Input) -> Result<Value, String> {
    let rules = policy::require()?;
    rules.check_action("gist_create")?;
    let public = input.public.unwrap_or(false);
    rules.check_public_gist(public)?;
    let body = json!({"description": text(&input.description, "description")?, "public": public, "files": gist_files(input, false)?});
    let (place, used) = rules.reserve_write()?;
    let gist = gh::post("/gists", &body)?;
    place.keep();
    Ok(json!({"gist_id": s(&gist, "id"), "public": s(&gist, "public"), "url": s(&gist, "html_url"), "writes_today": used}))
}

/// Changes a gist's files or description. It cannot make a secret gist public:
/// GitHub's API has no such switch, and this does not pretend to have one.
pub fn gist_update(input: &Input) -> Result<Value, String> {
    let rules = policy::require()?;
    rules.check_action("gist_update")?;
    let id = gist_id(input)?;
    let mut body = json!({});
    if !input.files.is_empty() { body["files"] = gist_files(input, true)?; }
    if input.description.is_some() { body["description"] = json!(text(&input.description, "description")?); }
    if body.as_object().map(|o| o.is_empty()).unwrap_or(true) {
        return Err("invalid: nothing to change — give `files`, `description` or both".to_string());
    }
    let (place, used) = rules.reserve_write()?;
    let gist = gh::patch(&format!("/gists/{}", segment(id)), &body)?;
    place.keep();
    Ok(json!({"gist_id": s(&gist, "id"), "public": s(&gist, "public"), "url": s(&gist, "html_url"), "writes_today": used}))
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

    #[test]
    fn a_gist_file_is_a_name_and_text() {
        let input = |json: &str| serde_json::from_str::<Input>(json).unwrap();
        assert!(gist_files(&input(r#"{"files":[{"path":"a.md","content":"x"}]}"#), false).is_ok());
        assert!(gist_files(&input(r#"{"files":[{"path":"dir/a.md","content":"x"}]}"#), false).is_err());
        assert!(gist_files(&input(r#"{"files":[{"path":"a.md","content":"  "}]}"#), false).is_err());
        assert!(gist_files(&input(r#"{"files":[{"path":"a.md","delete":true}]}"#), false).is_err());
        assert_eq!(gist_files(&input(r#"{"files":[{"path":"a.md","delete":true}]}"#), true).unwrap()["a.md"], Value::Null);
    }
}
