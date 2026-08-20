//! The 10 built-in tools for the AI research agent. All read-only except the
//! two interactive ones (ask_user, todo) — that is the safety posture.

use std::time::Instant;

use serde::Serialize;
use serde_json::{json, Value};

use super::tool::{
    arg_bool_default, arg_str, arg_str_default, arg_str_opt, arg_u64_default, display_rel,
    project_root, resolve_collection_root, resolve_in_project, wait_for_pending_response,
    PendingWaitError, Tool,
};
use rayon::prelude::*;
use tauri::Manager;
use crate::ai::AiStreamEvent;
use crate::fs_utils;
use crate::models::Vulnerability;

#[cfg(test)]
fn collect_agent_files(
    project_root: &std::path::Path,
    root: &std::path::Path,
    settings: &crate::models::ScanSettings,
) -> (Vec<std::path::PathBuf>, usize, u64) {
    fs_utils::collect_files(
        root,
        fs_utils::CollectFilesOptions {
            project_root,
            include_git: settings.include_git,
            follow_symlinks: settings.follow_symlinks,
            extra_ignored: &settings.ignored_dirs,
        },
    )
}

fn collect_agent_source_files(
    project_root: &std::path::Path,
    root: &std::path::Path,
    settings: &crate::models::ScanSettings,
) -> fs_utils::SourceFileCollection {
    fs_utils::collect_source_files(
        root,
        fs_utils::CollectFilesOptions {
            project_root,
            include_git: settings.include_git,
            follow_symlinks: settings.follow_symlinks,
            extra_ignored: &settings.ignored_dirs,
        },
    )
}

fn source_identity(path: &std::path::Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn collect_agent_lockfiles(
    project_root: &std::path::Path,
    root: &std::path::Path,
    settings: &crate::models::ScanSettings,
) -> Vec<std::path::PathBuf> {
    fs_utils::discover_lockfiles(project_root, root, &settings.ignored_dirs)
}

fn grep_project_files(
    project_root: &std::path::Path,
    root: &std::path::Path,
    settings: &crate::models::ScanSettings,
    pattern: &str,
    mode: &str,
    context: usize,
    head_limit: usize,
) -> Result<Value, String> {
    let re = regex::Regex::new(pattern).map_err(|e| format!("invalid regex: {e}"))?;
    let collection = collect_agent_source_files(project_root, root, settings);
    let mut hits: Vec<Value> = Vec::new();
    let mut counts: Vec<Value> = Vec::new();
    let mut files_with: Vec<String> = Vec::new();
    let mut total = 0usize;
    for file in &collection.files {
        if total >= head_limit {
            break;
        }
        let Some(content) = fs_utils::read_text_file(&file.canonical_path, 1024 * 1024) else {
            continue;
        };
        let identity = source_identity(&file.collection_relative_path);
        let lines: Vec<&str> = content.lines().collect();
        let mut file_count = 0usize;
        for found in re.find_iter(&content) {
            if total >= head_limit {
                break;
            }
            total += 1;
            file_count += 1;
            let line_no = content[..found.start()].matches('\n').count() + 1;
            let line_index = line_no - 1;
            if mode == "content" {
                let low = line_index.saturating_sub(context);
                let high = (line_index + 1 + context).min(lines.len());
                let context_lines: Vec<Value> = (low..high)
                    .map(|index| Value::String(format!("{:>6} │ {}", index + 1, lines[index])))
                    .collect();
                hits.push(json!({
                    "file": identity,
                    "line": line_no,
                    "column": found.start()
                        - content[..found.start()].rfind('\n').map(|position| position + 1).unwrap_or(0)
                        + 1,
                    "text": lines[line_index],
                    "context": if context > 0 { Value::Array(context_lines) } else { Value::Null },
                }));
            }
        }
        if mode == "count" {
            if file_count > 0 {
                counts.push(json!({ "file": identity, "matches": file_count }));
            }
        } else if file_count > 0 && mode == "files_with_matches" {
            files_with.push(identity);
        }
    }
    if total >= head_limit {
        hits.push(json!({ "note": "hit head_limit — results truncated" }));
    }
    Ok(json!({
        "total_matches": total,
        "mode": mode,
        "files_with_matches": files_with,
        "counts": counts,
        "matches": hits,
    }))
}

fn glob_project_files(
    project_root: &std::path::Path,
    root: &std::path::Path,
    settings: &crate::models::ScanSettings,
    pattern: &str,
    max_results: usize,
) -> Result<Value, String> {
    let mut builder = ignore::gitignore::GitignoreBuilder::new(root);
    builder
        .add_line(None, pattern)
        .map_err(|e| format!("invalid glob: {e}"))?;
    let matcher = builder.build().map_err(|e| format!("invalid glob: {e}"))?;
    let collection = collect_agent_source_files(project_root, root, settings);
    let mut matched: Vec<String> = Vec::new();
    for file in &collection.files {
        if matched.len() >= max_results {
            break;
        }
        let relative = source_identity(&file.collection_relative_path);
        if matcher
            .matched(std::path::Path::new(&relative), false)
            .is_ignore()
        {
            matched.push(relative);
        }
    }
    Ok(json!({
        "pattern": pattern,
        "matches": matched,
        "count": matched.len(),
        "truncated": matched.len() >= max_results,
    }))
}

fn scan_agent_code_files(
    project_root: &std::path::Path,
    root: &std::path::Path,
    settings: &crate::models::ScanSettings,
    scan_type: &str,
    scan_secrets: bool,
    scan_vulnerabilities: bool,
) -> Value {
    let started = Instant::now();
    let collection = collect_agent_source_files(project_root, root, settings);
    let findings: Vec<crate::models::Finding> = collection
        .files
        .par_iter()
        .flat_map(|file| {
            crate::scanners::scan_file_with_relative_path(
                &file.canonical_path,
                &source_identity(&file.collection_relative_path),
                settings.max_file_size_kb,
                scan_secrets,
                scan_vulnerabilities,
            )
        })
        .collect();
    let secrets = findings
        .iter()
        .filter(|finding| finding.category == "secret")
        .count();
    let vulnerabilities = findings
        .iter()
        .filter(|finding| finding.category == "vulnerability")
        .count();
    let mut sorted = findings.clone();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));
    let top: Vec<Value> = sorted
        .iter()
        .take(25)
        .map(|finding| {
            json!({
                "rule": finding.rule_name,
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "category": finding.category,
                "file": finding.file_path,
                "line": finding.line,
                "match": truncate(&finding.match_text, 120),
            })
        })
        .collect();
    json!({
        "scan_type": scan_type,
        "files_scanned": collection.files.len(),
        "files_skipped": collection.skipped,
        "secrets_found": secrets,
        "vulnerabilities_found": vulnerabilities,
        "total_findings": findings.len(),
        "top_findings": top,
        "duration_ms": started.elapsed().as_millis() as u64,
    })
}

fn scan_agent_source_files(
    project_root: &std::path::Path,
    root: &std::path::Path,
    settings: &crate::models::ScanSettings,
) -> Value {
    scan_agent_code_files(project_root, root, settings, "source", false, true)
}

fn scan_agent_secret_files(
    project_root: &std::path::Path,
    root: &std::path::Path,
    settings: &crate::models::ScanSettings,
) -> Value {
    scan_agent_code_files(project_root, root, settings, "secrets", true, false)
}

#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TodoItem {
    pub id: u64,
    pub text: String,
    pub status: String, // "pending" | "done"
}

fn truncate(s: &str, n: usize) -> String {
    crate::scanners::secrets::truncate(s, n)
}

/// The full agent tool set.
pub fn builtins() -> Vec<Tool> {
    vec![
        // ------------------------------------------------------------ read_file
        crate::tool!(
            "read_file",
            "Read a text file from the project (bounded line window). Use for understanding code the model was asked about or found via grep.",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File path relative to the project root (or absolute)." },
                    "line_offset": { "type": "integer", "description": "1-based first line to read.", "minimum": 1 },
                    "limit": { "type": "integer", "description": "Max lines to read (<= 2000).", "minimum": 1, "maximum": 2000 },
                    "include_line_numbers": { "type": "boolean" }
                },
                "required": ["path"]
            }),
            true, false, false,
            |ctx, args| {
                let path = arg_str(&args, "path")?;
                let offset = arg_u64_default(&args, "line_offset", 1);
                let limit = arg_u64_default(&args, "limit", 500).min(2000);
                let include_numbers = arg_bool_default(&args, "include_line_numbers", true);
                let root = project_root(&ctx)?;
                let full = resolve_in_project(&root, &path)?;
                let content = std::fs::read_to_string(&full).map_err(|e| format!("read failed: {e}"))?;
                let lines: Vec<&str> = content.lines().collect();
                let start = (offset.max(1) as usize - 1).min(lines.len());
                let end = (start + limit as usize).min(lines.len());
                let mut out = String::new();
                for i in start..end {
                    if include_numbers {
                        out.push_str(&format!("{:>6} │ {}\n", i + 1, lines[i]));
                    } else {
                        out.push_str(lines[i]);
                        out.push('\n');
                    }
                }
                Ok(json!({
                    "path": display_rel(&root, &full),
                    "line_offset": start + 1,
                    "line_count": end - start,
                    "total_lines": lines.len(),
                    "has_more_lines": end < lines.len(),
                    "content": truncate(&out, 20000),
                }))
            }
        ),
        // ---------------------------------------------------------- grep_project
        crate::tool!(
            "grep_project",
            "Search the project with a regular expression. Returns matching lines with file:line, or per-file counts.",
            json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Regular expression to search (Rust regex syntax)." },
                    "path": { "type": "string", "description": "Optional subdirectory or file to restrict the search to." },
                    "output_mode": { "type": "string", "enum": ["content", "files_with_matches", "count"], "description": "content: matching lines; files_with_matches: file list; count: per-file counts." },
                    "context_lines": { "type": "integer", "description": "Lines of context before/after each match.", "minimum": 0, "maximum": 5 },
                    "head_limit": { "type": "integer", "description": "Max matches to return.", "minimum": 1, "maximum": 250 }
                },
                "required": ["pattern"]
            }),
            true, false, false,
            |ctx, args| {
                let pattern = arg_str(&args, "pattern")?;
                let mode = arg_str_default(&args, "output_mode", "content");
                let context = arg_u64_default(&args, "context_lines", 0) as usize;
                let head_limit = arg_u64_default(&args, "head_limit", 100).min(250) as usize;
                let proj = project_root(&ctx)?;
                let root = match arg_str_opt(&args, "path") {
                    Some(p) => resolve_collection_root(&proj, &p)?,
                    None => proj.clone(),
                };
                let st = ctx.state().ok_or("app state unavailable")?;
                let settings = st.settings.lock().unwrap().scan.clone();
                drop(st);
                grep_project_files(
                    &proj,
                    &root,
                    &settings,
                    &pattern,
                    &mode,
                    context,
                    head_limit,
                )
            }
        ),
        // ----------------------------------------------------------------- glob
        crate::tool!(
            "glob",
            "List files in the project matching a glob pattern (e.g. **/*.rs, src/**/*.ts, *.toml).",
            json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Glob pattern." },
                    "path": { "type": "string", "description": "Optional root directory within the project." },
                    "max_results": { "type": "integer", "description": "Max paths to return.", "minimum": 1, "maximum": 200 }
                },
                "required": ["pattern"]
            }),
            true, false, false,
            |ctx, args| {
                let pattern = arg_str(&args, "pattern")?;
                let max_results = arg_u64_default(&args, "max_results", 100).min(200) as usize;
                let proj = project_root(&ctx)?;
                let root = match arg_str_opt(&args, "path") {
                    Some(p) => resolve_collection_root(&proj, &p)?,
                    None => proj.clone(),
                };
                let st = ctx.state().ok_or("app state unavailable")?;
                let settings = st.settings.lock().unwrap().scan.clone();
                drop(st);
                glob_project_files(&proj, &root, &settings, &pattern, max_results)
            }
        ),
        // -------------------------------------------------------------- run_scan
        crate::tool!(
            "run_scan",
            "Run a VulnCompanion scan on the active project: source (vulnerable code patterns), secrets (leaked credentials), or dependencies (lockfiles vs OSV). Returns counts and the top findings.",
            json!({
                "type": "object",
                "properties": {
                    "scan_type": { "type": "string", "enum": ["source", "secrets", "dependencies"], "description": "source: vuln patterns (default); secrets: secret scanning; dependencies: OSV check of lockfiles." },
                    "path": { "type": "string", "description": "Optional subfolder to scan (defaults to the project root)." }
                }
            }),
            true, false, false,
            |ctx, args| {
                let scan_type = arg_str_default(&args, "scan_type", "source");
                let proj = project_root(&ctx)?;
                let root = match arg_str_opt(&args, "path") {
                    Some(p) => resolve_collection_root(&proj, &p)?,
                    None => proj.clone(),
                };
                let started = Instant::now();
                let st = ctx.state().ok_or("app state unavailable")?;
                let settings = st.settings.lock().unwrap().clone();
                drop(st);

                if scan_type == "dependencies" || scan_type == "deps" {
                    let lockfiles = collect_agent_lockfiles(&proj, &root, &settings.scan);
                    let mut deps = Vec::new();
                    for lf in &lockfiles {
                        let name = lf.file_name().and_then(|s| s.to_str()).unwrap_or("");
                        let kind = crate::deps::lockfiles::lockfile_kind(name);
                        if let Ok(d) = crate::deps::lockfiles::parse_lockfile(lf, kind) {
                            deps.extend(d);
                        }
                    }
                    let deps = crate::deps::lockfiles::dedupe_dependencies(deps);
                    let st = ctx.state().ok_or("app state unavailable")?;
                    let vuln_map = st.osv.query_batch(&deps).await.unwrap_or_default();
                    drop(st);
                    let mut vulns: Vec<Vulnerability> = Vec::new();
                    for dep in &deps {
                        let key = format!("{}\u{0}{}\u{0}{}", dep.ecosystem, dep.name, dep.version);
                        if let Some(v) = vuln_map.get(&key) {
                            vulns.extend(v.clone());
                        }
                    }
                    vulns.sort_by(|a, b| b.cvss_score.unwrap_or(0.0).partial_cmp(&a.cvss_score.unwrap_or(0.0)).unwrap_or(std::cmp::Ordering::Equal));
                    let top: Vec<Value> = vulns.iter().take(20).map(|v| json!({
                        "id": v.id, "package": v.package_name, "installed": v.installed_version,
                        "severity": v.severity, "cvss": v.cvss_score, "fixed": v.fixed_versions,
                        "summary": truncate(&v.summary, 160),
                    })).collect();
                    return Ok(json!({
                        "scan_type": "dependencies",
                        "lockfiles": lockfiles.len(),
                        "packages_queried": deps.len(),
                        "vulnerabilities_found": vulns.len(),
                        "top_vulnerabilities": top,
                        "duration_ms": started.elapsed().as_millis() as u64,
                    }));
                }

                if scan_type == "secrets" {
                    Ok(scan_agent_secret_files(&proj, &root, &settings.scan))
                } else {
                    Ok(scan_agent_source_files(&proj, &root, &settings.scan))
                }
            }
        ),
        // ------------------------------------------------------------ search_cve
        crate::tool!(
            "search_cve",
            "Search the NVD database by keyword (free text or a CVE id). Returns a compact list of matching CVEs with severity.",
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "NVD keyword search, e.g. 'log4j rce', 'nginx', 'CVE-2024-1234'." },
                    "limit": { "type": "integer", "minimum": 1, "maximum": 25 }
                },
                "required": ["query"]
            }),
            true, false, false,
            |ctx, args| {
                let query = arg_str(&args, "query")?;
                let limit = arg_u64_default(&args, "limit", 10).min(25) as usize;
                let cve = ctx.app.state::<crate::cve::CveState>();
                let res = crate::cve::search_cves(&cve, &query, 0, limit, None)
                    .await
                    .map_err(|e| format!("NVD search failed: {e}"))?;
                let items: Vec<Value> = res.items.iter().map(|i| json!({
                    "id": i.id, "severity": i.severity, "cvss": i.cvss_score,
                    "published": i.published, "description": truncate(&i.description, 300),
                    "cwes": i.cwes,
                })).collect();
                Ok(json!({ "total": res.total, "items": items }))
            }
        ),
        // --------------------------------------------------------- get_cve_detail
        crate::tool!(
            "get_cve_detail",
            "Fetch the full NVD record for one CVE, including description, metrics, affected products, references and any OSV enrichment.",
            json!({
                "type": "object",
                "properties": {
                    "cve_id": { "type": "string", "description": "Full CVE id, e.g. CVE-2024-1234." }
                },
                "required": ["cve_id"]
            }),
            true, false, false,
            |ctx, args| {
                let cve_id = arg_str(&args, "cve_id")?;
                let cve = ctx.app.state::<crate::cve::CveState>();
                let detail = crate::cve::cve_detail(&cve, &cve_id).await.map_err(|e| e)?;
                let item = detail.item;
                Ok(json!({
                    "id": item.id, "severity": item.severity, "cvss": item.cvss_score,
                    "published": item.published, "modified": item.modified,
                    "description": item.description,
                    "cwes": item.cwes,
                    "affected_products": item.affected_products,
                    "references": item.references,
                    "has_osv_record": detail.osv.is_some(),
                }))
            }
        ),
        // ------------------------------------------------------ query_osv_package
        crate::tool!(
            "query_osv_package",
            "Look up known vulnerabilities for a software package in the OSV database (by ecosystem + name, optionally version).",
            json!({
                "type": "object",
                "properties": {
                    "ecosystem": { "type": "string", "enum": ["npm", "crates.io", "Go", "PyPI", "RubyGems", "Packagist", "Maven"] },
                    "name": { "type": "string", "description": "Package name, e.g. lodash." },
                    "version": { "type": "string", "description": "Optional exact version — omit to list all advisories." }
                },
                "required": ["ecosystem", "name"]
            }),
            true, false, false,
            |ctx, args| {
                let ecosystem = arg_str(&args, "ecosystem")?;
                let name = arg_str(&args, "name")?;
                let cve = ctx.app.state::<crate::cve::CveState>();
                if let Some(version) = arg_str_opt(&args, "version") {
                    let vulns = cve.osv.query_package(&ecosystem, &name, &version).await.map_err(|e| e)?;
                    let items: Vec<Value> = vulns.iter().map(|v| json!({
                        "id": v.id, "severity": v.severity, "cvss": v.cvss_score,
                        "summary": truncate(&v.summary, 200), "fixed": v.fixed_versions,
                    })).collect();
                    Ok(json!({ "package": name, "version": version, "vulnerabilities": items }))
                } else {
                    let raw = crate::cve::osv_package_vulns(&cve, &ecosystem, &name).await.map_err(|e| e)?;
                    let items: Vec<Value> = raw.iter().take(25).map(|v| json!({
                        "id": v.get("id").and_then(|x| x.as_str()).unwrap_or(""),
                        "summary": truncate(v.get("summary").and_then(|x| x.as_str()).unwrap_or(""), 200),
                        "published": v.get("published"),
                    })).collect();
                    Ok(json!({ "package": name, "advisories": items }))
                }
            }
        ),
        // ------------------------------------------------------------- web_fetch
        crate::tool!(
            "web_fetch",
            "Fetch an http(s) URL and return its visible text (HTML stripped). Use to read vendor advisories, PoC write-ups, NVD/OSV pages, etc.",
            json!({
                "type": "object",
                "properties": {
                    "url": { "type": "string", "description": "http(s) URL." },
                    "max_bytes": { "type": "integer", "maximum": 262144 }
                },
                "required": ["url"]
            }),
            true, false, false,
            |ctx, args| {
                let url = arg_str(&args, "url")?;
                let parsed = reqwest::Url::parse(&url).map_err(|e| format!("invalid URL: {e}"))?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err("only http(s) URLs are allowed".into());
                }
                let max_bytes = arg_u64_default(&args, "max_bytes", 262144).min(262144) as usize;
                let st = ctx.state().ok_or("app state unavailable")?;
                let http = st.http.clone();
                drop(st);
                let resp = http
                    .get(parsed)
                    .timeout(std::time::Duration::from_secs(20))
                    .send()
                    .await
                    .map_err(|e| format!("fetch failed: {e}"))?;
                if !resp.status().is_success() {
                    return Err(format!("endpoint returned {}", resp.status()));
                }
                let bytes = resp.bytes().await.map_err(|e| format!("read failed: {e}"))?;
                let slice = &bytes[..bytes.len().min(max_bytes)];
                let raw = String::from_utf8_lossy(slice);
                let text = strip_html(&raw);
                let text = crate::scanners::secrets::truncate(&text, 20000);
                Ok(json!({ "url": url, "content": text, "truncated": bytes.len() > max_bytes }))
            }
        ),
        // -------------------------------------------------------------- ask_user
        crate::tool!(
            "ask_user",
            "Ask the user 1-4 structured questions (with optional answer options). Use when you need a decision, clarification, or input the tools cannot provide.",
            json!({
                "type": "object",
                "properties": {
                    "questions": {
                        "type": "array",
                        "description": "1-4 questions.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "prompt": { "type": "string" },
                                "options": { "type": "array", "items": { "type": "string" }, "description": "Optional choices; max 6." },
                                "multi_select": { "type": "boolean" }
                            },
                            "required": ["prompt"]
                        }
                    }
                },
                "required": ["questions"]
            }),
            false, true, false,
            |ctx, args| {
                let questions = args.get("questions").cloned().ok_or("missing questions")?;
                let arr = questions.as_array().ok_or("questions must be an array")?;
                if arr.is_empty() || arr.len() > 4 {
                    return Err("ask_user takes 1-4 questions".into());
                }
                let (tx, rx) = tokio::sync::oneshot::channel();
                let req_id = uuid::Uuid::new_v4().to_string();
                if let Some(st) = ctx.state() {
                    st.pending_interactions.lock().unwrap().insert(req_id.clone(), tx);
                }
                (ctx.emit)(AiStreamEvent::AskUser { request_id: req_id.clone(), questions });
                let response = if let Some(st) = ctx.state() {
                    wait_for_pending_response(
                        &st.pending_interactions,
                        &req_id,
                        rx,
                        std::time::Duration::from_secs(180),
                        ctx.cancellation.as_deref(),
                    )
                    .await
                } else {
                    Err(PendingWaitError::ChannelClosed)
                };
                match response {
                    Ok(answers) => Ok(json!({ "answers": answers })),
                    Err(PendingWaitError::Cancelled) => Err("chat cancelled".into()),
                    Err(PendingWaitError::ChannelClosed) => {
                        Err("interaction channel closed".into())
                    }
                    Err(PendingWaitError::TimedOut) => Err("ask_user timed out after 180s".into()),
                }
            }
        ),
        // ------------------------------------------------- run_binary_scan
        crate::tool!(
            "run_binary_scan",
            "Scan a binary, firmware image, or archive in the active project for vulnerable bundled components (statically linked OpenSSL, zlib, curl, …) using the user's installed cve-bin-tool. Use this when the target is compiled output rather than source or a lockfile. Slow: the first run downloads a CVE database.",
            json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File or folder inside the project to scan (defaults to the project root)." },
                    "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Minimum severity to report." },
                    "offline": { "type": "boolean", "description": "Use only the already-downloaded CVE database and make no network calls." }
                }
            }),
            // Dangerous: this spawns a third-party process, so every call goes
            // through the HITL approval gate rather than running unattended.
            false, false, true,
            |ctx, args| {
                let proj = project_root(&ctx)?;
                let target = match arg_str_opt(&args, "path") {
                    Some(p) => resolve_collection_root(&proj, &p)?,
                    None => proj.clone(),
                };

                let st = ctx.state().ok_or("app state unavailable")?;
                let settings = st.settings.lock().unwrap().clone();
                let cancel = st.cancel_binary_scan.clone();
                drop(st);
                cancel.store(false, std::sync::atomic::Ordering::Relaxed);

                let scratch_dir = ctx
                    .app
                    .path()
                    .app_cache_dir()
                    .map_err(|e| format!("no cache directory available: {e}"))?
                    .join("binscan");

                let trimmed = |value: Option<String>| {
                    value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
                };
                let context = crate::binscan::scan::ScanContext {
                    runtime: crate::binscan::runtime::Runtime::parse(
                        settings.binary_scanner_runtime.as_deref(),
                    ),
                    cve_bin_tool_path: trimmed(settings.binary_scanner_path.clone()),
                    grype_path: trimmed(settings.grype_path.clone()),
                    nvd_api_key: settings.nvd_api_key.clone(),
                    scratch_dir,
                    use_cve_bin_tool: true,
                    // Both scanners see different things, so the agent gets the
                    // merged view rather than having to choose.
                    use_grype: true,
                };

                let request = crate::binscan::run::BinaryScanRequest {
                    path: target.to_string_lossy().into_owned(),
                    severity: arg_str_opt(&args, "severity"),
                    offline: args.get("offline").and_then(|v| v.as_bool()).unwrap_or(false),
                    update: None,
                };

                // cve-bin-tool's per-line progress is dropped on this path: the
                // agent surface renders a tool card with a running state and has
                // no channel for streaming sub-tool output. The Binary Scan page
                // gets the same lines over `binscan://progress`.
                let on_progress: std::sync::Arc<dyn Fn(String) + Send + Sync> =
                    std::sync::Arc::new(|_line| {});

                let outcome = crate::binscan::scan::run_scan(
                    &context,
                    &request,
                    cancel,
                    std::time::Duration::from_secs(45 * 60),
                    on_progress,
                )
                .await?;
                let result = outcome.result;

                // Return a bounded summary: a firmware image can carry hundreds
                // of components, and the whole report would swamp the context.
                let components: Vec<Value> = result
                    .components
                    .iter()
                    .take(25)
                    .map(|c| json!({
                        "product": c.product,
                        "vendor": c.vendor,
                        "version": c.version,
                        "paths": c.paths.iter().take(5).collect::<Vec<_>>(),
                        "cves": c.vulnerabilities.iter().take(10).map(|v| json!({
                            "id": v.cve_id,
                            "severity": v.severity,
                            "score": v.score,
                        })).collect::<Vec<_>>(),
                    }))
                    .collect();

                Ok(json!({
                    "target": result.target,
                    "summary": result.summary,
                    "databaseLastUpdated": result.database_last_updated,
                    "durationMs": result.duration_ms,
                    "componentsShown": components.len(),
                    "components": components,
                }))
            }
        ),
        // ----------------------------------------------------------------- todo
        crate::tool!(
            "todo",
            "Maintain a per-conversation todo list: add/update/complete/delete/list items. Keep multi-step research plans here so you don't lose track.",
            json!({
                "type": "object",
                "properties": {
                    "op": { "type": "string", "enum": ["add", "update", "complete", "delete", "list"] },
                    "text": { "type": "string", "description": "Text of the item (add, or new text for update)." },
                    "id": { "type": "integer", "description": "Item id (update/complete/delete)." }
                },
                "required": ["op"]
            }),
            false, true, false,
            |ctx, args| {
                let op = arg_str(&args, "op")?;
                let st = ctx.state().ok_or("app state unavailable")?;
                let key = ctx.conversation_id.clone().unwrap_or_else(|| "default".into());
                let mut todos = st.todos.lock().unwrap();
                let list = todos.entry(key).or_default();
                match op.as_str() {
                    "add" => {
                        let text = arg_str(&args, "text")?;
                        let id = list.iter().map(|t| t.id).max().unwrap_or(0) + 1;
                        list.push(TodoItem { id, text, status: "pending".into() });
                    }
                    "complete" => {
                        let id = arg_u64_default(&args, "id", 0);
                        if let Some(t) = list.iter_mut().find(|t| t.id == id) {
                            t.status = "done".into();
                        } else {
                            return Err(format!("no todo with id {id}"));
                        }
                    }
                    "delete" => {
                        let id = arg_u64_default(&args, "id", 0);
                        list.retain(|t| t.id != id);
                    }
                    "update" => {
                        let id = arg_u64_default(&args, "id", 0);
                        let text = arg_str(&args, "text")?;
                        if let Some(t) = list.iter_mut().find(|t| t.id == id) {
                            t.text = text;
                        } else {
                            return Err(format!("no todo with id {id}"));
                        }
                    }
                    "list" | _ => {}
                }
                let snapshot = json!(list.clone());
                // Drop the state lock before emitting: the UI callback runs
                // inline and must not be able to re-enter this mutex.
                drop(todos);
                (ctx.emit)(crate::ai::AiStreamEvent::Todos { items: snapshot.clone() });
                Ok(json!({ "todos": snapshot }))
            }
        ),
    ]
}

/// Crude HTML → text: drop scripts/styles, strip tags, collapse whitespace.
fn strip_html(raw: &str) -> String {
    let re_script = regex::Regex::new(r"(?is)<script.*?</script>").unwrap();
    let re_style = regex::Regex::new(r"(?is)<style.*?</style>").unwrap();
    let re_tag = regex::Regex::new(r"(?s)<[^>]+>").unwrap();
    let re_ws = regex::Regex::new(r"[ \t]+").unwrap();
    let re_nl = regex::Regex::new(r"\n{3,}").unwrap();
    let s = re_script.replace_all(raw, " ");
    let s = re_style.replace_all(&s, " ");
    let s = re_tag.replace_all(&s, " ");
    let s = re_ws.replace_all(&s, " ");
    let s = re_nl.replace_all(&s, "\n\n");
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        collect_agent_files, collect_agent_lockfiles, glob_project_files, grep_project_files,
        scan_agent_secret_files, scan_agent_source_files,
    };
    use crate::agent::tool::resolve_collection_root;
    use crate::models::ScanSettings;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".git")).unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::write(root.path().join(".git/config"), "[core]\n").unwrap();
        fs::write(root.path().join(".gitignore"), "ignored.rs\n").unwrap();
        fs::write(root.path().join("ignored.rs"), "ignored\n").unwrap();
        fs::write(root.path().join("src/main.rs"), "fn main() {}\n").unwrap();
        root
    }

    fn relative_files(root: &Path, include_git: bool) -> Vec<PathBuf> {
        let canonical_root = root.canonicalize().unwrap();
        let mut settings = ScanSettings::default();
        settings.include_git = include_git;
        settings.ignored_dirs.clear();
        let (files, _, _) = collect_agent_files(root, root, &settings);
        files
            .into_iter()
            .map(|path| path.strip_prefix(&canonical_root).unwrap().to_path_buf())
            .collect()
    }

    #[test]
    fn assistant_file_collection_uses_saved_include_git_policy() {
        let root = fixture();

        let excluded = relative_files(root.path(), false);
        let included = relative_files(root.path(), true);

        assert!(!excluded.contains(&PathBuf::from(".git/config")));
        assert!(included.contains(&PathBuf::from(".git/config")));
        for files in [excluded, included] {
            assert!(!files.contains(&PathBuf::from("ignored.rs")));
            assert!(files.contains(&PathBuf::from("src/main.rs")));
        }
    }

    #[test]
    fn assistant_subpath_collection_retains_the_project_policy_root() {
        let root = fixture();
        fs::write(root.path().join("src/ignored.rs"), "ignored\n").unwrap();
        let mut settings = ScanSettings::default();
        settings.ignored_dirs.clear();

        let (direct_git, _, _) =
            collect_agent_files(root.path(), &root.path().join(".git/config"), &settings);
        let (nested, _, _) = collect_agent_files(root.path(), &root.path().join("src"), &settings);
        assert!(direct_git.is_empty());
        assert!(!nested.contains(&root.path().join("src/ignored.rs").canonicalize().unwrap()));
        assert!(nested.contains(&root.path().join("src/main.rs").canonicalize().unwrap()));

        settings.include_git = true;
        let (direct_git, _, _) =
            collect_agent_files(root.path(), &root.path().join(".git/config"), &settings);
        assert_eq!(
            direct_git,
            [root.path().join(".git/config").canonicalize().unwrap()],
        );
    }

    #[cfg(unix)]
    #[test]
    fn assistant_subpath_collection_uses_saved_follow_symlinks_policy() {
        use std::os::unix::fs::symlink;

        let root = fixture();
        fs::create_dir(root.path().join("shared")).unwrap();
        fs::write(root.path().join("shared/lib.rs"), "pub fn shared() {}\n").unwrap();
        fs::write(root.path().join("shared/private.rs"), "private\n").unwrap();
        fs::write(root.path().join(".gitignore"), "shared/private.rs\n").unwrap();
        let alias = root.path().join("alias");
        symlink(root.path().join("shared"), &alias).unwrap();
        let collection_root = resolve_collection_root(root.path(), "alias").unwrap();
        assert_eq!(collection_root, alias);
        let mut settings = ScanSettings::default();
        settings.ignored_dirs.clear();

        settings.follow_symlinks = false;
        let (excluded, _, _) = collect_agent_files(root.path(), &collection_root, &settings);
        settings.follow_symlinks = true;
        let (included, _, _) = collect_agent_files(root.path(), &collection_root, &settings);

        assert!(excluded.is_empty());
        assert_eq!(
            included,
            [root.path().join("shared/lib.rs").canonicalize().unwrap()],
        );
    }

    #[test]
    fn assistant_dependency_discovery_is_separate_from_saved_source_git_policy() {
        let root = fixture();
        fs::write(root.path().join("Cargo.lock"), "").unwrap();
        fs::write(root.path().join(".gitignore"), "Cargo.lock\n").unwrap();
        fs::write(root.path().join(".git/package-lock.json"), "{}").unwrap();
        let mut settings = ScanSettings::default();
        settings.ignored_dirs.clear();

        let excluded = collect_agent_lockfiles(root.path(), root.path(), &settings);
        settings.include_git = true;
        let included = collect_agent_lockfiles(root.path(), root.path(), &settings);

        let lockfile = root.path().join("Cargo.lock").canonicalize().unwrap();
        assert_eq!(excluded, [lockfile.clone()]);
        assert_eq!(included, [lockfile]);
    }

    #[cfg(unix)]
    #[test]
    fn actual_assistant_source_callers_reject_lexical_git_alias_roots() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("ordinary")).unwrap();
        fs::write(root.path().join("ordinary/config"), "ordinary\n").unwrap();
        symlink(root.path().join("ordinary"), root.path().join(".git")).unwrap();
        let mut settings = ScanSettings::default();
        settings.follow_symlinks = true;
        settings.include_git = false;
        settings.ignored_dirs.clear();

        let requested = resolve_collection_root(root.path(), ".git/config").unwrap();
        let grep = grep_project_files(
            root.path(),
            &requested,
            &settings,
            "ordinary",
            "content",
            0,
            100,
        )
        .unwrap();
        let glob = glob_project_files(root.path(), &requested, &settings, "*", 100).unwrap();
        let source = scan_agent_source_files(root.path(), &requested, &settings);
        let secrets = scan_agent_secret_files(root.path(), &requested, &settings);

        assert_eq!(grep["total_matches"], 0);
        assert_eq!(glob["count"], 0);
        assert_eq!(source["files_scanned"], 0);
        assert_eq!(secrets["files_scanned"], 0);
    }

    #[cfg(unix)]
    #[test]
    fn actual_assistant_source_callers_cannot_search_or_scan_an_ignored_alias_root() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("shared")).unwrap();
        fs::write(
            root.path().join("shared/exposed.js"),
            "eval(userInput);\nconst token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';\n",
        )
        .unwrap();
        fs::write(root.path().join(".gitignore"), "alias\n").unwrap();
        let alias = root.path().join("alias");
        symlink(root.path().join("shared"), &alias).unwrap();
        let mut settings = ScanSettings::default();
        settings.follow_symlinks = true;
        settings.ignored_dirs.clear();

        let grep = grep_project_files(
            root.path(),
            &alias,
            &settings,
            "eval",
            "content",
            0,
            100,
        )
        .unwrap();
        let glob = glob_project_files(root.path(), &alias, &settings, "*.js", 100).unwrap();
        let source = scan_agent_source_files(root.path(), &alias, &settings);
        let secrets = scan_agent_secret_files(root.path(), &alias, &settings);

        assert_eq!(grep["total_matches"], 0);
        assert_eq!(glob["matches"], serde_json::json!([]));
        assert_eq!(source["files_scanned"], 0);
        assert_eq!(secrets["files_scanned"], 0);
    }

    #[cfg(unix)]
    #[test]
    fn actual_assistant_source_callers_use_collection_relative_alias_identity() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("shared")).unwrap();
        fs::write(
            root.path().join("shared/exposed.js"),
            "eval(userInput);\nconst token = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890';\n",
        )
        .unwrap();
        let alias = root.path().join("alias");
        symlink(root.path().join("shared"), &alias).unwrap();
        let mut settings = ScanSettings::default();
        settings.follow_symlinks = true;
        settings.ignored_dirs.clear();

        let grep = grep_project_files(
            root.path(),
            &alias,
            &settings,
            "eval",
            "files_with_matches",
            0,
            100,
        )
        .unwrap();
        let glob = glob_project_files(root.path(), &alias, &settings, "*.js", 100).unwrap();
        let source = scan_agent_source_files(root.path(), &alias, &settings);
        let secrets = scan_agent_secret_files(root.path(), &alias, &settings);

        assert_eq!(grep["files_with_matches"], serde_json::json!(["exposed.js"]));
        assert_eq!(glob["matches"], serde_json::json!(["exposed.js"]));
        assert_eq!(source["top_findings"][0]["file"], "exposed.js");
        assert_eq!(secrets["top_findings"][0]["file"], "exposed.js");
    }

    #[test]
    fn assistant_collection_root_rejects_paths_outside_the_project() {
        let root = fixture();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("outside.rs");
        fs::write(&outside_file, "outside\n").unwrap();

        assert_eq!(
            resolve_collection_root(root.path(), &outside_file.to_string_lossy()),
            Err("path escapes the project root".into())
        );
    }
}
