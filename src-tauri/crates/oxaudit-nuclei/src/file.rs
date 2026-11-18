//! File-protocol planning and evaluation.
//!
//! # Response parts
//!
//! `raw` (default), `all`, `body` and `data` are the file content; `path` is
//! the file path. Template variables are available to DSL matchers.
//!
//! Defaults where the Nuclei docs are ambiguous: a block with no
//! `extensions` behaves like `all`; `max-size` defaults to 5 MiB; names listed
//! in `extensions` are removed from the default denylist (so `[all, txt]`
//! includes `.txt`).

use crate::dsl::{EvalContext, Value, Vars, XorShiftContext};
use crate::matchers::{build_operators, evaluate_block, ResponseParts};
use crate::model::{FileBlock, Protocol, Template};
use crate::result::{FileLine, TemplateMatch};
use crate::support::Reasons;
use crate::vars::resolve_template_variables;
use crate::yaml::Yaml;

/// Extensions the file protocol skips unless the template lists them.
pub const DEFAULT_DENYLIST: &[&str] = &[
    "3g2", "3gp", "7z", "apk", "arj", "avi", "axd", "bmp", "css", "csv", "deb", "dll", "doc",
    "drv", "eot", "exe", "flv", "gif", "gifv", "gz", "h264", "ico", "iso", "jar", "jpeg", "jpg",
    "lock", "m4a", "m4v", "map", "mkv", "mov", "mp3", "mp4", "mpeg", "mpg", "msi", "ogg", "ogm",
    "ogv", "otf", "pdf", "pkg", "png", "ppt", "psd", "rar", "rm", "rpm", "svg", "swf", "sys",
    "tar", "tar.gz", "tif", "tiff", "ttf", "txt", "vob", "wav", "webm", "wmv", "woff", "woff2",
    "xcf", "xls", "xlsx", "zip",
];

const DEFAULT_MAX_SIZE: u64 = 5 * 1024 * 1024;
const MAX_LINES_PER_MATCH: usize = 200;
const MAX_LINE_TEXT: usize = 200;

/// A file rule for the host's directory walk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRuleSpec {
    pub request_index: usize,
    /// Lowercase, no dot; empty means every extension.
    pub extensions: Vec<String>,
    /// Effective denylist: the template's plus the default one, minus any
    /// extension the template lists explicitly.
    pub denylist: Vec<String>,
    /// Maximum file size in bytes; `None` is unlimited.
    pub max_size: Option<u64>,
    pub no_recursive: bool,
    /// The template asked to look inside archives. The engine does not open
    /// archives; the host decides what to do with this.
    pub archive: bool,
}

fn parse_size(text: &str) -> Option<Option<u64>> {
    let t = text.trim().to_ascii_lowercase();
    if t == "no" {
        return Some(None);
    }
    let split = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
    let (digits, unit) = t.split_at(split);
    let n: u64 = digits.parse().ok()?;
    let scale: u64 = match unit.trim() {
        "" | "b" => 1,
        "kb" | "k" => 1024,
        "mb" | "m" => 1024 * 1024,
        "gb" | "g" => 1024 * 1024 * 1024,
        _ => return None,
    };
    Some(Some(n.saturating_mul(scale)))
}

fn clean_ext(e: &str) -> String {
    e.trim().trim_start_matches('.').to_ascii_lowercase()
}

pub(crate) fn build_block(y: &Yaml, reasons: &mut Reasons) -> FileBlock {
    let extensions: Vec<String> = y
        .raw_list("extensions")
        .iter()
        .flat_map(|e| e.split(',').map(clean_ext).collect::<Vec<_>>())
        .filter(|e| !e.is_empty())
        .collect();
    if extensions.iter().any(|e| e.contains('/')) || y.boolean("mime-type") {
        reasons.add("matches files by mime type");
    }
    let denylist = y
        .raw_list("denylist")
        .iter()
        .flat_map(|e| e.split(',').map(clean_ext).collect::<Vec<_>>())
        .filter(|e| !e.is_empty())
        .collect();
    let max_size = match y.string("max-size") {
        None => Some(DEFAULT_MAX_SIZE),
        Some(text) => parse_size(&text).unwrap_or_else(|| {
            reasons.add(format!("has an unreadable file max-size `{text}`"));
            Some(DEFAULT_MAX_SIZE)
        }),
    };
    FileBlock {
        id: y.string("id"),
        extensions,
        denylist,
        max_size,
        no_recursive: y.boolean("no-recursive"),
        archive: y.boolean("archive"),
        ops: build_operators(y, reasons),
    }
}

impl FileRuleSpec {
    fn from_block(index: usize, block: &FileBlock) -> Self {
        let all = block.extensions.is_empty() || block.extensions.iter().any(|e| e == "all");
        let listed: Vec<String> = block
            .extensions
            .iter()
            .filter(|e| *e != "all")
            .cloned()
            .collect();
        let mut denylist: Vec<String> = DEFAULT_DENYLIST
            .iter()
            .filter(|d| !listed.iter().any(|l| l == *d))
            .map(|d| (*d).to_string())
            .collect();
        denylist.extend(block.denylist.iter().cloned());
        FileRuleSpec {
            request_index: index,
            extensions: if all { Vec::new() } else { listed },
            denylist,
            max_size: block.max_size,
            no_recursive: block.no_recursive,
            archive: block.archive,
        }
    }

    /// Whether the rule applies to a file with this path (by extension only;
    /// size is checked against the content).
    pub fn accepts(&self, path: &str) -> bool {
        let name = path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(path)
            .to_ascii_lowercase();
        let has_ext = |ext: &String| name.len() > ext.len() && name.ends_with(&format!(".{ext}"));
        if self.denylist.iter().any(has_ext) {
            return false;
        }
        self.extensions.is_empty() || self.extensions.iter().any(has_ext)
    }
}

/// One rule per file block of the template.
pub fn plan_file(template: &Template) -> Vec<FileRuleSpec> {
    template
        .file
        .iter()
        .enumerate()
        .map(|(i, b)| FileRuleSpec::from_block(i, b))
        .collect()
}

/// Evaluates every file block of `template` on `content`, with a default
/// deterministic context.
pub fn evaluate_file(template: &Template, path: &str, content: &[u8]) -> Vec<TemplateMatch> {
    evaluate_file_with(template, path, content, &mut XorShiftContext::default())
}

/// Like [`evaluate_file`] with a caller-supplied context.
pub fn evaluate_file_with(
    template: &Template,
    path: &str,
    content: &[u8],
    ctx: &mut dyn EvalContext,
) -> Vec<TemplateMatch> {
    let mut out = Vec::new();
    let base: Vars = resolve_template_variables(&template.variables, &Vars::new(), ctx);
    let mut line_starts: Option<Vec<usize>> = None;
    for (index, block) in template.file.iter().enumerate() {
        let spec = FileRuleSpec::from_block(index, block);
        if !spec.accepts(path) {
            continue;
        }
        if spec.max_size.is_some_and(|max| content.len() as u64 > max) {
            continue;
        }
        let value = match std::str::from_utf8(content) {
            Ok(s) => Value::str(s),
            Err(_) => Value::Bytes(content.to_vec()),
        };
        let mut parts = ResponseParts::new("raw");
        parts.collect_spans = true;
        parts.set_all(&["raw", "all", "body", "data"], value);
        parts.set("path", path);
        let mut parts = parts.with_base_vars(&base);
        let result = evaluate_block(&block.ops, &mut parts, ctx);
        if !result.matched {
            continue;
        }
        let starts = line_starts.get_or_insert_with(|| {
            let mut v = vec![0usize];
            v.extend(
                content
                    .iter()
                    .enumerate()
                    .filter(|(_, b)| **b == b'\n')
                    .map(|(i, _)| i + 1),
            );
            v
        });
        let mut spans: Vec<_> = result.spans.iter().collect();
        spans.sort_by_key(|s| (s.start, s.end));
        spans.dedup_by_key(|s| (s.start, s.end));
        let lines = spans
            .into_iter()
            .take(MAX_LINES_PER_MATCH)
            .map(|s| file_line(content, starts, s.start, s.end, s.matcher.clone()))
            .collect();
        out.push(TemplateMatch {
            template_id: template.id.clone(),
            name: template.info.name.clone(),
            severity: template.info.severity,
            matcher_names: result.matcher_names,
            extracted: result.extracted,
            protocol: Protocol::File,
            request_index: index,
            matched_at: path.to_string(),
            lines,
            matched_values: result.matched_values,
            warnings: result.warnings,
        });
    }
    out
}

/// Columns are 1-based byte columns; `end_column` is exclusive and clamped to
/// the end of the starting line for matches that span lines.
fn file_line(
    content: &[u8],
    starts: &[usize],
    start: usize,
    end: usize,
    matcher: Option<String>,
) -> FileLine {
    let idx = starts.partition_point(|s| *s <= start).saturating_sub(1);
    let line_start = starts.get(idx).copied().unwrap_or(0);
    let mut line_end = starts.get(idx + 1).copied().unwrap_or(content.len());
    if line_end > line_start && content.get(line_end - 1) == Some(&b'\n') {
        line_end -= 1;
    }
    if line_end > line_start && content.get(line_end - 1) == Some(&b'\r') {
        line_end -= 1;
    }
    let line_bytes = content.get(line_start..line_end).unwrap_or_default();
    let text: String = String::from_utf8_lossy(line_bytes)
        .chars()
        .take(MAX_LINE_TEXT)
        .collect();
    FileLine {
        line: idx + 1,
        start_column: start.saturating_sub(line_start) + 1,
        end_column: end.min(line_end).max(start).saturating_sub(line_start) + 1,
        start_offset: start,
        end_offset: end,
        text,
        matcher,
    }
}
