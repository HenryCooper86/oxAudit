//! What an executor hands back, whatever it executed: matches, the templates
//! it could not evaluate, and the counters and reasons the shared lifecycle
//! turns into the projection, warnings and terminal state.

use std::path::PathBuf;

use oxaudit_domain::NetworkExchangeEvidence;
use oxaudit_nuclei::{Template, TemplateMatch};

use super::{has_secret_tag, mask_value, NotEvaluatedRow, ResolvedHost, UnreachableTarget};
use crate::filewalk::SkipList;

/// A scanned file that matched.
#[derive(Debug, Clone)]
pub(crate) struct FileSubject {
    pub abs: PathBuf,
    /// Relative to the scan target, forward slashes.
    pub rel: String,
    pub sha256: String,
    pub size: u64,
}

/// A live target that matched, with the exchange that matched.
#[derive(Debug, Clone)]
pub(crate) struct TargetSubject {
    /// The target as the user typed it.
    pub target: String,
    /// Redacted, bounded excerpts; its `artifact_id` is replaced by the
    /// graph's artifact for `target`.
    pub exchange: Option<NetworkExchangeEvidence>,
}

/// What a match was found in: a scanned file, or a live target with its
/// exchange. The graph and projection are the only code that has to tell
/// them apart.
#[derive(Debug, Clone)]
pub(crate) enum Subject {
    File(FileSubject),
    Target(TargetSubject),
}

#[derive(Debug, Clone)]
pub(crate) struct RawMatch {
    /// Index into the selected templates the executor was given.
    pub template: usize,
    /// Already masked when the template reports credentials.
    pub found: TemplateMatch,
    pub subject: Subject,
}

/// An executor's output. Rows are in a deterministic order for the same
/// inputs.
#[derive(Debug, Default)]
pub(crate) struct Execution {
    pub matches: Vec<RawMatch>,
    /// Templates, or template/target pairs, that could not be evaluated.
    pub not_evaluated: Vec<NotEvaluatedRow>,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    /// Template × subject evaluations that actually happened: files read
    /// and evaluated by at least one template (path scans), or template ×
    /// target × protocol checks that got at least one answer (live scans).
    /// Zero means nothing was evaluated, which is never "no match".
    pub evaluated: u64,
    pub skipped: SkipList,
    pub requests_sent: u64,
    pub requests_refused: u64,
    /// Live scans: hosts refused by scope (host only), resolved names, and
    /// targets that were not reached.
    pub refused_hosts: Vec<String>,
    pub resolved: Vec<ResolvedHost>,
    pub unreachable: Vec<UnreachableTarget>,
    /// `(warning code, message)` for anything that narrows coverage; each
    /// makes the run Incomplete.
    pub incomplete: Vec<(&'static str, String)>,
    /// Coverage facts that do not make the run Incomplete.
    pub notes: Vec<String>,
    pub cancelled: bool,
}

/// Mask what a credential-reporting template extracted or matched, in place.
/// `content` is the scanned file when there is one, so the masked text is
/// derived from the exact matched bytes and nothing else on the line (which
/// often holds the rest of the secret) is kept. Templates that do not
/// report credentials are left alone.
pub(crate) fn redact_match(template: &Template, found: &mut TemplateMatch, content: Option<&[u8]>) {
    if !has_secret_tag(template.tags()) {
        return;
    }
    for line in &mut found.lines {
        let matched = content
            .and_then(|bytes| bytes.get(line.start_offset..line.end_offset))
            .map(|slice| String::from_utf8_lossy(slice).into_owned());
        line.text = mask_value(matched.as_deref().unwrap_or(&line.text));
    }
    for (_, values) in &mut found.extracted {
        for value in values.iter_mut() {
            *value = mask_value(value);
        }
    }
    for value in &mut found.matched_values {
        *value = mask_value(value);
    }
}
