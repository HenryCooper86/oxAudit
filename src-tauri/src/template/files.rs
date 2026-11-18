//! The local-path executor: the Nuclei `file` protocol over a folder or file.
//!
//! The walk is the YARA walk (no ignore rules, no symlink following,
//! deterministic order, capped file count). Each template's file rules decide
//! which files it reads by extension, denylist and size; a file no template
//! applies to is not opened and is counted in a note, not listed as skipped.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use oxaudit_nuclei::{evaluate_file, plan_file, FileRuleSpec, TemplateMatch};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use super::exec::{redact_match, Execution, FileSubject, RawMatch, Subject};
use super::select::Selected;
use super::{NotEvaluatedRow, MAX_FILES};
use crate::filewalk::{
    open_no_follow, read_budget_bytes, read_reserved, walk, ReadBudget, WalkedFile,
};

pub(crate) struct FileScanInput {
    /// Canonical scan target: a file or a folder.
    pub target: PathBuf,
    pub templates: Vec<Selected>,
    pub max_file_bytes: u64,
}

struct Prepared {
    rules: Vec<FileRuleSpec>,
}

enum Outcome {
    /// No template's extension rules accept this file; not opened.
    NotApplicable,
    /// Templates accept the name but every one has a `max-size` below the file.
    OverTemplateLimits,
    Scanned {
        bytes: u64,
        matches: Vec<(usize, TemplateMatch)>,
        subject: Option<FileSubject>,
    },
    Skipped(String),
    Cancelled,
}

/// Whether a file rule applies to a file at `rel`: its extension rules, and
/// `no-recursive` meaning only files directly inside the scan target.
fn applies(rule: &FileRuleSpec, rel: &str) -> bool {
    rule.accepts(rel) && !(rule.no_recursive && rel.contains('/'))
}

fn mib(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

fn scan_one(
    file: &WalkedFile,
    input: &FileScanInput,
    prepared: &[Prepared],
    budget: &ReadBudget,
    cancel: &AtomicBool,
) -> Outcome {
    if cancel.load(Ordering::Relaxed) {
        return Outcome::Cancelled;
    }
    let by_name: Vec<usize> = prepared
        .iter()
        .enumerate()
        .filter(|(_, p)| p.rules.iter().any(|rule| applies(rule, &file.rel)))
        .map(|(index, _)| index)
        .collect();
    if by_name.is_empty() {
        return Outcome::NotApplicable;
    }
    let handle = match open_no_follow(&file.abs) {
        Ok(handle) => handle,
        Err(error) => return Outcome::Skipped(format!("unreadable: {error}")),
    };
    let meta = match handle.metadata() {
        Ok(meta) => meta,
        Err(error) => return Outcome::Skipped(format!("unreadable: {error}")),
    };
    if !meta.is_file() {
        return Outcome::Skipped("not a regular file; not read".into());
    }
    let by_size: Vec<usize> = by_name
        .into_iter()
        .filter(|index| {
            prepared[*index].rules.iter().any(|rule| {
                applies(rule, &file.rel) && rule.max_size.is_none_or(|max| meta.len() <= max)
            })
        })
        .collect();
    if by_size.is_empty() {
        return Outcome::OverTemplateLimits;
    }
    let too_large = |size: u64| {
        Outcome::Skipped(format!(
            "larger than the {} MiB limit ({size} bytes)",
            mib(input.max_file_bytes)
        ))
    };
    if meta.len() > input.max_file_bytes {
        return too_large(meta.len());
    }
    // Reserved from the scan's shared budget until the templates are done.
    let (bytes, _permit) =
        match read_reserved(handle, meta.len(), input.max_file_bytes, budget, cancel) {
            Ok(Some(read)) => read,
            Ok(None) => return Outcome::Cancelled,
            Err(reason) => return Outcome::Skipped(reason),
        };
    let abs = file.abs.to_string_lossy().into_owned();
    let mut matches = Vec::new();
    for index in by_size {
        let selected = &input.templates[index];
        for mut found in evaluate_file(&selected.template, &abs, &bytes) {
            // `evaluate_file` runs every block that accepts the name; a block
            // that is `no-recursive` must not match below the target root.
            let block_applies = prepared[index]
                .rules
                .get(found.request_index)
                .is_none_or(|rule| applies(rule, &file.rel));
            if !block_applies {
                continue;
            }
            redact_match(&selected.template, &mut found, Some(&bytes));
            matches.push((index, found));
        }
    }
    let size = bytes.len() as u64;
    let subject = (!matches.is_empty()).then(|| FileSubject {
        abs: file.abs.clone(),
        rel: file.rel.clone(),
        sha256: hex::encode(Sha256::digest(&bytes)),
        size,
    });
    Outcome::Scanned {
        bytes: size,
        matches,
        subject,
    }
}

/// Walk `input.target` and evaluate every applicable template on every file
/// it accepts. `progress(done, total, bytes)` is called at most every 250 ms
/// and once at the end. Blocking: run it on a blocking thread.
pub(crate) fn scan_path(
    input: &FileScanInput,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64, u64) + Sync),
) -> Result<Execution, String> {
    let mut out = Execution::default();
    let walked = walk(&input.target, cancel)?;
    if walked.cancelled || cancel.load(Ordering::SeqCst) {
        out.cancelled = true;
        return Ok(out);
    }
    if walked.over_cap > 0 {
        out.incomplete.push((
            "template_file_cap",
            format!(
                "The target holds more than {MAX_FILES} files; {} were not scanned.",
                walked.over_cap
            ),
        ));
    }
    out.skipped = walked.skipped;
    let files = walked.files;

    let prepared: Vec<Prepared> = input
        .templates
        .iter()
        .map(|selected| Prepared {
            rules: plan_file(&selected.template),
        })
        .collect();
    for (selected, prepared) in input.templates.iter().zip(&prepared) {
        if prepared.rules.iter().any(|rule| rule.archive) {
            out.not_evaluated.push(NotEvaluatedRow {
                template_id: selected.template.id.clone(),
                pack: selected.pack.clone(),
                file: selected.file.clone(),
                protocol: Some("file".into()),
                target: None,
                reason: "asks to search inside archives (`archive: true`); oxAudit does not open archives in template scans, so files inside archives were not evaluated".into(),
            });
        }
    }

    let total = files.len() as u64;
    let budget = ReadBudget::new(read_budget_bytes(input.max_file_bytes));
    let done = AtomicU64::new(0);
    let bytes_done = AtomicU64::new(0);
    let last_emit = AtomicU64::new(0);
    let started = Instant::now();
    let outcomes: Vec<Outcome> = files
        .par_iter()
        .map(|file| {
            let outcome = scan_one(file, input, &prepared, &budget, cancel);
            let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
            if let Outcome::Scanned { bytes, .. } = &outcome {
                bytes_done.fetch_add(*bytes, Ordering::Relaxed);
            }
            let now_ms = started.elapsed().as_millis() as u64 + 1;
            let previous = last_emit.load(Ordering::Relaxed);
            if (previous == 0 || now_ms.saturating_sub(previous) >= 250)
                && last_emit
                    .compare_exchange(previous, now_ms, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                progress(finished, total, bytes_done.load(Ordering::Relaxed));
            }
            outcome
        })
        .collect();
    progress(
        done.load(Ordering::Relaxed),
        total,
        bytes_done.load(Ordering::Relaxed),
    );

    let mut not_applicable = 0u64;
    let mut over_limits = 0u64;
    for (file, outcome) in files.iter().zip(outcomes) {
        match outcome {
            Outcome::NotApplicable => not_applicable += 1,
            Outcome::OverTemplateLimits => over_limits += 1,
            Outcome::Scanned {
                bytes,
                matches,
                subject,
            } => {
                out.files_scanned += 1;
                out.bytes_scanned += bytes;
                if let Some(subject) = subject {
                    for (template, found) in matches {
                        out.matches.push(RawMatch {
                            template,
                            found,
                            subject: Subject::File(subject.clone()),
                        });
                    }
                }
            }
            Outcome::Skipped(reason) => out.skipped.push(file.rel.clone(), reason),
            Outcome::Cancelled => out.cancelled = true,
        }
    }
    out.cancelled |= cancel.load(Ordering::SeqCst);
    out.evaluated = out.files_scanned;
    if not_applicable > 0 {
        out.notes.push(format!(
            "{not_applicable} file(s) were not read because no selected template's file extensions apply to them."
        ));
    }
    if over_limits > 0 {
        out.notes.push(format!(
            "{over_limits} file(s) were not read because they exceed the max-size of every template that applies to them."
        ));
    }
    Ok(out)
}
