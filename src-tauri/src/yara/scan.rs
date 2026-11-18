//! Compiling rules, walking a target, and scanning its files in parallel.
//!
//! Nothing here is under the run lifecycle: it takes owned inputs, a
//! cancellation flag, and a progress callback, so the command can run it on
//! blocking threads while it keeps the run state.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use oxaudit_yara::{CompileLimits, FileScanner, RuleMatch, RuleSet};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use super::{YaraRuleSkip, MASKED_EXCERPT_BYTES, MAX_RULE_SKIP_ROWS, SECRET_RULE_TAGS};
pub(crate) use crate::filewalk::{open_no_follow, walk, SkipList, WalkedFile};
use crate::filewalk::{read_budget_bytes, read_reserved, ReadBudget};
use crate::sigpacks::PackFile;

/// Per-file scan timeout.
pub(crate) const FILE_TIMEOUT: Duration = Duration::from_secs(30);

/// One pack's rule files, ready to compile.
pub(crate) struct PackInput {
    pub id: String,
    pub files: Vec<PackFile>,
}

pub(crate) struct Compiled {
    pub set: RuleSet,
    pub skips: Vec<YaraRuleSkip>,
    pub skips_total: usize,
    /// Compiled rules per pack id.
    pub rules_per_pack: BTreeMap<String, usize>,
}

/// Compile every pack's files into one rule set. The namespace of each file
/// is `<pack id>/<relative path>`; pack ids never contain `/`, so the pack
/// can always be read back from a namespace.
pub(crate) fn compile(inputs: &[PackInput]) -> Result<Compiled, String> {
    let mut sources = Vec::new();
    for pack in inputs {
        for file in &pack.files {
            let namespace = format!("{}/{}", pack.id, file.path);
            sources.push(oxaudit_yara::RuleSource {
                origin: namespace.clone(),
                namespace,
                text: file.text.clone(),
            });
        }
    }
    if sources.is_empty() {
        return Err("no YARA rule files were provided".into());
    }
    let set =
        RuleSet::compile(&sources, &CompileLimits::default()).map_err(|error| error.to_string())?;
    let skips_total = set.skipped().len();
    let skips = set
        .skipped()
        .iter()
        .take(MAX_RULE_SKIP_ROWS)
        .map(|skip| {
            let (pack, file) = skip
                .origin
                .split_once('/')
                .unwrap_or(("", skip.origin.as_str()));
            YaraRuleSkip {
                pack: pack.to_owned(),
                file: file.to_owned(),
                line: skip.line,
                message: skip.message.clone(),
            }
        })
        .collect();
    let mut rules_per_pack = BTreeMap::new();
    for rule in set.rules() {
        let pack = rule.namespace.split('/').next().unwrap_or("").to_owned();
        *rules_per_pack.entry(pack).or_insert(0) += 1;
    }
    Ok(Compiled {
        set,
        skips,
        skips_total,
        rules_per_pack,
    })
}

/// True for a rule that reports secrets: a tag in [`SECRET_RULE_TAGS`]
/// (any case) or `meta: sensitive = true` (a boolean, or the string
/// `"true"`).
pub(crate) fn is_sensitive_rule(m: &RuleMatch) -> bool {
    m.tags.iter().any(|tag| {
        SECRET_RULE_TAGS
            .iter()
            .any(|secret| tag.eq_ignore_ascii_case(secret))
    }) || m.meta.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("sensitive")
            && match value {
                oxaudit_yara::MetaValue::Bool(flag) => *flag,
                oxaudit_yara::MetaValue::String(text) => text.trim().eq_ignore_ascii_case("true"),
                _ => false,
            }
    })
}

/// Masks the excerpts of every rule that reports secrets, in place, before
/// they leave the scan: only the first [`MASKED_EXCERPT_BYTES`] bytes are
/// kept, and only when the match is longer than 8 bytes. The match length
/// is kept as is.
pub(crate) fn mask_sensitive(matches: &mut [RuleMatch]) {
    for m in matches.iter_mut().filter(|m| is_sensitive_rule(m)) {
        for string in &mut m.strings {
            let keep = if string.length > 8 {
                MASKED_EXCERPT_BYTES * 2
            } else {
                0
            };
            string
                .excerpt_hex
                .truncate(keep.min(string.excerpt_hex.len()));
        }
    }
}

/// One matched file.
#[derive(Debug)]
pub(crate) struct FileMatches {
    pub abs: PathBuf,
    pub rel: String,
    pub sha256: String,
    pub size: u64,
    pub matches: Vec<RuleMatch>,
}

#[derive(Debug, Default)]
pub(crate) struct ScanOutput {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub matched: Vec<FileMatches>,
    pub skipped: SkipList,
    pub timed_out: u64,
    pub engine_errors: u64,
    pub cancelled: bool,
    /// The most file bytes held in memory at once by the workers.
    pub peak_read_bytes: u64,
}

pub(crate) struct ScanLimits {
    pub max_file_bytes: u64,
    pub timeout: Duration,
    /// Bytes all workers' file buffers may hold at once
    /// ([`read_budget_bytes`] unless a test overrides it).
    pub read_budget_bytes: u64,
}

impl ScanLimits {
    pub(crate) fn new(max_file_bytes: u64, timeout: Duration) -> Self {
        Self {
            max_file_bytes,
            timeout,
            read_budget_bytes: read_budget_bytes(max_file_bytes),
        }
    }
}

enum Outcome {
    Scanned {
        bytes: u64,
        matched: Option<FileMatches>,
    },
    Skipped(String),
    TimedOut,
    EngineError(String),
    Cancelled,
}

fn mib(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

fn scan_one(
    scanner: &mut FileScanner<'_>,
    file: &WalkedFile,
    limits: &ScanLimits,
    budget: &ReadBudget,
    cancel: &AtomicBool,
) -> Outcome {
    if cancel.load(Ordering::Relaxed) {
        return Outcome::Cancelled;
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
    let too_large = |size: u64| {
        Outcome::Skipped(format!(
            "larger than the {} MiB limit ({size} bytes)",
            mib(limits.max_file_bytes)
        ))
    };
    if meta.len() > limits.max_file_bytes {
        return too_large(meta.len());
    }
    // The buffer is reserved from the scan's shared budget and held until
    // the scan of this file is done.
    let (bytes, _permit) =
        match read_reserved(handle, meta.len(), limits.max_file_bytes, budget, cancel) {
            Ok(Some(read)) => read,
            Ok(None) => return Outcome::Cancelled,
            Err(reason) => return Outcome::Skipped(reason),
        };
    match scanner.scan(&bytes, limits.timeout) {
        Ok(mut matches) => {
            mask_sensitive(&mut matches);
            let size = bytes.len() as u64;
            let matched = (!matches.is_empty()).then(|| FileMatches {
                abs: file.abs.clone(),
                rel: file.rel.clone(),
                sha256: hex::encode(Sha256::digest(&bytes)),
                size,
                matches,
            });
            Outcome::Scanned {
                bytes: size,
                matched,
            }
        }
        Err(oxaudit_yara::ScanError::Timeout) => Outcome::TimedOut,
        Err(oxaudit_yara::ScanError::Engine(message)) => Outcome::EngineError(message),
    }
}

/// Scan `files` with one scanner per worker thread. Results come back in
/// `files` order whatever the thread schedule was, so two runs over the same
/// tree produce the same rows. `progress(done, total, bytes)` is called at
/// most every 250 ms and once at the end.
pub(crate) fn scan_files(
    set: &RuleSet,
    files: &[WalkedFile],
    limits: &ScanLimits,
    cancel: &AtomicBool,
    progress: &(dyn Fn(u64, u64, u64) + Sync),
) -> ScanOutput {
    let total = files.len() as u64;
    let budget = ReadBudget::new(limits.read_budget_bytes);
    let done = AtomicU64::new(0);
    let bytes_done = AtomicU64::new(0);
    let last_emit = AtomicU64::new(0);
    let started = Instant::now();
    let outcomes: Vec<Outcome> = files
        .par_iter()
        .map_init(
            || set.scanner(),
            |scanner, file| {
                let outcome = scan_one(scanner, file, limits, &budget, cancel);
                let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
                if let Outcome::Scanned { bytes, .. } = &outcome {
                    bytes_done.fetch_add(*bytes, Ordering::Relaxed);
                }
                // `+ 1` so the first call (last_emit == 0) always passes.
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
            },
        )
        .collect();
    progress(
        done.load(Ordering::Relaxed),
        total,
        bytes_done.load(Ordering::Relaxed),
    );

    let mut out = ScanOutput::default();
    for (file, outcome) in files.iter().zip(outcomes) {
        match outcome {
            Outcome::Scanned { bytes, matched } => {
                out.files_scanned += 1;
                out.bytes_scanned += bytes;
                out.matched.extend(matched);
            }
            Outcome::Skipped(reason) => out.skipped.push(file.rel.clone(), reason),
            Outcome::TimedOut => {
                out.timed_out += 1;
                out.skipped.push(
                    file.rel.clone(),
                    format!(
                        "scan timed out after {} s; this file was not fully evaluated",
                        limits.timeout.as_secs()
                    ),
                );
            }
            Outcome::EngineError(message) => {
                out.engine_errors += 1;
                out.skipped.push(
                    file.rel.clone(),
                    format!("the YARA engine could not scan this file: {message}"),
                );
            }
            Outcome::Cancelled => out.cancelled = true,
        }
    }
    out.cancelled |= cancel.load(Ordering::SeqCst);
    out.peak_read_bytes = budget.peak();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_file_buffers_stay_within_the_read_budget() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..12 {
            std::fs::write(
                dir.path().join(format!("f{i:02}.bin")),
                vec![b'a'; 64 * 1024],
            )
            .unwrap();
        }
        // Larger than the whole budget: scanned alone, not skipped.
        std::fs::write(dir.path().join("big.bin"), vec![b'b'; 200 * 1024]).unwrap();
        let compiled = compile(&[PackInput {
            id: "p".into(),
            files: vec![PackFile {
                path: "r.yar".into(),
                text: "rule r { strings: $a = \"aaaa\" condition: $a }".into(),
            }],
        }])
        .unwrap();
        let cancel = AtomicBool::new(false);
        let walked = walk(dir.path(), &cancel).unwrap();
        let budget = 150 * 1024;
        let limits = ScanLimits {
            max_file_bytes: 1024 * 1024,
            timeout: FILE_TIMEOUT,
            read_budget_bytes: budget,
        };
        let out = scan_files(
            &compiled.set,
            &walked.files,
            &limits,
            &cancel,
            &|_, _, _| {},
        );
        assert_eq!(out.files_scanned, 13);
        assert!(out.skipped.rows.is_empty(), "{:?}", out.skipped.rows);
        assert_eq!(out.matched.len(), 12);
        // Alone, the big file's reservation is the peak; the small ones
        // never held more than the budget together.
        assert_eq!(out.peak_read_bytes, 200 * 1024 + 1);
    }

    #[test]
    fn the_largest_accepted_file_size_is_one_gibibyte() {
        let request = |mb| super::super::YaraScanRequest {
            max_file_size_mb: Some(mb),
            ..Default::default()
        };
        assert_eq!(
            super::super::max_file_bytes(&request(1024)).unwrap(),
            1024 * 1024 * 1024
        );
        let error = super::super::max_file_bytes(&request(1025)).unwrap_err();
        assert!(error.contains("between 1 and 1024"), "{error}");
        assert!(error.contains("read into memory"), "{error}");
    }
}
