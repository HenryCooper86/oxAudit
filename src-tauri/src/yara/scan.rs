//! Compiling rules, walking a target, and scanning its files in parallel.
//!
//! Nothing here is under the run lifecycle: it takes owned inputs, a
//! cancellation flag, and a progress callback, so the command can run it on
//! blocking threads while it keeps the run state.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use oxaudit_yara::{CompileLimits, FileScanner, RuleMatch, RuleSet};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use super::{YaraRuleSkip, YaraSkippedFile, MAX_FILES, MAX_RULE_SKIP_ROWS, MAX_SKIPPED_ROWS};
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

/// Skipped-file rows up to a cap, with the remainder counted.
#[derive(Debug, Default)]
pub(crate) struct SkipList {
    pub rows: Vec<YaraSkippedFile>,
    pub dropped: u64,
}

impl SkipList {
    pub fn push(&mut self, path: String, reason: String) {
        if self.rows.len() < MAX_SKIPPED_ROWS {
            self.rows.push(YaraSkippedFile { path, reason });
        } else {
            self.dropped += 1;
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WalkedFile {
    pub abs: PathBuf,
    /// Relative to the target, forward slashes.
    pub rel: String,
}

#[derive(Debug, Default)]
pub(crate) struct Walk {
    pub files: Vec<WalkedFile>,
    pub skipped: SkipList,
    /// Regular files found beyond the file cap; not scanned.
    pub over_cap: u64,
    pub cancelled: bool,
}

fn relative_slashes(relative: &Path) -> String {
    relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Every file under `target` in a deterministic order. No ignore rules are
/// applied (malware hides in ignored folders) and symbolic links are listed
/// as skipped rather than followed. `target` should already be canonical.
pub(crate) fn walk(target: &Path, cancel: &AtomicBool) -> Result<Walk, String> {
    walk_capped(target, cancel, MAX_FILES)
}

pub(crate) fn walk_capped(target: &Path, cancel: &AtomicBool, cap: usize) -> Result<Walk, String> {
    let meta = std::fs::symlink_metadata(target)
        .map_err(|error| format!("cannot read the scan target: {error}"))?;
    let mut out = Walk::default();
    if meta.is_file() {
        let name = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| target.to_string_lossy().into_owned());
        out.files.push(WalkedFile {
            abs: target.to_owned(),
            rel: name,
        });
        return Ok(out);
    }
    if !meta.is_dir() {
        return Err("the scan target is neither a file nor a folder".into());
    }
    let mut visited = 0u64;
    for entry in walkdir::WalkDir::new(target)
        .follow_links(false)
        .sort_by_file_name()
    {
        visited += 1;
        if visited.is_multiple_of(1024) && cancel.load(Ordering::Relaxed) {
            out.cancelled = true;
            return Ok(out);
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                let path = error
                    .path()
                    .and_then(|p| p.strip_prefix(target).ok())
                    .map(relative_slashes)
                    .unwrap_or_default();
                out.skipped.push(path, format!("cannot be read: {error}"));
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let file_type = entry.file_type();
        if file_type.is_dir() {
            continue;
        }
        let rel = entry
            .path()
            .strip_prefix(target)
            .map(relative_slashes)
            .unwrap_or_default();
        if file_type.is_symlink() {
            out.skipped
                .push(rel, "symbolic link; links are not followed".into());
        } else if file_type.is_file() {
            if out.files.len() < cap {
                out.files.push(WalkedFile {
                    abs: entry.path().to_owned(),
                    rel,
                });
            } else {
                out.over_cap += 1;
            }
        } else {
            out.skipped.push(
                rel,
                "not a regular file (device, socket or pipe); not opened".into(),
            );
        }
    }
    Ok(out)
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
}

pub(crate) struct ScanLimits {
    pub max_file_bytes: u64,
    pub timeout: Duration,
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

fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Never follow a link swapped in after the walk, and never block on
        // a pipe swapped in.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn scan_one(
    scanner: &mut FileScanner<'_>,
    file: &WalkedFile,
    limits: &ScanLimits,
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
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    if let Err(error) = handle
        .take(limits.max_file_bytes + 1)
        .read_to_end(&mut bytes)
    {
        return Outcome::Skipped(format!("unreadable: {error}"));
    }
    if bytes.len() as u64 > limits.max_file_bytes {
        return too_large(bytes.len() as u64);
    }
    match scanner.scan(&bytes, limits.timeout) {
        Ok(matches) => {
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
    let done = AtomicU64::new(0);
    let bytes_done = AtomicU64::new(0);
    let last_emit = AtomicU64::new(0);
    let started = Instant::now();
    let outcomes: Vec<Outcome> = files
        .par_iter()
        .map_init(
            || set.scanner(),
            |scanner, file| {
                let outcome = scan_one(scanner, file, limits, cancel);
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
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_is_sorted_lists_links_and_reports_files_beyond_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["b/2.bin", "a/1.bin", "c.bin", "a/0.bin"] {
            let path = dir.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"x").unwrap();
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("c.bin"), dir.path().join("link")).unwrap();
        // A folder named like an ignore rule target is still walked.
        std::fs::create_dir_all(dir.path().join("node_modules/.git")).unwrap();
        std::fs::write(dir.path().join("node_modules/.git/hidden.bin"), b"x").unwrap();

        let cancel = AtomicBool::new(false);
        let walked = walk_capped(dir.path(), &cancel, 100).unwrap();
        let rels: Vec<_> = walked.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(
            rels,
            [
                "a/0.bin",
                "a/1.bin",
                "b/2.bin",
                "c.bin",
                "node_modules/.git/hidden.bin"
            ]
        );
        #[cfg(unix)]
        assert_eq!(walked.skipped.rows[0].path, "link");

        let capped = walk_capped(dir.path(), &cancel, 2).unwrap();
        assert_eq!(capped.files.len(), 2);
        assert_eq!(capped.over_cap, 3);
    }
}
