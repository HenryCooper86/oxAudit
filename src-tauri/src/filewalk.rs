//! The file walk shared by the YARA and Template scans: every file under a
//! target in a deterministic order, no ignore rules (malware and credentials
//! hide in ignored folders), symbolic links listed rather than followed.

#![cfg_attr(not(any(feature = "yara", feature = "templates")), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

/// Files beyond this are reported, not scanned, and make the run Incomplete.
pub const MAX_FILES: usize = 1_000_000;
/// Stored skipped-file rows; the remainder is counted.
pub const MAX_SKIPPED_ROWS: usize = 100_000;

/// A file that was not scanned, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedFile {
    pub path: String,
    pub reason: String,
}

/// Skipped-file rows up to a cap, with the remainder counted.
#[derive(Debug, Default)]
pub(crate) struct SkipList {
    pub rows: Vec<SkippedFile>,
    pub dropped: u64,
}

impl SkipList {
    pub fn push(&mut self, path: String, reason: String) {
        if self.rows.len() < MAX_SKIPPED_ROWS {
            self.rows.push(SkippedFile { path, reason });
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

pub(crate) fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
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

/// Upper bound on the bytes that file reads may hold at once across all
/// scan workers.
pub const MAX_READ_BUDGET_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The in-flight read budget for a scan: `min(2 GiB, workers × per-file
/// limit)`, and never below the per-file limit.
pub(crate) fn read_budget_bytes(max_file_bytes: u64) -> u64 {
    let workers = rayon::current_num_threads().max(1) as u64;
    MAX_READ_BUDGET_BYTES
        .min(workers.saturating_mul(max_file_bytes))
        .max(max_file_bytes.min(MAX_READ_BUDGET_BYTES))
}

/// A byte budget shared by the parallel workers of one scan. Each worker
/// reserves the size of the file it is about to read before allocating its
/// buffer and releases it when it has finished with the bytes, so the sum
/// of buffers held at once never exceeds the budget. A file larger than the
/// whole budget is admitted only when nothing else is held, so it is
/// scanned alone.
#[derive(Debug)]
pub(crate) struct ReadBudget {
    capacity: u64,
    state: std::sync::Mutex<BudgetState>,
    freed: std::sync::Condvar,
}

#[derive(Debug, Default)]
struct BudgetState {
    used: u64,
    holders: usize,
    peak: u64,
}

/// Bytes reserved from a [`ReadBudget`]; released on drop.
#[derive(Debug)]
pub(crate) struct ReadPermit<'a> {
    budget: &'a ReadBudget,
    bytes: u64,
}

impl Drop for ReadPermit<'_> {
    fn drop(&mut self) {
        let mut state = self
            .budget
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.used -= self.bytes;
        state.holders -= 1;
        drop(state);
        self.budget.freed.notify_all();
    }
}

impl ReadBudget {
    pub(crate) fn new(capacity: u64) -> Self {
        Self {
            capacity: capacity.max(1),
            state: std::sync::Mutex::new(BudgetState::default()),
            freed: std::sync::Condvar::new(),
        }
    }

    /// Reserves `bytes` if it fits now (or nothing else is held).
    #[cfg(test)]
    pub(crate) fn try_acquire(&self, bytes: u64) -> Option<ReadPermit<'_>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // `then`, not `then_some`: a permit built eagerly would be dropped
        // (and release bytes it never held) while the lock is held.
        Self::admit(self.capacity, &mut state, bytes).then(|| ReadPermit {
            budget: self,
            bytes,
        })
    }

    fn admit(capacity: u64, state: &mut BudgetState, bytes: u64) -> bool {
        if state.holders > 0 && state.used.saturating_add(bytes) > capacity {
            return false;
        }
        state.used += bytes;
        state.holders += 1;
        state.peak = state.peak.max(state.used);
        true
    }

    /// Waits until `bytes` can be reserved. `None` when `cancel` is set
    /// while waiting.
    pub(crate) fn acquire(&self, bytes: u64, cancel: &AtomicBool) -> Option<ReadPermit<'_>> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            if Self::admit(self.capacity, &mut state, bytes) {
                return Some(ReadPermit {
                    budget: self,
                    bytes,
                });
            }
            state = self
                .freed
                .wait_timeout(state, std::time::Duration::from_millis(50))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// The most bytes held at once so far.
    pub(crate) fn peak(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .peak
    }
}

/// Reads a regular file whose size is `expected` (from its metadata) with
/// `budget` reserved for it, up to `max` bytes. `Err` carries the skip
/// reason; `Ok(None)` means cancelled while waiting for the budget. A file
/// that grew past its expected size while being read is skipped rather
/// than read past its reservation or scanned in part.
pub(crate) fn read_reserved<'a>(
    handle: std::fs::File,
    expected: u64,
    max: u64,
    budget: &'a ReadBudget,
    cancel: &AtomicBool,
) -> Result<Option<(Vec<u8>, ReadPermit<'a>)>, String> {
    use std::io::Read;
    let Some(permit) = budget.acquire(expected.saturating_add(1), cancel) else {
        return Ok(None);
    };
    let mut bytes = Vec::with_capacity(usize::try_from(expected).unwrap_or(0));
    handle
        .take(expected.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("unreadable: {error}"))?;
    if bytes.len() as u64 > expected {
        return Err(if expected >= max {
            format!(
                "larger than the {} MiB limit (it grew while being read)",
                max / (1024 * 1024)
            )
        } else {
            "the file grew while it was being read; it was not scanned".to_owned()
        });
    }
    Ok(Some((bytes, permit)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_read_budget_bounds_bytes_held_at_once() {
        use super::ReadBudget;
        let budget = ReadBudget::new(100);
        let a = budget.try_acquire(60).expect("fits");
        assert!(budget.try_acquire(60).is_none(), "60 + 60 > 100");
        let b = budget.try_acquire(40).expect("60 + 40 fits");
        drop(a);
        let c = budget.try_acquire(60).expect("40 + 60 fits");
        // Larger than the whole budget: only alone.
        assert!(budget.try_acquire(150).is_none());
        drop((b, c));
        let alone = budget.try_acquire(150).expect("admitted alone");
        assert!(budget.try_acquire(1).is_none(), "nothing joins it");
        drop(alone);
        assert_eq!(budget.peak(), 150);
        assert!(super::read_budget_bytes(4096) >= 4096);
        let gib = 1024 * 1024 * 1024;
        let big = super::read_budget_bytes(gib);
        assert!((gib..=super::MAX_READ_BUDGET_BYTES).contains(&big), "{big}");
    }

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
