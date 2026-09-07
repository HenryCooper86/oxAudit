//! Read-only Git evidence. No status/diff worktree commands: those can run clean
//! filters. Paths come from NUL-delimited index/tree records, never pathspecs.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitSnapshot {
    pub branch: Option<String>,
    pub head: String,
    pub index_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitEvidence {
    pub before: Option<GitSnapshot>,
    pub after: Option<GitSnapshot>,
    pub context_changed: Option<bool>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitContext {
    pub target: String,
    pub snapshot: GitSnapshot,
    pub base_reference: String,
    pub base_commit: String,
    pub changed_paths: Vec<String>,
    pub staged_paths: Vec<String>,
    pub unstaged_paths: Vec<String>,
    pub partially_staged: bool,
    pub inspected_at: String,
}
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MAX_OUTPUT: u64 = 16 * 1024 * 1024;
const MAX_FILE: u64 = 16 * 1024 * 1024;
const MAX_BYTES: u64 = 128 * 1024 * 1024;
const MAX_PATHS: usize = 100_000;
const TIMEOUT: Duration = Duration::from_secs(10);
const UNAVAILABLE: &str = "Git context unavailable: not a supported local checkout, invalid base, changed context, or inspection limit reached. Normal full scans remain available.";

struct Git {
    root: PathBuf,
    deadline: Instant,
}
impl Git {
    fn run(&self, args: &[&str]) -> Result<Vec<u8>, String> {
        if Instant::now() >= self.deadline {
            return Err(UNAVAILABLE.into());
        }
        // Clear GIT_DIR/WORK_TREE/INDEX_FILE, injected config and alternate object
        // stores. Only object/index plumbing is allowed here. In particular never
        // add status, diff-files, checkout, or hash-object without --no-filters.
        let mut command = Command::new("git");
        command.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            command.env("PATH", path);
        }
        // Windows process loading needs these OS directories. Preserve only
        // this narrow OS allowlist, never inherited Git configuration/paths.
        #[cfg(windows)]
        for key in ["SystemRoot", "WINDIR"] {
            if let Some(value) = std::env::var_os(key) {
                command.env(key, value);
            }
        }
        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_LITERAL_PATHSPECS", "1")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .current_dir(&self.root)
            .args([
                "--no-pager",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "protocol.allow=never",
                "-c",
                "diff.external=",
                "-c",
                "core.pager=cat",
            ])
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let mut child = command.spawn().map_err(|_| UNAVAILABLE.to_owned())?;
        let stdout = child.stdout.take().ok_or(UNAVAILABLE)?;
        // A bounded reader drains concurrently so pipe capacity cannot deadlock.
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take(MAX_OUTPUT + 1)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if Instant::now() < self.deadline => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let bytes = reader
            .join()
            .map_err(|_| UNAVAILABLE)?
            .map_err(|_| UNAVAILABLE)?;
        if !status.is_some_and(|status| status.success()) || bytes.len() as u64 > MAX_OUTPUT {
            return Err(UNAVAILABLE.into());
        }
        Ok(bytes)
    }
    fn text(&self, args: &[&str]) -> Result<String, String> {
        let bytes = self.run(args)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| UNAVAILABLE)?;
        Ok(text.strip_suffix('\n').unwrap_or(text).to_owned())
    }
    fn resolve(&self, reference: &str) -> Result<String, String> {
        if reference.is_empty()
            || reference.len() > 256
            || reference.starts_with('-')
            || reference
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(UNAVAILABLE.into());
        }
        let oid = self.text(&[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{reference}^{{commit}}"),
        ])?;
        valid_oid(&oid)?;
        Ok(oid)
    }
    fn snapshot(&self) -> Result<GitSnapshot, String> {
        let head = self.resolve("HEAD")?;
        let branch = self
            .text(&["symbolic-ref", "--quiet", "--short", "HEAD"])
            .ok();
        let index = self.run(&["ls-files", "--stage", "--debug", "-z", "--"])?;
        Ok(GitSnapshot {
            branch,
            head,
            index_digest: format!("{:x}", Sha256::digest(index)),
        })
    }
}
fn discover(target: &Path) -> Result<(Git, PathBuf), String> {
    let target = target.canonicalize().map_err(|_| UNAVAILABLE)?;
    if !target.is_dir() {
        return Err(UNAVAILABLE.into());
    }
    let mut git = Git {
        root: target.clone(),
        deadline: Instant::now() + TIMEOUT,
    };
    let root = PathBuf::from(git.text(&["rev-parse", "--show-toplevel"])?)
        .canonicalize()
        .map_err(|_| UNAVAILABLE)?;
    let prefix = target
        .strip_prefix(&root)
        .map_err(|_| UNAVAILABLE)?
        .to_path_buf();
    git.root = root;
    Ok((git, prefix))
}
fn valid_oid(oid: &str) -> Result<(), String> {
    if matches!(oid.len(), 40 | 64) && oid.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(UNAVAILABLE.into())
    }
}
fn relative_path(path: &str) -> Result<PathBuf, String> {
    let result = PathBuf::from(path);
    if path.is_empty()
        || path.contains('\\')
        || result
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(value) if !value.to_string_lossy().eq_ignore_ascii_case(".git")))
    {
        return Err(UNAVAILABLE.into());
    }
    Ok(result)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    mode: String,
    oid: String,
}
type Entries = BTreeMap<String, Entry>;
fn entries(bytes: &[u8], index: bool) -> Result<Entries, String> {
    if !bytes.is_empty() && bytes.last() != Some(&0) {
        return Err(UNAVAILABLE.into());
    }
    let mut result = Entries::new();
    for record in bytes.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let text = std::str::from_utf8(record).map_err(|_| UNAVAILABLE)?;
        let (header, path) = text.split_once('\t').ok_or(UNAVAILABLE)?;
        relative_path(path)?;
        let fields: Vec<_> = header.split(' ').collect();
        if fields.len() != 3 || (index && fields[2] != "0") || (!index && fields[1] != "blob") {
            return Err(UNAVAILABLE.into());
        }
        let oid = if index { fields[1] } else { fields[2] };
        valid_oid(oid)?;
        if !matches!(fields[0], "100644" | "100755") {
            return Err(UNAVAILABLE.into());
        }
        if result
            .insert(
                path.to_owned(),
                Entry {
                    mode: fields[0].into(),
                    oid: oid.into(),
                },
            )
            .is_some()
            || result.len() > MAX_PATHS
        {
            return Err(UNAVAILABLE.into());
        }
    }
    Ok(result)
}
fn tree(git: &Git, oid: &str) -> Result<Entries, String> {
    valid_oid(oid)?;
    entries(
        &git.run(&["ls-tree", "-r", "-z", "--full-tree", oid, "--"])?,
        false,
    )
}
fn changed(left: &Entries, right: &Entries) -> BTreeSet<String> {
    left.keys()
        .chain(right.keys())
        .filter(|path| left.get(*path) != right.get(*path))
        .cloned()
        .collect()
}
fn raw_entry(
    git: &Git,
    path: &str,
    hash_len: usize,
    total: &mut u64,
) -> Result<Option<Entry>, String> {
    raw_entry_with_open(git, path, hash_len, total, open_raw_file)
}

// The injected open boundary lets regression tests replace an entry after all
// pathname checks and exercise the same actual-handle validation used in scans.
fn raw_entry_with_open(
    git: &Git,
    path: &str,
    hash_len: usize,
    total: &mut u64,
    open: impl FnOnce(&Path, &Path) -> std::io::Result<std::fs::File>,
) -> Result<Option<Entry>, String> {
    let relative = relative_path(path)?;
    let mut absolute = git.root.clone();
    for component in relative.components() {
        absolute.push(component);
        match std::fs::symlink_metadata(&absolute) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(UNAVAILABLE.into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(UNAVAILABLE.into()),
            _ => (),
        }
    }
    let metadata = std::fs::metadata(&absolute).map_err(|_| UNAVAILABLE)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE || Instant::now() >= git.deadline {
        return Err(UNAVAILABLE.into());
    }
    *total = total.saturating_add(metadata.len());
    if *total > MAX_BYTES {
        return Err(UNAVAILABLE.into());
    }
    // Recheck containment immediately before opening; never intentionally read
    // symlink targets. Non-atomic concurrent edits are disclosed in the UI.
    if !absolute
        .canonicalize()
        .map_err(|_| UNAVAILABLE)?
        .starts_with(&git.root)
    {
        return Err(UNAVAILABLE.into());
    }
    let file = open(&git.root, &relative).map_err(|_| UNAVAILABLE)?;
    let opened_metadata = file.metadata().map_err(|_| UNAVAILABLE)?;
    if !opened_metadata.is_file() || opened_metadata.len() != metadata.len() {
        return Err(UNAVAILABLE.into());
    }
    let metadata = opened_metadata;
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| UNAVAILABLE)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > MAX_FILE {
        return Err(UNAVAILABLE.into());
    }
    let header = format!("blob {}\0", bytes.len());
    let oid = if hash_len == 40 {
        let mut digest = sha1::Sha1::new();
        digest.update(header.as_bytes());
        digest.update(&bytes);
        format!("{:x}", digest.finalize())
    } else {
        let mut digest = Sha256::new();
        digest.update(header.as_bytes());
        digest.update(&bytes);
        format!("{:x}", digest.finalize())
    };
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    Ok(Some(Entry {
        mode: if executable { "100755" } else { "100644" }.into(),
        oid,
    }))
}

// Walk each component through directory handles on Unix. This closes the
// symlink-swap gap between containment checks and the raw byte read. NONBLOCK
// also prevents a concurrent replacement with a FIFO from hanging inspection.
#[cfg(unix)]
pub(crate) fn open_raw_file(root: &Path, relative: &Path) -> std::io::Result<std::fs::File> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::OpenOptionsExt},
        },
    };
    let mut directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_os_str().as_bytes())?;
        let last = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | libc::O_NONBLOCK
            | if last { 0 } else { libc::O_DIRECTORY };
        // SAFETY: name is NUL-terminated; directory owns the live parent fd.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: openat returned a new owned descriptor, transferred once.
        directory = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    if !directory.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(directory)
}
#[cfg(windows)]
#[path = "git_context_windows.rs"]
mod windows;
#[cfg(windows)]
pub(crate) fn open_raw_file(root: &Path, relative: &Path) -> std::io::Result<std::fs::File> {
    windows::open_raw_file(root, relative)
}
#[cfg(not(any(unix, windows)))]
pub(crate) fn open_raw_file(_root: &Path, _relative: &Path) -> std::io::Result<std::fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe Git raw reads are unavailable on this platform",
    ))
}

fn paths_overlap(left: &[String], right: &[String]) -> bool {
    let right: BTreeSet<_> = right.iter().collect();
    left.iter().any(|path| right.contains(path))
}

pub fn snapshot(target: &Path) -> Result<GitSnapshot, String> {
    discover(target)?.0.snapshot()
}

pub fn inspect(target: &Path, reference: &str) -> Result<GitContext, String> {
    let (git, prefix) = discover(target)?;
    let before = git.snapshot()?;
    let requested = git.resolve(reference)?;
    let base_commit = git.text(&["merge-base", &before.head, &requested])?;
    valid_oid(&base_commit)?;
    let head = tree(&git, &before.head)?;
    let base = tree(&git, &base_commit)?;
    let index = entries(&git.run(&["ls-files", "--stage", "-z", "--"])?, true)?;
    let untracked = git.run(&["ls-files", "--others", "--exclude-standard", "-z", "--"])?;
    let mut paths: BTreeSet<String> = head
        .keys()
        .chain(index.keys())
        .chain(base.keys())
        .cloned()
        .collect();
    for record in untracked.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let path = std::str::from_utf8(record).map_err(|_| UNAVAILABLE)?;
        relative_path(path)?;
        paths.insert(path.into());
    }
    if paths.len() > MAX_PATHS {
        return Err(UNAVAILABLE.into());
    }
    let mut worktree = Entries::new();
    let mut bytes = 0;
    // Only the selected scan target is read; no Git pathspec ever receives a
    // user's path. Names containing wildcard/pathspec syntax stay literal.
    for path in paths.iter().filter(|p| Path::new(p).starts_with(&prefix)) {
        if let Some(entry) = raw_entry(&git, path, before.head.len(), &mut bytes)? {
            worktree.insert(path.clone(), entry);
        }
    }
    let select = |paths: BTreeSet<String>| -> Vec<String> {
        paths
            .into_iter()
            .filter_map(|path| {
                Path::new(&path)
                    .strip_prefix(&prefix)
                    .ok()
                    .map(|p| p.to_string_lossy().replace('\\', "/"))
            })
            .collect()
    };
    let staged_paths = select(changed(&head, &index));
    let unstaged_paths = select(changed(&index, &worktree));
    // Include staged intent as well as current differences, even a staged edit
    // subsequently reverted in the working tree. This remains a path view.
    let mut changes = changed(&base, &worktree);
    changes.extend(changed(&head, &index));
    let changed_paths = select(changes);
    let partially_staged = paths_overlap(&staged_paths, &unstaged_paths);
    if git.snapshot()? != before {
        return Err(UNAVAILABLE.into());
    }
    Ok(GitContext {
        target: git.root.join(prefix).to_string_lossy().into(),
        snapshot: before,
        base_reference: reference.into(),
        base_commit,
        changed_paths,
        staged_paths,
        unstaged_paths,
        partially_staged,
        inspected_at: chrono::Utc::now().to_rfc3339(),
    })
}

#[cfg(test)]
#[path = "git_context_tests.rs"]
pub(crate) mod tests;
