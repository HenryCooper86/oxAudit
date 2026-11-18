//! Reading a signature pack from a file, a folder, or a `.zip`.
//!
//! The reader is deliberately strict because pack content is untrusted:
//! symlinks are never followed, zip members must stay inside the archive
//! root, every limit is enforced on bytes actually read (not on declared
//! sizes), and nothing is executed or interpreted here.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Component, Path};

use unicode_normalization::UnicodeNormalization;

use super::license::{detect_license, is_license_file_name};
use super::{PackKind, PackSkip};

/// Most accepted rule files in one pack.
pub const MAX_FILES: usize = 20_000;
/// Largest accepted rule file.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
/// Most accepted rule bytes in one pack.
pub const MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
/// Most directory entries or archive members examined, accepted or not. A
/// hostile archive of millions of empty members must not stall an import.
pub const MAX_ENTRIES: usize = 200_000;

/// One accepted rule file, in memory.
#[derive(Debug, Clone)]
pub struct PackFile {
    /// Forward-slash path relative to the pack root.
    pub path: String,
    pub text: String,
}

/// Everything read from an import source.
#[derive(Debug, Default)]
pub struct CollectedPack {
    pub files: Vec<PackFile>,
    /// Files that were not rule files for this kind (counted, not stored).
    pub ignored: usize,
    /// Rule-extension files left out, with the reason (for example not UTF-8).
    pub skipped: Vec<PackSkip>,
    pub total_bytes: u64,
    pub detected_license: Option<String>,
}

const COMPILED_MAGIC: &[u8] = b"YARA";

const COMPILED_REFUSAL: &str = "is a compiled YARA rules file (libyara or YARA-X); compiled rules cannot be imported because oxAudit cannot inspect or verify what they contain. Import the source rules (.yar or .yara) instead";

fn extension_accepted(kind: PackKind, name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    kind.extensions()
        .iter()
        .any(|ext| lower.ends_with(&format!(".{ext}")))
}

fn is_compiled_name(kind: PackKind, name: &str) -> bool {
    kind == PackKind::Yara && name.to_ascii_lowercase().ends_with(".yarc")
}

/// Read a pack from `source`: a single file, a directory, or a `.zip`.
pub fn collect(kind: PackKind, source: &Path) -> Result<CollectedPack, String> {
    let meta = std::fs::symlink_metadata(source)
        .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symbolic link; symbolic links are not followed, pass the real path",
            source.display()
        ));
    }
    let mut builder = Builder::new(kind);
    if meta.is_dir() {
        collect_dir(&mut builder, source)?;
    } else if meta.is_file() {
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| "the file name is not valid UTF-8".to_owned())?;
        if name.to_ascii_lowercase().ends_with(".zip") {
            collect_zip(&mut builder, source)?;
        } else if extension_accepted(kind, name) || is_compiled_name(kind, name) {
            let bytes = read_bounded(source, MAX_FILE_BYTES, name)?;
            builder.accept(name, bytes)?;
        } else {
            return Err(format!(
                "{name} is not a {} file; expected {}, a folder, or a .zip",
                kind.as_str(),
                kind.extensions()
                    .iter()
                    .map(|e| format!(".{e}"))
                    .collect::<Vec<_>>()
                    .join(" / ")
            ));
        }
    } else {
        return Err(format!(
            "{} is neither a file nor a folder",
            source.display()
        ));
    }
    builder.finish()
}

fn read_bounded(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("cannot read {label}: {error}"))?;
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {label}: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "{label} is larger than the {limit}-byte per-file limit"
        ));
    }
    Ok(bytes)
}

fn collect_dir(builder: &mut Builder, root: &Path) -> Result<(), String> {
    let walker = walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|entry| !(entry.depth() > 0 && entry.file_name() == ".git"));
    let mut seen = 0usize;
    for entry in walker {
        let entry = entry.map_err(|error| format!("cannot read the folder: {error}"))?;
        if entry.depth() == 0 {
            continue;
        }
        seen += 1;
        if seen > MAX_ENTRIES {
            return Err(format!(
                "the folder holds more than {MAX_ENTRIES} entries; import a smaller pack"
            ));
        }
        let file_type = entry.file_type();
        if file_type.is_dir() {
            continue;
        }
        if !file_type.is_file() {
            // Symlinks and special files: never followed, never read.
            builder.ignored += 1;
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            builder.ignored += 1;
            continue;
        };
        let Some(relative) = normal_relative(relative) else {
            builder.ignored += 1;
            continue;
        };
        let name = relative.rsplit('/').next().unwrap_or(&relative).to_owned();
        if builder.wants(&relative, &name) {
            let size = entry
                .metadata()
                .map_err(|error| format!("cannot read {relative}: {error}"))?
                .len();
            if size > MAX_FILE_BYTES {
                if extension_accepted(builder.kind, &name) {
                    return Err(format!(
                        "{relative} is {size} bytes, over the {MAX_FILE_BYTES}-byte per-file limit"
                    ));
                }
                builder.ignored += 1;
                continue;
            }
            let bytes = read_bounded(entry.path(), MAX_FILE_BYTES, &relative)?;
            builder.accept_at(&relative, &name, bytes)?;
        } else {
            builder.ignored += 1;
        }
    }
    Ok(())
}

/// Forward-slash relative path made only of normal components.
fn normal_relative(path: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_str()?.to_owned()),
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// Test hook: read a `.zip` with smaller limits and report how many members
/// were decompressed, so a test can prove the limits stop the read early.
#[cfg(test)]
pub(super) fn collect_zip_with_limits(
    kind: PackKind,
    path: &Path,
    max_files: usize,
    max_total_bytes: u64,
) -> (Result<CollectedPack, String>, usize) {
    let mut builder = Builder::new(kind);
    builder.max_files = max_files;
    builder.max_total_bytes = max_total_bytes;
    let result = collect_zip(&mut builder, path);
    let read = builder.members_read;
    (result.and_then(|()| builder.finish()), read)
}

fn collect_zip(builder: &mut Builder, path: &Path) -> Result<(), String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("cannot read the archive: {error}"))?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))
        .map_err(|error| format!("the archive is not a readable zip: {error}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(format!(
            "the archive holds {} members, over the limit of {MAX_ENTRIES}",
            archive.len()
        ));
    }
    // Members are gathered first so a single top-level folder (the shape of
    // a GitHub download) can be stripped from every path consistently.
    // The pack limits are enforced while reading, on the bytes held so far
    // (rule files and licence candidates), so a zip of many small members
    // that decompress to a megabyte each is refused at the limit instead of
    // being inflated into memory first.
    let mut members: Vec<(String, Option<Vec<u8>>)> = Vec::new();
    let mut held_bytes = 0u64;
    let mut rule_members = 0usize;
    for index in 0..archive.len() {
        let mut member = archive
            .by_index(index)
            .map_err(|error| format!("archive member {index} is unreadable: {error}"))?;
        let name = member
            .name()
            .map_err(|error| format!("archive member {index} has an unreadable name: {error}"))?
            .into_owned();
        let Some(enclosed) = member.enclosed_name() else {
            return Err(format!(
                "archive member {name:?} escapes the archive root; refusing the archive"
            ));
        };
        if member.is_dir() {
            continue;
        }
        let Some(relative) = normal_relative(&enclosed) else {
            return Err(format!(
                "archive member {name:?} has an unusable path; refusing the archive"
            ));
        };
        let is_symlink = member
            .unix_mode()
            .is_some_and(|mode| mode & 0o170_000 == 0o120_000);
        if is_symlink {
            members.push((relative, None));
            continue;
        }
        let leaf = relative.rsplit('/').next().unwrap_or(&relative).to_owned();
        // Whether a member is read depends on its stripped path, which is
        // not known yet; rule files and licence candidates at depth one or
        // two are read (bounded) and everything else is only counted.
        let read_it = extension_accepted(builder.kind, &leaf)
            || is_compiled_name(builder.kind, &leaf)
            || (is_license_file_name(&leaf) && relative.matches('/').count() <= 1);
        if !read_it {
            members.push((relative, None));
            continue;
        }
        let is_rule =
            extension_accepted(builder.kind, &leaf) || is_compiled_name(builder.kind, &leaf);
        if is_rule {
            rule_members += 1;
            if rule_members > builder.max_files {
                return Err(builder.too_many_files());
            }
        }
        if member.size() > MAX_FILE_BYTES {
            // The declared size is advisory; the bounded read below is the
            // real limit. A rule file declared too large is refused now.
            if extension_accepted(builder.kind, &leaf) {
                return Err(format!(
                    "{relative} is {} bytes, over the {MAX_FILE_BYTES}-byte per-file limit",
                    member.size()
                ));
            }
            members.push((relative, None));
            continue;
        }
        let mut bytes = Vec::new();
        builder.members_read += 1;
        member
            .by_ref()
            .take(MAX_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("archive member {name:?} is unreadable: {error}"))?;
        held_bytes += bytes.len() as u64;
        if held_bytes > builder.max_total_bytes {
            return Err(builder.too_many_bytes());
        }
        if bytes.len() as u64 > MAX_FILE_BYTES {
            if extension_accepted(builder.kind, &leaf) {
                return Err(format!(
                    "{relative} is over the {MAX_FILE_BYTES}-byte per-file limit"
                ));
            }
            members.push((relative, None));
            continue;
        }
        members.push((relative, Some(bytes)));
    }

    let strip = single_top_level(&members);
    let mut seen = BTreeMap::new();
    for (relative, bytes) in members {
        let relative = match &strip {
            Some(prefix) => relative[prefix.len() + 1..].to_owned(),
            None => relative,
        };
        if seen.insert(relative.clone(), ()).is_some() {
            return Err(format!("the archive lists {relative} more than once"));
        }
        let name = relative.rsplit('/').next().unwrap_or(&relative).to_owned();
        match bytes {
            Some(bytes) => {
                if builder.wants(&relative, &name) {
                    builder.accept_at(&relative, &name, bytes)?;
                } else if !relative.contains('/') && is_license_file_name(&name) {
                    builder.note_license(&bytes);
                    builder.ignored += 1;
                } else {
                    builder.ignored += 1;
                }
            }
            None => builder.ignored += 1,
        }
    }
    Ok(())
}

/// The single top-level folder every member lives in, when there is one.
fn single_top_level(members: &[(String, Option<Vec<u8>>)]) -> Option<String> {
    let first = members.first()?.0.split('/').next()?.to_owned();
    let all_inside = members
        .iter()
        .all(|(path, _)| path.split_once('/').is_some_and(|(top, _)| top == first));
    all_inside.then_some(first)
}

struct Builder {
    kind: PackKind,
    files: BTreeMap<String, PackFile>,
    /// Accepted paths folded the way a case- and normalisation-insensitive
    /// filesystem (macOS, Windows) compares them, to the original path.
    folded: BTreeMap<String, String>,
    ignored: usize,
    skipped: Vec<PackSkip>,
    total_bytes: u64,
    license: Option<String>,
    max_files: usize,
    max_total_bytes: u64,
    /// Archive members decompressed so far (tests assert on it).
    members_read: usize,
}

/// A path folded for collision detection: NFC, then lower case. Two pack
/// paths with the same fold would overwrite each other when the pack is
/// written to a case-insensitive or normalisation-insensitive filesystem.
fn fold_path(path: &str) -> String {
    path.nfc().collect::<String>().to_lowercase()
}

impl Builder {
    fn new(kind: PackKind) -> Self {
        Self {
            kind,
            files: BTreeMap::new(),
            folded: BTreeMap::new(),
            ignored: 0,
            skipped: Vec::new(),
            total_bytes: 0,
            license: None,
            max_files: MAX_FILES,
            max_total_bytes: MAX_TOTAL_BYTES,
            members_read: 0,
        }
    }

    fn too_many_files(&self) -> String {
        format!(
            "the pack holds more than {} rule files; import a smaller pack",
            self.max_files
        )
    }

    fn too_many_bytes(&self) -> String {
        format!(
            "the pack's rule files exceed {} bytes in total",
            self.max_total_bytes
        )
    }

    /// Whether this file should be read as a rule file (or a licence at the
    /// pack root, which is read for detection only).
    fn wants(&self, relative: &str, name: &str) -> bool {
        extension_accepted(self.kind, name)
            || is_compiled_name(self.kind, name)
            || (!relative.contains('/') && is_license_file_name(name))
    }

    fn note_license(&mut self, bytes: &[u8]) {
        if self.license.is_none() {
            if let Ok(text) = std::str::from_utf8(bytes) {
                self.license = detect_license(text);
            }
        }
    }

    fn accept(&mut self, name: &str, bytes: Vec<u8>) -> Result<(), String> {
        self.accept_at(name, name, bytes)
    }

    fn accept_at(&mut self, relative: &str, name: &str, bytes: Vec<u8>) -> Result<(), String> {
        if !extension_accepted(self.kind, name) && !is_compiled_name(self.kind, name) {
            // A root-level licence file read for detection.
            self.note_license(&bytes);
            self.ignored += 1;
            return Ok(());
        }
        if self.kind == PackKind::Yara
            && (is_compiled_name(self.kind, name) || bytes.starts_with(COMPILED_MAGIC))
        {
            return Err(format!("{relative} {COMPILED_REFUSAL}"));
        }
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                self.skipped.push(PackSkip {
                    file: relative.to_owned(),
                    line: None,
                    message: "skipped: the file is not valid UTF-8".into(),
                });
                return Ok(());
            }
        };
        if self.files.len() >= self.max_files {
            return Err(self.too_many_files());
        }
        self.total_bytes += text.len() as u64;
        if self.total_bytes > self.max_total_bytes {
            return Err(self.too_many_bytes());
        }
        if let Some(other) = self.folded.insert(fold_path(relative), relative.to_owned()) {
            if other != relative {
                return Err(format!(
                    "the pack holds both {other} and {relative}, which are the same file on a case-insensitive or Unicode-normalising filesystem (macOS, Windows); rename one and import again"
                ));
            }
        }
        self.files.insert(
            relative.to_owned(),
            PackFile {
                path: relative.to_owned(),
                text,
            },
        );
        Ok(())
    }

    fn finish(self) -> Result<CollectedPack, String> {
        if self.files.is_empty() {
            let reasons = if self.skipped.is_empty() {
                String::new()
            } else {
                format!(
                    " ({} file(s) were skipped: {})",
                    self.skipped.len(),
                    self.skipped[0].message
                )
            };
            return Err(format!(
                "no {} rule files were found{reasons}; expected {}",
                self.kind.as_str(),
                self.kind
                    .extensions()
                    .iter()
                    .map(|e| format!(".{e}"))
                    .collect::<Vec<_>>()
                    .join(" / ")
            ));
        }
        Ok(CollectedPack {
            files: self.files.into_values().collect(),
            ignored: self.ignored,
            skipped: self.skipped,
            total_bytes: self.total_bytes,
            detected_license: self.license,
        })
    }
}
