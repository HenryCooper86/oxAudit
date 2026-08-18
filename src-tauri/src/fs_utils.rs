use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use walkdir::WalkDir;

/// Directories that are always skipped when walking source trees,
/// regardless of the user-configured ignore list.
const ALWAYS_IGNORED: &[&str] = &[".hg", ".svn", ".DS_Store"];

/// File extensions we treat as "known text-ish" to short-circuit binary sniffing
/// for files we know we want to scan. Empty extension means "sniff content".
pub fn is_binary(bytes: &[u8]) -> bool {
    // Check the first 8KB for a NUL byte — strong binary indicator.
    let probe = &bytes[..bytes.len().min(8192)];
    probe.contains(&0)
}

/// Detect a human-readable language name from a file extension (for source patterns).
pub fn detect_language(path: &Path) -> Option<&'static str> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let lang = match ext.as_str() {
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" => "javascript",
        "py" | "pyw" => "python",
        "java" => "java",
        "go" => "go",
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" | "hh" | "hxx" => "cpp",
        "php" | "phtml" => "php",
        "rb" => "ruby",
        "rs" => "rust",
        "sql" => "sql",
        "cs" => "csharp",
        "kt" | "kts" => "kotlin",
        "swift" => "swift",
        "sh" | "bash" | "zsh" => "shell",
        "ps1" => "powershell",
        "pl" | "pm" => "perl",
        "lua" => "lua",
        "r" => "r",
        "dart" => "dart",
        "scala" => "scala",
        "groovy" => "groovy",
        "clj" | "cljs" => "clojure",
        "ex" | "exs" => "elixir",
        "erl" | "hrl" => "erlang",
        "hs" => "haskell",
        "ml" | "mli" => "ocaml",
        "vb" | "vbs" => "vb",
        "pas" => "pascal",
        "f" | "f90" | "f95" => "fortran",
        _ => return None,
    };
    Some(lang)
}

/// Whether a filename is one of the lockfiles / manifest files we parse for
/// dependency scanning.
pub fn is_lockfile_name(name: &str) -> bool {
    matches!(
        name,
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "Cargo.lock"
            | "go.sum"
            | "Pipfile.lock"
            | "Gemfile.lock"
            | "composer.lock"
            | "pom.xml"
            | "requirements.txt"
    )
}

/// Collect candidate files under `root`, applying ignore rules.
///
/// The named policy keeps `.git` inclusion distinct from ordinary git-ignore
/// handling at every call site.
///
/// Returns (files, skipped_count, total_bytes).
pub struct CollectFilesOptions<'a> {
    pub include_git: bool,
    pub follow_symlinks: bool,
    pub extra_ignored: &'a [String],
}

pub fn collect_files(
    root: &Path,
    options: CollectFilesOptions<'_>,
) -> (Vec<PathBuf>, usize, u64) {
    let mut files = Vec::new();
    let mut skipped = 0usize;
    let mut total_bytes = 0u64;

    let mut builder = WalkBuilder::new(root);
    let ignored: Vec<String> = options.extra_ignored.to_vec();
    builder
        .hidden(false)
        .follow_links(options.follow_symlinks)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .parents(false)
        .filter_entry(move |entry| {
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir {
                return true;
            }
            let name = entry.file_name().to_string_lossy();
            if name == ".git" {
                return options.include_git;
            }
            if ALWAYS_IGNORED.contains(&name.as_ref()) {
                return false;
            }
            !ignored.iter().any(|d| d == &name)
        });

    for entry in builder.build() {
        match entry {
            Ok(e) => {
                let ft = e.file_type();
                if ft.map(|t| t.is_file()).unwrap_or(false) {
                    let p = e.path().to_path_buf();
                    if let Ok(meta) = std::fs::metadata(&p) {
                        total_bytes += meta.len();
                    }
                    files.push(p);
                } else {
                    skipped += 1;
                }
            }
            Err(_) => skipped += 1,
        }
    }
    (files, skipped, total_bytes)
}

/// Collect lockfiles under `root`, skipping vendor trees so we don't descend
/// into node_modules etc. Reuses the standard ignore dirs.
pub fn collect_lockfiles(root: &Path, extra_ignored: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let ignored: Vec<String> = extra_ignored.to_vec();
    let walker = WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(move |e| {
            if !e.file_type().is_dir() {
                return true;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if name == ".git" || ALWAYS_IGNORED.contains(&name.as_str()) {
                return false;
            }
            !ignored.iter().any(|d| d == &name)
        });
    for entry in walker.flatten() {
        if entry.file_type().is_file() {
            if let Some(name) = entry.file_name().to_str() {
                if is_lockfile_name(name) {
                    out.push(entry.path().to_path_buf());
                }
            }
        }
    }
    out
}

/// Read a file's contents as a lossy UTF-8 string, returning None if it is
/// binary or larger than `max_bytes`.
pub fn read_text_file(path: &Path, max_bytes: u64) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > max_bytes {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    if is_binary(&bytes) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Build a sorted vector of line-start byte offsets for `content`.
pub fn line_starts(content: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(content.len() / 40 + 1);
    starts.push(0);
    for (i, b) in content.bytes().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

#[cfg(test)]
mod tests {
    use super::{collect_files, CollectFilesOptions};
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
        let (files, _, _) = collect_files(
            root,
            CollectFilesOptions {
                include_git,
                follow_symlinks: false,
                extra_ignored: &[],
            },
        );
        files
            .into_iter()
            .map(|path| path.strip_prefix(root).unwrap().to_path_buf())
            .collect()
    }

    #[test]
    fn include_git_toggle_controls_the_git_metadata_directory() {
        let root = fixture();

        let excluded = relative_files(root.path(), false);
        let included = relative_files(root.path(), true);

        assert!(!excluded.contains(&PathBuf::from(".git/config")));
        assert!(
            included.contains(&PathBuf::from(".git/config")),
            "Include .git must make metadata files available to the scan"
        );
    }

    #[test]
    fn gitignore_remains_respected_for_both_metadata_toggle_states() {
        let root = fixture();

        for include_git in [false, true] {
            assert!(
                !relative_files(root.path(), include_git)
                    .contains(&PathBuf::from("ignored.rs")),
                "Include .git must not invert ordinary .gitignore behavior"
            );
        }
    }

    #[test]
    fn lockfile_discovery_never_descends_into_git_metadata() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".git")).unwrap();
        fs::write(root.path().join("Cargo.lock"), "").unwrap();
        fs::write(root.path().join(".git/package-lock.json"), "{}").unwrap();

        let files = super::collect_lockfiles(root.path(), &[]);

        assert_eq!(files, [root.path().join("Cargo.lock")]);
    }
}

/// Given a byte offset and the line-start index, return (1-based line, 1-based column).
pub fn line_col(starts: &[usize], offset: usize) -> (usize, usize) {
    let idx = match starts.binary_search(&offset) {
        Ok(i) => i,
        Err(i) => i - 1,
    };
    (idx + 1, offset - starts[idx] + 1)
}

/// Extract `radius` lines around `line_index` (0-based) from the content.
pub fn context_lines(content: &str, starts: &[usize], line_index: usize, radius: usize) -> String {
    if starts.is_empty() {
        return String::new();
    }
    let first = line_index.saturating_sub(radius);
    let last = (line_index + radius).min(starts.len() - 1);
    let mut out = String::new();
    for i in first..=last {
        let start = starts[i];
        let end = starts.get(i + 1).copied().unwrap_or(content.len());
        let line = &content[start..end.min(content.len())];
        let trimmed = line.trim_end_matches(['\n', '\r']);
        out.push_str(&format!("{:>5} │ {}\n", i + 1, trimmed));
    }
    out
}

/// Turn a relative display path into a cross-platform string.
pub fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
