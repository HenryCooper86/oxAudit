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
    /// Stable policy boundary for this walk. `root` may be a file, nested
    /// directory, or symlink within this project.
    pub project_root: &'a Path,
    pub include_git: bool,
    pub follow_symlinks: bool,
    pub extra_ignored: &'a [String],
}

pub fn collect_files(root: &Path, options: CollectFilesOptions<'_>) -> (Vec<PathBuf>, usize, u64) {
    let mut files = Vec::new();
    let mut skipped = 0usize;
    let mut total_bytes = 0u64;

    let Ok(project_root) = options.project_root.canonicalize() else {
        return (files, skipped, total_bytes);
    };
    let Ok(collection_root) = root.canonicalize() else {
        return (files, skipped, total_bytes);
    };
    if !collection_root.starts_with(&project_root)
        || (!options.include_git && is_git_metadata(&project_root, &collection_root))
        || (!options.follow_symlinks && collection_root_uses_symlink(root, &project_root))
    {
        return (files, skipped, total_bytes);
    }

    let mut builder = WalkBuilder::new(root);
    let ignored: Vec<String> = options.extra_ignored.to_vec();
    let filter_project_root = project_root.clone();
    let project_gitignore = load_project_gitignore(&project_root);
    builder
        .hidden(false)
        .follow_links(options.follow_symlinks)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .parents(true)
        .filter_entry(move |entry| {
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let Ok(canonical_path) = entry.path().canonicalize() else {
                return false;
            };
            if !canonical_path.starts_with(&filter_project_root)
                || (!options.include_git && is_git_metadata(&filter_project_root, &canonical_path))
                || project_gitignore.as_ref().is_some_and(|gitignore| {
                    gitignore
                        .matched_path_or_any_parents(&canonical_path, is_dir)
                        .is_ignore()
                })
            {
                return false;
            }
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
                    let Ok(canonical_path) = p.canonicalize() else {
                        skipped += 1;
                        continue;
                    };
                    if !canonical_path.starts_with(&project_root)
                        || (!options.include_git && is_git_metadata(&project_root, &canonical_path))
                    {
                        skipped += 1;
                        continue;
                    }
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

fn load_project_gitignore(project_root: &Path) -> Option<ignore::gitignore::Gitignore> {
    let path = project_root.join(".gitignore");
    if !path.is_file() {
        return None;
    }
    let mut builder = ignore::gitignore::GitignoreBuilder::new(project_root);
    let _ = builder.add(path);
    builder.build().ok()
}

fn collection_root_uses_symlink(root: &Path, canonical_project_root: &Path) -> bool {
    for ancestor in root.ancestors() {
        if ancestor
            .canonicalize()
            .is_ok_and(|path| path == canonical_project_root)
        {
            return false;
        }
        if ancestor
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return true;
        }
    }
    false
}

fn is_git_metadata(project_root: &Path, path: &Path) -> bool {
    path.strip_prefix(project_root)
        .ok()
        .is_some_and(|relative| {
            relative
                .components()
                .any(|component| component.as_os_str() == ".git")
        })
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
                project_root: root,
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
    fn direct_git_file_root_is_excluded_unless_git_metadata_is_enabled() {
        let root = fixture();
        let git_config = root.path().join(".git/config");

        let (excluded, _, _) = collect_files(
            &git_config,
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: false,
                extra_ignored: &[],
            },
        );
        let (included, _, _) = collect_files(
            &git_config,
            CollectFilesOptions {
                project_root: root.path(),
                include_git: true,
                follow_symlinks: false,
                extra_ignored: &[],
            },
        );

        assert!(
            excluded.is_empty(),
            "direct .git roots must obey include_git=false"
        );
        assert_eq!(included, [git_config]);
    }

    #[test]
    fn nested_collection_root_honors_project_gitignore_ancestry() {
        let root = fixture();
        fs::write(root.path().join("src/ignored.rs"), "ignored\n").unwrap();

        let (files, _, _) = collect_files(
            &root.path().join("src"),
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: false,
                extra_ignored: &[],
            },
        );

        assert!(
            !files.contains(&root.path().join("src/ignored.rs")),
            "a nested walk must retain the project root's .gitignore rules"
        );
        assert!(files.contains(&root.path().join("src/main.rs")));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_alias_to_git_metadata_cannot_bypass_exclusion() {
        use std::os::unix::fs::symlink;

        let root = fixture();
        let alias = root.path().join("metadata");
        symlink(root.path().join(".git"), &alias).unwrap();

        let (files, _, _) = collect_files(
            &alias,
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: true,
                extra_ignored: &[],
            },
        );

        assert!(
            files.is_empty(),
            "a followed alias must not conceal .git metadata"
        );
    }

    #[cfg(unix)]
    #[test]
    fn followed_symlinks_remain_contained_in_the_project_root() {
        use std::os::unix::fs::symlink;

        let root = fixture();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("outside.rs");
        fs::write(&outside_file, "outside\n").unwrap();
        symlink(outside.path(), root.path().join("external")).unwrap();
        let canonical_root = root.path().canonicalize().unwrap();

        let (files, _, _) = collect_files(
            root.path(),
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: true,
                extra_ignored: &[],
            },
        );

        assert!(
            files
                .iter()
                .all(|path| path.canonicalize().unwrap().starts_with(&canonical_root)),
            "followed symlinks must not collect files outside the project root: {files:?}"
        );
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
