use std::collections::BTreeSet;
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

pub struct SourceFileCollection {
    /// Canonical collection root used for stable relative paths after policy
    /// validation. Callers must use this root with the canonical file paths.
    pub root: PathBuf,
    pub files: Vec<PathBuf>,
    pub skipped: usize,
    pub total_bytes: u64,
}

impl SourceFileCollection {
    fn empty() -> Self {
        Self {
            root: PathBuf::new(),
            files: Vec::new(),
            skipped: 0,
            total_bytes: 0,
        }
    }
}

pub fn collect_files(root: &Path, options: CollectFilesOptions<'_>) -> (Vec<PathBuf>, usize, u64) {
    let collection = collect_source_files(root, options);
    (collection.files, collection.skipped, collection.total_bytes)
}

/// Collect source files under one explicit project policy boundary.
///
/// Ignore evaluation is rooted at the project boundary with `parents(false)`;
/// a second contained walk selects the requested file/subtree and canonicalizes
/// every returned path. This preserves native project/nested ignore and
/// negation semantics without consulting ignore files above the project, while
/// making later reads independent from a swapped lexical symlink alias.
pub fn collect_source_files(
    root: &Path,
    options: CollectFilesOptions<'_>,
) -> SourceFileCollection {
    let Some((project_root, collection_root)) = validated_collection_scope(
        options.project_root,
        root,
        options.include_git,
        options.follow_symlinks,
    ) else {
        return SourceFileCollection::empty();
    };

    let ignored = options.extra_ignored.to_vec();
    let filter_project_root = project_root.clone();
    let filter_ignored = ignored.clone();
    let include_git = options.include_git;
    let mut policy_builder = WalkBuilder::new(&project_root);
    policy_builder
        .hidden(false)
        .follow_links(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .require_git(false)
        .parents(false)
        .filter_entry(move |entry| {
            let is_dir = entry.file_type().is_some_and(|file_type| file_type.is_dir());
            let Ok(canonical_path) = entry.path().canonicalize() else {
                return false;
            };
            source_entry_allowed(
                entry.path(),
                &canonical_path,
                &filter_project_root,
                is_dir,
                include_git,
                &filter_ignored,
            )
        });

    let mut allowed_files = BTreeSet::new();
    for entry in policy_builder.build().flatten() {
        if !entry.file_type().is_some_and(|file_type| file_type.is_file()) {
            continue;
        }
        let Ok(canonical_path) = entry.path().canonicalize() else {
            continue;
        };
        if canonical_path.starts_with(&project_root) {
            allowed_files.insert(canonical_path);
        }
    }

    let mut files = BTreeSet::new();
    let mut skipped = 0usize;
    let walker = WalkDir::new(&collection_root)
        .follow_links(options.follow_symlinks)
        .into_iter()
        .filter_entry(|entry| {
            let is_dir = entry.file_type().is_dir();
            let Ok(canonical_path) = entry.path().canonicalize() else {
                return false;
            };
            source_entry_allowed(
                entry.path(),
                &canonical_path,
                &project_root,
                is_dir,
                options.include_git,
                &ignored,
            )
        });

    for entry in walker {
        match entry {
            Ok(entry) if entry.file_type().is_file() => {
                let Ok(canonical_path) = entry.path().canonicalize() else {
                    skipped += 1;
                    continue;
                };
                if allowed_files.contains(&canonical_path) {
                    files.insert(canonical_path);
                } else {
                    skipped += 1;
                }
            }
            Ok(_) | Err(_) => skipped += 1,
        }
    }

    let files: Vec<PathBuf> = files.into_iter().collect();
    let total_bytes = files
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok().map(|metadata| metadata.len()))
        .sum();
    SourceFileCollection {
        root: collection_root,
        files,
        skipped,
        total_bytes,
    }
}

fn validated_collection_scope(
    project_root: &Path,
    root: &Path,
    include_git: bool,
    follow_symlinks: bool,
) -> Option<(PathBuf, PathBuf)> {
    let canonical_project_root = project_root.canonicalize().ok()?;
    let canonical_collection_root = root.canonicalize().ok()?;
    if !canonical_collection_root.starts_with(&canonical_project_root)
        || (!include_git
            && (has_git_component(root)
                || has_git_component(&canonical_collection_root)
                || has_git_component(project_root)
                || has_git_component(&canonical_project_root)))
        || (!follow_symlinks && scoped_path_uses_symlink(project_root, root))
    {
        return None;
    }
    Some((canonical_project_root, canonical_collection_root))
}

fn source_entry_allowed(
    lexical_path: &Path,
    canonical_path: &Path,
    project_root: &Path,
    is_dir: bool,
    include_git: bool,
    ignored: &[String],
) -> bool {
    if !canonical_path.starts_with(project_root)
        || (!include_git
            && (has_git_component(lexical_path) || has_git_component(canonical_path)))
    {
        return false;
    }
    if !is_dir {
        return true;
    }
    let name = lexical_path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    !ALWAYS_IGNORED.contains(&name.as_ref()) && !ignored.iter().any(|ignored| ignored == &name)
}

fn scoped_path_uses_symlink(project_root: &Path, root: &Path) -> bool {
    let mut current = Some(root);
    while let Some(path) = current {
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return true;
        }
        if path == project_root {
            return false;
        }
        current = path.parent().filter(|parent| parent.starts_with(project_root));
    }
    false
}

fn has_git_component(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == ".git")
}

/// Discover dependency lockfiles with a policy independent from source scans:
/// ordinary ignore files are deliberately not consulted, `.git` is always
/// excluded, symlinks are never followed, and canonical paths must stay within
/// the explicit project boundary.
pub fn discover_lockfiles(
    project_root: &Path,
    root: &Path,
    extra_ignored: &[String],
) -> Vec<PathBuf> {
    let Some((project_root, collection_root)) =
        validated_collection_scope(project_root, root, false, false)
    else {
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    let ignored: Vec<String> = extra_ignored.to_vec();
    let walker = WalkDir::new(&collection_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(move |e| {
            let Ok(canonical_path) = e.path().canonicalize() else {
                return false;
            };
            if !canonical_path.starts_with(&project_root)
                || has_git_component(e.path())
                || has_git_component(&canonical_path)
            {
                return false;
            }
            if !e.file_type().is_dir() {
                return true;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if ALWAYS_IGNORED.contains(&name.as_str()) {
                return false;
            }
            !ignored.iter().any(|d| d == &name)
        });
    for entry in walker.flatten() {
        if entry.file_type().is_file() {
            if let Some(name) = entry.file_name().to_str() {
                if is_lockfile_name(name) {
                    if let Ok(canonical_path) = entry.path().canonicalize() {
                        out.insert(canonical_path);
                    }
                }
            }
        }
    }
    out.into_iter().collect()
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
    use super::{collect_files, discover_lockfiles, read_text_file, CollectFilesOptions};
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
        let canonical_root = root.canonicalize().unwrap();
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
            .map(|path| path.strip_prefix(&canonical_root).unwrap().to_path_buf())
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
        assert_eq!(included, [git_config.canonicalize().unwrap()]);
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
            !files.contains(&root.path().join("src/ignored.rs").canonicalize().unwrap()),
            "a nested walk must retain the project root's .gitignore rules"
        );
        assert!(
            files.contains(&root.path().join("src/main.rs").canonicalize().unwrap()),
            "nested collection files: {files:?}",
        );
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

        let files = discover_lockfiles(root.path(), root.path(), &[]);

        assert_eq!(
            files,
            [root.path().join("Cargo.lock").canonicalize().unwrap()],
        );
    }

    #[cfg(unix)]
    #[test]
    fn lexical_git_alias_to_ordinary_content_is_excluded() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("ordinary")).unwrap();
        fs::write(root.path().join("ordinary/config"), "ordinary\n").unwrap();
        symlink(root.path().join("ordinary"), root.path().join(".git")).unwrap();

        let (files, _, _) = collect_files(
            &root.path().join(".git/config"),
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: true,
                extra_ignored: &[],
            },
        );

        assert!(files.is_empty(), "lexical .git components must remain excluded");
    }

    #[test]
    fn project_boundary_preserves_nested_negation_without_parent_ignore_leakage() {
        let parent = tempfile::tempdir().unwrap();
        let project = parent.path().join("project");
        let nested = project.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            parent.path().join(".gitignore"),
            "project/nested/parent-only.txt\n",
        )
        .unwrap();
        fs::write(nested.join(".gitignore"), "*.rs\n!keep.rs\n").unwrap();
        fs::write(nested.join("drop.rs"), "drop\n").unwrap();
        fs::write(nested.join("keep.rs"), "keep\n").unwrap();
        fs::write(nested.join("parent-only.txt"), "visible\n").unwrap();

        let (files, _, _) = collect_files(
            &nested,
            CollectFilesOptions {
                project_root: &project,
                include_git: false,
                follow_symlinks: false,
                extra_ignored: &[],
            },
        );

        assert!(
            files.contains(&nested.join("keep.rs").canonicalize().unwrap()),
            "boundary collection files: {files:?}",
        );
        assert!(!files.contains(&nested.join("drop.rs").canonicalize().unwrap()));
        assert!(
            files.contains(&nested.join("parent-only.txt").canonicalize().unwrap()),
            "ignore files above the explicit project boundary must not apply",
        );
    }

    #[cfg(unix)]
    #[test]
    fn followed_internal_alias_returns_stable_canonical_paths_before_reads() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("shared")).unwrap();
        fs::write(root.path().join("shared/value.rs"), "inside\n").unwrap();
        fs::write(outside.path().join("value.rs"), "outside\n").unwrap();
        let alias = root.path().join("alias");
        symlink(root.path().join("shared"), &alias).unwrap();

        let (excluded, _, _) = collect_files(
            &alias,
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: false,
                extra_ignored: &[],
            },
        );
        let (included, _, _) = collect_files(
            &alias,
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: true,
                extra_ignored: &[],
            },
        );

        assert!(excluded.is_empty());
        assert_eq!(
            included,
            [root.path().join("shared/value.rs").canonicalize().unwrap()],
        );
        fs::remove_file(&alias).unwrap();
        symlink(outside.path(), &alias).unwrap();
        assert_eq!(read_text_file(&included[0], 1024).as_deref(), Some("inside\n"));
    }

    #[test]
    fn ordinary_direct_file_and_subdirectory_roots_use_the_same_source_policy() {
        let root = fixture();
        let direct_file = root.path().join("src/main.rs");
        let (file, _, _) = collect_files(
            &direct_file,
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: false,
                extra_ignored: &[],
            },
        );
        let (subdirectory, _, _) = collect_files(
            &root.path().join("src"),
            CollectFilesOptions {
                project_root: root.path(),
                include_git: false,
                follow_symlinks: false,
                extra_ignored: &[],
            },
        );

        let canonical_file = direct_file.canonicalize().unwrap();
        assert_eq!(file, [canonical_file.clone()]);
        assert_eq!(subdirectory, [canonical_file]);
    }

    #[test]
    fn dependency_discovery_finds_gitignored_lockfiles_but_never_direct_git_roots() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join(".gitignore"), "Cargo.lock\n").unwrap();
        fs::write(root.path().join("Cargo.lock"), "").unwrap();
        fs::write(root.path().join(".git/package-lock.json"), "{}").unwrap();

        assert_eq!(
            discover_lockfiles(root.path(), root.path(), &[]),
            [root.path().join("Cargo.lock").canonicalize().unwrap()],
        );
        assert!(discover_lockfiles(
            root.path(),
            &root.path().join(".git"),
            &[],
        )
        .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn dependency_discovery_rejects_a_symlink_root_outside_its_boundary() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("Cargo.lock"), "").unwrap();
        let alias = root.path().join("external");
        symlink(outside.path(), &alias).unwrap();

        assert!(discover_lockfiles(&alias, &alias, &[]).is_empty());
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
