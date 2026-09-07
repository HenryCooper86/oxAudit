use super::*;
use std::{fs, process::Command};

pub(crate) fn git(root: &Path, args: &[&str]) -> String {
    let mut command = Command::new("git");
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default());
    #[cfg(windows)]
    for key in ["SystemRoot", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let result = command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .args([
            "-c",
            "commit.gpgSign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}
fn repository() -> tempfile::TempDir {
    let temp = tempfile::tempdir().unwrap();
    git(temp.path(), &["init", "-b", "main"]);
    git(
        temp.path(),
        &["config", "user.email", "test@example.invalid"],
    );
    git(temp.path(), &["config", "user.name", "Test"]);
    fs::create_dir(temp.path().join("src")).unwrap();
    fs::write(temp.path().join("src/app.js"), "one\n").unwrap();
    git(temp.path(), &["add", "."]);
    git(temp.path(), &["commit", "-m", "initial"]);
    temp
}

#[test]
fn staged_and_unstaged_paths_use_working_tree_and_handle_partial_staging() {
    let temp = repository();
    let root = temp.path();
    fs::write(root.join("src/app.js"), "two\n").unwrap();
    git(root, &["add", "."]);
    fs::write(root.join("src/app.js"), "three\n").unwrap();
    fs::write(root.join("src/new file.js"), "new\n").unwrap();
    let context = inspect(&root.join("src"), "HEAD").unwrap();
    assert_eq!(context.staged_paths, vec!["app.js"]);
    assert_eq!(context.unstaged_paths, vec!["app.js", "new file.js"]);
    assert_eq!(context.changed_paths, context.unstaged_paths);
    assert!(context.partially_staged);
    assert_eq!(context.snapshot.branch.as_deref(), Some("main"));
}

#[test]
fn branch_comparison_uses_merge_base_and_includes_deletions() {
    let temp = repository();
    let root = temp.path();
    let initial = git(root, &["rev-parse", "HEAD"]);
    git(root, &["checkout", "-b", "feature"]);
    fs::write(root.join("src/feature.js"), "feature\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-m", "feature"]);
    git(root, &["checkout", "main"]);
    fs::write(root.join("src/main.js"), "main\n").unwrap();
    git(root, &["add", "."]);
    git(root, &["commit", "-m", "main"]);
    git(root, &["checkout", "feature"]);
    fs::remove_file(root.join("src/app.js")).unwrap();
    let context = inspect(root, "main").unwrap();
    assert_eq!(context.base_commit, initial);
    assert_eq!(context.changed_paths, vec!["src/app.js", "src/feature.js"]);
    assert!(!context.changed_paths.contains(&"src/main.js".into()));
}

#[test]
fn inspection_never_runs_repository_filters_or_fsmonitor_or_writes_index() {
    let temp = repository();
    let root = temp.path();
    let marker = root.join("executed");
    let malicious = format!("touch {}; cat", marker.display());
    git(root, &["config", "filter.evil.clean", &malicious]);
    git(root, &["config", "filter.evil.process", &malicious]);
    git(root, &["config", "core.fsmonitor", &malicious]);
    fs::write(root.join(".gitattributes"), "*.js filter=evil\n").unwrap();
    fs::write(root.join("src/app.js"), "changed\n").unwrap();
    let index = fs::read(root.join(".git/index")).unwrap();
    assert!(inspect(root, "HEAD").is_ok());
    assert!(!marker.exists());
    assert_eq!(fs::read(root.join(".git/index")).unwrap(), index);
}

#[test]
fn no_git_bad_refs_and_path_escapes_are_unavailable() {
    assert!(inspect(tempfile::tempdir().unwrap().path(), "HEAD").is_err());
    let temp = repository();
    for reference in ["--help", "-c", "HEAD\n", "missing", "HEAD:src/app.js"] {
        assert!(inspect(temp.path(), reference).is_err(), "{reference:?}");
    }
    for path in ["../secret", "/outside", "src/../../outside", ".git/config"] {
        assert!(relative_path(path).is_err(), "{path}");
    }
}

#[cfg(unix)]
#[test]
fn symlink_escape_is_not_read_as_working_tree_content() {
    let temp = repository();
    fs::remove_file(temp.path().join("src/app.js")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", temp.path().join("src/app.js")).unwrap();
    assert!(inspect(temp.path(), "HEAD").is_err());
}

#[test]
fn snapshot_detects_index_and_head_changes() {
    let temp = repository();
    let before = snapshot(temp.path()).unwrap();
    fs::write(temp.path().join("src/app.js"), "new\n").unwrap();
    git(temp.path(), &["add", "."]);
    assert_ne!(snapshot(temp.path()).unwrap(), before);
}

#[test]
fn literal_target_and_file_names_never_become_pathspecs() {
    let temp = repository();
    let root = temp.path();
    let subdir = root.join("[src]");
    fs::create_dir(&subdir).unwrap();
    fs::write(subdir.join("literal file.js"), "literal\n").unwrap();
    fs::write(root.join("src/other.js"), "outside target\n").unwrap();
    let context = inspect(&subdir, "HEAD").unwrap();
    assert_eq!(context.unstaged_paths, vec!["literal file.js"]);
    assert_eq!(context.changed_paths, vec!["literal file.js"]);
}

#[test]
fn malformed_records_and_oversized_raw_files_are_unavailable() {
    for bytes in [
        b"100644 abc 0\t../escape\0".as_slice(),
        b"unterminated",
        b"100644 abc 0\tx\0",
    ] {
        assert!(entries(bytes, true).is_err());
    }
    let temp = repository();
    let file = fs::File::create(temp.path().join("large.js")).unwrap();
    file.set_len(MAX_FILE + 1).unwrap();
    assert!(inspect(temp.path(), "HEAD").is_err());
}

#[cfg(unix)]
#[test]
fn nul_delimited_names_with_newlines_and_pathspec_syntax_are_literal() {
    let temp = repository();
    let subdir = temp.path().join("[src]*");
    fs::create_dir(&subdir).unwrap();
    fs::write(subdir.join(":(exclude)literal\n.js"), "new\n").unwrap();
    let context = inspect(&subdir, "HEAD").unwrap();
    assert_eq!(context.unstaged_paths, vec![":(exclude)literal\n.js"]);
}

#[test]
fn partial_staging_handles_disjoint_sets_at_the_path_budget() {
    let left: Vec<_> = (0..MAX_PATHS / 2)
        .map(|i| format!("src/common/left-{i:05}.js"))
        .collect();
    let mut right: Vec<_> = (0..MAX_PATHS / 2)
        .map(|i| format!("src/common/right-{i:05}.js"))
        .collect();
    let started = Instant::now();
    assert!(!paths_overlap(&left, &right));
    assert!(
        started.elapsed() < TIMEOUT,
        "partial staging alone exhausted the full inspection deadline"
    );
    right[0] = left[0].clone();
    assert!(paths_overlap(&left, &right));
}

#[cfg(windows)]
#[test]
fn windows_normal_raw_file_remains_reviewable() {
    let temp = repository();
    let root = temp.path().canonicalize().unwrap();
    let mut opened = open_raw_file(&root, Path::new("src/app.js")).unwrap();
    let mut contents = String::new();
    opened.read_to_string(&mut contents).unwrap();
    assert_eq!(contents, "one\n");
    assert!(inspect(&root, "HEAD").is_ok());
}

#[cfg(windows)]
#[test]
fn windows_file_replaced_after_checks_cannot_hash_outside_bytes() {
    let temp = repository();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("outside.js"), "two\n").unwrap(); // same length as inside
    let (git, _) = discover(temp.path()).unwrap();
    let result = raw_entry_with_open(&git, "src/app.js", 40, &mut 0, |root, relative| {
        let path = root.join(relative);
        fs::remove_file(&path).unwrap();
        std::os::windows::fs::symlink_file(outside.path().join("outside.js"), &path)
            .expect("Windows security regression requires symlink privilege or Developer Mode");
        open_raw_file(root, relative)
    });
    assert!(
        result.is_err(),
        "replacement links must fail before raw bytes are read"
    );
}

#[cfg(windows)]
#[test]
fn windows_ancestor_junction_replaced_after_checks_cannot_hash_outside_bytes() {
    let temp = repository();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("app.js"), "two\n").unwrap(); // same length as inside
    let (git, _) = discover(temp.path()).unwrap();
    let junction = temp.path().join("src");
    let result = raw_entry_with_open(&git, "src/app.js", 40, &mut 0, |root, relative| {
        fs::rename(&junction, root.join("original-src")).unwrap();
        // A directory junction needs no symlink privilege. This OS fixture setup
        // runs only in the Windows test, never in repository inspection.
        let output = Command::new("cmd")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(outside.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "junction fixture: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        open_raw_file(root, relative)
    });
    assert!(
        result.is_err(),
        "actual opened handle must reject the outside junction target"
    );
    fs::remove_dir(junction).unwrap();
}

#[cfg(unix)]
#[test]
fn unix_ancestor_replaced_after_checks_cannot_hash_outside_bytes() {
    let temp = repository();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("app.js"), "two\n").unwrap();
    let (git, _) = discover(temp.path()).unwrap();
    let result = raw_entry_with_open(&git, "src/app.js", 40, &mut 0, |root, relative| {
        fs::rename(root.join("src"), root.join("original-src")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("src")).unwrap();
        open_raw_file(root, relative)
    });
    assert!(result.is_err());
}
