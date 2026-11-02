use oxaudit_parsers::go_inventory;
pub mod lockfiles;
pub mod osv;
pub mod service;

/// Discovered lockfiles plus the requirements files they include.
pub struct ExpandedLockfiles {
    pub files: Vec<std::path::PathBuf>,
    /// Files reached only through a `-r` include, whatever their name; they
    /// are parsed as pip requirements.
    pub included_requirements: std::collections::BTreeSet<std::path::PathBuf>,
    /// Includes that were not scanned, for the inventory notes.
    pub notes: Vec<String>,
}

impl ExpandedLockfiles {
    /// The parser kind for one of [`Self::files`].
    pub fn kind_for(&self, path: &std::path::Path) -> &'static str {
        if self.included_requirements.contains(path) {
            "pip"
        } else {
            lockfiles::lockfile_kind_for_path(path)
        }
    }
}

/// Lockfiles a sibling takes precedence over, with the sibling that wins:
/// npm installs from `npm-shrinkwrap.json` when both exist, and Bundler
/// reads `gems.locked` before `Gemfile.lock`. Reading both would count every
/// package twice.
const SHADOWED_BY: [(&str, &str); 2] = [
    ("package-lock.json", "npm-shrinkwrap.json"),
    ("Gemfile.lock", "gems.locked"),
];

/// Drop discovered lockfiles that a sibling in the same directory takes
/// precedence over, returning a note for each.
pub fn drop_shadowed_lockfiles(files: &mut Vec<std::path::PathBuf>) -> Vec<String> {
    let present: std::collections::BTreeSet<std::path::PathBuf> = files.iter().cloned().collect();
    let mut notes = Vec::new();
    files.retain(|file| {
        let Some(name) = file.file_name().and_then(|name| name.to_str()) else {
            return true;
        };
        // Bun's binary lockfile is never parsed. Beside a text bun.lock it
        // adds nothing; alone, the project's npm packages go unchecked, and
        // the scan says so rather than looking clean.
        if name == "bun.lockb" {
            if !present.contains(&file.with_file_name("bun.lock")) {
                notes.push(format!(
                    "{}: bun.lockb is Bun's binary lockfile and is not read; run \"bun install --save-text-lockfile\" to write bun.lock",
                    file.display()
                ));
            }
            return false;
        }
        let winner = if lockfiles::is_msbuild_project(file) {
            // A NuGet lock file beside a project is authoritative.
            "packages.lock.json"
        } else {
            match SHADOWED_BY.iter().find(|(shadowed, _)| *shadowed == name) {
                Some((_, winner)) => winner,
                None => return true,
            }
        };
        if present.contains(&file.with_file_name(winner)) {
            notes.push(format!(
                "{}: {name} was skipped because {winner} takes precedence",
                file.display()
            ));
            false
        } else {
            true
        }
    });
    notes
}

/// Turn discovered files into the lockfiles a scan reads: drop the ones a
/// sibling makes redundant (noted), enforce the lockfile budget on what is
/// left, and follow requirements includes. The dependency scan and the
/// desktop's project check both use this, so they agree on what is read.
pub fn prepare_lockfiles(
    project_root: &std::path::Path,
    mut discovered: Vec<std::path::PathBuf>,
    max_lockfiles: usize,
) -> Result<ExpandedLockfiles, String> {
    let shadowed = drop_shadowed_lockfiles(&mut discovered);
    if discovered.len() > max_lockfiles {
        return Err(format!(
            "resource limit: more than {max_lockfiles} lockfiles; scan a smaller subdirectory"
        ));
    }
    let mut expanded = expand_requirement_includes(project_root, discovered, max_lockfiles)?;
    expanded.notes.splice(0..0, shadowed);
    Ok(expanded)
}

/// Parse one prepared lockfile. .NET project files need the scan root, to
/// find their `Directory.*` files without reading above it.
pub fn parse_inventory(
    path: &std::path::Path,
    kind: &str,
    scan_root: &std::path::Path,
) -> Result<lockfiles::LockfileInventory, String> {
    if kind == "msbuild" {
        lockfiles::parse_msbuild_inventory(path, scan_root)
    } else {
        lockfiles::parse_lockfile_inventory(path, kind)
    }
}

/// Follow `-r` includes from every requirements file, so packages listed in
/// an included file are scanned even when its name is not one discovery
/// recognises. Only files inside `project_root` are read; remote, missing and
/// outside includes are reported as unscanned instead.
pub fn expand_requirement_includes(
    project_root: &std::path::Path,
    discovered: Vec<std::path::PathBuf>,
    max_lockfiles: usize,
) -> Result<ExpandedLockfiles, String> {
    let project_root = project_root
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", project_root.display()))?;
    let mut files = discovered
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let mut included_requirements = std::collections::BTreeSet::new();
    let mut notes = Vec::new();
    let mut pending = files
        .iter()
        .filter(|path| lockfiles::is_requirements_file(path))
        .cloned()
        .collect::<std::collections::VecDeque<_>>();
    while let Some(file) = pending.pop_front() {
        // Unreadable or oversized files fail later, in parsing, where the
        // error is reported against the file.
        let Ok(content) = read_bounded(&file) else {
            continue;
        };
        let Some(directory) = file.parent() else {
            continue;
        };
        for include in lockfiles::requirements_includes(&content) {
            let unscanned = |reason: &str| {
                format!(
                    "{}: not checked against advisories: included requirements file {include} {reason}",
                    file.display()
                )
            };
            if include.contains("://") {
                notes.push(unscanned("is remote and was not fetched"));
                continue;
            }
            let target = match directory.join(&include).canonicalize() {
                Ok(target) => target,
                Err(_) => {
                    notes.push(unscanned("was not found"));
                    continue;
                }
            };
            if !target.starts_with(&project_root) {
                notes.push(unscanned("is outside the scanned project and was not read"));
                continue;
            }
            if !target.is_file() {
                notes.push(unscanned("is not a file"));
                continue;
            }
            if files.contains(&target) {
                continue;
            }
            if files.len() >= max_lockfiles {
                return Err(format!(
                    "resource limit: more than {max_lockfiles} lockfiles including requirements \
                     includes; scan a smaller subdirectory"
                ));
            }
            files.insert(target.clone());
            if lockfiles::lockfile_format(&target).is_none() {
                included_requirements.insert(target.clone());
            }
            pending.push_back(target);
        }
    }
    Ok(ExpandedLockfiles {
        files: files.into_iter().collect(),
        included_requirements,
        notes,
    })
}

fn read_bounded(path: &std::path::Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut content = String::new();
    std::fs::File::open(path)?
        .take(lockfiles::MAX_LOCKFILE_BYTES)
        .read_to_string(&mut content)?;
    Ok(content)
}

const MAX_FAILED_LOCKFILES_IN_MESSAGE: usize = 5;
const MAX_PARSE_ERROR_CHARS: usize = 280;

/// Refuse to present dependency results when any discovered lockfile could not
/// be parsed. A partial inventory cannot support a clean vulnerability result.
///
/// Parser errors originate in files under the scanned project, so bound both
/// the number and length included in the user-facing error.
pub fn ensure_complete_lockfile_coverage(parse_errors: &[String]) -> Result<(), String> {
    if parse_errors.is_empty() {
        return Ok(());
    }

    let failed = parse_errors
        .iter()
        .take(MAX_FAILED_LOCKFILES_IN_MESSAGE)
        .map(|error| {
            let mut bounded = error
                .chars()
                .take(MAX_PARSE_ERROR_CHARS)
                .collect::<String>();
            if error.chars().count() > MAX_PARSE_ERROR_CHARS {
                bounded.push('…');
            }
            bounded
        })
        .collect::<Vec<_>>();
    let remaining = parse_errors.len().saturating_sub(failed.len());
    let suffix = if remaining == 0 {
        String::new()
    } else {
        format!("; and {remaining} more")
    };

    Err(format!(
        "incomplete dependency coverage: {} lockfile(s) failed to parse: {}{}. Fix or exclude the failed lockfiles before checking advisories.",
        parse_errors.len(),
        failed.join("; "),
        suffix,
    ))
}

#[cfg(test)]
mod tests {
    use super::ensure_complete_lockfile_coverage;

    #[test]
    fn complete_coverage_accepts_an_empty_parser_error_list() {
        // A parser that successfully produces an empty inventory must remain
        // distinguishable from a parser failure.
        assert!(ensure_complete_lockfile_coverage(&[]).is_ok());
    }

    #[test]
    fn incomplete_coverage_names_failed_lockfiles_in_a_bounded_error() {
        let errors = (0..7)
            .map(|index| format!("project-{index}/package-lock.json: invalid JSON"))
            .collect::<Vec<_>>();

        let error = ensure_complete_lockfile_coverage(&errors).expect_err("coverage is incomplete");

        assert!(
            error.starts_with("incomplete dependency coverage:"),
            "{error}"
        );
        assert!(error.contains("project-0/package-lock.json"), "{error}");
        assert!(error.contains("and 2 more"), "{error}");
        assert!(!error.contains("project-6/package-lock.json"), "{error}");
    }
}
