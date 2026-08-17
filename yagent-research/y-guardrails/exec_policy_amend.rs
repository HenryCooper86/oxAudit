//! Amendment persistence: append rules to a policy file with advisory locking.
//!
//! Used when the user responds to an HITL prompt with "Always Allow" —
//! the system derives a prefix rule that would auto-approve the command
//! next time and appends it to the policy file.
//!
//! Advisory locking is unix-only; on other platforms the lock helpers below are
//! no-ops and concurrent writers are not serialized.

use std::fs::OpenOptions;
use std::path::Path;

use crate::exec_policy::error::{ExecPolicyError, ExecPolicyResult};

/// Append an `allow` prefix rule for the given command tokens to a policy file.
///
/// This is a blocking function — use `tokio::task::spawn_blocking` from async.
/// The rule is appended with advisory file locking to prevent concurrent
/// write corruption.
pub fn append_allow_prefix_rule(policy_path: &Path, prefix: &[String]) -> ExecPolicyResult<()> {
    if prefix.is_empty() {
        return Err(ExecPolicyError::InvalidRule(
            "prefix rule requires at least one token".to_string(),
        ));
    }

    let tokens: Vec<String> = prefix
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ExecPolicyError::InvalidRule(format!("failed to serialize prefix: {e}")))?;

    let pattern = format!("[{}]", tokens.join(", "));
    let rule = format!(
        r#"prefix_rule(pattern={pattern}, decision="allow"){}"#,
        "\n"
    );
    append_rule_line(policy_path, &rule)
}

/// Append a single rule line to the policy file with advisory locking.
fn append_rule_line(policy_path: &Path, rule: &str) -> ExecPolicyResult<()> {
    let dir = policy_path
        .parent()
        .ok_or_else(|| ExecPolicyError::MissingParent(policy_path.to_path_buf()))?;

    std::fs::create_dir_all(dir).map_err(|source| ExecPolicyError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(policy_path)
        .map_err(|source| ExecPolicyError::Io {
            path: policy_path.to_path_buf(),
            source,
        })?;

    let mut guard = filelock::acquire(file, policy_path)?;
    let result = append_to_file(&mut guard, rule);
    filelock::release(guard);
    result
}

/// Exclusive advisory file locking (unix).
#[cfg(unix)]
mod filelock {
    use std::fs::File;
    use std::path::Path;

    use nix::fcntl::{Flock, FlockArg};

    use crate::exec_policy::error::{ExecPolicyError, ExecPolicyResult};

    /// An owned exclusive lock that dereferences to the locked file.
    pub type Guard = Flock<File>;

    /// Take an exclusive advisory lock, blocking until it is available.
    pub fn acquire(file: File, path: &Path) -> ExecPolicyResult<Guard> {
        Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, errno)| ExecPolicyError::Lock {
            path: path.to_path_buf(),
            source: errno.into(),
        })
    }

    /// Release the lock and close the file.
    pub fn release(guard: Guard) {
        match guard.unlock() {
            // Dropping the file closes the descriptor, releasing the lock.
            Ok(file) => drop(file),
            // `flock(LOCK_UN)` on a live descriptor cannot fail in practice.
            // Forget the guard rather than let its `Drop` panic on the retry.
            Err((guard, _)) => std::mem::forget(guard),
        }
    }
}

/// No-op stand-ins for platforms without unix advisory locking.
#[cfg(not(unix))]
mod filelock {
    use std::fs::File;
    use std::path::Path;

    use crate::exec_policy::error::ExecPolicyResult;

    /// The unlocked file itself; no advisory locking is available.
    pub type Guard = File;

    /// Returns the file unchanged: advisory locking is unix-only.
    pub fn acquire(file: File, _path: &Path) -> ExecPolicyResult<Guard> {
        Ok(file)
    }

    /// Closes the file; there is no lock to release.
    pub fn release(guard: Guard) {
        drop(guard);
    }
}

fn append_to_file(file: &mut std::fs::File, rule: &str) -> ExecPolicyResult<()> {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;

    // Read existing content to check if it ends with a newline.
    let mut existing = String::new();
    file.read_to_string(&mut existing)
        .map_err(|source| ExecPolicyError::Io {
            path: std::path::PathBuf::new(),
            source,
        })?;

    let needs_leading_newline = !existing.is_empty() && !existing.ends_with('\n');

    // Seek to end for appending.
    file.seek(SeekFrom::End(0))
        .map_err(|source| ExecPolicyError::Io {
            path: std::path::PathBuf::new(),
            source,
        })?;

    let mut writer = std::io::BufWriter::new(file);
    if needs_leading_newline {
        writer
            .write_all(b"\n")
            .map_err(|source| ExecPolicyError::Io {
                path: std::path::PathBuf::new(),
                source,
            })?;
    }
    writer
        .write_all(rule.as_bytes())
        .map_err(|source| ExecPolicyError::Io {
            path: std::path::PathBuf::new(),
            source,
        })?;
    writer.flush().map_err(|source| ExecPolicyError::Io {
        path: std::path::PathBuf::new(),
        source,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec_policy::parser::PolicyParser;

    #[test]
    fn append_allow_prefix_rule_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("subdir").join("test.policy");

        append_allow_prefix_rule(&policy_path, &["cargo".into(), "test".into()]).unwrap();

        assert!(policy_path.exists());

        let contents = std::fs::read_to_string(&policy_path).unwrap();
        assert!(
            contents.contains(r#"prefix_rule(pattern=["cargo", "test"], decision="allow")"#),
            "appended rule should be in file: {contents}"
        );
    }

    #[test]
    fn append_allow_prefix_rule_round_trips_through_parser() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("test.policy");

        append_allow_prefix_rule(&policy_path, &["npm".into(), "install".into()]).unwrap();

        let mut parser = PolicyParser::new();
        let contents = std::fs::read_to_string(&policy_path).unwrap();
        parser.parse("test.policy", &contents).unwrap();
        let policy = parser.build();

        let eval = policy.evaluate(&["npm".into(), "install".into()]).unwrap();
        assert_eq!(
            eval.decision,
            crate::exec_policy::decision::ExecDecision::Allow
        );
    }

    #[test]
    fn append_allow_prefix_rule_empty_prefix_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("test.policy");
        assert!(append_allow_prefix_rule(&policy_path, &[]).is_err());
    }

    #[test]
    fn append_multiple_rules_accumulate() {
        let tmp = tempfile::tempdir().unwrap();
        let policy_path = tmp.path().join("test.policy");

        append_allow_prefix_rule(&policy_path, &["git".into(), "status".into()]).unwrap();
        append_allow_prefix_rule(&policy_path, &["ls".into()]).unwrap();

        let contents = std::fs::read_to_string(&policy_path).unwrap();
        let mut parser = PolicyParser::new();
        parser.parse("test.policy", &contents).unwrap();
        let policy = parser.build();

        assert!(policy.has_match(&["git".into(), "status".into()]));
        assert!(policy.has_match(&["ls".into()]));
    }
}
