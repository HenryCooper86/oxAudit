//! Moved to the `oxaudit-parsers` crate so the lockfile parsers can be fuzzed
//! without any GUI dependency; re-exported here so the dependency scanner's
//! paths keep reading as one module tree.
pub use oxaudit_parsers::lockfiles::*;

#[cfg(test)]
mod tests {
    /// Every lockfile the parsers understand must also be one discovery walks
    /// to, or the parser would never see it.
    #[test]
    fn the_new_lockfile_names_are_discovered() {
        for name in super::LOCKFILE_NAMES {
            assert!(
                crate::fs_utils::is_lockfile_name(name),
                "{name} must be discovered"
            );
        }
    }
}
