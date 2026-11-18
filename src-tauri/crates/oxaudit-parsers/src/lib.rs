//! Parsers for content oxAudit reads from the project or image under scan, or
//! from a file the user imports: lockfiles, exported security reports, the ELF
//! package note, OS package databases and the rule-pack feed index.
//!
//! Everything here turns bytes or text into plain data, with no I/O beyond
//! the file-reading lockfile entry points, so the parsers can be fuzzed
//! without the GUI crate (see `src-tauri/fuzz`). The main crate re-exports
//! each module at its original path.

/// Entries of a JSON object in key order.
///
/// `serde_json::Map` iterates in insertion (file) order when any crate in the
/// build enables `preserve_order` (the `yara-x` dependency does, workspace
/// wide) and in key order otherwise. Every parser that iterates a JSON object
/// goes through this helper so output ordering, error precedence and
/// truncation limits are identical in both builds.
pub(crate) fn sorted_entries(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Vec<(&String, &serde_json::Value)> {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|a, b| a.0.cmp(b.0));
    entries
}

pub mod bdb_hash;
pub mod canonical_json;
pub mod go_buildinfo;
pub mod go_inventory;
pub(crate) mod graph_paths;
pub mod lockfiles;
pub mod models;
pub mod msbuild;
pub mod os_packages;
pub mod package_note;
pub mod relationships;
pub mod report_import;
pub mod rpm_header;
pub mod rulepack_index;
pub mod stable_json;
