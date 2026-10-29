//! Parsers for content oxAudit reads from the project or image under scan, or
//! from a file the user imports: lockfiles, exported security reports, the ELF
//! package note, OS package databases and the rule-pack feed index.
//!
//! Everything here turns bytes or text into plain data, with no I/O beyond
//! the file-reading lockfile entry points, so the parsers can be fuzzed
//! without the GUI crate (see `src-tauri/fuzz`). The main crate re-exports
//! each module at its original path.

pub mod go_inventory;
pub mod lockfiles;
pub mod models;
pub mod os_packages;
pub mod package_note;
pub mod relationships;
pub mod report_import;
pub mod rulepack_index;
