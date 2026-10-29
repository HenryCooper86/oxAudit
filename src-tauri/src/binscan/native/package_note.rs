//! Moved to the `oxaudit-parsers` crate so the ELF note reader can be fuzzed
//! without any GUI dependency; re-exported here so the binary scanner's
//! internal paths keep reading as one module tree.
pub use oxaudit_parsers::package_note::*;
