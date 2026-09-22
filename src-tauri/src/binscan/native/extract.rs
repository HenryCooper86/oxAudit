//! Moved to the `oxaudit-archive` crate so the untrusted-byte parsers can be
//! fuzzed without any GUI dependency; re-exported here so the binary
//! scanner's internal paths keep reading as one module tree.
pub use oxaudit_archive::extract::*;
