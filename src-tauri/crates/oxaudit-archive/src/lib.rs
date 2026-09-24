//! Bounded in-memory extraction of archives and filesystem images.
//!
//! This crate exists apart from the desktop application so the parsers of
//! untrusted bytes — the exact code a hostile firmware blob attacks — can be
//! fuzzed and tested without pulling in any GUI dependency, and so the
//! dependency list says what this code actually needs.

pub mod extract;
pub mod filetype;
pub mod oci;

/// Default per-member byte cap. Kept here rather than in the caller so the
/// budgets the extractors enforce are defined beside the extractors.
pub const DEFAULT_MAX_MEMBER_BYTES: u64 = 128 * 1024 * 1024;
