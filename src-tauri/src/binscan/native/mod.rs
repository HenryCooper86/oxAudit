//! oxAudit's own binary component scanner.
//!
//! This is the capability cve-bin-tool provided, reimplemented natively. The
//! method is the same one that project established and it is a good one —
//! anchor on a characteristic string, capture the version from nearby — but
//! nothing here is transcribed from it: cve-bin-tool is GPL-3.0-or-later, and
//! its checkers are the part that would carry the licence with it. The
//! signatures in `signatures.toml` were derived from binaries whose versions
//! were known independently. See `docs/binary-signatures.md`.
//!
//! Three things this does that the subprocess integration could not:
//!
//! - **No CVE database to bootstrap.** cve-bin-tool cannot run at all until it
//!   has downloaded roughly a gigabyte, a step that is broken upstream and
//!   rate-limited to hours when it does work. Detection needs none of it.
//! - **The ELF package note is read.** Libraries with no version string —
//!   zstd, sqlite3, pcre2, liblzma — are identified exactly, from what the
//!   builder declared.
//! - **One pass instead of hundreds.** Every pattern is matched with a single
//!   `RegexSet` per file rather than one checker at a time.

pub mod bytes;
pub mod enrich;
pub mod filetype;
pub mod package_note;
pub mod scan;
pub mod signature;
pub mod strings;
