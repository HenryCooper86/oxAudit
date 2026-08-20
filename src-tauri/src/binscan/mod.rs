//! Binary and firmware scanning via cve-bin-tool.
//!
//! oxAudit's own scanners read source, secrets and lockfiles. None of them can
//! see a statically linked OpenSSL inside a stripped binary or a firmware
//! image, which is what cve-bin-tool's ~450 component checkers are for.
//!
//! It is **not bundled**: cve-bin-tool is GPL-3.0-or-later, so shipping it
//! would make oxAudit a distributor of GPL software. We invoke a copy the user
//! installed, at arms length, and treat "not installed" as a normal state.
//!
//! Lockfile scanning is deliberately *not* routed through it — `deps/` already
//! parses ten lockfile formats natively and queries OSV directly.

pub mod detect;
pub mod exploit;
pub mod grype;
pub mod native;
pub mod report;
pub mod run;
pub mod runtime;
pub mod scan;
