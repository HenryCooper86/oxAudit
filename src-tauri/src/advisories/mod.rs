//! A local advisory database: the offline counterpart to OSV's network API.
//!
//! `deps` answers advisories online by asking OSV's server, which owns
//! ecosystem-correct version matching. The modules here carry that matching
//! onto the user's machine: OSV's published ecosystem dumps ingested into a
//! SQLite store, version comparison per ecosystem spec, and range evaluation
//! following the OSV schema. A scan answered from the database and a scan
//! answered by the network produce the same finding shape, because both go
//! through the same record parser.
//!
//! Stated limits, which the surfaces that use this module repeat:
//! - `GIT` ranges are skipped; those advisories match only through their
//!   explicit affected-versions lists.
//! - A comparison the local comparator refuses to make keeps the advisory
//!   (the reporting direction) and is counted, never silent.
//! - Coverage is per ecosystem: a query for an ecosystem whose dump was not
//!   downloaded is an incomplete-coverage error, never a clean result.

pub mod ingest;
pub mod matching;
pub mod store;
pub mod versioning;
