//! Plain dependency records produced by the lockfile parsers.
//!
//! They live beside the parsers that build them so the parsers can be fuzzed
//! without the GUI crate; the main crate re-exports them from `models`.

use serde::{Deserialize, Serialize};

/// Same-read lockfile occurrence evidence. Historical projections default unknown.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DependencyOccurrence {
    /// Origin kind when the lockfile distinguishes registry, git and local code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Ruby platform suffix, separated from the registry version used for queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(default)]
    pub local_workspace: bool,
    pub install_path: Option<String>,
    pub status: String,
    pub paths: Vec<DependencyPath>,
    pub warnings: Vec<String>,
}
impl Default for DependencyOccurrence {
    fn default() -> Self {
        Self {
            source: None,
            platform: None,
            local_workspace: false,
            install_path: None,
            status: "unknown".into(),
            paths: Vec::new(),
            warnings: Vec::new(),
        }
    }
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DependencyPath {
    /// Empty string identifies the root manifest; other values are relative directories.
    pub workspace: String,
    pub entry_point: String,
    pub chain: Vec<DependencyStep>,
}
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DependencyStep {
    pub name: String,
    pub package_name: String,
    pub install_path: String,
    pub dependency_type: String,
    pub declared: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Dependency {
    #[serde(default)]
    pub occurrence: DependencyOccurrence,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub lockfile: String,
    /// Declared license, when the lockfile itself carries it (npm
    /// package-lock v2/v3 entries do). Absent means unknown — never
    /// NOASSERTION-style guessing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
}

/// OSV requires all three package coordinates. Keep this predicate shared by
/// request construction, progress accounting, and cache receipts so a package
/// is never recorded as queried unless it was eligible for the request.
///
/// Only registry releases are queried. Git checkouts, local/path code, direct
/// URL archives and workspace members merely share a name and version with
/// whatever the public registry holds; querying them would attribute another
/// package's advisories (or its absence) to project code.
pub fn is_queryable_dependency(dependency: &Dependency) -> bool {
    dependency.ecosystem != "unknown"
        && !dependency.occurrence.local_workspace
        && !matches!(
            dependency.occurrence.source.as_deref(),
            Some("git" | "local" | "url")
        )
        && !dependency.name.trim().is_empty()
        && !dependency.version.trim().is_empty()
}

pub fn queryable_dependencies(deps: &[Dependency]) -> impl Iterator<Item = &Dependency> {
    deps.iter()
        .filter(|dependency| is_queryable_dependency(dependency))
}
