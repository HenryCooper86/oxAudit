use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::findings::fingerprint::FINGERPRINT_VERSION;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageManifest {
    pub fingerprint_version: u16,
    pub paths: BTreeMap<String, BTreeSet<String>>,
    /// A pack detector can establish absence only under the same validated
    /// content as the baseline. Legacy coverage lacks that proof.
    #[serde(default)]
    pub rule_pack_hashes: BTreeMap<String, BTreeSet<String>>,
    /// Preserve installed selection separately from one-off files, which may
    /// carry the same pack ID with different detector content.
    #[serde(default)]
    pub installed_rule_pack_ids: Option<BTreeSet<String>>,
}

fn normalize_path(path: &str) -> Option<String> {
    let parts: Vec<&str> = path
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    if parts.is_empty() || parts.contains(&"..") {
        None
    } else {
        Some(parts.join("/"))
    }
}

impl CoverageManifest {
    pub fn from_entries<I, P, F, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = (P, F)>,
        P: Into<String>,
        F: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut coverage = Self {
            fingerprint_version: FINGERPRINT_VERSION,
            paths: BTreeMap::new(),
            rule_pack_hashes: BTreeMap::new(),
            installed_rule_pack_ids: None,
        };
        for (path, families) in entries {
            let path = path.into();
            let Some(path) = normalize_path(&path) else {
                continue;
            };
            coverage.paths.entry(path).or_default().extend(
                families
                    .into_iter()
                    .map(Into::into)
                    .filter(|family: &String| !family.is_empty()),
            );
        }
        coverage
    }

    pub fn is_covered(&self, path: &str, family: &str) -> bool {
        normalize_path(path)
            .and_then(|path| self.paths.get(&path))
            .is_some_and(|families| families.contains(family))
    }

    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.fingerprint_version == other.fingerprint_version
            && self.paths.values().any(|families| {
                families.iter().any(|family| {
                    other
                        .paths
                        .values()
                        .any(|other_families| other_families.contains(family))
                })
            })
    }

    pub fn is_finding_covered(
        &self,
        path: &str,
        family: &str,
        rule_id: &str,
        baseline: &Self,
    ) -> bool {
        if !self.is_covered(path, family) {
            return false;
        }
        let Some((pack_id, _)) = rule_id.split_once('/') else {
            return true;
        };
        baseline
            .rule_pack_hashes
            .get(pack_id)
            .is_some_and(|hashes| {
                !hashes.is_empty() && self.rule_pack_hashes.get(pack_id) == Some(hashes)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::CoverageManifest;
    use crate::findings::fingerprint::FINGERPRINT_VERSION;

    #[test]
    fn coverage_tracks_only_successfully_scanned_families_per_normalized_path() {
        let coverage = CoverageManifest::from_entries([
            ("src\\a.rs", ["vulnerability"]),
            ("config.env", ["secret"]),
            ("src/../escaped.rs", ["secret"]),
        ]);

        assert_eq!(coverage.fingerprint_version, FINGERPRINT_VERSION);
        assert!(coverage.is_covered("src/a.rs", "vulnerability"));
        assert!(coverage.is_covered(r"src\a.rs", "vulnerability"));
        assert!(!coverage.is_covered("src/a.rs", "secret"));
        assert!(!coverage.is_covered("src/../a.rs", "vulnerability"));
        assert!(!coverage.paths.contains_key("src/../escaped.rs"));
        assert!(!coverage.paths.contains_key("escaped.rs"));
    }

    #[test]
    fn disabled_scanners_do_not_claim_coverage_or_compatibility() {
        let disabled = CoverageManifest::from_entries([("src/a.rs", std::iter::empty::<&str>())]);
        let secrets = CoverageManifest::from_entries([("src/a.rs", ["secret"])]);

        assert!(!disabled.is_covered("src/a.rs", "secret"));
        assert!(!disabled.is_compatible_with(&secrets));
    }

    #[test]
    fn compatible_coverage_requires_matching_fingerprint_version_and_scanner_family() {
        let secrets = CoverageManifest::from_entries([("src/a.rs", ["secret"])]);
        let shared_secrets = CoverageManifest::from_entries([
            ("src/other.rs", ["vulnerability"]),
            ("config.env", ["secret"]),
        ]);
        let vulnerabilities = CoverageManifest::from_entries([("src/a.rs", ["vulnerability"])]);
        let mut different_version = shared_secrets.clone();
        different_version.fingerprint_version = FINGERPRINT_VERSION + 1;

        assert!(secrets.is_compatible_with(&shared_secrets));
        assert!(!secrets.is_compatible_with(&vulnerabilities));
        assert!(!secrets.is_compatible_with(&different_version));
    }
}
