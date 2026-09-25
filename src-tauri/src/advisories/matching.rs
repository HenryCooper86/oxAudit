//! Decide, from a full OSV record, whether an installed version is affected.
//!
//! This is the matching OSV's server performs for online queries, restated
//! locally so an advisory database can answer without the network. The
//! evaluation follows the OSV schema's documented semantics: ranges are unions
//! of `introduced`/`fixed`/`last_affected`/`limit` intervals walked in event
//! order, explicit `versions` lists add exact matches, and `GIT` ranges —
//! which name commits, not releases — are skipped, so a GIT-only advisory
//! matches only through its explicit versions.
//!
//! Two behaviours are deliberate and must not change silently:
//!
//! - **Undetermined keeps the advisory.** When a comparator refuses to order
//!   the installed version against an event boundary, the decision is made in
//!   the reporting direction — the same trade the dataflow analysis makes —
//!   and the refusal is counted so a run can say how often it happened.
//! - **Evidence is parsed by the shared OSV path.** Records that match go
//!   through `parse_vulns` unchanged, so a finding from the database and a
//!   finding from the network carry the same shape and the same evidence.

use serde_json::Value;
use std::cmp::Ordering;

use super::versioning;
use crate::deps::osv;
use crate::models::Dependency;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Affected,
    NotAffected,
    /// A boundary the local comparator refused to order. Callers treat this
    /// as affected and count it.
    Undetermined,
}

#[derive(Debug, Default)]
pub struct MatchNotes {
    /// Advisory comparisons decided conservatively because a comparator
    /// refused to order the versions.
    pub undetermined: usize,
    pub undetermined_examples: Vec<String>,
    /// Ranges skipped because they name commits instead of releases.
    pub git_ranges_skipped: usize,
}

impl MatchNotes {
    fn note_undetermined(&mut self, ecosystem: &str, id: &str) {
        self.undetermined += 1;
        if self.undetermined_examples.len() < 5 {
            self.undetermined_examples.push(format!("{ecosystem}/{id}"));
        }
    }

    /// Render the notes as user-facing warnings; empty when nothing needs
    /// saying.
    pub fn warnings(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        if self.undetermined > 0 {
            let examples = self.undetermined_examples.join(", ");
            warnings.push(format!(
                "{} advisory match(es) could not be decided locally because a version comparison was undetermined; they are kept as findings (e.g. {examples})",
                self.undetermined
            ));
        }
        if self.git_ranges_skipped > 0 {
            warnings.push(format!(
                "{} GIT range(s) were skipped; those advisories match only through explicit affected versions",
                self.git_ranges_skipped
            ));
        }
        warnings
    }
}

fn cmp(family: versioning::VersionFamily, version: &str, boundary: &str) -> Option<Ordering> {
    versioning::compare(family, version, boundary)
}

fn event_boundary<'a>(event: &'a Value, key: &str) -> Option<&'a str> {
    event.get(key).and_then(Value::as_str)
}

fn range_affects(events: &[Value], family: versioning::VersionFamily, version: &str) -> Verdict {
    let mut affected = false;
    for event in events {
        if let Some(introduced) = event_boundary(event, "introduced") {
            if introduced == "0" {
                affected = true;
            } else {
                match cmp(family, version, introduced) {
                    Some(Ordering::Greater) | Some(Ordering::Equal) => affected = true,
                    Some(Ordering::Less) => {}
                    None => return Verdict::Undetermined,
                }
            }
        }
        for (key, clears_when) in [
            ("fixed", [Ordering::Greater, Ordering::Equal].as_slice()),
            ("limit", [Ordering::Greater, Ordering::Equal].as_slice()),
            ("last_affected", [Ordering::Greater].as_slice()),
        ] {
            if let Some(boundary) = event_boundary(event, key) {
                match cmp(family, version, boundary) {
                    Some(order) if clears_when.contains(&order) => affected = false,
                    Some(_) => {}
                    None => return Verdict::Undetermined,
                }
            }
        }
    }
    if affected {
        Verdict::Affected
    } else {
        Verdict::NotAffected
    }
}

/// Whether one full OSV record affects `ecosystem`/`name` at `version`.
/// `notes` accumulates the refusals and skips that shaped the decision.
pub fn record_affects(
    record: &Value,
    ecosystem: &str,
    name: &str,
    version: &str,
    notes: &mut MatchNotes,
) -> Verdict {
    let mut any_undetermined = false;
    let normalized = versioning::normalize_package(ecosystem, name);
    for affected in record
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let entry_ecosystem = affected
            .pointer("/package/ecosystem")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let entry_name = affected
            .pointer("/package/name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if entry_ecosystem != ecosystem
            || versioning::normalize_package(ecosystem, entry_name) != normalized
        {
            continue;
        }
        if let Some(versions) = affected.get("versions").and_then(Value::as_array) {
            if versions
                .iter()
                .any(|listed| listed.as_str() == Some(version))
            {
                return Verdict::Affected;
            }
        }
        for range in affected
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let range_type = range.get("type").and_then(Value::as_str).unwrap_or("");
            if range_type == "GIT" {
                notes.git_ranges_skipped += 1;
                continue;
            }
            let events = range
                .get("events")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            match versioning::family_for(range_type, ecosystem) {
                Some(family) => match range_affects(&events, family, version) {
                    Verdict::Affected => return Verdict::Affected,
                    Verdict::NotAffected => {}
                    Verdict::Undetermined => any_undetermined = true,
                },
                None => any_undetermined = true,
            }
        }
    }
    if any_undetermined {
        let id = record.get("id").and_then(Value::as_str).unwrap_or("?");
        notes.note_undetermined(ecosystem, id);
        Verdict::Undetermined
    } else {
        Verdict::NotAffected
    }
}

pub struct LocalQueryOutcome {
    pub results: crate::deps::service::AdvisoryResults,
    pub notes: MatchNotes,
}

/// Answer every queryable dependency from the local database.
///
/// Fails with an incomplete-coverage error when the database was not built
/// for one of the queried ecosystems — a package an advisory source cannot be
/// asked about must never be reported as clean.
pub fn query_local(
    db: &super::store::AdvisoryDb,
    deps: &[Dependency],
) -> Result<LocalQueryOutcome, String> {
    let queryable: Vec<&Dependency> = osv::queryable_dependencies(deps).collect();
    let mut missing: Vec<String> = Vec::new();
    let available = db.ecosystems()?;
    for dep in &queryable {
        if !available.iter().any(|e| e == &dep.ecosystem) && !missing.contains(&dep.ecosystem) {
            missing.push(dep.ecosystem.clone());
        }
    }
    if !missing.is_empty() {
        return Err(format!(
            "incomplete advisory coverage: the advisory database does not include the ecosystem(s) {}; update it with: oxaudit-cli advisory-db update --ecosystem {}",
            missing.join(", "),
            missing.join(" --ecosystem ")
        ));
    }

    let mut notes = MatchNotes::default();
    let mut results = std::collections::HashMap::new();
    for dep in &queryable {
        let stored_rows = db.records_for(&dep.ecosystem, &dep.name)?;
        let mut matches = Vec::new();
        for stored in &stored_rows {
            if let Verdict::Affected | Verdict::Undetermined = record_affects(
                &stored.record,
                &dep.ecosystem,
                &stored.package,
                &dep.version,
                &mut notes,
            ) {
                matches.push(stored.record.clone());
            }
        }
        if matches.is_empty() {
            continue;
        }
        // Parse with the name the record itself carries so affected-evidence
        // filtering sees the upstream spelling, then present the finding
        // under the lockfile's spelling so baselines compare like online runs.
        let stored_name = stored_rows
            .first()
            .map(|row| row.package.clone())
            .unwrap_or_else(|| dep.name.clone());
        let mut vulns = osv::parse_vulns(matches, &dep.ecosystem, &stored_name, &dep.version);
        for vuln in &mut vulns {
            vuln.package_name = dep.name.clone();
        }
        results.insert(osv::dependency_query_key(dep), vulns);
    }
    Ok(LocalQueryOutcome { results, notes })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(json: Value) -> Value {
        json
    }

    fn affects(json: Value, ecosystem: &str, name: &str, version: &str) -> Verdict {
        let mut notes = MatchNotes::default();
        let verdict = record_affects(&record(json), ecosystem, name, version, &mut notes);
        // The refusals and skips that shaped a verdict are part of the
        // contract, so hold the accounting honest alongside every decision.
        if matches!(verdict, Verdict::Undetermined) {
            assert!(notes.undetermined >= 1, "undetermined without a note");
        }
        if notes.git_ranges_skipped > 0 {
            assert!(!notes.warnings().is_empty());
        }
        verdict
    }

    fn npm_range(events: &[(&str, &str)]) -> Value {
        let events: Vec<Value> = events
            .iter()
            .map(|(kind, version)| serde_json::json!({ *kind: version }))
            .collect();
        serde_json::json!({
            "id": "GHSA-test",
            "affected": [{
                "package": { "ecosystem": "npm", "name": "lodash" },
                "ranges": [{ "type": "SEMVER", "events": events }]
            }]
        })
    }

    #[test]
    fn introduced_fixed_intervals_walk_in_event_order() {
        let advisory = npm_range(&[
            ("introduced", "0"),
            ("fixed", "1.0.1"),
            ("introduced", "2.0.0"),
            ("fixed", "2.0.5"),
        ]);
        assert_eq!(
            affects(advisory.clone(), "npm", "lodash", "1.0.0"),
            Verdict::Affected
        );
        assert_eq!(
            affects(advisory.clone(), "npm", "lodash", "1.0.1"),
            Verdict::NotAffected
        );
        assert_eq!(
            affects(advisory.clone(), "npm", "lodash", "1.5.0"),
            Verdict::NotAffected
        );
        assert_eq!(
            affects(advisory.clone(), "npm", "lodash", "2.0.0"),
            Verdict::Affected
        );
        assert_eq!(
            affects(advisory.clone(), "npm", "lodash", "2.0.5"),
            Verdict::NotAffected
        );
        assert_eq!(
            affects(advisory.clone(), "npm", "lodash", "3.0.0"),
            Verdict::NotAffected
        );
    }

    #[test]
    fn last_affected_is_inclusive_and_limit_is_exclusive() {
        let last = npm_range(&[("introduced", "0"), ("last_affected", "1.2.9")]);
        assert_eq!(
            affects(last.clone(), "npm", "lodash", "1.2.9"),
            Verdict::Affected
        );
        assert_eq!(
            affects(last, "npm", "lodash", "1.3.0"),
            Verdict::NotAffected
        );

        let limited = npm_range(&[("introduced", "0"), ("limit", "2.0.0")]);
        assert_eq!(
            affects(limited.clone(), "npm", "lodash", "1.9.9"),
            Verdict::Affected
        );
        assert_eq!(
            affects(limited, "npm", "lodash", "2.0.0"),
            Verdict::NotAffected
        );
    }

    #[test]
    fn explicit_versions_match_exactly() {
        let advisory = serde_json::json!({
            "id": "CVE-2020-1",
            "affected": [{
                "package": { "ecosystem": "Maven", "name": "org.example:lib" },
                "versions": ["1.0.0", "1.0.1"],
                "ranges": [{ "type": "GIT", "events": [{"introduced": "0"}] }]
            }]
        });
        assert_eq!(
            affects(advisory.clone(), "Maven", "org.example:lib", "1.0.1"),
            Verdict::Affected
        );
        // GIT ranges are skipped, so a version outside the explicit list is
        // not affected even though the GIT range says "everything".
        assert_eq!(
            affects(advisory.clone(), "Maven", "org.example:lib", "1.0.2"),
            Verdict::NotAffected
        );
    }

    #[test]
    fn affected_entries_for_other_packages_are_ignored() {
        let advisory = serde_json::json!({
            "id": "GHSA-two",
            "affected": [
                { "package": { "ecosystem": "npm", "name": "other" },
                  "ranges": [{ "type": "SEMVER", "events": [{"introduced": "0"}] }] },
                { "package": { "ecosystem": "PyPI", "name": "lodash" },
                  "ranges": [{ "type": "ECOSYSTEM", "events": [{"introduced": "0"}] }] }
            ]
        });
        assert_eq!(
            affects(advisory, "npm", "lodash", "1.0.0"),
            Verdict::NotAffected
        );
    }

    #[test]
    fn pypi_names_normalize_and_pep440_ranges_evaluate() {
        let advisory = serde_json::json!({
            "id": "PYSEC-1",
            "affected": [{
                "package": { "ecosystem": "PyPI", "name": "django" },
                "ranges": [{ "type": "ECOSYSTEM", "events": [
                    {"introduced": "1.11.0"}, {"fixed": "1.11.18"}
                ]}]
            }]
        });
        assert_eq!(
            affects(advisory.clone(), "PyPI", "Django", "1.11.15"),
            Verdict::Affected
        );
        assert_eq!(
            affects(advisory, "PyPI", "Django", "1.11.18"),
            Verdict::NotAffected
        );
    }

    #[test]
    fn a_comparator_refusal_is_undetermined_not_clean() {
        let advisory = npm_range(&[("introduced", "not-a-version")]);
        let mut notes = MatchNotes::default();
        let verdict = record_affects(&advisory, "npm", "lodash", "1.0.0", &mut notes);
        assert_eq!(verdict, Verdict::Undetermined);
        assert_eq!(notes.undetermined, 1);
        assert_eq!(notes.undetermined_examples, vec!["npm/GHSA-test"]);
        assert!(!notes.warnings().is_empty());
    }

    #[test]
    fn an_unknown_ecosystem_family_is_undetermined() {
        let advisory = serde_json::json!({
            "id": "OSV-1",
            "affected": [{
                "package": { "ecosystem": "Wolfi", "name": "zlib" },
                "ranges": [{ "type": "ECOSYSTEM", "events": [{"introduced": "0"}] }]
            }]
        });
        assert_eq!(
            affects(advisory, "Wolfi", "zlib", "1.0.0"),
            Verdict::Undetermined
        );
    }

    #[test]
    fn multiple_intervals_union_across_affected_entries() {
        let first = npm_range(&[("introduced", "0"), ("fixed", "1.0.0")]);
        let second = npm_range(&[("introduced", "5.0.0"), ("fixed", "5.0.1")]);
        let combined = serde_json::json!({
            "id": "GHSA-union",
            "affected": first["affected"]
                .as_array()
                .unwrap()
                .iter()
                .chain(second["affected"].as_array().unwrap().iter())
                .cloned()
                .collect::<Vec<_>>()
        });
        assert_eq!(
            affects(combined.clone(), "npm", "lodash", "5.0.0"),
            Verdict::Affected
        );
        assert_eq!(
            affects(combined, "npm", "lodash", "2.0.0"),
            Verdict::NotAffected
        );
    }
}
