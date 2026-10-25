//! Re-match stored dependency inventories against a refreshed advisory
//! database and report advisories the stored run did not report.
//!
//! This is the monitoring half of the daily loop: a dependency scan answers
//! "what affected us when we scanned", while `monitor` answers "what affects
//! the inventories we already stored, now that the advisory data moved".
//! The stored run is never modified — monitoring is read-only over durable
//! evidence, so a delta never rewrites history.
//!
//! Honesty rules the whole module, mirroring `deps`:
//! - The re-match re-queries exactly the components the stored run queried:
//!   only components that carry a purl were registry-queryable at scan time
//!   (git/local sources deliberately carry none), so they are the only ones
//!   re-matched. A component without a purl is counted and never silently
//!   dropped from coverage.
//! - An ecosystem the advisory database does not carry is an incomplete
//!   coverage error for that run, never a clean result.
//! - A row in the delta means "the stored run did not report this advisory
//!   for this component" — the cause may be a newly published advisory,
//!   updated range data, or the local comparator's conservative handling of
//!   a version it cannot order. The run's notes say which of those shaped
//!   the answer; the wording never claims the advisory is new upstream.

use crate::advisories::store::AdvisoryDb;
use crate::findings::domain::ResultPageQuery;
use crate::findings::inventory::InventoryComponentView;
use crate::findings::repository::FindingsRepository;
use crate::models::{Dependency, DependencyOccurrence};
use std::collections::{BTreeSet, HashSet};

/// The page ceiling the inventory read model allows; the loader walks pages
/// at this size until every component of the run is loaded.
const PAGE_SIZE: u32 = 200;

/// One advisory the stored run did not report for one installed component.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewAdvisory {
    pub ecosystem: String,
    pub package: String,
    pub installed_version: String,
    pub advisory_id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: Option<String>,
    pub cvss_score: Option<f32>,
    pub fixed_versions: Vec<String>,
}

/// The monitoring verdict for one stored run.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitoredRun {
    pub run_id: String,
    pub target: String,
    /// When the stored run last changed — the honest as-of stamp of the
    /// inventory being re-matched.
    pub updated_at_ms: u64,
    /// Every component the run stored.
    pub components_total: usize,
    /// The subset that was registry-queryable at scan time (carries a purl)
    /// and is therefore re-matched.
    pub components_matched: usize,
    pub newly_matching: Vec<NewAdvisory>,
    /// Set when the advisory database does not cover an ecosystem this
    /// inventory uses. Such a run is never reported as clean.
    pub coverage_error: Option<String>,
    /// Match-shaping notes (undetermined comparisons, skipped GIT ranges).
    pub notes: Vec<String>,
}

/// The result of monitoring a set of stored inventories.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorOutcome {
    /// The advisory database's own build time — the honest as-of stamp of
    /// the advisory side of the comparison.
    pub advisory_db_built_at_ms: Option<u64>,
    pub runs: Vec<MonitoredRun>,
}

impl MonitorOutcome {
    pub fn total_new(&self) -> usize {
        self.runs.iter().map(|run| run.newly_matching.len()).sum()
    }

    pub fn coverage_errors(&self) -> Vec<&MonitoredRun> {
        self.runs
            .iter()
            .filter(|run| run.coverage_error.is_some())
            .collect()
    }
}

/// A stored run plus its fully paged component inventory.
pub struct MonitoredInventory {
    pub run: oxaudit_domain::Run,
    pub components: Vec<InventoryComponentView>,
}

/// Select the stored runs to monitor.
///
/// With explicit ids every id must name a completed dependencies run; a
/// missing id, another kind, or an unfinished run is an error naming the id,
/// because quietly skipping a requested project would hide exactly the kind
/// of gap monitoring exists to surface. Without ids, the latest completed
/// dependencies run per target label is monitored.
pub fn select_runs(
    repository: &FindingsRepository,
    explicit: &[String],
) -> Result<Vec<oxaudit_domain::Run>, String> {
    let load = |id: &str| -> Result<oxaudit_domain::Run, String> {
        let run_id = oxaudit_domain::RunId::parse(id.to_string())
            .map_err(|error| format!("--run {id}: {error}"))?;
        let run = repository
            .canonical_load_run(&run_id)
            .map_err(|error| format!("--run {id}: {error}"))?
            .ok_or_else(|| format!("--run {id}: no stored run has this id"))?;
        if run.kind != oxaudit_domain::RunKind::Dependencies {
            return Err(format!(
                "--run {id}: expected a dependencies run, found {}",
                kind_name(&run)
            ));
        }
        if run.state != oxaudit_domain::RunState::Completed {
            return Err(format!(
                "--run {id}: run is {}, not completed; only completed runs hold a full inventory",
                state_name(&run)
            ));
        }
        Ok(run)
    };
    if !explicit.is_empty() {
        return explicit.iter().map(|id| load(id)).collect();
    }
    // The whole table, one row per target: `canonical_list_runs` is capped
    // at a hundred rows for listings, and a cap here would silently stop
    // monitoring every target whose latest run fell outside the newest
    // page while the command still reported success.
    repository
        .canonical_latest_completed_runs_per_target("dependencies")
        .map_err(|error| error.to_string())
}

fn kind_name(run: &oxaudit_domain::Run) -> String {
    serde_json::to_value(run.kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{:?}", run.kind))
}

fn state_name(run: &oxaudit_domain::Run) -> String {
    serde_json::to_value(run.state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{:?}", run.state))
}

/// Load every component of each selected run, paging the bounded inventory
/// read model until the run's whole component population is in memory.
pub fn load_inventories(
    repository: &FindingsRepository,
    runs: &[oxaudit_domain::Run],
) -> Result<Vec<MonitoredInventory>, String> {
    let mut inventories = Vec::new();
    for run in runs {
        let run_id =
            oxaudit_domain::RunId::parse(run.id.to_string()).map_err(|error| error.to_string())?;
        let mut components = Vec::new();
        let mut offset = 0u32;
        loop {
            let page = repository
                .inventory_page(
                    &run_id,
                    &ResultPageQuery {
                        offset,
                        limit: PAGE_SIZE,
                        ..ResultPageQuery::default()
                    },
                )
                .map_err(|error| format!("run {}: {error}", run.id))?;
            let fetched = page.page.items.len();
            components.extend(page.page.items);
            if fetched < PAGE_SIZE as usize {
                break;
            }
            offset += PAGE_SIZE;
        }
        inventories.push(MonitoredInventory {
            run: run.clone(),
            components,
        });
    }
    Ok(inventories)
}

/// The ecosystems the given inventories would query, sorted and deduplicated.
/// `--update` refreshes exactly this set, so monitoring never downloads an
/// ecosystem no monitored project uses.
pub fn ecosystems_used(inventories: &[MonitoredInventory]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for inventory in inventories {
        for component in &inventory.components {
            if queryable(component) {
                if let Some(ecosystem) = &component.ecosystem {
                    set.insert(ecosystem.clone());
                }
            }
        }
    }
    set.into_iter().collect()
}

/// Only components that carry a purl were registry-queryable at scan time;
/// `dependency_graph` sets a purl exactly for those. Git/local-sourced
/// declarations deliberately carry none and stay outside re-matching, the
/// same exclusion the original scan applied.
fn queryable(component: &InventoryComponentView) -> bool {
    component.purl.is_some()
        && component
            .version
            .as_deref()
            .is_some_and(|v| !v.trim().is_empty())
        && !component.name.trim().is_empty()
        && component
            .ecosystem
            .as_deref()
            .is_some_and(|e| e != "unknown")
}

fn rebuild_dependency(component: &InventoryComponentView) -> Option<Dependency> {
    if !queryable(component) {
        return None;
    }
    Some(Dependency {
        ecosystem: component
            .ecosystem
            .clone()
            .expect("queryable has ecosystem"),
        name: component.name.clone(),
        version: component.version.clone().expect("queryable has version"),
        lockfile: String::new(),
        occurrence: DependencyOccurrence::default(),
        license: None,
    })
}

/// Re-match every inventory against the advisory database and compute the
/// per-run delta. The stored runs and their evidence are never written.
pub fn monitor(
    advisory_db: &AdvisoryDb,
    inventories: &[MonitoredInventory],
) -> Result<MonitorOutcome, String> {
    let mut runs = Vec::with_capacity(inventories.len());
    for inventory in inventories {
        let mut monitored = MonitoredRun {
            run_id: inventory.run.id.to_string(),
            target: inventory.run.target_label.clone(),
            updated_at_ms: inventory.run.updated_at_ms,
            components_total: inventory.components.len(),
            components_matched: 0,
            newly_matching: Vec::new(),
            coverage_error: None,
            notes: Vec::new(),
        };
        let deps: Vec<Dependency> = inventory
            .components
            .iter()
            .filter_map(rebuild_dependency)
            .collect();
        monitored.components_matched = deps.len();
        if deps.is_empty() {
            // Nothing was ever queried for this inventory; monitoring has no
            // advisory claim to compare and must say so instead of implying
            // a verified clean state.
            monitored.notes.push(
                "this inventory declares no registry-queryable packages; no advisories were re-matched"
                    .into(),
            );
            runs.push(monitored);
            continue;
        }
        match crate::advisories::matching::query_local(advisory_db, &deps) {
            Err(error) => {
                monitored.coverage_error = Some(error);
            }
            Ok(outcome) => {
                monitored.notes = outcome.notes.warnings();
                let by_key: std::collections::HashMap<String, Vec<crate::models::Vulnerability>> =
                    outcome.results;
                for (component, dep) in inventory.components.iter().zip(deps.iter()) {
                    let Some(vulns) = by_key.get(&crate::deps::osv::dependency_query_key(dep))
                    else {
                        continue;
                    };
                    let reported: HashSet<&str> =
                        component.advisory_ids.iter().map(String::as_str).collect();
                    for vuln in vulns {
                        let already_reported = reported.contains(vuln.id.as_str())
                            || vuln.aliases.iter().any(|a| reported.contains(a.as_str()));
                        if already_reported {
                            continue;
                        }
                        monitored.newly_matching.push(NewAdvisory {
                            ecosystem: vuln.ecosystem.clone(),
                            package: vuln.package_name.clone(),
                            installed_version: vuln.installed_version.clone(),
                            advisory_id: vuln.id.clone(),
                            aliases: vuln.aliases.clone(),
                            summary: vuln.summary.clone(),
                            severity: vuln.severity.clone(),
                            cvss_score: vuln.cvss_score,
                            fixed_versions: vuln.fixed_versions.clone(),
                        });
                    }
                }
                monitored
                    .newly_matching
                    .sort_by(|a, b| a.advisory_id.cmp(&b.advisory_id));
            }
        }
        runs.push(monitored);
    }
    Ok(MonitorOutcome {
        advisory_db_built_at_ms: advisory_db.built_at_ms(),
        runs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxaudit_domain::{Component, Run, RunKind, RunState};
    use serde_json::json;
    use std::future::Future;

    fn test_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
    }

    fn stored_run(repository: &FindingsRepository, target: &str, updated_at_ms: u64) -> Run {
        let mut run = Run::queued(RunKind::Dependencies, target.to_string(), updated_at_ms);
        run.state = RunState::Completed;
        run.updated_at_ms = updated_at_ms;
        repository.canonical_create_run(&run).unwrap();
        run
    }

    fn component(
        id: &str,
        ecosystem: &str,
        name: &str,
        version: &str,
        purl: Option<&str>,
    ) -> Component {
        serde_json::from_value(json!({
            "id": id, "name": name, "version": version, "supplier": null,
            "ecosystem": ecosystem, "purl": purl, "cpes": [], "aliases": [],
            "identities": [{"method": "declared_manifest", "value": format!("{name}@{version}"),
                "confidence": 1.0, "sourceArtifactId": format!("artifact_{id}")}]
        }))
        .unwrap()
    }

    fn advisory_observation(
        run: &Run,
        component_id: &str,
        advisory_id: &str,
    ) -> oxaudit_application::ObservationRecord {
        let value = json!({
            "observation": {"id": format!("observation_{advisory_id}"), "runId": run.id,
                "artifactId": format!("artifact_{component_id}"),
                "kind": "advisory_match", "detectorId": "fixture", "detectorVersion": "1",
                "ruleId": advisory_id, "title": advisory_id, "summary": "stored advisory",
                "evidenceIds": [format!("evidence_{advisory_id}")]},
            "evidence": [{"id": format!("evidence_{advisory_id}"),
                "evidence": {"kind": "advisory_match", "details": {
                    "componentId": component_id, "providerSnapshotId": "provider_fixture",
                    "advisoryId": advisory_id, "affected": true,
                    "rationale": "stored run reported this advisory"}}}]
        });
        oxaudit_application::ObservationRecord {
            observation: serde_json::from_value(value["observation"].clone()).unwrap(),
            evidence: serde_json::from_value(value["evidence"].clone()).unwrap(),
        }
    }

    /// A stored dependencies run over two npm packages; `left` already
    /// reported `GHSA-old` at scan time.
    fn populated_repository() -> (FindingsRepository, Run) {
        let repository = FindingsRepository::open_in_memory().unwrap();
        let run = stored_run(&repository, "/project/fixture", 1_000);
        repository
            .canonical_append_observations(
                &run.id,
                &[advisory_observation(&run, "component_left", "GHSA-old")],
            )
            .unwrap();
        repository
            .canonical_append_components(
                &run.id,
                &[
                    component(
                        "component_left",
                        "npm",
                        "left-pad",
                        "1.0.0",
                        Some("pkg/npm/left-pad@1.0.0"),
                    ),
                    component(
                        "component_right",
                        "npm",
                        "right-pad",
                        "2.0.0",
                        Some("pkg/npm/right-pad@2.0.0"),
                    ),
                ],
            )
            .unwrap();
        (repository, run)
    }

    struct FixtureFetcher {
        dumps: std::collections::HashMap<String, Vec<u8>>,
    }

    impl crate::advisories::ingest::DumpFetcher for FixtureFetcher {
        fn fetch<'a>(
            &'a mut self,
            ecosystem: &'a str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
            Box::pin(async move {
                self.dumps
                    .get(ecosystem)
                    .cloned()
                    .ok_or_else(|| format!("no fixture dump for {ecosystem}"))
            })
        }
    }

    fn dump_zip(records: &[(String, String)]) -> Vec<u8> {
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in records {
            writer
                .start_file(name.clone(), zip::write::SimpleFileOptions::default())
                .unwrap();
            std::io::Write::write_all(&mut writer, body.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn advisory_json(id: &str, package: &str, fixed: &str, aliases: &[&str]) -> String {
        let mut record = json!({
            "id": id,
            "modified": "2024-05-01T00:00:00Z",
            "summary": format!("fixture advisory {id}"),
            "affected": [{
                "package": { "ecosystem": "npm", "name": package },
                "ranges": [{ "type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": fixed}] }]
            }]
        });
        if !aliases.is_empty() {
            record["aliases"] = json!(aliases);
        }
        record.to_string()
    }

    fn advisory_db(records: &[(String, String)]) -> AdvisoryDb {
        let mut db = AdvisoryDb::open_in_memory().unwrap();
        let mut fetcher = FixtureFetcher {
            dumps: std::collections::HashMap::from([("npm".to_string(), dump_zip(records))]),
        };
        test_runtime()
            .block_on(crate::advisories::ingest::update(
                &mut db,
                &["npm".to_string()],
                &mut fetcher,
                |_| {},
            ))
            .unwrap();
        db
    }

    fn monitor_repository(repository: &FindingsRepository, db: &AdvisoryDb) -> MonitorOutcome {
        let runs = select_runs(repository, &[]).unwrap();
        let inventories = load_inventories(repository, &runs).unwrap();
        monitor(db, &inventories).unwrap()
    }

    #[test]
    fn reports_advisories_the_stored_run_did_not_report() {
        let (repository, run) = populated_repository();
        let db = advisory_db(&[
            (
                "GHSA-old.json".to_string(),
                advisory_json("GHSA-old", "left-pad", "9.0.0", &[]),
            ),
            (
                "GHSA-new.json".to_string(),
                advisory_json("GHSA-new", "left-pad", "2.0.0", &[]),
            ),
            (
                "GHSA-right.json".to_string(),
                advisory_json("GHSA-right", "right-pad", "3.0.0", &[]),
            ),
        ]);
        let outcome = monitor_repository(&repository, &db);
        assert_eq!(outcome.runs.len(), 1);
        let monitored = &outcome.runs[0];
        assert_eq!(monitored.run_id, run.id.to_string());
        assert_eq!(monitored.components_total, 2);
        assert_eq!(monitored.components_matched, 2);
        assert!(monitored.coverage_error.is_none());
        let ids: Vec<&str> = monitored
            .newly_matching
            .iter()
            .map(|a| a.advisory_id.as_str())
            .collect();
        // GHSA-old was reported by the stored run; only the other two are new.
        assert_eq!(ids, ["GHSA-new", "GHSA-right"]);
        assert_eq!(monitored.newly_matching[0].package, "left-pad");
        assert_eq!(monitored.newly_matching[0].installed_version, "1.0.0");
        assert_eq!(monitored.newly_matching[0].fixed_versions, vec!["2.0.0"]);
    }

    #[test]
    fn an_alias_of_a_stored_advisory_is_not_new() {
        let (repository, _) = populated_repository();
        // The stored run reported GHSA-old; the refreshed database carries
        // the same advisory under its CVE alias as the record id.
        let db = advisory_db(&[(
            "CVE-old.json".to_string(),
            advisory_json("CVE-old", "left-pad", "9.0.0", &["GHSA-old"]),
        )]);
        let outcome = monitor_repository(&repository, &db);
        assert!(outcome.runs[0].newly_matching.is_empty());
    }

    #[test]
    fn a_missing_ecosystem_dump_is_a_coverage_error_not_a_clean_result() {
        let (repository, _) = populated_repository();
        // An empty-but-present npm dump indexes nothing; PyPI was never
        // downloaded, so a PyPI inventory must fail coverage.
        let repository_py = {
            let repository = FindingsRepository::open_in_memory().unwrap();
            let run = stored_run(&repository, "/project/pypi", 2_000);
            repository
                .canonical_append_components(
                    &run.id,
                    &[component(
                        "component_django",
                        "PyPI",
                        "django",
                        "3.2",
                        Some("pkg/pypi/django@3.2"),
                    )],
                )
                .unwrap();
            repository
        };
        let db = advisory_db(&[]);
        let outcome = monitor_repository(&repository_py, &db);
        let error = outcome.runs[0].coverage_error.as_deref().unwrap();
        assert!(
            error.contains("PyPI"),
            "coverage error names the ecosystem: {error}"
        );
        assert!(outcome.runs[0].newly_matching.is_empty());
        assert!(!outcome.coverage_errors().is_empty());
        // The npm repository still monitors cleanly in the same database.
        let outcome = monitor_repository(&repository, &db);
        assert!(outcome.runs[0].coverage_error.is_none());
    }

    #[test]
    fn git_and_local_components_were_never_queried_and_stay_excluded() {
        let repository = FindingsRepository::open_in_memory().unwrap();
        let run = stored_run(&repository, "/project/mixed", 3_000);
        repository
            .canonical_append_components(
                &run.id,
                &[
                    component(
                        "component_registry",
                        "npm",
                        "registry-pkg",
                        "1.0.0",
                        Some("pkg/npm/registry-pkg@1.0.0"),
                    ),
                    // A git-sourced declaration carries no purl: the scan
                    // never queried it and neither does monitoring.
                    component("component_git", "npm", "git-pkg", "abc123", None),
                ],
            )
            .unwrap();
        let db = advisory_db(&[(
            "GHSA-both.json".to_string(),
            advisory_json("GHSA-both", "git-pkg", "2.0.0", &[]),
        )]);
        let runs = select_runs(&repository, &[]).unwrap();
        let inventories = load_inventories(&repository, &runs).unwrap();
        assert_eq!(ecosystems_used(&inventories), vec!["npm"]);
        let outcome = monitor(&db, &inventories).unwrap();
        let monitored = &outcome.runs[0];
        assert_eq!(monitored.components_total, 2);
        assert_eq!(monitored.components_matched, 1);
        // The advisory affects only the excluded component, so the delta is
        // empty while the counts state what was and was not re-matched.
        assert!(monitored.newly_matching.is_empty());
    }

    #[test]
    fn selection_keeps_the_latest_completed_run_per_target() {
        let repository = FindingsRepository::open_in_memory().unwrap();
        let old = stored_run(&repository, "/project/a", 100);
        let new = stored_run(&repository, "/project/a", 200);
        let other = stored_run(&repository, "/project/b", 150);
        let mut failed = Run::queued(RunKind::Dependencies, "/project/a".to_string(), 300);
        failed.state = RunState::Failed;
        repository.canonical_create_run(&failed).unwrap();
        let runs = select_runs(&repository, &[]).unwrap();
        let targets: Vec<(String, u64)> = runs
            .iter()
            .map(|run| (run.target_label.clone(), run.updated_at_ms))
            .collect();
        assert_eq!(
            targets,
            vec![
                ("/project/a".to_string(), 200),
                ("/project/b".to_string(), 150)
            ]
        );
        assert_ne!(old.id, new.id);
        assert_ne!(new.id, other.id);
    }

    #[test]
    fn an_explicit_run_id_must_be_a_completed_dependencies_run() {
        let (repository, run) = populated_repository();
        let runs = select_runs(&repository, &[run.id.to_string()]).unwrap();
        assert_eq!(runs.len(), 1);

        let missing = select_runs(&repository, &["run_missing".to_string()]).unwrap_err();
        assert!(missing.contains("run_missing"), "{missing}");

        let repository_other = FindingsRepository::open_in_memory().unwrap();
        let mut source = Run::queued(RunKind::Source, "/project/s".to_string(), 1);
        source.state = RunState::Completed;

        repository_other.canonical_create_run(&source).unwrap();
        let wrong_kind = select_runs(&repository_other, &[source.id.to_string()]).unwrap_err();
        assert!(wrong_kind.contains("dependencies run"), "{wrong_kind}");

        let unfinished = Run::queued(RunKind::Dependencies, "/project/u".to_string(), 2);
        repository_other.canonical_create_run(&unfinished).unwrap();
        let not_completed =
            select_runs(&repository_other, &[unfinished.id.to_string()]).unwrap_err();
        assert!(not_completed.contains("not completed"), "{not_completed}");
    }

    #[test]
    fn selection_reaches_targets_beyond_the_listing_page_cap() {
        // `canonical_list_runs` clamps to one hundred rows; a monitor that
        // selected through it would silently drop every target whose only
        // run sits outside the newest page and still report success. This
        // fixture puts one hundred and twenty runs on /project/many and a
        // single old run on /project/quiet, then requires both targets.
        let repository = FindingsRepository::open_in_memory().unwrap();
        for n in 1..=120u64 {
            stored_run(&repository, "/project/many", n);
        }
        stored_run(&repository, "/project/quiet", 5);
        let runs = select_runs(&repository, &[]).unwrap();
        let selected: Vec<(String, u64)> = runs
            .into_iter()
            .map(|run| (run.target_label, run.updated_at_ms))
            .collect();
        assert_eq!(
            selected,
            vec![
                ("/project/many".to_string(), 120),
                ("/project/quiet".to_string(), 5),
            ],
            "every target's latest completed run must be monitored, page cap or not"
        );
    }

    #[test]
    fn inventories_page_past_the_two_hundred_component_boundary() {
        let repository = FindingsRepository::open_in_memory().unwrap();
        let run = stored_run(&repository, "/project/wide", 4_000);
        let components: Vec<Component> = (0..405)
            .map(|n| {
                component(
                    &format!("component_{n:04}"),
                    "npm",
                    &format!("package-{n:04}"),
                    "1.0.0",
                    Some("pkg/npm/package@1.0.0"),
                )
            })
            .collect();
        repository
            .canonical_append_components(&run.id, &components)
            .unwrap();
        let runs = select_runs(&repository, &[]).unwrap();
        let inventories = load_inventories(&repository, &runs).unwrap();
        assert_eq!(inventories[0].components.len(), 405);
    }
}
