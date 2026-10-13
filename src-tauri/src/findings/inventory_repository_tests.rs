use super::*;
use crate::findings::domain::ResultPageQuery;
use oxaudit_domain::{Artifact, Component, Run, RunKind, RunState};
use serde_json::json;

fn saved_run(repository: &FindingsRepository, kind: RunKind, n: u64) -> Run {
    let mut run = Run::queued(kind, format!("/inventory/{n}"), n);
    run.state = RunState::Completed;
    repository.canonical_create_run(&run).unwrap();
    run
}

fn component(n: usize) -> Component {
    serde_json::from_value(json!({
        "id": format!("component_{n:04}"), "name": format!("package-{n:04}"), "version": "1.0",
        "supplier": "Example", "ecosystem": "generic", "purl": null, "cpes": [],
        "aliases": if n == 202 { vec!["ÉCLAIR", "literal%_value"] } else { vec![] },
        "identities": [{"method":"package_metadata", "value":"declared version", "confidence":1.0,
            "sourceArtifactId":"artifact_inventory"}]
    }))
    .unwrap()
}

fn advisory(run: &Run) -> oxaudit_application::ObservationRecord {
    let value = json!({
        "observation": {"id":"observation_inventory", "runId":run.id, "artifactId":"artifact_inventory",
            "kind":"binary_component", "detectorId":"fixture", "detectorVersion":"1", "ruleId":null,
            "title":"Component match", "summary":"Fixture evidence", "evidenceIds":["evidence_inventory"]},
        "evidence":[{"id":"evidence_inventory", "evidence":{"kind":"advisory_match", "details":{
            "componentId":"component_0202", "providerSnapshotId":"provider_inventory", "advisoryId":"CVE-2026-1234",
            "affected":true, "rationale":"Fixture match"}}}]
    });
    oxaudit_application::ObservationRecord {
        observation: serde_json::from_value(value["observation"].clone()).unwrap(),
        evidence: serde_json::from_value(value["evidence"].clone()).unwrap(),
    }
}

fn populate(repository: &FindingsRepository) -> Run {
    let run = saved_run(repository, RunKind::Image, 1);
    // Evidence may arrive before the component or its artifact.
    repository
        .canonical_append_observations(&run.id, &[advisory(&run)])
        .unwrap();
    repository
        .canonical_append_components(&run.id, &(0..205).map(component).collect::<Vec<_>>())
        .unwrap();
    let artifact: Artifact =
        serde_json::from_value(json!({"id":"artifact_inventory", "kind":"archive_member",
        "location":{"normalizedPath":"layer!/packages", "canonicalPath":null, "parentId":null},
        "sizeBytes":1, "mediaType":null, "contentSha256":null}))
        .unwrap();
    repository
        .canonical_append_artifact(&run.id, &artifact)
        .unwrap();
    run
}

#[test]
fn inventory_runs_page_beyond_unrelated_recent_activity_and_the_first_hundred() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    for n in 0..120 {
        saved_run(&repository, RunKind::Image, n);
    }
    for n in 120..250 {
        saved_run(&repository, RunKind::Source, n);
    }
    let failed = Run::queued(RunKind::Binary, "/unfinished", 999);
    repository.canonical_create_run(&failed).unwrap();
    let first = repository
        .inventory_runs_page(&ResultPageQuery::default())
        .unwrap();
    assert_eq!(
        (first.total, first.filtered_total, first.items.len()),
        (120, 120, 50)
    );
    assert_eq!(first.items[0].target_label, "/inventory/119");
    let last = repository
        .inventory_runs_page(&ResultPageQuery {
            offset: 100,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(last.items.len(), 20);
    assert_eq!(last.items.last().unwrap().target_label, "/inventory/0");
}

#[test]
fn inventory_pages_preserve_counts_unicode_search_and_related_evidence() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let run = populate(&repository);
    let page = repository
        .inventory_page(
            &run.id,
            &ResultPageQuery {
                offset: 200,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        (
            page.page.total,
            page.page.filtered_total,
            page.page.items.len()
        ),
        (205, 205, 5)
    );
    assert_eq!(page.page.items[2].id, "component_0202");
    assert_eq!(
        page.page.items[2].identities[0].artifact_path,
        "layer!/packages"
    );
    assert_eq!(page.page.items[2].advisory_ids, ["CVE-2026-1234"]);
    for search in ["éclair", "cve-2026-1234", "literal%_value"] {
        let filtered = repository
            .inventory_page(
                &run.id,
                &ResultPageQuery {
                    search: search.into(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            (filtered.page.total, filtered.page.filtered_total),
            (205, 1)
        );
        assert_eq!(filtered.page.items[0].id, "component_0202");
    }
    let empty = repository
        .inventory_page(
            &run.id,
            &ResultPageQuery {
                search: "missing".into(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        (
            empty.page.total,
            empty.page.filtered_total,
            empty.page.items.len()
        ),
        (205, 0, 0)
    );
    repository
        .canonical_append_observations(&run.id, &[advisory(&run)])
        .unwrap();
    repository
        .canonical_append_components(&run.id, &[component(202)])
        .unwrap();
    let again = repository
        .inventory_page(
            &run.id,
            &ResultPageQuery {
                search: "cve-2026-1234".into(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(again.page.filtered_total, 1);
}

#[test]
fn inventory_page_does_not_deserialize_components_outside_the_requested_page() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let run = populate(&repository);
    repository
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE canonical_components SET payload_json='invalid' WHERE id='component_0204'",
            [],
        )
        .unwrap();
    let page = repository
        .inventory_page(&run.id, &ResultPageQuery::default())
        .unwrap();
    assert_eq!((page.page.total, page.page.items.len()), (205, 50));
    assert!(repository
        .inventory_page(
            &run.id,
            &ResultPageQuery {
                offset: 200,
                ..Default::default()
            }
        )
        .is_err());
}

#[test]
fn inventory_index_migration_backfills_existing_evidence_and_reopens_idempotently() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("private/findings.sqlite3");
    let repository = FindingsRepository::open(&path).unwrap();
    let run = populate(&repository);
    let before = repository.canonical_load_report_graph(&run.id).unwrap();
    repository.connection.lock().unwrap().execute_batch("DROP TABLE inventory_component_search; DROP TABLE inventory_advisories; DELETE FROM schema_migrations WHERE version=9;").unwrap();
    drop(repository);
    for _ in 0..2 {
        let repository = FindingsRepository::open(&path).unwrap();
        let page = repository
            .inventory_page(
                &run.id,
                &ResultPageQuery {
                    search: "cve-2026-1234".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!((page.page.total, page.page.filtered_total), (205, 1));
        assert_eq!(
            page.page.items[0].identities[0].artifact_path,
            "layer!/packages"
        );
        assert_eq!(
            repository.canonical_load_report_graph(&run.id).unwrap(),
            before
        );
    }
}

#[test]
fn inventory_queries_reject_invalid_bounds_and_missing_runs() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let run = populate(&repository);
    for query in [
        ResultPageQuery {
            limit: 0,
            ..Default::default()
        },
        ResultPageQuery {
            limit: 201,
            ..Default::default()
        },
        ResultPageQuery {
            search: "x".repeat(4097),
            ..Default::default()
        },
        ResultPageQuery {
            sort: "unknown".into(),
            ..Default::default()
        },
    ] {
        assert!(repository.inventory_page(&run.id, &query).is_err());
        assert!(repository.inventory_runs_page(&query).is_err());
    }
    assert!(repository
        .inventory_page(
            &oxaudit_domain::RunId::parse("run_missing").unwrap(),
            &ResultPageQuery::default()
        )
        .is_err());
}
