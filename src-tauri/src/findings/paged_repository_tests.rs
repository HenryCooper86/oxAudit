use super::*;
use crate::findings::domain::{ResultPageQuery, SourceFindingsQuery};
use serde_json::{json, Value};

fn canonical_fixture(
    repository: &FindingsRepository,
    kind: oxaudit_domain::RunKind,
    payload: Value,
) -> oxaudit_domain::RunId {
    let mut run = oxaudit_domain::Run::queued(kind, "/saved/target", 1);
    run.state = oxaudit_domain::RunState::Completed;
    repository.canonical_create_run(&run).unwrap();
    let kind = enum_name(&run.kind).unwrap();
    repository
        .canonical_save_projection(&run.id, &kind, 1, &payload)
        .unwrap();
    run.id
}

#[test]
fn canonical_pages_preserve_complete_rows_and_global_counts_across_filters() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let rows=(0..123).map(|ordinal|json!({
        "id":format!("CVE-{ordinal:03}"),"packageName":if ordinal%2==0 {"Éclair"} else {"other"},
        "summary":"advisory","aliases":["GHSA-extra"],"severity":if ordinal%3==0 {"critical"} else {"high"},
        "fixedVersions":["2.0"],"occurrence":{"installPath":format!("node_modules/{ordinal}")}
    })).collect::<Vec<_>>();
    let payload = json!({"summary":{"packagesFound":123,"vulnerabilitiesFound":123,"advisoryCoverage":"complete"},
        "dependencies":[{"name":"a","version":"1"}],"vulnerabilities":rows});
    let run = canonical_fixture(
        &repository,
        oxaudit_domain::RunKind::Dependencies,
        payload.clone(),
    );
    let header = repository.canonical_projection_metadata(&run).unwrap();
    assert_eq!(header.kind, "pagedProjection");
    assert_eq!(header.projection["vulnerabilities"], json!([]));
    assert_eq!(header.sections["vulnerabilities"], 123);
    assert_eq!(header.projection["summary"], payload["summary"]);
    let page = repository
        .canonical_projection_page(
            &run,
            "vulnerabilities",
            &ResultPageQuery {
                offset: 4,
                limit: 7,
                severity: Some("critical".into()),
                search: "ÉCLAIR".into(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(page.total, 123);
    assert_eq!(page.filtered_total, 21);
    assert_eq!(page.items.len(), 7);
    assert_eq!(page.items[0], rows[24]);
    assert_eq!(page.items[6], rows[60]);
    assert_eq!(
        repository.canonical_load_projection(&run).unwrap().unwrap(),
        payload
    );
}

#[test]
fn canonical_projection_index_preserves_json_values_without_narrowing_full_payload_contract() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let rows = json!([{"name":"known"}, "future-row", u64::MAX, 7.25, null, true, false, [{"nested":"value"}]]);
    let payload = json!({"summary": {}, "dependencies": rows, "vulnerabilities": []});
    let run = canonical_fixture(
        &repository,
        oxaudit_domain::RunKind::Dependencies,
        payload.clone(),
    );
    let page = repository
        .canonical_projection_page(&run, "dependencies", &Default::default())
        .unwrap();
    assert_eq!(page.total, 8);
    assert_eq!(page.items, rows.as_array().unwrap().clone());
    assert_eq!(
        repository.canonical_load_projection(&run).unwrap().unwrap(),
        payload
    );
    {
        let mut connection = repository.connection.lock().unwrap();
        connection
            .execute_batch(
                "DROP TABLE canonical_history_blob_links; DROP TABLE canonical_projection_items;
             DROP TABLE canonical_projection_metadata; DROP TABLE source_finding_index;
             DELETE FROM schema_migrations WHERE version=8;",
            )
            .unwrap();
        paging::migrate_paged_storage(&mut connection).unwrap();
    }
    assert_eq!(
        repository
            .canonical_projection_page(&run, "dependencies", &Default::default())
            .unwrap()
            .items,
        rows.as_array().unwrap().clone()
    );
}

#[test]
fn canonical_page_deserializes_only_requested_rows_and_rejects_unbounded_queries() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let run = canonical_fixture(
        &repository,
        oxaudit_domain::RunKind::Dependencies,
        json!({
            "summary":{},"dependencies":[],"vulnerabilities":[{"id":"first"},{"id":"off-page"}]
        }),
    );
    repository.connection.lock().unwrap().execute(
        "UPDATE canonical_projection_items SET payload_json='invalid json' WHERE run_id=?1 AND section='vulnerabilities' AND ordinal=1",
        [run.as_str()],
    ).unwrap();
    let page = repository
        .canonical_projection_page(
            &run,
            "vulnerabilities",
            &ResultPageQuery {
                limit: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(page.items[0]["id"], "first");
    assert_eq!(page.total, 2);
    assert!(repository
        .canonical_projection_page(
            &run,
            "vulnerabilities",
            &ResultPageQuery {
                offset: 1,
                limit: 1,
                ..Default::default()
            }
        )
        .is_err());
    for limit in [0, 201, u32::MAX] {
        assert!(repository
            .canonical_projection_page(
                &run,
                "vulnerabilities",
                &ResultPageQuery {
                    limit,
                    ..Default::default()
                }
            )
            .is_err());
    }
    let page = repository
        .canonical_projection_page(
            &run,
            "vulnerabilities",
            &ResultPageQuery {
                search: "'; DROP TABLE findings; --".into(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(page.filtered_total, 0);
    assert!(page.items.is_empty());
    assert!(repository
        .canonical_projection_page(&run, "not-a-section", &Default::default())
        .is_err());
}

#[test]
fn binary_and_image_component_pages_keep_minimum_severity_and_semantic_context() {
    for kind in [
        oxaudit_domain::RunKind::Binary,
        oxaudit_domain::RunKind::Image,
    ] {
        let repository = FindingsRepository::open_in_memory().unwrap();
        let scan = json!({"target":"/saved/target","summary":{"components":3,"vulnerabilities":4},
            "components":[
                {"product":"unknown","vulnerabilities":[{"severity":"unknown","cveId":"unknown"}]},
                {"product":"high","vulnerabilities":[{"severity":"low"},{"severity":"high"}]},
                {"product":"critical","vulnerabilities":[{"severity":"critical"}]}
            ],"semanticAnalysis":{"architecture":"x86_64","functionsAnalyzed":8,"findings":[{"ruleId":"danger","functionAddress":42}]}});
        let payload = if kind == oxaudit_domain::RunKind::Image {
            json!({"runId":null,"result":scan,"layers":[{"digest":"sha256:a"}],"offline":true,
                "localEvidence":{"file":{"sha256":"digest"}}})
        } else {
            scan.clone()
        };
        let run = canonical_fixture(&repository, kind, payload.clone());
        let header = repository.canonical_projection_metadata(&run).unwrap();
        let scan_header = if kind == oxaudit_domain::RunKind::Image {
            &header.projection["result"]
        } else {
            &header.projection
        };
        assert_eq!(scan_header["components"], json!([]));
        assert_eq!(scan_header["semanticAnalysis"]["findings"], json!([]));
        assert_eq!(scan_header["semanticAnalysis"]["functionsAnalyzed"], 8);
        let page = repository
            .canonical_projection_page(
                &run,
                "components",
                &ResultPageQuery {
                    minimum_severity: Some("high".into()),
                    limit: 1,
                    offset: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.filtered_total, 2);
        assert_eq!(page.items[0]["product"], "critical");
        let first = repository
            .canonical_projection_page(
                &run,
                "components",
                &ResultPageQuery {
                    minimum_severity: Some("high".into()),
                    limit: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            first.items[0]["vulnerabilities"].as_array().unwrap().len(),
            2
        );
        assert_eq!(
            repository
                .canonical_projection_page(&run, "semanticFindings", &Default::default())
                .unwrap()
                .items,
            scan["semanticAnalysis"]["findings"]
                .as_array()
                .unwrap()
                .clone()
        );
    }
}

#[test]
fn history_findings_pages_attach_only_their_blob_links_and_evidence() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let payload = json!({"findings":[{"id":"a","severity":"high","filePath":"src/a","line":1},
            {"id":"b","severity":"critical","filePath":"src/b","line":1}],
        "blobs":[{"oid":"oid-a","contentSha256":"hash-a"},{"oid":"oid-b","contentSha256":"hash-b"}],
        "findingBlobIds":{"a":"oid-a","b":"oid-b"},"blobsScanned":2,"coverage":{"maxBlobs":100000}});
    let run = canonical_fixture(
        &repository,
        oxaudit_domain::RunKind::History,
        payload.clone(),
    );
    let header = repository.canonical_projection_metadata(&run).unwrap();
    assert_eq!(header.projection["blobs"], json!([]));
    assert_eq!(header.projection["findingBlobIds"], json!({}));
    assert_eq!(header.projection["coverage"], payload["coverage"]);
    let page = repository
        .canonical_projection_page(
            &run,
            "findings",
            &ResultPageQuery {
                limit: 1,
                sort: "severity".into(),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(page.items[0]["id"], "b");
    assert_eq!(
        page.related.unwrap(),
        json!({"blobs":[payload["blobs"][1]],"findingBlobIds":{"b":"oid-b"}})
    );
}

#[test]
fn legacy_paged_migration_is_atomic_idempotent_and_preserves_original_payloads() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let run = canonical_fixture(
        &repository,
        oxaudit_domain::RunKind::Dependencies,
        json!({
            "summary":{"advisoryCoverage":"unknown"},"dependencies":[{"name":"legacy"}],"vulnerabilities":[{"id":"old","severity":"medium"}]
        }),
    );
    prepare_run(&repository, "legacy-source");
    let detail = run_detail(
        "legacy-source",
        RunStatus::Completed,
        vec![finding("legacy-source-f", "legacy-source-fp")],
    );
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);
    repository.complete_run(&detail, &coverage).unwrap();
    let mut connection = repository.connection.lock().unwrap();
    let original: String = connection
        .query_row(
            "SELECT payload_json FROM canonical_projections WHERE run_id=?1",
            [run.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    connection
        .execute_batch(
            "DROP TABLE canonical_history_blob_links; DROP TABLE canonical_projection_items;
         DROP TABLE canonical_projection_metadata; DROP TABLE source_finding_index;
         DELETE FROM schema_migrations WHERE version=8;",
        )
        .unwrap();
    paging::migrate_paged_storage(&mut connection).unwrap();
    paging::migrate_paged_storage(&mut connection).unwrap();
    let stored: String = connection
        .query_row(
            "SELECT payload_json FROM canonical_projections WHERE run_id=?1",
            [run.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, original);
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM canonical_projection_items",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM source_finding_index", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 1);
    connection
        .execute("DELETE FROM canonical_runs WHERE id=?1", [run.as_str()])
        .unwrap();
    let count: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM canonical_projection_items",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn source_pages_match_complete_baseline_statuses_and_global_view_counts() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let baseline_coverage = CoverageManifest::from_entries([
        ("src/shared.rs", ["secret"]),
        ("src/resolved.rs", ["secret"]),
        ("src/unread.rs", ["secret"]),
    ]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "page-baseline",
        "2026-08-20T09:00:00Z",
        vec![
            finding_at(
                "old-shared",
                "shared",
                "secret",
                "src/shared.rs",
                FindingScope::Production,
            ),
            finding_at(
                "old-resolved",
                "resolved",
                "secret",
                "src/resolved.rs",
                FindingScope::Production,
            ),
            finding_at(
                "old-unread",
                "unread",
                "secret",
                "src/unread.rs",
                FindingScope::Documentation,
            ),
        ],
        &baseline_coverage,
    );
    let coverage = CoverageManifest::from_entries([
        ("src/shared.rs", ["secret"]),
        ("src/resolved.rs", ["secret"]),
        ("src/new.rs", ["secret"]),
    ]);
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "page-current",
        "2026-08-20T11:00:00Z",
        vec![
            finding_at(
                "new-shared",
                "shared",
                "secret",
                "src/shared.rs",
                FindingScope::Production,
            ),
            finding_at("new-new", "new", "secret", "src/new.rs", FindingScope::Test),
        ],
        &coverage,
    );
    let full = repository.load_run("page-current").unwrap();
    let page = repository
        .source_run_page(
            "page-current",
            &SourceFindingsQuery {
                page: ResultPageQuery {
                    limit: 10,
                    sort: "original".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            true,
            Utc::now(),
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(&page.page.items).unwrap(),
        serde_json::to_value(&full.findings).unwrap()
    );
    assert_eq!(page.page.total, 4);
    assert_eq!(page.diff_counts.new, 1);
    assert_eq!(page.diff_counts.unchanged, 1);
    assert_eq!(page.diff_counts.resolved, 1);
    assert_eq!(page.diff_counts.not_evaluated, 1);
    assert_eq!(page.view_counts.open, 1);
    assert_eq!(page.view_counts.other_scopes, 2);
    assert_eq!(page.view_counts.resolved, 1);
    let selected = repository
        .source_run_page(
            "page-current",
            &SourceFindingsQuery {
                view: "resolved".into(),
                page: ResultPageQuery {
                    limit: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
            true,
            Utc::now(),
        )
        .unwrap();
    assert_eq!(selected.page.items[0].fingerprint, "resolved");
    assert_eq!(selected.page.filtered_total, 1);
    assert_eq!(selected.page.total, 4);
    assert_eq!(selected.diff_counts.new, 1);
    let paths = repository
        .source_run_page(
            "page-current",
            &SourceFindingsQuery {
                file_paths: Some(vec!["src/shared.rs".into(), "src/resolved.rs".into()]),
                ..Default::default()
            },
            true,
            Utc::now(),
        )
        .unwrap();
    assert_eq!(paths.page.filtered_total, 1);
    assert_eq!(paths.page.items[0].id, "new-shared");
    repository
        .connection
        .lock()
        .unwrap()
        .execute("DELETE FROM scan_runs WHERE id='page-baseline'", [])
        .unwrap();
    let page = repository
        .source_run_page("page-current", &Default::default(), true, Utc::now())
        .unwrap();
    assert_eq!(page.page.total, 2);
    assert_eq!(page.diff_counts.new, 2);
}

#[test]
fn source_page_payloads_and_review_histories_are_bounded_to_the_requested_page() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    prepare_run(&repository, "source-bounded");
    let coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);
    let detail = run_detail(
        "source-bounded",
        RunStatus::Completed,
        (0..80)
            .map(|n| finding(&format!("finding-{n:03}"), &format!("fp-{n:03}")))
            .collect(),
    );
    repository.complete_run(&detail, &coverage).unwrap();
    repository
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE findings SET payload_json='invalid json' WHERE id='finding-079'",
            [],
        )
        .unwrap();
    let page = repository
        .source_run_page(
            "source-bounded",
            &SourceFindingsQuery {
                page: ResultPageQuery {
                    limit: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
            true,
            Utc::now(),
        )
        .unwrap();
    assert_eq!(page.page.items.len(), 1);
    assert_eq!(page.page.total, 80);
    assert_eq!(page.page.items[0].id, "finding-000");
    assert!(repository
        .source_run_page(
            "source-bounded",
            &SourceFindingsQuery {
                page: ResultPageQuery {
                    offset: 79,
                    limit: 1,
                    ..Default::default()
                },
                ..Default::default()
            },
            true,
            Utc::now()
        )
        .is_err());
    assert!(repository.source_run_metadata("source-bounded").is_ok());
    assert_eq!(
        repository
            .latest_policy_observations("project-1")
            .unwrap()
            .len(),
        80
    );
}

#[test]
fn missing_or_malformed_sections_are_unavailable_while_empty_arrays_are_authoritative() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let run = canonical_fixture(
        &repository,
        oxaudit_domain::RunKind::Dependencies,
        json!({
            "summary":{},"dependencies":[],"vulnerabilities":{"unsupported":"shape"}
        }),
    );
    let metadata = repository.canonical_projection_metadata(&run).unwrap();
    assert_eq!(metadata.sections.get("dependencies"), Some(&0));
    assert!(!metadata.sections.contains_key("vulnerabilities"));
    assert!(!metadata.sections.contains_key("semanticFindings"));
    assert!(repository
        .canonical_projection_page(&run, "vulnerabilities", &Default::default())
        .is_err());
    assert!(repository
        .canonical_projection_page(&run, "semanticFindings", &Default::default())
        .is_err());
    assert_eq!(
        repository
            .canonical_projection_page(&run, "dependencies", &Default::default())
            .unwrap()
            .total,
        0
    );
}

#[test]
fn projection_and_legacy_migration_failures_do_not_leave_partial_rows_or_versions() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let run = oxaudit_domain::Run::queued(oxaudit_domain::RunKind::Dependencies, "/saved", 1);
    repository.canonical_create_run(&run).unwrap();
    repository
        .connection
        .lock()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_paged_item BEFORE INSERT ON canonical_projection_items
         BEGIN SELECT RAISE(ABORT,'paged index rejected'); END;",
        )
        .unwrap();
    assert!(repository
        .canonical_save_projection(
            &run.id,
            "dependencies",
            1,
            &json!({
                "summary":{},"dependencies":[{"name":"a"}],"vulnerabilities":[]
            })
        )
        .is_err());
    let mut connection = repository.connection.lock().unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM canonical_projections", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
    connection
        .execute_batch(
            "DROP TRIGGER fail_paged_item; DROP TABLE canonical_history_blob_links;
         DROP TABLE canonical_projection_items; DROP TABLE canonical_projection_metadata;
         DROP TABLE source_finding_index; DELETE FROM schema_migrations WHERE version=8;",
        )
        .unwrap();
    connection.execute(
        "INSERT INTO canonical_projections(run_id,projection_kind,schema_version,payload_json) VALUES(?1,'dependencies',1,'invalid json')",
        [run.id.as_str()],
    ).unwrap();
    assert!(paging::migrate_paged_storage(&mut connection).is_err());
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='canonical_projection_metadata')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!exists);
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=8)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!exists);
}

#[test]
fn source_review_state_precedence_expiry_and_filters_match_complete_projection() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    prepare_run(&repository, "source-reviewed");
    let mut other = finding_at(
        "other",
        "other-fp",
        "vulnerability",
        "test/ÉCLAIR_%_.rs",
        FindingScope::Test,
    );
    other.severity = "critical".into();
    other.language = "javascript".into();
    other.rule_name = "Unicode rule".into();
    let mut closed = finding_at(
        "closed",
        "closed-fp",
        "secret",
        "src/closed.rs",
        FindingScope::Production,
    );
    closed.severity = "low".into();
    let expired = finding_at(
        "expired",
        "expired-fp",
        "secret",
        "src/expired.rs",
        FindingScope::Production,
    );
    let local = finding_at(
        "local",
        "local-fp",
        "secret",
        "test/local.rs",
        FindingScope::Test,
    );
    let detail = run_detail(
        "source-reviewed",
        RunStatus::Completed,
        vec![other, closed, expired, local],
    );
    let coverage = CoverageManifest::from_entries([
        ("test/ÉCLAIR_%_.rs", ["vulnerability"]),
        ("src/closed.rs", ["secret"]),
        ("src/expired.rs", ["secret"]),
        ("test/local.rs", ["secret"]),
    ]);
    repository.complete_run(&detail, &coverage).unwrap();
    for (id, fp, state, expiry) in [
        (
            "closed-decision",
            "closed-fp",
            ReviewState::AcceptedRisk,
            None,
        ),
        (
            "expired-decision",
            "expired-fp",
            ReviewState::Suppressed,
            Some("2026-08-20T09:00:00Z"),
        ),
        ("local-decision", "local-fp", ReviewState::Confirmed, None),
    ] {
        let mut item = review(id);
        item.fingerprint = fp.into();
        item.state = state;
        item.expires_at = expiry.map(str::to_owned);
        repository
            .inject_local_review_event_for_test(&item)
            .unwrap();
    }
    // Isolated stored policy fixtures: one shadowed by a local decision, one applied.
    {
        let connection = repository.connection.lock().unwrap();
        for (id, fp) in [("shadowed-policy", "local-fp"), ("policy-only", "other-fp")] {
            connection.execute(
                "INSERT INTO reviews(id,project_id,fingerprint_version,fingerprint,state,reason,gates_json,origin,updated_at)
                 VALUES(?1,'project-1',1,?2,'suppressed','policy fixture','[]','projectPolicy','2026-08-20T10:00:00Z')",
                params![id,fp],
            ).unwrap();
        }
    }
    let now = DateTime::parse_from_rfc3339("2026-08-20T12:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let page = repository
        .source_run_page("source-reviewed", &Default::default(), true, now)
        .unwrap();
    assert_eq!(page.view_counts.open, 2);
    assert_eq!(page.view_counts.closed, 2);
    assert_eq!(
        page.page
            .items
            .iter()
            .find(|f| f.id == "local")
            .unwrap()
            .review
            .as_ref()
            .unwrap()
            .state,
        ReviewState::Confirmed
    );
    assert!(page
        .page
        .items
        .iter()
        .find(|f| f.id == "expired")
        .unwrap()
        .review
        .is_none());
    let invalid_policy = repository
        .source_run_page("source-reviewed", &Default::default(), false, now)
        .unwrap();
    assert_eq!(invalid_policy.view_counts.other_scopes, 1);
    assert_eq!(invalid_policy.view_counts.closed, 1);
    assert!(invalid_policy
        .page
        .items
        .iter()
        .find(|f| f.id == "other")
        .unwrap()
        .review
        .is_none());
    let filtered = repository
        .source_run_page(
            "source-reviewed",
            &SourceFindingsQuery {
                view: "closed".into(),
                category: "vulnerability".into(),
                scope: "test".into(),
                language: "javascript".into(),
                new_only: true,
                page: ResultPageQuery {
                    severity: Some("critical".into()),
                    search: "ÉCLAIR_%_".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            true,
            now,
        )
        .unwrap();
    assert_eq!(filtered.page.filtered_total, 1);
    assert_eq!(filtered.page.items[0].id, "other");
    assert_eq!(filtered.page.total, 4);
    assert_eq!(
        filtered.languages,
        vec!["javascript".to_string(), "rust".to_string()]
    );
    let literal = repository
        .source_run_page(
            "source-reviewed",
            &SourceFindingsQuery {
                page: ResultPageQuery {
                    search: "%_".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
            true,
            now,
        )
        .unwrap();
    assert_eq!(literal.page.filtered_total, 1);
}

#[test]
fn source_pack_hash_changes_remain_not_evaluated_in_paged_comparisons() {
    let repository = FindingsRepository::open_in_memory().unwrap();
    let mut coverage = CoverageManifest::from_entries([("src/config.rs", ["secret"])]);
    coverage
        .rule_pack_hashes
        .insert("pack".into(), BTreeSet::from(["old".into()]));
    let mut old = finding("pack-finding", "pack-fp");
    old.rule_id = "pack/detector".into();
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "pack-baseline",
        "2026-08-20T09:00:00Z",
        vec![old],
        &coverage,
    );
    coverage
        .rule_pack_hashes
        .insert("pack".into(), BTreeSet::from(["new".into()]));
    complete_project_run(
        &repository,
        "project-1",
        "/project",
        "pack-current",
        "2026-08-20T10:00:00Z",
        vec![],
        &coverage,
    );
    let page = repository
        .source_run_page("pack-current", &Default::default(), true, Utc::now())
        .unwrap();
    assert_eq!(page.page.total, 1);
    assert_eq!(page.diff_counts.not_evaluated, 1);
    assert_eq!(page.diff_counts.resolved, 0);
    assert_eq!(
        page.page.items[0].diff_status,
        Some(DiffStatus::NotEvaluated)
    );
    assert_eq!(
        serde_json::to_value(&page.page.items).unwrap(),
        serde_json::to_value(&repository.load_run("pack-current").unwrap().findings).unwrap()
    );
}
