//! Bounded saved-result reads. Original report payloads remain immutable.
use super::*;
use crate::findings::domain::{
    CanonicalProjectionMetadata, FindingDiffCounts, FindingViewCounts, ResultPage, ResultPageQuery,
    SourceFindingsPage, SourceFindingsQuery, SourceRunMetadata,
};
use serde_json::{json, Value};

const MIGRATION_V8: &str = r#"
CREATE TABLE canonical_projection_metadata (
  run_id TEXT PRIMARY KEY REFERENCES canonical_projections(run_id) ON DELETE CASCADE,
  projection_kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  sections_json TEXT NOT NULL
);
CREATE TABLE canonical_projection_items (
  run_id TEXT NOT NULL REFERENCES canonical_projection_metadata(run_id) ON DELETE CASCADE,
  section TEXT NOT NULL,
  ordinal INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  item_key TEXT NOT NULL,
  severity TEXT NOT NULL,
  severity_rank INTEGER NOT NULL,
  search_text TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line_number INTEGER NOT NULL,
  column_number INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  PRIMARY KEY(run_id, section, ordinal)
);
CREATE INDEX projection_items_severity_idx ON canonical_projection_items(run_id, section, severity_rank, ordinal);
CREATE INDEX projection_items_key_idx ON canonical_projection_items(run_id, section, item_key);
CREATE TABLE canonical_history_blob_links (
  run_id TEXT NOT NULL REFERENCES canonical_projection_metadata(run_id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL,
  blob_oid TEXT NOT NULL,
  PRIMARY KEY(run_id, finding_id)
);
CREATE TABLE source_finding_index (
  id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
  run_id TEXT NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
  severity TEXT NOT NULL,
  severity_rank INTEGER NOT NULL,
  file_path TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  title TEXT NOT NULL,
  language TEXT NOT NULL,
  line_number INTEGER NOT NULL,
  column_number INTEGER NOT NULL,
  search_text TEXT NOT NULL
);
CREATE INDEX source_page_severity_idx ON source_finding_index(run_id, severity_rank, file_path, line_number, column_number, id);
CREATE INDEX source_page_file_idx ON source_finding_index(run_id, file_path, line_number, column_number, id);
"#;

pub(super) fn migrate_paged_storage(connection: &mut Connection) -> Result<(), CommandError> {
    let applied: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=8)",
            [],
            |row| row.get(0),
        )
        .map_err(persistence_error)?;
    if applied {
        return Ok(());
    }
    let transaction = connection.transaction().map_err(persistence_error)?;
    transaction
        .execute_batch(MIGRATION_V8)
        .map_err(persistence_error)?;
    // Keyset batches keep migration memory bounded even for large legacy histories.
    let mut after = String::new();
    loop {
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT run_id, projection_kind, payload_json FROM canonical_projections WHERE run_id>?1 ORDER BY run_id LIMIT 1"
            ).map_err(persistence_error)?;
            let rows = statement
                .query_map([&after], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(persistence_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?
        };
        let Some((run_id, kind, payload)) = rows.into_iter().next() else {
            break;
        };
        save_projection_index(&transaction, &run_id, &kind, &payload)?;
        after = run_id;
    }
    let mut after_rowid = 0_i64;
    loop {
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT rowid, id, run_id, payload_json, rule_id FROM findings WHERE rowid>?1 ORDER BY rowid LIMIT 200"
            ).map_err(persistence_error)?;
            let rows = statement
                .query_map([after_rowid], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(persistence_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?
        };
        if rows.is_empty() {
            break;
        }
        for (rowid, id, run_id, payload, rule_id) in rows {
            let mut value: Value = from_json(&payload)?;
            value
                .as_object_mut()
                .ok_or_else(CommandError::persistence_unavailable)?
                .insert("ruleId".into(), Value::String(rule_id));
            save_source_value_index(&transaction, &id, &run_id, &value)?;
            after_rowid = rowid;
        }
    }
    transaction
        .execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES (8,?1)",
            [Utc::now().to_rfc3339()],
        )
        .map_err(persistence_error)?;
    transaction.commit().map_err(persistence_error)
}

fn text_field<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or("")
}

fn severity_rank(severity: &str) -> i64 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

pub(super) fn save_source_index(
    connection: &Connection,
    finding: &Finding,
    run_id: &str,
) -> Result<(), CommandError> {
    let mut value =
        serde_json::to_value(StoredFindingPayload::from(finding)).map_err(persistence_error)?;
    value
        .as_object_mut()
        .expect("stored finding is an object")
        .insert("ruleId".into(), Value::String(finding.rule_id.clone()));
    save_source_value_index(connection, &finding.id, run_id, &value)
}

fn save_source_value_index(
    connection: &Connection,
    id: &str,
    run_id: &str,
    value: &Value,
) -> Result<(), CommandError> {
    let search = ["ruleName", "ruleId", "filePath", "title", "matchText"]
        .map(|key| text_field(value, key))
        .join(" ")
        .to_lowercase();
    connection.execute(
        r#"INSERT INTO source_finding_index(id,run_id,severity,severity_rank,file_path,rule_name,title,language,line_number,column_number,search_text)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
        ON CONFLICT(id) DO UPDATE SET severity=excluded.severity,severity_rank=excluded.severity_rank,
          file_path=excluded.file_path,rule_name=excluded.rule_name,title=excluded.title,
          language=excluded.language,line_number=excluded.line_number,column_number=excluded.column_number,search_text=excluded.search_text"#,
        params![id,run_id,text_field(value,"severity"),severity_rank(text_field(value,"severity")),
            text_field(value,"filePath"),text_field(value,"ruleName"),text_field(value,"title"),
            text_field(value,"language"), value["line"].as_i64().unwrap_or(0),
            value["column"].as_i64().unwrap_or(0), search],
    ).map_err(persistence_error)?;
    Ok(())
}

fn sections(kind: &str) -> &'static [(&'static str, &'static str)] {
    match kind {
        "dependencies" => &[
            ("dependencies", "$.dependencies"),
            ("vulnerabilities", "$.vulnerabilities"),
        ],
        "binary" => &[
            ("components", "$.components"),
            ("semanticFindings", "$.semanticAnalysis.findings"),
        ],
        "image" => &[
            ("components", "$.result.components"),
            ("semanticFindings", "$.result.semanticAnalysis.findings"),
            ("layers", "$.layers"),
        ],
        "history" => &[("findings", "$.findings"), ("blobs", "$.blobs")],
        _ => &[],
    }
}

pub(super) fn save_projection_index(
    connection: &Connection,
    run_id: &str,
    kind: &str,
    payload: &str,
) -> Result<(), CommandError> {
    let mut counts = BTreeMap::new();
    let mut header = payload.to_owned();
    for (section, path) in sections(kind) {
        let count: usize = connection.query_row(
            "SELECT CASE WHEN json_type(?1,?2)='array' THEN json_array_length(?1,?2) ELSE 0 END",
            params![payload,path], |row| row.get::<_, i64>(0).map(|n| n as usize),
        ).map_err(persistence_error)?;
        let exists: bool = connection
            .query_row(
                "SELECT json_type(?1,?2)='array'",
                params![payload, path],
                |row| Ok(row.get::<_, Option<bool>>(0)?.unwrap_or(false)),
            )
            .map_err(persistence_error)?;
        if exists {
            counts.insert((*section).to_owned(), count);
            header = connection
                .query_row(
                    "SELECT json_set(?1,?2,json('[]'))",
                    params![header, path],
                    |row| row.get(0),
                )
                .map_err(persistence_error)?;
        }
    }
    if kind == "history" {
        header = connection.query_row(
            "SELECT CASE WHEN json_type(?1,'$.findingBlobIds')='object' THEN json_set(?1,'$.findingBlobIds',json('{}')) ELSE ?1 END",
            [&header], |row| row.get(0),
        ).map_err(persistence_error)?;
    }
    connection.execute(
        "INSERT INTO canonical_projection_metadata(run_id,projection_kind,payload_json,sections_json) VALUES(?1,?2,?3,?4)",
        params![run_id,kind,header,to_json(&counts)?],
    ).map_err(persistence_error)?;
    // SQLite emits one original item at a time; Rust never parses the full report.
    for (section, path) in sections(kind) {
        let mut statement = connection.prepare(
            "SELECT CAST(key AS INTEGER),CASE WHEN type IN ('object','array') THEN value ELSE ?1 -> (?2 || '[' || key || ']') END
             FROM json_each(?1,?2) WHERE json_type(?1,?2)='array' ORDER BY CAST(key AS INTEGER)"
        ).map_err(persistence_error)?;
        let mut rows = statement
            .query(params![payload, path])
            .map_err(persistence_error)?;
        while let Some(row) = rows.next().map_err(persistence_error)? {
            let ordinal: i64 = row.get(0).map_err(persistence_error)?;
            let item: String = row.get(1).map_err(persistence_error)?;
            let value: Value = from_json(&item)?;
            let severity = if *section == "components" {
                value["vulnerabilities"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|v| text_field(v, "severity"))
                    .filter(|s| matches!(*s, "critical" | "high" | "medium" | "low"))
                    .min_by_key(|s| severity_rank(s))
                    .unwrap_or("unknown")
            } else {
                value["severity"].as_str().unwrap_or("unknown")
            };
            let search = match *section {
                "findings" => ["ruleName", "ruleId", "filePath", "title"]
                    .map(|key| text_field(&value, key))
                    .join(" "),
                "vulnerabilities" => format!(
                    "{} {} {} {}",
                    text_field(&value, "id"),
                    text_field(&value, "packageName"),
                    text_field(&value, "summary"),
                    value["aliases"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                _ => item.clone(),
            }
            .to_lowercase();
            connection.execute(
                "INSERT INTO canonical_projection_items(run_id,section,ordinal,payload_json,item_key,severity,severity_rank,search_text,file_path,line_number,column_number,rule_id)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                params![run_id,section,ordinal,item,
                    value["id"].as_str().or_else(|| value["oid"].as_str()).unwrap_or(""),
                    severity,severity_rank(severity),search,text_field(&value,"filePath"),
                    value["line"].as_i64().unwrap_or(0),value["column"].as_i64().unwrap_or(0),text_field(&value,"ruleId")],
            ).map_err(persistence_error)?;
        }
    }
    if kind == "history" {
        connection
            .execute(
                "INSERT INTO canonical_history_blob_links(run_id,finding_id,blob_oid)
             SELECT ?1,key,value FROM json_each(?2,'$.findingBlobIds') WHERE type='text'",
                params![run_id, payload],
            )
            .map_err(persistence_error)?;
    }
    Ok(())
}

fn validate_page(
    query: &ResultPageQuery,
) -> Result<(u32, Option<&str>, Option<i64>), CommandError> {
    if query.limit == 0
        || query.limit > 200
        || query.search.len() > 4096
        || !matches!(
            query.sort.as_str(),
            "original" | "severity" | "file" | "rule"
        )
    {
        return Err(CommandError::review_invalid());
    }
    let severity = query.severity.as_deref().filter(|s| *s != "all");
    let minimum = query.minimum_severity.as_deref().filter(|s| *s != "all");
    if severity.into_iter().chain(minimum).any(|s| {
        !matches!(
            s,
            "critical" | "high" | "medium" | "low" | "info" | "unknown"
        )
    }) {
        return Err(CommandError::review_invalid());
    }
    Ok((query.limit, severity, minimum.map(severity_rank)))
}

impl FindingsRepository {
    pub(crate) fn canonical_projection_metadata(
        &self,
        run_id: &oxaudit_domain::RunId,
    ) -> Result<CanonicalProjectionMetadata, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let (kind, payload, counts, state): (String,String,String,String) = connection.query_row(
            "SELECT m.projection_kind,m.payload_json,m.sections_json,r.state FROM canonical_projection_metadata m
             JOIN canonical_runs r ON r.id=m.run_id WHERE m.run_id=?1",
            [run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).optional().map_err(persistence_error)?.ok_or_else(CommandError::not_found)?;
        let mut projection: Value = from_json(&payload)?;
        if matches!(kind.as_str(), "image" | "history") {
            if let Some(object) = projection.as_object_mut() {
                object.insert("state".into(), Value::String(state));
            }
        }
        Ok(CanonicalProjectionMetadata {
            kind: "pagedProjection",
            projection_kind: kind,
            projection,
            sections: from_json(&counts)?,
        })
    }

    pub(crate) fn canonical_projection_page(
        &self,
        run_id: &oxaudit_domain::RunId,
        section: &str,
        query: &ResultPageQuery,
    ) -> Result<ResultPage<Value>, CommandError> {
        let (limit, severity, minimum) = validate_page(query)?;
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        let (kind, section_counts): (String,String) = transaction.query_row(
            "SELECT projection_kind,sections_json FROM canonical_projection_metadata WHERE run_id=?1",
            [run_id.as_str()], |row| Ok((row.get(0)?,row.get(1)?)),
        ).optional().map_err(persistence_error)?.ok_or_else(CommandError::not_found)?;
        if !sections(&kind).iter().any(|(name, _)| *name == section) {
            return Err(CommandError::not_found());
        }
        let section_counts: BTreeMap<String, usize> = from_json(&section_counts)?;
        if !section_counts.contains_key(section) {
            return Err(CommandError::not_found());
        }
        let predicate = "run_id=?1 AND section=?2 AND (?3 IS NULL OR severity=?3)
            AND (?4 IS NULL OR severity_rank<=?4) AND instr(search_text,?5)>0";
        let search = query.search.trim().to_lowercase();
        let total: usize = transaction
            .query_row(
                "SELECT COUNT(*) FROM canonical_projection_items WHERE run_id=?1 AND section=?2",
                params![run_id.as_str(), section],
                |row| row.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(persistence_error)?;
        let filtered_total: usize = transaction
            .query_row(
                &format!("SELECT COUNT(*) FROM canonical_projection_items WHERE {predicate}"),
                params![run_id.as_str(), section, severity, minimum, search],
                |row| row.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(persistence_error)?;
        let order = match query.sort.as_str() {
            "severity" => "severity_rank,file_path,line_number,column_number,ordinal",
            "file" => "file_path,line_number,column_number,ordinal",
            "rule" => "rule_id,severity_rank,file_path,line_number,ordinal",
            _ => "ordinal",
        };
        let items = {
            let mut statement = transaction.prepare(&format!(
                "SELECT payload_json FROM canonical_projection_items WHERE {predicate} ORDER BY {order} LIMIT ?6 OFFSET ?7"
            )).map_err(persistence_error)?;
            let rows = statement
                .query_map(
                    params![
                        run_id.as_str(),
                        section,
                        severity,
                        minimum,
                        search,
                        limit,
                        query.offset
                    ],
                    |row| row.get::<_, String>(0),
                )
                .map_err(persistence_error)?;
            rows.map(|row| from_json(&row.map_err(persistence_error)?))
                .collect::<Result<Vec<Value>, CommandError>>()?
        };
        let related = if kind == "history" && section == "findings" {
            let mut links = serde_json::Map::new();
            let mut blobs = BTreeMap::<String, Value>::new();
            let mut statement = transaction.prepare(
                "SELECT l.blob_oid,b.payload_json FROM canonical_history_blob_links l
                 LEFT JOIN canonical_projection_items b ON b.run_id=l.run_id AND b.section='blobs' AND b.item_key=l.blob_oid
                 WHERE l.run_id=?1 AND l.finding_id=?2"
            ).map_err(persistence_error)?;
            for item in &items {
                let Some(id) = item["id"].as_str() else {
                    continue;
                };
                let link: Option<(String, Option<String>)> = statement
                    .query_row(params![run_id.as_str(), id], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })
                    .optional()
                    .map_err(persistence_error)?;
                if let Some((oid, payload)) = link {
                    links.insert(id.into(), Value::String(oid.clone()));
                    if let Some(payload) = payload {
                        blobs.insert(oid, from_json(&payload)?);
                    }
                }
            }
            Some(json!({"blobs":blobs.into_values().collect::<Vec<_>>(),"findingBlobIds":links}))
        } else {
            None
        };
        transaction.commit().map_err(persistence_error)?;
        Ok(ResultPage {
            items,
            offset: query.offset,
            limit,
            filtered_total,
            total,
            related,
        })
    }

    pub(crate) fn source_run_metadata(
        &self,
        run_id: &str,
    ) -> Result<SourceRunMetadata, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        source_metadata(&connection, run_id)
    }

    pub(crate) fn source_run_page(
        &self,
        run_id: &str,
        query: &SourceFindingsQuery,
        include_policy_reviews: bool,
        now: DateTime<Utc>,
    ) -> Result<SourceFindingsPage, CommandError> {
        let (limit, severity, minimum) = validate_page(&query.page)?;
        if !matches!(
            query.view.as_str(),
            "all" | "open" | "otherScopes" | "closed" | "resolved"
        ) || !matches!(query.category.as_str(), "all" | "secret" | "vulnerability")
            || !matches!(
                query.scope.as_str(),
                "all"
                    | "production"
                    | "infrastructure"
                    | "test"
                    | "fixture"
                    | "generated"
                    | "vendored"
                    | "documentation"
                    | "unknown"
            )
            || query.language.len() > 128
            || query.file_paths.as_ref().is_some_and(|paths| {
                paths.len() > 100_000
                    || paths.iter().any(|path| path.len() > 4096)
                    || paths.iter().map(String::len).sum::<usize>() > 8 * 1024 * 1024
            })
        {
            return Err(CommandError::review_invalid());
        }
        let mut connection = self.connection.lock().map_err(persistence_error)?;
        let transaction = connection.transaction().map_err(persistence_error)?;
        let metadata = source_metadata(&transaction, run_id)?;
        let baseline_id = query
            .baseline_run_id
            .as_deref()
            .or(metadata.baseline_run_id.as_deref());
        let comparison = if metadata.status == RunStatus::Completed {
            baseline_id
                .map(|baseline| comparison_coverage(&transaction, run_id, baseline))
                .transpose()?
        } else {
            if query.baseline_run_id.is_some() {
                return Err(CommandError::baseline_incompatible());
            }
            None
        };
        transaction
            .execute_batch(
                "CREATE TEMP TABLE IF NOT EXISTS source_page_projection (
              id TEXT PRIMARY KEY, observation_run_id TEXT NOT NULL, diff_status TEXT,
              resolved_by_run_id TEXT, view TEXT NOT NULL DEFAULT 'open');
             CREATE TEMP TABLE IF NOT EXISTS source_page_reviews (
              fingerprint_version INTEGER NOT NULL, fingerprint TEXT NOT NULL, state TEXT NOT NULL,
              PRIMARY KEY(fingerprint_version,fingerprint));
             CREATE TEMP TABLE IF NOT EXISTS source_page_paths(path TEXT PRIMARY KEY);
             DELETE FROM source_page_projection;
             DELETE FROM source_page_reviews;
             DELETE FROM source_page_paths;",
            )
            .map_err(persistence_error)?;
        transaction.execute(
            "INSERT INTO source_page_projection(id,observation_run_id,diff_status)
             SELECT f.id,f.run_id,CASE WHEN ?3=0 THEN NULL
               WHEN ?2 IS NOT NULL AND EXISTS(SELECT 1 FROM findings b WHERE b.run_id=?2
                 AND b.fingerprint_version=f.fingerprint_version AND b.fingerprint=f.fingerprint) THEN 'unchanged'
               ELSE 'new' END FROM findings f WHERE f.run_id=?1",
            params![run_id,baseline_id,metadata.status==RunStatus::Completed],
        ).map_err(persistence_error)?;
        if let Some((current_coverage, baseline_coverage)) = comparison {
            let baseline = baseline_id.expect("comparison has baseline");
            let mut statement = transaction
                .prepare(
                    "SELECT f.id,f.category,f.rule_id,i.file_path FROM findings f
                 JOIN source_finding_index i ON i.id=f.id WHERE f.run_id=?1
                 AND NOT EXISTS(SELECT 1 FROM findings c WHERE c.run_id=?2
                    AND c.fingerprint_version=f.fingerprint_version AND c.fingerprint=f.fingerprint)
                 ORDER BY f.rowid",
                )
                .map_err(persistence_error)?;
            let mut rows = statement
                .query(params![baseline, run_id])
                .map_err(persistence_error)?;
            while let Some(row) = rows.next().map_err(persistence_error)? {
                let id: String = row.get(0).map_err(persistence_error)?;
                let category: String = row.get(1).map_err(persistence_error)?;
                let rule_id: String = row.get(2).map_err(persistence_error)?;
                let path: String = row.get(3).map_err(persistence_error)?;
                let resolved = current_coverage.is_finding_covered(
                    &path,
                    &category,
                    &rule_id,
                    &baseline_coverage,
                );
                transaction.execute(
                    "INSERT INTO source_page_projection(id,observation_run_id,diff_status,resolved_by_run_id)
                     VALUES(?1,?2,?3,?4)",
                    params![id,baseline,if resolved {"resolved"} else {"notEvaluated"},resolved.then_some(run_id)],
                ).map_err(persistence_error)?;
            }
        }
        // Active review state needs only identity/origin/state/expiry, never evidence or history.
        // Read local first; a Candidate or expired local decision falls through to project policy.
        {
            let mut statement = transaction
                .prepare(
                    "SELECT fingerprint_version,fingerprint,state,expires_at,origin FROM reviews
                 WHERE project_id=?1 AND superseded_at IS NULL
                 ORDER BY CASE origin WHEN 'local' THEN 0 ELSE 1 END, rowid DESC",
                )
                .map_err(persistence_error)?;
            let mut rows = statement
                .query([&metadata.project_id])
                .map_err(persistence_error)?;
            while let Some(row) = rows.next().map_err(persistence_error)? {
                let version: u16 = row.get(0).map_err(persistence_error)?;
                let fingerprint: String = row.get(1).map_err(persistence_error)?;
                let state: String = row.get(2).map_err(persistence_error)?;
                let expiry: Option<String> = row.get(3).map_err(persistence_error)?;
                let origin: String = row.get(4).map_err(persistence_error)?;
                let valid_expiry = expiry.as_deref().map_or(true, |expiry| {
                    DateTime::parse_from_rfc3339(expiry)
                        .is_ok_and(|expiry| expiry.with_timezone(&Utc) > now)
                });
                if state == "candidate"
                    || !valid_expiry
                    || (!include_policy_reviews && origin == "projectPolicy")
                {
                    continue;
                }
                // Validate the state/origin just as the complete loader does.
                parse_json_enum::<ReviewState>(&state)?;
                parse_json_enum::<ReviewOrigin>(&origin)?;
                transaction.execute(
                    "INSERT OR IGNORE INTO source_page_reviews(fingerprint_version,fingerprint,state) VALUES(?1,?2,?3)",
                    params![version,fingerprint,state],
                ).map_err(persistence_error)?;
            }
        }
        transaction.execute_batch(
            "UPDATE source_page_projection SET view=CASE
               WHEN diff_status='resolved' THEN 'resolved'
               WHEN (SELECT state FROM source_page_reviews r JOIN findings f
                     ON r.fingerprint_version=f.fingerprint_version AND r.fingerprint=f.fingerprint
                     WHERE f.id=source_page_projection.id)='confirmed' THEN 'open'
               WHEN (SELECT state FROM source_page_reviews r JOIN findings f
                     ON r.fingerprint_version=f.fingerprint_version AND r.fingerprint=f.fingerprint
                     WHERE f.id=source_page_projection.id) IN ('falsePositive','acceptedRisk','suppressed') THEN 'closed'
               WHEN (SELECT scope FROM findings WHERE id=source_page_projection.id)
                    IN ('production','infrastructure','unknown') THEN 'open'
               ELSE 'otherScopes' END;"
        ).map_err(persistence_error)?;
        if let Some(paths) = &query.file_paths {
            let mut statement = transaction
                .prepare("INSERT OR IGNORE INTO source_page_paths(path) VALUES(?1)")
                .map_err(persistence_error)?;
            for path in paths {
                statement.execute([path]).map_err(persistence_error)?;
            }
        }
        let mut view_counts = FindingViewCounts::default();
        let mut diff_counts = FindingDiffCounts::default();
        let mut total = 0;
        {
            let mut statement=transaction.prepare(
                "SELECT view,diff_status,COUNT(*) FROM source_page_projection GROUP BY view,diff_status"
            ).map_err(persistence_error)?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })
                .map_err(persistence_error)?;
            for row in rows {
                let (view, diff, count) = row.map_err(persistence_error)?;
                let count = count as usize;
                total += count;
                match view.as_str() {
                    "open" => view_counts.open += count,
                    "closed" => view_counts.closed += count,
                    "resolved" => view_counts.resolved += count,
                    _ => view_counts.other_scopes += count,
                }
                match diff.as_deref() {
                    Some("new") => diff_counts.new += count,
                    Some("unchanged") => diff_counts.unchanged += count,
                    Some("resolved") => diff_counts.resolved += count,
                    Some("notEvaluated") => diff_counts.not_evaluated += count,
                    _ => {}
                }
            }
        }
        let languages = {
            let mut statement=transaction.prepare(
                "SELECT DISTINCT i.language FROM source_page_projection p JOIN source_finding_index i ON i.id=p.id ORDER BY i.language"
            ).map_err(persistence_error)?;
            let rows = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(persistence_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?
        };
        let predicate="(?1='all' OR p.view=?1) AND (?2=0 OR p.diff_status='new')
            AND (?3='all' OR f.category=?3) AND (?4 IS NULL OR i.severity=?4)
            AND (?5 IS NULL OR i.severity_rank<=?5) AND (?6='all' OR f.scope=?6)
            AND (?7='all' OR i.language=?7)
            AND instr(i.search_text,?8)>0
            AND (?9=0 OR (p.observation_run_id=?10 AND EXISTS(SELECT 1 FROM source_page_paths paths WHERE paths.path=i.file_path)))";
        let from="source_page_projection p JOIN findings f ON f.id=p.id JOIN source_finding_index i ON i.id=p.id";
        let search = query.page.search.trim().to_lowercase();
        let filtered_total: usize = transaction
            .query_row(
                &format!("SELECT COUNT(*) FROM {from} WHERE {predicate}"),
                params![
                    query.view,
                    query.new_only,
                    query.category,
                    severity,
                    minimum,
                    query.scope,
                    query.language,
                    search,
                    query.file_paths.is_some(),
                    run_id
                ],
                |row| row.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(persistence_error)?;
        let order = match query.page.sort.as_str() {
            "file" => "i.file_path,i.line_number,i.column_number,f.id",
            "rule" => "f.rule_id,i.severity_rank,i.file_path,i.line_number,f.id",
            "original" => "CASE WHEN p.observation_run_id=?10 THEN 0 ELSE 1 END,f.rowid",
            _ => "i.severity_rank,i.file_path,i.line_number,i.column_number,f.id",
        };
        let selected = {
            let mut statement=transaction.prepare(&format!(
                "SELECT f.id,p.observation_run_id,f.fingerprint_version,f.fingerprint,f.category,f.rule_id,
                   f.payload_json,f.scope,f.scope_reason,p.diff_status,p.resolved_by_run_id
                 FROM {from} WHERE {predicate} ORDER BY {order} LIMIT ?11 OFFSET ?12"
            )).map_err(persistence_error)?;
            let rows = statement
                .query_map(
                    params![
                        query.view,
                        query.new_only,
                        query.category,
                        severity,
                        minimum,
                        query.scope,
                        query.language,
                        search,
                        query.file_paths.is_some(),
                        run_id,
                        limit,
                        query.page.offset
                    ],
                    |row| {
                        Ok((
                            RawProjectObservation {
                                id: row.get(0)?,
                                run_id: row.get(1)?,
                                fingerprint_version: row.get(2)?,
                                fingerprint: row.get(3)?,
                                category: row.get(4)?,
                                rule_id: row.get(5)?,
                                payload: row.get(6)?,
                                scope: row.get(7)?,
                                scope_reason: row.get(8)?,
                                completed_at: now,
                            },
                            row.get::<_, Option<String>>(9)?,
                            row.get::<_, Option<String>>(10)?,
                        ))
                    },
                )
                .map_err(persistence_error)?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(persistence_error)?
        };
        let mut items = Vec::with_capacity(selected.len());
        for (raw, diff, resolved_by) in selected {
            let mut finding = finding_from_raw_project_observation(raw)?;
            finding.review_history = load_reviews(
                &transaction,
                &metadata.project_id,
                finding.fingerprint_version,
                &finding.fingerprint,
            )?;
            finding.review = if include_policy_reviews {
                select_active_review(&finding.review_history, now)
            } else {
                select_active_local_review(&finding.review_history, now)
            };
            finding.diff_status = diff
                .as_deref()
                .map(parse_json_enum::<DiffStatus>)
                .transpose()?;
            finding.resolved_by_run_id = resolved_by;
            items.push(finding);
        }
        transaction.commit().map_err(persistence_error)?;
        Ok(SourceFindingsPage {
            page: ResultPage {
                items,
                offset: query.page.offset,
                limit,
                filtered_total,
                total,
                related: None,
            },
            view_counts,
            diff_counts,
            languages,
        })
    }

    /// Policy matching needs identity and location, never snippets or complete finding payloads.
    pub(in crate::findings) fn latest_policy_observations(
        &self,
        project_id: &str,
    ) -> Result<Vec<PolicyObservation>, CommandError> {
        let connection = self.connection.lock().map_err(persistence_error)?;
        let mut statement=connection.prepare(
            "SELECT f.fingerprint_version,f.fingerprint,f.category,f.rule_id,i.file_path,r.id,r.completed_at
             FROM findings f JOIN scan_runs r ON r.id=f.run_id JOIN source_finding_index i ON i.id=f.id
             WHERE r.project_id=?1 AND r.status='completed'"
        ).map_err(persistence_error)?;
        let mut rows = statement.query([project_id]).map_err(persistence_error)?;
        let mut winners =
            BTreeMap::<(u16, String), (DateTime<Utc>, String, PolicyObservation)>::new();
        while let Some(row) = rows.next().map_err(persistence_error)? {
            let observation = PolicyObservation {
                fingerprint_version: row.get(0).map_err(persistence_error)?,
                fingerprint: row.get(1).map_err(persistence_error)?,
                category: row.get(2).map_err(persistence_error)?,
                rule_id: row.get(3).map_err(persistence_error)?,
                file_path: row.get(4).map_err(persistence_error)?,
            };
            let run_id: String = row.get(5).map_err(persistence_error)?;
            let completed: Option<String> = row.get(6).map_err(persistence_error)?;
            let completed = completed
                .as_deref()
                .ok_or_else(CommandError::persistence_unavailable)
                .and_then(parse_utc_timestamp)?;
            let key = (
                observation.fingerprint_version,
                observation.fingerprint.clone(),
            );
            if winners.get(&key).map_or(true, |old| {
                completed > old.0 || (completed == old.0 && run_id > old.1)
            }) {
                winners.insert(key, (completed, run_id, observation));
            }
        }
        Ok(winners
            .into_values()
            .map(|(_, _, observation)| observation)
            .collect())
    }
}

pub(in crate::findings) struct PolicyObservation {
    pub fingerprint_version: u16,
    pub fingerprint: String,
    pub category: String,
    pub rule_id: String,
    pub file_path: String,
}

fn source_metadata(
    connection: &Connection,
    run_id: &str,
) -> Result<SourceRunMetadata, CommandError> {
    let stored=connection.query_row(
        "SELECT project_id,id,baseline_run_id,status,policy_status_json,started_at,completed_at,summary_json FROM scan_runs WHERE id=?1",
        [run_id],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<String>>(2)?,
            row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?,
            row.get::<_,Option<String>>(6)?,row.get::<_,Option<String>>(7)?)),
    ).optional().map_err(persistence_error)?.ok_or_else(CommandError::not_found)?;
    Ok(SourceRunMetadata {
        project_id: stored.0,
        run_id: stored.1,
        baseline_run_id: stored.2,
        status: parse_run_status(&stored.3)?,
        policy: from_json(&stored.4)?,
        started_at: stored.5,
        completed_at: stored.6,
        persistence: RunPersistence::Saved,
        summary: stored
            .7
            .as_deref()
            .map(from_json::<StoredScanSummary>)
            .transpose()?
            .map(Into::into)
            .unwrap_or_else(empty_summary),
        maintenance_warning: None,
    })
}

fn comparison_coverage(
    connection: &Connection,
    current_id: &str,
    baseline_id: &str,
) -> Result<(CoverageManifest, CoverageManifest), CommandError> {
    let current = load_comparison_run(connection, current_id)?;
    let baseline = load_comparison_run(connection, baseline_id)?;
    require_completed_comparison_run(&current)
        .map_err(|_| CommandError::baseline_incompatible())?;
    require_completed_comparison_run(&baseline)
        .map_err(|_| CommandError::baseline_incompatible())?;
    let prior = baseline
        .completed_at
        .as_deref()
        .ok_or_else(CommandError::baseline_incompatible)
        .and_then(parse_utc_timestamp)?
        < parse_utc_timestamp(&current.started_at)?;
    let current_coverage = current
        .coverage
        .ok_or_else(CommandError::baseline_incompatible)?;
    let baseline_coverage = baseline
        .coverage
        .ok_or_else(CommandError::baseline_incompatible)?;
    if current.project_id != baseline.project_id
        || current.fingerprint_version != baseline.fingerprint_version
        || !prior
        || !current_coverage.is_compatible_with(&baseline_coverage)
    {
        return Err(CommandError::baseline_incompatible());
    }
    Ok((current_coverage, baseline_coverage))
}
