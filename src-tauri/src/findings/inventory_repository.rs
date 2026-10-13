//! Paged canonical inventories and rebuildable search indexes.
use super::*;
use crate::findings::{
    domain::{ResultPage, ResultPageQuery},
    inventory::{InventoryComponentView, InventoryIdentityView, InventoryPage},
};

pub(super) fn save_component_index(
    connection: &Connection,
    run_id: &str,
    component: &oxaudit_domain::Component,
) -> Result<(), CommandError> {
    let mut fields = vec![component.name.as_str()];
    fields.extend(
        [
            component.version.as_deref(),
            component.supplier.as_deref(),
            component.ecosystem.as_deref(),
            component.purl.as_deref(),
        ]
        .into_iter()
        .flatten(),
    );
    fields.extend(
        component
            .aliases
            .iter()
            .chain(&component.cpes)
            .map(String::as_str),
    );
    connection.execute("INSERT INTO inventory_component_search(run_id,component_id,search_text) VALUES(?1,?2,?3)",
        params![run_id, component.id.as_str(), fields.join(" ").to_lowercase()]).map_err(persistence_error)?;
    Ok(())
}

pub(super) fn save_advisories(
    connection: &Connection,
    run_id: &str,
    evidence: &[oxaudit_domain::EvidenceRecord],
) -> Result<(), CommandError> {
    for record in evidence {
        if let oxaudit_domain::Evidence::AdvisoryMatch(item) = &record.evidence {
            connection.execute("INSERT OR IGNORE INTO inventory_advisories(run_id,component_id,advisory_id,search_text) VALUES(?1,?2,?3,?4)",
                params![run_id, item.component_id.as_str(), item.advisory_id, item.advisory_id.to_lowercase()]).map_err(persistence_error)?;
        }
    }
    Ok(())
}

pub(super) fn migrate_inventory(connection: &mut Connection) -> Result<(), CommandError> {
    let applied: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=9)",
            [],
            |row| row.get(0),
        )
        .map_err(persistence_error)?;
    if applied {
        return Ok(());
    }
    let transaction = connection.transaction().map_err(persistence_error)?;
    transaction
        .execute_batch(
            r#"
        CREATE TABLE inventory_component_search (
            run_id TEXT NOT NULL REFERENCES canonical_runs(id) ON DELETE CASCADE,
            component_id TEXT NOT NULL REFERENCES canonical_components(id) ON DELETE CASCADE,
            search_text TEXT NOT NULL,
            PRIMARY KEY(run_id,component_id)
        );
        CREATE TABLE inventory_advisories (
            run_id TEXT NOT NULL REFERENCES canonical_runs(id) ON DELETE CASCADE,
            component_id TEXT NOT NULL,
            advisory_id TEXT NOT NULL,
            search_text TEXT NOT NULL,
            PRIMARY KEY(run_id,component_id,advisory_id)
        );
    "#,
        )
        .map_err(persistence_error)?;
    // Keyset backfill retains only one component/evidence row at a time.
    for (table, column) in [
        ("canonical_components", "payload_json"),
        ("canonical_observations", "evidence_json"),
    ] {
        let mut after = String::new();
        loop {
            let row = transaction
                .query_row(
                    &format!(
                        "SELECT id,run_id,{column} FROM {table} WHERE id>?1 ORDER BY id LIMIT 1"
                    ),
                    [&after],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(persistence_error)?;
            let Some((id, run_id, payload)) = row else {
                break;
            };
            if table == "canonical_components" {
                save_component_index(&transaction, &run_id, &from_json(&payload)?)?;
            } else {
                save_advisories(
                    &transaction,
                    &run_id,
                    &from_json::<Vec<oxaudit_domain::EvidenceRecord>>(&payload)?,
                )?;
            }
            after = id;
        }
    }
    transaction
        .execute(
            "INSERT INTO schema_migrations(version,applied_at) VALUES(9,?1)",
            [Utc::now().to_rfc3339()],
        )
        .map_err(persistence_error)?;
    transaction.commit().map_err(persistence_error)
}

fn validate(query: &ResultPageQuery) -> Result<(), CommandError> {
    if query.limit == 0
        || query.limit > 200
        || query.search.len() > 4096
        || query.sort != "original"
        || query.severity.is_some()
        || query.minimum_severity.is_some()
    {
        return Err(CommandError::review_invalid());
    }
    Ok(())
}

impl FindingsRepository {
    pub(crate) fn inventory_runs_page(
        &self,
        query: &ResultPageQuery,
    ) -> Result<ResultPage<oxaudit_domain::Run>, CommandError> {
        validate(query)?;
        if !query.search.is_empty() {
            return Err(CommandError::review_invalid());
        }
        let connection = self.connection.lock().map_err(persistence_error)?;
        const FILTER: &str =
            "state='completed' AND kind IN ('dependencies','binary','image','firmware','import')";
        let total: usize = connection
            .query_row(
                &format!("SELECT COUNT(*) FROM canonical_runs WHERE {FILTER}"),
                [],
                |row| row.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(persistence_error)?;
        let mut statement = connection.prepare(&format!("SELECT payload_json FROM canonical_runs WHERE {FILTER} ORDER BY updated_at_ms DESC,id DESC LIMIT ?1 OFFSET ?2")).map_err(persistence_error)?;
        let items = statement
            .query_map(params![query.limit, query.offset], |row| {
                row.get::<_, String>(0)
            })
            .map_err(persistence_error)?
            .map(|row| from_json(&row.map_err(persistence_error)?))
            .collect::<Result<Vec<_>, CommandError>>()?;
        Ok(ResultPage {
            items,
            offset: query.offset,
            limit: query.limit,
            total,
            filtered_total: total,
            related: None,
        })
    }

    pub(crate) fn inventory_page(
        &self,
        run_id: &oxaudit_domain::RunId,
        query: &ResultPageQuery,
    ) -> Result<InventoryPage, CommandError> {
        validate(query)?;
        let connection = self.connection.lock().map_err(persistence_error)?;
        let payload = connection
            .query_row(
                "SELECT payload_json FROM canonical_runs WHERE id=?1",
                [run_id.as_str()],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(persistence_error)?
            .ok_or_else(CommandError::review_invalid)?;
        let run: oxaudit_domain::Run = from_json(&payload)?;
        let search = query.search.trim().to_lowercase();
        const FILTER: &str = "c.run_id=?1 AND (?2='' OR instr(s.search_text,?2)>0 OR EXISTS(SELECT 1 FROM inventory_advisories a WHERE a.run_id=c.run_id AND a.component_id=c.id AND instr(a.search_text,?2)>0))";
        const JOIN: &str = "canonical_components c JOIN inventory_component_search s ON s.run_id=c.run_id AND s.component_id=c.id";
        let total: usize = connection
            .query_row(
                "SELECT COUNT(*) FROM canonical_components WHERE run_id=?1",
                [run_id.as_str()],
                |row| row.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(persistence_error)?;
        let filtered_total: usize = connection
            .query_row(
                &format!("SELECT COUNT(*) FROM {JOIN} WHERE {FILTER}"),
                params![run_id.as_str(), search],
                |row| row.get::<_, i64>(0).map(|n| n as usize),
            )
            .map_err(persistence_error)?;
        let mut statement = connection
            .prepare(&format!(
                "SELECT c.payload_json FROM {JOIN} WHERE {FILTER} ORDER BY c.id LIMIT ?3 OFFSET ?4"
            ))
            .map_err(persistence_error)?;
        let mut rows = statement
            .query(params![run_id.as_str(), search, query.limit, query.offset])
            .map_err(persistence_error)?;
        let mut items = Vec::new();
        while let Some(row) = rows.next().map_err(persistence_error)? {
            let component: oxaudit_domain::Component =
                from_json(&row.get::<_, String>(0).map_err(persistence_error)?)?;
            let mut identities = Vec::new();
            for identity in component.identities {
                let artifact_path = connection.query_row("SELECT json_extract(payload_json,'$.location.normalizedPath') FROM canonical_artifacts WHERE run_id=?1 AND id=?2",
                    params![run_id.as_str(),identity.source_artifact_id.as_str()], |row| row.get::<_,String>(0)).optional().map_err(persistence_error)?
                    .unwrap_or_else(|| "artifact unavailable".into());
                identities.push(InventoryIdentityView {
                    method: enum_name(&identity.method)?,
                    value: identity.value,
                    confidence: identity.confidence,
                    artifact_id: identity.source_artifact_id.to_string(),
                    artifact_path,
                });
            }
            let mut advisory_statement = connection.prepare("SELECT advisory_id FROM inventory_advisories WHERE run_id=?1 AND component_id=?2 ORDER BY advisory_id").map_err(persistence_error)?;
            let advisory_ids = advisory_statement
                .query_map(params![run_id.as_str(), component.id.as_str()], |row| {
                    row.get(0)
                })
                .map_err(persistence_error)?
                .collect::<Result<Vec<String>, _>>()
                .map_err(persistence_error)?;
            items.push(InventoryComponentView {
                id: component.id.to_string(),
                name: component.name,
                version: component.version,
                supplier: component.supplier,
                ecosystem: component.ecosystem,
                purl: component.purl,
                cpes: component.cpes,
                aliases: component.aliases,
                identities,
                advisory_ids,
            });
        }
        Ok(InventoryPage {
            page: ResultPage {
                items,
                offset: query.offset,
                limit: query.limit,
                total,
                filtered_total,
                related: None,
            },
            run_id: run.id.to_string(),
            target_label: run.target_label,
            run_kind: run.kind,
            updated_at_ms: run.updated_at_ms,
            provider_snapshot_count: run.provider_snapshot_ids.len(),
        })
    }
}
