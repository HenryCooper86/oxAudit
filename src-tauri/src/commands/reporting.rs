//! Export, import, and inventory commands.
//!
//! Split out of `commands/mod.rs`. A child module rather than a sibling
//! file, so `use super::*` still reaches the shared state and helpers
//! without widening anything to `pub`.

use super::*;
use crate::findings::{
    domain::{ResultPage, ResultPageQuery},
    inventory::InventoryPage,
};

#[tauri::command]
pub fn list_inventory_runs(
    findings: State<'_, FindingsState>,
    query: Option<ResultPageQuery>,
) -> Result<ResultPage<oxaudit_domain::Run>, String> {
    list_inventory_runs_inner(&findings, query.unwrap_or_default())
}

pub(crate) fn list_inventory_runs_inner(
    findings: &FindingsState,
    query: ResultPageQuery,
) -> Result<ResultPage<oxaudit_domain::Run>, String> {
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .inventory_runs_page(&query)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn load_inventory_page(
    findings: State<'_, FindingsState>,
    run_id: String,
    query: Option<ResultPageQuery>,
) -> Result<InventoryPage, String> {
    load_inventory_page_inner(&findings, run_id, query.unwrap_or_default())
}

pub(crate) fn load_inventory_page_inner(
    findings: &FindingsState,
    run_id: String,
    query: ResultPageQuery,
) -> Result<InventoryPage, String> {
    let id =
        oxaudit_domain::RunId::parse(run_id).map_err(|_| "invalid run identity".to_string())?;
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .inventory_page(&id, &query)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn preview_report_import(
    findings: State<'_, FindingsState>,
    path: String,
) -> Result<ImportPreview, String> {
    preview_report_import_inner(&findings, path)
}

pub(crate) fn preview_report_import_inner(
    findings: &FindingsState,
    path: String,
) -> Result<ImportPreview, String> {
    let (path, _, analysis) = read_import_report(&path)?;
    let service = findings.service().map_err(|error| error.to_string())?;
    let conflicts = imported_component_conflicts(service, &analysis)?;
    let conflict_count = conflicts.len();
    let unmapped_count = analysis.unmapped_records.len();
    let can_import_inventory = analysis.can_import_inventory();
    let can_import_external_claims = !analysis.external_claims.is_empty();
    let mapped_claim_count = analysis.external_claims.len();
    Ok(ImportPreview {
        format: analysis.format.into(),
        media_type: analysis.media_type.into(),
        file_name: path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "report.json".into()),
        content_sha256: analysis.content_sha256,
        component_records: analysis.components.len(),
        finding_records: analysis.finding_records,
        review_records: analysis.review_records,
        conflict_count,
        conflicts: conflicts.into_iter().take(200).collect(),
        unmapped_count,
        unmapped_records: analysis.unmapped_records.into_iter().take(200).collect(),
        warnings: analysis.warnings,
        can_import_inventory,
        mapped_claim_count,
        mapped_claims: analysis.external_claims.into_iter().take(200).collect(),
        can_import_external_claims,
    })
}

#[tauri::command]
pub fn import_external_report(
    app: AppHandle,
    findings: State<'_, FindingsState>,
    path: String,
    expected_sha256: String,
) -> Result<oxaudit_domain::Run, String> {
    let events = crate::presentation::TauriRunEvents::new(app);
    import_external_report_inner(&findings, &events, path, expected_sha256)
}

pub(crate) fn import_external_report_inner(
    findings: &FindingsState,
    events: &dyn oxaudit_application::RunEventSink,
    path: String,
    expected_sha256: String,
) -> Result<oxaudit_domain::Run, String> {
    const MAX_EXTERNAL_CLAIMS: usize = 50_000;
    let (path, bytes, analysis) = read_import_report(&path)?;
    if analysis.content_sha256 != expected_sha256.to_ascii_lowercase() {
        return Err("the report changed after preview; preview it again before importing".into());
    }
    if analysis.external_claims.is_empty() {
        return Err("this report has no external claims that can be mapped safely".into());
    }
    if analysis.external_claims.len() > MAX_EXTERNAL_CLAIMS {
        return Err("the report exceeds the 50,000-claim import limit".into());
    }

    let service = findings.service().map_err(|error| error.to_string())?;
    persist_external_claims(service.repository(), &path, &bytes, &analysis, events)
}

/// The import path shared by the desktop command and the CLI: run
/// lifecycle, artifact, warnings, and the immutable external-claims
/// projection. Nothing here trusts the imported content — see the trust
/// boundary warning, which the projection itself carries forward.
pub(crate) fn persist_external_claims(
    repository: &crate::findings::repository::FindingsRepository,
    path: &std::path::Path,
    bytes: &[u8],
    analysis: &crate::adapters::reporting::import::ImportAnalysis,
    events: &dyn oxaudit_application::RunEventSink,
) -> Result<oxaudit_domain::Run, String> {
    use sha2::Digest;
    let mut run = oxaudit_domain::Run::queued(
        oxaudit_domain::RunKind::ExternalEvidence,
        path.to_string_lossy(),
        epoch_millis(),
    );
    run.engine_ids
        .push(format!("oxaudit.external-import.{}", analysis.format));
    let artifact_id = oxaudit_domain::ArtifactId::parse(format!(
        "artifact_{:x}",
        sha2::Sha256::digest(
            format!(
                "{}\0{}\0{}\0external-claims",
                run.id,
                path.display(),
                analysis.content_sha256
            )
            .as_bytes()
        )
    ))
    .map_err(|error| error.to_string())?;
    let artifact = oxaudit_domain::Artifact {
        id: artifact_id,
        kind: oxaudit_domain::ArtifactKind::Report,
        location: oxaudit_domain::ArtifactLocation {
            normalized_path: path.to_string_lossy().replace('\\', "/"),
            canonical_path: Some(path.to_string_lossy().into_owned()),
            parent_id: None,
        },
        size_bytes: bytes.len() as u64,
        media_type: Some(analysis.media_type.into()),
        content_sha256: Some(analysis.content_sha256.clone()),
    };
    let canonical_repository =
        crate::adapters::persistence::CanonicalSqliteRepository::new(repository);
    let coordinator = oxaudit_application::RunCoordinator::new(&canonical_repository, events);
    let mut managed = Some(coordinator.begin(run).map_err(|error| error.to_string())?);
    let imported = (|| -> Result<oxaudit_domain::Run, String> {
        let lifecycle = managed.as_mut().expect("managed external import exists");
        lifecycle
            .transition(oxaudit_domain::RunState::Discovering, epoch_millis())
            .map_err(|error| error.to_string())?;
        lifecycle
            .append_artifact(&artifact)
            .map_err(|error| error.to_string())?;
        lifecycle
            .transition(oxaudit_domain::RunState::Detecting, epoch_millis())
            .map_err(|error| error.to_string())?;
        lifecycle
            .transition(oxaudit_domain::RunState::Normalizing, epoch_millis())
            .map_err(|error| error.to_string())?;
        lifecycle
            .transition(oxaudit_domain::RunState::Assessing, epoch_millis())
            .map_err(|error| error.to_string())?;
        lifecycle.warning(
            "external_claims_unverified",
            "Imported claims remain external-unverified and cannot change local findings or reviews.",
        );
        for warning in &analysis.warnings {
            lifecycle.warning("import_limitation", warning);
        }
        lifecycle
            .transition(oxaudit_domain::RunState::Persisting, epoch_millis())
            .map_err(|error| error.to_string())?;
        repository
            .canonical_save_projection(
                &lifecycle.run().id,
                "external-claims",
                1,
                &serde_json::json!({
                    "format": analysis.format,
                    "contentSha256": analysis.content_sha256,
                    "trustBoundary": "external-unverified",
                    "claims": analysis.external_claims,
                    "unmappedRecords": analysis.unmapped_records,
                }),
            )
            .map_err(|error| error.to_string())?;
        let outcome = managed
            .take()
            .expect("managed external import exists")
            .complete(epoch_millis())
            .map_err(|error| error.to_string())?;
        Ok(outcome.run)
    })();
    if imported.is_err() {
        if let Some(lifecycle) = managed.take() {
            let _ = lifecycle.terminate(oxaudit_domain::RunState::Failed, epoch_millis());
        }
    }
    imported
}

#[tauri::command]
pub fn import_inventory_report(
    app: AppHandle,
    findings: State<'_, FindingsState>,
    path: String,
    expected_sha256: String,
) -> Result<oxaudit_domain::Run, String> {
    let events = crate::presentation::TauriRunEvents::new(app);
    import_inventory_report_inner(&findings, &events, path, expected_sha256)
}

pub(crate) fn import_inventory_report_inner(
    findings: &FindingsState,
    events: &dyn oxaudit_application::RunEventSink,
    path: String,
    expected_sha256: String,
) -> Result<oxaudit_domain::Run, String> {
    use sha2::Digest;

    const MAX_COMPONENT_RECORDS: usize = 50_000;
    let (path, bytes, analysis) = read_import_report(&path)?;
    if analysis.content_sha256 != expected_sha256.to_ascii_lowercase() {
        return Err("the report changed after preview; preview it again before importing".into());
    }
    if !analysis.can_import_inventory() {
        return Err("this report has no inventory records that can be imported safely".into());
    }
    if analysis.components.len() > MAX_COMPONENT_RECORDS {
        return Err("the report exceeds the 50,000-component import limit".into());
    }
    let service = findings.service().map_err(|error| error.to_string())?;
    let conflicts = imported_component_conflicts(service, &analysis)?;
    let mut run = oxaudit_domain::Run::queued(
        oxaudit_domain::RunKind::Import,
        path.to_string_lossy(),
        epoch_millis(),
    );
    run.engine_ids
        .push(format!("oxaudit.import.{}", analysis.format));
    let artifact_id = oxaudit_domain::ArtifactId::parse(format!(
        "artifact_{:x}",
        sha2::Sha256::digest(
            format!(
                "{}\0{}\0{}",
                run.id,
                path.display(),
                analysis.content_sha256
            )
            .as_bytes()
        )
    ))
    .map_err(|error| error.to_string())?;
    let artifact = oxaudit_domain::Artifact {
        id: artifact_id.clone(),
        kind: if matches!(analysis.format, "cyclonedx" | "cyclonedx-vex" | "spdx") {
            oxaudit_domain::ArtifactKind::Sbom
        } else {
            oxaudit_domain::ArtifactKind::Report
        },
        location: oxaudit_domain::ArtifactLocation {
            normalized_path: path.to_string_lossy().replace('\\', "/"),
            canonical_path: Some(path.to_string_lossy().into_owned()),
            parent_id: None,
        },
        size_bytes: bytes.len() as u64,
        media_type: Some(analysis.media_type.into()),
        content_sha256: Some(analysis.content_sha256.clone()),
    };
    // Allocate every canonical ID first; source refs may point forward, form
    // cycles, or identify two components with the same name and version.
    let component_ids = analysis
        .components
        .iter()
        .enumerate()
        .map(|(index, imported)| {
            oxaudit_domain::ComponentId::parse(format!(
                "component_{:x}",
                sha2::Sha256::digest(
                    format!("{}\0{}\0{}", run.id, index, imported.conflict_key()).as_bytes()
                )
            ))
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;
    let components = analysis
        .components
        .iter()
        .enumerate()
        .map(|(index, imported)| oxaudit_domain::Component {
            depends_on: imported
                .depends_on
                .iter()
                .map(|target| component_ids[*target].to_string())
                .collect(),
            license: imported.license.clone(),
            id: component_ids[index].clone(),
            name: imported.name.clone(),
            version: imported.version.clone(),
            supplier: imported.supplier.clone(),
            ecosystem: imported.ecosystem.clone(),
            purl: imported.purl.clone(),
            cpes: imported.cpes.clone(),
            aliases: imported.aliases.clone(),
            identities: vec![oxaudit_domain::ComponentIdentity {
                method: oxaudit_domain::IdentityMethod::ImportedSbom,
                value: imported.purl.clone().unwrap_or_else(|| {
                    format!(
                        "{}@{}",
                        imported.name,
                        imported.version.as_deref().unwrap_or("unknown")
                    )
                }),
                confidence: imported.confidence,
                source_artifact_id: artifact_id.clone(),
            }],
        })
        .collect::<Vec<_>>();
    let component_metadata = analysis
        .components
        .iter()
        .enumerate()
        .map(|(index, imported)| {
            let mut metadata = imported.license_metadata.clone();
            metadata["componentId"] = serde_json::json!(component_ids[index]);
            metadata["sourceRef"] = serde_json::json!(imported.source_ref);
            metadata
        })
        .collect::<Vec<_>>();
    let source_document: Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let source_relationships = if analysis.format == "oxaudit-json" {
        source_document.pointer("/projection/sourceRelationships")
    } else {
        source_document
            .get("relationships")
            .or_else(|| source_document.get("dependencies"))
    };
    let native_licenses = (analysis.format == "oxaudit-json")
        .then(|| crate::adapters::reporting::import::native_license_projection(&source_document))
        .flatten();
    let license_document = native_licenses.unwrap_or(&source_document);
    let source_license_format = native_licenses
        .and_then(|projection| projection.get("sourceLicenseFormat"))
        .and_then(Value::as_str)
        .unwrap_or(if analysis.format == "cyclonedx-vex" {
            "cyclonedx"
        } else {
            analysis.format
        });
    let canonical_repository =
        crate::adapters::persistence::CanonicalSqliteRepository::new(service.repository());
    let coordinator = oxaudit_application::RunCoordinator::new(&canonical_repository, events);
    let mut managed = Some(coordinator.begin(run).map_err(|error| error.to_string())?);
    let imported = (|| -> Result<oxaudit_domain::Run, String> {
        let lifecycle = managed.as_mut().expect("managed import run exists");
        lifecycle
            .transition(oxaudit_domain::RunState::Discovering, epoch_millis())
            .map_err(|error| error.to_string())?;
        lifecycle
            .append_artifact(&artifact)
            .map_err(|error| error.to_string())?;
        lifecycle
            .transition(oxaudit_domain::RunState::Detecting, epoch_millis())
            .map_err(|error| error.to_string())?;
        lifecycle
            .transition(oxaudit_domain::RunState::Normalizing, epoch_millis())
            .map_err(|error| error.to_string())?;
        lifecycle
            .append_components(&components)
            .map_err(|error| error.to_string())?;
        lifecycle
            .transition(oxaudit_domain::RunState::Assessing, epoch_millis())
            .map_err(|error| error.to_string())?;
        for warning in &analysis.warnings {
            lifecycle.warning("import_limitation", warning);
        }
        if !analysis.unmapped_records.is_empty() {
            lifecycle.warning("import_unmapped_records", format!("{} source records or relationships could not be mapped exactly; see the inventory-import projection for details.", analysis.unmapped_records.len()));
        }
        if !conflicts.is_empty() {
            lifecycle.warning(
                "inventory_conflicts_preserved",
                format!(
                    "{} component identities overlap earlier runs; both immutable records were preserved.",
                    conflicts.len()
                ),
            );
        }
        lifecycle
            .transition(oxaudit_domain::RunState::Persisting, epoch_millis())
            .map_err(|error| error.to_string())?;
        service
            .repository()
            .canonical_save_projection(
                &lifecycle.run().id,
                "inventory-import",
                1,
                &serde_json::json!({
                    "format": analysis.format,
                    "contentSha256": analysis.content_sha256,
                    "componentRecords": components.len(),
                    "componentMetadata": component_metadata,
                    "sourceLicenseFormat": source_license_format,
                    "hasExtractedLicensingInfos": license_document.get("hasExtractedLicensingInfos"),
                    "externalDocumentRefs": license_document.get("externalDocumentRefs"),
                    "sourceRelationships": source_relationships,
                    "conflictsPreserved": conflicts.len(),
                    "unmappedRecords": analysis.unmapped_records,
                }),
            )
            .map_err(|error| error.to_string())?;
        let outcome = managed
            .take()
            .expect("managed import run exists")
            .complete(epoch_millis())
            .map_err(|error| error.to_string())?;
        Ok(outcome.run)
    })();
    if imported.is_err() {
        if let Some(lifecycle) = managed.take() {
            let _ = lifecycle.terminate(oxaudit_domain::RunState::Failed, epoch_millis());
        }
    }
    imported
}

#[tauri::command]
pub fn load_inventory(
    findings: State<'_, FindingsState>,
    run_id: String,
) -> Result<InventoryView, String> {
    load_inventory_inner(&findings, run_id)
}

pub(crate) fn load_inventory_inner(
    findings: &FindingsState,
    run_id: String,
) -> Result<InventoryView, String> {
    let run_id =
        oxaudit_domain::RunId::parse(run_id).map_err(|_| "invalid run identity".to_string())?;
    let data = report_data(
        findings.service().map_err(|error| error.to_string())?,
        &run_id,
    )?;
    let artifact_paths = data
        .artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.id.clone(),
                artifact.location.normalized_path.clone(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut advisory_ids = std::collections::BTreeMap::<
        oxaudit_domain::ComponentId,
        std::collections::BTreeSet<String>,
    >::new();
    for record in &data.observations {
        for evidence in &record.evidence {
            if let oxaudit_domain::Evidence::AdvisoryMatch(match_evidence) = &evidence.evidence {
                advisory_ids
                    .entry(match_evidence.component_id.clone())
                    .or_default()
                    .insert(match_evidence.advisory_id.clone());
            }
        }
    }
    let components = data
        .components
        .into_iter()
        .map(|component| {
            let identities = component
                .identities
                .into_iter()
                .map(|identity| InventoryIdentityView {
                    method: serde_json::to_value(identity.method)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_else(|| "unknown".into()),
                    value: identity.value,
                    confidence: identity.confidence,
                    artifact_path: artifact_paths
                        .get(&identity.source_artifact_id)
                        .cloned()
                        .unwrap_or_else(|| "artifact unavailable".into()),
                    artifact_id: identity.source_artifact_id.to_string(),
                })
                .collect();
            InventoryComponentView {
                advisory_ids: advisory_ids
                    .remove(&component.id)
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
                id: component.id.to_string(),
                name: component.name,
                version: component.version,
                supplier: component.supplier,
                ecosystem: component.ecosystem,
                purl: component.purl,
                cpes: component.cpes,
                aliases: component.aliases,
                identities,
            }
        })
        .collect();
    Ok(InventoryView {
        run_id: data.run.id.to_string(),
        target_label: data.run.target_label,
        run_kind: data.run.kind,
        updated_at_ms: data.run.updated_at_ms,
        provider_snapshot_count: data.run.provider_snapshot_ids.len(),
        components,
    })
}

#[tauri::command]
pub fn preview_run_export(
    findings: State<'_, FindingsState>,
    run_id: String,
    format: String,
) -> Result<ExportPreview, String> {
    preview_run_export_inner(&findings, run_id, format)
}

pub(crate) fn preview_run_export_inner(
    findings: &FindingsState,
    run_id: String,
    format: String,
) -> Result<ExportPreview, String> {
    const PREVIEW_LIMIT: usize = 1024 * 1024;
    let run_id =
        oxaudit_domain::RunId::parse(run_id).map_err(|_| "invalid run identity".to_string())?;
    let format_value = crate::adapters::reporting::ReportFormat::parse(&format)?;
    let data = report_data(
        findings.service().map_err(|error| error.to_string())?,
        &run_id,
    )?;
    let generated = crate::adapters::reporting::generate(&data, format_value)?;
    let truncated = generated.bytes.len() > PREVIEW_LIMIT;
    let preview_bytes = &generated.bytes[..generated.bytes.len().min(PREVIEW_LIMIT)];
    let content = String::from_utf8_lossy(preview_bytes).into_owned();
    Ok(ExportPreview {
        format,
        media_type: format_value.media_type().into(),
        suggested_file_name: format!("{}-{}", run_id.as_str(), format_value.suffix()),
        valid: true,
        warnings: generated.warnings,
        artifacts: data.artifacts.len(),
        components: data.components.len(),
        observations: data.observations.len(),
        content,
        truncated,
    })
}

#[tauri::command]
pub fn write_run_export(
    findings: State<'_, FindingsState>,
    run_id: String,
    format: String,
    output_path: String,
) -> Result<(), String> {
    write_run_export_inner(&findings, run_id, format, output_path)
}

pub(crate) fn write_run_export_inner(
    findings: &FindingsState,
    run_id: String,
    format: String,
    output_path: String,
) -> Result<(), String> {
    let run_id =
        oxaudit_domain::RunId::parse(run_id).map_err(|_| "invalid run identity".to_string())?;
    let format = crate::adapters::reporting::ReportFormat::parse(&format)?;
    let data = report_data(
        findings.service().map_err(|error| error.to_string())?,
        &run_id,
    )?;
    let generated = crate::adapters::reporting::generate(&data, format)?;
    let destination = PathBuf::from(output_path);
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| "export destination must have a parent directory".to_string())?;
    if !parent.is_dir() {
        return Err("export destination directory does not exist".into());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| format!("could not create export file: {error}"))?;
    temporary
        .write_all(&generated.bytes)
        .and_then(|_| temporary.as_file().sync_all())
        .map_err(|error| format!("could not write export: {error}"))?;
    temporary
        .persist(&destination)
        .map_err(|error| format!("could not finalize export: {}", error.error))?;
    Ok(())
}

#[tauri::command]
pub fn list_verification_claims(
    findings: State<'_, FindingsState>,
    run_id: Option<String>,
) -> Result<Vec<oxaudit_domain::Finding>, String> {
    list_verification_claims_inner(&findings, run_id)
}

pub(crate) fn list_verification_claims_inner(
    findings: &FindingsState,
    run_id: Option<String>,
) -> Result<Vec<oxaudit_domain::Finding>, String> {
    let parsed = run_id
        .map(oxaudit_domain::RunId::parse)
        .transpose()
        .map_err(|_| "invalid run identity".to_string())?;
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .canonical_list_findings(parsed.as_ref())
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn list_verifications(
    findings: State<'_, FindingsState>,
    finding_id: Option<String>,
) -> Result<Vec<oxaudit_domain::Verification>, String> {
    list_verifications_inner(&findings, finding_id)
}

pub(crate) fn list_verifications_inner(
    findings: &FindingsState,
    finding_id: Option<String>,
) -> Result<Vec<oxaudit_domain::Verification>, String> {
    let parsed = finding_id
        .map(oxaudit_domain::FindingId::parse)
        .transpose()
        .map_err(|_| "invalid finding identity".to_string())?;
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .verification_list(parsed.as_ref())
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn verify_finding(
    findings: State<'_, FindingsState>,
    finding_id: String,
    verifier_id: String,
    result: String,
    limitation: String,
) -> Result<oxaudit_domain::Verification, String> {
    verify_finding_inner(&findings, finding_id, verifier_id, result, limitation)
}

pub(crate) fn verify_finding_inner(
    findings: &FindingsState,
    finding_id: String,
    verifier_id: String,
    result: String,
    limitation: String,
) -> Result<oxaudit_domain::Verification, String> {
    use sha2::Digest;

    let finding_id = oxaudit_domain::FindingId::parse(finding_id)
        .map_err(|_| "invalid finding identity".to_string())?;
    let verifier_id = verifier_id.trim();
    if verifier_id.is_empty() {
        return Err("verifier identity is required".into());
    }
    let result = match result.as_str() {
        "supported" => oxaudit_domain::VerificationResult::Supported,
        "refuted" => oxaudit_domain::VerificationResult::Refuted,
        "inconclusive" => oxaudit_domain::VerificationResult::Inconclusive,
        _ => return Err("invalid verification result".into()),
    };
    let service = findings.service().map_err(|error| error.to_string())?;
    let repository = service.repository();
    let finding = repository
        .canonical_load_finding(&finding_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "finding was not found".to_string())?;
    let (_, _, observations) = repository
        .canonical_load_report_graph(&finding.run_id)
        .map_err(|error| error.to_string())?;
    let observation = observations
        .iter()
        .find(|record| finding.observation_ids.contains(&record.observation.id))
        .ok_or_else(|| "finding evidence is unavailable".to_string())?;
    let producer_id = observation.observation.detector_id.clone();
    if verifier_id == producer_id {
        return Err("the producing detector cannot independently verify its own claim".into());
    }
    let snapshot = serde_json::to_vec(&(
        finding.clone(),
        &observation.observation,
        &observation.evidence,
    ))
    .map_err(|error| error.to_string())?;
    let verification = oxaudit_domain::Verification {
        id: oxaudit_domain::VerificationId::new(),
        finding_id,
        producer_id,
        verifier: oxaudit_domain::VerifierIdentity {
            kind: "human".into(),
            id: verifier_id.into(),
            version: "1".into(),
        },
        input_snapshot_sha256: format!("{:x}", sha2::Sha256::digest(snapshot)),
        result,
        evidence_delta: Vec::new(),
        limitations: if limitation.trim().is_empty() {
            vec!["No additional limitation was recorded by the verifier.".into()]
        } else {
            vec![limitation.trim().into()]
        },
        verified_at_ms: epoch_millis(),
    };
    verification
        .validate_independence()
        .map_err(|error| error.to_string())?;
    let mut run = repository
        .canonical_load_run(&finding.run_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "verification run was not found".to_string())?;
    run.transition(oxaudit_domain::RunState::Verifying, epoch_millis())
        .map_err(|error| error.to_string())?;
    repository
        .canonical_save_run(&run)
        .map_err(|error| error.to_string())?;
    repository
        .verification_save(&verification)
        .map_err(|error| error.to_string())?;
    run.transition(oxaudit_domain::RunState::Completed, epoch_millis())
        .map_err(|error| error.to_string())?;
    repository
        .canonical_save_run(&run)
        .map_err(|error| error.to_string())?;
    Ok(verification)
}

#[tauri::command]
pub fn load_canonical_projection(
    findings: State<'_, FindingsState>,
    run_id: String,
) -> Result<Value, String> {
    load_canonical_projection_inner(&findings, run_id)
}

pub(crate) fn load_canonical_projection_inner(
    findings: &FindingsState,
    run_id: String,
) -> Result<Value, String> {
    let run_id =
        oxaudit_domain::RunId::parse(run_id).map_err(|_| "invalid run identity".to_string())?;
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .canonical_load_projection(&run_id)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "run result projection was not found".into())
}

#[tauri::command]
pub fn load_canonical_projection_metadata(
    findings: State<'_, FindingsState>,
    run_id: String,
) -> Result<crate::findings::domain::CanonicalProjectionMetadata, String> {
    load_canonical_projection_metadata_inner(&findings, run_id)
}

pub(crate) fn load_canonical_projection_metadata_inner(
    findings: &FindingsState,
    run_id: String,
) -> Result<crate::findings::domain::CanonicalProjectionMetadata, String> {
    let run_id =
        oxaudit_domain::RunId::parse(run_id).map_err(|_| "invalid run identity".to_string())?;
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .canonical_projection_metadata(&run_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn load_canonical_projection_page(
    findings: State<'_, FindingsState>,
    run_id: String,
    section: String,
    query: Option<crate::findings::domain::ResultPageQuery>,
) -> Result<crate::findings::domain::ResultPage<Value>, String> {
    load_canonical_projection_page_inner(&findings, run_id, section, query.unwrap_or_default())
}

pub(crate) fn load_canonical_projection_page_inner(
    findings: &FindingsState,
    run_id: String,
    section: String,
    query: crate::findings::domain::ResultPageQuery,
) -> Result<crate::findings::domain::ResultPage<Value>, String> {
    let run_id =
        oxaudit_domain::RunId::parse(run_id).map_err(|_| "invalid run identity".to_string())?;
    findings
        .service()
        .map_err(|error| error.to_string())?
        .repository()
        .canonical_projection_page(&run_id, &section, &query)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod import_fidelity_tests {
    use super::*;

    struct NoEvents;
    impl oxaudit_application::RunEventSink for NoEvents {
        fn publish(&self, _: &oxaudit_application::EventEnvelope) -> Result<(), String> {
            Ok(())
        }
    }

    fn import_fixture(document: Value) -> (tempfile::TempDir, FindingsState, oxaudit_domain::Run) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inventory.json");
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let findings = FindingsState::available(crate::findings::service::FindingsService::new(
            crate::findings::repository::FindingsRepository::open_in_memory().unwrap(),
        ));
        let preview =
            preview_report_import_inner(&findings, path.to_string_lossy().into()).unwrap();
        let run = import_inventory_report_inner(
            &findings,
            &NoEvents,
            path.to_string_lossy().into(),
            preview.content_sha256,
        )
        .unwrap();
        (directory, findings, run)
    }

    #[test]
    fn native_intermediary_preserves_source_license_metadata() {
        use crate::adapters::reporting::{generate, ReportFormat};
        let fixtures = [
            (
                ReportFormat::Spdx,
                serde_json::json!({
                    "spdxVersion":"SPDX-2.3", "documentNamespace":"https://example.test/bom",
                    "hasExtractedLicensingInfos":[{"licenseId":"LicenseRef-Custom","extractedText":"Custom permission text"}],
                    "externalDocumentRefs":[{"externalDocumentId":"DocumentRef-Other","spdxDocument":"https://example.test/other","checksum":{"algorithm":"SHA1","checksumValue":"0123456789012345678901234567890123456789"}}],
                    "packages":[{"SPDXID":"SPDXRef-a","name":"a","licenseDeclared":"LicenseRef-Custom","licenseConcluded":"MIT"}]
                }),
            ),
            (
                ReportFormat::CycloneDx,
                serde_json::json!({
                    "bomFormat":"CycloneDX","specVersion":"1.6","version":1,
                    "components":[{"type":"library","bom-ref":"a","name":"a","licenses":[
                        {"license":{"id":"MIT","url":"https://opensource.org/licenses/MIT"}},
                        {"license":{"name":"Custom","text":{"content":"Custom permission text"}}}
                    ]}]
                }),
            ),
        ];
        for (format, original) in fixtures {
            let (_first_dir, first, first_run) = import_fixture(original.clone());
            let first_data = report_data(first.service().unwrap(), &first_run.id).unwrap();
            let native = generate(&first_data, ReportFormat::OxAuditJson).unwrap();
            let (_second_dir, second, second_run) =
                import_fixture(serde_json::from_slice(&native.bytes).unwrap());
            let second_data = report_data(second.service().unwrap(), &second_run.id).unwrap();
            assert_ne!(first_data.components[0].id, second_data.components[0].id);
            let exported: Value =
                serde_json::from_slice(&generate(&second_data, format).unwrap().bytes).unwrap();
            match format {
                ReportFormat::Spdx => {
                    for field in ["licenseDeclared", "licenseConcluded"] {
                        assert_eq!(
                            exported["packages"][0][field],
                            original["packages"][0][field]
                        );
                    }
                    for field in ["hasExtractedLicensingInfos", "externalDocumentRefs"] {
                        assert_eq!(exported[field], original[field]);
                    }
                }
                ReportFormat::CycloneDx => assert_eq!(
                    exported["components"][0]["licenses"],
                    original["components"][0]["licenses"]
                ),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn sbom_import_persists_nested_licenses_and_canonical_graph() {
        let (_directory, findings, run) = import_fixture(serde_json::json!({
            "bomFormat":"CycloneDX", "specVersion":"1.6", "version":1,
            "components":[{"type":"library","bom-ref":"parent","name":"same","licenses":[{"expression":"MIT OR Apache-2.0"}],"components":[
                {"type":"library","bom-ref":"child","name":"same","licenses":[{"license":{"id":"BSD-3-Clause"}}]},
                {"type":"library","bom-ref":"rich","name":"rich","licenses":[{"license":{"id":"MIT","url":"https://opensource.org/licenses/MIT"}},{"license":{"name":"Internal license","text":{"content":"Internal permission text."}}}]}
            ]}],
            "dependencies":[{"ref":"parent","dependsOn":["child"]}]
        }));
        let data = report_data(findings.service().unwrap(), &run.id).unwrap();
        let parent = data
            .components
            .iter()
            .find(|component| component.license.as_deref() == Some("MIT OR Apache-2.0"))
            .expect("declared license must survive import");
        let child = data
            .components
            .iter()
            .find(|component| component.license.as_deref() == Some("BSD-3-Clause"))
            .unwrap();
        assert_ne!(parent.id, child.id);
        assert_eq!(parent.depends_on, [child.id.to_string()]);
        let output = crate::adapters::reporting::generate(
            &data,
            crate::adapters::reporting::ReportFormat::CycloneDx,
        )
        .unwrap();
        let exported: Value = serde_json::from_slice(&output.bytes).unwrap();
        assert_eq!(
            exported["dependencies"][0]["dependsOn"][0],
            child.id.as_str()
        );
        let rich = exported["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["name"] == "rich")
            .unwrap();
        assert_eq!(
            rich["licenses"],
            serde_json::json!([
                {"license":{"id":"MIT","url":"https://opensource.org/licenses/MIT"}},
                {"license":{"name":"Internal license","text":{"content":"Internal permission text."}}}
            ])
        );
    }
    #[test]
    fn spdx_import_persists_license_metadata_and_reexports_dependencies() {
        let licenses = serde_json::json!([{"licenseId":"LicenseRef-Custom", "extractedText":"Permission granted for local use."}]);
        let external = serde_json::json!([{"externalDocumentId":"DocumentRef-ThirdParty","spdxDocument":"https://example.test/third-party","checksum":{"algorithm":"SHA1","checksumValue":"0123456789012345678901234567890123456789"}}]);
        let (_directory, findings, run) = import_fixture(serde_json::json!({
            "spdxVersion":"SPDX-2.3", "documentNamespace":"https://example.test/bom",
            "hasExtractedLicensingInfos": licenses,
            "externalDocumentRefs": external,
            "packages":[
                {"SPDXID":"SPDXRef-a","name":"a","licenseDeclared":"LicenseRef-Custom","licenseConcluded":"MIT"},
                {"SPDXID":"SPDXRef-b","name":"b","licenseDeclared":"NOASSERTION"}
            ],
            "relationships":[{"spdxElementId":"SPDXRef-b","relationshipType":"DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-a"}]
        }));
        let data = report_data(findings.service().unwrap(), &run.id).unwrap();
        let a = data
            .components
            .iter()
            .find(|component| component.name == "a")
            .unwrap();
        let b = data
            .components
            .iter()
            .find(|component| component.name == "b")
            .unwrap();
        assert_eq!(a.depends_on, [b.id.to_string()]);
        assert_eq!(a.license.as_deref(), Some("LicenseRef-Custom"));
        let projection = data.projection.as_ref().unwrap();
        let metadata = projection["componentMetadata"]
            .as_array()
            .unwrap()
            .iter()
            .find(|metadata| metadata["componentId"] == a.id.as_str())
            .unwrap();
        assert_eq!(metadata["licenseConcluded"], "MIT");
        assert_eq!(projection["hasExtractedLicensingInfos"], licenses);
        let output = crate::adapters::reporting::generate(
            &data,
            crate::adapters::reporting::ReportFormat::Spdx,
        )
        .unwrap();
        let exported: Value = serde_json::from_slice(&output.bytes).unwrap();
        let packages = exported["packages"].as_array().unwrap();
        let exported_a = packages
            .iter()
            .find(|package| package["name"] == "a")
            .unwrap();
        let exported_b = packages
            .iter()
            .find(|package| package["name"] == "b")
            .unwrap();
        assert_eq!(exported_a["licenseConcluded"], "MIT");
        assert_eq!(exported["hasExtractedLicensingInfos"], licenses);
        assert_eq!(exported["externalDocumentRefs"], external);
        assert!(exported["relationships"]
            .as_array()
            .unwrap()
            .iter()
            .any(|relationship| {
                relationship["spdxElementId"] == exported_a["SPDXID"]
                    && relationship["relatedSpdxElement"] == exported_b["SPDXID"]
                    && relationship["relationshipType"] == "DEPENDS_ON"
            }));
    }
    #[test]
    fn native_intermediary_retains_unmapped_relationship_evidence() {
        use crate::adapters::reporting::{generate, ReportFormat};
        let relationships = serde_json::json!([{"ref":"root","dependsOn":["missing"]}]);
        let (_first_dir, first, first_run) = import_fixture(serde_json::json!({
            "bomFormat":"CycloneDX","specVersion":"1.6",
            "components":[{"bom-ref":"root","name":"root"}],
            "dependencies":relationships
        }));
        let first_data = report_data(first.service().unwrap(), &first_run.id).unwrap();
        let native = generate(&first_data, ReportFormat::OxAuditJson).unwrap();
        let (_second_dir, second, second_run) =
            import_fixture(serde_json::from_slice(&native.bytes).unwrap());
        let second_data = report_data(second.service().unwrap(), &second_run.id).unwrap();
        let projection = second_data.projection.as_ref().unwrap();
        assert_eq!(projection["sourceRelationships"], relationships);
        assert_eq!(
            projection["unmappedRecords"],
            first_data.projection.as_ref().unwrap()["unmappedRecords"]
        );
        assert!(second_data
            .run
            .warnings
            .iter()
            .any(|warning| warning.code == "import_unmapped_records"));
        let sbom = generate(&second_data, ReportFormat::CycloneDx).unwrap();
        assert!(sbom
            .warnings
            .iter()
            .any(|warning| warning.contains("could not be mapped exactly")));
        // Original dangling references remain evidence, never canonical edges.
        assert!(second_data.components[0].depends_on.is_empty());
    }

    #[test]
    fn unresolved_import_relationships_remain_visible_after_persistence() {
        let relationships = serde_json::json!([{"ref":"root","dependsOn":["missing","duplicate"]}]);
        let (_directory, findings, run) = import_fixture(serde_json::json!({
            "bomFormat":"CycloneDX","specVersion":"1.6",
            "components":[{"bom-ref":"root","name":"root"},{"bom-ref":"duplicate","name":"one"},{"bom-ref":"duplicate","name":"two"}],
            "dependencies":relationships
        }));
        let data = report_data(findings.service().unwrap(), &run.id).unwrap();
        assert!(data
            .components
            .iter()
            .all(|component| component.depends_on.is_empty()));
        assert!(data
            .run
            .warnings
            .iter()
            .any(|warning| warning.code == "import_unmapped_records"));
        let projection = data.projection.unwrap();
        assert_eq!(projection["sourceRelationships"], relationships);
        let unmapped = projection["unmappedRecords"].as_array().unwrap();
        assert!(unmapped.iter().any(|record| record
            .as_str()
            .unwrap()
            .contains("duplicate component reference")));
        assert!(unmapped
            .iter()
            .any(|record| record.as_str().unwrap().contains("missing")));
    }
}
