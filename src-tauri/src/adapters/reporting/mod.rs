use oxaudit_application::ObservationRecord;
use oxaudit_domain::{Artifact, Component, Evidence, Run};

pub mod compliance;
mod dependencies;
pub mod import;
mod schema;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    OxAuditJson,
    Sarif,
    CycloneDx,
    Spdx,
    OpenVex,
    CycloneDxVex,
    GithubIssuesCsv,
    JiraCsv,
}

impl ReportFormat {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "oxaudit-json" => Ok(Self::OxAuditJson),
            "sarif" => Ok(Self::Sarif),
            "cyclonedx" => Ok(Self::CycloneDx),
            "spdx" => Ok(Self::Spdx),
            "openvex" => Ok(Self::OpenVex),
            "cyclonedx-vex" => Ok(Self::CycloneDxVex),
            "github-issues-csv" => Ok(Self::GithubIssuesCsv),
            "jira-csv" => Ok(Self::JiraCsv),
            _ => Err("unsupported export format".into()),
        }
    }

    pub fn media_type(self) -> &'static str {
        match self {
            Self::Sarif => "application/sarif+json",
            Self::CycloneDx | Self::CycloneDxVex => "application/vnd.cyclonedx+json",
            Self::Spdx => "application/spdx+json",
            Self::OpenVex => "application/openvex+json",
            Self::OxAuditJson => "application/vnd.oxaudit.run+json",
            Self::GithubIssuesCsv | Self::JiraCsv => "text/csv",
        }
    }

    pub fn suffix(self) -> &'static str {
        match self {
            Self::OxAuditJson => "oxaudit.json",
            Self::Sarif => "sarif.json",
            Self::CycloneDx => "cdx.json",
            Self::Spdx => "spdx.json",
            Self::OpenVex => "openvex.json",
            Self::CycloneDxVex => "cdx-vex.json",
            Self::GithubIssuesCsv => "github-issues.csv",
            Self::JiraCsv => "jira.csv",
        }
    }
}

pub struct ReportData {
    pub run: Run,
    pub artifacts: Vec<Artifact>,
    pub components: Vec<Component>,
    pub observations: Vec<ObservationRecord>,
    pub findings: Vec<crate::models::Finding>,
    pub projection: Option<serde_json::Value>,
}

pub struct GeneratedReport {
    pub bytes: Vec<u8>,
    pub warnings: Vec<String>,
}

fn coverage_warnings(data: &ReportData) -> Vec<String> {
    let mut warnings = data
        .run
        .warnings
        .iter()
        .map(|warning| warning.message.clone())
        .collect::<Vec<_>>();
    if data.run.state != oxaudit_domain::RunState::Completed {
        warnings.insert(0, format!("Run {} is {}; execution was not completed. Retained evidence does not establish complete coverage.", data.run.id, run_state(data)));
    }
    if let Some(projection) = &data.projection {
        for pointer in ["/summary/coverageWarnings", "/notes"] {
            if let Some(notes) = projection
                .pointer(pointer)
                .and_then(serde_json::Value::as_array)
            {
                for note in notes.iter().filter_map(serde_json::Value::as_str) {
                    if !warnings.iter().any(|warning| warning == note) {
                        warnings.push(note.to_owned());
                    }
                }
            }
        }
        if let Some(note) = projection
            .get("limitNote")
            .and_then(serde_json::Value::as_str)
        {
            if !warnings.iter().any(|warning| warning == note) {
                warnings.push(note.to_owned());
            }
        }
    }
    warnings
}

fn run_state(data: &ReportData) -> String {
    serde_json::to_value(data.run.state)
        .expect("run state is serializable")
        .as_str()
        .expect("run state is a string")
        .to_owned()
}

fn lifecycle_text(data: &ReportData) -> String {
    let mut text = format!("oxAudit run {}; state: {}.", data.run.id, run_state(data));
    for warning in coverage_warnings(data) {
        text.push_str(&format!("\n{warning}"));
    }
    text
}

fn lifecycle_properties(data: &ReportData) -> serde_json::Value {
    serde_json::json!([
        {"name": "oxaudit:runId", "value": data.run.id.as_str()},
        {"name": "oxaudit:runState", "value": run_state(data)},
        {"name": "oxaudit:coverageWarnings", "value": serde_json::to_string(&coverage_warnings(data)).expect("warnings are serializable")}
    ])
}

pub fn generate(data: &ReportData, format: ReportFormat) -> Result<GeneratedReport, String> {
    if matches!(
        format,
        ReportFormat::GithubIssuesCsv | ReportFormat::JiraCsv
    ) {
        return generate_ticket_csv(data, format);
    }
    let mut warnings = coverage_warnings(data);
    let mut value = match format {
        ReportFormat::OxAuditJson => serde_json::json!({
            "schemaVersion": 1,
            "run": data.run,
            "artifacts": data.artifacts,
            "components": data.components,
            "observations": data.observations.iter().map(|record| serde_json::json!({
                "observation": record.observation,
                "evidence": record.evidence,
            })).collect::<Vec<_>>(),
            "projection": data.projection,
        }),
        ReportFormat::Sarif => {
            let findings_by_observation = data
                .findings
                .iter()
                .map(|finding| (finding.id.as_str(), finding))
                .collect::<std::collections::BTreeMap<_, _>>();
            let applicable = data.observations.iter().filter(|record| {
                matches!(
                    record.observation.kind,
                    oxaudit_domain::ObservationKind::SourceWeakness
                        | oxaudit_domain::ObservationKind::SecretCandidate
                        | oxaudit_domain::ObservationKind::PolicyConcern
                        | oxaudit_domain::ObservationKind::SemanticDataFlow
                )
            });
            let mut results =
                applicable
                    .map(|record| {
                        let location = record.evidence.iter().find_map(|evidence| match &evidence
                            .evidence
                        {
                            Evidence::FileLocation(location) => Some(location),
                            Evidence::RedactedSecret(secret) => Some(&secret.location),
                            _ => None,
                        });
                        let locations = location
                            .map(|location| {
                                vec![serde_json::json!({
                                    "physicalLocation": {
                                        "artifactLocation": { "uri": sarif_artifact_uri(&location.normalized_path) },
                                        "region": {
                                            "startLine": location.start_line.unwrap_or(1),
                                            "startColumn": location.start_column.unwrap_or(1)
                                        }
                                    }
                                })]
                            })
                            .unwrap_or_default();
                        let rule_id = record.observation.rule_id.as_deref();
                        let mut result = serde_json::json!({
                            // Consumers that show a severity read `level`, not
                            // our own vocabulary. Without it every finding
                            // arrives as an undifferentiated warning.
                            "level": sarif_level(rule_severity(rule_id)),
                            "message": { "text": record.observation.summary },
                            "locations": locations,
                            "properties": {
                                "observationId": record.observation.id,
                                "detectorId": record.observation.detector_id,
                                "detectorVersion": record.observation.detector_version,
                                "severity": rule_severity(rule_id).unwrap_or("unknown")
                            }
                        });
                        if let Some(rule_id) = &record.observation.rule_id {
                            result["ruleId"] = serde_json::json!(rule_id);
                        }
                        if let Some(suppression) = findings_by_observation
                            .get(record.observation.id.as_str())
                            .and_then(|finding| sarif_suppression(finding.review.as_ref()))
                        {
                            result["suppressions"] = serde_json::json!([suppression]);
                        }
                        result
                    })
                    .collect::<Vec<_>>();
            if data.run.kind == oxaudit_domain::RunKind::Dependencies {
                results.extend(dependencies::sarif_results(data)?);
            }
            if results.is_empty() {
                warnings.push("This run has no observations that map to SARIF.".into());
            }
            // `tool.driver.rules` is where a SARIF consumer finds what a rule
            // means and how to fix it. Emitting only the rules that fired keeps
            // the document proportional to the run.
            let fired: std::collections::BTreeSet<&str> = data
                .observations
                .iter()
                .filter_map(|record| record.observation.rule_id.as_deref())
                .collect();
            let rules = fired
                .iter()
                .filter_map(|id| sarif_rule(id))
                .collect::<Vec<_>>();
            serde_json::json!({
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": { "driver": {
                        "name": "oxAudit",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://github.com/HenryCooper86/oxAudit",
                        "rules": rules
                    } },
                    "results": results,
                    "invocations": [{"executionSuccessful": data.run.state == oxaudit_domain::RunState::Completed,
                        "toolExecutionNotifications": coverage_warnings(data).iter().map(|warning| serde_json::json!({
                            "level": "warning", "message": {"text": warning}})).collect::<Vec<_>>() }],
                    "properties": { "oxAuditRunId": data.run.id, "oxAuditRunState": data.run.state,
                        "oxAuditCoverageWarnings": coverage_warnings(data) }
                }]
            })
        }
        ReportFormat::CycloneDx => serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "version": 1,
            "metadata": { "tools": { "components": [{ "type": "application", "name": "oxAudit", "version": env!("CARGO_PKG_VERSION") }] }, "properties": lifecycle_properties(data) },
            "components": data.components.iter().map(cyclonedx_component).collect::<Vec<_>>(),

        }),
        ReportFormat::Spdx => serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": format!("oxAudit run {}", data.run.id.as_str()),
            "comment": lifecycle_text(data),
            "documentNamespace": format!("https://oxaudit.local/spdx/{}", uuid::Uuid::new_v4()),
            "creationInfo": { "creators": [format!("Tool: oxAudit-{}", env!("CARGO_PKG_VERSION"))], "created": chrono::Utc::now().to_rfc3339() },
            "packages": data.components.iter().enumerate().map(|(index, component)| {
                let mut package = serde_json::json!({
                    "SPDXID": format!("SPDXRef-Package-{index}"),
                    "name": component.name,
                    "supplier": component.supplier.as_ref().map(|supplier| format!("Organization: {supplier}")).unwrap_or_else(|| "NOASSERTION".into()),
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "externalRefs": component.purl.as_ref().map(|purl| vec![serde_json::json!({ "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": standard_purl(purl) })]).unwrap_or_default()
                });
                if let Some(version) = &component.version {
                    package["versionInfo"] = serde_json::json!(version);
                }
                // Declared license only when the lockfile stated one; absent
                // stays absent rather than asserting NOASSERTION per field.
                if let Some(license) = &component.license {
                    package["licenseDeclared"] = serde_json::json!(license);
                }
                package
            }).collect::<Vec<_>>()
        }),
        ReportFormat::OpenVex => {
            let statements = vex_statements(data);
            if statements.is_empty() {
                return Err("OpenVEX requires at least one advisory statement; no advisory observations are available for this run.".into());
            }
            serde_json::json!({
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": format!("https://oxaudit.local/vex/{}", data.run.id.as_str()),
                "author": "oxAudit local user",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "version": 1,
                "tooling": format!("oxAudit {}\n{}", env!("CARGO_PKG_VERSION"), lifecycle_text(data)),
                "statements": statements
            })
        }
        ReportFormat::CycloneDxVex => {
            let components = dependencies::ComponentIndex::new(data);
            let vulnerabilities = data.observations.iter().filter(|record| record.observation.kind == oxaudit_domain::ObservationKind::AdvisoryMatch).map(|record| serde_json::json!({
                "id": record.observation.rule_id.clone().unwrap_or_else(|| record.observation.title.clone()),
                "analysis": { "state": "exploitable", "detail": "Affected-range match observed by oxAudit; review status was not silently inferred." },
                "affects": components.affected_components(record).iter().map(|component| serde_json::json!({"ref": component.id.as_str()})).collect::<Vec<_>>(),
                "properties": [{ "name": "oxaudit:observationId", "value": record.observation.id.as_str() }]
            })).collect::<Vec<_>>();
            serde_json::json!({
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "version": 1,
                "metadata": {"properties": lifecycle_properties(data)},
                "components": data.components.iter().map(cyclonedx_component).collect::<Vec<_>>(),
                "vulnerabilities": vulnerabilities
            })
        }
        // Ticket CSVs return from generate before this JSON-shaped match.
        ReportFormat::GithubIssuesCsv | ReportFormat::JiraCsv => {
            unreachable!("ticket CSV formats never build a JSON value")
        }
    };
    preserve_inventory_metadata(data, format, &mut value, &mut warnings)?;
    validate(&value, format)?;
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    Ok(GeneratedReport { bytes, warnings })
}

// ----------------------------------------------------------------- ticketing

/// One CSV cell, quoted per RFC 4180 whenever it contains anything the
/// importer would otherwise split on. Descriptions are multi-line markdown,
/// so quoting is the norm here, not the exception.
fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// The shared body of a handed-off ticket: everything a triager needs
/// before opening the file, and the fingerprint that ties the ticket back
/// to this finding when it comes back as "fixed".
fn ticket_body(data: &ReportData, finding: &crate::models::Finding) -> String {
    format!(
        "**{severity}** — {rule}\n\n`{path}:{line}:{column}`\n\n{description}\n\n**Recommendation:** {recommendation}\n\n_Finding fingerprint `{fingerprint}` · oxAudit run `{run}`_\n\n{coverage}",
        severity = finding.severity,
        rule = finding.rule_id,
        path = finding.file_path,
        line = finding.line,
        column = finding.column,
        description = finding.description,
        recommendation = finding.recommendation,
        fingerprint = finding.fingerprint,
        run = data.run.id.as_str(),
        coverage = lifecycle_text(data),
    )
}

/// GitHub's issue importer expects exactly `title,description,labels`.
fn github_issues_row(data: &ReportData, finding: &crate::models::Finding) -> String {
    [
        csv_cell(&format!(
            "[{severity}] {title}",
            severity = finding.severity,
            title = finding.title
        )),
        csv_cell(&ticket_body(data, finding)),
        csv_cell(&format!(
            "security,oxaudit,{severity}",
            severity = finding.severity
        )),
    ]
    .join(",")
}

/// Jira's CSV importer maps columns onto fields by header name.
fn jira_priority(severity: &str) -> &'static str {
    match severity {
        "critical" => "Highest",
        "high" => "High",
        "medium" => "Medium",
        "low" | "info" => "Low",
        _ => "Medium",
    }
}

fn jira_row(data: &ReportData, finding: &crate::models::Finding) -> String {
    [
        csv_cell(&format!(
            "[{severity}] {title}",
            severity = finding.severity,
            title = finding.title
        )),
        csv_cell("Task"),
        csv_cell(&ticket_body(data, finding)),
        csv_cell(jira_priority(&finding.severity)),
        csv_cell("security,oxaudit"),
    ]
    .join(",")
}

/// Ticket handoff exports: one importable row per finding, for the two
/// trackers whose CSV import shapes are stable and documented (GitHub
/// Issues: `title,description,labels`; Jira: `Summary,Issue Type,
/// Description,Priority,Labels`). The structural contract is checked here
/// rather than in [`validate`], which is JSON-only: the header must be
/// exact and the row count must equal the finding count, so an importer
/// can never silently drop rows.
fn generate_ticket_csv(data: &ReportData, format: ReportFormat) -> Result<GeneratedReport, String> {
    if data.run.state != oxaudit_domain::RunState::Completed {
        return Err("Ticket CSV requires a completed run. Export retained partial evidence as oxAudit JSON or a standard report that preserves run state.".into());
    }
    let (header, row): (&str, fn(&ReportData, &crate::models::Finding) -> String) = match format {
        ReportFormat::GithubIssuesCsv => ("title,description,labels", github_issues_row),
        ReportFormat::JiraCsv => ("Summary,Issue Type,Description,Priority,Labels", jira_row),
        _ => unreachable!("caller checked the format is a ticket CSV"),
    };
    let mut warnings = coverage_warnings(data);
    if data.findings.is_empty() {
        warnings.push("This run has no findings to hand off; the CSV is header-only.".into());
    }
    let mut lines = vec![header.to_owned()];
    lines.extend(data.findings.iter().map(|finding| row(data, finding)));
    let text = lines.join("\r\n") + "\r\n";
    let body_rows = lines.len() - 1;
    if body_rows != data.findings.len() {
        return Err("ticket CSV failed its structural contract".into());
    }
    if !text.starts_with(header) {
        return Err("ticket CSV failed its structural contract".into());
    }
    Ok(GeneratedReport {
        bytes: text.into_bytes(),
        warnings,
    })
}

// Older canonical inventories used `pkg/` as the package URL prefix.
// Export that known representation using the standard URI scheme without
// rewriting retained evidence or inventing identities from component names.
fn standard_purl(purl: &str) -> String {
    purl.strip_prefix("pkg/")
        .map(|rest| format!("pkg:{rest}"))
        .unwrap_or_else(|| purl.to_owned())
}

pub(super) fn sarif_artifact_uri(path: &str) -> String {
    const PATH: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'/')
        .remove(b'.')
        .remove(b'-')
        .remove(b'_')
        .remove(b'~')
        .remove(b':')
        .remove(b'!')
        .remove(b'$')
        .remove(b'&')
        .remove(b'\'')
        .remove(b'(')
        .remove(b')')
        .remove(b'*')
        .remove(b'+')
        .remove(b',')
        .remove(b';')
        .remove(b'=')
        .remove(b'@');
    percent_encoding::utf8_percent_encode(path, PATH).to_string()
}

fn cyclonedx_component(component: &Component) -> serde_json::Value {
    let mut value = serde_json::json!({
        "type": "library",
        "bom-ref": component.id.as_str(),
        "name": component.name,
        "properties": [{ "name": "oxaudit:identityConfidence", "value": component.identities.iter().map(|identity| identity.confidence).fold(0.0_f32, f32::max).to_string() }]
    });
    // Optional CycloneDX fields accept their declared type, never JSON null.
    if let Some(version) = &component.version {
        value["version"] = serde_json::json!(version);
    }
    if let Some(supplier) = &component.supplier {
        value["supplier"] = serde_json::json!({ "name": supplier });
    }
    if let Some(purl) = &component.purl {
        value["purl"] = serde_json::json!(standard_purl(purl));
    }
    if let Some(cpe) = component.cpes.first() {
        value["cpe"] = serde_json::json!(cpe);
    }
    // Unknown licenses are omitted, not null — an absent field reads as
    // unknown; a null array would not.
    if let Some(license) = &component.license {
        value["licenses"] = serde_json::json!([{ "license": { "name": license } }]);
    }
    value
}

/// Restore source-format license details that exceed the canonical summary,
/// and translate graph IDs only after checking that every edge is resolvable.
fn preserve_inventory_metadata(
    data: &ReportData,
    format: ReportFormat,
    value: &mut serde_json::Value,
    warnings: &mut Vec<String>,
) -> Result<(), String> {
    let target = match format {
        ReportFormat::CycloneDx | ReportFormat::CycloneDxVex => "cyclonedx",
        ReportFormat::Spdx => "spdx",
        _ => return Ok(()),
    };
    let indices = data
        .components
        .iter()
        .enumerate()
        .map(|(index, component)| (component.id.as_str(), index))
        .collect::<std::collections::HashMap<_, _>>();
    if indices.len() != data.components.len() {
        return Err("Cannot export inventory with duplicate component IDs.".into());
    }
    let mut relationships = Vec::new();
    for (index, component) in data.components.iter().enumerate() {
        for dependency in &component.depends_on {
            let dependency_index = indices.get(dependency.as_str()).ok_or_else(|| {
                format!(
                    "Cannot export unresolved dependency from {} to {dependency}.",
                    component.id
                )
            })?;
            relationships.push(serde_json::json!({
                "spdxElementId": format!("SPDXRef-Package-{index}"),
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": format!("SPDXRef-Package-{dependency_index}"),
            }));
        }
    }
    if target == "spdx" {
        value["relationships"] = serde_json::json!(relationships);
    } else {
        value["dependencies"] = serde_json::json!(data.components.iter()
            .filter(|component| !component.depends_on.is_empty())
            .map(|component| serde_json::json!({"ref": component.id.as_str(), "dependsOn": component.depends_on}))
            .collect::<Vec<_>>());
    }
    let Some(projection) = &data.projection else {
        return Ok(());
    };
    let source = projection
        .get("sourceLicenseFormat")
        .and_then(serde_json::Value::as_str);
    let entries = projection
        .get("componentMetadata")
        .and_then(serde_json::Value::as_array);
    if source == Some(target) {
        if target == "spdx" {
            for field in ["hasExtractedLicensingInfos", "externalDocumentRefs"] {
                if let Some(original) = projection.get(field).filter(|v| !v.is_null()) {
                    value[field] = original.clone();
                }
            }
        }
        for entry in entries.into_iter().flatten() {
            let Some(index) = entry
                .get("componentId")
                .and_then(serde_json::Value::as_str)
                .and_then(|id| indices.get(id))
            else {
                continue;
            };
            let fields: &[&str] = if target == "cyclonedx" {
                &["licenses"]
            } else {
                &[
                    "licenseDeclared",
                    "licenseConcluded",
                    "licenseInfoFromFiles",
                    "licenseComments",
                    "copyrightText",
                    "attributionTexts",
                ]
            };
            let destination = if target == "cyclonedx" {
                &mut value["components"][*index]
            } else {
                &mut value["packages"][*index]
            };
            for field in fields {
                if let Some(original) = entry.get(*field) {
                    destination[*field] = original.clone();
                }
            }
        }
    } else if source.is_some_and(|source| source != "oxaudit-json")
        && (entries.into_iter().flatten().any(|entry| {
            entry.as_object().is_some_and(|object| {
                object
                    .keys()
                    .any(|key| !matches!(key.as_str(), "componentId" | "sourceRef"))
            })
        }) || projection
            .get("hasExtractedLicensingInfos")
            .is_some_and(|v| v.as_array().is_some_and(|v| !v.is_empty())))
    {
        warnings.push(format!("Imported {} license metadata cannot be represented completely in {target}; only canonical license summaries are exported. Export the original format to retain full license records.", source.unwrap_or("source")));
    }
    Ok(())
}

fn vex_statements(data: &ReportData) -> Vec<serde_json::Value> {
    let components = dependencies::ComponentIndex::new(data);
    data.observations
        .iter()
        .filter(|record| record.observation.kind == oxaudit_domain::ObservationKind::AdvisoryMatch)
        .map(|record| serde_json::json!({
            "@id": format!("https://oxaudit.local/vex/{}/statements/{}", data.run.id, record.observation.id),
            "vulnerability": { "name": record.observation.rule_id.clone().unwrap_or_else(|| record.observation.title.clone()) },
            "products": components.affected_components(record).iter().map(|component| serde_json::json!({ "@id": component.purl.as_deref().map(standard_purl).unwrap_or_else(|| format!("urn:oxaudit:component:{}", component.id)) })).collect::<Vec<_>>(),
            "status": "affected",
            "action_statement": "Review the affected-range match and the advisory's remediation guidance before selecting an upgrade or mitigation; oxAudit has not verified a remediation.",
            "status_notes": "Affected-range match observed; no analyst disposition was inferred."
        }))
        .collect()
}

fn validate(value: &serde_json::Value, format: ReportFormat) -> Result<(), String> {
    let valid = match format {
        // Ticket CSVs carry their own structural check in generate_ticket_csv.
        ReportFormat::GithubIssuesCsv | ReportFormat::JiraCsv => true,
        ReportFormat::OxAuditJson => {
            value.get("schemaVersion") == Some(&serde_json::json!(1)) && value.get("run").is_some()
        }
        ReportFormat::Sarif
        | ReportFormat::CycloneDx
        | ReportFormat::CycloneDxVex
        | ReportFormat::Spdx
        | ReportFormat::OpenVex => return schema::validate(value, format),
    };
    valid
        .then_some(())
        .ok_or_else(|| "generated report failed its structural contract".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxaudit_domain::{RunKind, RunState};

    fn completed_run() -> Run {
        let mut run = Run::queued(RunKind::Source, "/fixture", 1);
        for (index, state) in [
            RunState::Discovering,
            RunState::Detecting,
            RunState::Normalizing,
            RunState::Enriching,
            RunState::Assessing,
            RunState::Persisting,
            RunState::Completed,
        ]
        .into_iter()
        .enumerate()
        {
            run.transition(state, index as u64 + 2).unwrap();
        }
        run
    }

    #[test]
    fn partial_standard_reports_preserve_lifecycle_and_coverage() {
        for terminal in [RunState::Failed, RunState::Cancelled, RunState::Incomplete] {
            let mut run = Run::queued(RunKind::History, "/fixture", 1);
            if terminal == RunState::Cancelled {
                run.transition(RunState::Cancelling, 2).unwrap();
            }
            run.transition(terminal, 3).unwrap();
            run.warnings.push(oxaudit_domain::RunWarning {
                code: "history_coverage".into(),
                message: "Some blobs were not inspected.".into(),
            });
            let mut data = advisory_report();
            data.run = run;
            let state = serde_json::to_value(terminal).unwrap();
            for format in [
                ReportFormat::Sarif,
                ReportFormat::CycloneDx,
                ReportFormat::CycloneDxVex,
                ReportFormat::Spdx,
                ReportFormat::OpenVex,
            ] {
                let report = generate(&data, format).unwrap();
                assert!(report
                    .warnings
                    .iter()
                    .any(|warning| warning.contains("not completed")));
                let value: serde_json::Value = serde_json::from_slice(&report.bytes).unwrap();
                match format {
                    ReportFormat::Sarif => {
                        assert_eq!(
                            value["runs"][0]["invocations"][0]["executionSuccessful"],
                            false
                        );
                        assert_eq!(value["runs"][0]["properties"]["oxAuditRunState"], state);
                        assert!(
                            value["runs"][0]["invocations"][0]["toolExecutionNotifications"]
                                .to_string()
                                .contains("Some blobs were not inspected.")
                        );
                    }
                    ReportFormat::CycloneDx | ReportFormat::CycloneDxVex => {
                        let properties = value["metadata"]["properties"].as_array().unwrap();
                        assert!(properties
                            .iter()
                            .any(|entry| entry["name"] == "oxaudit:runState"
                                && entry["value"] == state));
                        assert!(properties.to_vec().iter().any(|entry| entry["value"]
                            .as_str()
                            .is_some_and(|text| text.contains("Some blobs were not inspected."))));
                    }
                    ReportFormat::Spdx => assert!(value["comment"]
                        .as_str()
                        .unwrap()
                        .contains("Some blobs were not inspected.")),
                    ReportFormat::OpenVex => assert!(value["tooling"]
                        .as_str()
                        .unwrap()
                        .contains("Some blobs were not inspected.")),
                    _ => unreachable!(),
                }
            }
            for format in [ReportFormat::GithubIssuesCsv, ReportFormat::JiraCsv] {
                assert!(
                    generate(&data, format).is_err(),
                    "partial empty CSV must not look clean"
                );
            }
        }
    }

    #[test]
    fn completed_reports_keep_coverage_warnings_without_marking_execution_failed() {
        let mut run = completed_run();
        run.warnings.push(oxaudit_domain::RunWarning {
            code: "offline".into(),
            message: "Advisory coverage unavailable offline.".into(),
        });
        let data = ReportData {
            run,
            artifacts: Vec::new(),
            components: Vec::new(),
            observations: Vec::new(),
            findings: Vec::new(),
            projection: None,
        };
        let report = generate(&data, ReportFormat::Sarif).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&report.bytes).unwrap();
        assert_eq!(
            value["runs"][0]["invocations"][0]["executionSuccessful"],
            true
        );
        assert!(value["runs"][0]["properties"]["oxAuditCoverageWarnings"]
            .to_string()
            .contains("Advisory coverage unavailable offline."));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("Advisory coverage unavailable offline.")));
    }

    #[test]
    fn cyclonedx_optional_component_fields_are_omitted_when_unknown() {
        let mut component = Component {
            id: oxaudit_domain::ComponentId::parse("component_minimal").unwrap(),
            name: "minimal".into(),
            version: None,
            supplier: None,
            ecosystem: None,
            purl: None,
            cpes: Vec::new(),
            aliases: Vec::new(),
            identities: Vec::new(),
            depends_on: Vec::new(),
            license: None,
        };
        let data = ReportData {
            run: completed_run(),
            artifacts: Vec::new(),
            components: vec![component.clone()],
            observations: Vec::new(),
            findings: Vec::new(),
            projection: None,
        };
        for format in [ReportFormat::CycloneDx, ReportFormat::CycloneDxVex] {
            let report: serde_json::Value =
                serde_json::from_slice(&generate(&data, format).unwrap().bytes).unwrap();
            for field in ["version", "supplier", "purl", "cpe"] {
                assert!(
                    report["components"][0].get(field).is_none(),
                    "unknown {field} must be omitted, not null"
                );
            }
        }
        component.version = Some("1".into());
        component.supplier = Some("Example".into());
        component.purl = Some("pkg:generic/minimal@1".into());
        component
            .cpes
            .push("cpe:2.3:a:example:minimal:1:*:*:*:*:*:*:*".into());
        let value = cyclonedx_component(&component);
        assert_eq!(value["version"], "1");
        assert_eq!(value["supplier"]["name"], "Example");
        assert_eq!(value["purl"], "pkg:generic/minimal@1");
        assert_eq!(value["cpe"], "cpe:2.3:a:example:minimal:1:*:*:*:*:*:*:*");
    }

    #[test]
    fn spdx_retains_coverage_in_the_standard_document_comment_field() {
        let mut data = ReportData {
            run: completed_run(),
            artifacts: Vec::new(),
            components: Vec::new(),
            observations: Vec::new(),
            findings: Vec::new(),
            projection: None,
        };
        data.run.warnings.push(oxaudit_domain::RunWarning {
            code: "provider-unavailable".into(),
            message: "Advisory coverage unavailable offline.".into(),
        });
        let report: serde_json::Value =
            serde_json::from_slice(&generate(&data, ReportFormat::Spdx).unwrap().bytes).unwrap();
        assert!(report["comment"]
            .as_str()
            .is_some_and(|comment| comment.contains("Advisory coverage unavailable offline.")));
        assert!(report.get("documentComment").is_none());
    }

    #[test]
    fn spdx_omits_unknown_package_versions_and_preserves_known_versions() {
        let mut data = ReportData {
            run: completed_run(),
            artifacts: Vec::new(),
            components: vec![Component {
                id: oxaudit_domain::ComponentId::parse("component_spdx_minimal").unwrap(),
                name: "minimal".into(),
                version: None,
                supplier: None,
                ecosystem: None,
                purl: None,
                cpes: Vec::new(),
                aliases: Vec::new(),
                identities: Vec::new(),
                depends_on: Vec::new(),
                license: None,
            }],
            observations: Vec::new(),
            findings: Vec::new(),
            projection: None,
        };
        let report: serde_json::Value =
            serde_json::from_slice(&generate(&data, ReportFormat::Spdx).unwrap().bytes).unwrap();
        assert!(report["packages"][0].get("versionInfo").is_none());
        data.components[0].version = Some("1.2.3".into());
        let report: serde_json::Value =
            serde_json::from_slice(&generate(&data, ReportFormat::Spdx).unwrap().bytes).unwrap();
        assert_eq!(report["packages"][0]["versionInfo"], "1.2.3");
    }

    fn advisory_report() -> ReportData {
        use oxaudit_domain::*;
        let run = completed_run();
        let component = Component {
            id: ComponentId::parse("component_example").unwrap(),
            name: "example".into(),
            version: Some("1.0".into()),
            supplier: Some("Example".into()),
            ecosystem: None,
            purl: Some("pkg:generic/example@1.0".into()),
            cpes: vec![],
            aliases: vec![],
            identities: vec![],
            depends_on: vec![],
            license: Some("MIT".into()),
        };
        let evidence = EvidenceRecord {
            id: EvidenceId::parse("evidence_advisory").unwrap(),
            evidence: Evidence::AdvisoryMatch(AdvisoryMatchEvidence {
                install_path: None,
                component_id: component.id.clone(),
                provider_snapshot_id: ProviderSnapshotId::parse("provider_fixture").unwrap(),
                advisory_id: "CVE-2026-1234".into(),
                affected: true,
                rationale: "affected range".into(),
            }),
        };
        let observation = Observation {
            id: ObservationId::parse("observation_advisory").unwrap(),
            run_id: run.id.clone(),
            artifact_id: ArtifactId::parse("artifact_fixture").unwrap(),
            kind: ObservationKind::AdvisoryMatch,
            detector_id: "fixture".into(),
            detector_version: "1".into(),
            rule_id: Some("CVE-2026-1234".into()),
            title: "advisory".into(),
            summary: "affected range".into(),
            evidence_ids: vec![evidence.id.clone()],
        };
        ReportData {
            run,
            components: vec![component],
            observations: vec![ObservationRecord {
                observation,
                evidence: vec![evidence],
            }],
            artifacts: vec![],
            findings: vec![],
            projection: None,
        }
    }

    #[test]
    fn openvex_without_advisories_is_rejected_instead_of_emitting_invalid_empty_statements() {
        let mut data = advisory_report();
        data.observations.clear();
        assert!(generate(&data, ReportFormat::OpenVex).is_err());
    }

    #[test]
    fn same_format_exports_restore_complete_imported_license_records() {
        let mut data = advisory_report();
        let licenses = serde_json::json!([
            {"license":{"id":"MIT", "url":"https://opensource.org/license/mit"}},
            {"license":{"name":"Example Commercial License", "text":{"content":"Full license text"}}}
        ]);
        data.projection = Some(
            serde_json::json!({"sourceLicenseFormat":"cyclonedx", "componentMetadata":[{"componentId":"component_example", "licenses":licenses}]}),
        );
        let output = generate(&data, ReportFormat::CycloneDx).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        assert_eq!(value["components"][0]["licenses"], licenses);
        let cross_format = generate(&data, ReportFormat::Spdx).unwrap();
        assert!(cross_format
            .warnings
            .iter()
            .any(|warning| warning.contains("license")));

        let extracted = serde_json::json!([{"licenseId":"LicenseRef-Example", "extractedText":"Example license", "name":"Example"}]);
        data.projection = Some(
            serde_json::json!({"sourceLicenseFormat":"spdx", "hasExtractedLicensingInfos":extracted,
            "componentMetadata":[{"componentId":"component_example", "licenseDeclared":"MIT", "licenseConcluded":"LicenseRef-Example", "licenseComments":"Reviewed by supplier", "copyrightText":"Copyright Example"}]}),
        );
        let output = generate(&data, ReportFormat::Spdx).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        assert_eq!(value["packages"][0]["licenseDeclared"], "MIT");
        assert_eq!(
            value["packages"][0]["licenseConcluded"],
            "LicenseRef-Example"
        );
        assert_eq!(
            value["packages"][0]["licenseComments"],
            "Reviewed by supplier"
        );
        assert_eq!(value["packages"][0]["copyrightText"], "Copyright Example");
        assert_eq!(value["hasExtractedLicensingInfos"], extracted);
        assert!(generate(&data, ReportFormat::CycloneDx)
            .unwrap()
            .warnings
            .iter()
            .any(|warning| warning.contains("license")));
    }

    #[test]
    fn spdx_dependencies_reference_exported_package_ids_and_reject_dangling_edges() {
        let mut data = advisory_report();
        let mut child = data.components[0].clone();
        child.id = oxaudit_domain::ComponentId::parse("component_child").unwrap();
        child.name = "child".into();
        data.components[0].depends_on.push(child.id.to_string());
        data.components.push(child);
        let output = generate(&data, ReportFormat::Spdx).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        assert!(value["relationships"].as_array().unwrap().contains(&serde_json::json!({
            "spdxElementId":"SPDXRef-Package-0", "relationshipType":"DEPENDS_ON", "relatedSpdxElement":"SPDXRef-Package-1"
        })));
        for format in [ReportFormat::CycloneDx, ReportFormat::CycloneDxVex] {
            let output = generate(&data, format).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
            assert_eq!(
                value["dependencies"],
                serde_json::json!([{"ref":"component_example", "dependsOn":["component_child"]}])
            );
        }
        data.components.pop();
        assert!(generate(&data, ReportFormat::Spdx).is_err());
        assert!(generate(&data, ReportFormat::CycloneDx).is_err());
    }

    #[test]
    fn sarif_encodes_paths_as_uri_references() {
        let mut data = advisory_report();
        data.observations[0].observation.kind = oxaudit_domain::ObservationKind::SourceWeakness;
        data.observations[0].evidence[0].evidence =
            Evidence::FileLocation(oxaudit_domain::FileLocationEvidence {
                artifact_id: data.observations[0].observation.artifact_id.clone(),
                normalized_path: "src/my file#1.ts".into(),
                start_line: Some(5),
                start_column: Some(2),
                end_line: None,
                end_column: None,
                context_sha256: None,
            });
        let output = generate(&data, ReportFormat::Sarif).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        assert_eq!(
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/my%20file%231.ts"
        );
    }

    #[test]
    fn sarif_omits_absent_rule_ids_instead_of_emitting_null() {
        let mut data = advisory_report();
        data.observations[0].observation.kind = oxaudit_domain::ObservationKind::SourceWeakness;
        data.observations[0].observation.rule_id = None;
        let output = generate(&data, ReportFormat::Sarif).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&output.bytes).unwrap();
        assert!(value["runs"][0]["results"][0].get("ruleId").is_none());
    }

    #[test]
    fn schemas_reject_malformed_nested_records() {
        let cases = [
            (
                ReportFormat::Sarif,
                serde_json::json!({"version":"2.1.0","runs":[{"tool":{"driver":{"name":"oxAudit"}},"results":[{"message":{"text":42}}]}]}),
            ),
            (
                ReportFormat::CycloneDx,
                serde_json::json!({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"example","hashes":[{"alg":"SHA-256","content":12}]}]}),
            ),
            (
                ReportFormat::CycloneDxVex,
                serde_json::json!({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"vulnerabilities":[{"id":"CVE-2026-1234","analysis":{"state":"made-up"}}]}),
            ),
            (
                ReportFormat::Spdx,
                serde_json::json!({"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","SPDXID":"SPDXRef-DOCUMENT","name":"fixture","documentNamespace":"https://example.com/spdx/fixture","creationInfo":{"creators":["Tool: oxAudit"],"created":"2026-10-28T00:00:00Z"},"packages":[{"SPDXID":"SPDXRef-Package","name":"example","downloadLocation":"NOASSERTION","externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":42}]}]}),
            ),
            (
                ReportFormat::OpenVex,
                serde_json::json!({"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/1","author":"oxAudit","timestamp":"2026-10-28T00:00:00Z","version":1,"statements":[{"vulnerability":{"name":"CVE-2026-1234"},"products":[{"@id":42}],"status":"affected","action_statement":"Review the advisory."}]}),
            ),
        ];
        for (format, value) in cases {
            assert!(
                validate(&value, format).is_err(),
                "{format:?} accepted malformed nested evidence"
            );
        }
    }

    #[test]
    fn every_standard_writer_produces_structurally_valid_json() {
        let mut data = advisory_report();
        let mut source = data.observations[0].clone();
        source.observation.id = oxaudit_domain::ObservationId::parse("observation_source").unwrap();
        source.observation.kind = oxaudit_domain::ObservationKind::SourceWeakness;
        source.observation.rule_id = Some("js-eval".into());
        source.observation.summary = "Untrusted input reaches eval".into();
        source.evidence.clear();
        source.observation.evidence_ids.clear();
        data.observations.push(source);
        for format in [
            ReportFormat::OxAuditJson,
            ReportFormat::Sarif,
            ReportFormat::CycloneDx,
            ReportFormat::Spdx,
            ReportFormat::OpenVex,
            ReportFormat::CycloneDxVex,
        ] {
            let report = generate(&data, format).expect("generate report");
            serde_json::from_slice::<serde_json::Value>(&report.bytes).expect("valid JSON");
        }
    }

    fn ticket_fixture() -> ReportData {
        let mut data = ReportData {
            run: completed_run(),
            artifacts: Vec::new(),
            components: Vec::new(),
            observations: Vec::new(),
            findings: vec![crate::models::Finding {
                id: "finding-1".into(),
                category: "vulnerability".into(),
                rule_id: "js-eval".into(),
                rule_name: "eval() of dynamic input".into(),
                severity: "high".into(),
                title: "eval() with attacker-influenced input".into(),
                description: "The input reaches eval(), \"quoted\", with a comma, and\na newline."
                    .into(),
                file_path: "src/render.js".into(),
                line: 42,
                column: 9,
                match_text: "eval(input)".into(),
                context: "eval(input)".into(),
                language: "javascript".into(),
                cwe: Some("CWE-95".into()),
                cwe_exploited: false,
                cwe_exploited_count: 0,
                recommendation: "Parse, don't evaluate.".into(),
                entropy: None,
                verified: None,
                analysis: Default::default(),
                analysis_gates: Vec::new(),
                observation_run_id: String::new(),
                resolved_by_run_id: None,
                fingerprint_version: 1,
                fingerprint: "fingerprint-1".into(),
                in_test_region: false,
                scope: None,
                scope_reason: None,
                review: None,
                review_history: Vec::new(),
                diff_status: None,
            }],
            projection: None,
        };
        data.findings.push(crate::models::Finding {
            id: "finding-2".into(),
            severity: "critical".into(),
            title: "Leaked credential".into(),
            rule_id: "github-token".into(),
            description: "A token was committed.".into(),
            recommendation: "Rotate the token.".into(),
            fingerprint: "fingerprint-2".into(),
            ..data.findings[0].clone()
        });
        data
    }

    /// RFC 4180: the quote inside the description doubles, the commas and
    /// newlines sit inside one quoted cell, and the importer sees one row
    /// per finding — not one row per line of description.
    #[test]
    fn github_issues_csv_matches_the_importer_shape_and_escapes_cells() {
        let report = generate(&ticket_fixture(), ReportFormat::GithubIssuesCsv)
            .expect("generate github csv");
        let text = String::from_utf8(report.bytes).unwrap();
        let mut lines = text.split("\r\n");
        assert_eq!(lines.next(), Some("title,description,labels"));
        let rows: Vec<&str> = lines
            .collect::<Vec<_>>()
            .iter()
            .filter(|line| !line.is_empty())
            .copied()
            .collect();
        assert_eq!(rows.len(), 2, "one row per finding");
        assert!(rows[0].starts_with("[high] eval() with attacker-influenced input,\"**high**"));
        assert!(rows[0].contains("\"\"quoted\"\""), "inner quotes double");
        assert!(rows[0].ends_with("\"security,oxaudit,high\""));
        assert!(rows[1].ends_with("\"security,oxaudit,critical\""));
        assert!(
            text.contains("fingerprint-1"),
            "tickets carry the fingerprint"
        );
    }

    #[test]
    fn jira_csv_maps_priority_and_keeps_its_five_columns() {
        let report = generate(&ticket_fixture(), ReportFormat::JiraCsv).expect("generate jira csv");
        let text = String::from_utf8(report.bytes).unwrap();
        let mut lines = text.split("\r\n");
        assert_eq!(
            lines.next(),
            Some("Summary,Issue Type,Description,Priority,Labels")
        );
        let rows: Vec<&str> = lines
            .collect::<Vec<_>>()
            .iter()
            .filter(|line| !line.is_empty())
            .copied()
            .collect();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].contains(",High,\"security,oxaudit\""));
        assert!(rows[1].contains(",Highest,"), "critical maps to Highest");
        assert!(rows[0].contains(",Task,"));
    }

    #[test]
    fn a_run_without_findings_hands_off_an_honest_header_only_csv() {
        let data = ReportData {
            run: completed_run(),
            artifacts: Vec::new(),
            components: Vec::new(),
            observations: Vec::new(),
            findings: Vec::new(),
            projection: None,
        };
        for format in [ReportFormat::GithubIssuesCsv, ReportFormat::JiraCsv] {
            let report = generate(&data, format).expect("generate empty csv");
            assert_eq!(
                report.warnings,
                vec!["This run has no findings to hand off; the CSV is header-only.".to_owned()]
            );
            let text = String::from_utf8(report.bytes).unwrap();
            assert_eq!(text.lines().count(), 1, "header only");
        }
    }

    #[test]
    fn ticket_formats_parse_and_carry_csv_metadata() {
        assert_eq!(
            ReportFormat::parse("github-issues-csv").unwrap(),
            ReportFormat::GithubIssuesCsv
        );
        assert_eq!(
            ReportFormat::parse("jira-csv").unwrap(),
            ReportFormat::JiraCsv
        );
        assert_eq!(ReportFormat::GithubIssuesCsv.media_type(), "text/csv");
        assert_eq!(ReportFormat::GithubIssuesCsv.suffix(), "github-issues.csv");
        assert_eq!(ReportFormat::JiraCsv.suffix(), "jira.csv");
        assert!(ReportFormat::parse("github-csv").is_err());
    }

    #[test]
    fn csv_cells_quote_only_what_requires_it() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("with,comma"), "\"with,comma\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
    }
}

/// The severity a rule carries in the catalogue that defines it.
///
/// The canonical `Observation` deliberately records what was seen rather than
/// how bad it is; severity is a property of the rule. Reading it back here is
/// what lets a SARIF consumer rank findings without oxAudit inventing a second
/// source of truth for it.
fn rule_severity(rule_id: Option<&str>) -> Option<&'static str> {
    let rule_id = rule_id?;
    if let Some(rule) = crate::scanners::patterns::SOURCE_RULES
        .iter()
        .find(|rule| rule.id == rule_id)
    {
        return Some(rule.severity);
    }
    crate::scanners::secrets::SECRET_RULES
        .iter()
        .find(|rule| rule.id == rule_id)
        .map(|rule| rule.severity)
}

/// Map oxAudit's five-step severity onto SARIF's three levels.
///
/// SARIF has no "critical", so critical and high both become `error`. Losing
/// that distinction in `level` is why the original severity is also carried in
/// `properties.severity`.
pub(crate) fn sarif_level(severity: Option<&str>) -> &'static str {
    match severity {
        Some("critical") | Some("high") => "error",
        Some("medium") | Some("low") => "warning",
        Some("info") => "note",
        _ => "warning",
    }
}

fn sarif_suppression(
    review: Option<&crate::findings::domain::ReviewRecord>,
) -> Option<serde_json::Value> {
    use crate::findings::domain::ReviewState;

    let review = review?;
    if !matches!(
        review.state,
        ReviewState::FalsePositive | ReviewState::AcceptedRisk | ReviewState::Suppressed
    ) {
        return None;
    }
    Some(serde_json::json!({
        "kind": "external",
        "status": "accepted",
        "justification": review.reason,
    }))
}

/// A `reportingDescriptor` for one rule: what it detects and how to fix it.
fn sarif_rule(rule_id: &str) -> Option<serde_json::Value> {
    if let Some(rule) = crate::scanners::patterns::SOURCE_RULES
        .iter()
        .find(|rule| rule.id == rule_id)
    {
        let mut tags = vec!["security".to_string()];
        if !rule.cwe.is_empty() {
            tags.push(rule.cwe.to_string());
        }
        for language in rule.languages {
            tags.push((*language).to_string());
        }
        return Some(serde_json::json!({
            "id": rule.id,
            "name": rule.name,
            "shortDescription": { "text": rule.name },
            "fullDescription": { "text": rule.message },
            "help": { "text": rule.recommendation },
            "defaultConfiguration": { "level": sarif_level(Some(rule.severity)) },
            "properties": {
                "severity": rule.severity,
                "tags": tags,
                "problem.severity": rule.severity,
                "cwe": rule.cwe
            }
        }));
    }
    crate::scanners::secrets::SECRET_RULES
        .iter()
        .find(|rule| rule.id == rule_id)
        .map(|rule| {
            serde_json::json!({
                "id": rule.id,
                "name": rule.name,
                "shortDescription": { "text": rule.name },
                "fullDescription": { "text": rule.description },
                "help": { "text": rule.recommendation },
                "defaultConfiguration": { "level": sarif_level(Some(rule.severity)) },
                "properties": {
                    "severity": rule.severity,
                    "tags": ["security", "secret", "CWE-798"],
                    "problem.severity": rule.severity,
                    "cwe": "CWE-798"
                }
            })
        })
}

#[cfg(test)]
mod sarif_metadata_tests {
    use super::{rule_severity, sarif_level, sarif_rule, sarif_suppression};
    use crate::findings::domain::{ReviewOrigin, ReviewRecord, ReviewState};

    #[test]
    fn severity_is_read_from_the_rule_that_defines_it() {
        // A canonical Observation records what was seen, not how bad it is.
        // SARIF consumers rank by severity, so it has to come from somewhere.
        assert_eq!(rule_severity(Some("js-eval")), Some("high"));
        assert_eq!(rule_severity(Some("go-weak-hash")), Some("medium"));
    }

    #[test]
    fn secret_rules_resolve_as_well_as_source_rules() {
        assert!(rule_severity(Some("generic-api-key")).is_some());
    }

    #[test]
    fn an_unknown_rule_has_no_severity_rather_than_a_guessed_one() {
        assert_eq!(rule_severity(Some("not-a-rule")), None);
        assert_eq!(rule_severity(None), None);
    }

    #[test]
    fn severity_maps_onto_the_three_levels_sarif_actually_has() {
        assert_eq!(sarif_level(Some("critical")), "error");
        assert_eq!(sarif_level(Some("high")), "error");
        assert_eq!(sarif_level(Some("medium")), "warning");
        assert_eq!(sarif_level(Some("low")), "warning");
        assert_eq!(sarif_level(Some("info")), "note");
    }

    #[test]
    fn an_unrankable_finding_defaults_to_warning_not_error() {
        // Defaulting unknown to `error` would fail builds over a metadata gap.
        assert_eq!(sarif_level(None), "warning");
        assert_eq!(sarif_level(Some("nonsense")), "warning");
    }

    #[test]
    fn a_rule_descriptor_carries_what_a_reviewer_needs() {
        let rule = sarif_rule("py-subprocess-shell").expect("rule exists");
        assert_eq!(rule["id"], "py-subprocess-shell");
        assert!(rule["fullDescription"]["text"]
            .as_str()
            .is_some_and(|t| !t.is_empty()));
        // Without remediation text a SARIF alert tells a reviewer that
        // something is wrong and nothing about what to do next.
        assert!(rule["help"]["text"].as_str().is_some_and(|t| !t.is_empty()));
        assert_eq!(rule["defaultConfiguration"]["level"], "error");
        assert_eq!(rule["properties"]["cwe"], "CWE-78");
        let tags = rule["properties"]["tags"].as_array().expect("tags");
        assert!(tags.iter().any(|tag| tag == "CWE-78"));
        assert!(tags.iter().any(|tag| tag == "security"));
    }

    #[test]
    fn every_catalogued_rule_can_describe_itself() {
        // A rule that fires but has no descriptor shows up in a SARIF viewer as
        // a bare identifier with no explanation.
        for rule in crate::scanners::patterns::SOURCE_RULES.iter() {
            assert!(
                sarif_rule(rule.id).is_some(),
                "{} has no descriptor",
                rule.id
            );
        }
        for rule in crate::scanners::secrets::SECRET_RULES.iter() {
            assert!(
                sarif_rule(rule.id).is_some(),
                "{} has no descriptor",
                rule.id
            );
        }
    }

    #[test]
    fn an_unknown_rule_yields_no_descriptor() {
        assert!(sarif_rule("not-a-rule").is_none());
    }

    #[test]
    fn reviewed_dismissals_become_external_sarif_suppressions() {
        let mut review = ReviewRecord {
            id: "review-1".into(),
            project_id: "project-1".into(),
            fingerprint_version: 1,
            fingerprint: "fingerprint-1".into(),
            state: ReviewState::Suppressed,
            reason: "Reviewed fixture".into(),
            evidence: None,
            entry_point: None,
            data_flow: None,
            gates: Vec::new(),
            deciding_gate: None,
            expires_at: None,
            origin: ReviewOrigin::ProjectPolicy,
            policy_hash: Some("policy-hash".into()),
            updated_at: "2026-08-31T00:00:00Z".into(),
            superseded_at: None,
        };

        let suppression = sarif_suppression(Some(&review)).expect("dismissal is represented");
        assert_eq!(suppression["kind"], "external");
        assert_eq!(suppression["status"], "accepted");
        assert_eq!(suppression["justification"], "Reviewed fixture");

        review.state = ReviewState::Confirmed;
        assert!(sarif_suppression(Some(&review)).is_none());
        assert!(sarif_suppression(None).is_none());
    }
}
