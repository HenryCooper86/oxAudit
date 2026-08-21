use oxaudit_application::ObservationRecord;
use oxaudit_domain::{Artifact, Component, Evidence, Run};

pub mod compliance;
pub mod import;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    OxAuditJson,
    Sarif,
    CycloneDx,
    Spdx,
    OpenVex,
    CycloneDxVex,
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
        }
    }
}

pub struct ReportData {
    pub run: Run,
    pub artifacts: Vec<Artifact>,
    pub components: Vec<Component>,
    pub observations: Vec<ObservationRecord>,
    pub projection: Option<serde_json::Value>,
}

pub struct GeneratedReport {
    pub bytes: Vec<u8>,
    pub warnings: Vec<String>,
}

pub fn generate(data: &ReportData, format: ReportFormat) -> Result<GeneratedReport, String> {
    let mut warnings = Vec::new();
    let value = match format {
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
            let applicable = data.observations.iter().filter(|record| {
                matches!(
                    record.observation.kind,
                    oxaudit_domain::ObservationKind::SourceWeakness
                        | oxaudit_domain::ObservationKind::SecretCandidate
                        | oxaudit_domain::ObservationKind::PolicyConcern
                        | oxaudit_domain::ObservationKind::SemanticDataFlow
                )
            });
            let results =
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
                                        "artifactLocation": { "uri": location.normalized_path },
                                        "region": {
                                            "startLine": location.start_line.unwrap_or(1),
                                            "startColumn": location.start_column.unwrap_or(1)
                                        }
                                    }
                                })]
                            })
                            .unwrap_or_default();
                        serde_json::json!({
                            "ruleId": record.observation.rule_id,
                            "message": { "text": record.observation.summary },
                            "locations": locations,
                            "properties": {
                                "observationId": record.observation.id,
                                "detectorId": record.observation.detector_id,
                                "detectorVersion": record.observation.detector_version
                            }
                        })
                    })
                    .collect::<Vec<_>>();
            if results.is_empty() {
                warnings.push("This run has no source, secret, policy, or semantic observations that map to SARIF.".into());
            }
            serde_json::json!({
                "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": { "driver": { "name": "oxAudit", "version": env!("CARGO_PKG_VERSION") } },
                    "results": results,
                    "properties": { "oxAuditRunId": data.run.id }
                }]
            })
        }
        ReportFormat::CycloneDx => serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            "version": 1,
            "metadata": { "tools": { "components": [{ "type": "application", "name": "oxAudit", "version": env!("CARGO_PKG_VERSION") }] } },
            "components": data.components.iter().map(cyclonedx_component).collect::<Vec<_>>()
        }),
        ReportFormat::Spdx => serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": format!("oxAudit run {}", data.run.id.as_str()),
            "documentNamespace": format!("https://oxaudit.local/spdx/{}", uuid::Uuid::new_v4()),
            "creationInfo": { "creators": [format!("Tool: oxAudit-{}", env!("CARGO_PKG_VERSION"))], "created": chrono::Utc::now().to_rfc3339() },
            "packages": data.components.iter().enumerate().map(|(index, component)| serde_json::json!({
                "SPDXID": format!("SPDXRef-Package-{index}"),
                "name": component.name,
                "versionInfo": component.version,
                "supplier": component.supplier.as_ref().map(|supplier| format!("Organization: {supplier}")).unwrap_or_else(|| "NOASSERTION".into()),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "externalRefs": component.purl.as_ref().map(|purl| vec![serde_json::json!({ "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl })]).unwrap_or_default()
            })).collect::<Vec<_>>()
        }),
        ReportFormat::OpenVex => {
            let statements = vex_statements(data);
            if statements.is_empty() {
                warnings.push("No advisory observations are available for VEX statements.".into());
            }
            serde_json::json!({
                "@context": "https://openvex.dev/ns/v0.2.0",
                "@id": format!("https://oxaudit.local/vex/{}", data.run.id.as_str()),
                "author": "oxAudit local user",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "version": 1,
                "tooling": format!("oxAudit {}", env!("CARGO_PKG_VERSION")),
                "statements": statements
            })
        }
        ReportFormat::CycloneDxVex => {
            let vulnerabilities = data.observations.iter().filter(|record| record.observation.kind == oxaudit_domain::ObservationKind::AdvisoryMatch).map(|record| serde_json::json!({
                "id": record.observation.rule_id.clone().unwrap_or_else(|| record.observation.title.clone()),
                "analysis": { "state": "exploitable", "detail": "Affected-range match observed by oxAudit; review status was not silently inferred." },
                "properties": [{ "name": "oxaudit:observationId", "value": record.observation.id.as_str() }]
            })).collect::<Vec<_>>();
            serde_json::json!({
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                "version": 1,
                "components": data.components.iter().map(cyclonedx_component).collect::<Vec<_>>(),
                "vulnerabilities": vulnerabilities
            })
        }
    };
    validate(&value, format)?;
    let bytes = serde_json::to_vec_pretty(&value).map_err(|error| error.to_string())?;
    Ok(GeneratedReport { bytes, warnings })
}

fn cyclonedx_component(component: &Component) -> serde_json::Value {
    serde_json::json!({
        "type": "library",
        "bom-ref": component.id.as_str(),
        "name": component.name,
        "version": component.version,
        "supplier": component.supplier.as_ref().map(|name| serde_json::json!({ "name": name })),
        "purl": component.purl,
        "cpe": component.cpes.first(),
        "properties": [{ "name": "oxaudit:identityConfidence", "value": component.identities.iter().map(|identity| identity.confidence).fold(0.0_f32, f32::max).to_string() }]
    })
}

fn vex_statements(data: &ReportData) -> Vec<serde_json::Value> {
    data.observations
        .iter()
        .filter(|record| record.observation.kind == oxaudit_domain::ObservationKind::AdvisoryMatch)
        .map(|record| serde_json::json!({
            "vulnerability": { "name": record.observation.rule_id.clone().unwrap_or_else(|| record.observation.title.clone()) },
            "products": data.components.iter().map(|component| serde_json::json!({ "@id": component.purl.clone().unwrap_or_else(|| format!("pkg:generic/{}@{}", component.name, component.version.clone().unwrap_or_else(|| "unknown".into()))) })).collect::<Vec<_>>(),
            "status": "affected",
            "status_notes": "Affected-range match observed; no analyst disposition was inferred."
        }))
        .collect()
}

fn validate(value: &serde_json::Value, format: ReportFormat) -> Result<(), String> {
    let valid = match format {
        ReportFormat::OxAuditJson => {
            value.get("schemaVersion") == Some(&serde_json::json!(1)) && value.get("run").is_some()
        }
        ReportFormat::Sarif => {
            value.get("version") == Some(&serde_json::json!("2.1.0"))
                && value
                    .get("runs")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|runs| !runs.is_empty())
        }
        ReportFormat::CycloneDx | ReportFormat::CycloneDxVex => {
            value.get("bomFormat") == Some(&serde_json::json!("CycloneDX"))
                && value.get("specVersion").is_some()
        }
        ReportFormat::Spdx => {
            value.get("spdxVersion") == Some(&serde_json::json!("SPDX-2.3"))
                && value.get("documentNamespace").is_some()
        }
        ReportFormat::OpenVex => {
            value.get("@context").is_some()
                && value
                    .get("statements")
                    .and_then(serde_json::Value::as_array)
                    .is_some()
        }
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
    fn every_standard_writer_produces_structurally_valid_json() {
        let data = ReportData {
            run: completed_run(),
            artifacts: Vec::new(),
            components: Vec::new(),
            observations: Vec::new(),
            projection: None,
        };
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
}
