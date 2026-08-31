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
    pub findings: Vec<crate::models::Finding>,
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
                        let rule_id = record.observation.rule_id.as_deref();
                        let mut result = serde_json::json!({
                            "ruleId": record.observation.rule_id,
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
                        if let Some(suppression) = findings_by_observation
                            .get(record.observation.id.as_str())
                            .and_then(|finding| sarif_suppression(finding.review.as_ref()))
                        {
                            result["suppressions"] = serde_json::json!([suppression]);
                        }
                        result
                    })
                    .collect::<Vec<_>>();
            if results.is_empty() {
                warnings.push("This run has no source, secret, policy, or semantic observations that map to SARIF.".into());
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
            findings: Vec::new(),
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
fn sarif_level(severity: Option<&str>) -> &'static str {
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
