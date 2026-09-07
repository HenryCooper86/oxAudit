//! Dependency standards mappings use immutable advisory/component/artifact links.
use super::{Evidence, ObservationRecord, ReportData};
use oxaudit_domain::Component;

pub(super) fn affected_components<'a>(
    data: &'a ReportData,
    record: &'a ObservationRecord,
) -> Vec<&'a Component> {
    data.components.iter().filter(|component| record.evidence.iter().any(|evidence| matches!(&evidence.evidence, Evidence::AdvisoryMatch(advisory) if advisory.affected && advisory.component_id == component.id))).collect()
}

pub(super) fn sarif_results(data: &ReportData) -> Result<Vec<serde_json::Value>, String> {
    let mut results = Vec::new();
    for record in data
        .observations
        .iter()
        .filter(|record| record.observation.kind == oxaudit_domain::ObservationKind::AdvisoryMatch)
    {
        let artifact = data
            .artifacts
            .iter()
            .find(|artifact| artifact.id == record.observation.artifact_id)
            .ok_or("dependency SARIF requires the advisory's lockfile artifact")?;
        let components = affected_components(data, record);
        if components.is_empty() {
            return Err(
                "dependency SARIF requires evidence linking each advisory to an affected package"
                    .into(),
            );
        }
        for component in components {
            let advisory = record
                .evidence
                .iter()
                .find_map(|evidence| match &evidence.evidence {
                    Evidence::AdvisoryMatch(advisory)
                        if advisory.affected && advisory.component_id == component.id =>
                    {
                        Some(advisory)
                    }
                    _ => None,
                })
                .expect("component selected through advisory evidence");
            let detail = data
                .projection
                .as_ref()
                .and_then(|projection| projection.get("vulnerabilities"))
                .and_then(|v| v.as_array())
                .and_then(|entries| {
                    entries.iter().find(|v| {
                        v.get("id").and_then(|v| v.as_str()) == Some(advisory.advisory_id.as_str())
                            && v.get("packageName").and_then(|v| v.as_str())
                                == Some(component.name.as_str())
                            && v.get("installedVersion").and_then(|v| v.as_str())
                                == component.version.as_deref()
                            && v.get("ecosystem").and_then(|v| v.as_str())
                                == component.ecosystem.as_deref()
                            && v.get("lockfile").and_then(|v| v.as_str())
                                == Some(artifact.location.normalized_path.as_str())
                    })
                });
            let severity = detail
                .and_then(|v| v.get("severity"))
                .and_then(|v| v.as_str());
            results.push(serde_json::json!({
                "ruleId": advisory.advisory_id,
                "level": super::sarif_level(severity),
                "message": {"text": format!("{} {}: {}", component.name, component.version.as_deref().unwrap_or("unknown"), record.observation.summary)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": artifact.location.normalized_path}}}],
                "properties": {
                    "observationId": record.observation.id,
                    "componentId": component.id,
                    "providerSnapshotId": advisory.provider_snapshot_id,
                    "packageName": component.name,
                    "installedVersion": component.version,
                    "ecosystem": component.ecosystem,
                    "severity": severity.unwrap_or("unknown"),
                    "evidenceKind": "advisoryMatch"
                }
            }));
        }
    }
    Ok(results)
}
