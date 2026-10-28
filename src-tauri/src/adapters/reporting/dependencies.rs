//! Dependency standards mappings use immutable advisory/component/artifact links.
use super::{Evidence, ObservationRecord, ReportData};
use oxaudit_domain::{AdvisoryMatchEvidence, Component};
use std::collections::{HashMap, HashSet};

pub(super) struct ComponentIndex<'a> {
    by_id: HashMap<&'a str, (usize, &'a Component)>,
}

impl<'a> ComponentIndex<'a> {
    pub(super) fn new(data: &'a ReportData) -> Self {
        Self {
            by_id: data
                .components
                .iter()
                .enumerate()
                .map(|(index, component)| (component.id.as_str(), (index, component)))
                .collect(),
        }
    }

    fn affected_advisories(
        &self,
        record: &'a ObservationRecord,
    ) -> Vec<(&'a Component, &'a AdvisoryMatchEvidence)> {
        let mut seen = HashSet::new();
        let mut affected = Vec::new();
        for evidence in &record.evidence {
            if let Evidence::AdvisoryMatch(advisory) = &evidence.evidence {
                if advisory.affected {
                    if let Some(&(index, component)) =
                        self.by_id.get(advisory.component_id.as_str())
                    {
                        if seen.insert(index) {
                            affected.push((index, component, advisory));
                        }
                    }
                }
            }
        }
        // Retain inventory order and one result per component, as before indexing.
        affected.sort_unstable_by_key(|(index, _, _)| *index);
        affected
            .into_iter()
            .map(|(_, component, advisory)| (component, advisory))
            .collect()
    }

    pub(super) fn affected_components(&self, record: &'a ObservationRecord) -> Vec<&'a Component> {
        self.affected_advisories(record)
            .into_iter()
            .map(|(component, _)| component)
            .collect()
    }
}

#[derive(PartialEq, Eq, Hash)]
struct DetailKey<'a> {
    advisory: &'a str,
    package: &'a str,
    version: Option<&'a str>,
    ecosystem: Option<&'a str>,
    lockfile: &'a str,
    install_path: Option<&'a str>,
}

pub(super) fn sarif_results(data: &ReportData) -> Result<Vec<serde_json::Value>, String> {
    let components = ComponentIndex::new(data);
    let artifacts: HashMap<_, _> = data
        .artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect();
    let mut details = HashMap::new();
    if let Some(entries) = data
        .projection
        .as_ref()
        .and_then(|p| p.get("vulnerabilities"))
        .and_then(|v| v.as_array())
    {
        for entry in entries {
            let (Some(advisory), Some(package), Some(lockfile)) = (
                entry.get("id").and_then(|v| v.as_str()),
                entry.get("packageName").and_then(|v| v.as_str()),
                entry.get("lockfile").and_then(|v| v.as_str()),
            ) else {
                continue;
            };
            details
                .entry(DetailKey {
                    advisory,
                    package,
                    lockfile,
                    version: entry.get("installedVersion").and_then(|v| v.as_str()),
                    ecosystem: entry.get("ecosystem").and_then(|v| v.as_str()),
                    install_path: entry
                        .get("occurrence")
                        .and_then(|v| v.get("installPath"))
                        .and_then(|v| v.as_str()),
                })
                .or_insert(entry);
        }
    }
    let mut results = Vec::new();
    for record in data
        .observations
        .iter()
        .filter(|record| record.observation.kind == oxaudit_domain::ObservationKind::AdvisoryMatch)
    {
        let artifact = artifacts
            .get(record.observation.artifact_id.as_str())
            .ok_or("dependency SARIF requires the advisory's lockfile artifact")?;
        let affected = components.affected_advisories(record);
        if affected.is_empty() {
            return Err(
                "dependency SARIF requires evidence linking each advisory to an affected package"
                    .into(),
            );
        }
        for (component, advisory) in affected {
            let detail = details.get(&DetailKey {
                advisory: &advisory.advisory_id,
                package: &component.name,
                version: component.version.as_deref(),
                ecosystem: component.ecosystem.as_deref(),
                lockfile: &artifact.location.normalized_path,
                install_path: advisory.install_path.as_deref(),
            });
            let severity = detail
                .and_then(|v| v.get("severity"))
                .and_then(|v| v.as_str());
            let fixed_versions = detail
                .and_then(|v| v.get("fixedVersions"))
                .filter(|v| v.is_array())
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            results.push(serde_json::json!({
                "ruleId": advisory.advisory_id,
                "level": super::sarif_level(severity),
                "message": {"text": format!("{} {}: {}", component.name, component.version.as_deref().unwrap_or("unknown"), record.observation.summary)},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": super::sarif_artifact_uri(&artifact.location.normalized_path)}}}],
                "properties": {
                    "observationId": record.observation.id,
                    "componentId": component.id,
                    "providerSnapshotId": advisory.provider_snapshot_id,
                    "packageName": component.name,
                    "installedVersion": component.version,
                    "ecosystem": component.ecosystem,
                    "severity": severity.unwrap_or("unknown"),
                    "fixedVersions": fixed_versions,
                    "evidenceKind": "advisoryMatch"
                }
            }));
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxaudit_domain::{
        Artifact, ArtifactId, ArtifactKind, ArtifactLocation, ComponentId, EvidenceId,
        EvidenceRecord, Observation, ObservationId, ObservationKind, ProviderSnapshotId, Run,
        RunKind,
    };

    fn dependency_report(projection: Option<serde_json::Value>) -> ReportData {
        let artifact = Artifact {
            id: ArtifactId::parse("artifact_lockfile").unwrap(),
            kind: ArtifactKind::Lockfile,
            location: ArtifactLocation {
                normalized_path: "package-lock.json".into(),
                canonical_path: None,
                parent_id: None,
            },
            size_bytes: 1,
            media_type: None,
            content_sha256: None,
        };
        let component = Component {
            id: ComponentId::parse("component_leaf").unwrap(),
            name: "leaf".into(),
            version: Some("1.0.0".into()),
            supplier: None,
            ecosystem: Some("npm".into()),
            purl: None,
            cpes: Vec::new(),
            aliases: Vec::new(),
            identities: Vec::new(),
            depends_on: Vec::new(),
            license: None,
        };
        let evidence = EvidenceRecord {
            id: EvidenceId::parse("evidence_advisory").unwrap(),
            evidence: Evidence::AdvisoryMatch(AdvisoryMatchEvidence {
                install_path: None,
                component_id: component.id.clone(),
                provider_snapshot_id: ProviderSnapshotId::parse("provider_osv").unwrap(),
                advisory_id: "GHSA-test".into(),
                affected: true,
                rationale: "affected range match".into(),
            }),
        };
        let run = Run::queued(RunKind::Dependencies, "/fixture", 1);
        ReportData {
            observations: vec![ObservationRecord {
                observation: Observation {
                    id: ObservationId::parse("observation_advisory").unwrap(),
                    run_id: run.id.clone(),
                    artifact_id: artifact.id.clone(),
                    kind: ObservationKind::AdvisoryMatch,
                    detector_id: "dependency-inventory".into(),
                    detector_version: "1".into(),
                    rule_id: Some("GHSA-test".into()),
                    title: "GHSA-test".into(),
                    summary: "test advisory".into(),
                    evidence_ids: vec![evidence.id.clone()],
                },
                evidence: vec![evidence],
            }],
            run,
            artifacts: vec![artifact],
            components: vec![component],
            findings: Vec::new(),
            projection,
        }
    }

    #[test]
    fn sarif_results_carry_advisory_fixed_versions() {
        let data = dependency_report(Some(serde_json::json!({
            "vulnerabilities": [{
                "id": "GHSA-test",
                "packageName": "leaf",
                "installedVersion": "1.0.0",
                "ecosystem": "npm",
                "lockfile": "package-lock.json",
                "severity": "high",
                "fixedVersions": ["1.0.1", "1.1.0"]
            }]
        })));
        let results = sarif_results(&data).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]["properties"]["fixedVersions"],
            serde_json::json!(["1.0.1", "1.1.0"])
        );
    }

    #[test]
    fn sarif_results_default_fixed_versions_to_an_empty_array() {
        let data = dependency_report(None);
        let results = sarif_results(&data).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]["properties"]["fixedVersions"],
            serde_json::json!([])
        );
    }
}
