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
