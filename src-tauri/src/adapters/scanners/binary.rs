use std::collections::BTreeMap;

use oxaudit_application::ObservationRecord;
use oxaudit_domain::{
    AdvisoryMatchEvidence, Artifact, ArtifactId, ArtifactKind, ArtifactLocation,
    BinaryMatchEvidence, Component, ComponentId, ComponentIdentity, Evidence, EvidenceId,
    EvidenceRecord, IdentityMethod, Observation, ObservationId, ObservationKind,
    ProviderSnapshotId, RunId, ToolReceiptEvidence,
};
use sha2::{Digest, Sha256};

use crate::binscan::report::BinaryScanResult;

pub fn binary_graph(run_id: &RunId, result: &BinaryScanResult) -> Result<super::ScanGraph, String> {
    let mut artifacts = BTreeMap::<String, Artifact>::new();
    for path in result
        .components
        .iter()
        .flat_map(|component| component.paths.iter())
    {
        let normalized = path.replace('\\', "/");
        let id = ArtifactId::parse(format!(
            "artifact_{:x}",
            Sha256::digest(format!("{}\0{}", run_id, normalized).as_bytes())
        ))
        .map_err(|error| error.to_string())?;
        artifacts.entry(normalized.clone()).or_insert(Artifact {
            id,
            kind: ArtifactKind::Binary,
            location: ArtifactLocation {
                normalized_path: normalized,
                canonical_path: None,
                parent_id: None,
            },
            size_bytes: 0,
            media_type: Some("application/octet-stream".into()),
            content_sha256: None,
        });
    }
    if artifacts.is_empty() {
        let normalized = result.target.replace('\\', "/");
        let id = ArtifactId::parse(format!(
            "artifact_{:x}",
            Sha256::digest(format!("{}\0{}", run_id, normalized).as_bytes())
        ))
        .map_err(|error| error.to_string())?;
        artifacts.insert(
            normalized.clone(),
            Artifact {
                id,
                kind: ArtifactKind::Binary,
                location: ArtifactLocation {
                    normalized_path: normalized,
                    canonical_path: Some(result.target.clone()),
                    parent_id: None,
                },
                size_bytes: 0,
                media_type: Some("application/octet-stream".into()),
                content_sha256: None,
            },
        );
    }

    let fallback_artifact = artifacts
        .values()
        .next()
        .expect("one artifact exists")
        .clone();
    let mut components = Vec::new();
    let mut observations = Vec::new();
    for component in &result.components {
        let component_id = ComponentId::parse(format!(
            "component_{:x}",
            Sha256::digest(
                format!(
                    "{}\0{}\0{}\0{}",
                    run_id, component.vendor, component.product, component.version
                )
                .as_bytes()
            )
        ))
        .map_err(|error| error.to_string())?;
        let artifact = component
            .paths
            .first()
            .and_then(|path| artifacts.get(&path.replace('\\', "/")))
            .unwrap_or(&fallback_artifact);
        let native = component
            .detected_by
            .iter()
            .any(|detector| detector == crate::binscan::native::scan::NATIVE);
        components.push(Component {
            id: component_id.clone(),
            name: component.product.clone(),
            version: (!component.version.is_empty()).then(|| component.version.clone()),
            supplier: (!component.vendor.is_empty()).then(|| component.vendor.clone()),
            ecosystem: None,
            purl: None,
            cpes: if component.vendor.is_empty() || component.version.is_empty() {
                Vec::new()
            } else {
                vec![format!(
                    "cpe:2.3:a:{}:{}:{}:*:*:*:*:*:*:*",
                    component.vendor, component.product, component.version
                )]
            },
            aliases: Vec::new(),
            identities: vec![ComponentIdentity {
                method: if native {
                    IdentityMethod::CharacteristicString
                } else {
                    IdentityMethod::ExternalTool
                },
                value: format!("{}:{}", component.product, component.version),
                confidence: if native { 0.85 } else { 0.75 },
                source_artifact_id: artifact.id.clone(),
            }],
        });
        let evidence: Vec<EvidenceRecord> = component
            .paths
            .iter()
            .enumerate()
            .filter_map(|(index, path)| {
                let artifact = artifacts.get(&path.replace('\\', "/"))?;
                Some(EvidenceRecord {
                    id: EvidenceId::new(),
                    evidence: Evidence::BinaryMatch(BinaryMatchEvidence {
                        artifact_id: artifact.id.clone(),
                        offset: None,
                        section: None,
                        matcher_id: component.detected_by.join("+"),
                        encoding: "scanner-reported".into(),
                        captured_value: (index == 0 && !component.version.is_empty())
                            .then(|| component.version.clone()),
                    }),
                })
            })
            .collect();
        let evidence = if evidence.is_empty() {
            vec![EvidenceRecord {
                id: EvidenceId::new(),
                evidence: Evidence::BinaryMatch(BinaryMatchEvidence {
                    artifact_id: artifact.id.clone(),
                    offset: None,
                    section: None,
                    matcher_id: component.detected_by.join("+"),
                    encoding: "scanner-reported".into(),
                    captured_value: (!component.version.is_empty())
                        .then(|| component.version.clone()),
                }),
            }]
        } else {
            evidence
        };
        observations.push(ObservationRecord {
            observation: Observation {
                id: ObservationId::new(),
                run_id: run_id.clone(),
                artifact_id: artifact.id.clone(),
                kind: ObservationKind::BinaryComponent,
                detector_id: component.detected_by.join("+"),
                detector_version: env!("CARGO_PKG_VERSION").into(),
                rule_id: None,
                title: component.product.clone(),
                summary: format!("Detected binary component version {}", component.version),
                evidence_ids: evidence.iter().map(|record| record.id.clone()).collect(),
            },
            evidence,
        });

        for vulnerability in &component.vulnerabilities {
            let advisory_id = EvidenceId::new();
            let receipt_id = EvidenceId::new();
            let provider_id = binary_provider_snapshot_id(run_id, &vulnerability.source)?;
            observations.push(ObservationRecord {
                observation: Observation {
                    id: ObservationId::new(),
                    run_id: run_id.clone(),
                    artifact_id: artifact.id.clone(),
                    kind: ObservationKind::AdvisoryMatch,
                    detector_id: component.detected_by.join("+"),
                    detector_version: env!("CARGO_PKG_VERSION").into(),
                    rule_id: Some(vulnerability.cve_id.clone()),
                    title: vulnerability.cve_id.clone(),
                    summary: format!(
                        "{} {} is reported affected",
                        component.product, component.version
                    ),
                    evidence_ids: vec![advisory_id.clone(), receipt_id.clone()],
                },
                evidence: vec![
                    EvidenceRecord {
                        id: advisory_id,
                        evidence: Evidence::AdvisoryMatch(AdvisoryMatchEvidence {
                            component_id: component_id.clone(),
                            provider_snapshot_id: provider_id,
                            advisory_id: vulnerability.cve_id.clone(),
                            affected: true,
                            rationale: vulnerability
                                .remarks
                                .clone()
                                .unwrap_or_else(|| "scanner advisory match".into()),
                        }),
                    },
                    EvidenceRecord {
                        id: receipt_id,
                        evidence: Evidence::ToolReceipt(ToolReceiptEvidence {
                            engine_id: component.detected_by.join("+"),
                            engine_version: env!("CARGO_PKG_VERSION").into(),
                            invocation_sha256: format!(
                                "{:x}",
                                Sha256::digest(format!("{}\0{}", run_id, result.target).as_bytes())
                            ),
                            bounded_metadata: vec![("target".into(), result.target.clone())],
                        }),
                    },
                ],
            });
        }
    }
    Ok((artifacts.into_values().collect(), components, observations))
}

pub fn binary_provider_snapshot_id(
    run_id: &RunId,
    source: &str,
) -> Result<ProviderSnapshotId, String> {
    ProviderSnapshotId::parse(format!(
        "provider_{:x}",
        Sha256::digest(format!("{}\0{}", run_id, source).as_bytes())
    ))
    .map_err(|error| error.to_string())
}
